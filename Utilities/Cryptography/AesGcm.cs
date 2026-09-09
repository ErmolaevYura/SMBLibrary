/* Copyright (C) 2020-2026 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Security.Cryptography;

namespace Utilities
{
    /// <summary>
    /// Implements AES-GCM (Galois/Counter Mode) authenticated encryption as detailed in NIST SP 800-38D.
    /// Supports 128-bit and 256-bit AES keys (per the key length supplied) with the 96-bit (12-byte) nonce
    /// used by SMB2 (AES-128-GCM / AES-256-GCM ciphers).
    /// Implemented from AES primitives (rather than System.Security.Cryptography.AesGcm) so it is available
    /// on targets (net20 / net40 / netstandard2.0) that lack a built-in AES-GCM implementation.
    /// </summary>
    public static class AesGcm
    {
        private const int BlockLength = 16;
        private const int NonceLength = 12;

        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] data, byte[] associatedData, int signatureLength, out byte[] signature)
        {
            ValidateNonceLength(nonce);
            ValidateSignatureLength(signatureLength);

            using (EcbEncryptor encryptor = CreateEcbEncryptor(key))
            {
                byte[] hashSubkey = AesEncryptBlock(encryptor, new byte[BlockLength]);
                byte[] j0 = BuildInitialCounterBlock(nonce);
            
                byte[] cipherText = TransformWithCounter(encryptor, j0, data);
                byte[] tag = ComputeTag(encryptor, hashSubkey, j0, associatedData, cipherText);
                signature = ByteReader.ReadBytes(tag, 0, signatureLength);
                return cipherText;
            }
        }

        public static byte[] DecryptAndAuthenticate(byte[] key, byte[] nonce, byte[] encryptedData, byte[] associatedData, byte[] signature)
        {
            ValidateNonceLength(nonce);
            ValidateSignatureLength(signature.Length);

            using (EcbEncryptor encryptor = CreateEcbEncryptor(key))
            {
                byte[] hashSubkey = AesEncryptBlock(encryptor, new byte[BlockLength]);
                byte[] j0 = BuildInitialCounterBlock(nonce);

                byte[] tag = ComputeTag(encryptor, hashSubkey, j0, associatedData, encryptedData);
                byte[] expectedSignature = ByteReader.ReadBytes(tag, 0, signature.Length);
                if (!ByteUtils.AreByteArraysEqual(expectedSignature, signature))
                {
                    throw new CryptographicException("The computed authentication value did not match the input");
                }

                return TransformWithCounter(encryptor, j0, encryptedData);
            }
        }

        private static byte[] ComputeTag(EcbEncryptor encryptor, byte[] hashSubkey, byte[] j0, byte[] associatedData, byte[] cipherText)
        {
            byte[] tag = Ghash(hashSubkey, associatedData, cipherText);
            byte[] mask = AesEncryptBlock(encryptor, j0);
            Xor128(tag, mask);
            return tag;
        }

        private static byte[] TransformWithCounter(EcbEncryptor encryptor, byte[] j0, byte[] data)
        {
            byte[] output = new byte[data.Length];
            byte[] counter = IncrementCounter(j0);
            int offset = 0;
            while (offset < data.Length)
            {
                byte[] keyStreamBlock = AesEncryptBlock(encryptor, counter);
                int chunkLength = Math.Min(BlockLength, data.Length - offset);
                for (int index = 0; index < chunkLength; index++)
                {
                    output[offset + index] = (byte)(data[offset + index] ^ keyStreamBlock[index]);
                }

                counter = IncrementCounter(counter);
                offset += BlockLength;
            }

            return output;
        }

        private static byte[] Ghash(byte[] hashSubkey, byte[] associatedData, byte[] cipherText)
        {
            byte[] y = new byte[BlockLength];
            GhashUpdate(y, hashSubkey, associatedData);
            GhashUpdate(y, hashSubkey, cipherText);

            byte[] lengthBlock = new byte[BlockLength];
            WriteBigEndianBitLength(lengthBlock, 0, associatedData.Length);
            WriteBigEndianBitLength(lengthBlock, 8, cipherText.Length);
            Xor128(y, lengthBlock);
            return GaloisFieldMultiply(y, hashSubkey);
        }

        private static void GhashUpdate(byte[] y, byte[] hashSubkey, byte[] data)
        {
            int offset = 0;
            while (offset < data.Length)
            {
                byte[] block = new byte[BlockLength];
                int chunkLength = Math.Min(BlockLength, data.Length - offset);
                Array.Copy(data, offset, block, 0, chunkLength);
                Xor128(y, block);
                byte[] product = GaloisFieldMultiply(y, hashSubkey);
                Array.Copy(product, y, BlockLength);
                offset += BlockLength;
            }
        }

        /// <summary>
        /// Multiplies two 128-bit elements of GF(2^128) as defined by the GHASH function in NIST SP 800-38D,
        /// section 6.3 (reduction polynomial: 1 + x + x^2 + x^7 + x^128).
        /// </summary>
        private static byte[] GaloisFieldMultiply(byte[] x, byte[] y)
        {
            byte[] z = new byte[BlockLength];
            byte[] v = (byte[])y.Clone();
            for (int byteIndex = 0; byteIndex < BlockLength; byteIndex++)
            {
                for (int bitIndex = 0; bitIndex < 8; bitIndex++)
                {
                    if ((x[byteIndex] & (0x80 >> bitIndex)) != 0)
                    {
                        Xor128(z, v);
                    }

                    bool lsbSet = (v[BlockLength - 1] & 0x01) != 0;
                    ShiftRight1(v);
                    if (lsbSet)
                    {
                        v[0] ^= 0xE1;
                    }
                }
            }

            return z;
        }

        private static void ShiftRight1(byte[] v)
        {
            for (int index = BlockLength - 1; index >= 0; index--)
            {
                byte incomingBit = (index > 0) ? (byte)((v[index - 1] & 0x01) << 7) : (byte)0;
                v[index] = (byte)((v[index] >> 1) | incomingBit);
            }
        }

        private static byte[] BuildInitialCounterBlock(byte[] nonce)
        {
            byte[] block = new byte[BlockLength];
            Array.Copy(nonce, 0, block, 0, NonceLength);
            block[BlockLength - 1] = 0x01;
            return block;
        }

        private static byte[] IncrementCounter(byte[] counterBlock)
        {
            byte[] next = (byte[])counterBlock.Clone();
            for (int index = BlockLength - 1; index >= BlockLength - 4; index--)
            {
                next[index]++;
                if (next[index] != 0)
                {
                    break;
                }
            }

            return next;
        }

        // Every block encrypted within a single Encrypt/DecryptAndAuthenticate call (the hash subkey, the
        // tag mask, and every counter-mode keystream block) uses the same key, so the caller creates one
        // encryptor for the whole call instead of paying for a fresh AES key-schedule expansion per block.
        // Wraps both the algorithm and its transform so disposing one call site's "using" clears the key
        // schedule from both, same as the single-block-per-call code this replaced.
        private sealed class EcbEncryptor : IDisposable
        {
            private readonly RijndaelManaged m_aes;
            private readonly ICryptoTransform m_transform;

            public EcbEncryptor(byte[] key)
            {
                m_aes = new RijndaelManaged
                {
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.None
                };
                m_transform = m_aes.CreateEncryptor(key, new byte[BlockLength]);
            }

            public byte[] EncryptBlock(byte[] block)
            {
                byte[] output = new byte[BlockLength];
                m_transform.TransformBlock(block, 0, BlockLength, output, 0);
                return output;
            }
            public void Dispose()
            {
                m_transform.Dispose();
                m_aes.Clear();
                m_aes.Dispose();
            }
        }

        private static EcbEncryptor CreateEcbEncryptor(byte[] key)
        {
            return new EcbEncryptor(key);
        }

        private static byte[] AesEncryptBlock(EcbEncryptor encryptor, byte[] block)
        {
            return encryptor.EncryptBlock(block);
        }

        private static void Xor128(byte[] target, byte[] value)
        {
            for (int index = 0; index < BlockLength; index++)
            {
                target[index] ^= value[index];
            }
        }

        private static void WriteBigEndianBitLength(byte[] buffer, int offset, int byteLength)
        {
            ulong bitLength = (ulong)byteLength * 8;
            for (int index = 7; index >= 0; index--)
            {
                buffer[offset + index] = (byte)(bitLength & 0xFF);
                bitLength >>= 8;
            }
        }

        private static void ValidateNonceLength(byte[] nonce)
        {
            if (nonce.Length != NonceLength)
            {
                throw new ArgumentException("nonce length must be 12 bytes for AES-GCM as used by SMB2");
            }
        }

        private static void ValidateSignatureLength(int signatureLength)
        {
            if (signatureLength < 12 || signatureLength > 16)
            {
                throw new ArgumentException("signature length must be between 12 and 16 bytes");
            }
        }
    }
}
