/* Copyright (C) 2020-2026 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Security.Cryptography;
using Utilities;

namespace SMBLibrary.SMB2
{
    internal class SMB2Cryptography
    {
        public static byte[] CalculateSignature(byte[] signingKey, SigningAlgorithm signingAlgorithm, byte[] buffer, int offset, int paddedLength)
        {
            byte[] hash;
            if (signingAlgorithm == SigningAlgorithm.HMACSHA256)
            {
                hash = new HMACSHA256(signingKey).ComputeHash(buffer, offset, paddedLength);
            }
            else if (signingAlgorithm == SigningAlgorithm.AESCMAC)
            {
                hash = AesCmac.CalculateAesCmac(signingKey, buffer, offset, paddedLength);
            }
            else if (signingAlgorithm == SigningAlgorithm.AESGMAC)
            {
                byte[] nonce = BuildGmacNonce(buffer, offset);
                hash = AesGmac.CalculateAesGmac(signingKey, nonce, buffer, offset, paddedLength);
            }
            else
            {
                throw new NotSupportedException($"Signing algorithm {signingAlgorithm} is not supported");
            }

            // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
            return ByteReader.ReadBytes(hash, 0, SMB2Header.SignatureLength);
        }

        /// <summary>
        /// [MS-SMB2] 3.1.4.1 / 3.1.4.1.1: The AES-GMAC nonce is the message's 8-byte little-endian MessageId,
        /// followed by 4 bytes where bit 0 identifies the sender (0 = client, 1 = server), bit 1 is set only
        /// for an SMB2 CANCEL request, and the remaining 30 bits are zero.
        /// </summary>
        private static byte[] BuildGmacNonce(byte[] buffer, int offset)
        {
            const int GmacNonceLength = 12;
            byte[] nonce = new byte[GmacNonceLength];

            const int MessageIdOffset = 24;
            const int MessageIdLength = 8;
            Array.Copy(buffer, offset + MessageIdOffset, nonce, 0, MessageIdLength);

            const int CommandOffset = 12;
            ushort command = LittleEndianConverter.ToUInt16(buffer, offset + CommandOffset);

            const int FlagsOffset = 16;
            uint flags = LittleEndianConverter.ToUInt32(buffer, offset + FlagsOffset);
            const uint ServerToRedirFlag = 0x00000001;
            bool isServer = (flags & ServerToRedirFlag) != 0;
            const ushort CancelCommand = 0x000C;
            bool isCancel = command == CancelCommand;

            byte trailingFlags = 0;
            if (isServer)
            {
                trailingFlags |= 0x01;
            }

            if (isCancel)
            {
                trailingFlags |= 0x02;
            }

            nonce[MessageIdLength] = trailingFlags;
            return nonce;
        }

        public static bool VerifySignature(byte[] messageBytes, SigningAlgorithm algorithm, byte[] signingKey)
        {
            byte[] signature = ByteReader.ReadBytes(messageBytes, SMB2Header.SignatureOffset, SMB2Header.SignatureLength);
            Array.Clear(messageBytes, SMB2Header.SignatureOffset, SMB2Header.SignatureLength);
            byte[] expectedSignature = CalculateSignature(signingKey, algorithm, messageBytes, 0, messageBytes.Length);
            return ByteUtils.AreByteArraysEqual(signature, expectedSignature);
        }

        // Shared by the Client (pre-3.1.1, before SigningCapabilities negotiation applies) and the server
        // (which does not yet negotiate SMB2_SIGNING_CAPABILITIES at all) so the default-signing-algorithm
        // rule can't drift between the two and cause signature verification to fail on one side only.
        public static SigningAlgorithm GetDefaultSigningAlgorithm(SMB2Dialect dialect)
        {
            return (dialect == SMB2Dialect.SMB202 || dialect == SMB2Dialect.SMB210) ? SigningAlgorithm.HMACSHA256 : SigningAlgorithm.AESCMAC;
        }

        public static byte[] GenerateSigningKey(byte[] sessionKey, SMB2Dialect dialect, byte[] preauthIntegrityHashValue)
        {
            if (dialect == SMB2Dialect.SMB202 || dialect == SMB2Dialect.SMB210)
            {
                return sessionKey;
            }

            if (dialect == SMB2Dialect.SMB311 && preauthIntegrityHashValue == null)
            {
                throw new ArgumentNullException("preauthIntegrityHashValue");
            }

            string labelString = (dialect == SMB2Dialect.SMB311) ? "SMBSigningKey" : "SMB2AESCMAC";
            byte[] label = GetNullTerminatedAnsiString(labelString);
            byte[] context = (dialect == SMB2Dialect.SMB311) ? preauthIntegrityHashValue : GetNullTerminatedAnsiString("SmbSign");

            HMACSHA256 hmac = new HMACSHA256(sessionKey);
            return SP800_1008.DeriveKey(hmac, label, context, 128);
        }

        public static byte[] GenerateClientEncryptionKey(byte[] sessionKey, SMB2Dialect dialect, byte[] preauthIntegrityHashValue, CipherAlgorithm cipherAlgorithm)
        {
            if (dialect == SMB2Dialect.SMB311 && preauthIntegrityHashValue == null)
            {
                throw new ArgumentNullException("preauthIntegrityHashValue");
            }

            string labelString = (dialect == SMB2Dialect.SMB311) ? "SMBC2SCipherKey" : "SMB2AESCCM";
            byte[] label = GetNullTerminatedAnsiString(labelString);
            byte[] context = (dialect == SMB2Dialect.SMB311) ? preauthIntegrityHashValue : GetNullTerminatedAnsiString("ServerIn ");

            HMACSHA256 hmac = new HMACSHA256(sessionKey);
            return SP800_1008.DeriveKey(hmac, label, context, SMB2CipherProvider.GetKeyLengthInBits(cipherAlgorithm));
        }

        public static byte[] GenerateClientDecryptionKey(byte[] sessionKey, SMB2Dialect dialect, byte[] preauthIntegrityHashValue, CipherAlgorithm cipherAlgorithm)
        {
            if (dialect == SMB2Dialect.SMB311 && preauthIntegrityHashValue == null)
            {
                throw new ArgumentNullException("preauthIntegrityHashValue");
            }

            string labelString = (dialect == SMB2Dialect.SMB311) ? "SMBS2CCipherKey" : "SMB2AESCCM";
            byte[] label = GetNullTerminatedAnsiString(labelString);
            byte[] context = (dialect == SMB2Dialect.SMB311) ? preauthIntegrityHashValue : GetNullTerminatedAnsiString("ServerOut");

            HMACSHA256 hmac = new HMACSHA256(sessionKey);
            return SP800_1008.DeriveKey(hmac, label, context, SMB2CipherProvider.GetKeyLengthInBits(cipherAlgorithm));
        }

        /// <summary>
        /// Encyrpt message and prefix with SMB2 TransformHeader
        /// </summary>
        public static byte[] TransformMessage(byte[] key, byte[] message, ulong sessionID, CipherAlgorithm cipherAlgorithm)
        {
            byte[] nonce = SMB2CipherProvider.GenerateNonce(cipherAlgorithm);
            byte[] signature;
            byte[] encryptedMessage = EncryptMessage(key, nonce, message, sessionID, out signature, cipherAlgorithm);
            SMB2TransformHeader transformHeader = CreateTransformHeader(nonce, message.Length, sessionID);
            transformHeader.Signature = signature;

            byte[] buffer = new byte[SMB2TransformHeader.Length + message.Length];
            transformHeader.WriteBytes(buffer, 0);
            ByteWriter.WriteBytes(buffer, SMB2TransformHeader.Length, encryptedMessage);
            return buffer;
        }

        public static byte[] EncryptMessage(byte[] key, byte[] nonce, byte[] message, ulong sessionID, out byte[] signature, CipherAlgorithm cipherAlgorithm)
        {
            SMB2TransformHeader transformHeader = CreateTransformHeader(nonce, message.Length, sessionID);
            byte[] associatedata = transformHeader.GetAssociatedData();
            return SMB2CipherProvider.Encrypt(cipherAlgorithm, key, nonce, message, associatedata, SMB2TransformHeader.SignatureLength, out signature);
        }

        public static byte[] DecryptMessage(byte[] key, SMB2TransformHeader transformHeader, byte[] encryptedMessage, CipherAlgorithm cipherAlgorithm)
        {
            byte[] associatedData = transformHeader.GetAssociatedData();
            byte[] nonce = ByteReader.ReadBytes(transformHeader.Nonce, 0, SMB2CipherProvider.GetNonceLength(cipherAlgorithm));
            return SMB2CipherProvider.DecryptAndAuthenticate(cipherAlgorithm, key, nonce, encryptedMessage, associatedData, transformHeader.Signature);
        }

        public static byte[] ComputeHash(HashAlgorithm hashAlgorithm, byte[] buffer)
        {
            if (hashAlgorithm == HashAlgorithm.SHA512)
            {
                return SHA512.Create().ComputeHash(buffer);
            }
            else
            {
                throw new NotSupportedException($"Hash algorithm {hashAlgorithm} is not supported");
            }
        }

        private static SMB2TransformHeader CreateTransformHeader(byte[] nonce, int originalMessageLength, ulong sessionID)
        {
            byte[] nonceWithPadding = new byte[SMB2TransformHeader.NonceLength];
            Array.Copy(nonce, nonceWithPadding, nonce.Length);

            SMB2TransformHeader transformHeader = new SMB2TransformHeader();
            transformHeader.Nonce = nonceWithPadding;
            transformHeader.OriginalMessageSize = (uint)originalMessageLength;
            transformHeader.Flags = SMB2TransformHeaderFlags.Encrypted;
            transformHeader.SessionId = sessionID;

            return transformHeader;
        }

        private static byte[] GetNullTerminatedAnsiString(string value)
        {
            byte[] result = new byte[value.Length + 1];
            ByteWriter.WriteNullTerminatedAnsiString(result, 0, value);
            return result;
        }
    }
}
