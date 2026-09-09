/* Copyright (C) 2020-2026 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// Selects and drives the AEAD cipher negotiated for a session (AES-CCM or AES-GCM, 128 or 256-bit key),
    /// per the CipherId list in the SMB2_ENCRYPTION_CAPABILITIES negotiate context ([MS-SMB2] 2.2.3.1.3).
    /// </summary>
    internal static class SMB2CipherProvider
    {
        public const int NonceLength11 = 11;
        public const int NonceLength12 = 12;

        public static int GetNonceLength(CipherAlgorithm cipherAlgorithm)
        {
            return IsGcm(cipherAlgorithm) ? NonceLength12 : NonceLength11;
        }

        public static int GetKeyLengthInBits(CipherAlgorithm cipherAlgorithm)
        {
            return IsAes256(cipherAlgorithm) ? 256 : 128;
        }

        public static byte[] GenerateNonce(CipherAlgorithm cipherAlgorithm)
        {
            // Nonce reuse under the same key breaks confidentiality and authenticity for both AEAD modes
            // used here (AES-CCM and AES-GCM alike), so this must come from a CSPRNG, not System.Random.
            return SecureRandom.GetBytes(GetNonceLength(cipherAlgorithm));
        }

        public static byte[] Encrypt(CipherAlgorithm cipherAlgorithm, byte[] key, byte[] nonce, byte[] data, byte[] associatedData, int signatureLength, out byte[] signature)
        {
            if (IsGcm(cipherAlgorithm))
            {
                return Utilities.AesGcm.Encrypt(key, nonce, data, associatedData, signatureLength, out signature);
            }

            return Utilities.AesCcm.Encrypt(key, nonce, data, associatedData, signatureLength, out signature);
        }

        public static byte[] DecryptAndAuthenticate(CipherAlgorithm cipherAlgorithm, byte[] key, byte[] nonce, byte[] encryptedData, byte[] associatedData, byte[] signature)
        {
            if (IsGcm(cipherAlgorithm))
            {
                return Utilities.AesGcm.DecryptAndAuthenticate(key, nonce, encryptedData, associatedData, signature);
            }

            return Utilities.AesCcm.DecryptAndAuthenticate(key, nonce, encryptedData, associatedData, signature);
        }

        private static bool IsGcm(CipherAlgorithm cipherAlgorithm)
        {
            return cipherAlgorithm == CipherAlgorithm.Aes128Gcm || cipherAlgorithm == CipherAlgorithm.Aes256Gcm;
        }

        private static bool IsAes256(CipherAlgorithm cipherAlgorithm)
        {
            return cipherAlgorithm == CipherAlgorithm.Aes256Ccm || cipherAlgorithm == CipherAlgorithm.Aes256Gcm;
        }
    }
}
