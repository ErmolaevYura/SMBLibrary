/* Copyright (C) 2020-2026 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
namespace Utilities
{
    /// <summary>
    /// Implements AES-GMAC as detailed in RFC 4543 / NIST SP 800-38D - the MAC-only degenerate case of AES-GCM
    /// where the entire input is authenticated as associated data and no payload is encrypted.
    /// Used by SMB 3.1.1 as an alternative to AES-CMAC for message signing (see [MS-SMB2] Signing Capabilities).
    /// Unlike AES-CMAC, a nonce is required; reusing a nonce with the same key breaks the authentication guarantee,
    /// so callers must ensure each (key, nonce) pair is used to sign at most one message.
    /// </summary>
    public static class AesGmac
    {
        private static readonly byte[] EmptyData = new byte[0];

        public static byte[] CalculateAesGmac(byte[] key, byte[] nonce, byte[] buffer, int offset, int length)
        {
            byte[] data = ByteReader.ReadBytes(buffer, offset, length);
            return CalculateAesGmac(key, nonce, data);
        }

        public static byte[] CalculateAesGmac(byte[] key, byte[] nonce, byte[] data)
        {
            byte[] signature;
            AesGcm.Encrypt(key, nonce, EmptyData, data, 16, out signature);
            return signature;
        }

        public static bool VerifyAesGmac(byte[] key, byte[] nonce, byte[] data, byte[] signature)
        {
            return ByteUtils.AreByteArraysEqual(CalculateAesGmac(key, nonce, data), signature);
        }
    }
}
