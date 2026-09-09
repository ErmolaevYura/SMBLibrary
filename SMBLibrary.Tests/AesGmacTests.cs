/* Copyright (C) 2020-2026 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Utilities;

namespace SMBLibrary.Tests
{
    [TestClass]
    public class AesGmacTests
    {
#if NET6_0_OR_GREATER
        [TestMethod]
        // Cross-checks the hand-rolled implementation against the BCL's own AES-GCM used in its degenerate
        // GMAC form (empty payload, message passed as associated data), which is available on the net6.0+
        // targets this test project also builds for.
        public void TestCalculateAesGmac_MatchesBclAesGcmAsGmac_Aes128()
        {
            AssertMatchesBclForAllLengths(new byte[16]);
        }

        [TestMethod]
        public void TestCalculateAesGmac_MatchesBclAesGcmAsGmac_Aes256()
        {
            AssertMatchesBclForAllLengths(new byte[32]);
        }

        private static void AssertMatchesBclForAllLengths(byte[] key)
        {
            new Random(42).NextBytes(key);
            byte[] nonce = new byte[12];
            new Random(43).NextBytes(nonce);

            foreach (int length in new int[] { 0, 1, 15, 16, 17, 33, 100 })
            {
                byte[] data = new byte[length];
                new Random(length + 1).NextBytes(data);

                byte[] tag = AesGmac.CalculateAesGmac(key, nonce, data);

                byte[] expectedTag = new byte[16];
                using (System.Security.Cryptography.AesGcm bclAesGcm = new System.Security.Cryptography.AesGcm(key, 16))
                {
                    bclAesGcm.Encrypt(nonce, Array.Empty<byte>(), Array.Empty<byte>(), expectedTag, data);
                }

                Assert.IsTrue(ByteUtils.AreByteArraysEqual(expectedTag, tag), "Tag mismatch for length " + length);
            }
        }
#endif

        [TestMethod]
        public void TestVerifyAesGmac_ValidSignature_ReturnsTrue()
        {
            byte[] key = new byte[16];
            byte[] nonce = new byte[12];
            new Random(1).NextBytes(key);
            new Random(2).NextBytes(nonce);
            byte[] data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            byte[] signature = AesGmac.CalculateAesGmac(key, nonce, data);

            Assert.IsTrue(AesGmac.VerifyAesGmac(key, nonce, data, signature));
        }

        [TestMethod]
        public void TestVerifyAesGmac_TamperedData_ReturnsFalse()
        {
            byte[] key = new byte[16];
            byte[] nonce = new byte[12];
            new Random(3).NextBytes(key);
            new Random(4).NextBytes(nonce);
            byte[] data = new byte[] { 1, 2, 3, 4, 5 };

            byte[] signature = AesGmac.CalculateAesGmac(key, nonce, data);
            data[0] ^= 0xFF;

            Assert.IsFalse(AesGmac.VerifyAesGmac(key, nonce, data, signature));
        }

        [TestMethod]
        public void TestCalculateAesGmac_BufferOffsetLengthOverload_MatchesDataOverload()
        {
            byte[] key = new byte[16];
            byte[] nonce = new byte[12];
            new Random(5).NextBytes(key);
            new Random(6).NextBytes(nonce);
            byte[] payload = new byte[] { 9, 9, 1, 2, 3, 4, 5, 9, 9 };

            byte[] tagFromSlice = AesGmac.CalculateAesGmac(key, nonce, payload, 2, 5);
            byte[] tagFromData = AesGmac.CalculateAesGmac(key, nonce, new byte[] { 1, 2, 3, 4, 5 });

            Assert.IsTrue(ByteUtils.AreByteArraysEqual(tagFromSlice, tagFromData));
        }
    }
}
