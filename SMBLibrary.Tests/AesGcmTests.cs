/* Copyright (C) 2020-2026 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Utilities;

namespace SMBLibrary.Tests
{
    [TestClass]
    public class AesGcmTests
    {
#if NET6_0_OR_GREATER
        [TestMethod]
        // Cross-checks the hand-rolled implementation (needed because SMBLibrary/Utilities also target net20 / net40 /
        // netstandard2.0, which lack System.Security.Cryptography.AesGcm) against the BCL's own AES-GCM, which is
        // available on the net6.0+ targets this test project also builds for.
        public void TestEncryption_MatchesBclAesGcm_Aes128()
        {
            AssertMatchesBclForAllLengths(new byte[16]);
        }

        [TestMethod]
        public void TestEncryption_MatchesBclAesGcm_Aes256()
        {
            AssertMatchesBclForAllLengths(new byte[32]);
        }

        private static void AssertMatchesBclForAllLengths(byte[] key)
        {
            new Random(42).NextBytes(key);
            byte[] nonce = new byte[12];
            new Random(43).NextBytes(nonce);
            byte[] associatedData = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

            foreach (int length in new int[] { 0, 1, 15, 16, 17, 33, 100 })
            {
                byte[] data = new byte[length];
                new Random(length + 1).NextBytes(data);

                byte[] signature;
                byte[] cipherText = Utilities.AesGcm.Encrypt(key, nonce, data, associatedData, 16, out signature);

                byte[] expectedCipherText = new byte[length];
                byte[] expectedTag = new byte[16];
                using (System.Security.Cryptography.AesGcm bclAesGcm = new System.Security.Cryptography.AesGcm(key, 16))
                {
                    bclAesGcm.Encrypt(nonce, data, expectedCipherText, expectedTag, associatedData);
                }

                Assert.IsTrue(ByteUtils.AreByteArraysEqual(expectedCipherText, cipherText), "Ciphertext mismatch for length " + length);
                Assert.IsTrue(ByteUtils.AreByteArraysEqual(expectedTag, signature), "Tag mismatch for length " + length);
            }
        }
#endif

        [TestMethod]
        public void TestRoundTrip_Aes128_WithAssociatedData_VariousLengths()
        {
            AssertRoundTripForAllLengths(new byte[16]);
        }

        [TestMethod]
        public void TestRoundTrip_Aes256_WithAssociatedData_VariousLengths()
        {
            AssertRoundTripForAllLengths(new byte[32]);
        }

        [TestMethod]
        public void TestDecryption_TamperedCipherText_ThrowsCryptographicException()
        {
            byte[] key = new byte[16];
            byte[] nonce = new byte[12];
            new Random(1).NextBytes(key);
            new Random(2).NextBytes(nonce);
            byte[] associatedData = new byte[] { 1, 2, 3, 4 };
            byte[] data = new byte[] { 10, 20, 30, 40, 50 };

            byte[] signature;
            byte[] cipherText = Utilities.AesGcm.Encrypt(key, nonce, data, associatedData, 16, out signature);
            cipherText[0] ^= 0xFF;

            Assert.ThrowsException<CryptographicException>(() =>
                Utilities.AesGcm.DecryptAndAuthenticate(key, nonce, cipherText, associatedData, signature));
        }

        private static void AssertRoundTripForAllLengths(byte[] key)
        {
            new Random(42).NextBytes(key);
            byte[] nonce = new byte[12];
            new Random(43).NextBytes(nonce);
            byte[] associatedData = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

            foreach (int length in new int[] { 0, 1, 15, 16, 17, 33, 100 })
            {
                byte[] data = new byte[length];
                new Random(length + 1).NextBytes(data);

                byte[] signature;
                byte[] cipherText = Utilities.AesGcm.Encrypt(key, nonce, data, associatedData, 16, out signature);
                byte[] decrypted = Utilities.AesGcm.DecryptAndAuthenticate(key, nonce, cipherText, associatedData, signature);

                Assert.IsTrue(ByteUtils.AreByteArraysEqual(data, decrypted), "Round-trip mismatch for length " + length);
            }
        }
    }
}
