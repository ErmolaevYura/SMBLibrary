/* Copyright (C) 2026 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System.Security.Cryptography;

namespace Utilities
{
    /// <summary>
    /// Shared cryptographically-secure random byte source. Use this instead of System.Random for any
    /// security-sensitive value (nonces, salts, session keys) - System.Random is seeded from the clock
    /// and is not suitable where predictability would compromise confidentiality or integrity.
    /// </summary>
    public static class SecureRandom
    {
        private static readonly RandomNumberGenerator s_rng = RandomNumberGenerator.Create();

        public static void GetBytes(byte[] buffer)
        {
            s_rng.GetBytes(buffer);
        }

        public static byte[] GetBytes(int length)
        {
            byte[] buffer = new byte[length];
            s_rng.GetBytes(buffer);
            return buffer;
        }
    }
}
