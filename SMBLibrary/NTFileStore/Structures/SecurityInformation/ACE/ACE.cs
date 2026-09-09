/* Copyright (C) 2014-2024 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-DTYP] ACE (Access Control Entry)
    /// </summary>
    public abstract class ACE
    {
        public AceHeader Header;

        public abstract void WriteBytes(byte[] buffer, ref int offset);

        public abstract int Length
        {
            get;
        }

        public static ACE GetAce(byte[] buffer, int offset)
        {
            if (offset + AceHeader.Length > buffer.Length)
            {
                throw new ArgumentException("Invalid ACE size");
            }

            var aceHeader = new AceHeader(buffer, offset);
            if (offset + aceHeader.AceSize > buffer.Length || aceHeader.AceSize < AceHeader.Length)
            {
                throw new ArgumentException("Invalid ACE size");
            }

            switch (aceHeader.AceType)
            {
                case AceType.ACCESS_ALLOWED_ACE_TYPE:
                    return new AccessAllowedACE(buffer, offset);
                case AceType.ACCESS_DENIED_ACE_TYPE:
                    return new AccessDeniedACE(buffer, offset);
                default:
                    return new UnsupportedACE(buffer, offset);
            }
        }
    }
}
