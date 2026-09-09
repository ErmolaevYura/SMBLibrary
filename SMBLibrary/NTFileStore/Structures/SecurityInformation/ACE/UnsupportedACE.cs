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
    public class UnsupportedACE : ACE
    {
        public const int FixedLength = 4;
        public byte[] OpaqueData = new byte[10];

        public UnsupportedACE(byte[] buffer, int offset)
        {
            Header = new AceHeader(buffer, offset + 0);
            var opaqueDataSize = Header.AceSize - FixedLength;
            OpaqueData = new byte[opaqueDataSize];
            Array.Copy(buffer, offset + FixedLength, OpaqueData, 0, opaqueDataSize);
        }

        public override void WriteBytes(byte[] buffer, ref int offset)
        {
            Header.AceSize = (ushort)this.Length;
            Header.WriteBytes(buffer, ref offset);
            ByteWriter.WriteBytes(buffer, ref offset, OpaqueData);
        }

        public override int Length
        {
            get
            {
                return FixedLength + OpaqueData.Length;
            }
        }
    }
}
