namespace SMBLibrary.SMB2
{
    public enum SigningAlgorithm : ushort
    {
        HMACSHA256 = 0x0000,
        AESCMAC = 0x0001,
        AESGMAC = 0x0002
    }
}
