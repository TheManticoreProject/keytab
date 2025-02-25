package keytab

type EncryptionType uint16

const (
	EncryptionType_NULL EncryptionType = 0x0000

	EncryptionType_DES_CBC_CRC EncryptionType = 0x0001
	EncryptionType_DES_CBC_MD4 EncryptionType = 0x0002
	EncryptionType_DES_CBC_MD5 EncryptionType = 0x0003

	EncryptionType_RESERVED_OLD_RC4_HMAC EncryptionType = 0x0004 // old RC4-HMAC

	EncryptionType_DES3_CBC_MD5      EncryptionType = 0x0005
	EncryptionType_DES3_CBC_SHA1     EncryptionType = 0x0010
	EncryptionType_DES3_HMAC_SHA1_KD EncryptionType = 0x0010

	EncryptionType_RC4_HMAC     EncryptionType = 0x0017
	EncryptionType_RC4_HMAC_EXP EncryptionType = 0x0018

	EncryptionType_CAMELLIA128_CTS_CMAC EncryptionType = 0x0019
	EncryptionType_CAMELLIA256_CTS_CMAC EncryptionType = 0x001A

	EncryptionType_AES128_CTS_HMAC_SHA1_96    EncryptionType = 0x0011
	EncryptionType_AES256_CTS_HMAC_SHA1_96    EncryptionType = 0x0012
	EncryptionType_AES128_CTS_HMAC_SHA256_128 EncryptionType = 0x0013
	EncryptionType_AES256_CTS_HMAC_SHA384_192 EncryptionType = 0x0014
)

// EncryptionTypeMap is a map of EncryptionType to its string representation.
var EncryptionTypeMap = map[EncryptionType]string{
	EncryptionType_NULL:                       "NULL",
	EncryptionType_DES_CBC_CRC:                "DES-CBC-CRC",
	EncryptionType_DES_CBC_MD4:                "DES-CBC-MD4",
	EncryptionType_DES_CBC_MD5:                "DES-CBC-MD5",
	EncryptionType_RESERVED_OLD_RC4_HMAC:      "RESERVED-OLD-RC4-HMAC",
	EncryptionType_DES3_CBC_MD5:               "DES3-CBC-MD5",
	EncryptionType_DES3_CBC_SHA1:              "DES3-CBC-SHA1",
	EncryptionType_RC4_HMAC:                   "RC4-HMAC",
	EncryptionType_RC4_HMAC_EXP:               "RC4-HMAC-EXP",
	EncryptionType_CAMELLIA128_CTS_CMAC:       "CAMELLIA128-CTS-CMAC",
	EncryptionType_CAMELLIA256_CTS_CMAC:       "CAMELLIA256-CTS-CMAC",
	EncryptionType_AES128_CTS_HMAC_SHA1_96:    "AES128-CTS-HMAC-SHA1-96",
	EncryptionType_AES256_CTS_HMAC_SHA1_96:    "AES256-CTS-HMAC-SHA1-96",
	EncryptionType_AES128_CTS_HMAC_SHA256_128: "AES128-CTS-HMAC-SHA256-128",
	EncryptionType_AES256_CTS_HMAC_SHA384_192: "AES256-CTS-HMAC-SHA384-192",
}

// String returns the string representation of the EncryptionType.
//
// Parameters:
//   - k (EncryptionType): The EncryptionType to convert to a string.
//
// Returns:
//   - string: The string representation of the EncryptionType.
func (k EncryptionType) String() string {
	return EncryptionTypeMap[k]
}
