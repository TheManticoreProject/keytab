package keytab

import (
	"testing"
)

func Test_Keytab_ToBytesFromBytesInvolution(t *testing.T) {
	kt1 := Keytab{}
	kt1.FileFormatVersion = 0x502
	kt1.Entries = []KeytabEntry{
		{
			NumComponents: 1,
			Realm: CountedOctetString{
				Length: 17,
				Data:   []byte("TESTSEGMENT.local"),
			},
			Components: []CountedOctetString{
				{
					Length: 6,
					Data:   []byte("krbtgt"),
				},
			},
			NameType:  0,
			Timestamp: 0,
			Vno8:      0,
			Key: KeyBlock{
				Type: EncryptionType(EncryptionType_AES256_CTS_HMAC_SHA1_96),
				Key: CountedOctetString{
					Length: 16,
					Data:   []byte("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0c\x0b\x0d\x0e\x0f\x10"),
				},
			},
			Vno: 0,
		},
		{
			NumComponents: 1,
			Realm: CountedOctetString{
				Length: 17,
				Data:   []byte("TESTSEGMENT.local"),
			},
			Components: []CountedOctetString{
				{
					Length: 6,
					Data:   []byte("krbtgt"),
				},
			},
			NameType:  0,
			Timestamp: 0,
			Vno8:      0,
			Key: KeyBlock{
				Type: EncryptionType(EncryptionType_AES256_CTS_HMAC_SHA1_96),
				Key: CountedOctetString{
					Length: 16,
					Data:   []byte("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0c\x0b\x0d\x0e\x0f\x10"),
				},
			},
			Vno: 0,
		},
	}
	err := kt1.UpdateEntriesSizes()
	if err != nil {
		t.Errorf("Error updating entries sizes: %v", err)
	}

	kt1Bytes, err := kt1.ToBytes()
	if err != nil {
		t.Errorf("Error converting keytab to bytes: %v", err)
	}

	kt2 := Keytab{}
	err = kt2.FromBytes(kt1Bytes)
	if err != nil {
		t.Errorf("Error converting bytes to keytab: %v", err)
	}

	if !kt1.Equal(&kt2) {
		t.Errorf("Keytab mismatch: expected %+v, got %+v", kt1, kt2)
	}
}
