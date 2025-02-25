package keytab

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_KeytabEntry_ToBytesFromBytesInvolution(t *testing.T) {
	entry1 := KeytabEntry{
		Size:          0,
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
	}
	entry1.Size = 0
	err := entry1.UpdateSize()
	if err != nil {
		t.Errorf("Error updating size: %v", err)
	}
	entry1Bytes, _ := entry1.ToBytes()

	entry2 := KeytabEntry{}
	entry2.FromBytes(entry1Bytes)
	entry2Bytes, _ := entry2.ToBytes()

	if !bytes.Equal(entry1Bytes, entry2Bytes) {
		t.Errorf("entry2.FromBytes(entry1Bytes) is not equal to Entry1.ToBytes().")
		fmt.Printf("entry1: %s\n", hex.EncodeToString(entry1Bytes))
		fmt.Printf("entry2: %s\n", hex.EncodeToString(entry2Bytes))
	}
}

func Test_KeytabEntry_Equal(t *testing.T) {
	entry1 := KeytabEntry{
		Size:          0,
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
	}

	entry2 := KeytabEntry{
		Size:          0,
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
	}

	if !entry1.Equal(entry2) {
		t.Errorf("entry1.Equal(entry2) is not true.")
	}
}
