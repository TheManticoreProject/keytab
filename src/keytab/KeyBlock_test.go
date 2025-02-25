package keytab

import (
	"encoding/hex"
	"testing"
)

func Test_KeyBlock_ToBytesFromBytesInvolution(t *testing.T) {
	k1 := KeyBlock{}
	k1.Type = EncryptionType(EncryptionType_AES128_CTS_HMAC_SHA256_128)
	k1KeyBytes, err := hex.DecodeString("00100102030405060708090a0c0b0d0e0f10")
	if err != nil {
		t.Errorf("Error decoding key block: %v", err)
	}
	k1.Key.FromBytes(k1KeyBytes)

	k2 := KeyBlock{}
	k1Bytes, _ := k1.ToBytes()
	err = k2.FromBytes(k1Bytes)
	if err != nil {
		t.Errorf("Error parsing key block: %v", err)
	}

	if k2.Type != k1.Type {
		t.Errorf("Type mismatch: expected %d, got %d", k1.Type, k2.Type)
	}

	if !k1.Key.Equal(k2.Key) {
		t.Errorf("Data mismatch: expected %v, got %v", k1.Key.Data, k2.Key.Data)
	}
}
