package keytab

import "testing"

func Test_KeyBlockType_String(t *testing.T) {
	k := EncryptionType(EncryptionType_AES256_CTS_HMAC_SHA1_96)
	if k.String() != "AES256-CTS-HMAC-SHA1-96" {
		t.Errorf("Expected AES256-CTS-HMAC-SHA1-96, got %s", k.String())
	}
}
