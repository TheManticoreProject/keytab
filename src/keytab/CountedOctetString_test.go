package keytab

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func Test_CountedOctetString_FromBytes(t *testing.T) {
	c1 := CountedOctetString{}
	c1.Data, _ = hex.DecodeString("0102030405060708090a0c0b0d0e0f10")
	c1.Length = uint16(len(c1.Data))

	c2 := CountedOctetString{}
	c1Bytes, _ := c1.ToBytes()
	err := c2.FromBytes(c1Bytes)
	if err != nil {
		t.Errorf("Error parsing counted octet string: %v", err)
	}

	if c2.Length != c1.Length {
		t.Errorf("Length mismatch: expected %d, got %d", c1.Length, c2.Length)
	}

	if !bytes.Equal(c1.Data, c2.Data) {
		t.Errorf("Data mismatch: expected %v, got %v", c1.Data, c2.Data)
	}
}
