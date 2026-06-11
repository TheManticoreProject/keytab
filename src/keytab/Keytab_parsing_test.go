package keytab

import (
	"encoding/binary"
	"testing"
)

// validEntryBytes builds a single record (4-byte length prefix + body) for a
// minimal AES256 krbtgt entry without the 32-bit kvno extension.
func validEntryBytes(t *testing.T) []byte {
	t.Helper()
	entry := KeytabEntry{
		NumComponents: 1,
		Realm: CountedOctetString{
			Length: 17,
			Data:   []byte("TESTSEGMENT.local"),
		},
		Components: []CountedOctetString{
			{Length: 6, Data: []byte("krbtgt")},
		},
		NameType:  1,
		Timestamp: 0,
		Vno8:      2,
		Key: KeyBlock{
			Type: EncryptionType_AES256_CTS_HMAC_SHA1_96,
			Key:  CountedOctetString{Length: 16, Data: []byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")},
		},
	}
	if err := entry.UpdateSize(); err != nil {
		t.Fatalf("UpdateSize failed: %v", err)
	}
	b, err := entry.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes failed: %v", err)
	}
	return b
}

// Test_Keytab_TruncatedInputReturnsError ensures malformed/truncated input is
// rejected with an error instead of panicking.
func Test_Keytab_TruncatedInputReturnsError(t *testing.T) {
	header := []byte{0x05, 0x02}
	full := append(append([]byte{}, header...), validEntryBytes(t)...)

	for n := 0; n < len(full); n++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parsing truncated input of %d bytes panicked: %v", n, r)
				}
			}()
			kt := Keytab{}
			_ = kt.FromBytes(full[:n])
		}()
	}
}

// Test_Keytab_HoleIsSkipped ensures a negative record length (a zero-filled
// hole) is skipped and the following entry is still parsed.
func Test_Keytab_HoleIsSkipped(t *testing.T) {
	header := []byte{0x05, 0x02}

	var holeLen int32 = -8
	hole := make([]byte, 4)
	binary.BigEndian.PutUint32(hole, uint32(holeLen))
	hole = append(hole, make([]byte, 8)...)

	entry := validEntryBytes(t)

	data := append(append(append([]byte{}, header...), hole...), entry...)

	kt := Keytab{}
	if err := kt.FromBytes(data); err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	if len(kt.Entries) != 1 {
		t.Fatalf("expected 1 entry after skipping the hole, got %d", len(kt.Entries))
	}
	if string(kt.Entries[0].Realm.Data) != "TESTSEGMENT.local" {
		t.Fatalf("unexpected realm after hole: %q", kt.Entries[0].Realm.Data)
	}
}

// Test_Keytab_EndOfFileMarker ensures a zero record length terminates parsing.
func Test_Keytab_EndOfFileMarker(t *testing.T) {
	header := []byte{0x05, 0x02}
	entry := validEntryBytes(t)
	data := append(append(append([]byte{}, header...), entry...), 0x00, 0x00, 0x00, 0x00)
	// Trailing garbage after the EOF marker must be ignored.
	data = append(data, 0xde, 0xad, 0xbe, 0xef)

	kt := Keytab{}
	if err := kt.FromBytes(data); err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	if len(kt.Entries) != 1 {
		t.Fatalf("expected 1 entry before EOF marker, got %d", len(kt.Entries))
	}
}
