package keytab

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// makeV1EntryRecord builds, by hand, the raw bytes of a single version-1 keytab
// entry record (little-endian, realm counted in num_components, no name_type)
// for a "foo@ACME" principal with an RC4 key of 0xAABB and a 32-bit vno of 9.
func makeV1EntryRecord() []byte {
	le := binary.LittleEndian
	body := []byte{}

	put16 := func(v uint16) { b := make([]byte, 2); le.PutUint16(b, v); body = append(body, b...) }
	put32 := func(v uint32) { b := make([]byte, 4); le.PutUint32(b, v); body = append(body, b...) }

	put16(2) // num_components: 1 name component + the realm
	put16(4) // realm length
	body = append(body, []byte("ACME")...)
	put16(3) // component length
	body = append(body, []byte("foo")...)
	// no name_type in version 1
	put32(0x11223344) // timestamp
	body = append(body, 0x05) // vno8
	put16(uint16(EncryptionType_RC4_HMAC))
	put16(2) // key length
	body = append(body, 0xAA, 0xBB)
	put32(9) // 32-bit vno

	size := make([]byte, 4)
	le.PutUint32(size, uint32(len(body)))
	return append(size, body...)
}

// Test_KeytabEntry_Version1_Parse parses a hand-built version-1 record and
// verifies the byte order, the component-count adjustment, and the absence of
// name_type are all handled.
func Test_KeytabEntry_Version1_Parse(t *testing.T) {
	rec := makeV1EntryRecord()

	entry := KeytabEntry{}
	if err := entry.FromBytes(rec, FileFormatVersion1); err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}

	if entry.NumComponents != 1 {
		t.Errorf("NumComponents: expected 1 (realm subtracted), got %d", entry.NumComponents)
	}
	if string(entry.Realm.Data) != "ACME" {
		t.Errorf("Realm: expected ACME, got %q", entry.Realm.Data)
	}
	if len(entry.Components) != 1 || string(entry.Components[0].Data) != "foo" {
		t.Errorf("Components: expected [foo], got %v", entry.Components)
	}
	if entry.NameType != nameTypePrincipal {
		t.Errorf("NameType: expected default %d, got %d", nameTypePrincipal, entry.NameType)
	}
	if entry.Timestamp != 0x11223344 {
		t.Errorf("Timestamp: expected 0x11223344, got 0x%08x", entry.Timestamp)
	}
	if entry.Vno8 != 0x05 {
		t.Errorf("Vno8: expected 5, got %d", entry.Vno8)
	}
	if entry.Key.Type != EncryptionType_RC4_HMAC {
		t.Errorf("Key.Type: expected RC4_HMAC, got %d", entry.Key.Type)
	}
	if !bytes.Equal(entry.Key.Key.Data, []byte{0xAA, 0xBB}) {
		t.Errorf("Key data: expected aabb, got % x", entry.Key.Key.Data)
	}
	if entry.Vno != 9 {
		t.Errorf("Vno: expected 9, got %d", entry.Vno)
	}
}

// Test_KeytabEntry_Version1_RoundTrip verifies a hand-built version-1 record
// serializes back to the identical bytes.
func Test_KeytabEntry_Version1_RoundTrip(t *testing.T) {
	rec := makeV1EntryRecord()

	entry := KeytabEntry{}
	if err := entry.FromBytes(rec, FileFormatVersion1); err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}

	out, err := entry.ToBytes(FileFormatVersion1)
	if err != nil {
		t.Fatalf("ToBytes failed: %v", err)
	}
	if !bytes.Equal(rec, out) {
		t.Fatalf("version-1 round-trip changed the bytes:\n in (%d): % x\nout (%d): % x", len(rec), rec, len(out), out)
	}
}

// Test_Keytab_Version1_FileRoundTrip builds a full version-1 keytab in memory,
// serializes it, parses it back, and verifies equality and the on-disk header.
func Test_Keytab_Version1_FileRoundTrip(t *testing.T) {
	kt := Keytab{FileFormatVersion: FileFormatVersion1}
	kt.Entries = []KeytabEntry{
		{
			NumComponents: 1,
			Realm:         CountedOctetString{Length: 4, Data: []byte("ACME")},
			Components:    []CountedOctetString{{Length: 3, Data: []byte("foo")}},
			NameType:      nameTypePrincipal,
			Timestamp:     0x11223344,
			Vno8:          5,
			Key: KeyBlock{
				Type: EncryptionType_RC4_HMAC,
				Key:  CountedOctetString{Length: 2, Data: []byte{0xAA, 0xBB}},
			},
			Vno: 9,
		},
	}
	if err := kt.UpdateEntriesSizes(); err != nil {
		t.Fatalf("UpdateEntriesSizes failed: %v", err)
	}

	out, err := kt.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes failed: %v", err)
	}
	if out[0] != 0x05 || out[1] != 0x01 {
		t.Fatalf("expected version-1 header 0x05 0x01, got 0x%02x 0x%02x", out[0], out[1])
	}
	// The on-disk component count is little-endian and includes the realm.
	if got := binary.LittleEndian.Uint16(out[6:8]); got != 2 {
		t.Fatalf("on-disk num_components: expected 2 (1 component + realm), got %d", got)
	}

	kt2 := Keytab{}
	if err := kt2.FromBytes(out); err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	if !kt.Equal(&kt2) {
		t.Fatalf("version-1 keytab mismatch:\nexpected %+v\ngot %+v", kt, kt2)
	}
}

// Test_KeytabEntry_Version1_OmitsNameType verifies a version-1 entry is exactly
// 4 bytes shorter than the version-2 encoding of the same logical entry (the
// missing 32-bit name_type field).
func Test_KeytabEntry_Version1_OmitsNameType(t *testing.T) {
	entry := KeytabEntry{
		NumComponents: 1,
		Realm:         CountedOctetString{Length: 4, Data: []byte("ACME")},
		Components:    []CountedOctetString{{Length: 3, Data: []byte("foo")}},
		NameType:      nameTypePrincipal,
		Timestamp:     0x11223344,
		Vno8:          5,
		Key: KeyBlock{
			Type: EncryptionType_RC4_HMAC,
			Key:  CountedOctetString{Length: 2, Data: []byte{0xAA, 0xBB}},
		},
		Vno: 9,
	}

	v1Bytes, err := entry.ToBytes(FileFormatVersion1)
	if err != nil {
		t.Fatalf("v1 ToBytes failed: %v", err)
	}
	v2Bytes, err := entry.ToBytes(FileFormatVersion2)
	if err != nil {
		t.Fatalf("v2 ToBytes failed: %v", err)
	}

	if len(v2Bytes)-len(v1Bytes) != 4 {
		t.Fatalf("expected version-1 entry to be 4 bytes shorter (no name_type): v1=%d v2=%d", len(v1Bytes), len(v2Bytes))
	}
}
