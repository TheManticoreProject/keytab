package keytab

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// rawEntry builds the raw bytes of a keytab entry record, optionally appending
// the 32-bit kvno extension.
func rawEntry(withKvno bool, kvno uint32) []byte {
	body := []byte{}

	put16 := func(v uint16) { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); body = append(body, b...) }
	put32 := func(v uint32) { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); body = append(body, b...) }

	put16(1)                          // NumComponents
	put16(17)                         // Realm length
	body = append(body, []byte("TESTSEGMENT.local")...)
	put16(6)                          // Component length
	body = append(body, []byte("krbtgt")...)
	put32(1)                          // NameType
	put32(0)                          // Timestamp
	body = append(body, 0x02)         // Vno8
	put16(uint16(EncryptionType_RC4_HMAC))
	put16(16)                         // Key length
	body = append(body, bytes.Repeat([]byte{0x23}, 16)...)
	if withKvno {
		put32(kvno)
	}

	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...)
}

// Test_KeytabEntry_NoKvnoRoundTrip ensures an entry parsed without the 32-bit
// kvno extension serializes back to the identical bytes (no spurious 4 bytes).
func Test_KeytabEntry_NoKvnoRoundTrip(t *testing.T) {
	in := rawEntry(false, 0)

	entry := KeytabEntry{}
	if err := entry.FromBytes(in); err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	if entry.HasVno {
		t.Fatalf("HasVno should be false for an entry without the kvno extension")
	}

	out, err := entry.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes failed: %v", err)
	}
	if !bytes.Equal(in, out) {
		t.Fatalf("round-trip changed the bytes:\n in (%d): % x\nout (%d): % x", len(in), in, len(out), out)
	}
}

// Test_KeytabEntry_KvnoRoundTrip ensures the 32-bit kvno extension is preserved
// across a parse/serialize round-trip.
func Test_KeytabEntry_KvnoRoundTrip(t *testing.T) {
	in := rawEntry(true, 0x01020304)

	entry := KeytabEntry{}
	if err := entry.FromBytes(in); err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	if !entry.HasVno {
		t.Fatalf("HasVno should be true for an entry with the kvno extension")
	}
	if entry.Vno != 0x01020304 {
		t.Fatalf("expected Vno 0x01020304, got 0x%08x", entry.Vno)
	}

	out, err := entry.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes failed: %v", err)
	}
	if !bytes.Equal(in, out) {
		t.Fatalf("round-trip changed the bytes:\n in (%d): % x\nout (%d): % x", len(in), in, len(out), out)
	}
}
