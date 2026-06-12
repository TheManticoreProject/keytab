package keytab

import "encoding/binary"

// Keytab file format versions. The first header byte is always 0x05; the second
// byte is the version number, so the 16-bit header reads as 0x0501 or 0x0502.
const (
	FileFormatVersion1 uint16 = 0x0501
	FileFormatVersion2 uint16 = 0x0502
)

// nameTypePrincipal is the KRB5_NT_PRINCIPAL name type. It is used as the
// in-memory default for version-1 entries, which do not store a name_type on
// disk.
const nameTypePrincipal uint32 = 1

// isVersion1 reports whether the given file format version is version 1, which
// differs from version 2 in byte order, component count, and name_type
// presence. Only the low byte (the version number) is significant.
func isVersion1(version uint16) bool {
	return version&0x00ff == 0x01
}

// byteOrderForVersion returns the integer byte order used by the given keytab
// file format version. Version 1 uses native byte order, which in practice is
// little-endian (version 1 predates the big-endian convention introduced in
// version 2 specifically to remove this ambiguity); every other version uses
// big-endian.
func byteOrderForVersion(version uint16) binary.ByteOrder {
	if isVersion1(version) {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// resolveVersion returns the version from an optional variadic argument,
// defaulting to version 2 when none is supplied or the supplied value is zero.
// This lets the entry (de)serialization methods stay backward compatible: an
// existing call with no version behaves exactly as before (version 2).
func resolveVersion(version []uint16) uint16 {
	if len(version) > 0 && version[0] != 0 {
		return version[0]
	}
	return FileFormatVersion2
}

// resolveByteOrder returns the byte order from an optional variadic argument,
// defaulting to big-endian (version 2) when none is supplied. This keeps the
// counted-octet-string and key-block (de)serialization methods backward
// compatible with callers that do not pass a byte order.
func resolveByteOrder(order []binary.ByteOrder) binary.ByteOrder {
	if len(order) > 0 && order[0] != nil {
		return order[0]
	}
	return binary.BigEndian
}
