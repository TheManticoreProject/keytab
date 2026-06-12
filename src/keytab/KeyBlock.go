package keytab

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// KeyBlock represents a KeyBlock in a keytab file.
//
// Attributes:
//   - Type (EncryptionType): The type of encryption used.
//   - Key (CountedOctetString): The key used.
//   - RawBytes ([]byte): The raw bytes of the keyblock.
//   - RawBytesSize (uint32): The size of the raw bytes of the keyblock.
type KeyBlock struct {
	Type EncryptionType
	Key  CountedOctetString
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// FromBytes parses a byte array into a KeyBlock.
//
// Parameters:
//   - data ([]byte): The byte array to parse.
//
// Returns:
//   - error: An error if the parsing failed.
func (k *KeyBlock) FromBytes(data []byte, order ...binary.ByteOrder) error {
	bo := resolveByteOrder(order)

	k.Type = EncryptionType(bo.Uint16(data[0:2]))
	k.RawBytesSize = 2

	k.Key.FromBytes(data[2:], bo)
	k.RawBytesSize += k.Key.RawBytesSize

	return nil
}

// ToBytes converts a KeyBlock to a byte array.
//
// Returns:
//   - ([]byte, error): The byte array and an error if the conversion failed.
func (k *KeyBlock) ToBytes(order ...binary.ByteOrder) ([]byte, error) {
	bo := resolveByteOrder(order)

	data := make([]byte, 0)

	buffer := make([]byte, 2)
	bo.PutUint16(buffer, uint16(k.Type))
	data = append(data, buffer...)

	keyBytes, err := k.Key.ToBytes(bo)
	if err != nil {
		return nil, err
	}
	data = append(data, keyBytes...)

	return data, nil
}

// Describe prints the KeyBlock to the console.
//
// Parameters:
//   - indent (int): The indentation level.
func (k *KeyBlock) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<KeyBlock>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mType\x1b[0m : \x1b[96m0x%04x\x1b[0m (\x1b[94m%s\x1b[0m) (\x1b[94m%d\x1b[0m)\n", indentPrompt, uint16(k.Type), k.Type.String(), uint16(k.Type))
	fmt.Printf("%s │ \x1b[93mKey\x1b[0m  :\n", indentPrompt)
	k.Key.Describe(indent+2, 0)
	fmt.Printf("%s └─\n", indentPrompt)
}

// Equal checks if two KeyBlock structs are equal.
//
// Parameters:
//   - k2 (KeyBlock): The KeyBlock to compare to.
//
// Returns:
//   - bool: True if the KeyBlock structs are equal, false otherwise.
func (k *KeyBlock) Equal(k2 KeyBlock) bool {
	return k.Type == k2.Type && k.Key.Equal(k2.Key)
}
