package keytab

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"keytab/utils"
	"strings"
)

// CountedOctetString represents a counted octet string in a keytab file.
//
// Attributes:
//   - Length (uint16): The length of the counted octet string.
//   - Data ([]byte): The data of the counted octet string.
//   - RawBytes ([]byte): The raw bytes of the counted octet string.
//   - RawBytesSize (uint32): The size of the raw bytes of the counted octet string.
type CountedOctetString struct {
	Length uint16
	Data   []byte
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// FromBytes parses a byte array into a CountedOctetString.
//
// Parameters:
//   - data ([]byte): The byte array to parse.
//
// Returns:
//   - error: An error if the parsing fails.
func (c *CountedOctetString) FromBytes(data []byte) error {
	c.RawBytes = data

	c.Length = binary.BigEndian.Uint16(data[0:2])
	data = data[2:]

	c.Data = data[:c.Length]

	c.RawBytesSize = 2 + uint32(c.Length)

	return nil
}

// ToBytes converts a CountedOctetString to a byte array.
//
// Returns:
//   - []byte: The byte array representation of the CountedOctetString.
//   - error: An error if the conversion fails.
func (c *CountedOctetString) ToBytes() ([]byte, error) {
	if c.Length != uint16(len(c.Data)) {
		return nil, fmt.Errorf("length of data is not equal to the length of the counted octet string")
	}

	data := make([]byte, 0)

	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, c.Length)
	data = append(data, buffer...)

	data = append(data, c.Data...)

	return data, nil
}

// Describe prints the CountedOctetString to the console.
//
// Parameters:
//   - indent (int): The indentation level.
//   - id (int): The ID of the CountedOctetString.
func (c *CountedOctetString) Describe(indent, id int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<CountedOctetString #%d>\n", indentPrompt, id)
	fmt.Printf("%s │ \x1b[93mLength\x1b[0m : \x1b[96m0x%04x\x1b[0m (\x1b[94m%d\x1b[0m)\n", indentPrompt, c.Length, c.Length)
	fmt.Printf("%s │ \x1b[93mData\x1b[0m:\n", indentPrompt)
	fmt.Printf("%s │  │ \x1b[93mHex\x1b[0m : \x1b[96m%s\x1b[0m\n", indentPrompt, hex.EncodeToString(c.Data))
	fmt.Printf("%s │  │ \x1b[93mRaw\x1b[0m : \x1b[96m%s\x1b[0m\n", indentPrompt, utils.BytesToPrintableString(c.Data))
	fmt.Printf("%s │  └─\n", indentPrompt)
	fmt.Printf("%s └─\n", indentPrompt)
}

// Equal checks if two CountedOctetString are equal.
func (c *CountedOctetString) Equal(c2 CountedOctetString) bool {
	if c.Length != c2.Length {
		return false
	}

	if !bytes.Equal(c.Data, c2.Data) {
		return false
	}

	return true
}
