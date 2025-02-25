package keytab

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

// Keytab represents a keytab file.
//
// Attributes:
//   - FileFormatVersion (uint16): The version of the keytab file format.
//   - Entries ([]KeytabEntry): The entries in the keytab file.
//   - RawBytes ([]byte): The raw bytes of the keytab file.
//   - RawBytesSize (uint32): The size of the raw bytes of the keytab file.
type Keytab struct {
	FileFormatVersion uint16
	Entries           []KeytabEntry
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// FromBytes parses a byte array into a Keytab.
//
// Parameters:
//   - data ([]byte): The byte array to parse.
//
// Returns:
//   - error: An error if the parsing failed.
func (k *Keytab) FromBytes(data []byte) error {
	k.RawBytes = data
	k.RawBytesSize = 0

	k.FileFormatVersion = binary.BigEndian.Uint16(data[0:2])
	data = data[2:]
	k.RawBytesSize += 2

	k.Entries = make([]KeytabEntry, 0)

	for len(data) != 0 {
		entry := KeytabEntry{}
		entry.FromBytes(data)
		data = data[entry.RawBytesSize:]
		k.Entries = append(k.Entries, entry)
		k.RawBytesSize += entry.RawBytesSize
	}

	k.RawBytes = k.RawBytes[:k.RawBytesSize]

	return nil
}

// ToBytes converts a Keytab to a byte array.
//
// Returns:
//   - ([]byte, error): The byte array and an error if the conversion failed.
func (k *Keytab) ToBytes() ([]byte, error) {
	data := make([]byte, 0)

	buffer2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer2, k.FileFormatVersion)
	data = append(data, buffer2...)

	for _, entry := range k.Entries {
		entryBytes, err := entry.ToBytes()
		if err != nil {
			return nil, err
		}
		data = append(data, entryBytes...)
	}

	return data, nil
}

// UpdateEntriesSizes updates the size of each entry in the keytab.
//
// Returns:
//   - error: An error if the update fails.
func (k *Keytab) UpdateEntriesSizes() error {
	for i := range k.Entries {
		err := k.Entries[i].UpdateSize()
		if err != nil {
			return err
		}
	}
	return nil
}

// Equal checks if two Keytab structs are equal.
//
// Parameters:
//   - other (*Keytab): The other Keytab struct to compare.
//
// Returns:
//   - bool: True if the Keytab structs are equal, false otherwise.
func (k *Keytab) Equal(other *Keytab) bool {
	if k.FileFormatVersion != other.FileFormatVersion {
		return false
	}

	if len(k.Entries) != len(other.Entries) {
		return false
	}

	for i := range k.Entries {
		if !k.Entries[i].Equal(other.Entries[i]) {
			return false
		}
	}

	return true
}

// LoadKeytabFromFile loads a Keytab from a file.
//
// Parameters:
//   - path (string): The path to the keytab file.
//
// Returns:
//   - (*Keytab, error): The Keytab struct and an error if the file could not be read.
func LoadKeytabFromFile(path string) (*Keytab, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	keytab := &Keytab{}
	err = keytab.FromBytes(data)
	if err != nil {
		return nil, err
	}

	return keytab, nil
}

// Describe prints a detailed description of the Keytab struct,
// including its attributes formatted with indentation for clarity.
//
// Parameters:
//   - indent (int): The indentation level for formatting the output. Each level increases
//     the indentation depth, allowing for a hierarchical display of the entry's components.
func (k *Keytab) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<Keytab>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mFileFormatVersion\x1b[0m : \x1b[96m0x%04x\x1b[0m (\x1b[94m%d\x1b[0m)\n", indentPrompt, k.FileFormatVersion, k.FileFormatVersion)
	fmt.Printf("%s │ \x1b[93mEntries\x1b[0m           : \x1b[96m%d\x1b[0m\n", indentPrompt, len(k.Entries))
	for i, entry := range k.Entries {
		entry.Describe(indent+1, i)
	}
	fmt.Printf("%s └─\n", indentPrompt)
}

// SaveToFile saves the Keytab struct to a file.
//
// Parameters:
//   - path (string): The path to the file to save the Keytab struct to.
//
// Returns:
//   - error: An error if the saving failed.
func (k *Keytab) SaveToFile(path string) error {
	data, err := k.ToBytes()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// AddKey adds a new key to the keytab file.
//
// Parameters:
//   - principal (string): The principal to add.
//   - key (string): The key to add.
//   - password (string): The password to add.
func (k *Keytab) AddKey(principal string, key string, password string) {
	// entry := KeytabEntry{}
	// entry.AddKey(principal, key, password)
	// k.Entries = append(k.Entries, entry)
}

// DeleteKey deletes a key from the keytab file.
//
// Parameters:
//   - principal (string): The principal to delete.
func (k *Keytab) DeleteKey(principal string) {
	// for i, entry := range k.Entries {
	// 	if entry.Principal == principal {
	// 		k.Entries = append(k.Entries[:i], k.Entries[i+1:]...)
	// 		break
	// 	}
	// }
}

// Export exports the keytab file to a file.
//
// Parameters:
//   - path (string): The path to the file to save the keytab file to.
//   - jsonOutput (bool): Whether to export the keytab file to a JSON file.
//   - txtOutput (bool): Whether to export the keytab file to a TXT file.
//   - csvOutput (bool): Whether to export the keytab file to a CSV file.
func (k *Keytab) Export(path string, jsonOutput, txtOutput, csvOutput bool) error {
	data, err := k.ToBytes()
	if err != nil {
		return err
	}

	if jsonOutput {
		os.WriteFile(path, data, 0644)
	}

	if txtOutput {
		os.WriteFile(path, data, 0644)
	}

	if csvOutput {
		os.WriteFile(path, data, 0644)
	}

	return nil
}
