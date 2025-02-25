package keytab

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// KeytabEntry represents a single entry in a keytab file.
type KeytabEntry struct {
	Size          uint32
	NumComponents uint16
	Realm         CountedOctetString
	Components    []CountedOctetString
	NameType      uint32
	Timestamp     uint32
	Vno8          uint8
	Key           KeyBlock
	Vno           uint32
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// FromBytes parses a byte array into a KeytabEntry.
//
// Parameters:
//   - data ([]byte): The byte array to parse into a KeytabEntry.
//
// Returns:
//   - error: An error if the parsing fails.
func (k *KeytabEntry) FromBytes(data []byte) error {
	k.RawBytesSize = 0
	k.RawBytes = data

	// Size
	k.Size = binary.BigEndian.Uint32(data[0:4])
	data = data[4:]
	data = data[:k.Size]
	k.RawBytesSize += 4

	// NumComponents
	k.NumComponents = binary.BigEndian.Uint16(data[0:2])
	data = data[2:]
	k.RawBytesSize += 2

	// Realm
	k.Realm = CountedOctetString{}
	k.Realm.FromBytes(data)
	data = data[k.Realm.RawBytesSize:]
	k.RawBytesSize += k.Realm.RawBytesSize

	// Components
	for i := uint16(0); i < k.NumComponents; i++ {
		component := CountedOctetString{}
		component.FromBytes(data)
		k.Components = append(k.Components, component)
		data = data[component.RawBytesSize:]
		k.RawBytesSize += component.RawBytesSize
	}

	// NameType
	k.NameType = binary.BigEndian.Uint32(data[0:4])
	data = data[4:]
	k.RawBytesSize += 4

	// Timestamp
	k.Timestamp = binary.BigEndian.Uint32(data[0:4])
	data = data[4:]
	k.RawBytesSize += 4

	// Vno8
	k.Vno8 = data[0]
	data = data[1:]
	k.RawBytesSize += 1

	// Key
	k.Key.FromBytes(data)
	data = data[k.Key.RawBytesSize:]
	k.RawBytesSize += k.Key.RawBytesSize

	// Vno
	if len(data) >= 4 {
		k.Vno = binary.BigEndian.Uint32(data[0:4])
		k.RawBytesSize += 4
		// data = data[4:]
	} else {
		k.Vno = 0
	}

	k.RawBytes = k.RawBytes[:k.RawBytesSize]

	return nil
}

// ToBytes converts a KeytabEntry to a byte array.
//
// Returns:
//   - []byte: The byte array representation of the KeytabEntry.
//   - error: An error if the conversion fails.
func (k *KeytabEntry) ToBytes() ([]byte, error) {
	data := make([]byte, 0)

	buffer4 := make([]byte, 4)
	buffer2 := make([]byte, 2)

	// Add the number of components
	binary.BigEndian.PutUint16(buffer2, k.NumComponents)
	data = append(data, buffer2...)

	// Add the realm
	realmBytes, err := k.Realm.ToBytes()
	if err != nil {
		return nil, err
	}
	data = append(data, realmBytes...)

	// Add the components
	for _, component := range k.Components {
		componentBytes, err := component.ToBytes()
		if err != nil {
			return nil, err
		}
		data = append(data, componentBytes...)
	}

	// Add the name type
	binary.BigEndian.PutUint32(buffer4, k.NameType)
	data = append(data, buffer4...)

	// Add the timestamp
	binary.BigEndian.PutUint32(buffer4, k.Timestamp)
	data = append(data, buffer4...)

	// Add the vno8
	data = append(data, k.Vno8)

	// Add the key
	keyBytes, err := k.Key.ToBytes()
	if err != nil {
		return nil, err
	}
	data = append(data, keyBytes...)

	// Add the vno
	binary.BigEndian.PutUint32(buffer4, k.Vno)
	data = append(data, buffer4...)

	// At the start of the data, add the size of the entry
	binary.BigEndian.PutUint32(buffer4, uint32(len(data)))
	data = append(buffer4, data...)

	return data, nil
}

// UpdateSize updates the size of the KeytabEntry.
//
// Returns:
//   - error: An error if the update fails.
func (k *KeytabEntry) UpdateSize() error {
	bytes, err := k.ToBytes()
	if err != nil {
		return err
	}

	// We remove the first 4 bytes because they are the size of the entry
	k.Size = uint32(len(bytes) - 4)

	return nil
}

// Describe prints a detailed description of the KeytabEntry struct,
// including its attributes formatted with indentation for clarity.
//
// Parameters:
//   - indent (int): The indentation level for formatting the output. Each level increases
//     the indentation depth, allowing for a hierarchical display of the entry's components.
func (k *KeytabEntry) Describe(indent, id int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<KeytabEntry #%d>\n", indentPrompt, id)
	fmt.Printf("%s │ \x1b[93mSize\x1b[0m          : \x1b[96m0x%08x\x1b[0m (\x1b[94m%d\x1b[0m)\n", indentPrompt, k.Size, k.Size)
	fmt.Printf("%s │ \x1b[93mNumComponents\x1b[0m : \x1b[96m0x%04x\x1b[0m (\x1b[94m%d\x1b[0m)\n", indentPrompt, k.NumComponents, k.NumComponents)
	fmt.Printf("%s │ \x1b[93mRealm\x1b[0m         : \x1b[96m%s\x1b[0m\n", indentPrompt, k.Realm.Data)

	fmt.Printf("%s │ \x1b[93mComponents\x1b[0m    : \n", indentPrompt)
	for i, component := range k.Components {
		component.Describe(indent+2, i)
		fmt.Printf("%s │  └─\n", indentPrompt)
	}

	fmt.Printf("%s │ \x1b[93mNameType\x1b[0m      : \x1b[96m0x%08x\x1b[0m (\x1b[94m%d\x1b[0m)\n", indentPrompt, k.NameType, k.NameType)
	fmt.Printf("%s │ \x1b[93mTimestamp\x1b[0m     : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, k.Timestamp, time.Unix(int64(k.Timestamp), 0).Format(time.RFC3339))
	fmt.Printf("%s │ \x1b[93mVno8\x1b[0m          : \x1b[96m0x%02x\x1b[0m (\x1b[94m%d\x1b[0m)\n", indentPrompt, k.Vno8, k.Vno8)
	fmt.Printf("%s │ \x1b[93mKey\x1b[0m           : \n", indentPrompt)
	k.Key.Describe(indent + 2)
	fmt.Printf("%s │ \x1b[93mVno\x1b[0m           : \x1b[96m0x%08x\x1b[0m (\x1b[94m%d\x1b[0m)\n", indentPrompt, k.Vno, k.Vno)
	fmt.Printf("%s └─\n", indentPrompt)
}

// Equal checks if two KeytabEntry structs are equal.
//
// Parameters:
//   - k2 (KeytabEntry): The KeytabEntry to compare to.
//
// Returns:
//   - bool: True if the KeytabEntry structs are equal, false otherwise.
func (k *KeytabEntry) Equal(k2 KeytabEntry) bool {
	return k.Size == k2.Size &&
		k.NumComponents == k2.NumComponents &&
		k.Realm.Equal(k2.Realm) &&
		k.NameType == k2.NameType &&
		k.Timestamp == k2.Timestamp &&
		k.Vno8 == k2.Vno8 &&
		k.Key.Equal(k2.Key) &&
		k.Vno == k2.Vno
}
