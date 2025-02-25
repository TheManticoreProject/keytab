package utils

import "fmt"

// BytesToPrintableString takes a byte slice and returns a string with only the printable characters.
// Non-printable characters are represented in the form of \x00.
func BytesToPrintableString(data []byte) string {
	result := ""

	for _, b := range data {
		if b >= 32 && b <= 126 {
			result += string(b)
		} else {
			result += fmt.Sprintf("\\x%02x", b)
		}
	}

	return result
}
