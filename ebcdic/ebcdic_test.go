package ebcdic

import (
	"bytes"
	"fmt"
	"testing"
)

// The vectors below were checked by hand against the published IBM CP037
// code chart, row by row: the high nibble selects the row and the low nibble
// the column. For example 'A' sits at row C column 1 (0xC1), 'J' at row D
// column 1 (0xD1) because of the gap after 'I', and 'S' at row E column 2
// (0xE2) because column E0 holds '\' and E1 is unassigned to a letter.
func TestKnownCharacters(t *testing.T) {
	tests := []struct {
		latin1 byte
		ebcdic byte
	}{
		{' ', 0x40},
		{'.', 0x4B},
		{'<', 0x4C},
		{'(', 0x4D},
		{'+', 0x4E},
		{'|', 0x4F},
		{'&', 0x50},
		{'!', 0x5A},
		{'$', 0x5B},
		{'*', 0x5C},
		{')', 0x5D},
		{';', 0x5E},
		{'-', 0x60},
		{'/', 0x61},
		{',', 0x6B},
		{'%', 0x6C},
		{'_', 0x6D},
		{'>', 0x6E},
		{'?', 0x6F},
		{':', 0x7A},
		{'#', 0x7B},
		{'@', 0x7C},
		{'\'', 0x7D},
		{'=', 0x7E},
		{'"', 0x7F},
		{'a', 0x81},
		{'i', 0x89},
		{'j', 0x91},
		{'r', 0x99},
		{'s', 0xA2},
		{'z', 0xA9},
		{'^', 0xB0},
		{'[', 0xBA},
		{']', 0xBB},
		{'{', 0xC0},
		{'A', 0xC1},
		{'I', 0xC9},
		{'}', 0xD0},
		{'J', 0xD1},
		{'R', 0xD9},
		{'\\', 0xE0},
		{'S', 0xE2},
		{'Z', 0xE9},
		{'0', 0xF0},
		{'9', 0xF9},
		{0x00, 0x00},
		{'\n', 0x25}, // LF maps to EBCDIC LF (0x25), not NL (0x15)
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.latin1), func(t *testing.T) {
			if got := EncodeByte(tt.latin1); got != tt.ebcdic {
				t.Errorf("EncodeByte(%#02x) = %#02x, want %#02x", tt.latin1, got, tt.ebcdic)
			}
			if got := DecodeByte(tt.ebcdic); got != tt.latin1 {
				t.Errorf("DecodeByte(%#02x) = %#02x, want %#02x", tt.ebcdic, got, tt.latin1)
			}
		})
	}
}

func TestBijection(t *testing.T) {
	seen := make(map[byte]bool)
	for i := 0; i < 256; i++ {
		e := EncodeByte(byte(i))
		if seen[e] {
			t.Fatalf("EBCDIC byte %#02x produced twice", e)
		}
		seen[e] = true
		if DecodeByte(e) != byte(i) {
			t.Fatalf("round trip of %#02x failed", i)
		}
	}
}

func TestEncodeDecode(t *testing.T) {
	// "0200" in CP037 is F0 F2 F0 F0; "AB=1" is C1 C2 7E F1.
	if got := Encode(nil, []byte("0200")); !bytes.Equal(got, []byte{0xF0, 0xF2, 0xF0, 0xF0}) {
		t.Errorf("Encode(0200) = % X", got)
	}
	if got := Encode([]byte{0x01}, []byte("AB=1")); !bytes.Equal(got, []byte{0x01, 0xC1, 0xC2, 0x7E, 0xF1}) {
		t.Errorf("Encode(AB=1) = % X", got)
	}
	if got := Decode(nil, []byte{0xC8, 0x85, 0x93, 0x93, 0x96}); string(got) != "Hello" {
		t.Errorf("Decode = %q", got)
	}
}

func ExampleEncode() {
	fmt.Printf("% X\n", Encode(nil, []byte("0800 OK")))
	// Output: F0 F8 F0 F0 40 D6 D2
}
