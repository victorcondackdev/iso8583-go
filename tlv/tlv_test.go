package tlv

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseVectors(t *testing.T) {
	// Hand-assembled field 55 fragment:
	//   9F02 06 000000001000   two-byte tag (9F: low bits 11111 -> more
	//                          tag bytes; 02 has bit 8 clear -> last)
	//   5F2A 02 0986           currency 986 (BRL), BCD
	//   82   02 1980           one-byte tag, AIP
	//   70   0A [5A 08 ...]    constructed (70 = 0111 0000, bit 6 set)
	data := mustHex(t, "9F0206000000001000 5F2A020986 82021980 700A 5A084111111111111111")
	l, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	want := List{
		{Tag: 0x9F02, Value: mustHex(t, "000000001000")},
		{Tag: 0x5F2A, Value: mustHex(t, "0986")},
		{Tag: 0x82, Value: mustHex(t, "1980")},
		{Tag: 0x70, Value: mustHex(t, "5A084111111111111111"), Children: List{
			{Tag: 0x5A, Value: mustHex(t, "4111111111111111")},
		}},
	}
	if !reflect.DeepEqual(l, want) {
		t.Fatalf("Parse =\n%#v\nwant\n%#v", l, want)
	}
	if got := l.Bytes(); !bytes.Equal(got, data) {
		t.Errorf("Bytes = %X, want %X", got, data)
	}
	if v, ok := l.Find(0x5A); !ok || !bytes.Equal(v.Value, mustHex(t, "4111111111111111")) {
		t.Errorf("Find(5A) = %v, %v", v, ok)
	}
	if _, ok := l.Find(0x9F26); ok {
		t.Error("Find(9F26) found a missing tag")
	}
}

func TestLongFormLengths(t *testing.T) {
	// Lengths >= 128 use the long form: 0x81 followed by one length byte
	// for 128..255, 0x82 and two bytes for 256..65535.
	for _, n := range []int{0, 1, 127, 128, 255, 256, 1000, 65535, 65536} {
		v := bytes.Repeat([]byte{0xAB}, n)
		enc := List{New(0x91, v)}.Bytes()
		var wantHdr string
		switch {
		case n < 128:
			wantHdr = fmt.Sprintf("91%02X", n)
		case n < 256:
			wantHdr = fmt.Sprintf("9181%02X", n)
		case n < 65536:
			wantHdr = fmt.Sprintf("9182%04X", n)
		default:
			wantHdr = fmt.Sprintf("9183%06X", n)
		}
		if got := fmt.Sprintf("%X", enc[:len(enc)-n]); got != wantHdr {
			t.Errorf("n=%d header %s, want %s", n, got, wantHdr)
		}
		l, err := Parse(enc)
		if err != nil || len(l) != 1 || !bytes.Equal(l[0].Value, v) {
			t.Errorf("n=%d round trip failed: %v", n, err)
		}
	}
	if got := appendLength(nil, 1<<24); !bytes.Equal(got, []byte{0x84, 0x01, 0, 0, 0}) {
		t.Errorf("appendLength(1<<24) = % X", got)
	}
	// Non-minimal long form is accepted on input.
	l, err := Parse(mustHex(t, "9F0281020102"))
	if err != nil || !bytes.Equal(l[0].Value, []byte{1, 2}) {
		t.Errorf("non-minimal length: %v %v", l, err)
	}
}

func TestPadding(t *testing.T) {
	l, err := Parse(mustHex(t, "00 9C0100 0000 9A03261122 00"))
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 2 || l[0].Tag != 0x9C || l[1].Tag != 0x9A {
		t.Errorf("Parse with padding = %v", l)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		in     string
		err    error
		offset int
	}{
		{"9F", ErrTruncated, 0},             // tag needs a second byte
		{"9F02", ErrTruncated, 2},           // no length
		{"9F0205 0000", ErrTruncated, 3},    // value shorter than length
		{"9F0281", ErrTruncated, 2},         // long form missing its byte
		{"9F0280", ErrLength, 2},            // indefinite form
		{"9F0285 0000000001", ErrLength, 2}, // five length bytes
		{"9F8181 8101 00", ErrTag, 0},       // five-byte tag
		{"5A01 41 9F02", ErrTruncated, 5},   // second object has no length
		{"7003 9F0205", ErrTruncated, 5},    // child overruns template
		{"9F0284 7FFFFFFF", ErrLength, 2},   // absurd length
	}
	for _, tt := range tests {
		_, err := Parse(mustHex(t, tt.in))
		var pe *ParseError
		if !errors.As(err, &pe) || !errors.Is(err, tt.err) || pe.Offset != tt.offset {
			t.Errorf("Parse(%s) = %v, want %v at offset %d", tt.in, err, tt.err, tt.offset)
		}
	}
	err := &ParseError{Offset: 3, Tag: 0x9F02, Err: ErrTruncated}
	if got := err.Error(); got != "tlv: truncated (tag 9F02 at offset 3)" {
		t.Errorf("Error() = %q", got)
	}
}

func TestDepthLimit(t *testing.T) {
	// 70 nested MaxDepth+2 times.
	var inner []byte
	for i := 0; i < MaxDepth+2; i++ {
		inner = append([]byte{0x70, byte(len(inner))}, inner...)
	}
	if _, err := Parse(inner); !errors.Is(err, ErrDepth) {
		t.Errorf("deep nesting err = %v", err)
	}
}

func TestTag(t *testing.T) {
	tests := []struct {
		s           string
		tag         Tag
		constructed bool
		class       int
	}{
		{"82", 0x82, false, 2},
		{"9F26", 0x9F26, false, 2},
		{"70", 0x70, true, 1},
		{"5F2A", 0x5F2A, false, 1},
		{"BF0C", 0xBF0C, true, 2},
		{"DF8101", 0xDF8101, false, 3},
		{"1F818101", 0x1F818101, false, 0},
	}
	for _, tt := range tests {
		got, err := ParseTag(tt.s)
		if err != nil || got != tt.tag {
			t.Errorf("ParseTag(%s) = %v, %v", tt.s, got, err)
			continue
		}
		if got.String() != tt.s || got.Constructed() != tt.constructed || got.Class() != tt.class {
			t.Errorf("%s: String %s constructed %v class %d", tt.s, got, got.Constructed(), got.Class())
		}
	}
	for _, bad := range []string{"", "zz", "9F", "9F0201", "00", "1F8181818101"} {
		if _, err := ParseTag(bad); !errors.Is(err, ErrTag) {
			t.Errorf("ParseTag(%q) err = %v", bad, err)
		}
	}
	if Tag(0x9F26).Name() != "Application Cryptogram" || Tag(0x9F53).Name() != "" {
		t.Error("dictionary lookup")
	}
	if !Tag(0x5A).Sensitive() || Tag(0x9F02).Sensitive() {
		t.Error("sensitive flags")
	}
}

func TestBuildConstructed(t *testing.T) {
	l := List{NewConstructed(0x71, New(0x9F18, []byte{0, 0, 0, 1}), New(0x86, []byte{0x84, 0x24}))}
	if got := fmt.Sprintf("%X", l.Bytes()); got != "710B9F18040000000186028424" {
		t.Errorf("Bytes = %s", got)
	}
	// A constructed object without children falls back to its raw Value.
	raw := List{{Tag: 0x70, Value: []byte{0x9C, 0x01, 0x00}}}
	if got := fmt.Sprintf("%X", raw.Bytes()); got != "70039C0100" {
		t.Errorf("Bytes = %s", got)
	}
}

func TestMaskedValue(t *testing.T) {
	tests := []struct {
		t    TLV
		want string
	}{
		{New(0x5A, mustHex(t, "4111111111111111")), "411111******1111"},
		{New(0x5A, mustHex(t, "4111111111111111111F")), "411111*********1111"},
		{New(0x57, mustHex(t, "4111111111111111D29121010000000F")), "411111******1111D**************"},
		{New(0x5F20, []byte("DOE/JOHN")), "****************"},
		{New(0x9F02, mustHex(t, "000000001000")), "000000001000"},
	}
	for _, tt := range tests {
		if got := MaskedValue(tt.t); got != tt.want {
			t.Errorf("MaskedValue(%s) = %s, want %s", tt.t.Tag, got, tt.want)
		}
	}
}

// FuzzParse checks that Parse never panics and that whatever it accepts is
// stable: re-encoding and re-parsing yields the same structure.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"9F0206000000001000", "700A5A084111111111111111", "9F02810201020",
		"00", "9F8181", "5F2A020986820219809A03261122",
	} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := Parse(data)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) || pe.Offset < 0 || pe.Offset > len(data) {
				t.Fatalf("bad error %v", err)
			}
			return
		}
		again, err := Parse(l.Bytes())
		if err != nil {
			t.Fatalf("re-parse: %v", err)
		}
		if !bytes.Equal(again.Bytes(), l.Bytes()) {
			t.Fatalf("unstable encoding")
		}
		_ = l.String()
	})
}

func ExampleParse() {
	field55, _ := hex.DecodeString("9F02060000000010005F2A0209869F2608A1B2C3D4E5F607085A084111111111111111")
	l, err := Parse(field55)
	if err != nil {
		panic(err)
	}
	fmt.Println(l)
	amount, _ := l.Find(0x9F02)
	fmt.Printf("amount: %X\n", amount.Value)
	// Output:
	// 9F02 Amount, Authorised (Numeric): 000000001000
	// 5F2A Transaction Currency Code: 0986
	// 9F26 Application Cryptogram: A1B2C3D4E5F60708
	// 5A Application Primary Account Number (PAN): 411111******1111
	// amount: 000000001000
}

func ExampleList_Bytes() {
	l := List{
		New(0x9C, []byte{0x00}),
		New(0x9A, []byte{0x26, 0x11, 0x22}),
		NewConstructed(0x70, New(0x5F34, []byte{0x01})),
	}
	fmt.Printf("%X\n", l.Bytes())
	// Output: 9C01009A0326112270045F340101
}
