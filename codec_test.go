package iso8583

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/victorcondackdev/iso8583-go/spec"
)

// BCD vectors, computed by hand: each pair of decimal digits becomes one
// byte whose high nibble is the first digit. An odd count needs one filler
// nibble, 0 on the left or F on the right; track 2's '=' separator is the
// nibble D.
func TestBCDVectors(t *testing.T) {
	tests := []struct {
		digits   string
		padRight bool
		track2   bool
		want     []byte
	}{
		{"", false, false, nil},
		{"0", false, false, []byte{0x00}},
		{"7", false, false, []byte{0x07}},          // 0|7
		{"7", true, false, []byte{0x7F}},           // 7|F
		{"12", false, false, []byte{0x12}},         // 1|2
		{"123", false, false, []byte{0x01, 0x23}},  // 0|1 2|3
		{"123", true, false, []byte{0x12, 0x3F}},   // 1|2 3|F
		{"0200", false, false, []byte{0x02, 0x00}}, // an MTI
		{"986", false, false, []byte{0x09, 0x86}},  // BRL currency
		{"000000001000", false, false, []byte{0, 0, 0, 0, 0x10, 0x00}},
		{"4111111111111111", false, false, []byte{0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}},
		{"41=29", true, true, []byte{0x41, 0xD2, 0x9F}}, // 4|1 =|2 9|F
		{"411=2", false, true, []byte{0x04, 0x11, 0xD2}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/right=%v", tt.digits, tt.padRight), func(t *testing.T) {
			got, ferr := appendBCD(nil, []byte(tt.digits), tt.padRight)
			if ferr != nil || !bytes.Equal(got, tt.want) {
				t.Fatalf("appendBCD = % X, %v; want % X", got, ferr, tt.want)
			}
			back, ferr := decodeBCD(nil, got, len(tt.digits), tt.padRight, tt.track2, true)
			if ferr != nil || string(back) != tt.digits {
				t.Fatalf("decodeBCD = %q, %v", back, ferr)
			}
		})
	}
}

func TestBCDErrors(t *testing.T) {
	for _, in := range []string{"1x", "x", "x1", "12x"} {
		for _, right := range []bool{false, true} {
			if _, ferr := appendBCD(nil, []byte(in), right); ferr == nil || !errors.Is(ferr.err, ErrInvalidChar) {
				t.Errorf("appendBCD(%q, %v) = %v", in, right, ferr)
			}
		}
	}
	// Wrong filler nibble: strict rejects, lenient accepts.
	if _, ferr := decodeBCD(nil, []byte{0x51, 0x23}, 3, false, false, true); ferr == nil || ferr.err != ErrPadding {
		t.Errorf("left filler 5 accepted: %v", ferr)
	}
	if _, ferr := decodeBCD(nil, []byte{0x12, 0x30}, 3, true, false, true); ferr == nil || ferr.err != ErrPadding {
		t.Errorf("right filler 0 accepted: %v", ferr)
	}
	if got, ferr := decodeBCD(nil, []byte{0x12, 0x30}, 3, true, false, false); ferr != nil || string(got) != "123" {
		t.Errorf("lenient decode = %q, %v", got, ferr)
	}
	// Non-decimal nibbles surface as hex letters for later validation.
	if got, _ := decodeBCD(nil, []byte{0x1A, 0xDF}, 4, false, false, true); string(got) != "1ADF" {
		t.Errorf("decode hex nibbles = %q", got)
	}
}

func TestHex(t *testing.T) {
	if got := appendHex(nil, []byte{0x00, 0x9F, 0xAB}); string(got) != "009FAB" {
		t.Errorf("appendHex = %s", got)
	}
	if got, ferr := decodeHex(nil, []byte("009FAB"), true); ferr != nil || !bytes.Equal(got, []byte{0x00, 0x9F, 0xAB}) {
		t.Errorf("decodeHex = % X, %v", got, ferr)
	}
	if _, ferr := decodeHex(nil, []byte("9fab"), true); ferr == nil {
		t.Error("strict decodeHex accepted lowercase")
	}
	if got, ferr := decodeHex(nil, []byte("9fab"), false); ferr != nil || !bytes.Equal(got, []byte{0x9F, 0xAB}) {
		t.Errorf("lenient decodeHex = % X, %v", got, ferr)
	}
	for _, bad := range []string{"G0", "0G", "zz"} {
		if _, ferr := decodeHex(nil, []byte(bad), false); ferr == nil {
			t.Errorf("decodeHex(%s) accepted", bad)
		}
	}
}

// Length prefix vectors for a length of 37, by hand: ASCII "37" is 33 37,
// "037" is 30 33 37; BCD 37 is the byte 0x37 and LLL BCD pads to four
// digits 0037 -> 00 37; binary is 37 = 0x25 in one byte (LL) or two bytes
// (LLL); EBCDIC digits are F0-F9.
func TestPrefixVectors(t *testing.T) {
	tests := []struct {
		digits int
		enc    spec.Encoding
		n      int
		want   []byte
	}{
		{2, spec.ASCII, 37, []byte("37")},
		{3, spec.ASCII, 37, []byte("037")},
		{4, spec.ASCII, 37, []byte("0037")},
		{2, spec.EBCDIC, 37, []byte{0xF3, 0xF7}},
		{3, spec.EBCDIC, 999, []byte{0xF9, 0xF9, 0xF9}},
		{2, spec.BCD, 37, []byte{0x37}},
		{3, spec.BCD, 37, []byte{0x00, 0x37}},
		{3, spec.BCD, 999, []byte{0x09, 0x99}},
		{4, spec.BCD, 1234, []byte{0x12, 0x34}},
		{2, spec.Raw, 37, []byte{0x25}},
		{3, spec.Raw, 999, []byte{0x03, 0xE7}},
		{4, spec.Raw, 9999, []byte{0x27, 0x0F}},
	}
	for _, tt := range tests {
		got := appendPrefix(nil, tt.digits, tt.enc, tt.n)
		if !bytes.Equal(got, tt.want) {
			t.Errorf("appendPrefix(%d, %s, %d) = % X, want % X", tt.digits, tt.enc, tt.n, got, tt.want)
		}
		if len(got) != prefixLen(tt.digits, tt.enc) {
			t.Errorf("prefixLen(%d, %s) = %d, encoded %d", tt.digits, tt.enc, prefixLen(tt.digits, tt.enc), len(got))
		}
		n, ferr := readPrefix(got, tt.digits, tt.enc)
		if ferr != nil || n != tt.n {
			t.Errorf("readPrefix(% X) = %d, %v", got, n, ferr)
		}
	}
	for _, bad := range []struct {
		b   []byte
		enc spec.Encoding
	}{
		{[]byte("3x"), spec.ASCII},
		{[]byte{0x3A}, spec.BCD},
		{[]byte{0xA3}, spec.BCD},
		{[]byte{0xC1, 0xF0}, spec.EBCDIC},
	} {
		if _, ferr := readPrefix(bad.b, len(bad.b), bad.enc); ferr == nil || ferr.err != ErrLength {
			t.Errorf("readPrefix(% X, %s) accepted", bad.b, bad.enc)
		}
	}
}

func TestEncodedLen(t *testing.T) {
	f := func(typ spec.Type, enc spec.Encoding) *spec.Field { return &spec.Field{Type: typ, Encoding: enc} }
	tests := []struct {
		f     *spec.Field
		units int
		want  int
	}{
		{f(spec.Numeric, spec.ASCII), 19, 19},
		{f(spec.Numeric, spec.BCD), 19, 10},
		{f(spec.Track2, spec.BCD), 37, 19},
		{f(spec.Amount, spec.ASCII), 8, 9},
		{f(spec.Amount, spec.BCD), 8, 5},
		{f(spec.Binary, spec.Raw), 8, 8},
		{f(spec.Binary, spec.Hex), 8, 16},
		{f(spec.AlphaNumericSpecial, spec.EBCDIC), 40, 40},
	}
	for _, tt := range tests {
		if got := encodedLen(tt.f, tt.units); got != tt.want {
			t.Errorf("encodedLen(%s/%s, %d) = %d, want %d", tt.f.Type, tt.f.Encoding, tt.units, got, tt.want)
		}
	}
}
