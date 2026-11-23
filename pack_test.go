package iso8583

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/victorcondackdev/iso8583-go/spec"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// purchase builds the 0200 used by several tests: fields 2, 3, 4, 7, 11,
// 14, 22, 35, 37, 41, 42, 49, 52 and 55.
func purchase(t testing.TB, s *spec.Spec) *Message {
	t.Helper()
	m := NewMessage(s)
	must(t, m.SetMTI("0200"))
	must(t, m.SetString(2, "4111111111111111"))
	must(t, m.SetString(3, "000000"))
	must(t, m.SetAmount(4, 1000))
	must(t, m.SetString(7, "1122140500"))
	must(t, m.SetString(11, "123"))
	must(t, m.SetString(14, "2912"))
	must(t, m.SetString(22, "051"))
	must(t, m.SetString(35, "4111111111111111=2912101123456789"))
	must(t, m.SetString(37, "632614000123"))
	must(t, m.SetString(41, "TERM0001"))
	must(t, m.SetString(42, "MERCHANT0000001"))
	must(t, m.SetString(49, "986"))
	must(t, m.SetBytes(52, mustHex(t, "1234567890ABCDEF")))
	must(t, m.SetBytes(55, mustHex(t, "9F0206000000001000 5F2A020986")))
	return m
}

// The bitmap of purchase(), by hand. Bits are numbered from 1 at the most
// significant bit of the first byte:
//
//	byte 1, fields 1-8:   2 3 4 7    -> 0111 0010 = 72
//	byte 2, fields 9-16:  11 14      -> 0010 0100 = 24
//	byte 3, fields 17-24: 22         -> 0000 0100 = 04
//	byte 4, fields 25-32: none       -> 00
//	byte 5, fields 33-40: 35 37      -> 0010 1000 = 28
//	byte 6, fields 41-48: 41 42      -> 1100 0000 = C0
//	byte 7, fields 49-56: 49 52 55   -> 1001 0010 = 92
//	byte 8, fields 57-64: none       -> 00
const purchaseBitmap = "7224040028C09200"

func TestPackISO87ASCII(t *testing.T) {
	got, err := purchase(t, spec.ISO87ASCII()).Pack()
	must(t, err)
	want := strings.Join([]string{
		"0200",                   // MTI
		purchaseBitmap,           // hex bitmap
		"16", "4111111111111111", // 2: LL ASCII
		"000000",                                  // 3
		"000000001000",                            // 4: SetAmount(1000) zero padded
		"1122140500",                              // 7
		"000123",                                  // 11: "123" left padded with 0
		"2912",                                    // 14
		"051",                                     // 22
		"33", "4111111111111111=2912101123456789", // 35: z..37
		"632614000123",                        // 37
		"TERM0001",                            // 41
		"MERCHANT0000001",                     // 42
		"986",                                 // 49
		"1234567890ABCDEF",                    // 52: 8 bytes as 16 hex chars
		"014", "9F02060000000010005F2A020986", // 55: LLL counts 14 bytes, hex encoded
	}, "")
	if string(got) != want {
		t.Fatalf("Pack =\n%s\nwant\n%s", got, want)
	}
}

func TestPackISO87Binary(t *testing.T) {
	got, err := purchase(t, spec.ISO87Binary()).Pack()
	must(t, err)
	want := mustHex(t, strings.Join([]string{
		"0200",                                  // MTI, BCD
		purchaseBitmap,                          // raw bitmap
		"16 4111111111111111",                   // 2: LL BCD = 0x16, 16 digits in 8 bytes
		"000000",                                // 3
		"000000001000",                          // 4
		"1122140500",                            // 7
		"000123",                                // 11
		"2912",                                  // 14
		"0051",                                  // 22: odd length, left filler 0
		"33 4111111111111111D2912101123456789F", // 35: '=' is D, right filler F
		hex.EncodeToString([]byte("632614000123")), // 37: an stays ASCII
		hex.EncodeToString([]byte("TERM0001")),
		hex.EncodeToString([]byte("MERCHANT0000001")),
		"0986",                              // 49: odd length
		"1234567890ABCDEF",                  // 52: raw
		"0014 9F02060000000010005F2A020986", // 55: LLL BCD in two bytes
	}, " "))
	if !bytes.Equal(got, want) {
		t.Fatalf("Pack =\n%X\nwant\n%X", got, want)
	}
}

// ebcdicSpec is ISO87ASCII re-encoded the way mainframe hosts do: EBCDIC
// MTI, text, numerics and prefixes, binary bitmap and binary fields.
func ebcdicSpec() *spec.Spec {
	s := spec.ISO87ASCII().Clone()
	s.Name = "ISO87EBCDIC"
	s.MTIEncoding = spec.EBCDIC
	s.BitmapEncoding = spec.Raw
	s.Defaults = spec.Defaults{Numeric: spec.EBCDIC, Text: spec.EBCDIC, Binary: spec.Raw, Prefix: spec.EBCDIC}
	for _, f := range s.Fields {
		f.Encoding, f.PrefixEncoding = "", ""
	}
	return s
}

func TestPackEBCDIC(t *testing.T) {
	m := NewMessage(ebcdicSpec())
	must(t, m.SetMTI("0810"))
	must(t, m.SetString(2, "4111111111111"))
	must(t, m.SetString(39, "00"))
	must(t, m.SetString(41, "TERM A"))
	got, err := m.Pack()
	must(t, err)
	// CP037 by hand: digits are F0-F9, space 40, 'A' C1, 'E' C5, 'M' D4,
	// 'R' D9, 'T' E3.
	want := mustHex(t, `
		F0 F8 F1 F0
		40 00 00 00 02 80 00 00
		F1 F3 F4 F1 F1 F1 F1 F1 F1 F1 F1 F1 F1 F1 F1
		F0 F0
		E3 C5 D9 D4 40 C1 40 40`)
	// Bitmap: field 2 -> byte 1 = 0100 0000; fields 39 and 41 -> byte 5
	// (fields 33-40) bit 7 = 02, byte 6 (41-48) bit 1 = 80.
	if !bytes.Equal(got, want) {
		t.Fatalf("Pack =\n% X\nwant\n% X", got, want)
	}
	back := NewMessage(ebcdicSpec())
	must(t, back.Unpack(got))
	if v, _ := back.GetString(41); v != "TERM A  " {
		t.Errorf("field 41 = %q", v)
	}
}

func TestAmountFieldEncodings(t *testing.T) {
	// x+n 8: sign then eight digits. With BCD digits the sign stays a
	// single ASCII byte: 'C' = 43, then 00000150 -> 00 00 01 50.
	tests := []struct {
		s    *spec.Spec
		want []byte
	}{
		{spec.ISO87ASCII(), []byte("D00000150")},
		{spec.ISO87Binary(), mustHex(t, "44 00 00 01 50")},
		{ebcdicSpec(), mustHex(t, "C4 F0 F0 F0 F0 F0 F1 F5 F0")}, // 'D' is C4 in CP037
	}
	for _, tt := range tests {
		m := NewMessage(tt.s)
		must(t, m.SetMTI("0200"))
		must(t, m.SetAmount(28, -150))
		got, err := m.Pack()
		must(t, err)
		hdr := 4 + 16
		if tt.s.MTIEncoding == spec.BCD {
			hdr = 2 + 8
		} else if tt.s.BitmapEncoding == spec.Raw {
			hdr = 4 + 8
		}
		if !bytes.Equal(got[hdr:], tt.want) {
			t.Errorf("%s: field 28 = % X, want % X", tt.s.Name, got[hdr:], tt.want)
		}
		back := NewMessage(tt.s)
		must(t, back.Unpack(got))
		if v, err := back.GetAmount(28); err != nil || v != -150 {
			t.Errorf("%s: GetAmount = %d, %v", tt.s.Name, v, err)
		}
	}
}

func TestSecondaryAndTertiaryBitmaps(t *testing.T) {
	m := NewMessage(spec.ISO87ASCII())
	must(t, m.SetMTI("0800"))
	must(t, m.SetString(11, "000001"))
	must(t, m.SetString(70, "301"))
	got, err := m.Pack()
	must(t, err)
	// Primary: bit 1 (secondary present) and bit 11 -> 80 20 00 ...;
	// secondary: field 70 is bit 6 of the secondary -> 04 00 ...
	if want := "0800" + "8020000000000000" + "0400000000000000" + "000001" + "301"; string(got) != want {
		t.Fatalf("Pack = %s, want %s", got, want)
	}

	s := spec.ISO87Binary().Clone()
	s.TertiaryBitmap = true
	s.Fields[130] = &spec.Field{Name: "Private 130", Type: spec.AlphaNumeric, Length: 2}
	m = NewMessage(s)
	must(t, m.SetMTI("0200"))
	must(t, m.SetString(130, "OK"))
	got, err = m.Pack()
	must(t, err)
	// Bit 1, bit 65 (first bit of the secondary) and field 130 = bit 2 of
	// the tertiary.
	want := mustHex(t, "0200 8000000000000000 8000000000000000 4000000000000000 4F4B")
	if !bytes.Equal(got, want) {
		t.Fatalf("Pack = % X, want % X", got, want)
	}
	back := NewMessage(s)
	must(t, back.Unpack(got))
	if v, _ := back.GetString(130); v != "OK" {
		t.Errorf("field 130 = %q", v)
	}
	if err := m.SetString(65, "x"); !errors.Is(err, ErrUndefined) {
		t.Errorf("field 65 with tertiary bitmap: %v", err)
	}
}

func acmeSpec(t testing.TB) *spec.Spec {
	t.Helper()
	s, err := spec.LoadFile("examples/acme-spec.json")
	must(t, err)
	return s
}

func TestCompositeFields(t *testing.T) {
	s := acmeSpec(t)
	m := NewMessage(s)
	must(t, m.SetMTI("0100"))
	must(t, m.SetSub("48.1", "3"))
	must(t, m.SetSub("48.3", "ORDER-42"))
	must(t, m.SetSub("62.1", "SN-0042"))
	must(t, m.SetSub("62.8", "17"))
	// 48.2 (fixed n 3, no padding) is missing between 48.1 and 48.3.
	_, err := m.Pack()
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Path != "48.2" || !errors.Is(err, ErrNotSet) {
		t.Fatalf("Pack with a gap = %v", err)
	}
	must(t, m.SetSub("48.2", "123"))
	got, err := m.Pack()
	must(t, err)
	want := "0100" + "0000000000010004" +
		"015" + "03" + "123" + "08ORDER-42" + // 48: LLL = 2+3+10 bytes
		"031" + "8100000000000000" + "07SN-0042" + "000017" // 62: bitmap bits 1 and 8
	if string(got) != want {
		t.Fatalf("Pack =\n%s\nwant\n%s", got, want)
	}
	back := NewMessage(s)
	must(t, back.Unpack(got))
	for path, want := range map[string]string{"48.1": "03", "48.2": "123", "48.3": "ORDER-42", "62.1": "SN-0042", "62.8": "000017"} {
		if v, err := back.GetSub(path); err != nil || v != want {
			t.Errorf("GetSub(%s) = %q, %v; want %q", path, v, err, want)
		}
	}
	if _, err := back.GetSub("62.2"); !errors.Is(err, ErrNotSet) {
		t.Errorf("GetSub(62.2) err = %v", err)
	}

	// Positional subfields may be omitted at the end.
	short := NewMessage(s)
	must(t, short.SetMTI("0100"))
	must(t, short.SetSub("48.1", "12"))
	got, err = short.Pack()
	must(t, err)
	if want := "0100" + "0000000000010000" + "002" + "12"; string(got) != want {
		t.Fatalf("Pack = %s, want %s", got, want)
	}
}

func TestPositionalFiller(t *testing.T) {
	s := &spec.Spec{
		Name: "T", MTIEncoding: spec.ASCII, BitmapEncoding: spec.Hex,
		Defaults: spec.Defaults{Numeric: spec.ASCII, Text: spec.ASCII, Binary: spec.Hex, Prefix: spec.ASCII},
		Fields: map[int]*spec.Field{
			48: {Name: "P", Type: spec.AlphaNumericSpecial, Length: 99, LengthType: spec.LLVar,
				Composite: &spec.Composite{Kind: spec.Positional, Fields: map[int]*spec.Field{
					1: {Name: "padded", Type: spec.Numeric, Length: 3, Pad: spec.PadLeft},
					2: {Name: "var", Type: spec.AlphaNumericSpecial, Length: 9, LengthType: spec.LLVar},
					3: {Name: "last", Type: spec.AlphaNumeric, Length: 1},
				}}},
		},
	}
	m := NewMessage(s)
	must(t, m.SetMTI("0100"))
	must(t, m.SetSub("48.3", "X"))
	got, err := m.Pack()
	must(t, err)
	if want := "0100" + "0000000000010000" + "06" + "000" + "00" + "X"; string(got) != want {
		t.Fatalf("Pack = %s, want %s", got, want)
	}
}

func TestPackErrors(t *testing.T) {
	m := NewMessage(spec.ISO87ASCII())
	if _, err := m.Pack(); !errors.Is(err, ErrNotSet) {
		t.Errorf("Pack without MTI: %v", err)
	}
	// Values that bypassed validation (lenient mode) still cannot be
	// packed when the encoding cannot represent them.
	l := NewMessage(spec.ISO87Binary(), WithMode(Lenient))
	must(t, l.SetMTI("0200"))
	must(t, l.SetString(3, "00X000"))
	_, err := l.Pack()
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != 3 || fe.Offset != 10 || !errors.Is(err, ErrInvalidChar) {
		t.Errorf("Pack of unencodable value = %v", err)
	}
	if fe != nil && !strings.Contains(fe.Error(), "field 3 at offset 10") {
		t.Errorf("Error() = %q", fe.Error())
	}
}
