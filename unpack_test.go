package iso8583

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/victorcondackdev/iso8583-go/spec"
)

func TestUnpackRoundTrip(t *testing.T) {
	for _, s := range []*spec.Spec{spec.ISO87ASCII(), spec.ISO87Binary(), ebcdicSpec()} {
		t.Run(s.Name, func(t *testing.T) {
			m := purchase(t, s)
			b, err := m.Pack()
			must(t, err)
			back := NewMessage(s)
			must(t, back.Unpack(b))
			again, err := back.Pack()
			must(t, err)
			if !bytes.Equal(b, again) {
				t.Fatalf("repack differs:\n% X\n% X", b, again)
			}
			if back.MTI() != "0200" {
				t.Errorf("MTI = %q", back.MTI())
			}
			if pan, _ := back.GetString(2); pan != "4111111111111111" {
				t.Errorf("PAN = %q", pan)
			}
			if tr, _ := back.GetString(35); tr != "4111111111111111=2912101123456789" {
				t.Errorf("track 2 = %q", tr)
			}
			if amt, _ := back.GetAmount(4); amt != 1000 {
				t.Errorf("amount = %d", amt)
			}
			if pin, _ := back.GetBytes(52); !bytes.Equal(pin, mustHex(t, "1234567890ABCDEF")) {
				t.Errorf("PIN block = % X", pin)
			}
		})
	}
}

// asciiMsg assembles an ISO87ASCII message from parts.
func asciiMsg(parts ...string) []byte { return []byte(strings.Join(parts, "")) }

func TestUnpackErrors(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		field  int
		path   string
		offset int
		err    error
	}{
		{"empty", nil, FieldMTI, "", 0, ErrTruncated},
		{"short MTI", []byte("020"), FieldMTI, "", 0, ErrTruncated},
		{"non-digit MTI", []byte("02X0"), FieldMTI, "", 0, ErrMTI},
		{"short bitmap", asciiMsg("0200", "7234"), FieldBitmap, "", 4, ErrTruncated},
		{"bad bitmap hex", asciiMsg("0200", "72340541ZZC08000"), FieldBitmap, "", 4, ErrBitmap},
		{"lowercase bitmap", asciiMsg("0200", "7234054128c08000"), FieldBitmap, "", 4, ErrBitmap},
		{"secondary truncated", asciiMsg("0200", "8000000000000000", "00"), FieldBitmap, "", 20, ErrTruncated},
		{"empty secondary", asciiMsg("0200", "8000000000000000", "0000000000000000"), FieldBitmap, "", 20, ErrBitmap},
		// Field 2 prefix says 20 digits; the maximum is 19.
		{"LL over max", asciiMsg("0200", "4000000000000000", "20", "41111111111111111111"), 2, "2", 20, ErrLength},
		{"LL not numeric", asciiMsg("0200", "4000000000000000", "1x"), 2, "2", 20, ErrLength},
		{"LL truncated", asciiMsg("0200", "4000000000000000", "1"), 2, "2", 20, ErrTruncated},
		{"value truncated", asciiMsg("0200", "4000000000000000", "16", "41111111"), 2, "2", 22, ErrTruncated},
		{"bad digit", asciiMsg("0200", "4000000000000000", "16", "411111111111111X"), 2, "2", 22, ErrInvalidChar},
		// Field 3 follows a valid field 2 at 4+16+2+16 = 38.
		{"second field", asciiMsg("0200", "6000000000000000", "16", "4111111111111111", "00000Z"), 3, "3", 38, ErrInvalidChar},
		// Bit 5 set: field 5 exists; bit 65... field 1 says no secondary.
		{"undefined field", asciiMsg("0200", "0000000000000004"), 62, "", 20, ErrTruncated},
		{"trailing data", asciiMsg("0200", "2000000000000000", "000000", "XX"), FieldNone, "", 26, ErrTrailingData},
		{"x+n sign", asciiMsg("0200", "0000001000000000", "X00000150"), 28, "28", 20, ErrInvalidChar},
		// Field 55 claims 3 bytes of TLV: 9F 02 05 -> value runs past the
		// field. The TLV error is at TLV offset 3, i.e. 6 hex characters
		// into the field data, which starts at 20+3.
		{"bad TLV", asciiMsg("0200", "0000000000000200", "003", "9F0205"), 55, "55", 29, ErrTLV},
		{"z invalid", asciiMsg("0200", "0000000020000000", "05", "41=1A"), 35, "35", 22, ErrInvalidChar},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewMessage(spec.ISO87ASCII()).Unpack(tt.data)
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("Unpack = %v, want *FieldError", err)
			}
			if fe.Field != tt.field || fe.Offset != tt.offset || !errors.Is(err, tt.err) {
				t.Fatalf("Unpack = %v (field %d offset %d), want field %d offset %d %v",
					err, fe.Field, fe.Offset, tt.field, tt.offset, tt.err)
			}
			if tt.path != "" && fe.Path != tt.path {
				t.Errorf("path = %q, want %q", fe.Path, tt.path)
			}
		})
	}
}

func TestUnpackUndefinedField(t *testing.T) {
	s := spec.ISO87ASCII().Clone()
	delete(s.Fields, 5)
	err := NewMessage(s).Unpack(asciiMsg("0200", "0800000000000000", "000000000001"))
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != 5 || fe.Offset != 20 || !errors.Is(err, ErrUndefined) {
		t.Fatalf("Unpack = %v", err)
	}
	// Bit 65 in a spec without a tertiary bitmap and no field 65.
	err = NewMessage(spec.ISO87ASCII()).Unpack(asciiMsg("0800", "8000000000000000", "8000000000000000"))
	if !errors.As(err, &fe) || fe.Field != 65 || !errors.Is(err, ErrUndefined) {
		t.Fatalf("bit 65: %v", err)
	}
}

func TestUnpackBinaryErrors(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		field  int
		offset int
		err    error
	}{
		{"BCD MTI", "02A0", FieldMTI, 0, ErrMTI},
		{"prefix not BCD", "0200 4000000000000000 1A", 2, 10, ErrLength},
		// Field 22 is n 3 in two bytes; strict mode wants a 0 filler.
		{"filler nibble", "0200 0000040000000000 1051", 22, 10, ErrPadding},
		// Field 35 z..37 with an odd count must end with filler F.
		{"track filler", "0200 0000000020000000 03 41D0", 35, 11, ErrPadding},
		{"track nibble", "0200 0000000020000000 04 41A1", 35, 11, ErrInvalidChar},
		{"LLL over max", "0200 0000000000000200 1000", 55, 10, ErrLength},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewMessage(spec.ISO87Binary()).Unpack(mustHex(t, tt.data))
			var fe *FieldError
			if !errors.As(err, &fe) || fe.Field != tt.field || fe.Offset != tt.offset || !errors.Is(err, tt.err) {
				t.Fatalf("Unpack = %v, want field %d offset %d %v", err, tt.field, tt.offset, tt.err)
			}
		})
	}
}

func TestLenientMode(t *testing.T) {
	inputs := []struct {
		name string
		s    *spec.Spec
		data []byte
		get  int
		want string
	}{
		{"lowercase hex", spec.ISO87ASCII(), asciiMsg("0200", "0000000000001000", "1234567890abcdef"), 52, "\x12\x34\x56\x78\x90\xab\xcd\xef"},
		{"letters in n", spec.ISO87ASCII(), asciiMsg("0200", "2000000000000000", "00A000"), 3, "00A000"},
		{"trailing bytes", spec.ISO87ASCII(), asciiMsg("0200", "2000000000000000", "000000", "\r\n"), 3, "000000"},
		{"empty secondary", spec.ISO87ASCII(), asciiMsg("0200", "a000000000000000", "0000000000000000", "000000"), 3, "000000"},
		{"filler nibble", spec.ISO87Binary(), mustHex(t, "0200 0000040000000000 1051"), 22, "051"},
		{"bad TLV", spec.ISO87ASCII(), asciiMsg("0200", "0000000000000200", "003", "9f0205"), 55, "\x9f\x02\x05"},
		{"x+n sign", spec.ISO87ASCII(), asciiMsg("0200", "0000001000000000", "X00000150"), 28, "X00000150"},
	}
	for _, tt := range inputs {
		t.Run(tt.name, func(t *testing.T) {
			if err := NewMessage(tt.s).Unpack(tt.data); err == nil {
				t.Fatal("strict mode accepted the input")
			}
			m := NewMessage(tt.s, WithMode(Lenient))
			must(t, m.Unpack(tt.data))
			if v, err := m.GetString(tt.get); err != nil || v != tt.want {
				t.Errorf("GetString(%d) = %q, %v; want %q", tt.get, v, err, tt.want)
			}
			if m.Mode() != Lenient {
				t.Error("Mode() is not Lenient")
			}
		})
	}
	// Lenient still refuses ambiguous framing.
	m := NewMessage(spec.ISO87ASCII(), WithMode(Lenient))
	if err := m.Unpack(asciiMsg("0200", "4000000000000000", "20", "4111")); !errors.Is(err, ErrLength) {
		t.Errorf("lenient LL over max: %v", err)
	}
}

func TestLenientCompositeTrailing(t *testing.T) {
	s := acmeSpec(t)
	data := asciiMsg("0100", "0000000000010000", "009", "03", "123", "01Z", "X")
	if err := NewMessage(s).Unpack(data); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("strict: %v", err)
	}
	m := NewMessage(s, WithMode(Lenient))
	must(t, m.Unpack(data))
	if v, _ := m.GetSub("48.2"); v != "123" {
		t.Errorf("48.2 = %q", v)
	}
}

func TestUnpackCompositeErrors(t *testing.T) {
	s := acmeSpec(t)
	tests := []struct {
		name   string
		data   []byte
		path   string
		offset int
		err    error
	}{
		{"subfield bad char", asciiMsg("0100", "0000000000010000", "005", "0X", "123"), "48.1", 23, ErrInvalidChar},
		{"subfield overruns", asciiMsg("0100", "0000000000010000", "004", "03", "12", "3"), "48.2", 25, ErrTruncated},
		{"sub bitmap undefined", asciiMsg("0100", "0000000000000004", "016", "2000000000000000"), "62.3", 39, ErrUndefined},
		{"sub bitmap short", asciiMsg("0100", "0000000000000004", "004", "8100"), "62", 23, ErrTruncated},
		{"sub bitmap bad hex", asciiMsg("0100", "0000000000000004", "016", "81000000000000ZZ"), "62", 23, ErrBitmap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewMessage(s).Unpack(tt.data)
			var fe *FieldError
			if !errors.As(err, &fe) || fe.Path != tt.path || fe.Offset != tt.offset || !errors.Is(err, tt.err) {
				t.Fatalf("Unpack = %v, want %s at %d: %v", err, tt.path, tt.offset, tt.err)
			}
		})
	}
}

func TestUnpackLeavesMessageOnError(t *testing.T) {
	m := purchase(t, spec.ISO87ASCII())
	if err := m.Unpack([]byte("0200")); err == nil {
		t.Fatal("Unpack accepted a truncated message")
	}
	if m.MTI() != "0200" || !m.Has(2) {
		t.Error("failed Unpack modified the message")
	}
}
