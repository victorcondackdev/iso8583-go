package spec

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuiltins(t *testing.T) {
	for _, s := range []*Spec{ISO87ASCII(), ISO87Binary()} {
		if err := s.Compile(); err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		if got := len(s.Fields); got != 126 { // 2..128 minus 65
			t.Errorf("%s has %d fields", s.Name, got)
		}
		if s.Field(1) != nil || s.Field(65) != nil || s.Field(200) != nil || s.Field(-1) != nil {
			t.Errorf("%s defines reserved fields", s.Name)
		}
		pan := s.Field(2)
		if pan.Path() != "2" || pan.Mask != MaskPAN || !pan.IsVariable() || pan.Notation() != "n..19" {
			t.Errorf("%s field 2 = %+v", s.Name, pan)
		}
		if !s.Field(55).IsTLV() || s.Field(55).IsComposite() {
			t.Errorf("%s field 55 is not TLV", s.Name)
		}
		if s.MaxField() != 128 {
			t.Errorf("MaxField = %d", s.MaxField())
		}
		// The JSON form loads back to the same spec.
		data, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		back, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: Parse(Marshal) = %v", s.Name, err)
		}
		if !reflect.DeepEqual(back.Fields, s.Fields) {
			t.Errorf("%s: JSON round trip differs", s.Name)
		}
	}
	a, b := ISO87ASCII(), ISO87ASCII()
	if a == b || a.Fields[2] == b.Fields[2] {
		t.Error("built-in constructors share state")
	}
	if ISO87Binary().Field(35).BCDPad != PadRight || ISO87Binary().Field(2).BCDPad != PadLeft {
		t.Error("BCD padding defaults")
	}
}

func TestNotation(t *testing.T) {
	s := ISO87ASCII()
	for id, want := range map[int]string{3: "n 6", 28: "x+n 8", 35: "z..37", 36: "n...104", 52: "b 8", 55: "b...999"} {
		if got := s.Field(id).Notation(); got != want {
			t.Errorf("field %d Notation = %q, want %q", id, got, want)
		}
	}
	f := &Field{Type: AlphaNumericSpecial, Length: 9999, LengthType: LLLLVar}
	if f.Notation() != "ans....9999" {
		t.Errorf("Notation = %q", f.Notation())
	}
	if LengthType("x").PrefixDigits() != -1 {
		t.Error("PrefixDigits of unknown type")
	}
}

func TestLookupAndClone(t *testing.T) {
	for _, name := range []string{"iso87ascii", "ISO87Binary"} {
		if s, err := Lookup(name); err != nil || s == nil {
			t.Errorf("Lookup(%s) = %v", name, err)
		}
	}
	if _, err := Lookup("visa"); err == nil {
		t.Error("Lookup(visa) succeeded")
	}
	s := ISO87ASCII()
	c := s.Clone()
	c.Fields[2].Length = 12
	if s.Fields[2].Length != 19 {
		t.Error("Clone shares fields")
	}
	if err := c.Compile(); err != nil {
		t.Fatal(err)
	}
}

func TestLoad(t *testing.T) {
	s, err := LoadFile("../examples/acme-spec.json")
	if err != nil {
		t.Fatal(err)
	}
	f := s.Field(48)
	if !f.IsComposite() || f.Composite.Kind != Positional || !reflect.DeepEqual(f.Composite.IDs(), []int{1, 2, 3}) {
		t.Fatalf("field 48 = %+v", f.Composite)
	}
	if f.Composite.Fields[2].Path() != "48.2" || f.Composite.Fields[2].Mask != MaskFull {
		t.Errorf("48.2 = %+v", f.Composite.Fields[2])
	}
	if c := s.Field(62).Composite; c.BitmapBytes != 8 || c.BitmapEncoding != Hex {
		t.Errorf("62 bitmap = %d %s", c.BitmapBytes, c.BitmapEncoding)
	}
	if _, err := LoadFile("does-not-exist.json"); err == nil {
		t.Error("LoadFile of a missing file")
	}
	if _, err := Load(strings.NewReader(`{"name":"x","mtiEncoding":"ascii","bitmapEncoding":"hex","fieldz":{}}`)); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown key: %v", err)
	}
	if _, err := Load(errReader{}); err == nil {
		t.Error("Load of a failing reader")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte(`{"name":"x","mtiEncoding":"ascii","bitmapEncoding":"hex","fields":{"2":{"name":"x","type":"q","length":1}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var se *Error
	if _, err := LoadFile(p); !errors.As(err, &se) || se.Path != "2" {
		t.Errorf("LoadFile(bad) = %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestValidation(t *testing.T) {
	base := func(fields string) string {
		return `{"name":"t","mtiEncoding":"ascii","bitmapEncoding":"hex",
			"defaults":{"numeric":"ascii","text":"ascii","binary":"hex","prefix":"ascii"},"fields":{` + fields + `}}`
	}
	tests := []struct {
		name string
		json string
		path string
		msg  string
	}{
		{"mti encoding", `{"name":"t","mtiEncoding":"hex","bitmapEncoding":"hex"}`, "", "mtiEncoding"},
		{"bitmap encoding", `{"name":"t","mtiEncoding":"ascii","bitmapEncoding":"bcd"}`, "", "bitmapEncoding"},
		{"field 1", base(`"1":{"name":"x","type":"n","length":1}`), "1", "out of range"},
		{"field 129", base(`"129":{"name":"x","type":"n","length":1}`), "129", "out of range"},
		{"null", base(`"2":null`), "2", "null"},
		{"type", base(`"2":{"name":"x","type":"q","length":1}`), "2", "unknown type"},
		{"n encoding", base(`"2":{"name":"x","type":"n","length":1,"encoding":"hex"}`), "2", "cannot use encoding"},
		{"an encoding", base(`"2":{"name":"x","type":"an","length":1,"encoding":"bcd"}`), "2", "cannot use encoding"},
		{"b encoding", base(`"2":{"name":"x","type":"b","length":1,"encoding":"ascii"}`), "2", "cannot use encoding"},
		{"length zero", base(`"2":{"name":"x","type":"n","length":0}`), "2", "positive"},
		{"length type", base(`"2":{"name":"x","type":"n","length":1,"lengthType":"lvar"}`), "2", "lengthType"},
		{"LL max", base(`"2":{"name":"x","type":"n","length":100,"lengthType":"llvar"}`), "2", "exceeds"},
		{"fixed max", base(`"2":{"name":"x","type":"n","length":10000}`), "2", "too large"},
		{"prefix encoding", base(`"2":{"name":"x","type":"n","length":9,"lengthType":"llvar","prefixEncoding":"hex"}`), "2", "prefixEncoding"},
		{"pad side", base(`"2":{"name":"x","type":"n","length":9,"pad":"middle"}`), "2", "pad"},
		{"pad binary", base(`"2":{"name":"x","type":"b","length":9,"pad":"left"}`), "2", "not supported"},
		{"pad char", base(`"2":{"name":"x","type":"n","length":9,"pad":"left","padChar":"x"}`), "2", "padChar"},
		{"pad char alone", base(`"2":{"name":"x","type":"n","length":9,"padChar":"0"}`), "2", "without pad"},
		{"x+n right pad", base(`"2":{"name":"x","type":"xn","length":9,"pad":"right"}`), "2", "left padded"},
		{"bcd pad", base(`"2":{"name":"x","type":"n","length":9,"bcdPad":"up"}`), "2", "bcdPad"},
		{"mask", base(`"2":{"name":"x","type":"n","length":9,"mask":"half"}`), "2", "mask"},
		{"kind", base(`"2":{"name":"x","type":"b","length":9,"composite":{"kind":"xml"}}`), "2", "composite kind"},
		{"tlv type", base(`"2":{"name":"x","type":"ans","length":9,"composite":{"kind":"tlv"}}`), "2", "type b"},
		{"tlv subfields", base(`"2":{"name":"x","type":"b","length":9,"composite":{"kind":"tlv","fields":{"1":{"name":"y","type":"n","length":1}}}}`), "2", "cannot declare"},
		{"composite type", base(`"2":{"name":"x","type":"n","length":9,"composite":{"kind":"positional","fields":{"1":{"name":"y","type":"n","length":1}}}}`), "2", "type b or ans"},
		{"no subfields", base(`"2":{"name":"x","type":"ans","length":9,"composite":{"kind":"positional"}}`), "2", "no subfields"},
		{"bitmap bytes", base(`"2":{"name":"x","type":"ans","length":9,"composite":{"kind":"bitmapped","bitmapBytes":17,"fields":{"1":{"name":"y","type":"n","length":1}}}}`), "2", "bitmapBytes"},
		{"sub bitmap enc", base(`"2":{"name":"x","type":"ans","length":9,"composite":{"kind":"bitmapped","bitmapEncoding":"bcd","fields":{"1":{"name":"y","type":"n","length":1}}}}`), "2", "bitmapEncoding"},
		{"positional bitmap", base(`"2":{"name":"x","type":"ans","length":9,"composite":{"kind":"positional","bitmapBytes":8,"fields":{"1":{"name":"y","type":"n","length":1}}}}`), "2", "only valid"},
		{"sub range", base(`"2":{"name":"x","type":"ans","length":9,"composite":{"kind":"bitmapped","bitmapBytes":1,"fields":{"9":{"name":"y","type":"n","length":1}}}}`), "2.9", "out of range"},
		{"sub zero", base(`"2":{"name":"x","type":"ans","length":9,"composite":{"kind":"positional","fields":{"0":{"name":"y","type":"n","length":1}}}}`), "2.0", "out of range"},
		{"sub null", base(`"2":{"name":"x","type":"ans","length":9,"composite":{"kind":"positional","fields":{"1":null}}}`), "2.1", "null"},
		{"sub invalid", base(`"2":{"name":"x","type":"ans","length":9,"composite":{"kind":"positional","fields":{"1":{"name":"y","type":"n","length":0}}}}`), "2.1", "positive"},
		{"tertiary 65", `{"name":"t","mtiEncoding":"ascii","bitmapEncoding":"hex","tertiaryBitmap":true,"defaults":{"numeric":"ascii"},"fields":{"65":{"name":"x","type":"n","length":1}}}`, "65", "tertiary"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.json))
			var se *Error
			if !errors.As(err, &se) || se.Path != tt.path || !strings.Contains(err.Error(), tt.msg) || !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse = %v, want path %q containing %q", err, tt.path, tt.msg)
			}
		})
	}
	if _, err := Parse([]byte(`{`)); !errors.Is(err, ErrInvalid) {
		t.Errorf("syntax error: %v", err)
	}
}

func TestNestingDepth(t *testing.T) {
	leaf := &Field{Name: "leaf", Type: Numeric, Length: 1}
	f := leaf
	for i := 0; i < MaxDepth+1; i++ {
		f = &Field{Name: "c", Type: AlphaNumericSpecial, Length: 99, LengthType: LLVar,
			Composite: &Composite{Kind: Positional, Fields: map[int]*Field{1: f}}}
	}
	s := &Spec{Name: "deep", MTIEncoding: ASCII, BitmapEncoding: Hex,
		Defaults: Defaults{Numeric: ASCII, Text: ASCII, Binary: Hex, Prefix: ASCII}, Fields: map[int]*Field{48: f}}
	if err := s.Compile(); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Errorf("Compile = %v", err)
	}
	if s.Field(48) != nil {
		t.Error("Field() on a spec that does not compile")
	}
}

func TestTertiary(t *testing.T) {
	s := ISO87Binary().Clone()
	s.TertiaryBitmap = true
	s.Fields[192] = &Field{Name: "MAC", Type: Binary, Length: 8}
	if err := s.Compile(); err != nil {
		t.Fatal(err)
	}
	if s.MaxField() != 192 || s.Field(192) == nil {
		t.Error("tertiary field 192")
	}
}

func TestValidChar(t *testing.T) {
	tests := []struct {
		t    Type
		ok   string
		fail string
	}{
		{Numeric, "0123456789", "a=- "},
		{Track2, "0123456789=", "DdA "},
		{AlphaNumeric, "azAZ09 ", "-_=\x00"},
		{AlphaNumericSpecial, " ~!@#{}", "\x00\x1F\x7F\xFF"},
		{Amount, "CD0123456789", "c+-"},
		{Binary, "\x00\xFFa", ""},
		{"q", "", "a0"},
	}
	for _, tt := range tests {
		for i := 0; i < len(tt.ok); i++ {
			if !ValidChar(tt.t, tt.ok[i]) {
				t.Errorf("ValidChar(%s, %q) = false", tt.t, tt.ok[i])
			}
		}
		for i := 0; i < len(tt.fail); i++ {
			if ValidChar(tt.t, tt.fail[i]) {
				t.Errorf("ValidChar(%s, %q) = true", tt.t, tt.fail[i])
			}
		}
	}
}

func TestErrorString(t *testing.T) {
	if got := (&Error{Reason: "r"}).Error(); got != "spec: r" {
		t.Errorf("Error() = %q", got)
	}
	if got := (&Error{Path: "48.2", Reason: "r"}).Error(); got != "spec: field 48.2: r" {
		t.Errorf("Error() = %q", got)
	}
}

// FuzzParse checks that arbitrary JSON never makes spec loading panic.
func FuzzParse(f *testing.F) {
	data, _ := os.ReadFile("../examples/acme-spec.json")
	f.Add(data)
	f.Add([]byte(`{"name":"t","mtiEncoding":"bcd","bitmapEncoding":"binary","fields":{"2":{"name":"x","type":"z","length":37,"lengthType":"llvar"}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Parse(data)
		if err == nil {
			_ = s.IDs()
			_ = s.Clone()
		}
	})
}
