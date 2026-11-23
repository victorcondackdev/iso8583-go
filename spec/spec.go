// Package spec describes ISO 8583 message layouts declaratively.
//
// A [Spec] says, for the MTI, the bitmaps and every data field, what the
// bytes on the wire look like: the field's data type, fixed or variable
// length, character or BCD encoding, length-prefix format, padding,
// masking policy and, for composite fields, how subfields are laid out.
// Specs are plain data: they load from JSON ([Parse], [Load], [LoadFile]),
// marshal back to JSON, and can be cloned and patched in Go. The codec in
// the parent package interprets them; nothing here touches message bytes.
//
// # Built-in specs
//
// [ISO87ASCII] and [ISO87Binary] follow the commonly published ISO
// 8583:1987 data element table. They are generic baselines meant as a
// starting point: real networks (Visa, Mastercard, Elo, domestic switches)
// redefine private fields, encodings and subfield layouts, and none of the
// built-ins is a certified network layout. Clone one, change what your
// interface document says, and keep the result in JSON next to your code.
//
// # Units
//
// Field lengths and length prefixes count units of the field's type:
// digits for n, z and x+n (the sign of x+n is not counted), characters for
// an and ans, bytes for b. A 19-digit PAN is "length": 19 whether it travels
// as 19 ASCII bytes or as 10 BCD bytes. Hex-encoded binary fields count
// bytes, not hex characters. Composite (positional and bitmapped) fields
// count the bytes of their packed subfields.
//
// # Concurrency
//
// A Spec is compiled (defaults resolved, validated) on first use and is
// then read-only: share one Spec between goroutines freely, but do not
// modify it after the first message was built with it.
package spec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
)

// Type is the ISO 8583 data type of a field.
type Type string

// Field data types.
const (
	// Numeric: digits 0-9.
	Numeric Type = "n"
	// AlphaNumeric: letters, digits and space. Space is accepted because
	// fixed an fields are space padded on the wire.
	AlphaNumeric Type = "an"
	// AlphaNumericSpecial: printable ASCII, 0x20 through 0x7E.
	AlphaNumericSpecial Type = "ans"
	// Binary: arbitrary bytes.
	Binary Type = "b"
	// Track2: magnetic stripe track 2 code set, digits and the '='
	// separator (BCD nibble D on the wire).
	Track2 Type = "z"
	// Amount: x+n, a 'C' (credit) or 'D' (debit) sign followed by digits.
	Amount Type = "xn"
)

// Encoding is how a field's data, a length prefix, the MTI or a bitmap is
// represented in bytes.
type Encoding string

// Encodings.
const (
	// ASCII: one byte per character or digit.
	ASCII Encoding = "ascii"
	// EBCDIC: one byte per character in code page 037.
	EBCDIC Encoding = "ebcdic"
	// BCD: two digits per byte (packed decimal). Odd digit counts are
	// padded with one nibble as set by Field.BCDPad.
	BCD Encoding = "bcd"
	// Raw: bytes as they are. For length prefixes, a big-endian unsigned
	// integer of one (LL) or two (LLL, LLLL) bytes.
	Raw Encoding = "binary"
	// Hex: binary data as uppercase hexadecimal ASCII, two characters per
	// byte.
	Hex Encoding = "hex"
)

// LengthType says whether a field is fixed or variable length and, if
// variable, how many digits its length prefix has.
type LengthType string

// Length types.
const (
	Fixed   LengthType = "fixed"
	LLVar   LengthType = "llvar"
	LLLVar  LengthType = "lllvar"
	LLLLVar LengthType = "llllvar"
)

// PrefixDigits returns the number of decimal digits of the length prefix:
// 0 for fixed fields, 2, 3 or 4 for variable ones, -1 if unknown.
func (l LengthType) PrefixDigits() int {
	switch l {
	case Fixed, "":
		return 0
	case LLVar:
		return 2
	case LLLVar:
		return 3
	case LLLLVar:
		return 4
	}
	return -1
}

// Pad is a padding side.
type Pad string

// Padding sides.
const (
	PadNone  Pad = ""
	PadLeft  Pad = "left"
	PadRight Pad = "right"
)

// Mask is the masking policy applied when a field is displayed.
type Mask string

// Masking policies.
const (
	// MaskNone shows the value.
	MaskNone Mask = ""
	// MaskPAN keeps the first six and last four digits.
	MaskPAN Mask = "pan"
	// MaskTrack masks track data, keeping the PAN's first six and last
	// four digits of track 2 style data.
	MaskTrack Mask = "track"
	// MaskFull hides the whole value (PIN block, CVV, keys).
	MaskFull Mask = "full"
)

// CompositeKind is the layout of a composite field's subfields.
type CompositeKind string

// Composite layouts.
const (
	// Positional: subfields follow each other in subfield-number order.
	// Trailing subfields may be absent when the field's length ends early.
	Positional CompositeKind = "positional"
	// Bitmapped: a bitmap of Composite.BitmapBytes bytes, then the present
	// subfields in bit order (bit 1 is subfield 1; there is no continuation
	// bit).
	Bitmapped CompositeKind = "bitmapped"
	// TLV: the value is BER-TLV data (EMV field 55). It is stored and packed
	// as raw bytes; the codec validates its structure when unpacking in
	// strict mode and renders the tags in dumps.
	TLV CompositeKind = "tlv"
)

// Field describes one data field or subfield.
type Field struct {
	// Name is a human-readable description used in dumps.
	Name string `json:"name"`
	// Type is the ISO data type.
	Type Type `json:"type"`
	// Length is the exact length of a fixed field or the maximum length of
	// a variable one, in units of Type (see the package documentation).
	Length int `json:"length"`
	// LengthType defaults to Fixed.
	LengthType LengthType `json:"lengthType,omitempty"`
	// Encoding of the data. Defaults come from Spec.Defaults by type.
	Encoding Encoding `json:"encoding,omitempty"`
	// PrefixEncoding of the length prefix of variable fields: ascii,
	// ebcdic, bcd or binary. Defaults to Spec.Defaults.Prefix.
	PrefixEncoding Encoding `json:"prefixEncoding,omitempty"`
	// Pad, when set, lets shorter values be assigned to a fixed field: they
	// are padded on this side with PadChar when set. Unset means values
	// must be exactly Length long.
	Pad Pad `json:"pad,omitempty"`
	// PadChar is the padding character. Defaults to "0" for n and x+n and
	// " " for an and ans.
	PadChar string `json:"padChar,omitempty"`
	// BCDPad is the side of the filler nibble when a BCD value has an odd
	// number of digits: left (filler 0) or right (filler F). Defaults to
	// right for z (track 2) and left otherwise.
	BCDPad Pad `json:"bcdPad,omitempty"`
	// Mask is the display masking policy.
	Mask Mask `json:"mask,omitempty"`
	// Composite, when set, makes this a composite field.
	Composite *Composite `json:"composite,omitempty"`

	path string
}

// Composite describes the subfields of a composite field.
type Composite struct {
	Kind CompositeKind `json:"kind"`
	// BitmapBytes is the size of a bitmapped composite's bitmap, 1 to 16
	// bytes (8 to 128 subfields). Defaults to 8.
	BitmapBytes int `json:"bitmapBytes,omitempty"`
	// BitmapEncoding of a bitmapped composite's bitmap: binary or hex.
	// Defaults to the spec's bitmap encoding.
	BitmapEncoding Encoding `json:"bitmapEncoding,omitempty"`
	// Fields are the subfields by number (1-based).
	Fields Fields `json:"fields,omitempty"`

	ids []int
}

// Fields maps field or subfield numbers to definitions. It marshals to a
// JSON object whose keys are in numeric order, so dumped specs read like
// the data element tables they come from.
type Fields map[int]*Field

// MarshalJSON implements json.Marshaler.
func (fs Fields) MarshalJSON() ([]byte, error) {
	if fs == nil {
		return []byte("null"), nil
	}
	ids := make([]int, 0, len(fs))
	for id := range fs {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var b bytes.Buffer
	b.WriteByte('{')
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:", fmt.Sprint(id))
		v, err := json.Marshal(fs[id])
		if err != nil {
			return nil, err
		}
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// IDs returns the subfield numbers in ascending order. The returned slice
// must not be modified.
func (c *Composite) IDs() []int { return c.ids }

// Path returns the field's dotted path within its spec, e.g. "2" or "48.3".
// It is set when the spec is compiled.
func (f *Field) Path() string { return f.path }

// IsVariable reports whether the field has a length prefix.
func (f *Field) IsVariable() bool { return f.LengthType.PrefixDigits() > 0 }

// IsComposite reports whether the field has positional or bitmapped
// subfields. TLV fields are not composite in this sense: their value is a
// single byte string.
func (f *Field) IsComposite() bool {
	return f.Composite != nil && f.Composite.Kind != TLV
}

// IsTLV reports whether the field carries BER-TLV data.
func (f *Field) IsTLV() bool { return f.Composite != nil && f.Composite.Kind == TLV }

// Notation returns the field's format in the usual ISO notation: "n 6",
// "n..19", "ans...999", "b 8", "z..37", "x+n 8".
func (f *Field) Notation() string {
	t := string(f.Type)
	if f.Type == Amount {
		t = "x+n"
	}
	if d := f.LengthType.PrefixDigits(); d > 0 {
		return t + strings.Repeat(".", d) + fmt.Sprint(f.Length)
	}
	return fmt.Sprintf("%s %d", t, f.Length)
}

// Defaults are the encodings used by fields that do not set their own.
type Defaults struct {
	// Numeric is the encoding of n, z and x+n fields.
	Numeric Encoding `json:"numeric"`
	// Text is the encoding of an and ans fields.
	Text Encoding `json:"text"`
	// Binary is the encoding of b fields: binary or hex.
	Binary Encoding `json:"binary"`
	// Prefix is the length-prefix encoding of variable fields.
	Prefix Encoding `json:"prefix"`
}

// Spec is a complete message layout.
type Spec struct {
	// Name identifies the spec in dumps and errors.
	Name string `json:"name"`
	// Description is free text.
	Description string `json:"description,omitempty"`
	// MTIEncoding is ascii, ebcdic or bcd.
	MTIEncoding Encoding `json:"mtiEncoding"`
	// BitmapEncoding is binary (8 bytes per bitmap) or hex (16 characters).
	BitmapEncoding Encoding `json:"bitmapEncoding"`
	// TertiaryBitmap enables fields 129-192. Bit 65 of the secondary bitmap
	// then announces the tertiary bitmap and field 65 cannot be defined.
	TertiaryBitmap bool `json:"tertiaryBitmap,omitempty"`
	// Defaults are per-type encodings for fields that do not set one.
	Defaults Defaults `json:"defaults"`
	// Fields are the data fields by number, 2 to 128 (192 with a tertiary
	// bitmap). Field 1, the secondary bitmap indicator, is implicit.
	Fields Fields `json:"fields"`

	once  sync.Once
	err   error
	table [193]*Field
}

// MaxDepth bounds composite nesting (a subfield of a subfield ...).
const MaxDepth = 4

// ErrInvalid is wrapped by every spec validation error.
var ErrInvalid = errors.New("spec: invalid")

// Error is a validation error for one field of a spec.
type Error struct {
	// Path is the dotted field path ("48.2"), or "" for spec-level errors.
	Path   string
	Reason string
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Path == "" {
		return "spec: " + e.Reason
	}
	return fmt.Sprintf("spec: field %s: %s", e.Path, e.Reason)
}

// Unwrap returns [ErrInvalid].
func (e *Error) Unwrap() error { return ErrInvalid }

// Compile resolves defaults and validates the spec. It runs once; later
// calls return the first result. Codec functions call it implicitly.
func (s *Spec) Compile() error {
	s.once.Do(func() { s.err = s.compile() })
	return s.err
}

// Field returns the compiled definition of field n, or nil when the field
// is not defined or the spec does not compile.
func (s *Spec) Field(n int) *Field {
	if n < 0 || n >= len(s.table) || s.Compile() != nil {
		return nil
	}
	return s.table[n]
}

// MaxField returns the highest field number the spec's bitmaps can carry:
// 128, or 192 with a tertiary bitmap.
func (s *Spec) MaxField() int {
	if s.TertiaryBitmap {
		return 192
	}
	return 128
}

// IDs returns the defined field numbers in ascending order.
func (s *Spec) IDs() []int {
	ids := make([]int, 0, len(s.Fields))
	for id := range s.Fields {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func (s *Spec) compile() error {
	switch s.MTIEncoding {
	case ASCII, EBCDIC, BCD:
	default:
		return &Error{Reason: fmt.Sprintf("mtiEncoding %q: want ascii, ebcdic or bcd", s.MTIEncoding)}
	}
	switch s.BitmapEncoding {
	case Raw, Hex:
	default:
		return &Error{Reason: fmt.Sprintf("bitmapEncoding %q: want binary or hex", s.BitmapEncoding)}
	}
	for _, id := range s.IDs() {
		f := s.Fields[id]
		p := fmt.Sprint(id)
		switch {
		case id < 2 || id > s.MaxField():
			return &Error{Path: p, Reason: fmt.Sprintf("field number out of range 2..%d", s.MaxField())}
		case id == 65 && s.TertiaryBitmap:
			return &Error{Path: p, Reason: "field 65 is the tertiary bitmap indicator"}
		case f == nil:
			return &Error{Path: p, Reason: "null definition"}
		}
		if err := s.compileField(f, p, 0, s.BitmapEncoding); err != nil {
			return err
		}
		s.table[id] = f
	}
	return nil
}

func (s *Spec) compileField(f *Field, path string, depth int, bitmapEnc Encoding) error {
	f.path = path
	bad := func(format string, a ...any) error {
		return &Error{Path: path, Reason: fmt.Sprintf(format, a...)}
	}
	if f.LengthType == "" {
		f.LengthType = Fixed
	}
	digits := f.LengthType.PrefixDigits()
	if digits < 0 {
		return bad("lengthType %q: want fixed, llvar, lllvar or llllvar", f.LengthType)
	}

	// Encoding defaults and compatibility.
	switch f.Type {
	case Numeric, Track2, Amount:
		if f.Encoding == "" {
			f.Encoding = s.Defaults.Numeric
		}
		if f.Encoding != ASCII && f.Encoding != EBCDIC && f.Encoding != BCD {
			return bad("type %s cannot use encoding %q", f.Type, f.Encoding)
		}
	case AlphaNumeric, AlphaNumericSpecial:
		if f.Encoding == "" {
			f.Encoding = s.Defaults.Text
		}
		if f.Encoding != ASCII && f.Encoding != EBCDIC {
			return bad("type %s cannot use encoding %q", f.Type, f.Encoding)
		}
	case Binary:
		if f.Encoding == "" {
			f.Encoding = s.Defaults.Binary
		}
		if f.Encoding != Raw && f.Encoding != Hex {
			return bad("type b cannot use encoding %q", f.Encoding)
		}
	default:
		return bad("unknown type %q", f.Type)
	}

	// Lengths.
	if f.Length < 1 {
		return bad("length must be positive")
	}
	if digits > 0 {
		if max := []int{0, 0, 99, 999, 9999}[digits]; f.Length > max {
			return bad("length %d exceeds the %s maximum of %d", f.Length, f.LengthType, max)
		}
		if f.PrefixEncoding == "" {
			f.PrefixEncoding = s.Defaults.Prefix
		}
		switch f.PrefixEncoding {
		case ASCII, EBCDIC, BCD, Raw:
		default:
			return bad("prefixEncoding %q: want ascii, ebcdic, bcd or binary", f.PrefixEncoding)
		}
	} else {
		if f.Length > 9999 {
			return bad("fixed length %d is too large", f.Length)
		}
		f.PrefixEncoding = ""
	}

	// Padding.
	switch f.Pad {
	case PadNone, PadLeft, PadRight:
	default:
		return bad("pad %q: want left or right", f.Pad)
	}
	if f.Pad != PadNone {
		if f.Type == Binary || f.Composite != nil {
			return bad("pad is not supported for binary or composite fields")
		}
		if f.PadChar == "" {
			f.PadChar = "0"
			if f.Type == AlphaNumeric || f.Type == AlphaNumericSpecial {
				f.PadChar = " "
			}
		}
		if len(f.PadChar) != 1 || !ValidChar(f.Type, f.PadChar[0]) {
			return bad("padChar %q is not a valid %s character", f.PadChar, f.Type)
		}
		if f.Type == Amount && f.Pad != PadLeft {
			return bad("x+n fields can only be left padded")
		}
	} else if f.PadChar != "" {
		return bad("padChar set without pad")
	}
	switch f.BCDPad {
	case PadNone:
		f.BCDPad = PadLeft
		if f.Type == Track2 {
			f.BCDPad = PadRight
		}
	case PadLeft, PadRight:
	default:
		return bad("bcdPad %q: want left or right", f.BCDPad)
	}

	switch f.Mask {
	case MaskNone, MaskPAN, MaskTrack, MaskFull:
	default:
		return bad("mask %q: want pan, track or full", f.Mask)
	}

	if f.Composite == nil {
		return nil
	}
	return s.compileComposite(f, path, depth, bitmapEnc)
}

func (s *Spec) compileComposite(f *Field, path string, depth int, bitmapEnc Encoding) error {
	c := f.Composite
	bad := func(format string, a ...any) error {
		return &Error{Path: path, Reason: fmt.Sprintf(format, a...)}
	}
	switch c.Kind {
	case TLV:
		if f.Type != Binary {
			return bad("tlv composite requires type b")
		}
		if len(c.Fields) > 0 {
			return bad("tlv composite cannot declare subfields")
		}
		return nil
	case Positional, Bitmapped:
	default:
		return bad("composite kind %q: want positional, bitmapped or tlv", c.Kind)
	}
	if f.Type != Binary && f.Type != AlphaNumericSpecial {
		return bad("positional and bitmapped composites require type b or ans")
	}
	if depth+1 > MaxDepth {
		return bad("composite nesting deeper than %d", MaxDepth)
	}
	if len(c.Fields) == 0 {
		return bad("composite has no subfields")
	}
	maxSub := 9999
	if c.Kind == Bitmapped {
		if c.BitmapBytes == 0 {
			c.BitmapBytes = 8
		}
		if c.BitmapBytes < 1 || c.BitmapBytes > 16 {
			return bad("bitmapBytes %d: want 1..16", c.BitmapBytes)
		}
		if c.BitmapEncoding == "" {
			c.BitmapEncoding = bitmapEnc
		}
		if c.BitmapEncoding != Raw && c.BitmapEncoding != Hex {
			return bad("bitmapEncoding %q: want binary or hex", c.BitmapEncoding)
		}
		maxSub = c.BitmapBytes * 8
	} else if c.BitmapBytes != 0 || c.BitmapEncoding != "" {
		return bad("bitmap settings are only valid for bitmapped composites")
	}
	c.ids = c.ids[:0]
	for id := range c.Fields {
		c.ids = append(c.ids, id)
	}
	sort.Ints(c.ids)
	for _, id := range c.ids {
		sub := c.Fields[id]
		p := fmt.Sprintf("%s.%d", path, id)
		if id < 1 || id > maxSub {
			return &Error{Path: p, Reason: fmt.Sprintf("subfield number out of range 1..%d", maxSub)}
		}
		if sub == nil {
			return &Error{Path: p, Reason: "null definition"}
		}
		if err := s.compileField(sub, p, depth+1, c.BitmapEncoding); err != nil {
			return err
		}
	}
	return nil
}

// ValidChar reports whether c belongs to the character set of type t, as
// enforced in strict mode. Binary accepts any byte.
func ValidChar(t Type, c byte) bool {
	switch t {
	case Numeric:
		return c >= '0' && c <= '9'
	case Track2:
		return c >= '0' && c <= '9' || c == '='
	case AlphaNumeric:
		return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == ' '
	case AlphaNumericSpecial:
		return c >= 0x20 && c <= 0x7E
	case Amount:
		return c >= '0' && c <= '9' || c == 'C' || c == 'D'
	case Binary:
		return true
	}
	return false
}

// Parse decodes and compiles a JSON spec. Unknown JSON keys are rejected so
// that typos in hand-written specs surface immediately.
func Parse(data []byte) (*Spec, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	s := new(Spec)
	if err := dec.Decode(s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := s.Compile(); err != nil {
		return nil, err
	}
	return s, nil
}

// Load reads a JSON spec from r.
func Load(r io.Reader) (*Spec, error) {
	data, err := io.ReadAll(io.LimitReader(r, 4<<20))
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// LoadFile reads a JSON spec from a file.
func LoadFile(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Clone returns a deep, uncompiled copy of s, ready to be modified.
func (s *Spec) Clone() *Spec {
	data, err := json.Marshal(s)
	if err != nil { // cannot happen: Spec holds only JSON-safe values
		panic(err)
	}
	c := new(Spec)
	if err := json.Unmarshal(data, c); err != nil {
		panic(err)
	}
	return c
}

// Lookup returns a fresh copy of a built-in spec by case-insensitive name:
// "iso87ascii" or "iso87binary".
func Lookup(name string) (*Spec, error) {
	switch strings.ToLower(name) {
	case "iso87ascii":
		return ISO87ASCII(), nil
	case "iso87binary":
		return ISO87Binary(), nil
	}
	return nil, fmt.Errorf("spec: unknown built-in spec %q (want iso87ascii or iso87binary)", name)
}
