// Package tlv parses and builds BER-TLV data as used by EMV chip cards and
// carried in ISO 8583 field 55 ("ICC system related data").
//
// The subset of ISO/IEC 8825-1 BER that EMV Book 3 Annex B allows is
// supported:
//
//   - Multi-byte tags: when the low five bits of the first tag byte are all
//     set (0x1F), further tag bytes follow while their high bit is set.
//     9F02 and 5F2A are two-byte tags. Tags of up to four bytes are accepted.
//   - Constructed tags: bit 6 (0x20) of the first tag byte marks a template
//     whose value is itself TLV data (70, 77, 71, 72, ...). Their children
//     are parsed recursively.
//   - Short and long length forms: lengths below 128 take one byte; longer
//     ones are 0x81 nn, 0x82 nn nn, ... up to four length bytes. The
//     indefinite form (0x80) is rejected, as EMV forbids it.
//   - Padding: 0x00 bytes before, between or after objects carry no meaning
//     and are skipped.
//
// Parsing is strict about structure (a length that runs past the input is
// an error, with its byte offset) and never panics: [Parse] is fuzzed.
package tlv

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/victorcondackdev/iso8583-go/card"
)

// MaxDepth bounds how deeply constructed objects may nest. EMV data rarely
// goes past two levels; the limit keeps hostile input from recursing.
const MaxDepth = 16

// Sentinel errors, wrapped by [*ParseError].
var (
	// ErrTruncated reports a tag, length or value that runs past the end of
	// the input.
	ErrTruncated = errors.New("tlv: truncated")
	// ErrTag reports an invalid tag: zero, or longer than four bytes.
	ErrTag = errors.New("tlv: invalid tag")
	// ErrLength reports an indefinite or oversized length.
	ErrLength = errors.New("tlv: invalid length")
	// ErrDepth reports constructed objects nested deeper than [MaxDepth].
	ErrDepth = errors.New("tlv: nesting too deep")
)

// ParseError is a BER-TLV syntax error with the byte offset at which it was
// detected and the tag being read, if known.
type ParseError struct {
	Offset int
	Tag    Tag
	Err    error
}

// Error implements the error interface.
func (e *ParseError) Error() string {
	if e.Tag != 0 {
		return fmt.Sprintf("%v (tag %s at offset %d)", e.Err, e.Tag, e.Offset)
	}
	return fmt.Sprintf("%v at offset %d", e.Err, e.Offset)
}

// Unwrap returns the sentinel error.
func (e *ParseError) Unwrap() error { return e.Err }

// Tag is a BER tag, its bytes packed big-endian into an integer: the
// two-byte tag 9F 26 is Tag(0x9F26).
type Tag uint32

// String returns the tag as uppercase hex, two digits per tag byte.
func (t Tag) String() string { return strings.ToUpper(hex.EncodeToString(t.Bytes())) }

// Bytes returns the encoded tag.
func (t Tag) Bytes() []byte {
	switch {
	case t > 0xFFFFFF:
		return []byte{byte(t >> 24), byte(t >> 16), byte(t >> 8), byte(t)}
	case t > 0xFFFF:
		return []byte{byte(t >> 16), byte(t >> 8), byte(t)}
	case t > 0xFF:
		return []byte{byte(t >> 8), byte(t)}
	}
	return []byte{byte(t)}
}

// first returns the first encoded byte of the tag.
func (t Tag) first() byte { return t.Bytes()[0] }

// Constructed reports whether the tag denotes a constructed object (bit 6
// of the first byte set).
func (t Tag) Constructed() bool { return t.first()&0x20 != 0 }

// Class returns the tag class from bits 8-7 of the first byte: 0 universal,
// 1 application, 2 context-specific, 3 private.
func (t Tag) Class() int { return int(t.first() >> 6) }

// Name returns the EMV name of the tag from the built-in dictionary, or "".
func (t Tag) Name() string { return dictionary[t].name }

// Sensitive reports whether the tag carries cardholder data that must be
// masked in logs (PAN, track equivalents, cardholder name, expiry).
func (t Tag) Sensitive() bool { return dictionary[t].sensitive }

// ParseTag parses a tag written as hex, e.g. "9F02". It checks that the
// bytes form exactly one well-formed BER tag.
func ParseTag(s string) (Tag, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) == 0 {
		return 0, fmt.Errorf("%w: %q", ErrTag, s)
	}
	t, n, err := readTag(b)
	if err != nil || n != len(b) || t == 0 {
		return 0, fmt.Errorf("%w: %q", ErrTag, s)
	}
	return t, nil
}

// TLV is one data object. For a primitive tag, Value holds the value bytes.
// For a constructed tag, Children holds the nested objects; on [Parse],
// Value also holds the raw content they were parsed from.
type TLV struct {
	Tag      Tag
	Value    []byte
	Children List
}

// New returns a primitive object.
func New(tag Tag, value []byte) TLV { return TLV{Tag: tag, Value: value} }

// NewConstructed returns a constructed object (template) holding children.
func NewConstructed(tag Tag, children ...TLV) TLV { return TLV{Tag: tag, Children: children} }

// content returns the encoded value of the object: Value for primitive
// objects, and for constructed ones the encoding of Children when present,
// else Value.
func (t TLV) content() []byte {
	if t.Tag.Constructed() && len(t.Children) > 0 {
		return t.Children.Bytes()
	}
	return t.Value
}

// List is a sequence of data objects in wire order.
type List []TLV

// Find returns the first object with the given tag, searching depth-first
// through constructed objects.
func (l List) Find(tag Tag) (TLV, bool) {
	for _, t := range l {
		if t.Tag == tag {
			return t, true
		}
		if f, ok := t.Children.Find(tag); ok {
			return f, true
		}
	}
	return TLV{}, false
}

// Bytes encodes the list using minimal length forms.
func (l List) Bytes() []byte { return l.AppendTo(nil) }

// AppendTo appends the encoding of the list to dst.
func (l List) AppendTo(dst []byte) []byte {
	for _, t := range l {
		c := t.content()
		dst = append(dst, t.Tag.Bytes()...)
		dst = appendLength(dst, len(c))
		dst = append(dst, c...)
	}
	return dst
}

func appendLength(dst []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(dst, byte(n))
	case n <= 0xFF:
		return append(dst, 0x81, byte(n))
	case n <= 0xFFFF:
		return append(dst, 0x82, byte(n>>8), byte(n))
	case n <= 0xFFFFFF:
		return append(dst, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(dst, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// Parse parses BER-TLV data. Constructed objects are parsed recursively.
// Errors are [*ParseError] values with the absolute offset of the problem.
func Parse(b []byte) (List, error) { return parse(b, 0, 0) }

func parse(b []byte, base, depth int) (List, error) {
	if depth > MaxDepth {
		return nil, &ParseError{Offset: base, Err: ErrDepth}
	}
	var out List
	i := 0
	for i < len(b) {
		if b[i] == 0x00 { // inter-object padding
			i++
			continue
		}
		start := i
		tag, n, err := readTag(b[i:])
		if err != nil {
			return nil, &ParseError{Offset: base + start, Err: err}
		}
		i += n
		length, n, err := readLength(b[i:])
		if err != nil {
			return nil, &ParseError{Offset: base + i, Tag: tag, Err: err}
		}
		i += n
		if length > len(b)-i {
			return nil, &ParseError{Offset: base + i, Tag: tag,
				Err: fmt.Errorf("%w: value needs %d bytes, %d left", ErrTruncated, length, len(b)-i)}
		}
		v := b[i : i+length : i+length]
		obj := TLV{Tag: tag, Value: v}
		if tag.Constructed() {
			obj.Children, err = parse(v, base+i, depth+1)
			if err != nil {
				return nil, err
			}
		}
		i += length
		out = append(out, obj)
	}
	return out, nil
}

// readTag reads one tag from the start of b and returns it with its size.
func readTag(b []byte) (Tag, int, error) {
	if len(b) == 0 {
		return 0, 0, ErrTruncated
	}
	t := Tag(b[0])
	if b[0]&0x1F != 0x1F {
		return t, 1, nil
	}
	for i := 1; ; i++ {
		if i >= len(b) {
			return 0, 0, ErrTruncated
		}
		if i >= 4 {
			return 0, 0, ErrTag
		}
		t = t<<8 | Tag(b[i])
		if b[i]&0x80 == 0 {
			return t, i + 1, nil
		}
	}
}

// readLength reads one length from the start of b and returns it with its
// size.
func readLength(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, ErrTruncated
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, nil
	}
	n := int(b[0] & 0x7F)
	if n == 0 || n > 4 {
		return 0, 0, fmt.Errorf("%w: length byte %#02x", ErrLength, b[0])
	}
	if len(b) < 1+n {
		return 0, 0, ErrTruncated
	}
	v := 0
	for _, c := range b[1 : 1+n] {
		v = v<<8 | int(c)
	}
	if v < 0 || v > 1<<24 { // far beyond any ISO 8583 field
		return 0, 0, fmt.Errorf("%w: %d bytes", ErrLength, v)
	}
	return v, 1 + n, nil
}

// MaskedValue returns the object's value as uppercase hex, masked when the
// tag is [Tag.Sensitive]: the PAN (5A) keeps its first six and last four
// digits, track 2 equivalent data (57) is masked like magnetic track 2, and
// other sensitive tags are replaced by '*'. Trailing 'F' padding nibbles of
// 5A and 57 are dropped before masking.
func MaskedValue(t TLV) string {
	h := strings.ToUpper(hex.EncodeToString(t.content()))
	if !t.Tag.Sensitive() {
		return h
	}
	switch t.Tag {
	case 0x5A:
		return card.MaskPAN(strings.TrimRight(h, "F"))
	case 0x57:
		return card.MaskTrack(strings.TrimRight(h, "F"))
	}
	return strings.Repeat("*", len(h))
}

// String renders the list one object per line, with tag names from the
// dictionary and sensitive values masked by [MaskedValue]. Children of
// constructed objects are indented by two spaces.
func (l List) String() string {
	var sb strings.Builder
	l.describe(&sb, "")
	return strings.TrimSuffix(sb.String(), "\n")
}

func (l List) describe(sb *strings.Builder, indent string) {
	for _, t := range l {
		sb.WriteString(indent)
		sb.WriteString(t.Tag.String())
		if name := t.Tag.Name(); name != "" {
			sb.WriteString(" ")
			sb.WriteString(name)
		}
		if t.Tag.Constructed() && len(t.Children) > 0 {
			sb.WriteString("\n")
			t.Children.describe(sb, indent+"  ")
			continue
		}
		sb.WriteString(": ")
		sb.WriteString(MaskedValue(t))
		sb.WriteString("\n")
	}
}
