package iso8583

import (
	"fmt"

	"github.com/victorcondackdev/iso8583-go/spec"
)

// bitmap returns the bitmaps implied by the present fields, with bit 1 set
// when fields 65-128 are present and bit 65 when 129-192 are, and the number
// of 8-byte bitmaps that must be sent (1, 2 or 3).
func (m *Message) bitmap() ([24]byte, int) {
	var bm [24]byte
	hi := 0
	for id := 2; id < len(m.fields); id++ {
		if m.fields[id] != nil {
			setBit(bm[:], id)
			hi = id
		}
	}
	count := 1
	if hi > 64 {
		setBit(bm[:], 1)
		count = 2
	}
	if hi > 128 {
		setBit(bm[:], 65)
		count = 3
	}
	return bm, count
}

// setBit sets bit n (1-based, most significant bit of byte 0 first).
func setBit(b []byte, n int) { b[(n-1)/8] |= 0x80 >> ((n - 1) % 8) }

// bitSet reports whether bit n (1-based) is set.
func bitSet(b []byte, n int) bool { return b[(n-1)/8]&(0x80>>((n-1)%8)) != 0 }

// Pack encodes the message. Bitmaps are computed from the present fields:
// the secondary bitmap is sent only when a field above 64 is present, the
// tertiary only above 128.
func (m *Message) Pack() ([]byte, error) {
	return m.AppendPack(make([]byte, 0, 256))
}

// AppendPack appends the encoded message to dst, which lets callers reuse
// buffers or reserve room for a frame header.
func (m *Message) AppendPack(dst []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.mti == "" {
		return nil, &FieldError{Field: FieldMTI, Offset: -1, Err: ErrNotSet, Reason: "MTI is not set"}
	}
	base := len(dst)
	switch m.spec.MTIEncoding {
	case spec.BCD:
		dst, _ = appendBCD(dst, []byte(m.mti), false) // validated by SetMTI
	default:
		dst = appendText(dst, []byte(m.mti), m.spec.MTIEncoding)
	}

	bm, count := m.bitmap()
	if m.spec.BitmapEncoding == spec.Hex {
		dst = appendHex(dst, bm[:8*count])
	} else {
		dst = append(dst, bm[:8*count]...)
	}

	for id := 2; id < len(m.fields); id++ {
		n := m.fields[id]
		if n == nil {
			continue
		}
		f := m.spec.Field(id)
		var err error
		start := len(dst)
		if dst, err = packField(dst, f, n, id); err != nil {
			if fe, ok := err.(*FieldError); ok && fe.Offset < 0 {
				fe.Offset = start - base
			}
			return nil, err
		}
	}
	return dst, nil
}

// packField appends the length prefix and data of field f.
func packField(dst []byte, f *spec.Field, n *node, top int) ([]byte, error) {
	fail := func(ferr *fault) error {
		return &FieldError{Field: top, Path: f.Path(), Offset: -1, Err: ferr.err, Reason: ferr.reason}
	}
	if f.IsComposite() {
		content, err := packComposite(nil, f, n, top)
		if err != nil {
			return dst, err
		}
		if ferr := checkLength(f, len(content)); ferr != nil {
			return dst, fail(ferr)
		}
		if d := f.LengthType.PrefixDigits(); d > 0 {
			dst = appendPrefix(dst, d, f.PrefixEncoding, len(content))
		}
		return append(dst, content...), nil
	}
	units := unitsOf(f, n.val)
	if ferr := checkLength(f, units); ferr != nil {
		return dst, fail(ferr)
	}
	if d := f.LengthType.PrefixDigits(); d > 0 {
		dst = appendPrefix(dst, d, f.PrefixEncoding, units)
	}
	dst, ferr := appendData(dst, f, n.val)
	if ferr != nil {
		return dst, fail(ferr)
	}
	return dst, nil
}

func checkLength(f *spec.Field, units int) *fault {
	switch {
	case units < 0:
		return faultf(ErrLength, "x+n value has no sign")
	case f.LengthType == spec.Fixed && units != f.Length:
		return faultf(ErrLength, "length %d, field is fixed at %d", units, f.Length)
	case units > f.Length:
		return faultf(ErrLength, "length %d exceeds the maximum of %d", units, f.Length)
	}
	return nil
}

// packComposite appends the packed subfields of a positional or bitmapped
// composite field.
func packComposite(dst []byte, f *spec.Field, n *node, top int) ([]byte, error) {
	c := f.Composite
	if c.Kind == spec.Bitmapped {
		bm := make([]byte, c.BitmapBytes)
		for id := range n.sub {
			setBit(bm, id)
		}
		if c.BitmapEncoding == spec.Hex {
			dst = appendHex(dst, bm)
		} else {
			dst = append(dst, bm...)
		}
		for _, id := range c.IDs() {
			if sn := n.sub[id]; sn != nil {
				var err error
				if dst, err = packField(dst, c.Fields[id], sn, top); err != nil {
					return dst, err
				}
			}
		}
		return dst, nil
	}

	// Positional: emit every subfield up to the last present one. Absent
	// subfields in between are filled when the spec makes that unambiguous.
	last := -1
	ids := c.IDs()
	for i, id := range ids {
		if n.sub[id] != nil {
			last = i
		}
	}
	for _, id := range ids[:last+1] {
		sf := c.Fields[id]
		sn := n.sub[id]
		if sn == nil {
			filler, ok := fillerFor(sf)
			if !ok {
				return dst, &FieldError{Field: top, Path: sf.Path(), Offset: -1, Err: ErrNotSet,
					Reason: fmt.Sprintf("subfield %s must be set because a later subfield is", sf.Path())}
			}
			sn = &node{val: filler}
		}
		var err error
		if dst, err = packField(dst, sf, sn, top); err != nil {
			return dst, err
		}
	}
	return dst, nil
}

// fillerFor returns the value used for an absent positional subfield: empty
// for variable fields, all padding for padded fixed fields.
func fillerFor(f *spec.Field) ([]byte, bool) {
	switch {
	case f.IsComposite():
		return nil, false
	case f.IsVariable():
		if f.Type == spec.Amount {
			return nil, false
		}
		return []byte{}, true
	case f.Pad != spec.PadNone && f.Type != spec.Amount:
		b := make([]byte, f.Length)
		for i := range b {
			b[i] = f.PadChar[0]
		}
		return b, true
	}
	return nil, false
}
