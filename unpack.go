package iso8583

import (
	"errors"
	"fmt"

	"github.com/victorcondackdev/iso8583-go/spec"
	"github.com/victorcondackdev/iso8583-go/tlv"
)

// Unpack decodes data into the message, replacing its MTI and fields.
// Errors are [*FieldError] values naming the field and the byte offset at
// which decoding failed. On error the message is left unchanged.
func (m *Message) Unpack(data []byte) error {
	if m.err != nil {
		return m.err
	}
	// Decoded values never exceed twice the input (BCD doubles, everything
	// else shrinks or stays), so one arena holds them all.
	u := unpacker{data: data, strict: m.mode == Strict, arena: make([]byte, 0, 2*len(data))}
	mti, err := u.mti(m.spec.MTIEncoding)
	if err != nil {
		return err
	}

	var bm [24]byte
	if err := u.bitmap(bm[:8], m.spec.BitmapEncoding); err != nil {
		return err
	}
	count := 1
	if bitSet(bm[:], 1) {
		if err := u.bitmap(bm[8:16], m.spec.BitmapEncoding); err != nil {
			return err
		}
		count = 2
		if m.spec.TertiaryBitmap && bitSet(bm[:], 65) {
			if err := u.bitmap(bm[16:24], m.spec.BitmapEncoding); err != nil {
				return err
			}
			count = 3
		}
	}
	if u.strict {
		// An empty secondary or tertiary bitmap would not be re-emitted by
		// Pack, so the bytes would not round-trip.
		for i := 2; i <= count; i++ {
			if isZero(bm[(i-1)*8 : i*8]) {
				return &FieldError{Field: FieldBitmap, Offset: u.bitmapOffset(i, m.spec.BitmapEncoding),
					Err: ErrBitmap, Reason: fmt.Sprintf("bitmap %d is announced but empty", i)}
			}
		}
	}

	var fields [193]*node
	for id := 2; id <= 64*count; id++ {
		if !bitSet(bm[:], id) || (id == 65 && m.spec.TertiaryBitmap) {
			continue
		}
		f := m.spec.Field(id)
		if f == nil {
			return &FieldError{Field: id, Offset: u.off, Err: ErrUndefined,
				Reason: fmt.Sprintf("bit %d is set but field %d is not defined in spec %s", id, id, m.spec.Name)}
		}
		n, err := u.field(f, id, len(data))
		if err != nil {
			return err
		}
		fields[id] = n
	}
	if u.off < len(data) && u.strict {
		return &FieldError{Field: FieldNone, Offset: u.off, Err: ErrTrailingData,
			Reason: fmt.Sprintf("%d bytes after the last field", len(data)-u.off)}
	}
	m.mti = mti
	m.fields = fields
	return nil
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// unpacker walks a message, tracking the absolute offset. Values and nodes
// are carved out of shared slabs to keep allocations per message constant.
type unpacker struct {
	data   []byte
	off    int
	strict bool
	mtiLen int
	arena  []byte
	nodes  []node
}

// newNode returns a zeroed node from the slab.
func (u *unpacker) newNode() *node {
	if len(u.nodes) == cap(u.nodes) {
		u.nodes = make([]node, 0, 16)
	}
	u.nodes = u.nodes[:len(u.nodes)+1]
	return &u.nodes[len(u.nodes)-1]
}

func (u *unpacker) need(n, end int, field int, path string) error {
	if u.off+n > end {
		return &FieldError{Field: field, Path: path, Offset: u.off, Err: ErrTruncated,
			Reason: fmt.Sprintf("need %d bytes, %d left", n, end-u.off)}
	}
	return nil
}

func (u *unpacker) mti(enc spec.Encoding) (string, error) {
	n := 4
	if enc == spec.BCD {
		n = 2
	}
	if err := u.need(n, len(u.data), FieldMTI, ""); err != nil {
		return "", err
	}
	raw := u.data[:n]
	var v []byte
	if enc == spec.BCD {
		v, _ = decodeBCD(nil, raw, 4, false, false, false)
	} else {
		v = decodeText(nil, raw, enc)
	}
	if !validMTI(string(v)) {
		return "", &FieldError{Field: FieldMTI, Offset: 0, Err: ErrMTI,
			Reason: fmt.Sprintf("MTI %q is not four digits", v)}
	}
	u.off, u.mtiLen = n, n
	return string(v), nil
}

func (u *unpacker) bitmapOffset(i int, enc spec.Encoding) int {
	size := 8
	if enc == spec.Hex {
		size = 16
	}
	return u.mtiLen + (i-1)*size
}

// bitmap reads one 8-byte bitmap into dst.
func (u *unpacker) bitmap(dst []byte, enc spec.Encoding) error {
	return u.bitmapN(dst, enc, len(u.data), FieldBitmap, "")
}

func (u *unpacker) bitmapN(dst []byte, enc spec.Encoding, end, field int, path string) error {
	size := len(dst)
	if enc == spec.Hex {
		size *= 2
	}
	if err := u.need(size, end, field, path); err != nil {
		return err
	}
	raw := u.data[u.off : u.off+size]
	if enc == spec.Hex {
		b, ferr := decodeHex(dst[:0], raw, u.strict)
		if ferr != nil {
			return &FieldError{Field: field, Path: path, Offset: u.off, Err: ErrBitmap, Reason: ferr.reason}
		}
		copy(dst, b)
	} else {
		copy(dst, raw)
	}
	u.off += size
	return nil
}

// field decodes field f starting at u.off, not reading past end.
func (u *unpacker) field(f *spec.Field, top, end int) (*node, error) {
	start := u.off
	fail := func(off int, ferr *fault) error {
		return &FieldError{Field: top, Path: f.Path(), Offset: off, Err: ferr.err, Reason: ferr.reason}
	}
	units := f.Length
	if d := f.LengthType.PrefixDigits(); d > 0 {
		pl := prefixLen(d, f.PrefixEncoding)
		if err := u.need(pl, end, top, f.Path()); err != nil {
			return nil, err
		}
		n, ferr := readPrefix(u.data[u.off:u.off+pl], d, f.PrefixEncoding)
		if ferr != nil {
			return nil, fail(start, ferr)
		}
		if n > f.Length {
			return nil, fail(start, faultf(ErrLength, "length prefix %d exceeds the maximum of %d", n, f.Length))
		}
		units = n
		u.off += pl
	}

	if f.IsComposite() {
		if err := u.need(units, end, top, f.Path()); err != nil {
			return nil, err
		}
		return u.composite(f, top, u.off+units)
	}

	size := encodedLen(f, units)
	if err := u.need(size, end, top, f.Path()); err != nil {
		return nil, err
	}
	dataOff := u.off
	vstart := len(u.arena)
	arena, ferr := decodeData(u.arena, f, u.data[dataOff:dataOff+size], units, u.strict)
	if ferr != nil {
		return nil, fail(dataOff, ferr)
	}
	u.arena = arena
	v := arena[vstart:len(arena):len(arena)]
	if u.strict {
		if ferr := checkChars(f, v); ferr != nil {
			return nil, fail(dataOff, ferr)
		}
		if f.IsTLV() {
			if _, err := tlv.Parse(v); err != nil {
				off := dataOff
				var pe *tlv.ParseError
				if errors.As(err, &pe) {
					if f.Encoding == spec.Hex {
						off += 2 * pe.Offset
					} else {
						off += pe.Offset
					}
				}
				return nil, &FieldError{Field: top, Path: f.Path(), Offset: off, Err: ErrTLV, Reason: err.Error()}
			}
		}
	}
	u.off += size
	n := u.newNode()
	n.val = v
	return n, nil
}

// composite decodes the subfields of a positional or bitmapped field whose
// content ends at end.
func (u *unpacker) composite(f *spec.Field, top, end int) (*node, error) {
	c := f.Composite
	n := u.newNode()
	n.sub = make(map[int]*node)
	if c.Kind == spec.Bitmapped {
		bm := make([]byte, c.BitmapBytes)
		if err := u.bitmapN(bm, c.BitmapEncoding, end, top, f.Path()); err != nil {
			return nil, err
		}
		for id := 1; id <= 8*c.BitmapBytes; id++ {
			if !bitSet(bm, id) {
				continue
			}
			sf := c.Fields[id]
			if sf == nil {
				return nil, &FieldError{Field: top, Path: fmt.Sprintf("%s.%d", f.Path(), id), Offset: u.off,
					Err: ErrUndefined, Reason: fmt.Sprintf("bit %d is set but subfield %s.%d is not defined", id, f.Path(), id)}
			}
			sn, err := u.field(sf, top, end)
			if err != nil {
				return nil, err
			}
			n.sub[id] = sn
		}
	} else {
		for _, id := range c.IDs() {
			if u.off == end {
				break
			}
			sn, err := u.field(c.Fields[id], top, end)
			if err != nil {
				return nil, err
			}
			n.sub[id] = sn
		}
	}
	if u.off < end {
		if u.strict {
			return nil, &FieldError{Field: top, Path: f.Path(), Offset: u.off, Err: ErrTrailingData,
				Reason: fmt.Sprintf("%d bytes after the last subfield", end-u.off)}
		}
		u.off = end
	}
	return n, nil
}
