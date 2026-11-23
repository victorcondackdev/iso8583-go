package iso8583

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/victorcondackdev/iso8583-go/spec"
)

// Mode selects how strictly values are checked.
type Mode uint8

const (
	// Strict, the default, enforces each type's character set, the
	// prescribed BCD filler nibble, uppercase hex, BER-TLV syntax in TLV
	// fields, x+n signs, non-empty secondary bitmaps and the absence of
	// trailing bytes. A message that unpacks in strict mode packs back to
	// the identical bytes.
	Strict Mode = iota
	// Lenient accepts what real-world hosts send when it can still be
	// framed unambiguously: out-of-set characters, any filler nibble,
	// lowercase hex, malformed TLV data, empty secondary bitmaps and
	// trailing bytes. Lengths and truncation are always checked. Lenient
	// messages do not carry the round-trip guarantee.
	Lenient
)

// Option configures a [Message].
type Option func(*Message)

// WithMode sets the validation mode. The default is [Strict].
func WithMode(mode Mode) Option { return func(m *Message) { m.mode = mode } }

// node holds a field value: val for primitive fields, sub for positional
// and bitmapped composites.
type node struct {
	val []byte
	sub map[int]*node
}

// Message is an ISO 8583 message bound to a [spec.Spec].
//
// Values are stored as they travel, after padding: a 12-digit amount field
// set to "1000" reads back as "000000001000". Binary fields hold raw bytes
// regardless of how the spec encodes them on the wire.
//
// A Message is not safe for concurrent mutation; concurrent reads are fine.
type Message struct {
	spec   *spec.Spec
	err    error
	mode   Mode
	mti    string
	fields [193]*node
}

// NewMessage returns an empty message for spec s. If s does not compile,
// every method returns the compile error.
func NewMessage(s *spec.Spec, opts ...Option) *Message {
	m := &Message{spec: s}
	if s == nil {
		m.err = ErrNoSpec
	} else {
		m.err = s.Compile()
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Spec returns the message's spec.
func (m *Message) Spec() *spec.Spec { return m.spec }

// Mode returns the validation mode.
func (m *Message) Mode() Mode { return m.mode }

// MTI returns the message type indicator, or "" when unset.
func (m *Message) MTI() string { return m.mti }

// SetMTI sets the four-digit message type indicator, e.g. "0200".
func (m *Message) SetMTI(mti string) error {
	if !validMTI(mti) {
		return &FieldError{Field: FieldMTI, Offset: -1, Err: ErrMTI,
			Reason: fmt.Sprintf("MTI %q is not four digits", mti)}
	}
	m.mti = mti
	return nil
}

func validMTI(s string) bool {
	if len(s) != 4 {
		return false
	}
	for i := 0; i < 4; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// SetString sets data field id. For binary fields the string holds raw
// bytes. Values shorter than a fixed field are padded when the spec sets a
// padding side. In strict mode characters are checked against the type.
func (m *Message) SetString(id int, v string) error {
	return m.set([]int{id}, []byte(v))
}

// SetBytes is like [Message.SetString] but takes bytes, which are copied.
func (m *Message) SetBytes(id int, v []byte) error {
	return m.set([]int{id}, v)
}

// SetAmount sets a numeric (n) or x+n field from an amount in minor units
// (cents). Fixed fields are zero padded to their length. For x+n fields a
// negative amount is written with the D (debit) sign and a non-negative one
// with C (credit); n fields reject negative amounts.
func (m *Message) SetAmount(id int, cents int64) error {
	f, err := m.lookup([]int{id})
	if err != nil {
		return err
	}
	bad := func(reason string) error {
		return &FieldError{Field: id, Path: f.Path(), Offset: -1, Err: ErrLength, Reason: reason}
	}
	var sign string
	switch f.Type {
	case spec.Numeric:
		if cents < 0 {
			return bad("negative amount in an unsigned numeric field")
		}
	case spec.Amount:
		sign = "C"
		if cents < 0 {
			sign = "D"
			cents = -cents
			if cents < 0 { // math.MinInt64
				return bad("amount out of range")
			}
		}
	default:
		return bad(fmt.Sprintf("SetAmount needs an n or x+n field, field is %s", f.Type))
	}
	digits := strconv.FormatInt(cents, 10)
	if f.LengthType == spec.Fixed && len(digits) < f.Length {
		digits = strings.Repeat("0", f.Length-len(digits)) + digits
	}
	return m.set([]int{id}, []byte(sign+digits))
}

// GetAmount parses a numeric (n) or x+n field as an amount in minor units.
// A D sign yields a negative amount.
func (m *Message) GetAmount(id int) (int64, error) {
	f, err := m.lookup([]int{id})
	if err != nil {
		return 0, err
	}
	v, err := m.get([]int{id})
	if err != nil {
		return 0, err
	}
	neg := false
	if f.Type == spec.Amount && len(v) > 0 {
		neg = v[0] == 'D'
		v = v[1:]
	}
	n, perr := strconv.ParseUint(string(v), 10, 63)
	if perr != nil || (f.Type != spec.Numeric && f.Type != spec.Amount) {
		return 0, &FieldError{Field: id, Path: f.Path(), Offset: -1, Err: ErrInvalidChar,
			Reason: fmt.Sprintf("value %q is not an amount", v)}
	}
	if neg {
		return -int64(n), nil
	}
	return int64(n), nil
}

// GetString returns data field id. It returns an error wrapping [ErrNotSet]
// when the field is absent and [ErrComposite] for composite fields.
func (m *Message) GetString(id int) (string, error) {
	v, err := m.get([]int{id})
	return string(v), err
}

// GetBytes returns a copy of data field id.
func (m *Message) GetBytes(id int) ([]byte, error) {
	v, err := m.get([]int{id})
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), v...), nil
}

// SetSub sets a subfield of a composite field by dotted path, e.g. "48.2"
// or "127.3.1". A path without dots is the same as [Message.SetString].
func (m *Message) SetSub(path string, v string) error {
	ids, err := parsePath(path)
	if err != nil {
		return err
	}
	return m.set(ids, []byte(v))
}

// GetSub returns a subfield by dotted path.
func (m *Message) GetSub(path string) (string, error) {
	ids, err := parsePath(path)
	if err != nil {
		return "", err
	}
	v, err := m.get(ids)
	return string(v), err
}

// Has reports whether data field id is present.
func (m *Message) Has(id int) bool {
	return id >= 2 && id < len(m.fields) && m.fields[id] != nil
}

// Unset removes data field id. Unsetting an absent field is a no-op.
func (m *Message) Unset(id int) {
	if id >= 0 && id < len(m.fields) {
		m.fields[id] = nil
	}
}

// Fields returns the numbers of the present data fields in ascending order.
func (m *Message) Fields() []int {
	var ids []int
	for id, n := range m.fields {
		if n != nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// Reset clears the MTI and every field, keeping the spec and mode.
func (m *Message) Reset() {
	m.mti = ""
	m.fields = [193]*node{}
}

func parsePath(path string) ([]int, error) {
	parts := strings.Split(path, ".")
	ids := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, &FieldError{Field: FieldNone, Path: path, Offset: -1, Err: ErrUndefined,
				Reason: fmt.Sprintf("invalid field path %q", path)}
		}
		ids[i] = n
	}
	return ids, nil
}

func pathString(ids []int) string {
	var sb strings.Builder
	for i, id := range ids {
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.WriteString(strconv.Itoa(id))
	}
	return sb.String()
}

// lookup resolves the spec of a field path.
func (m *Message) lookup(ids []int) (*spec.Field, error) {
	if m.err != nil {
		return nil, m.err
	}
	undefined := func(reason string) error {
		return &FieldError{Field: ids[0], Path: pathString(ids), Offset: -1, Err: ErrUndefined, Reason: reason}
	}
	if ids[0] < 2 || ids[0] > m.spec.MaxField() {
		return nil, undefined(fmt.Sprintf("field %d cannot carry data", ids[0]))
	}
	f := m.spec.Field(ids[0])
	if f == nil {
		return nil, undefined(fmt.Sprintf("field %d is not defined in spec %s", ids[0], m.spec.Name))
	}
	for i, id := range ids[1:] {
		if !f.IsComposite() {
			return nil, &FieldError{Field: ids[0], Path: pathString(ids), Offset: -1, Err: ErrComposite,
				Reason: fmt.Sprintf("field %s has no subfields", pathString(ids[:i+1]))}
		}
		sub := f.Composite.Fields[id]
		if sub == nil {
			return nil, undefined(fmt.Sprintf("subfield %s is not defined", pathString(ids[:i+2])))
		}
		f = sub
	}
	return f, nil
}

func (m *Message) set(ids []int, v []byte) error {
	f, err := m.lookup(ids)
	if err != nil {
		return err
	}
	if f.IsComposite() {
		return &FieldError{Field: ids[0], Path: f.Path(), Offset: -1, Err: ErrComposite,
			Reason: fmt.Sprintf("field %s is composite; set its subfields with SetSub", f.Path())}
	}
	nv, ferr := normalize(f, v, m.mode == Strict)
	if ferr != nil {
		return &FieldError{Field: ids[0], Path: f.Path(), Offset: -1, Err: ferr.err, Reason: ferr.reason}
	}
	if len(ids) == 1 {
		m.fields[ids[0]] = &node{val: nv}
		return nil
	}
	parent := m.fields[ids[0]]
	if parent == nil {
		parent = &node{sub: make(map[int]*node)}
		m.fields[ids[0]] = parent
	}
	for _, id := range ids[1 : len(ids)-1] {
		c := parent.sub[id]
		if c == nil {
			c = &node{sub: make(map[int]*node)}
			parent.sub[id] = c
		}
		parent = c
	}
	parent.sub[ids[len(ids)-1]] = &node{val: nv}
	return nil
}

func (m *Message) get(ids []int) ([]byte, error) {
	f, err := m.lookup(ids)
	if err != nil {
		return nil, err
	}
	if f.IsComposite() {
		return nil, &FieldError{Field: ids[0], Path: f.Path(), Offset: -1, Err: ErrComposite,
			Reason: fmt.Sprintf("field %s is composite; read its subfields with GetSub", f.Path())}
	}
	n := m.fields[ids[0]]
	for _, id := range ids[1:] {
		if n == nil {
			break
		}
		n = n.sub[id]
	}
	if n == nil {
		return nil, &FieldError{Field: ids[0], Path: f.Path(), Offset: -1, Err: ErrNotSet,
			Reason: fmt.Sprintf("field %s is not set", f.Path())}
	}
	return n.val, nil
}

// normalize copies v, pads it to a fixed length when the spec allows, and
// checks its length and, in strict mode, its characters.
func normalize(f *spec.Field, v []byte, strict bool) ([]byte, *fault) {
	if f.Type == spec.Amount && len(v) == 0 {
		return nil, faultf(ErrLength, "x+n value needs a C or D sign")
	}
	units := unitsOf(f, v)
	out := make([]byte, 0, len(v)+max(0, f.Length-units))
	if f.LengthType == spec.Fixed && units < f.Length && f.Pad != spec.PadNone {
		pad := strings.Repeat(f.PadChar, f.Length-units)
		switch {
		case f.Type == spec.Amount: // always left padded, after the sign
			out = append(append(append(out, v[0]), pad...), v[1:]...)
		case f.Pad == spec.PadLeft:
			out = append(append(out, pad...), v...)
		default:
			out = append(append(out, v...), pad...)
		}
		units = f.Length
	} else {
		out = append(out, v...)
	}
	if f.LengthType == spec.Fixed && units != f.Length {
		return nil, faultf(ErrLength, "length %d, field %s is fixed at %d", units, f.Path(), f.Length)
	}
	if units > f.Length {
		return nil, faultf(ErrLength, "length %d exceeds the maximum of %d", units, f.Length)
	}
	if strict {
		if ferr := checkChars(f, out); ferr != nil {
			return nil, ferr
		}
	}
	return out, nil
}

// checkChars validates the character set of a primitive value.
func checkChars(f *spec.Field, v []byte) *fault {
	if f.Type == spec.Binary {
		return nil
	}
	if f.Type == spec.Amount {
		if len(v) == 0 || (v[0] != 'C' && v[0] != 'D') {
			return faultf(ErrInvalidChar, "x+n sign must be C or D")
		}
		v = v[1:]
		for i, c := range v {
			if c < '0' || c > '9' {
				return faultf(ErrInvalidChar, "invalid character %q at position %d for type x+n", c, i+1)
			}
		}
		return nil
	}
	for i, c := range v {
		if !spec.ValidChar(f.Type, c) {
			return faultf(ErrInvalidChar, "invalid character %q at position %d for type %s", c, i, f.Type)
		}
	}
	return nil
}
