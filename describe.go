package iso8583

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/victorcondackdev/iso8583-go/card"
	"github.com/victorcondackdev/iso8583-go/spec"
	"github.com/victorcondackdev/iso8583-go/tlv"
)

// Masking
//
// Everything in this file renders a message for humans or logs, and every
// renderer except UnmaskedJSON applies the spec's masking policy: PANs keep
// their first six and last four digits, track data is masked, and fields
// marked "full" (PIN block, CVV, expiry in the built-in specs) are replaced
// by '*'. Inside BER-TLV fields the sensitive EMV tags (5A, 57, 5F20, 5F24,
// 9F1F, 9F20) are masked the same way. The goal is that a message can be
// logged with %v without leaking cardholder data.

// display renders a primitive value with masking.
func display(f *spec.Field, v []byte) string {
	s := plain(f, v)
	switch f.Mask {
	case spec.MaskPAN:
		return card.MaskPAN(s)
	case spec.MaskTrack:
		return card.MaskTrack(s)
	case spec.MaskFull:
		return strings.Repeat("*", len(s))
	}
	return s
}

// plain renders a primitive value without masking: binary as uppercase hex,
// text as is, or Go-quoted if it holds non-printable bytes.
func plain(f *spec.Field, v []byte) string {
	if f.Type == spec.Binary {
		return strings.ToUpper(hex.EncodeToString(v))
	}
	for _, c := range v {
		if c < 0x20 || c > 0x7E {
			return strconv.Quote(string(v))
		}
	}
	return string(v)
}

// String returns a one-line masked summary such as
// "0200 2=411111******1111 3=000000 4=000000001000 ...". TLV fields are
// summarised by their tags, composites in braces.
func (m *Message) String() string {
	var sb strings.Builder
	if m.mti == "" {
		sb.WriteString("----")
	} else {
		sb.WriteString(m.mti)
	}
	if m.spec == nil || m.err != nil {
		return sb.String()
	}
	for id := 2; id < len(m.fields); id++ {
		if n := m.fields[id]; n != nil {
			sb.WriteByte(' ')
			sb.WriteString(strconv.Itoa(id))
			sb.WriteByte('=')
			writeShort(&sb, m.spec.Field(id), n)
		}
	}
	return sb.String()
}

func writeShort(sb *strings.Builder, f *spec.Field, n *node) {
	switch {
	case f.IsComposite():
		sb.WriteByte('{')
		first := true
		for _, id := range f.Composite.IDs() {
			if sn := n.sub[id]; sn != nil {
				if !first {
					sb.WriteByte(' ')
				}
				first = false
				sb.WriteString(strconv.Itoa(id))
				sb.WriteByte('=')
				writeShort(sb, f.Composite.Fields[id], sn)
			}
		}
		sb.WriteByte('}')
	case f.IsTLV():
		l, err := tlv.Parse(n.val)
		if err != nil {
			fmt.Fprintf(sb, "[%d bytes, not TLV]", len(n.val))
			return
		}
		sb.WriteByte('[')
		for i, t := range l {
			if i > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(t.Tag.String())
		}
		sb.WriteByte(']')
	default:
		sb.WriteString(display(f, n.val))
	}
}

// Describe returns a masked, multi-line dump of the message: the MTI and
// its meaning, the bitmap, then one row per field with its number, ISO
// format, name and value. Subfields get their own rows; TLV fields list
// their EMV tags.
func (m *Message) Describe() string {
	var sb strings.Builder
	row := func(label, format, name, value string) {
		line := fmt.Sprintf("%-8s %-10s %-44s %s", label, format, name, value)
		sb.WriteString(strings.TrimRight(line, " "))
		sb.WriteByte('\n')
	}
	sb.WriteString(strings.TrimRight(fmt.Sprintf("%-8s %-4s %s", "MTI", m.mti, MTIName(m.mti)), " ") + "\n")
	if m.spec == nil || m.err != nil {
		return sb.String()
	}
	bm, count := m.bitmap()
	fmt.Fprintf(&sb, "%-8s %s\n", "Bitmap", strings.ToUpper(hex.EncodeToString(bm[:8*count])))
	var walk func(f *spec.Field, n *node)
	walk = func(f *spec.Field, n *node) {
		label := "F" + f.Path()
		switch {
		case f.IsComposite():
			row(label, f.Notation(), f.Name, "")
			for _, id := range f.Composite.IDs() {
				if sn := n.sub[id]; sn != nil {
					walk(f.Composite.Fields[id], sn)
				}
			}
		case f.IsTLV():
			l, err := tlv.Parse(n.val)
			if err != nil {
				row(label, f.Notation(), f.Name, fmt.Sprintf("%s (invalid TLV: %v)",
					strings.Repeat("*", 2*len(n.val)), err))
				return
			}
			row(label, f.Notation(), f.Name, fmt.Sprintf("%d bytes, %d tags", len(n.val), len(l)))
			for _, line := range strings.Split(l.String(), "\n") {
				if line != "" {
					sb.WriteString("           " + line + "\n")
				}
			}
		default:
			row(label, f.Notation(), f.Name, display(f, n.val))
		}
	}
	for id := 2; id < len(m.fields); id++ {
		if n := m.fields[id]; n != nil {
			walk(m.spec.Field(id), n)
		}
	}
	return sb.String()
}

// MarshalJSON renders the message as JSON with the same masking as
// [Message.Describe], so a Message can be passed to a JSON logger safely:
//
//	{"mti":"0200","fields":{"2":"411111******1111","4":"000000001000",
//	 "48":{"1":"..."},"55":{"9F02":"000000001000"}}}
//
// Field keys appear in numeric order. Binary values are uppercase hex, TLV
// fields become objects keyed by tag. Use [Message.UnmaskedJSON] for a form
// that [Message.UnmarshalJSON] can read back.
func (m *Message) MarshalJSON() ([]byte, error) { return m.marshal(true) }

// UnmaskedJSON renders the message as JSON without masking: binary and TLV
// values as uppercase hex, composites as objects. The output is accepted by
// [Message.UnmarshalJSON]. It contains cardholder data in clear: never log
// it for real cards.
func (m *Message) UnmaskedJSON() ([]byte, error) { return m.marshal(false) }

func (m *Message) marshal(masked bool) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	var b bytes.Buffer
	b.WriteString(`{"mti":`)
	writeJSONString(&b, m.mti)
	b.WriteString(`,"fields":{`)
	first := true
	for id := 2; id < len(m.fields); id++ {
		n := m.fields[id]
		if n == nil {
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		fmt.Fprintf(&b, `"%d":`, id)
		writeJSONValue(&b, m.spec.Field(id), n, masked)
	}
	b.WriteString("}}")
	return b.Bytes(), nil
}

func writeJSONString(b *bytes.Buffer, s string) {
	enc, _ := json.Marshal(s) // strings always marshal
	b.Write(enc)
}

func writeJSONValue(b *bytes.Buffer, f *spec.Field, n *node, masked bool) {
	switch {
	case f.IsComposite():
		b.WriteByte('{')
		first := true
		for _, id := range f.Composite.IDs() {
			sn := n.sub[id]
			if sn == nil {
				continue
			}
			if !first {
				b.WriteByte(',')
			}
			first = false
			fmt.Fprintf(b, `"%d":`, id)
			writeJSONValue(b, f.Composite.Fields[id], sn, masked)
		}
		b.WriteByte('}')
	case masked && f.IsTLV():
		l, err := tlv.Parse(n.val)
		if err != nil {
			writeJSONString(b, strings.Repeat("*", 2*len(n.val)))
			return
		}
		writeTLVJSON(b, l)
	case masked:
		writeJSONString(b, display(f, n.val))
	case f.Type == spec.Binary:
		writeJSONString(b, strings.ToUpper(hex.EncodeToString(n.val)))
	default:
		writeJSONString(b, string(n.val))
	}
}

func writeTLVJSON(b *bytes.Buffer, l tlv.List) {
	b.WriteByte('{')
	for i, t := range l {
		if i > 0 {
			b.WriteByte(',')
		}
		writeJSONString(b, t.Tag.String())
		b.WriteByte(':')
		if t.Tag.Constructed() && len(t.Children) > 0 {
			writeTLVJSON(b, t.Children)
		} else {
			writeJSONString(b, tlv.MaskedValue(t))
		}
	}
	b.WriteByte('}')
}

// jsonMessage is the input shape of UnmarshalJSON.
type jsonMessage struct {
	MTI    string                     `json:"mti"`
	Fields map[string]json.RawMessage `json:"fields"`
}

// UnmarshalJSON replaces the message content with the JSON produced by
// [Message.UnmaskedJSON]: {"mti":"0200","fields":{"2":"4111...", ...}}.
// Binary and TLV fields are hex strings; composite fields are objects keyed
// by subfield number. The message must have been created with
// [NewMessage] so that the spec is known.
func (m *Message) UnmarshalJSON(data []byte) error {
	if m.spec == nil {
		return ErrNoSpec
	}
	if m.err != nil {
		return m.err
	}
	var jm jsonMessage
	if err := json.Unmarshal(data, &jm); err != nil {
		return err
	}
	tmp := NewMessage(m.spec, WithMode(m.mode))
	if jm.MTI != "" {
		if err := tmp.SetMTI(jm.MTI); err != nil {
			return err
		}
	}
	if err := tmp.setJSON(nil, jm.Fields); err != nil {
		return err
	}
	m.mti, m.fields = tmp.mti, tmp.fields
	return nil
}

func (m *Message) setJSON(prefix []int, fields map[string]json.RawMessage) error {
	for key, raw := range fields {
		id, err := strconv.Atoi(key)
		if err != nil {
			return fmt.Errorf("iso8583: JSON field key %q is not a number", key)
		}
		ids := append(append([]int(nil), prefix...), id)
		f, err := m.lookup(ids)
		if err != nil {
			return err
		}
		if f.IsComposite() {
			var sub map[string]json.RawMessage
			if err := json.Unmarshal(raw, &sub); err != nil {
				return fmt.Errorf("iso8583: field %s: composite fields are JSON objects: %w", pathString(ids), err)
			}
			if len(sub) == 0 {
				m.createEmpty(ids)
			}
			if err := m.setJSON(ids, sub); err != nil {
				return err
			}
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("iso8583: field %s: value must be a JSON string: %w", pathString(ids), err)
		}
		v := []byte(s)
		if f.Type == spec.Binary {
			if v, err = hex.DecodeString(s); err != nil {
				return &FieldError{Field: ids[0], Path: pathString(ids), Offset: -1, Err: ErrInvalidChar,
					Reason: "binary values are hex strings in JSON"}
			}
		}
		if err := m.set(ids, v); err != nil {
			return err
		}
	}
	return nil
}

// createEmpty makes a present composite field with no subfields.
func (m *Message) createEmpty(ids []int) {
	if len(ids) == 1 {
		if m.fields[ids[0]] == nil {
			m.fields[ids[0]] = &node{sub: make(map[int]*node)}
		}
		return
	}
	parent := m.fields[ids[0]]
	if parent == nil {
		parent = &node{sub: make(map[int]*node)}
		m.fields[ids[0]] = parent
	}
	for _, id := range ids[1:] {
		c := parent.sub[id]
		if c == nil {
			c = &node{sub: make(map[int]*node)}
			parent.sub[id] = c
		}
		parent = c
	}
}
