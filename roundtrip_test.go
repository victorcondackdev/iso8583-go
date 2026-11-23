package iso8583

import (
	"bytes"
	"math/rand/v2"
	"reflect"
	"testing"

	"github.com/victorcondackdev/iso8583-go/spec"
	"github.com/victorcondackdev/iso8583-go/tlv"
)

// kitchenSink exercises every encoding combination the spec model allows:
// raw, BCD and EBCDIC prefixes, right-padded BCD, EBCDIC text, binary and
// hex bitmaps inside composites, nested composites and the tertiary bitmap.
func kitchenSink() *spec.Spec {
	f := func(typ spec.Type, length int, lt spec.LengthType, enc, prefix spec.Encoding) *spec.Field {
		return &spec.Field{Name: "f", Type: typ, Length: length, LengthType: lt, Encoding: enc, PrefixEncoding: prefix}
	}
	s := &spec.Spec{
		Name: "KitchenSink", MTIEncoding: spec.EBCDIC, BitmapEncoding: spec.Raw, TertiaryBitmap: true,
		Defaults: spec.Defaults{Numeric: spec.BCD, Text: spec.ASCII, Binary: spec.Raw, Prefix: spec.Raw},
		Fields: map[int]*spec.Field{
			2:   f(spec.Numeric, 19, spec.LLVar, spec.BCD, spec.BCD),
			3:   {Name: "rpad", Type: spec.Numeric, Length: 5, Encoding: spec.BCD, BCDPad: spec.PadRight},
			4:   f(spec.Numeric, 7, spec.Fixed, spec.EBCDIC, ""),
			5:   f(spec.Amount, 9, spec.Fixed, spec.BCD, ""),
			6:   f(spec.Amount, 11, spec.LLVar, spec.EBCDIC, spec.EBCDIC),
			7:   f(spec.Track2, 37, spec.LLVar, spec.BCD, spec.Raw),
			8:   f(spec.Track2, 20, spec.LLLVar, spec.ASCII, spec.BCD),
			9:   f(spec.AlphaNumeric, 10, spec.LLLLVar, spec.EBCDIC, spec.Raw),
			10:  f(spec.AlphaNumericSpecial, 30, spec.LLLLVar, spec.ASCII, spec.EBCDIC),
			11:  f(spec.Binary, 16, spec.LLVar, spec.Hex, spec.ASCII),
			12:  f(spec.Binary, 4, spec.Fixed, spec.Raw, ""),
			13:  {Name: "tlv", Type: spec.Binary, Length: 200, LengthType: spec.LLLVar, Composite: &spec.Composite{Kind: spec.TLV}},
			14:  f(spec.Numeric, 3, spec.LLLLVar, spec.BCD, spec.BCD),
			70:  f(spec.Numeric, 3, spec.Fixed, spec.BCD, ""),
			130: f(spec.AlphaNumericSpecial, 12, spec.LLVar, spec.EBCDIC, spec.ASCII),
			192: f(spec.Binary, 8, spec.Fixed, spec.Raw, ""),
			20: {Name: "bitmapped", Type: spec.Binary, Length: 400, LengthType: spec.LLLVar,
				Composite: &spec.Composite{Kind: spec.Bitmapped, BitmapBytes: 2, Fields: map[int]*spec.Field{
					1:  f(spec.Numeric, 4, spec.Fixed, spec.BCD, ""),
					3:  f(spec.AlphaNumericSpecial, 20, spec.LLVar, spec.EBCDIC, spec.BCD),
					16: f(spec.Binary, 3, spec.LLVar, spec.Raw, spec.Raw),
					9: {Name: "nested", Type: spec.AlphaNumericSpecial, Length: 99, LengthType: spec.LLVar,
						Composite: &spec.Composite{Kind: spec.Positional, Fields: map[int]*spec.Field{
							1: f(spec.Numeric, 2, spec.Fixed, spec.ASCII, ""),
							2: f(spec.AlphaNumeric, 8, spec.LLVar, spec.ASCII, spec.ASCII),
						}}},
				}}},
			21: {Name: "hexmapped", Type: spec.AlphaNumericSpecial, Length: 99, LengthType: spec.LLVar,
				Composite: &spec.Composite{Kind: spec.Bitmapped, BitmapBytes: 1, BitmapEncoding: spec.Hex,
					Fields: map[int]*spec.Field{2: f(spec.Numeric, 3, spec.Fixed, spec.ASCII, "")}}},
		},
	}
	return s
}

func randValue(r *rand.Rand, f *spec.Field) []byte {
	n := f.Length
	if f.IsVariable() {
		n = r.IntN(min(f.Length, 24) + 1)
	}
	if f.IsTLV() {
		var l tlv.List
		for i := r.IntN(4); i > 0; i-- {
			v := make([]byte, r.IntN(12))
			for j := range v {
				v[j] = byte(r.Uint32())
			}
			l = append(l, tlv.New(tlv.Tag([]uint32{0x9F02, 0x5A, 0x82, 0x9F26, 0x5F2A}[r.IntN(5)]), v))
		}
		if r.IntN(3) == 0 {
			l = append(l, tlv.NewConstructed(0x70, tlv.New(0x57, []byte{0x41, 0x11, 0xD2})))
		}
		return l.Bytes()
	}
	charset := map[spec.Type]string{
		spec.Numeric:             "0123456789",
		spec.Track2:              "0123456789=",
		spec.AlphaNumeric:        "ABCXYZabcxyz0189 ",
		spec.AlphaNumericSpecial: " !\"#$%&'()*+,-./09:;<=>?@AZ[\\]^_`az{|}~",
		spec.Amount:              "0123456789",
	}[f.Type]
	out := make([]byte, 0, n+1)
	if f.Type == spec.Amount {
		out = append(out, "CD"[r.IntN(2)])
	}
	for i := 0; i < n; i++ {
		if f.Type == spec.Binary {
			out = append(out, byte(r.Uint32()))
		} else {
			out = append(out, charset[r.IntN(len(charset))])
		}
	}
	return out
}

// fillRandom sets random values on a random subset of the fields of
// composite c (or of the spec when c is nil), under path prefix.
func fillRandom(t testing.TB, r *rand.Rand, m *Message, prefix string, fields map[int]*spec.Field, ids []int, positional bool) {
	count := 0
	stop := len(ids)
	if positional {
		stop = 1 + r.IntN(len(ids))
	}
	for i, id := range ids[:stop] {
		f := fields[id]
		if !positional && r.IntN(3) != 0 && !(count == 0 && i == stop-1) {
			continue
		}
		count++
		path := prefix + itoa(id)
		if f.IsComposite() {
			fillRandom(t, r, m, path+".", f.Composite.Fields, f.Composite.IDs(), f.Composite.Kind == spec.Positional)
			continue
		}
		if err := m.SetSub(path, string(randValue(r, f))); err != nil {
			t.Fatalf("SetSub(%s): %v", path, err)
		}
	}
}

func itoa(n int) string { return string(appendInt(nil, n)) }

func appendInt(b []byte, n int) []byte {
	if n >= 10 {
		b = appendInt(b, n/10)
	}
	return append(b, byte('0'+n%10))
}

func randomMessage(t testing.TB, r *rand.Rand, s *spec.Spec) *Message {
	m := NewMessage(s)
	must(t, m.SetMTI([]string{"0100", "0110", "0200", "0210", "0400", "0420", "0800"}[r.IntN(7)]))
	fillRandom(t, r, m, "", s.Fields, s.IDs(), false)
	return m
}

// TestRoundTripProperty packs random valid messages and checks that
// unpacking yields the same values and repacking the same bytes.
func TestRoundTripProperty(t *testing.T) {
	specs := []*spec.Spec{spec.ISO87ASCII(), spec.ISO87Binary(), ebcdicSpec(), acmeSpec(t), kitchenSink()}
	r := rand.New(rand.NewPCG(1, 2))
	for _, s := range specs {
		t.Run(s.Name, func(t *testing.T) {
			for i := 0; i < 400; i++ {
				m := randomMessage(t, r, s)
				b, err := m.Pack()
				if err != nil {
					t.Fatalf("Pack: %v\n%s", err, m.Describe())
				}
				back := NewMessage(s)
				if err := back.Unpack(b); err != nil {
					t.Fatalf("Unpack: %v\n%X\n%s", err, b, m.Describe())
				}
				if back.mti != m.mti || !reflect.DeepEqual(back.fields, m.fields) {
					j1, _ := m.UnmaskedJSON()
					j2, _ := back.UnmaskedJSON()
					t.Fatalf("values differ:\n%s\n%s", j1, j2)
				}
				again, err := back.Pack()
				if err != nil || !bytes.Equal(again, b) {
					t.Fatalf("repack: %v\n%X\n%X", err, b, again)
				}
				// The JSON form round-trips too.
				j, err := m.UnmaskedJSON()
				must(t, err)
				fromJSON := NewMessage(s)
				if err := fromJSON.UnmarshalJSON(j); err != nil {
					t.Fatalf("UnmarshalJSON: %v\n%s", err, j)
				}
				if b2, err := fromJSON.Pack(); err != nil || !bytes.Equal(b2, b) {
					t.Fatalf("JSON round trip: %v\n%s", err, j)
				}
				_ = m.String()
				_ = m.Describe()
				if _, err := m.MarshalJSON(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
