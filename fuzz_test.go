package iso8583

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"testing"

	"github.com/victorcondackdev/iso8583-go/spec"
)

// fuzzUnpack checks, for arbitrary input, that Unpack never panics, that
// every error is a *FieldError with an in-range offset, and that anything
// strict mode accepts packs back to the identical bytes. Lenient mode must
// not panic either, and its output must unpack leniently again.
func fuzzUnpack(f *testing.F, s *spec.Spec, withPurchase bool) {
	r := rand.New(rand.NewPCG(7, 7))
	if withPurchase {
		b, _ := purchase(f, s).Pack()
		f.Add(b)
	}
	for i := 0; i < 16; i++ {
		b, err := randomMessage(f, r, s).Pack()
		if err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m := NewMessage(s)
		err := m.Unpack(data)
		if err != nil {
			var fe *FieldError
			if !errors.As(err, &fe) || fe.Offset < 0 || fe.Offset > len(data) {
				t.Fatalf("error without a valid offset: %v", err)
			}
		} else {
			again, err := m.Pack()
			if err != nil {
				t.Fatalf("strict Unpack accepted what Pack rejects: %v", err)
			}
			if !bytes.Equal(again, data) {
				t.Fatalf("round trip differs:\n%X\n%X", data, again)
			}
			_ = m.String()
			_ = m.Describe()
			if _, err := m.MarshalJSON(); err != nil {
				t.Fatal(err)
			}
		}

		l := NewMessage(s, WithMode(Lenient))
		if err := l.Unpack(data); err != nil {
			return
		}
		_ = l.Describe()
		if out, err := l.Pack(); err == nil {
			if err := NewMessage(s, WithMode(Lenient)).Unpack(out); err != nil {
				t.Fatalf("lenient repack does not unpack: %v", err)
			}
		}
	})
}

func FuzzUnpackISO87ASCII(f *testing.F)  { fuzzUnpack(f, spec.ISO87ASCII(), true) }
func FuzzUnpackISO87Binary(f *testing.F) { fuzzUnpack(f, spec.ISO87Binary(), true) }

// FuzzUnpackComposite covers positional and bitmapped subfields.
func FuzzUnpackComposite(f *testing.F) { fuzzUnpack(f, acmeSpec(f), false) }

// FuzzUnpackKitchenSink covers EBCDIC, raw and BCD prefixes, right-padded
// BCD, nested composites and the tertiary bitmap.
func FuzzUnpackKitchenSink(f *testing.F) { fuzzUnpack(f, kitchenSink(), false) }
