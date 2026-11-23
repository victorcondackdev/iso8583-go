package iso8583

import (
	"testing"

	"github.com/victorcondackdev/iso8583-go/spec"
)

// Benchmarks use the 0200 purchase from purchase(): 14 fields including a
// PAN, track 2, PIN block and a small EMV field 55.

func benchPack(b *testing.B, s *spec.Spec) {
	m := purchase(b, s)
	buf := make([]byte, 0, 512)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		if buf, err = m.AppendPack(buf[:0]); err != nil {
			b.Fatal(err)
		}
	}
	b.SetBytes(int64(len(buf)))
}

func benchUnpack(b *testing.B, s *spec.Spec) {
	data, err := purchase(b, s).Pack()
	if err != nil {
		b.Fatal(err)
	}
	m := NewMessage(s)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := m.Unpack(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPack0200ASCII(b *testing.B)    { benchPack(b, spec.ISO87ASCII()) }
func BenchmarkPack0200Binary(b *testing.B)   { benchPack(b, spec.ISO87Binary()) }
func BenchmarkUnpack0200ASCII(b *testing.B)  { benchUnpack(b, spec.ISO87ASCII()) }
func BenchmarkUnpack0200Binary(b *testing.B) { benchUnpack(b, spec.ISO87Binary()) }

func BenchmarkBuildAndPack0200(b *testing.B) {
	s := spec.ISO87Binary()
	pin := []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF}
	icc := []byte{0x9F, 0x02, 0x06, 0, 0, 0, 0, 0x10, 0, 0x5F, 0x2A, 0x02, 0x09, 0x86}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m := NewMessage(s)
		_ = m.SetMTI("0200")
		_ = m.SetString(2, "4111111111111111")
		_ = m.SetString(3, "000000")
		_ = m.SetAmount(4, 1000)
		_ = m.SetString(7, "1122140500")
		_ = m.SetString(11, "000123")
		_ = m.SetString(14, "2912")
		_ = m.SetString(22, "051")
		_ = m.SetString(35, "4111111111111111=2912101123456789")
		_ = m.SetString(37, "632614000123")
		_ = m.SetString(41, "TERM0001")
		_ = m.SetString(42, "MERCHANT0000001")
		_ = m.SetString(49, "986")
		_ = m.SetBytes(52, pin)
		_ = m.SetBytes(55, icc)
		if _, err := m.Pack(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDescribe0200(b *testing.B) {
	m := purchase(b, spec.ISO87ASCII())
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = m.Describe()
	}
}
