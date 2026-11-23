package iso8583

import (
	"fmt"

	"github.com/victorcondackdev/iso8583-go/ebcdic"
	"github.com/victorcondackdev/iso8583-go/spec"
)

// This file holds the byte-level encoders shared by Pack and Unpack. They
// return a *fault instead of an error so that callers can wrap it in a
// FieldError carrying the field and the offset.

// fault is a sentinel error plus a human-readable reason.
type fault struct {
	err    error
	reason string
}

func faultf(err error, format string, a ...any) *fault {
	return &fault{err: err, reason: fmt.Sprintf(format, a...)}
}

const hexDigits = "0123456789ABCDEF"

// encodedLen returns the number of wire bytes of a value of the given
// number of units in field f (data only, without the length prefix).
func encodedLen(f *spec.Field, units int) int {
	switch f.Type {
	case spec.Binary:
		if f.Encoding == spec.Hex {
			return 2 * units
		}
		return units
	case spec.Numeric, spec.Track2:
		if f.Encoding == spec.BCD {
			return (units + 1) / 2
		}
		return units
	case spec.Amount:
		if f.Encoding == spec.BCD {
			return 1 + (units+1)/2
		}
		return 1 + units
	}
	return units // an, ans
}

// unitsOf returns the length of value v in units of field f.
func unitsOf(f *spec.Field, v []byte) int {
	if f.Type == spec.Amount {
		return len(v) - 1
	}
	return len(v)
}

// nibble maps a digit or BCD pseudo-digit to its 4-bit value.
func nibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c == '=':
		return 0xD, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// appendBCD packs digits two per byte. An odd count gets a filler nibble:
// 0 on the left when padRight is false, F on the right when it is true.
//
// Example: "12345" left padded is 01 23 45; right padded it is 12 34 5F.
func appendBCD(dst, digits []byte, padRight bool) ([]byte, *fault) {
	n := len(digits)
	i := 0
	if n%2 == 1 && !padRight {
		lo, ok := nibble(digits[0])
		if !ok {
			return dst, faultf(ErrInvalidChar, "%q cannot be BCD encoded", digits[0])
		}
		dst = append(dst, lo)
		i = 1
	}
	for ; i+1 < n; i += 2 {
		hi, ok1 := nibble(digits[i])
		lo, ok2 := nibble(digits[i+1])
		if !ok1 || !ok2 {
			c := digits[i]
			if ok1 {
				c = digits[i+1]
			}
			return dst, faultf(ErrInvalidChar, "%q cannot be BCD encoded", c)
		}
		dst = append(dst, hi<<4|lo)
	}
	if n%2 == 1 && padRight {
		hi, ok := nibble(digits[n-1])
		if !ok {
			return dst, faultf(ErrInvalidChar, "%q cannot be BCD encoded", digits[n-1])
		}
		dst = append(dst, hi<<4|0xF)
	}
	return dst, nil
}

// decodeBCD unpacks ndigits digits from src, which holds exactly
// (ndigits+1)/2 bytes. Nibbles 0-9 become '0'-'9'; for track 2 data nibble D
// becomes '='; any other nibble becomes 'A'-'F' and is left for character
// validation to reject. In strict mode the filler nibble of an odd count
// must be 0 (left) or F (right).
func decodeBCD(dst, src []byte, ndigits int, padRight, track2, strict bool) ([]byte, *fault) {
	odd := ndigits%2 == 1
	if odd && strict {
		var filler, want byte
		if padRight {
			filler, want = src[len(src)-1]&0x0F, 0xF
		} else {
			filler, want = src[0]>>4, 0x0
		}
		if filler != want {
			return dst, faultf(ErrPadding, "BCD filler nibble is %X, want %X", filler, want)
		}
	}
	start := 0
	if odd && !padRight {
		start = 1
	}
	for k := start; k < start+ndigits; k++ {
		b := src[k/2]
		var v byte
		if k%2 == 0 {
			v = b >> 4
		} else {
			v = b & 0x0F
		}
		switch {
		case v <= 9:
			dst = append(dst, '0'+v)
		case v == 0xD && track2:
			dst = append(dst, '=')
		default:
			dst = append(dst, hexDigits[v])
		}
	}
	return dst, nil
}

// appendHex appends the uppercase hex encoding of b.
func appendHex(dst, b []byte) []byte {
	for _, c := range b {
		dst = append(dst, hexDigits[c>>4], hexDigits[c&0x0F])
	}
	return dst
}

// unhex decodes one hex digit. Lowercase is accepted only when lower is
// true (lenient mode), so that strict decoding is canonical.
func unhex(c byte, lower bool) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	case lower && c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// decodeHex appends the bytes encoded by hex text src.
func decodeHex(dst, src []byte, strict bool) ([]byte, *fault) {
	for i := 0; i+1 < len(src); i += 2 {
		hi, ok1 := unhex(src[i], !strict)
		lo, ok2 := unhex(src[i+1], !strict)
		if !ok1 || !ok2 {
			c := src[i]
			if ok1 {
				c = src[i+1]
			}
			if strict && c >= 'a' && c <= 'f' {
				return dst, faultf(ErrInvalidChar, "lowercase hex digit %q (strict mode wants uppercase)", c)
			}
			return dst, faultf(ErrInvalidChar, "invalid hex digit %q", c)
		}
		dst = append(dst, hi<<4|lo)
	}
	return dst, nil
}

// appendText encodes characters in ASCII or EBCDIC.
func appendText(dst, v []byte, enc spec.Encoding) []byte {
	if enc == spec.EBCDIC {
		return ebcdic.Encode(dst, v)
	}
	return append(dst, v...)
}

// decodeText decodes ASCII or EBCDIC characters.
func decodeText(dst, src []byte, enc spec.Encoding) []byte {
	if enc == spec.EBCDIC {
		return ebcdic.Decode(dst, src)
	}
	return append(dst, src...)
}

// appendData encodes the value of a primitive field (no prefix).
func appendData(dst []byte, f *spec.Field, v []byte) ([]byte, *fault) {
	switch f.Type {
	case spec.Binary:
		if f.Encoding == spec.Hex {
			return appendHex(dst, v), nil
		}
		return append(dst, v...), nil
	case spec.Numeric, spec.Track2:
		if f.Encoding == spec.BCD {
			return appendBCD(dst, v, f.BCDPad == spec.PadRight)
		}
		return appendText(dst, v, f.Encoding), nil
	case spec.Amount:
		if len(v) == 0 {
			return dst, faultf(ErrLength, "x+n value has no sign")
		}
		if f.Encoding == spec.EBCDIC {
			dst = ebcdic.Encode(dst, v[:1])
		} else {
			dst = append(dst, v[0]) // the sign travels as an ASCII byte with BCD digits
		}
		if f.Encoding == spec.BCD {
			return appendBCD(dst, v[1:], f.BCDPad == spec.PadRight)
		}
		return appendText(dst, v[1:], f.Encoding), nil
	}
	return appendText(dst, v, f.Encoding), nil
}

// decodeData appends to out the decoded wire bytes raw (exactly
// encodedLen(f, units) long) of a primitive field.
func decodeData(out []byte, f *spec.Field, raw []byte, units int, strict bool) ([]byte, *fault) {
	switch f.Type {
	case spec.Binary:
		if f.Encoding == spec.Hex {
			return decodeHex(out, raw, strict)
		}
		return append(out, raw...), nil
	case spec.Numeric, spec.Track2:
		if f.Encoding == spec.BCD {
			return decodeBCD(out, raw, units, f.BCDPad == spec.PadRight, f.Type == spec.Track2, strict)
		}
		return decodeText(out, raw, f.Encoding), nil
	case spec.Amount:
		if f.Encoding == spec.EBCDIC {
			out = ebcdic.Decode(out, raw[:1])
		} else {
			out = append(out, raw[0])
		}
		if f.Encoding == spec.BCD {
			return decodeBCD(out, raw[1:], units, f.BCDPad == spec.PadRight, false, strict)
		}
		return decodeText(out, raw[1:], f.Encoding), nil
	}
	return decodeText(out, raw, f.Encoding), nil
}

// prefixLen returns the number of bytes of a length prefix with the given
// digit count and encoding: 2, 3 or 4 for character encodings; 1 for LL and
// 2 for LLL and LLLL in BCD and binary.
func prefixLen(digits int, enc spec.Encoding) int {
	switch enc {
	case spec.BCD, spec.Raw:
		return (digits + 1) / 2
	}
	return digits
}

// appendPrefix encodes a length prefix. Hand-computed examples for a length
// of 37: LL ASCII "37" (33 37); LL BCD 37; LLL BCD 00 37 (the extra nibble
// is a leading 0); LLL ASCII "037"; LLL binary 00 25.
func appendPrefix(dst []byte, digits int, enc spec.Encoding, n int) []byte {
	switch enc {
	case spec.Raw:
		if digits == 2 {
			return append(dst, byte(n))
		}
		return append(dst, byte(n>>8), byte(n))
	case spec.BCD:
		var d [4]byte
		w := (digits + 1) / 2 * 2
		for i := w - 1; i >= 0; i-- {
			d[i] = byte('0' + n%10)
			n /= 10
		}
		out, _ := appendBCD(dst, d[:w], false)
		return out
	}
	var d [4]byte
	for i := digits - 1; i >= 0; i-- {
		d[i] = byte('0' + n%10)
		n /= 10
	}
	return appendText(dst, d[:digits], enc)
}

// readPrefix decodes a length prefix from b, which holds exactly
// prefixLen(digits, enc) bytes.
func readPrefix(b []byte, digits int, enc spec.Encoding) (int, *fault) {
	switch enc {
	case spec.Raw:
		if digits == 2 {
			return int(b[0]), nil
		}
		return int(b[0])<<8 | int(b[1]), nil
	case spec.BCD:
		n := 0
		for _, c := range b {
			hi, lo := c>>4, c&0x0F
			if hi > 9 || lo > 9 {
				return 0, faultf(ErrLength, "length prefix %X is not BCD", b)
			}
			n = n*100 + int(hi)*10 + int(lo)
		}
		return n, nil
	}
	n := 0
	for _, c := range b {
		if enc == spec.EBCDIC {
			c = ebcdic.DecodeByte(c)
		}
		if c < '0' || c > '9' {
			return 0, faultf(ErrLength, "length prefix %q is not numeric", b)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
