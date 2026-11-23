// Package card holds small, allocation-light helpers for primary account
// numbers (PANs): the Luhn (mod 10) check digit, brand detection from the
// issuer identification number (IIN, a.k.a. BIN) and PCI DSS-style masking.
//
// Brand detection covers only long-standing, publicly documented prefix
// ranges. It is a hint for routing and display, not an authoritative BIN
// table: networks publish range files that change monthly, and production
// routing must use them.
package card

import (
	"errors"
	"strings"
)

// ErrNotDigits reports a PAN containing something other than ASCII digits,
// or an empty PAN.
var ErrNotDigits = errors.New("card: PAN must be a non-empty string of digits")

// Luhn reports whether pan is all digits, at least two long, and has a valid
// Luhn (ISO/IEC 7812-1 mod 10) check digit as its last digit.
func Luhn(pan string) bool {
	if len(pan) < 2 || !isDigits(pan) {
		return false
	}
	return luhnSum(pan, false)%10 == 0
}

// LuhnDigit returns the check digit that makes partial+digit pass [Luhn].
func LuhnDigit(partial string) (byte, error) {
	if partial == "" || !isDigits(partial) {
		return 0, ErrNotDigits
	}
	// Computing the sum as if a check digit followed doubles the right
	// positions of partial.
	s := luhnSum(partial, true)
	return byte('0' + (10-s%10)%10), nil
}

// Complete returns partial followed by its Luhn check digit.
func Complete(partial string) (string, error) {
	d, err := LuhnDigit(partial)
	if err != nil {
		return "", err
	}
	return partial + string(d), nil
}

// luhnSum returns the Luhn sum of digits. When pending is true the
// rightmost digit of s is treated as the second from the right, i.e. a
// check digit is assumed to follow.
func luhnSum(s string, pending bool) int {
	sum := 0
	double := pending
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Brand is a card scheme detected from the leading digits of a PAN.
type Brand string

// Brands recognised by [DetectBrand].
const (
	Unknown    Brand = ""
	Visa       Brand = "visa"
	Mastercard Brand = "mastercard"
	Amex       Brand = "amex"
	Discover   Brand = "discover"
	JCB        Brand = "jcb"
)

// String returns the brand's display name.
func (b Brand) String() string {
	switch b {
	case Visa:
		return "Visa"
	case Mastercard:
		return "Mastercard"
	case Amex:
		return "American Express"
	case Discover:
		return "Discover"
	case JCB:
		return "JCB"
	}
	return "Unknown"
}

// DetectBrand returns the brand implied by the PAN's prefix, or [Unknown].
// Only the prefix is inspected; combine with [Luhn] and a length check to
// validate a PAN. The ranges are:
//
//   - Visa: 4
//   - Mastercard: 51–55 and 2221–2720
//   - American Express: 34, 37
//   - Discover: 6011, 644–649, 65
//   - JCB: 3528–3589
//
// Domestic schemes whose ranges overlap these (Elo in Brazil, for example,
// issues inside 4, 5 and 6 prefixes) are not detected; they need the
// scheme's own BIN table.
func DetectBrand(pan string) Brand {
	p := func(n int) int { return prefix(pan, n) }
	switch {
	case p(1) == 4:
		return Visa
	case p(2) >= 51 && p(2) <= 55, p(4) >= 2221 && p(4) <= 2720:
		return Mastercard
	case p(2) == 34, p(2) == 37:
		return Amex
	case p(4) == 6011, p(3) >= 644 && p(3) <= 649, p(2) == 65:
		return Discover
	case p(4) >= 3528 && p(4) <= 3589:
		return JCB
	}
	return Unknown
}

// prefix returns the first n digits of s as an integer, or -1 when s is
// shorter than n or they are not all digits.
func prefix(s string, n int) int {
	if len(s) < n {
		return -1
	}
	v := 0
	for i := 0; i < n; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return -1
		}
		v = v*10 + int(c-'0')
	}
	return v
}

// BIN returns the issuer identification number: the first eight digits of
// a PAN of 16 digits or more, the first six otherwise (the industry moved
// to 8-digit BINs in 2022 for 16-digit-plus PANs). It returns "" when pan
// is shorter than 6 digits or not numeric.
func BIN(pan string) string {
	if len(pan) < 6 || !isDigits(pan) {
		return ""
	}
	if len(pan) >= 16 {
		return pan[:8]
	}
	return pan[:6]
}

// MaskPAN masks a PAN for display, keeping at most the first six and the
// last four digits as PCI DSS allows. Values shorter than 13 characters are
// masked entirely, since showing ten of twelve digits would reveal almost
// everything.
func MaskPAN(pan string) string {
	if len(pan) < 13 {
		return strings.Repeat("*", len(pan))
	}
	return pan[:6] + strings.Repeat("*", len(pan)-10) + pan[len(pan)-4:]
}

// MaskTrack masks magnetic stripe track data. For track 2 style data (a
// PAN, then '=' or 'D', then expiry, service code and discretionary data)
// the PAN is masked with [MaskPAN], the separator kept and everything after
// it replaced by '*'. Anything else (track 1, track 3, unrecognised data) is
// masked entirely.
func MaskTrack(track string) string {
	i := strings.IndexAny(track, "=D")
	if i <= 0 || !isDigits(track[:i]) {
		return strings.Repeat("*", len(track))
	}
	return MaskPAN(track[:i]) + track[i:i+1] + strings.Repeat("*", len(track)-i-1)
}
