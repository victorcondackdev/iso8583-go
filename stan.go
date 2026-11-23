package iso8583

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// STAN generates system trace audit numbers (field 11): six digits from
// 000001 to 999999, wrapping back to 000001. The zero value is ready to use
// and safe for concurrent use. 000000 is never produced.
type STAN struct {
	n atomic.Uint32
}

// Next returns the next trace number.
func (s *STAN) Next() string {
	v := (s.n.Add(1)-1)%999999 + 1
	var b [6]byte
	for i := 5; i >= 0; i-- {
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[:])
}

// Reset makes the next call to Next return last+1, for counters persisted
// across restarts.
func (s *STAN) Reset(last uint32) { s.n.Store(last % 999999) }

// RRN builds a 12-character retrieval reference number (field 37) using the
// common YDDDhh + STAN convention: last digit of the year, day of the year
// (001-366), hour (00-23), then the six-digit STAN. stan is left padded with
// zeros, or truncated to its last six characters.
//
// For 2026-11-22 14:05 UTC and STAN 000123: "6326" + "14" + "000123".
func RRN(t time.Time, stan string) string {
	t = t.UTC()
	if len(stan) < 6 {
		stan = strings.Repeat("0", 6-len(stan)) + stan
	}
	return fmt.Sprintf("%d%03d%02d%s", t.Year()%10, t.YearDay(), t.Hour(), stan[len(stan)-6:])
}

// TransmissionDateTime formats t for field 7 as MMDDhhmmss in UTC (GMT, as
// ISO 8583 prescribes for this field).
func TransmissionDateTime(t time.Time) string {
	return t.UTC().Format("0102150405")
}

// ParseTransmissionDateTime parses a field 7 value (MMDDhhmmss, UTC). The
// field carries no year, so the year is chosen to put the result closest to
// ref; this handles messages sent around New Year and on February 29.
func ParseTransmissionDateTime(s string, ref time.Time) (time.Time, error) {
	t, err := time.Parse("0102150405", s)
	if err != nil {
		// The layout has no year, so time.Parse uses year 0, a leap year:
		// 0229 parses here and is resolved against real years below.
		return time.Time{}, fmt.Errorf("iso8583: transmission date and time %q: %w", s, err)
	}
	ref = ref.UTC()
	var best time.Time
	for _, y := range []int{ref.Year() - 1, ref.Year(), ref.Year() + 1} {
		c := time.Date(y, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
		if c.Month() != t.Month() { // February 29 in a common year
			continue
		}
		if best.IsZero() || absDuration(c.Sub(ref)) < absDuration(best.Sub(ref)) {
			best = c
		}
	}
	if best.IsZero() {
		return time.Time{}, fmt.Errorf("iso8583: transmission date and time %q: no valid year near %d", s, ref.Year())
	}
	return best, nil
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// LocalDateTime formats t for fields 12 (local time, hhmmss) and 13 (local
// date, MMDD) in t's own location.
func LocalDateTime(t time.Time) (hhmmss, mmdd string) {
	return t.Format("150405"), t.Format("0102")
}
