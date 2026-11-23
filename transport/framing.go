// Package transport carries ISO 8583 messages over stream connections.
//
// ISO 8583 defines messages, not transport. Over TCP, every network and
// host link frames each message with a length header and sometimes a TPDU
// routing header, and multiplexes many outstanding requests on one
// connection, pairing responses by trace numbers rather than by order.
// This package implements those conventions:
//
//   - [Framing]: 2-byte big-endian binary or 4-digit ASCII length headers.
//   - [TPDU]: the optional 5-byte transport protocol data unit used by POS
//     terminals and NAC devices, swapped automatically on responses.
//   - [Conn]: concurrent request/response matching by MTI, STAN (field 11)
//     and RRN (field 37), per-request timeouts, automatic replies to 0800
//     echo tests, optional keep-alive echoes and graceful shutdown.
//   - [Server]: accepts connections and dispatches requests to a [Handler].
package transport

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Framing is the length header that delimits messages on a stream.
type Framing uint8

const (
	// Binary2 is a 2-byte unsigned big-endian length that excludes itself;
	// the most common framing on host-to-host and terminal links. Frames up
	// to 65535 bytes.
	Binary2 Framing = iota
	// ASCII4 is a 4-digit zero-padded decimal length in ASCII, excluding
	// itself. Frames up to 9999 bytes.
	ASCII4
)

// ErrFrame reports a malformed or oversized frame header.
var ErrFrame = errors.New("transport: invalid frame")

// String returns "binary2" or "ascii4".
func (f Framing) String() string {
	switch f {
	case Binary2:
		return "binary2"
	case ASCII4:
		return "ascii4"
	}
	return fmt.Sprintf("Framing(%d)", uint8(f))
}

// ParseFraming parses the names returned by [Framing.String].
func ParseFraming(s string) (Framing, error) {
	switch strings.ToLower(s) {
	case "binary2", "binary", "2":
		return Binary2, nil
	case "ascii4", "ascii", "4":
		return ASCII4, nil
	}
	return 0, fmt.Errorf("transport: unknown framing %q (want binary2 or ascii4)", s)
}

// HeaderLen returns the size of the length header.
func (f Framing) HeaderLen() int {
	if f == ASCII4 {
		return 4
	}
	return 2
}

// MaxLen returns the largest payload the header can describe.
func (f Framing) MaxLen() int {
	if f == ASCII4 {
		return 9999
	}
	return 0xFFFF
}

// putHeader writes the header for an n-byte payload into dst, which has
// HeaderLen bytes.
func (f Framing) putHeader(dst []byte, n int) error {
	if n > f.MaxLen() {
		return fmt.Errorf("%w: %d-byte message exceeds %s maximum of %d", ErrFrame, n, f, f.MaxLen())
	}
	if f == ASCII4 {
		for i := 3; i >= 0; i-- {
			dst[i] = byte('0' + n%10)
			n /= 10
		}
		return nil
	}
	dst[0], dst[1] = byte(n>>8), byte(n)
	return nil
}

// WriteFrame writes payload with its length header in a single Write call.
func (f Framing) WriteFrame(w io.Writer, payload []byte) error {
	buf := make([]byte, f.HeaderLen(), f.HeaderLen()+len(payload))
	if err := f.putHeader(buf, len(payload)); err != nil {
		return err
	}
	_, err := w.Write(append(buf, payload...))
	return err
}

// ReadFrame reads one frame and returns its payload. A header announcing
// zero bytes yields an empty payload; some hosts send those as keep-alives.
func (f Framing) ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	h := hdr[:f.HeaderLen()]
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	var n int
	if f == ASCII4 {
		for _, c := range h {
			if c < '0' || c > '9' {
				return nil, fmt.Errorf("%w: ASCII length header %q is not numeric", ErrFrame, h)
			}
			n = n*10 + int(c-'0')
		}
	} else {
		n = int(h[0])<<8 | int(h[1])
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return payload, nil
}

// TPDU is the 5-byte transport protocol data unit that precedes the MTI on
// many terminal links: an ID byte (0x60 for transactions), a 2-byte
// destination address and a 2-byte source address. Responses carry the
// request's TPDU with the addresses swapped.
type TPDU [5]byte

// ParseTPDU parses a TPDU written as 10 hex digits, e.g. "6000010000".
func ParseTPDU(s string) (TPDU, error) {
	var t TPDU
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(t) {
		return t, fmt.Errorf("transport: TPDU %q must be 10 hex digits", s)
	}
	copy(t[:], b)
	return t, nil
}

// Swap returns the TPDU for a response: destination and source exchanged.
func (t TPDU) Swap() TPDU {
	return TPDU{t[0], t[3], t[4], t[1], t[2]}
}

// String returns the TPDU as uppercase hex.
func (t TPDU) String() string { return strings.ToUpper(hex.EncodeToString(t[:])) }
