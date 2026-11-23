package iso8583

import (
	"errors"
	"fmt"
)

// Sentinel errors. Errors returned by this package wrap one of them, usually
// inside a [*FieldError]; test with [errors.Is].
var (
	// ErrTruncated reports a message that ends inside a field.
	ErrTruncated = errors.New("iso8583: message truncated")
	// ErrInvalidChar reports a byte outside the field type's character set,
	// or one that cannot be represented in the field's encoding.
	ErrInvalidChar = errors.New("iso8583: invalid character")
	// ErrLength reports a value or length prefix that does not fit the
	// field's fixed or maximum length.
	ErrLength = errors.New("iso8583: invalid length")
	// ErrUndefined reports a field number the spec does not define, either
	// in a bitmap being unpacked or in a Set call.
	ErrUndefined = errors.New("iso8583: field not defined in spec")
	// ErrTrailingData reports bytes left over after the last field (strict
	// mode only).
	ErrTrailingData = errors.New("iso8583: trailing data after last field")
	// ErrNotSet reports a Get of an absent field, or a Pack without an MTI.
	ErrNotSet = errors.New("iso8583: field not set")
	// ErrMTI reports a message type indicator that is not four digits.
	ErrMTI = errors.New("iso8583: invalid MTI")
	// ErrBitmap reports a malformed bitmap.
	ErrBitmap = errors.New("iso8583: invalid bitmap")
	// ErrPadding reports a BCD filler nibble other than the one the spec
	// prescribes (strict mode only).
	ErrPadding = errors.New("iso8583: invalid padding")
	// ErrComposite reports a value assigned to a composite field as a whole,
	// or a subfield path into a field that has no subfields.
	ErrComposite = errors.New("iso8583: composite field misuse")
	// ErrTLV reports a field 55 style value that is not valid BER-TLV
	// (strict mode only).
	ErrTLV = errors.New("iso8583: invalid TLV data")
	// ErrNoSpec reports a Message created without a spec.
	ErrNoSpec = errors.New("iso8583: message has no spec")
)

// Field numbers used in [FieldError] for the parts of a message that are
// not data fields.
const (
	// FieldMTI identifies the message type indicator.
	FieldMTI = 0
	// FieldBitmap identifies the primary, secondary or tertiary bitmap.
	FieldBitmap = 1
	// FieldNone identifies errors not tied to a field (trailing data).
	FieldNone = -1
)

// FieldError locates a problem in a message: the data field (or [FieldMTI],
// [FieldBitmap], [FieldNone]), the dotted path of the subfield when the
// problem is inside a composite field, and for wire errors the byte offset
// from the start of the message at which the field or its length prefix
// begins. Offset is -1 for errors that are not about bytes on the wire,
// such as a bad value passed to a setter.
//
// FieldError wraps a sentinel error such as [ErrTruncated] or
// [ErrInvalidChar].
type FieldError struct {
	Field  int
	Path   string
	Offset int
	Reason string
	Err    error
}

// Error implements the error interface. The format is
// "iso8583: field 35 at offset 47: <reason>".
func (e *FieldError) Error() string {
	var where string
	switch {
	case e.Path != "" && e.Path != fmt.Sprint(e.Field):
		where = "field " + e.Path
	case e.Field == FieldMTI:
		where = "MTI"
	case e.Field == FieldBitmap:
		where = "bitmap"
	case e.Field == FieldNone:
		where = "message"
	default:
		where = fmt.Sprintf("field %d", e.Field)
	}
	if e.Offset >= 0 {
		where += fmt.Sprintf(" at offset %d", e.Offset)
	}
	reason := e.Reason
	if reason == "" && e.Err != nil {
		reason = e.Err.Error()
	}
	return "iso8583: " + where + ": " + reason
}

// Unwrap returns the sentinel error.
func (e *FieldError) Unwrap() error { return e.Err }
