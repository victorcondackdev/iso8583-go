// Package iso8583 packs and unpacks ISO 8583 financial messages: the
// card-acquiring and issuing protocol spoken between POS terminals,
// acquirers, card networks and issuers.
//
// A [Message] is a message type indicator (MTI) plus numbered data fields,
// laid out on the wire according to a declarative [spec.Spec]: which fields
// exist, their ISO data types, fixed or variable lengths, encodings (ASCII,
// EBCDIC, BCD, binary, hex), length-prefix formats and subfield layouts.
// The codec itself knows nothing about any particular network.
//
//	m := iso8583.NewMessage(spec.ISO87ASCII())
//	m.SetMTI("0200")
//	m.SetString(2, "4111111111111111")
//	m.SetString(3, "000000")
//	m.SetAmount(4, 1000) // 10.00 -> "000000001000"
//	b, err := m.Pack()
//
// # Bitmaps
//
// Bitmaps are never set by hand. [Message.Pack] derives them from the
// fields present: the secondary bitmap (and bit 1) only when a field above
// 64 is set, the tertiary bitmap (and bit 65) only when the spec enables it
// and a field above 128 is set.
//
// # Errors
//
// [Message.Unpack] reports problems as a [*FieldError] carrying the field
// number, the subfield path and the byte offset where decoding failed, so
// a bad message from a host can be diagnosed from the log line alone:
//
//	iso8583: field 35 at offset 47: invalid character 'x' at position 16 for type z
//
// # Strict and lenient modes
//
// Messages are [Strict] by default: character sets, BCD filler nibbles,
// hex case, TLV syntax and trailing bytes are enforced, and anything that
// unpacks packs back to the identical bytes (the round-trip guarantee,
// covered by fuzz and property tests). [Lenient] relaxes the content checks
// for interoperating with hosts that bend the rules, while still refusing
// anything whose framing is ambiguous.
//
// # Masking
//
// [Message.String], [Message.Describe] and [Message.MarshalJSON] apply the
// spec's masking policy, so messages can be logged without leaking the PAN,
// track data, PIN block or CVV; [Message.UnmaskedJSON] is the explicit
// opt-out.
//
// Sub-packages provide the building blocks around the codec: [spec] for
// layouts, tlv for EMV field 55, transport for TCP framing and
// request/response matching, card for Luhn, brand detection and masking,
// and ebcdic for code page 037.
package iso8583
