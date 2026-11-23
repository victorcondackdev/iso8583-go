# iso8583-go

[![CI](https://github.com/victorcondackdev/iso8583-go/actions/workflows/ci.yml/badge.svg)](https://github.com/victorcondackdev/iso8583-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/victorcondackdev/iso8583-go.svg)](https://pkg.go.dev/github.com/victorcondackdev/iso8583-go)

iso8583-go is a dependency-free Go codec for ISO 8583, the message format
spoken between POS terminals, acquirers, card networks and issuers. Message
layouts are declarative specs (JSON or Go), decoding errors carry the field
and byte offset that failed, every human-readable rendering masks
cardholder data, and the package ships what a real integration needs
around the codec: EMV field 55 BER-TLV, TCP framing with concurrent
request/response matching, and a test issuer you can point a terminal at.

```text
$ iso8583 decode --spec iso87binary 020050200000200012001641111111111111110000000025000001233441...
MTI      0200 Financial request
Bitmap   5020000020001200
F2       n..19      Primary account number (PAN)                 411111******1111
F4       n 12       Amount, transaction                          000000002500
F11      n 6        System trace audit number (STAN)             000123
F35      z..37      Track 2 data                                 411111******1111=*****************
F52      b 8        Personal identification number (PIN) data    ****************
F55      b...999    ICC system related data (EMV)                24 bytes, 3 tags
           9F02 Amount, Authorised (Numeric): 000000002500
           5F2A Transaction Currency Code: 0986
           5A Application Primary Account Number (PAN): 411111******1111
```

## Why

- **Declarative specs.** Field types (n, an, ans, b, z, x+n), fixed and
  LL/LLL/LLLL lengths, ASCII / EBCDIC (CP037) / BCD / binary / hex
  encodings, length-prefix encodings, padding rules, masking policy and
  composite subfields (positional, bitmapped, BER-TLV) are data. Load a
  network's layout from JSON, or clone a built-in and patch it in Go.
- **Positional errors.** `Unpack` returns a `*FieldError` with the field,
  the subfield path and the byte offset: `iso8583: field 35 at offset 47:
  invalid character 'x' at position 16 for type z`. Works with `errors.Is`
  and `errors.As`.
- **Round-trip guarantee.** In strict mode, anything that unpacks packs back
  to the identical bytes. Fuzzing and property tests enforce it on every
  encoding combination. Lenient mode accepts what real hosts send
  (lowercase hex, odd filler nibbles, trailing bytes) without giving up on
  framing.
- **PCI DSS-minded by default.** `String()`, `Describe()` and `MarshalJSON`
  mask the PAN (first six, last four), track data, PIN block, CVV and
  expiry, including the sensitive EMV tags inside field 55 (5A, 57, 5F20,
  5F24, 9F1F, 9F20). A `Message` can go straight into a log line;
  `UnmaskedJSON` is the explicit, greppable opt-out.
- **EMV TLV.** A BER-TLV parser and builder for field 55: multi-byte tags,
  constructed templates, long-form lengths, a dictionary of common EMV tags.
- **Framing and a simulator.** 2-byte binary or 4-digit ASCII length
  headers, optional TPDU, a `Conn` that multiplexes concurrent requests and
  matches responses by MTI + STAN + RRN, timeouts, 0800 echo and
  keep-alive, graceful shutdown. `iso8583-sim` approves and declines
  0100/0200 by rule and answers reversals.
- **Zero dependencies.** Standard library only, Go 1.22+.

## Install

```sh
go get github.com/victorcondackdev/iso8583-go
```

CLI and simulator:

```sh
go install github.com/victorcondackdev/iso8583-go/cmd/iso8583@latest
go install github.com/victorcondackdev/iso8583-go/cmd/iso8583-sim@latest
```

## Quick start

```go
import (
	iso8583 "github.com/victorcondackdev/iso8583-go"
	"github.com/victorcondackdev/iso8583-go/spec"
)

s := spec.ISO87ASCII() // or spec.ISO87Binary(), or spec.LoadFile("visa.json")

req := iso8583.NewMessage(s)
req.SetMTI("0200")
req.SetString(2, "4111111111111111")
req.SetString(3, "000000")
req.SetAmount(4, 2500) // 25.00 -> "000000002500"
req.SetString(11, "000123")
req.SetString(41, "TERM0001")
req.SetString(49, "986")

b, err := req.Pack()
// 02007020000000808000164111111111111111000000000000002500000123TERM0001986

in := iso8583.NewMessage(s)
if err := in.Unpack(b); err != nil {
	var fe *iso8583.FieldError
	if errors.As(err, &fe) {
		log.Printf("field %d at byte %d: %s", fe.Field, fe.Offset, fe.Reason)
	}
}
amount, _ := in.GetAmount(4) // 2500
log.Println(in)              // 0200 2=411111******1111 3=000000 4=000000002500 11=000123 ...
```

Bitmaps are never set by hand: `Pack` derives the primary, secondary and
(when the spec enables it) tertiary bitmaps from the fields present.
Values are stored as they travel, after padding, so a fixed `n 6` set to
`"123"` reads back as `"000123"`.

`iso8583.NewResponse(req)` starts the 0210 with the fields an acquirer
expects echoed (2, 3, 4, 7, 11, 12, 13, 32, 37, 41, 42, 49) and never the
PIN block or track data.

## Specs

A spec says how every field looks on the wire. The two built-ins follow
the commonly published ISO 8583:1987 data element table:

| Spec          | MTI   | Bitmap          | Numerics | Text  | Binary | Length prefixes          |
|---------------|-------|-----------------|----------|-------|--------|--------------------------|
| `ISO87ASCII`  | ASCII | 16 hex chars    | ASCII    | ASCII | hex    | ASCII digits             |
| `ISO87Binary` | BCD   | 8 raw bytes     | BCD      | ASCII | raw    | BCD (LL 1 byte, LLL 2)   |

They are generic baselines. Every network (Visa, Mastercard, Elo, domestic
switches, processors) redefines private fields, encodings and subfields,
and neither built-in is a certified layout. Start from one:

```sh
iso8583 spec iso87binary > mynetwork.json   # edit, then load with spec.LoadFile
```

A customised layout, abridged from [examples/acme-spec.json](examples/acme-spec.json):

```json
{
  "name": "ACME-POS",
  "mtiEncoding": "ascii",
  "bitmapEncoding": "hex",
  "defaults": { "numeric": "ascii", "text": "ascii", "binary": "hex", "prefix": "ascii" },
  "fields": {
    "2":  { "name": "PAN", "type": "n", "length": 19, "lengthType": "llvar", "mask": "pan" },
    "4":  { "name": "Amount, transaction", "type": "n", "length": 12, "pad": "left" },
    "35": { "name": "Track 2 data", "type": "z", "length": 37, "lengthType": "llvar", "mask": "track" },
    "48": {
      "name": "Additional data (private)", "type": "ans", "length": 999, "lengthType": "lllvar",
      "composite": { "kind": "positional", "fields": {
        "1": { "name": "Installments", "type": "n", "length": 2, "pad": "left" },
        "2": { "name": "CVV2", "type": "n", "length": 3, "mask": "full" },
        "3": { "name": "Merchant order reference", "type": "ans", "length": 20, "lengthType": "llvar" }
      } }
    },
    "55": { "name": "ICC data", "type": "b", "length": 255, "lengthType": "lllvar", "composite": { "kind": "tlv" } },
    "62": {
      "name": "Terminal data (private)", "type": "ans", "length": 999, "lengthType": "lllvar",
      "composite": { "kind": "bitmapped", "bitmapBytes": 8, "fields": {
        "1": { "name": "Terminal serial number", "type": "ans", "length": 20, "lengthType": "llvar" },
        "8": { "name": "Batch number", "type": "n", "length": 6, "pad": "left" }
      } }
    }
  }
}
```

Subfields are addressed by dotted path:

```go
m.SetSub("48.1", "3")        // "03"
m.SetSub("48.2", "123")      // masked as *** in every dump
m.SetSub("62.8", "17")       // "000017", announced in 62's own bitmap
```

The rules, in short:

- **Units.** Lengths count digits for n, z and x+n, characters for an and
  ans, bytes for b. A 19-digit PAN is `"length": 19` in ASCII and BCD alike;
  hex-encoded binary fields still count bytes.
- **Encodings.** n, z, x+n: `ascii`, `ebcdic`, `bcd`. an, ans: `ascii`,
  `ebcdic`. b: `binary`, `hex`. Prefixes: `ascii`, `ebcdic`, `bcd`, `binary`.
- **BCD padding.** Odd digit counts get one filler nibble: `"bcdPad":
  "left"` (0, the default) or `"right"` (F, the default for z). Track 2's
  `=` is nibble D.
- **x+n amounts** travel as a `C`/`D` sign byte (ASCII, or EBCDIC with an
  EBCDIC field) followed by the digits in the field's encoding.
- **Validation.** Specs are checked when loaded: incompatible type and
  encoding pairs, lengths beyond what the prefix can express, padding
  characters outside the type's set, unknown JSON keys and malformed
  composites are reported with the field path.

## EMV field 55

```go
import "github.com/victorcondackdev/iso8583-go/tlv"

l, err := tlv.Parse(field55)
amount, _ := l.Find(0x9F02)    // Amount, Authorised
fmt.Println(l)                 // one tag per line, names from the dictionary, PAN masked

icc := tlv.List{
	tlv.New(0x9F02, []byte{0, 0, 0, 0, 0x25, 0}),
	tlv.New(0x5F2A, []byte{0x09, 0x86}),
	tlv.NewConstructed(0x70, tlv.New(0x5F34, []byte{0x01})),
}.Bytes()
m.SetBytes(55, icc)
```

Strict `Unpack` validates TLV structure in TLV fields and reports the
offset of the bad tag or length within the message.

## Transport

```go
import "github.com/victorcondackdev/iso8583-go/transport"

cfg := transport.Config{Spec: spec.ISO87Binary(), Framing: transport.Binary2, Timeout: 5 * time.Second,
	EchoInterval: 30 * time.Second}
conn, err := transport.Dial(ctx, "acquirer.example:5000", cfg)
defer conn.Shutdown(context.Background())

resp, err := conn.Send(ctx, req) // safe from many goroutines; matched by MTI + STAN (+ RRN)
code, _ := resp.GetString(39)
```

- Responses may arrive in any order; each `Send` gets its own. A request
  without field 11 is rejected; a second in-flight request with the same
  MTI and STAN gets `ErrDuplicate`. If both request and response carry
  field 37, they must agree.
- Timeouts return an error matching both `transport.ErrTimeout` and
  `context.DeadlineExceeded`; the late response is logged and dropped.
- Incoming 0800 echo tests (field 70 = 301) are answered automatically.
  With `EchoInterval`, the Conn sends its own after read inactivity and
  closes the link with `ErrEcho` when the peer stops answering.
- `TPDU` support: the configured TPDU prefixes outgoing requests; responses
  reuse the incoming TPDU with destination and source swapped.
- `Shutdown` refuses new work, waits for in-flight requests and handlers,
  then closes. `transport.Server` does the same for every accepted
  connection and dispatches requests to a `Handler`.

## Simulator walkthrough

`iso8583-sim` (also `iso8583 sim`) is a test issuer. It approves 0100/0200
requests unless a rule declines them, in this order:

| Code | Meaning             | Rule                                                   |
|------|---------------------|--------------------------------------------------------|
| 30   | Format error        | no PAN (field 2 or track 2) or no amount (field 4)     |
| 14   | Invalid card number | PAN fails the Luhn check                               |
| 05   | Do not honor        | PAN listed in `-block`                                 |
| 54   | Expired card        | expiry (field 14 or track 2) before the current month  |
| 51   | Insufficient funds  | amount above `-limit` (minor units)                    |
| 00   | Approved            | otherwise; field 38 gets an authorization code         |

Reversals (0400/0420) are matched to the original by field 90 (or by STAN
and field 7) and answered 00, or 25 when the original is unknown. 0800
sign-on, sign-off and echo get 0810 with 00.

```sh
$ iso8583-sim -spec iso87ascii -framing binary2 -limit 2000 &
level=INFO msg="iso8583-sim listening" addr=127.0.0.1:8583 spec=ISO87ASCII framing=binary2 limit=2000

$ iso8583 send --addr 127.0.0.1:8583 examples/purchase.json    # 25.00, over the 20.00 limit
> 0200 2=411111******1111 3=000000 4=000000002500 7=1123010846 11=450271 ... 55=[9F02 5F2A 9F26 82 95 9A 9C]
MTI      0210 Financial response
Bitmap   7238000002C08000
F2       n..19      Primary account number (PAN)                 411111******1111
F4       n 12       Amount, transaction                          000000002500
F11      n 6        System trace audit number (STAN)             450271
F39      an 2       Response code                                51
...
```

Fields 7 and 11 are filled in by `send` when the JSON omits them. The
simulator logs each exchange as a masked one-liner. Run it in Docker:

```sh
docker build -t iso8583-sim .
docker run --rm -p 8583:8583 iso8583-sim -limit 50000 -block 5555555555554444
```

## CLI

```sh
iso8583 decode --spec iso87binary 02005020...         # masked field table
iso8583 decode --spec mynetwork.json --json dump.bin  # masked JSON, raw or hex file
iso8583 decode --raw --skip 2 "$(cat frame.txt)"      # literal ASCII message, drop a length header
iso8583 encode examples/acme-spec.json examples/acme-purchase.json
iso8583 send --addr host:port --spec iso87binary --framing ascii4 --tpdu 6000010000 msg.json
iso8583 spec iso87ascii
```

A failed decode prints the positional error and the bytes around it:

```text
iso8583: field 3 at offset 20: invalid character 'A' at position 2 for type n
  bytes 12-25: 30 30 30 30 30 30 30 30 30 30 41 30 30 30
                                       ^
```

## Benchmarks

A 0200 purchase with 14 fields (PAN, track 2, PIN block, a 14-byte field
55), Go 1.24, 2 vCPU shared VM (Intel Xeon 2.1 GHz), `go test -bench .`:

| Benchmark                    | ISO87ASCII            | ISO87Binary           |
|------------------------------|-----------------------|-----------------------|
| Pack (reused buffer)         | ~0.5 µs, 0 allocs     | ~0.6 µs, 0 allocs     |
| Unpack (strict)              | ~1.3–2.5 µs, 6 allocs | ~2.0–2.3 µs, 6 allocs |
| NewMessage + 14 Sets + Pack  |                       | ~4.5 µs, 31 allocs    |

Unpack carves every value out of one arena, so allocations do not grow
with the field count. Run `go test -run '^$' -bench . -benchmem` to
reproduce on your hardware.

## Testing

- Hand-computed vectors for BCD packing and filler nibbles, EBCDIC CP037,
  length prefixes in every encoding, bitmaps (primary, secondary,
  tertiary) and complete messages in ASCII, binary and EBCDIC layouts. The
  computations are written out in the test comments.
- Property tests pack random valid messages for five specs (including one
  that combines every encoding, nested composites and the tertiary bitmap),
  then check unpack, repack and JSON round trips.
- Fuzz targets for `Unpack` (both built-ins, composites, the kitchen-sink
  spec), `tlv.Parse` and spec loading. Strict-mode inputs must round-trip
  byte for byte.
- Transport tests over `net.Pipe` and real TCP, under `-race`: 200
  concurrent out-of-order requests, timeouts and late responses, echo and
  keep-alive failure, TPDU swapping, graceful shutdown with and without a
  deadline.

```sh
go test -race ./...
go test -run '^$' -fuzz '^FuzzUnpackISO87Binary$' -fuzztime 60s .
```

## Disclaimer

The built-in specs are generic ISO 8583:1987 baselines, not network-
certified layouts; certification is between you, your acquirer and the
networks. The brand detection in `card` covers a few long-standing public
prefix ranges and is a hint, not a BIN table. The simulator implements no
cryptography (PIN translation, MAC, ARQC validation).

Never log, commit or paste real card data, including into this project's
CLI, issues or test fixtures. The masking here reduces accidental
exposure; it does not make a system PCI DSS compliant.

## Roadmap

- ISO 8583:1993 and 2003 baselines (3-digit function codes, different
  field 1/65 semantics).
- Elo and other domestic-scheme brand detection, which needs the schemes'
  own BIN tables because their ranges overlap Visa and Discover.
- MAC (fields 64/128) and PIN block helpers behind an HSM-friendly
  interface.

## License

[MIT](LICENSE)
