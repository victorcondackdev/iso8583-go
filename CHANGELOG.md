# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-22

First public release.

### Added

- `spec`: declarative message layouts loadable from JSON: data types n, an,
  ans, b, z and x+n; fixed, LLVAR, LLLVAR and LLLLVAR lengths; ASCII,
  EBCDIC (CP037), BCD, binary and hex encodings for data and length
  prefixes; padding and BCD filler rules; masking policies; positional,
  bitmapped and BER-TLV composite fields; tertiary bitmap support;
  validation with field paths. Built-in `ISO87ASCII` and `ISO87Binary`
  baselines.
- `iso8583`: `Message` with typed accessors (`SetString`, `SetBytes`,
  `SetAmount`, `SetSub` for dotted subfield paths), automatic bitmaps,
  `Pack`/`AppendPack`/`Unpack`, positional `FieldError`, strict and lenient
  modes with a byte-exact round-trip guarantee in strict mode, masked
  `String`, `Describe` and `MarshalJSON`, `UnmaskedJSON`/`UnmarshalJSON`,
  MTI helpers, `NewResponse`, STAN and RRN generators, field 7 formatting
  and parsing.
- `tlv`: BER-TLV parser and builder for EMV field 55 with multi-byte tags,
  constructed templates, long-form lengths, a dictionary of common EMV tags
  and masking of sensitive tags.
- `transport`: Binary2 and ASCII4 framing, TPDU, `Conn` with concurrent
  request/response matching by MTI, STAN and RRN, timeouts, automatic
  echo replies, keep-alive echoes, graceful shutdown; `Server`.
- `card`: Luhn check and check digit, brand detection for Visa,
  Mastercard, American Express, Discover and JCB, BIN extraction, PAN and
  track masking.
- `ebcdic`: CP037 conversion.
- `cmd/iso8583`: `decode`, `encode`, `send`, `sim` and `spec` commands.
- `cmd/iso8583-sim`: test issuer with Luhn, blocked-PAN, expiry and
  amount-limit rules, reversals and network management; Dockerfile.

[Unreleased]: https://github.com/victorcondackdev/iso8583-go/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/victorcondackdev/iso8583-go/releases/tag/v0.1.0
