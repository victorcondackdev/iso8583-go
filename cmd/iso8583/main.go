// Command iso8583 decodes, encodes and sends ISO 8583 messages, and runs a
// test issuer.
//
// Run "iso8583 help" for usage.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	iso8583 "github.com/victorcondackdev/iso8583-go"
	"github.com/victorcondackdev/iso8583-go/internal/sim"
	"github.com/victorcondackdev/iso8583-go/spec"
	"github.com/victorcondackdev/iso8583-go/transport"
)

// version is set at build time with -ldflags "-X main.version=v0.1.0".
var version = "dev"

// Exit codes.
const (
	exitOK      = 0
	exitInvalid = 1
	exitUsage   = 2
)

// maxInput bounds what is read from files and stdin.
const maxInput = 1 << 20

const usage = `iso8583 decodes, encodes and sends ISO 8583 messages.

Usage:
  iso8583 decode [--spec NAME|FILE] [--lenient] [--json] [--skip N] [--raw] [hex | FILE | -]
        Unpack a message and print a masked field table (or masked JSON).
        Arguments are hex; files and stdin may hold hex text or raw bytes.
        --skip drops leading bytes such as a length header or TPDU.
  iso8583 encode [--out FILE] SPEC MESSAGE.json
        Pack a JSON message ({"mti": ..., "fields": {...}}) and print it as
        hex, or write the raw bytes to --out.
  iso8583 send --addr HOST:PORT [--spec S] [--framing F] [--tpdu HEX]
               [--timeout D] MESSAGE.json
        Send a request and print the masked response. Fields 7 and 11 are
        filled in when absent.
  iso8583 sim [flags]
        Run the test issuer (same as iso8583-sim; see "iso8583 sim -h").
  iso8583 spec NAME
        Print a built-in spec (iso87ascii, iso87binary) as JSON, as a
        starting point for a custom layout.
  iso8583 version
        Print the version.

SPEC is a built-in spec name (iso87ascii, iso87binary) or a JSON spec file.
Exit status: 0 success, 1 invalid input, 2 usage error.

Output is masked (PAN, track data, PIN block, CVV) except for encode, which
needs the clear values. Never use real card data with this tool.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type cli struct {
	ctx    context.Context
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// run is the whole program, minus process-level concerns, for testing.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	c := &cli{ctx: ctx, stdin: stdin, stdout: stdout, stderr: stderr}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "decode":
		return c.decode(rest)
	case "encode":
		return c.encode(rest)
	case "send":
		return c.send(rest)
	case "sim":
		return sim.Main(ctx, rest, stdout, stderr)
	case "spec":
		return c.spec(rest)
	case "version":
		fmt.Fprintln(stdout, "iso8583", version)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "iso8583: unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
}

func (c *cli) fail(format string, a ...any) int {
	msg := fmt.Sprintf(format, a...)
	if !strings.HasPrefix(msg, "iso8583: ") {
		msg = "iso8583: " + msg
	}
	fmt.Fprintln(c.stderr, msg)
	return exitInvalid
}

func (c *cli) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() { fmt.Fprint(c.stderr, usage) }
	return fs
}

// parse parses flags, allowing them after positional arguments too.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func usageErr(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	return exitUsage
}

func (c *cli) decode(args []string) int {
	fs := c.flags("decode")
	specName := fs.String("spec", "iso87ascii", "spec name or JSON file")
	lenient := fs.Bool("lenient", false, "lenient mode")
	asJSON := fs.Bool("json", false, "print masked JSON")
	skip := fs.Int("skip", 0, "leading bytes to drop")
	raw := fs.Bool("raw", false, "treat input as raw bytes, not hex")
	pos, err := parse(fs, args)
	if err != nil {
		return usageErr(err)
	}
	if len(pos) > 1 {
		pos = []string{strings.Join(pos, "")} // hex split by spaces
	}
	s, err := sim.LoadSpec(*specName)
	if err != nil {
		return c.fail("%v", err)
	}
	data, err := c.input(pos, *raw)
	if err != nil {
		return c.fail("%v", err)
	}
	if *skip < 0 || *skip > len(data) {
		return c.fail("--skip %d is outside the %d-byte input", *skip, len(data))
	}
	data = data[*skip:]
	mode := iso8583.Strict
	if *lenient {
		mode = iso8583.Lenient
	}
	m := iso8583.NewMessage(s, iso8583.WithMode(mode))
	if err := m.Unpack(data); err != nil {
		c.fail("%v", err)
		var fe *iso8583.FieldError
		if errors.As(err, &fe) && fe.Offset >= 0 {
			fmt.Fprint(c.stderr, pointAt(data, fe.Offset))
		}
		return exitInvalid
	}
	if *asJSON {
		j, err := m.MarshalJSON()
		if err != nil {
			return c.fail("%v", err)
		}
		fmt.Fprintln(c.stdout, string(j))
		return exitOK
	}
	fmt.Fprint(c.stdout, m.Describe())
	return exitOK
}

// pointAt renders up to 16 bytes around offset as hex with a caret under
// the failing byte. It only shows bytes the decoder already rejected, so
// it is printed to stderr and not masked.
func pointAt(data []byte, off int) string {
	start := max(0, off-8)
	end := min(len(data), off+8)
	var sb strings.Builder
	fmt.Fprintf(&sb, "  bytes %d-%d: % X\n", start, max(start, end-1), data[start:end])
	sb.WriteString("  " + strings.Repeat(" ", len(fmt.Sprintf("bytes %d-%d: ", start, max(start, end-1)))+3*(off-start)) + "^\n")
	return sb.String()
}

// input returns the message bytes from a hex argument, a file or stdin.
func (c *cli) input(pos []string, raw bool) ([]byte, error) {
	if len(pos) == 0 || pos[0] == "-" {
		b, err := io.ReadAll(io.LimitReader(c.stdin, maxInput))
		if err != nil {
			return nil, err
		}
		return maybeHex(b, raw), nil
	}
	arg := pos[0]
	if st, err := os.Stat(arg); err == nil && !st.IsDir() {
		b, err := os.ReadFile(arg)
		if err != nil {
			return nil, err
		}
		return maybeHex(b, raw), nil
	}
	if raw {
		return []byte(arg), nil
	}
	b, err := hex.DecodeString(strings.Join(strings.Fields(arg), ""))
	if err != nil {
		return nil, fmt.Errorf("argument is neither a file nor hex (use --raw for a literal message): %v", err)
	}
	return b, nil
}

// maybeHex decodes b when it is hex text (whitespace allowed).
func maybeHex(b []byte, raw bool) []byte {
	if raw {
		return b
	}
	compact := bytes.Join(bytes.Fields(b), nil)
	if len(compact) == 0 || len(compact)%2 != 0 {
		return b
	}
	out := make([]byte, len(compact)/2)
	if _, err := hex.Decode(out, compact); err != nil {
		return b
	}
	return out
}

func (c *cli) loadMessage(s *spec.Spec, path string) (*iso8583.Message, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := iso8583.NewMessage(s)
	if err := m.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

func (c *cli) encode(args []string) int {
	fs := c.flags("encode")
	out := fs.String("out", "", "write raw bytes to this file instead of hex to stdout")
	pos, err := parse(fs, args)
	if err != nil {
		return usageErr(err)
	}
	if len(pos) != 2 {
		fmt.Fprint(c.stderr, "iso8583: encode needs SPEC and MESSAGE.json\n")
		return exitUsage
	}
	s, err := sim.LoadSpec(pos[0])
	if err != nil {
		return c.fail("%v", err)
	}
	m, err := c.loadMessage(s, pos[1])
	if err != nil {
		return c.fail("%v", err)
	}
	b, err := m.Pack()
	if err != nil {
		return c.fail("%v", err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, b, 0o600); err != nil {
			return c.fail("%v", err)
		}
		fmt.Fprintf(c.stderr, "wrote %d bytes to %s\n", len(b), *out)
		return exitOK
	}
	fmt.Fprintf(c.stdout, "%X\n", b)
	return exitOK
}

func (c *cli) send(args []string) int {
	fs := c.flags("send")
	addr := fs.String("addr", "127.0.0.1:8583", "host:port")
	specName := fs.String("spec", "iso87ascii", "spec name or JSON file")
	framing := fs.String("framing", "binary2", "binary2 or ascii4")
	tpdu := fs.String("tpdu", "", "TPDU in hex")
	timeout := fs.Duration("timeout", 10*time.Second, "response timeout")
	pos, err := parse(fs, args)
	if err != nil {
		return usageErr(err)
	}
	if len(pos) != 1 {
		fmt.Fprint(c.stderr, "iso8583: send needs one MESSAGE.json\n")
		return exitUsage
	}
	cfg, err := sim.Config(*specName, *framing, *tpdu)
	if err != nil {
		return c.fail("%v", err)
	}
	cfg.Timeout = *timeout
	req, err := c.loadMessage(cfg.Spec, pos[0])
	if err != nil {
		return c.fail("%v", err)
	}
	now := time.Now()
	if !req.Has(7) {
		if err := req.SetString(7, iso8583.TransmissionDateTime(now)); err != nil {
			return c.fail("%v", err)
		}
	}
	if !req.Has(11) {
		if err := req.SetString(11, fmt.Sprintf("%06d", now.UnixNano()/1000%999999+1)); err != nil {
			return c.fail("%v", err)
		}
	}
	ctx, cancel := context.WithTimeout(c.ctx, *timeout)
	defer cancel()
	conn, err := transport.Dial(ctx, *addr, cfg)
	if err != nil {
		return c.fail("%v", err)
	}
	defer conn.Close()
	fmt.Fprintf(c.stdout, "> %s\n", req)
	resp, err := conn.Send(ctx, req)
	if err != nil {
		return c.fail("%v", err)
	}
	fmt.Fprint(c.stdout, resp.Describe())
	return exitOK
}

func (c *cli) spec(args []string) int {
	if len(args) != 1 {
		fmt.Fprint(c.stderr, "iso8583: spec needs a built-in spec name (iso87ascii, iso87binary)\n")
		return exitUsage
	}
	s, err := spec.Lookup(args[0])
	if err != nil {
		return c.fail("%v", err)
	}
	b, err := jsonIndent(s)
	if err != nil {
		return c.fail("%v", err)
	}
	fmt.Fprintln(c.stdout, string(b))
	return exitOK
}

func jsonIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
