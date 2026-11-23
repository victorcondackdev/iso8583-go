package sim

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/victorcondackdev/iso8583-go/spec"
	"github.com/victorcondackdev/iso8583-go/transport"

	iso8583 "github.com/victorcondackdev/iso8583-go"
)

// Usage describes the simulator flags.
const Usage = `Usage: iso8583-sim [flags]

Runs a test issuer on TCP. It approves 0100/0200 requests unless a rule
declines them, answers reversals (0400/0420) and network management (0800).

Decline rules, in order:
  30  format error: no PAN (field 2 or 35) or no amount (field 4)
  14  invalid card number: PAN fails the Luhn check
  05  do not honor: PAN listed in -block
  54  expired card: expiry (field 14 or track 2) before the current month
  51  insufficient funds: amount (field 4) above -limit
Reversals of unknown transactions get 25.

Flags:
`

// Main runs the simulator until ctx is canceled, then shuts down
// gracefully. It returns a process exit code.
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return run(ctx, args, stdout, stderr, nil)
}

// run is Main with a hook that receives the listener address (for tests).
func run(ctx context.Context, args []string, stdout, stderr io.Writer, ready func(net.Addr)) int {
	fs := flag.NewFlagSet("iso8583-sim", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, Usage)
		fs.PrintDefaults()
	}
	addr := fs.String("addr", "127.0.0.1:8583", "TCP address to listen on")
	specName := fs.String("spec", "iso87ascii", "built-in spec name (iso87ascii, iso87binary) or JSON spec file")
	framing := fs.String("framing", "binary2", "length header: binary2 or ascii4")
	tpdu := fs.String("tpdu", "", "expect a 5-byte TPDU, e.g. 6000010000")
	limit := fs.Int64("limit", 100000, "decline amounts above this many minor units with 51 (0 = no limit)")
	block := fs.String("block", "", "comma-separated PANs to decline with 05")
	lenient := fs.Bool("lenient", false, "unpack requests in lenient mode")
	verbose := fs.Bool("v", false, "log every frame")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "iso8583-sim: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	cfg, err := Config(*specName, *framing, *tpdu)
	if err != nil {
		fmt.Fprintln(stderr, "iso8583-sim:", err)
		return 2
	}
	if *lenient {
		cfg.Mode = iso8583.Lenient
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(stdout, &slog.HandlerOptions{Level: level}))
	cfg.Logger = logger

	issuer := &Issuer{Logger: logger, Rules: Rules{AmountLimit: *limit, Blocked: map[string]bool{}}}
	for _, p := range strings.Split(*block, ",") {
		if p = strings.TrimSpace(p); p != "" {
			issuer.Rules.Blocked[p] = true
		}
	}
	cfg.Handler = issuer

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(stderr, "iso8583-sim:", err)
		return 1
	}
	srv := &transport.Server{Config: cfg}
	logger.Info("iso8583-sim listening", "addr", ln.Addr().String(), "spec", cfg.Spec.Name,
		"framing", cfg.Framing.String(), "limit", *limit)
	if ready != nil {
		ready(ln.Addr())
	}

	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	select {
	case err := <-served:
		fmt.Fprintln(stderr, "iso8583-sim:", err)
		return 1
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		logger.Warn("shutdown", "err", err)
	}
	<-served
	logger.Info("iso8583-sim stopped")
	return 0
}

// Config builds a transport configuration from command-line style values:
// a built-in spec name or JSON spec path, a framing name and an optional
// TPDU in hex.
func Config(specName, framing, tpdu string) (transport.Config, error) {
	var cfg transport.Config
	s, err := LoadSpec(specName)
	if err != nil {
		return cfg, err
	}
	cfg.Spec = s
	if cfg.Framing, err = transport.ParseFraming(framing); err != nil {
		return cfg, err
	}
	if tpdu != "" {
		t, err := transport.ParseTPDU(tpdu)
		if err != nil {
			return cfg, err
		}
		cfg.TPDU = &t
	}
	return cfg, nil
}

// LoadSpec returns a built-in spec by name or loads a JSON spec file.
func LoadSpec(name string) (*spec.Spec, error) {
	if s, err := spec.Lookup(name); err == nil {
		return s, nil
	}
	if _, err := os.Stat(name); err != nil {
		return nil, fmt.Errorf("spec %q is neither a built-in spec (iso87ascii, iso87binary) nor a readable file", name)
	}
	return spec.LoadFile(name)
}
