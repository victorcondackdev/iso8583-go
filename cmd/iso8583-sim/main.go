// Command iso8583-sim runs a test card issuer over TCP. It approves or
// declines 0100/0200 requests by simple rules (Luhn check, blocked PANs,
// expiry, amount limit), answers reversals and 0800 network management,
// and logs every exchange with card data masked.
//
// Run "iso8583-sim -h" for the flags. Never point it at real card data.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/victorcondackdev/iso8583-go/internal/sim"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := sim.Main(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
