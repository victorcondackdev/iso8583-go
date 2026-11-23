// Package sim is a small test issuer: it answers authorization, financial
// and reversal requests according to a few deterministic rules, so that
// acquirer and terminal code can be exercised end to end without a card
// network. It is shared by the iso8583-sim binary and the "iso8583 sim"
// subcommand.
//
// It is a development tool. It keeps authorizations in memory, implements
// no cryptography (PIN, MAC, ARQC) and must never see real card data.
package sim

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	iso8583 "github.com/victorcondackdev/iso8583-go"
	"github.com/victorcondackdev/iso8583-go/card"
)

// ISO 8583 response codes (field 39) used by the simulator.
const (
	Approved          = "00"
	DoNotHonor        = "05"
	InvalidTxn        = "12"
	InvalidCardNumber = "14"
	RecordNotFound    = "25"
	FormatError       = "30"
	InsufficientFunds = "51"
	ExpiredCard       = "54"
)

// Rules decide the outcome of authorization and financial requests. They
// are applied in this order: format (PAN and amount present), Luhn check
// (14), blocked PAN (05), expiry (54), amount limit (51).
type Rules struct {
	// AmountLimit declines amounts above it (in minor units) with 51.
	// Zero or negative means no limit.
	AmountLimit int64
	// Blocked PANs are declined with 05.
	Blocked map[string]bool
	// Now returns the current time for expiry checks. Defaults to time.Now.
	Now func() time.Time
}

// Issuer is an [transport.Handler] implementing the simulator rules.
type Issuer struct {
	Rules  Rules
	Logger *slog.Logger

	mu       sync.Mutex
	auths    map[string]*auth
	authCode int
}

type auth struct {
	amount   int64
	reversed bool
}

func (is *Issuer) now() time.Time {
	if is.Rules.Now != nil {
		return is.Rules.Now()
	}
	return time.Now()
}

func (is *Issuer) log() *slog.Logger {
	if is.Logger != nil {
		return is.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ServeISO8583 answers one request. Unsupported request MTIs get the
// matching response MTI with response code 12.
func (is *Issuer) ServeISO8583(_ context.Context, req *iso8583.Message) (*iso8583.Message, error) {
	resp, err := iso8583.NewResponse(req)
	if err != nil {
		return nil, nil // not a request: nothing to answer
	}
	var code string
	switch req.MTI() {
	case "0100", "0200":
		code = is.authorize(req, resp)
	case "0400", "0401", "0420", "0421":
		code = is.reverse(req)
	case "0800":
		if nm, err := req.GetString(70); err == nil {
			_ = resp.SetString(70, nm) // sign-on 001, sign-off 002, echo 301, key change 161 ...
		}
		code = Approved
	default:
		code = InvalidTxn
	}
	if err := resp.SetString(39, code); err != nil {
		return nil, err
	}
	is.log().Info("exchange", "request", req.String(), "response", resp.String())
	return resp, nil
}

// pan returns the PAN from field 2, or from track 2 (field 35) before the
// separator.
func pan(m *iso8583.Message) string {
	if p, err := m.GetString(2); err == nil {
		return p
	}
	if t, err := m.GetString(35); err == nil {
		if i := strings.IndexAny(t, "=D"); i > 0 {
			return t[:i]
		}
	}
	return ""
}

// expiry returns YYMM from field 14 or from track 2 after the separator.
func expiry(m *iso8583.Message) string {
	if e, err := m.GetString(14); err == nil {
		return e
	}
	if t, err := m.GetString(35); err == nil {
		if i := strings.IndexAny(t, "=D"); i > 0 && len(t) >= i+5 {
			return t[i+1 : i+5]
		}
	}
	return ""
}

func traceKey(mti string, m *iso8583.Message) string {
	stan, _ := m.GetString(11)
	dt, _ := m.GetString(7)
	return mti + "/" + stan + "/" + dt
}

func (is *Issuer) authorize(req, resp *iso8583.Message) string {
	p := pan(req)
	amount, err := req.GetAmount(4)
	switch {
	case p == "" || err != nil:
		return FormatError
	case !card.Luhn(p):
		return InvalidCardNumber
	case is.Rules.Blocked[p]:
		return DoNotHonor
	}
	if exp := expiry(req); exp != "" {
		if len(exp) != 4 || exp[2:] < "01" || exp[2:] > "12" {
			return FormatError
		}
		// Cards are valid through the last day of the expiry month.
		if exp < is.now().UTC().Format("0601") {
			return ExpiredCard
		}
	}
	if is.Rules.AmountLimit > 0 && amount > is.Rules.AmountLimit {
		return InsufficientFunds
	}
	is.mu.Lock()
	defer is.mu.Unlock()
	is.authCode = is.authCode%999999 + 1
	if err := resp.SetString(38, fmt.Sprintf("%06d", is.authCode)); err != nil {
		return FormatError
	}
	if is.auths == nil {
		is.auths = make(map[string]*auth)
	}
	is.auths[traceKey(req.MTI(), req)] = &auth{amount: amount}
	return Approved
}

// reverse looks the original transaction up by field 90 (original MTI,
// STAN and transmission date-time in its first 20 digits) or, without
// field 90, by the reversal's own MTI class, STAN and field 7. Repeated
// reversals of the same transaction are approved again, as acquirers
// resend them until they get an answer.
func (is *Issuer) reverse(req *iso8583.Message) string {
	var key string
	if ode, err := req.GetString(90); err == nil && len(ode) >= 20 {
		key = ode[:4] + "/" + ode[4:10] + "/" + ode[10:20]
	} else {
		dt, _ := req.GetString(7)
		stan, _ := req.GetString(11)
		key = "0200/" + stan + "/" + dt
		is.mu.Lock()
		if is.auths[key] == nil {
			key = "0100/" + stan + "/" + dt
		}
		is.mu.Unlock()
	}
	is.mu.Lock()
	defer is.mu.Unlock()
	a := is.auths[key]
	if a == nil {
		return RecordNotFound
	}
	a.reversed = true
	return Approved
}

// Reversed reports whether the transaction with the given request MTI,
// STAN and field 7 was approved and then reversed.
func (is *Issuer) Reversed(mti, stan, dt string) bool {
	is.mu.Lock()
	defer is.mu.Unlock()
	a := is.auths[mti+"/"+stan+"/"+dt]
	return a != nil && a.reversed
}
