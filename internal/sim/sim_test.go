package sim

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	iso8583 "github.com/victorcondackdev/iso8583-go"
	"github.com/victorcondackdev/iso8583-go/spec"
	"github.com/victorcondackdev/iso8583-go/transport"
)

var testNow = func() time.Time { return time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC) }

func msg(t *testing.T, mti string, fields map[int]string) *iso8583.Message {
	t.Helper()
	m := iso8583.NewMessage(spec.ISO87ASCII())
	if err := m.SetMTI(mti); err != nil {
		t.Fatal(err)
	}
	for id, v := range fields {
		if err := m.SetString(id, v); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func TestRules(t *testing.T) {
	is := &Issuer{Rules: Rules{AmountLimit: 10000, Blocked: map[string]bool{"5555555555554444": true}, Now: testNow}}
	base := func(over map[int]string) map[int]string {
		f := map[int]string{2: "4111111111111111", 4: "5000", 7: "1122120000", 11: "000001", 14: "2912"}
		for k, v := range over {
			if v == "" {
				delete(f, k)
			} else {
				f[k] = v
			}
		}
		return f
	}
	tests := []struct {
		name string
		mti  string
		over map[int]string
		code string
	}{
		{"approved", "0200", nil, Approved},
		{"auth approved", "0100", map[int]string{11: "000002"}, Approved},
		{"at limit", "0200", map[int]string{4: "10000", 11: "000003"}, Approved},
		{"over limit", "0200", map[int]string{4: "10001"}, InsufficientFunds},
		{"luhn", "0200", map[int]string{2: "4111111111111112"}, InvalidCardNumber},
		{"blocked", "0200", map[int]string{2: "5555555555554444"}, DoNotHonor},
		{"expired", "0200", map[int]string{14: "2610"}, ExpiredCard},
		{"expires this month", "0200", map[int]string{14: "2611", 11: "000004"}, Approved},
		{"bad expiry", "0200", map[int]string{14: "2613"}, FormatError},
		{"no amount", "0200", map[int]string{4: ""}, FormatError},
		{"no PAN", "0200", map[int]string{2: ""}, FormatError},
		{"track 2 only", "0200", map[int]string{2: "", 14: "", 35: "4111111111111111=2512101"}, ExpiredCard},
		{"track 2 valid", "0200", map[int]string{2: "", 14: "", 11: "000005", 35: "4111111111111111=2912101"}, Approved},
		{"short track", "0200", map[int]string{2: "", 14: "", 11: "000006", 35: "4111111111111111="}, Approved},
		{"unsupported", "0300", nil, InvalidTxn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := msg(t, tt.mti, base(tt.over))
			resp, err := is.ServeISO8583(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if want, _ := iso8583.ResponseMTI(tt.mti); resp.MTI() != want {
				t.Errorf("MTI = %s, want %s", resp.MTI(), want)
			}
			code, _ := resp.GetString(39)
			if code != tt.code {
				t.Errorf("response code = %s, want %s", code, tt.code)
			}
			if _, err := resp.GetString(38); (err == nil) != (code == Approved && tt.mti != "0300") {
				t.Errorf("auth code presence wrong for %s", code)
			}
		})
	}
	if resp, _ := is.ServeISO8583(context.Background(), msg(t, "0210", nil)); resp != nil {
		t.Error("answered a response")
	}
}

func TestReversals(t *testing.T) {
	is := &Issuer{Rules: Rules{Now: testNow}}
	purchase := msg(t, "0200", map[int]string{2: "4111111111111111", 4: "1000", 7: "1122120000", 11: "000042"})
	if resp, _ := is.ServeISO8583(context.Background(), purchase); mustCode(t, resp) != Approved {
		t.Fatal("purchase declined")
	}
	ode := "0200" + "000042" + "1122120000" + strings.Repeat("0", 22)
	tests := []struct {
		name   string
		mti    string
		fields map[int]string
		code   string
	}{
		{"by field 90", "0400", map[int]string{11: "000043", 90: ode}, Approved},
		{"repeat advice", "0420", map[int]string{11: "000044", 90: ode}, Approved},
		{"by own STAN", "0420", map[int]string{11: "000042", 7: "1122120000"}, Approved},
		{"unknown", "0400", map[int]string{11: "000099", 7: "1122120000"}, RecordNotFound},
	}
	for _, tt := range tests {
		resp, err := is.ServeISO8583(context.Background(), msg(t, tt.mti, tt.fields))
		if err != nil {
			t.Fatal(err)
		}
		if want, _ := iso8583.ResponseMTI(tt.mti); resp.MTI() != want {
			t.Errorf("%s: MTI = %s", tt.name, resp.MTI())
		}
		if code := mustCode(t, resp); code != tt.code {
			t.Errorf("%s: code = %s, want %s", tt.name, code, tt.code)
		}
	}
	if !is.Reversed("0200", "000042", "1122120000") || is.Reversed("0200", "000001", "x") {
		t.Error("Reversed")
	}
	// An 0100 found through the fallback path.
	auth := msg(t, "0100", map[int]string{2: "4111111111111111", 4: "1000", 7: "1122120000", 11: "000050"})
	is.ServeISO8583(context.Background(), auth)
	resp, _ := is.ServeISO8583(context.Background(), msg(t, "0400", map[int]string{11: "000050", 7: "1122120000"}))
	if mustCode(t, resp) != Approved {
		t.Error("0100 reversal by STAN")
	}
	nm, _ := is.ServeISO8583(context.Background(), msg(t, "0800", map[int]string{11: "000001", 70: "001"}))
	if v, _ := nm.GetString(70); v != "001" || mustCode(t, nm) != Approved {
		t.Error("sign-on")
	}
}

func mustCode(t *testing.T, m *iso8583.Message) string {
	t.Helper()
	c, err := m.GetString(39)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestMainOverTCP(t *testing.T) {
	for _, tt := range []struct {
		spec, framing, tpdu string
	}{
		{"iso87ascii", "binary2", ""},
		{"iso87binary", "ascii4", "6000010000"},
		{"../../examples/acme-spec.json", "binary2", ""},
	} {
		t.Run(tt.spec, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			addrc := make(chan net.Addr, 1)
			var out, errOut syncBuffer
			done := make(chan int, 1)
			args := []string{"-addr", "127.0.0.1:0", "-spec", tt.spec, "-framing", tt.framing,
				"-limit", "5000", "-block", "5555555555554444, ", "-v"}
			if tt.tpdu != "" {
				args = append(args, "-tpdu", tt.tpdu, "-lenient")
			}
			go func() { done <- run(ctx, args, &out, &errOut, func(a net.Addr) { addrc <- a }) }()
			var addr net.Addr
			select {
			case addr = <-addrc:
			case code := <-done:
				t.Fatalf("exited with %d: %s", code, errOut.String())
			}
			cfg, err := Config(tt.spec, tt.framing, tt.tpdu)
			if err != nil {
				t.Fatal(err)
			}
			c, err := transport.Dial(context.Background(), addr.String(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			for stan, want := range map[string]string{"000001": Approved, "000002": InsufficientFunds} {
				req := iso8583.NewMessage(cfg.Spec)
				amount := int64(4999)
				if want == InsufficientFunds {
					amount = 5001
				}
				err := errors.Join(req.SetMTI("0200"), req.SetString(2, "4111111111111111"),
					req.SetAmount(4, amount), req.SetString(11, stan), req.SetString(7, "1122120000"))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := c.Send(context.Background(), req)
				if err != nil {
					t.Fatal(err)
				}
				if code := mustCode(t, resp); code != want {
					t.Errorf("STAN %s: code %s, want %s", stan, code, want)
				}
			}
			if err := c.Echo(context.Background()); err != nil {
				t.Errorf("Echo: %v", err)
			}
			cancel()
			if code := <-done; code != 0 {
				t.Errorf("exit code %d: %s", code, errOut.String())
			}
			log := out.String()
			if !strings.Contains(log, "listening") || !strings.Contains(log, "411111******1111") || strings.Contains(log, "4111111111111111") {
				t.Errorf("log does not show masked traffic:\n%s", log)
			}
		})
	}
}

func TestMainErrors(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		args []string
		code int
	}{
		{[]string{"-h"}, 0},
		{[]string{"-nope"}, 2},
		{[]string{"extra"}, 2},
		{[]string{"-spec", "visa"}, 2},
		{[]string{"-framing", "ebcdic"}, 2},
		{[]string{"-tpdu", "60"}, 2},
		{[]string{"-addr", "256.0.0.1:1"}, 1},
		{[]string{"-spec", "sim_test.go"}, 2},
	} {
		if got := Main(ctx, tt.args, io.Discard, io.Discard); got != tt.code {
			t.Errorf("Main(%v) = %d, want %d", tt.args, got, tt.code)
		}
	}
}
