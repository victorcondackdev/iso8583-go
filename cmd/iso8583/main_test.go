package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/victorcondackdev/iso8583-go/internal/sim"
	"github.com/victorcondackdev/iso8583-go/transport"
)

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestEncodeDecode(t *testing.T) {
	code, out, errOut := runCLI(t, "", "encode", "../../examples/acme-spec.json", "../../examples/acme-purchase.json")
	if code != 0 {
		t.Fatalf("encode = %d: %s", code, errOut)
	}
	hexMsg := strings.TrimSpace(out)
	raw, err := hex.DecodeString(hexMsg)
	if err != nil || !bytes.HasPrefix(raw, []byte("0200723C")) {
		t.Fatalf("encode output %q", out)
	}

	code, out, errOut = runCLI(t, "", "decode", "--spec", "../../examples/acme-spec.json", hexMsg)
	if code != 0 {
		t.Fatalf("decode = %d: %s", code, errOut)
	}
	for _, want := range []string{"411111******1111", "F48.2    n 3        CVV2                                         ***", "9F02 Amount, Authorised"} {
		if !strings.Contains(out, want) {
			t.Errorf("decode output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "4111111111111111") {
		t.Error("decode output shows the clear PAN")
	}

	// From a file holding raw bytes, from stdin as hex, as JSON, split hex.
	dir := t.TempDir()
	bin := filepath.Join(dir, "msg.bin")
	code, _, errOut = runCLI(t, "", "encode", "--out", bin, "../../examples/acme-spec.json", "../../examples/acme-purchase.json")
	if code != 0 || !strings.Contains(errOut, "wrote") {
		t.Fatalf("encode --out = %d: %s", code, errOut)
	}
	if code, _, errOut := runCLI(t, "", "decode", "--spec", "../../examples/acme-spec.json", bin); code != 0 {
		t.Errorf("decode file = %d: %s", code, errOut)
	}
	if code, _, errOut := runCLI(t, hexMsg+"\n", "decode", "--spec", "../../examples/acme-spec.json", "-"); code != 0 {
		t.Errorf("decode stdin = %d: %s", code, errOut)
	}
	code, out, _ = runCLI(t, hexMsg, "decode", "--json", "--spec", "../../examples/acme-spec.json")
	if code != 0 || !strings.HasPrefix(out, `{"mti":"0200","fields":{"2":"411111******1111"`) {
		t.Errorf("decode --json = %d %s", code, out)
	}
	if code, _, errOut := runCLI(t, "", "decode", "--spec", "../../examples/acme-spec.json", hexMsg[:20], hexMsg[20:]); code != 0 {
		t.Errorf("decode split hex = %d: %s", code, errOut)
	}
}

func TestDecodeOptions(t *testing.T) {
	msg := "0200" + "2000000000000000" + "000000"
	framed := "\x00\x1A" + msg
	if code, out, errOut := runCLI(t, "", "decode", "--raw", "--skip", "2", framed); code != 0 || !strings.Contains(out, "Processing code") {
		t.Errorf("decode --raw --skip = %d %s %s", code, out, errOut)
	}
	bad := "0200" + "2000000000000000" + "00A000"
	code, _, errOut := runCLI(t, "", "decode", "--raw", bad)
	if code != 1 || !strings.Contains(errOut, "field 3 at offset 20") || !strings.Contains(errOut, "^") {
		t.Errorf("decode bad = %d %s", code, errOut)
	}
	if code, _, _ := runCLI(t, "", "decode", "--raw", "--lenient", bad); code != 0 {
		t.Errorf("decode --lenient = %d", code)
	}
	if code, _, errOut := runCLI(t, "", "decode", "zz"); code != 1 || !strings.Contains(errOut, "--raw") {
		t.Errorf("decode zz = %d %s", code, errOut)
	}
	if code, _, _ := runCLI(t, "", "decode", "--skip", "99", "00"); code != 1 {
		t.Errorf("decode --skip 99 = %d", code)
	}
	if code, _, _ := runCLI(t, "", "decode", "--spec", "visa", "00"); code != 1 {
		t.Errorf("decode --spec visa = %d", code)
	}
	if code, _, _ := runCLI(t, "", "decode", "--nope"); code != 2 {
		t.Errorf("decode --nope = %d", code)
	}
	if code, _, _ := runCLI(t, "", "decode", "-h"); code != 0 {
		t.Errorf("decode -h = %d", code)
	}
	// Binary spec, file with hex text and whitespace.
	dir := t.TempDir()
	p := filepath.Join(dir, "msg.hex")
	if err := os.WriteFile(p, []byte("0200 2000000000000000\n000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runCLI(t, "", "decode", "--spec", "iso87binary", p); code != 0 || !strings.Contains(out, "Processing code") {
		t.Errorf("decode binary = %d %s %s", code, out, errOut)
	}
	if got := maybeHex([]byte("abc"), false); string(got) != "abc" {
		t.Errorf("maybeHex(odd) = %q", got)
	}
	if got := maybeHex([]byte("zz"), false); string(got) != "zz" {
		t.Errorf("maybeHex(zz) = %q", got)
	}
}

func TestEncodeErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"mti":"0200","fields":{"3":"1234567"}}`), 0o600)
	noMTI := filepath.Join(dir, "nomti.json")
	os.WriteFile(noMTI, []byte(`{"fields":{"3":"000000"}}`), 0o600)
	for _, tt := range []struct {
		args []string
		code int
	}{
		{[]string{"encode"}, 2},
		{[]string{"encode", "--nope"}, 2},
		{[]string{"encode", "visa", bad}, 1},
		{[]string{"encode", "iso87ascii", "missing.json"}, 1},
		{[]string{"encode", "iso87ascii", bad}, 1},
		{[]string{"encode", "iso87ascii", noMTI}, 1},
		{[]string{"encode", "--out", filepath.Join(dir, "no", "such", "dir"), "iso87ascii", "../../examples/purchase.json"}, 1},
	} {
		if code, _, errOut := runCLI(t, "", tt.args...); code != tt.code {
			t.Errorf("%v = %d, want %d: %s", tt.args, code, tt.code, errOut)
		}
	}
}

func TestSend(t *testing.T) {
	cfg, err := sim.Config("iso87ascii", "binary2", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Handler = &sim.Issuer{Rules: sim.Rules{AmountLimit: 2000}}
	srv := &transport.Server{Config: cfg}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())
	addr := ln.Addr().String()

	code, out, errOut := runCLI(t, "", "send", "--addr", addr, "../../examples/purchase.json")
	if code != 0 {
		t.Fatalf("send = %d: %s", code, errOut)
	}
	// 25.00 is above the 20.00 limit.
	if !strings.Contains(out, "0210 Financial response") || !strings.Contains(out, "Response code                                51") {
		t.Errorf("send output:\n%s", out)
	}
	for _, tt := range []struct {
		args []string
		code int
	}{
		{[]string{"send"}, 2},
		{[]string{"send", "--nope"}, 2},
		{[]string{"send", "--framing", "x", "../../examples/purchase.json"}, 1},
		{[]string{"send", "--addr", addr, "missing.json"}, 1},
		{[]string{"send", "--addr", "127.0.0.1:1", "../../examples/purchase.json"}, 1},
		{[]string{"send", "--addr", addr, "--framing", "ascii4", "--timeout", "100ms", "../../examples/purchase.json"}, 1},
	} {
		start := time.Now()
		if code, _, errOut := runCLI(t, "", tt.args...); code != tt.code {
			t.Errorf("%v = %d, want %d: %s", tt.args, code, tt.code, errOut)
		}
		if time.Since(start) > 5*time.Second {
			t.Errorf("%v took too long", tt.args)
		}
	}
}

func TestMisc(t *testing.T) {
	if code, out, _ := runCLI(t, "", "version"); code != 0 || !strings.HasPrefix(out, "iso8583 ") {
		t.Errorf("version = %d %q", code, out)
	}
	if code, out, _ := runCLI(t, "", "help"); code != 0 || !strings.Contains(out, "Usage:") {
		t.Errorf("help = %d", code)
	}
	if code, _, _ := runCLI(t, ""); code != 2 {
		t.Errorf("no args = %d", code)
	}
	if code, _, _ := runCLI(t, "", "frobnicate"); code != 2 {
		t.Errorf("unknown = %d", code)
	}
	code, out, _ := runCLI(t, "", "spec", "iso87binary")
	if code != 0 || !strings.Contains(out, `"mtiEncoding": "bcd"`) {
		t.Errorf("spec = %d", code)
	}
	if code, _, _ := runCLI(t, "", "spec"); code != 2 {
		t.Errorf("spec without name = %d", code)
	}
	if code, _, _ := runCLI(t, "", "spec", "visa"); code != 1 {
		t.Errorf("spec visa = %d", code)
	}
	if code, _, _ := runCLI(t, "", "sim", "-h"); code != 0 {
		t.Errorf("sim -h = %d", code)
	}
}
