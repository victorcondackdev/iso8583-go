package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iso8583 "github.com/victorcondackdev/iso8583-go"
	"github.com/victorcondackdev/iso8583-go/spec"
)

var testSpec = spec.ISO87ASCII()

func TestFramingVectors(t *testing.T) {
	payload := bytes.Repeat([]byte{'x'}, 300)
	for _, tt := range []struct {
		f    Framing
		want []byte
	}{
		{Binary2, []byte{0x01, 0x2C}}, // 300 = 0x012C
		{ASCII4, []byte("0300")},
	} {
		var buf bytes.Buffer
		if err := tt.f.WriteFrame(&buf, payload); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf.Bytes()[:tt.f.HeaderLen()], tt.want) {
			t.Errorf("%s header = % X, want % X", tt.f, buf.Bytes()[:tt.f.HeaderLen()], tt.want)
		}
		got, err := tt.f.ReadFrame(&buf)
		if err != nil || !bytes.Equal(got, payload) {
			t.Errorf("%s ReadFrame = %d bytes, %v", tt.f, len(got), err)
		}
	}
	if err := ASCII4.WriteFrame(io.Discard, make([]byte, 10000)); !errors.Is(err, ErrFrame) {
		t.Errorf("oversized ASCII4 frame: %v", err)
	}
	if err := Binary2.WriteFrame(io.Discard, make([]byte, 70000)); !errors.Is(err, ErrFrame) {
		t.Errorf("oversized Binary2 frame: %v", err)
	}
	if _, err := ASCII4.ReadFrame(strings.NewReader("00x1abc")); !errors.Is(err, ErrFrame) {
		t.Errorf("non-numeric header: %v", err)
	}
	if _, err := Binary2.ReadFrame(bytes.NewReader([]byte{0})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("short header: %v", err)
	}
	if _, err := Binary2.ReadFrame(bytes.NewReader([]byte{0, 5, 1})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("short payload: %v", err)
	}
	if _, err := Binary2.ReadFrame(bytes.NewReader([]byte{0, 5})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("missing payload: %v", err)
	}
	if got, err := Binary2.ReadFrame(bytes.NewReader([]byte{0, 0})); err != nil || len(got) != 0 {
		t.Errorf("empty frame = %v, %v", got, err)
	}
	for in, want := range map[string]Framing{"binary2": Binary2, "ASCII4": ASCII4, "ascii": ASCII4, "2": Binary2} {
		if got, err := ParseFraming(in); err != nil || got != want {
			t.Errorf("ParseFraming(%s) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseFraming("ebcdic"); err == nil {
		t.Error("ParseFraming(ebcdic) succeeded")
	}
	if Framing(9).String() != "Framing(9)" || Binary2.MaxLen() != 65535 || ASCII4.MaxLen() != 9999 {
		t.Error("Framing helpers")
	}
}

func TestTPDU(t *testing.T) {
	tp, err := ParseTPDU("6000010002")
	if err != nil {
		t.Fatal(err)
	}
	if got := tp.Swap().String(); got != "6000020001" {
		t.Errorf("Swap = %s", got)
	}
	for _, bad := range []string{"60", "zz00010002", "600001000200"} {
		if _, err := ParseTPDU(bad); err == nil {
			t.Errorf("ParseTPDU(%s) succeeded", bad)
		}
	}
}

// approve is a handler that answers every request with 00, after an
// optional random delay, and echoes the STAN in field 38 so tests can check
// the pairing independently of field 11.
func approve(maxDelay time.Duration) Handler {
	return HandlerFunc(func(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error) {
		if maxDelay > 0 {
			time.Sleep(time.Duration(rand.Int64N(int64(maxDelay))))
		}
		resp, err := iso8583.NewResponse(req)
		if err != nil {
			return nil, err
		}
		stan, _ := req.GetString(11)
		_ = resp.SetString(38, "A"+stan[1:])
		return resp, resp.SetString(39, "00")
	})
}

func pipe(t *testing.T, client, server Config) (*Conn, *Conn) {
	t.Helper()
	a, b := net.Pipe()
	if client.Spec == nil {
		client.Spec = testSpec
	}
	if server.Spec == nil {
		server.Spec = testSpec
	}
	cc, sc := NewConn(a, client), newConn(b, server, true)
	t.Cleanup(func() {
		cc.Close()
		sc.Close()
	})
	return cc, sc
}

func request(t testing.TB, mti, stan string) *iso8583.Message {
	m := iso8583.NewMessage(testSpec)
	if err := errors.Join(m.SetMTI(mti), m.SetString(11, stan), m.SetAmount(4, 100)); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestConcurrentMatching(t *testing.T) {
	client, _ := pipe(t, Config{Timeout: 5 * time.Second}, Config{Handler: approve(5 * time.Millisecond)})
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for i := 1; i <= 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stan := fmt.Sprintf("%06d", i)
			mti := []string{"0100", "0200"}[i%2]
			resp, err := client.Send(context.Background(), request(t, mti, stan))
			if err != nil {
				errs <- err
				return
			}
			got, _ := resp.GetString(11)
			auth, _ := resp.GetString(38)
			if got != stan || auth != "A"+stan[1:] || resp.MTI()[2] != '1' || resp.MTI()[1] != mti[1] {
				errs <- fmt.Errorf("request %s %s got %s %s %s", mti, stan, resp.MTI(), got, auth)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestSameSTANDifferentMTI(t *testing.T) {
	// 0100/000001 and 0200/000001 can be in flight together.
	client, _ := pipe(t, Config{}, Config{Handler: approve(10 * time.Millisecond)})
	var wg sync.WaitGroup
	for _, mti := range []string{"0100", "0200", "0400"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Send(context.Background(), request(t, mti, "000001"))
			if err != nil {
				t.Error(err)
				return
			}
			if want, _ := iso8583.ResponseMTI(mti); resp.MTI() != want {
				t.Errorf("%s answered by %s", mti, resp.MTI())
			}
		}()
	}
	wg.Wait()
}

func TestTimeout(t *testing.T) {
	slow := HandlerFunc(func(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error) {
		time.Sleep(150 * time.Millisecond)
		return approve(0).ServeISO8583(ctx, req)
	})
	client, _ := pipe(t, Config{Timeout: 30 * time.Millisecond}, Config{Handler: slow})
	start := time.Now()
	_, err := client.Send(context.Background(), request(t, "0200", "000001"))
	if !errors.Is(err, ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send = %v", err)
	}
	if d := time.Since(start); d > 140*time.Millisecond {
		t.Errorf("timeout took %v", d)
	}
	// The late response is discarded and the connection stays usable.
	time.Sleep(200 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.Send(ctx, request(t, "0200", "000002")); err != nil {
		t.Fatalf("Send after timeout: %v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err := client.Send(ctx, request(t, "0200", "000003")); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled Send = %v", err)
	}
}

func TestSendErrors(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	hold := HandlerFunc(func(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error) {
		<-block
		return nil, nil
	})
	client, _ := pipe(t, Config{Timeout: time.Second}, Config{Handler: hold})
	noTrace := iso8583.NewMessage(testSpec)
	_ = noTrace.SetMTI("0200")
	if _, err := client.Send(context.Background(), noTrace); !errors.Is(err, ErrNoTrace) {
		t.Errorf("Send without STAN = %v", err)
	}
	if _, err := client.Send(context.Background(), request(t, "0210", "000001")); err == nil {
		t.Error("Send of a response succeeded")
	}
	go client.Send(context.Background(), request(t, "0200", "000009"))
	time.Sleep(20 * time.Millisecond)
	if _, err := client.Send(context.Background(), request(t, "0200", "000009")); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate Send = %v", err)
	}
	bad := iso8583.NewMessage(testSpec)
	_ = bad.SetString(11, "000010")
	if err := client.Write(bad); err == nil {
		t.Error("Write of a message without MTI succeeded")
	}
}

func TestAutoEcho(t *testing.T) {
	client, _ := pipe(t, Config{}, Config{})
	if err := client.Echo(context.Background()); err != nil {
		t.Fatalf("Echo = %v", err)
	}
	// With auto echo disabled and no handler, nobody answers.
	client, _ = pipe(t, Config{Timeout: 30 * time.Millisecond}, Config{DisableAutoEcho: true})
	if err := client.Echo(context.Background()); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Echo = %v", err)
	}
	// A declined echo is reported.
	decline := HandlerFunc(func(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error) {
		resp, _ := iso8583.NewResponse(req)
		return resp, resp.SetString(39, "91")
	})
	client, _ = pipe(t, Config{}, Config{DisableAutoEcho: true, Handler: decline})
	if err := client.Echo(context.Background()); err == nil || !strings.Contains(err.Error(), "91") {
		t.Fatalf("Echo = %v", err)
	}
	// Specs without fields 7, 11 or 70 cannot echo.
	s := spec.ISO87ASCII().Clone()
	delete(s.Fields, 70)
	client, _ = pipe(t, Config{Spec: s}, Config{})
	if err := client.Echo(context.Background()); err == nil {
		t.Fatal("Echo without field 70 succeeded")
	}
}

func TestKeepAlive(t *testing.T) {
	var echoes atomic.Int32
	count := HandlerFunc(func(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error) {
		if code, _ := req.GetString(70); req.MTI() == "0800" && code == "301" {
			echoes.Add(1)
		}
		return approve(0).ServeISO8583(ctx, req)
	})
	client, _ := pipe(t, Config{EchoInterval: 20 * time.Millisecond}, Config{DisableAutoEcho: true, Handler: count})
	time.Sleep(200 * time.Millisecond)
	if n := echoes.Load(); n < 2 {
		t.Errorf("%d echoes in 200ms with a 20ms interval", n)
	}
	if client.Err() != nil {
		t.Errorf("connection closed: %v", client.Err())
	}
}

func TestEchoFailureCloses(t *testing.T) {
	client, _ := pipe(t, Config{EchoInterval: 20 * time.Millisecond, Timeout: 30 * time.Millisecond},
		Config{DisableAutoEcho: true})
	select {
	case <-client.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("connection not closed after a failed echo")
	}
	if !errors.Is(client.Err(), ErrEcho) {
		t.Errorf("Err = %v", client.Err())
	}
}

func TestShutdownWaitsForInFlight(t *testing.T) {
	slow := HandlerFunc(func(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error) {
		time.Sleep(80 * time.Millisecond)
		return approve(0).ServeISO8583(ctx, req)
	})
	client, _ := pipe(t, Config{}, Config{Handler: slow})
	done := make(chan error, 1)
	go func() {
		_, err := client.Send(context.Background(), request(t, "0200", "000001"))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("in-flight Send = %v", err)
	}
	if _, err := client.Send(context.Background(), request(t, "0200", "000002")); !errors.Is(err, ErrClosed) {
		t.Errorf("Send after Shutdown = %v", err)
	}
	if !errors.Is(client.Err(), ErrClosed) {
		t.Errorf("Err = %v", client.Err())
	}
	if err := client.Write(request(t, "0200", "000003")); !errors.Is(err, ErrClosed) {
		t.Errorf("Write after Shutdown = %v", err)
	}
}

func TestShutdownDeadline(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	hold := HandlerFunc(func(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error) {
		<-block
		return nil, nil
	})
	client, _ := pipe(t, Config{Timeout: 5 * time.Second}, Config{Handler: hold})
	done := make(chan error, 1)
	go func() {
		_, err := client.Send(context.Background(), request(t, "0200", "000001"))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := client.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v", err)
	}
	if err := <-done; !errors.Is(err, ErrClosed) {
		t.Fatalf("in-flight Send = %v", err)
	}
}

func TestPeerClose(t *testing.T) {
	client, server := pipe(t, Config{}, Config{Handler: HandlerFunc(
		func(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error) {
			c, ok := ConnFromContext(ctx)
			if !ok {
				return nil, errors.New("no conn in context")
			}
			return nil, c.Close()
		})})
	_, err := client.Send(context.Background(), request(t, "0200", "000001"))
	if err == nil {
		t.Fatal("Send succeeded on a closed peer")
	}
	<-server.Done()
	<-client.Done()
	if !errors.Is(client.Err(), io.EOF) && !errors.Is(client.Err(), io.ErrClosedPipe) {
		t.Errorf("client Err = %v", client.Err())
	}
	if client.RemoteAddr() == nil {
		t.Error("RemoteAddr")
	}
}

// rawPeer exchanges frames with a Conn by hand.
func rawPeer(t *testing.T, cfg Config) (net.Conn, *Conn) {
	a, b := net.Pipe()
	if cfg.Spec == nil {
		cfg.Spec = testSpec
	}
	c := newConn(b, cfg, true)
	t.Cleanup(func() {
		a.Close()
		c.Close()
	})
	return a, c
}

func packed(t *testing.T, m *iso8583.Message) []byte {
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTPDUOnTheWire(t *testing.T) {
	tp, _ := ParseTPDU("6000030001")
	raw, _ := rawPeer(t, Config{TPDU: &tp, Handler: approve(0)})
	echo := request(t, "0800", "000777")
	_ = echo.SetString(70, "301")
	// Garbage frames are skipped: one shorter than a TPDU, one that does
	// not unpack, one empty keep-alive.
	for _, payload := range [][]byte{{0x60}, append(tp[:], "XXXX"...), {}} {
		if err := Binary2.WriteFrame(raw, payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := Binary2.WriteFrame(raw, append(tp[:], packed(t, echo)...)); err != nil {
		t.Fatal(err)
	}
	frame, err := Binary2.ReadFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := TPDU(frame[:5]).String(); got != "6000010003" {
		t.Errorf("response TPDU = %s, want swapped 6000010003", got)
	}
	resp := iso8583.NewMessage(testSpec)
	if err := resp.Unpack(frame[5:]); err != nil {
		t.Fatal(err)
	}
	if rc, _ := resp.GetString(39); resp.MTI() != "0810" || rc != "00" {
		t.Errorf("echo response %s", resp)
	}

	// A request originated by the Conn carries the configured TPDU.
	raw2, c := rawPeer(t, Config{TPDU: &tp, Framing: ASCII4})
	go c.Write(request(t, "0200", "000001"))
	frame, err = ASCII4.ReadFrame(raw2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(frame, tp[:]) || !bytes.HasPrefix(frame[5:], []byte("0200")) {
		t.Errorf("frame = %q", frame)
	}
}

func TestUnmatchedResponses(t *testing.T) {
	raw, c := rawPeer(t, Config{Timeout: 50 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	req := request(t, "0200", "000001")
	_ = req.SetString(37, "000000000001")
	errc := make(chan error, 1)
	go func() {
		_, err := c.Send(context.Background(), req)
		errc <- err
	}()
	if _, err := Binary2.ReadFrame(raw); err != nil {
		t.Fatal(err)
	}
	// Wrong RRN, then a response without STAN, then one nobody asked for.
	wrong, _ := iso8583.NewResponse(req)
	_ = wrong.SetString(37, "999999999999")
	noSTAN := iso8583.NewMessage(testSpec)
	_ = noSTAN.SetMTI("0210")
	other := request(t, "0110", "123456")
	for _, m := range []*iso8583.Message{wrong, noSTAN, other} {
		if err := Binary2.WriteFrame(raw, packed(t, m)); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-errc; !errors.Is(err, ErrTimeout) {
		t.Fatalf("Send = %v", err)
	}
	// Requests without a handler are dropped.
	if err := Binary2.WriteFrame(raw, packed(t, request(t, "0200", "000002"))); err != nil {
		t.Fatal(err)
	}
}

func TestHandlerErrorsAndNotifications(t *testing.T) {
	var calls atomic.Int32
	h := HandlerFunc(func(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error) {
		calls.Add(1)
		if req.MTI() == "0420" {
			return nil, nil // nothing to send
		}
		return nil, errors.New("boom")
	})
	client, _ := pipe(t, Config{Timeout: 30 * time.Millisecond}, Config{Handler: h})
	if err := client.Write(request(t, "0420", "000001")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send(context.Background(), request(t, "0200", "000002")); !errors.Is(err, ErrTimeout) {
		t.Errorf("Send = %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("handler called %d times", calls.Load())
	}
}

func TestServerTCP(t *testing.T) {
	srv := &Server{Config: Config{Spec: testSpec, Framing: ASCII4, Handler: HandlerFunc(
		func(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error) {
			if _, ok := ConnFromContext(ctx); !ok {
				return nil, errors.New("no conn in context")
			}
			return approve(2*time.Millisecond).ServeISO8583(ctx, req)
		})}}
	if srv.Addr() != nil {
		t.Error("Addr before Serve")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	for srv.Addr() == nil {
		time.Sleep(time.Millisecond)
	}

	var wg sync.WaitGroup
	for c := 0; c < 4; c++ {
		conn, err := Dial(context.Background(), srv.Addr().String(), Config{Spec: testSpec, Framing: ASCII4})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		for i := 0; i < 25; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				stan := fmt.Sprintf("%03d%03d", c, i)
				resp, err := conn.Send(context.Background(), request(t, "0200", stan))
				if err != nil {
					t.Error(err)
					return
				}
				if got, _ := resp.GetString(11); got != stan {
					t.Errorf("STAN %s answered with %s", stan, got)
				}
			}()
		}
	}
	wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if err := <-served; !errors.Is(err, ErrServerClosed) {
		t.Errorf("Serve = %v", err)
	}
	if err := srv.Serve(ln); !errors.Is(err, ErrServerClosed) {
		t.Errorf("Serve after Shutdown = %v", err)
	}
	if _, err := Dial(ctx, "127.0.0.1:1", Config{Spec: testSpec}); err == nil {
		t.Error("Dial to a closed port succeeded")
	}
	if err := (&Server{}).ListenAndServe("256.0.0.1:0"); err == nil {
		t.Error("ListenAndServe on a bad address succeeded")
	}
}

// failListener returns a temporary error once, then a permanent one.
type failListener struct {
	net.Listener
	n int
}

type tempErr struct{}

func (tempErr) Error() string   { return "temporary" }
func (tempErr) Timeout() bool   { return true }
func (tempErr) Temporary() bool { return true }

func (l *failListener) Accept() (net.Conn, error) {
	l.n++
	if l.n == 1 {
		return nil, tempErr{}
	}
	return nil, errors.New("permanent")
}

func TestServeAcceptErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &Server{Config: Config{Spec: testSpec}}
	if err := srv.Serve(&failListener{Listener: ln}); err == nil || err.Error() != "permanent" {
		t.Errorf("Serve = %v", err)
	}
}
