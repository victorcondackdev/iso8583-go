package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	iso8583 "github.com/victorcondackdev/iso8583-go"
	"github.com/victorcondackdev/iso8583-go/spec"
)

// Errors returned by [Conn].
var (
	// ErrClosed reports an operation on a closed or shutting-down Conn.
	ErrClosed = errors.New("transport: connection closed")
	// ErrTimeout reports a request that got no response in time. The error
	// also matches context.DeadlineExceeded.
	ErrTimeout = errors.New("transport: response timeout")
	// ErrNoTrace reports a request without a STAN (field 11), which cannot
	// be matched to its response.
	ErrNoTrace = errors.New("transport: request has no STAN (field 11)")
	// ErrDuplicate reports a request whose MTI and STAN equal those of a
	// request still waiting for its response.
	ErrDuplicate = errors.New("transport: duplicate in-flight STAN")
	// ErrEcho reports a keep-alive echo test that failed; the Conn is
	// closed with this error.
	ErrEcho = errors.New("transport: echo test failed")
)

// Handler serves requests that arrive on a Conn: authorizations, financial
// requests, reversals, network management from the peer. The returned
// message, if not nil, is sent back; a nil message sends nothing (useful
// for notifications). ctx is canceled when the connection closes.
type Handler interface {
	ServeISO8583(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error)
}

// HandlerFunc adapts a function to [Handler].
type HandlerFunc func(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error)

// ServeISO8583 calls f.
func (f HandlerFunc) ServeISO8583(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error) {
	return f(ctx, req)
}

// Config configures a [Conn] or a [Server].
type Config struct {
	// Spec is the message layout. Required.
	Spec *spec.Spec
	// Mode is the validation mode used to unpack incoming messages.
	Mode iso8583.Mode
	// Framing is the length header. The zero value is Binary2.
	Framing Framing
	// TPDU, when set, is written before every request this side originates,
	// and a 5-byte TPDU is expected (and stripped) on every incoming
	// message. Responses reuse the request's TPDU with the addresses
	// swapped.
	TPDU *TPDU
	// Timeout bounds the wait for a response when the context passed to
	// Send has no deadline, and every socket write. Zero means 30 seconds.
	Timeout time.Duration
	// EchoInterval, when positive, sends an 0800 echo test (field 70 = 301)
	// after this much read inactivity. If the echo fails the connection is
	// closed with [ErrEcho].
	EchoInterval time.Duration
	// DisableAutoEcho stops the Conn from answering 0800 echo tests itself;
	// they are passed to Handler instead.
	DisableAutoEcho bool
	// Handler serves incoming requests. When nil, requests other than echo
	// tests are logged and dropped.
	Handler Handler
	// STAN generates trace numbers for echo tests. When nil, a per-Conn
	// generator is used.
	STAN *iso8583.STAN
	// Logger receives connection events and masked message summaries. When
	// nil, nothing is logged.
	Logger *slog.Logger
}

func (c Config) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 30 * time.Second
	}
	return c.Timeout
}

type pending struct {
	ch  chan *iso8583.Message
	rrn string
}

// Conn is an ISO 8583 connection. Any number of goroutines may call
// [Conn.Send] concurrently; responses are matched to requests by MTI,
// STAN and, when both sides carry it, RRN, regardless of the order in
// which they arrive.
type Conn struct {
	nc     net.Conn
	cfg    Config
	log    *slog.Logger
	stan   *iso8583.STAN
	ctx    context.Context
	cancel context.CancelFunc

	wmu sync.Mutex // serialises frame writes

	mu      sync.Mutex
	pending map[string]*pending
	closing bool
	active  sync.WaitGroup // in-flight Sends and handlers

	closeOnce sync.Once
	closed    chan struct{}
	err       error

	lastRead atomic.Int64 // unix nanoseconds
}

// NewConn wraps an established connection and starts reading from it. The
// Conn owns nc from now on.
func NewConn(nc net.Conn, cfg Config) *Conn { return newConn(nc, cfg, false) }

// newConn builds a Conn; server Conns are reachable from handler contexts
// through ConnFromContext.
func newConn(nc net.Conn, cfg Config, server bool) *Conn {
	c := &Conn{
		nc:      nc,
		cfg:     cfg,
		log:     cfg.Logger,
		stan:    cfg.STAN,
		pending: make(map[string]*pending),
		closed:  make(chan struct{}),
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if c.stan == nil {
		c.stan = new(iso8583.STAN)
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	if server {
		c.ctx = context.WithValue(c.ctx, connKey{}, c)
	}
	c.lastRead.Store(time.Now().UnixNano())
	go c.readLoop()
	if cfg.EchoInterval > 0 {
		go c.echoLoop()
	}
	return c
}

// Dial connects to addr over TCP and returns a Conn.
func Dial(ctx context.Context, addr string, cfg Config) (*Conn, error) {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return NewConn(nc, cfg), nil
}

// RemoteAddr returns the peer's address.
func (c *Conn) RemoteAddr() net.Addr { return c.nc.RemoteAddr() }

// Done is closed when the connection is closed.
func (c *Conn) Done() <-chan struct{} { return c.closed }

// Err returns why the connection closed: [ErrClosed] after Close or
// Shutdown, the read error (often io.EOF) when the peer went away, or nil
// while it is open.
func (c *Conn) Err() error {
	select {
	case <-c.closed:
		return c.err
	default:
		return nil
	}
}

// matchKey identifies a request/response pair: the request MTI and the
// STAN.
func matchKey(m *iso8583.Message) (key, rrn string, err error) {
	mti := m.MTI()
	if iso8583.IsResponse(mti) {
		if mti, err = iso8583.RequestMTI(mti); err != nil {
			return "", "", err
		}
	}
	stan, err := m.GetString(11)
	if err != nil {
		return "", "", ErrNoTrace
	}
	rrn, _ = m.GetString(37)
	return mti + "/" + stan, rrn, nil
}

// Send writes a request (or advice) and waits for its response. The wait
// ends at ctx's deadline or, if ctx has none, after Config.Timeout; on
// timeout the error matches both [ErrTimeout] and context.DeadlineExceeded,
// and a late response is discarded. The request must carry field 11.
func (c *Conn) Send(ctx context.Context, req *iso8583.Message) (*iso8583.Message, error) {
	if iso8583.IsResponse(req.MTI()) {
		return nil, fmt.Errorf("transport: Send of response MTI %s; use Write", req.MTI())
	}
	key, rrn, err := matchKey(req)
	if err != nil {
		return nil, err
	}
	p := &pending{ch: make(chan *iso8583.Message, 1), rrn: rrn}

	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	if _, dup := c.pending[key]; dup {
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrDuplicate, key)
	}
	c.pending[key] = p
	c.active.Add(1)
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, key)
		c.mu.Unlock()
		c.active.Done()
	}()

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.cfg.timeout())
		defer cancel()
	}
	if err := c.write(req, c.cfg.TPDU); err != nil {
		return nil, err
	}
	select {
	case resp := <-p.ch:
		return resp, nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w for %s (%w)", ErrTimeout, key, ctx.Err())
		}
		return nil, ctx.Err()
	case <-c.closed:
		return nil, c.err
	}
}

// Write sends a message without waiting for a response: responses produced
// outside a Handler, or notifications.
func (c *Conn) Write(m *iso8583.Message) error { return c.write(m, c.cfg.TPDU) }

func (c *Conn) write(m *iso8583.Message, tpdu *TPDU) error {
	select {
	case <-c.closed:
		return c.err
	default:
	}
	hl := c.cfg.Framing.HeaderLen()
	buf := make([]byte, hl, 512)
	if tpdu != nil {
		buf = append(buf, tpdu[:]...)
	}
	buf, err := m.AppendPack(buf)
	if err != nil {
		return err
	}
	if err := c.cfg.Framing.putHeader(buf[:hl], len(buf)-hl); err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.nc.SetWriteDeadline(time.Now().Add(c.cfg.timeout()))
	if _, err := c.nc.Write(buf); err != nil {
		c.closeWith(err)
		return err
	}
	c.log.Debug("iso8583 sent", "remote", c.nc.RemoteAddr().String(), "msg", m.String())
	return nil
}

func (c *Conn) readLoop() {
	br := bufio.NewReader(c.nc)
	for {
		frame, err := c.cfg.Framing.ReadFrame(br)
		if err != nil {
			c.closeWith(err)
			return
		}
		c.lastRead.Store(time.Now().UnixNano())
		if len(frame) == 0 {
			continue
		}
		var tpdu *TPDU
		if c.cfg.TPDU != nil {
			if len(frame) < len(TPDU{}) {
				c.log.Warn("iso8583 frame shorter than its TPDU", "remote", c.nc.RemoteAddr().String(), "len", len(frame))
				continue
			}
			t := TPDU(frame[:5])
			tpdu = &t
			frame = frame[5:]
		}
		m := iso8583.NewMessage(c.cfg.Spec, iso8583.WithMode(c.cfg.Mode))
		if err := m.Unpack(frame); err != nil {
			c.log.Warn("iso8583 unpack failed", "remote", c.nc.RemoteAddr().String(), "err", err)
			continue
		}
		c.log.Debug("iso8583 received", "remote", c.nc.RemoteAddr().String(), "msg", m.String())
		if iso8583.IsResponse(m.MTI()) {
			c.deliver(m)
		} else {
			c.dispatch(m, tpdu)
		}
	}
}

// deliver hands a response to the Send waiting for it.
func (c *Conn) deliver(m *iso8583.Message) {
	key, rrn, err := matchKey(m)
	if err != nil {
		c.log.Warn("iso8583 response without STAN", "msg", m.String())
		return
	}
	c.mu.Lock()
	p := c.pending[key]
	if p != nil && p.rrn != "" && rrn != "" && p.rrn != rrn {
		p = nil
	}
	if p != nil {
		delete(c.pending, key) // a duplicate response must not be delivered twice
	}
	c.mu.Unlock()
	if p == nil {
		c.log.Warn("iso8583 unsolicited or late response", "key", key, "msg", m.String())
		return
	}
	p.ch <- m
}

// isEcho reports whether m is an 0800 echo test (field 70 = 301).
func isEcho(m *iso8583.Message) bool {
	if m.MTI()[1:3] != "80" {
		return false
	}
	code, err := m.GetString(70)
	return err == nil && code == "301"
}

// dispatch serves an incoming request.
func (c *Conn) dispatch(req *iso8583.Message, tpdu *TPDU) {
	var reply *TPDU
	if tpdu != nil {
		s := tpdu.Swap()
		reply = &s
	}
	if !c.cfg.DisableAutoEcho && isEcho(req) {
		resp, err := iso8583.NewResponse(req)
		if err == nil {
			_ = resp.SetString(70, "301")
			err = resp.SetString(39, "00")
		}
		if err == nil {
			err = c.write(resp, reply)
		}
		if err != nil {
			c.log.Warn("iso8583 echo reply failed", "err", err)
		}
		return
	}
	if c.cfg.Handler == nil {
		c.log.Warn("iso8583 request dropped: no handler", "msg", req.String())
		return
	}
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		c.log.Warn("iso8583 request dropped: shutting down", "msg", req.String())
		return
	}
	c.active.Add(1)
	c.mu.Unlock()
	go func() {
		defer c.active.Done()
		resp, err := c.cfg.Handler.ServeISO8583(c.ctx, req)
		if err != nil {
			c.log.Error("iso8583 handler failed", "msg", req.String(), "err", err)
		}
		if resp == nil {
			return
		}
		if err := c.write(resp, reply); err != nil {
			c.log.Warn("iso8583 response write failed", "msg", resp.String(), "err", err)
		}
	}()
}

// echoLoop sends echo tests after read inactivity.
func (c *Conn) echoLoop() {
	t := time.NewTicker(c.cfg.EchoInterval / 2)
	defer t.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
		}
		idle := time.Since(time.Unix(0, c.lastRead.Load()))
		if idle < c.cfg.EchoInterval {
			continue
		}
		if err := c.Echo(c.ctx); err != nil {
			if errors.Is(err, ErrClosed) {
				return
			}
			c.log.Warn("iso8583 echo failed, closing", "remote", c.nc.RemoteAddr().String(), "err", err)
			c.closeWith(fmt.Errorf("%w: %w", ErrEcho, err))
			return
		}
	}
}

// Echo sends an 0800 echo test (fields 7, 11 and 70 = 301) and waits for
// the 0810. It returns an error if the response code (field 39) is present
// and not 00.
func (c *Conn) Echo(ctx context.Context) error {
	m := iso8583.NewMessage(c.cfg.Spec)
	err := errors.Join(
		m.SetMTI("0800"),
		m.SetString(7, iso8583.TransmissionDateTime(time.Now())),
		m.SetString(11, c.stan.Next()),
		m.SetString(70, "301"),
	)
	if err != nil {
		return err
	}
	resp, err := c.Send(ctx, m)
	if err != nil {
		return err
	}
	if rc, err := resp.GetString(39); err == nil && rc != "00" {
		return fmt.Errorf("transport: echo answered with response code %s", rc)
	}
	return nil
}

// Close closes the connection immediately. Waiting Sends return
// [ErrClosed].
func (c *Conn) Close() error {
	c.mu.Lock()
	c.closing = true
	c.mu.Unlock()
	c.closeWith(ErrClosed)
	return nil
}

func (c *Conn) closeWith(err error) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closing = true
		c.mu.Unlock()
		c.err = err
		if !errors.Is(err, ErrClosed) {
			c.log.Info("iso8583 connection closed", "remote", c.nc.RemoteAddr().String(), "err", err)
		}
		c.cancel()
		close(c.closed)
		_ = c.nc.Close()
	})
}

// Shutdown stops new Sends and incoming requests, waits for in-flight
// Sends to get their responses and handlers to finish, then closes the
// connection. If ctx ends first, the connection is closed anyway and
// ctx.Err() is returned.
func (c *Conn) Shutdown(ctx context.Context) error {
	c.mu.Lock()
	c.closing = true
	c.mu.Unlock()
	idle := make(chan struct{})
	go func() {
		c.active.Wait()
		close(idle)
	}()
	var err error
	select {
	case <-idle:
	case <-c.closed:
	case <-ctx.Done():
		err = ctx.Err()
	}
	c.closeWith(ErrClosed)
	return err
}
