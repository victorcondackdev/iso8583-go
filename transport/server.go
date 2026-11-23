package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// ErrServerClosed is returned by [Server.Serve] after [Server.Shutdown].
var ErrServerClosed = errors.New("transport: server closed")

// Server accepts connections and serves the requests arriving on each with
// Config.Handler. Every accepted connection is a [Conn] configured with
// Config, so the server side gets the same framing, TPDU handling, echo
// replies and request matching (a Handler may itself call Send on the
// peer's Conn, which it can obtain with [ConnFromContext]).
type Server struct {
	Config Config

	mu      sync.Mutex
	ln      net.Listener
	conns   map[*Conn]struct{}
	closing bool
}

type connKey struct{}

// ConnFromContext returns the Conn a Handler is serving, from the context
// passed to ServeISO8583.
func ConnFromContext(ctx context.Context) (*Conn, bool) {
	c, ok := ctx.Value(connKey{}).(*Conn)
	return c, ok
}

// ListenAndServe listens on the TCP address addr and calls Serve.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve accepts connections on ln until Shutdown or a non-temporary accept
// error. It always returns a non-nil error; after Shutdown it is
// [ErrServerClosed].
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		_ = ln.Close()
		return ErrServerClosed
	}
	s.ln = ln
	if s.conns == nil {
		s.conns = make(map[*Conn]struct{})
	}
	s.mu.Unlock()

	var delay time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing {
				return ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		c := newConn(nc, s.Config, true)
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			_ = c.Close()
			continue
		}
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		go func() {
			<-c.Done()
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
		}()
	}
}

// Addr returns the listener's address, or nil before Serve.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Shutdown stops accepting connections, then shuts every connection down
// gracefully (see [Conn.Shutdown]) and waits for them, or for ctx.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	if s.ln != nil {
		_ = s.ln.Close()
	}
	conns := make([]*Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	var wg sync.WaitGroup
	errs := make([]error, len(conns))
	for i, c := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = c.Shutdown(ctx)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}
