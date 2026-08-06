package proxy

import (
	"net"
	"time"
)

// Connection-limit defaults. They bound the blast radius of one tenant on the
// shared proxy: idle tunnels are reaped, and no single client IP (nor the proxy
// as a whole) can pin an unbounded number of goroutines/FDs (NL-REQ-02).
const (
	// defaultIdleTimeout reaps a connection that neither sends nor receives any
	// bytes for this long — killing Slowloris dribblers and CONNECT-then-idle
	// tunnels. It is an IDLE timeout (reset on every read/write), so legitimate
	// long downloads that keep making progress are unaffected.
	defaultIdleTimeout = 120 * time.Second

	// defaultMaxConns caps total concurrent connections (a backstop against
	// global FD/goroutine exhaustion).
	defaultMaxConns = 4096

	// defaultMaxConnsPerIP caps concurrent connections from a single client IP,
	// so one sandbox cannot consume the shared proxy's capacity and deny service
	// to its co-tenants.
	defaultMaxConnsPerIP = 256
)

// idleConn applies an idle timeout to a net.Conn: every read and write pushes
// the corresponding deadline forward by idle, so a connection that stalls for
// longer than idle fails its next operation and is torn down. A value of 0
// disables the timeout.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Write(b)
}

// CloseWrite forwards a write-half shutdown to the wrapped connection when it
// supports one (e.g. *net.TCPConn), so a spliced tunnel can signal EOF to one
// peer without fully closing the connection. A no-op otherwise.
func (c *idleConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// acquireConn admits a freshly accepted connection under the global and per-IP
// concurrency caps. It returns false (and the caller must drop the connection)
// when either cap is already reached. releaseConn must be called for every
// acquireConn that returns true.
func (s *Server) acquireConn(remoteIP string) bool {
	// Global cap first (cheap, non-blocking).
	if s.sem != nil {
		select {
		case s.sem <- struct{}{}:
		default:
			s.log.Warn("proxy: global connection cap reached; dropping connection", "cap", s.maxConns)
			return false
		}
	}

	if s.maxConnsPerIP > 0 && remoteIP != "" {
		s.ipConnMu.Lock()
		if s.ipConns[remoteIP] >= s.maxConnsPerIP {
			s.ipConnMu.Unlock()
			if s.sem != nil {
				<-s.sem
			}
			s.log.Warn("proxy: per-client connection cap reached; dropping connection", "remote", remoteIP, "cap", s.maxConnsPerIP)
			return false
		}
		s.ipConns[remoteIP]++
		s.ipConnMu.Unlock()
	}
	return true
}

// releaseConn returns the slots taken by a successful acquireConn.
func (s *Server) releaseConn(remoteIP string) {
	if s.maxConnsPerIP > 0 && remoteIP != "" {
		s.ipConnMu.Lock()
		if n := s.ipConns[remoteIP]; n <= 1 {
			delete(s.ipConns, remoteIP)
		} else {
			s.ipConns[remoteIP] = n - 1
		}
		s.ipConnMu.Unlock()
	}
	if s.sem != nil {
		<-s.sem
	}
}
