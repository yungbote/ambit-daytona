package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Server is a MITM forward proxy that intercepts HTTPS connections,
// terminates TLS with per-host certs signed by an ephemeral CA,
// and injects real secret values in place of placeholders.
// It also enforces a domain allowlist — requests to non-allowed hosts are rejected.
//
// The policy applied to a connection (allow list + secret injector) is held in a
// Binding. By default every client shares one static binding (per-workload use).
// Set WithBindingResolver to run in shared mode, where the binding is chosen per
// connection from the client's IP — letting a single proxy serve many sandboxes,
// each with its own secrets and allow list.
type Server struct {
	ca              *CA
	static          *Binding              // applied to all clients unless bindingFor is set
	bindingFor      func(net.IP) *Binding // shared mode: resolve binding by client IP (nil → use static)
	allowedClientIP net.IP                // if set, only accept connections from this IP
	authToken       string                // if set, require Proxy-Authorization: Bearer <token>
	addr            string
	listener        net.Listener
	wg              sync.WaitGroup
	log             *slog.Logger

	// Connection limits (NL-REQ-02). idleTimeout reaps stalled/idle connections;
	// maxConns caps total concurrency; maxConnsPerIP caps a single client so one
	// tenant can't exhaust the shared proxy. Zero disables the corresponding cap.
	idleTimeout   time.Duration
	maxConns      int
	maxConnsPerIP int
	sem           chan struct{} // global concurrency cap (nil when maxConns == 0)
	ipConnMu      sync.Mutex
	ipConns       map[string]int // per-client-IP active connection counts

	// Active client connections, tracked so teardown can forcibly terminate them
	// (closing the listener alone leaves established tunnels forwarding/injecting).
	// Close() drops all of them; CloseClient(ip) drops one workload's — used so a
	// sandbox's tunnels stop immediately when its binding is removed (revocation).
	connMu  sync.Mutex
	conns   map[net.Conn]net.IP
	closing bool
}

// NewServer creates a new MITM proxy server.
// allowedDomains is the set of hostnames the proxy will forward to;
// requests to any other host are rejected with 403.
// Entries prefixed with "*." are treated as wildcard suffixes.
// allowedClientIP restricts access to a single client IP (empty = no restriction).
func NewServer(addr string, ca *CA, injector *Injector, allowedDomains []string, allowedClientIP string, opts ...Option) *Server {
	s := &Server{
		ca:            ca,
		static:        newBinding("", false, allowedDomains, injector),
		addr:          addr,
		conns:         make(map[net.Conn]net.IP),
		idleTimeout:   defaultIdleTimeout,
		maxConns:      defaultMaxConns,
		maxConnsPerIP: defaultMaxConnsPerIP,
		ipConns:       make(map[string]int),
	}
	if allowedClientIP != "" {
		s.allowedClientIP = net.ParseIP(allowedClientIP)
	}
	for _, o := range opts {
		o(s)
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.maxConns > 0 {
		s.sem = make(chan struct{}, s.maxConns)
	}
	return s
}

// Start begins listening for proxy connections. Non-blocking.
func (s *Server) Start() (string, error) {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return "", fmt.Errorf("proxy listen: %w", err)
	}
	s.listener = ln
	actualAddr := ln.Addr().String()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			if !s.acquireConn(remoteHost) {
				conn.Close() // over a concurrency cap; drop without serving
				continue
			}
			go func() {
				defer s.releaseConn(remoteHost)
				s.handleConn(conn)
			}()
		}
	}()

	s.log.Debug("MITM proxy started", "addr", actualAddr)
	return actualAddr, nil
}

// Close stops the proxy server and forcibly terminates any active connections
// (so established tunnels can't keep forwarding/injecting after teardown).
func (s *Server) Close() {
	if s.listener != nil {
		s.listener.Close()
	}
	s.connMu.Lock()
	s.closing = true
	for c := range s.conns {
		c.Close()
	}
	s.connMu.Unlock()
	s.wg.Wait()
}

// CloseClient terminates any active connections from the given client IP. Used
// to immediately drop a workload's tunnels when its secret binding is removed
// (sandbox destroyed or token rotated), so injection can't continue on an
// already-open tunnel.
func (s *Server) CloseClient(ip net.IP) {
	if ip == nil {
		return
	}
	s.connMu.Lock()
	for c, cip := range s.conns {
		if cip != nil && cip.Equal(ip) {
			c.Close()
		}
	}
	s.connMu.Unlock()
}

// trackConn registers an active connection. It returns false if the server is
// already closing, in which case the caller should drop the connection.
func (s *Server) trackConn(conn net.Conn, ip net.IP) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.closing {
		return false
	}
	s.conns[conn] = ip
	return true
}

func (s *Server) untrackConn(conn net.Conn) {
	s.connMu.Lock()
	delete(s.conns, conn)
	s.connMu.Unlock()
}

func (s *Server) handleConn(conn net.Conn) {
	// Apply an idle timeout to every read/write (handshake, request parse, tunnel
	// loop, response streaming) so a stalled or idle connection is reaped instead
	// of pinning a goroutine + FD forever (NL-REQ-02).
	if s.idleTimeout > 0 {
		conn = &idleConn{Conn: conn, idle: s.idleTimeout}
	}
	defer conn.Close()

	remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	remoteIP := net.ParseIP(remoteHost)

	if !s.trackConn(conn, remoteIP) {
		return // server is shutting down
	}
	defer s.untrackConn(conn)

	// Enforce client IP restriction (multitenancy isolation).
	if s.allowedClientIP != nil {
		if remoteIP == nil || !remoteIP.Equal(s.allowedClientIP) {
			s.log.Warn("proxy: rejected connection from unauthorized IP", "remote", remoteHost)
			return
		}
	}

	// Resolve the policy binding for this connection. In shared mode an unknown
	// client (no binding for its IP) is rejected — it can't be mapped to a
	// sandbox, so we can't know its allow list or secrets.
	binding := s.static
	if s.bindingFor != nil {
		binding = s.bindingFor(remoteIP)
		if binding == nil {
			s.log.Warn("proxy: no binding for client; rejecting", "remote", remoteHost)
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}
	}

	// A large buffer so the whole ClientHello of a transparently-redirected TLS
	// connection can be Peek'd (and later replayed) without consuming it.
	br := bufio.NewReaderSize(conn, maxClientHelloPeek)

	// Distinguish a transparently-redirected connection (eBPF connect4 rewrote a
	// direct web-port dial to the proxy) from an explicit proxy request. A raw TLS
	// ClientHello begins with the handshake record byte (0x16); an explicit
	// CONNECT or origin/absolute-form HTTP request begins with an ASCII method.
	first, err := br.Peek(1)
	if err != nil {
		s.log.Debug("proxy: failed to peek connection", "error", err)
		return
	}
	if first[0] == tlsHandshakeRecord {
		s.handleTransparentTLS(conn, br, binding)
		return
	}

	req, err := http.ReadRequest(br)
	if err != nil {
		s.log.Debug("proxy: failed to read request", "error", err)
		return
	}

	// Enforce Bearer token authentication. Only explicit-proxy clients can carry
	// the header; transparently-redirected connections (handled above) are
	// isolated by client IP via the binding instead.
	if s.authToken != "" {
		proxyAuth := req.Header.Get("Proxy-Authorization")
		valid := strings.HasPrefix(proxyAuth, "Bearer ") &&
			subtle.ConstantTimeCompare([]byte(proxyAuth[7:]), []byte(s.authToken)) == 1
		if !valid {
			s.log.Warn("proxy: rejected unauthenticated request", "remote", conn.RemoteAddr().String())
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Bearer\r\n\r\n"))
			return
		}
		req.Header.Del("Proxy-Authorization")
	}

	if req.Method == http.MethodConnect {
		s.handleConnect(conn, br, req, binding)
	} else {
		s.handleHTTP(conn, br, req, binding)
	}
}

// handleTransparentTLS serves a TLS connection that eBPF connect4 transparently
// redirected to the proxy (the client dialed a host directly, unaware of any
// proxy, so there is no CONNECT). The destination host is taken from the
// ClientHello SNI. The allow list is enforced on that hostname; then the
// connection is either spliced end-to-end (when no secret targets the host — so
// the client does real TLS with the real server, preserving pinning/h2/websocket)
// or MITM-terminated (when a secret must be injected). The original web port is
// 443 for a TLS ClientHello (connect4 only redirects TCP 80/443, and 80 is
// cleartext HTTP handled elsewhere).
func (s *Server) handleTransparentTLS(clientConn net.Conn, br *bufio.Reader, binding *Binding) {
	hostname, err := sniffClientHelloSNI(br)
	if err != nil {
		// No SNI → we can't identify the host, so we can't enforce the allow list.
		// Fail closed: drop the connection rather than forward blind.
		s.log.Warn("proxy: transparent TLS connection without usable SNI; dropping",
			"binding", binding.name, "error", err)
		return
	}

	if !binding.isAllowed(hostname) {
		// A transparent TLS client isn't speaking HTTP yet, so there is no clean
		// status code to send; dropping the connection surfaces as a TLS failure.
		s.log.Warn("proxy: blocked transparent connection to non-allowed host", "host", hostname, "binding", binding.name)
		return
	}

	if binding.injector.TargetsHost(hostname) {
		// Secret injection needs the plaintext, so terminate TLS. The buffered
		// ClientHello is replayed to the TLS server via the bufio reader.
		s.mitmTLS(&connWithReader{Conn: clientConn, r: br}, hostname, hostname, binding)
		return
	}
	// No secret targets this host: splice through untouched so end-to-end TLS
	// (and thus pinning, ALPN/h2, websockets) is preserved. The proxy resolves
	// the SNI hostname itself and dials it, ignoring where the client's socket
	// was originally pointed — this is what defeats DNS/shared-IP fronting.
	s.spliceUpstream(clientConn, br, hostname, "443")
}

// handleConnect handles an explicit HTTPS CONNECT tunnel. After the tunnel is
// established it either splices the bytes through end-to-end (when no secret
// targets the host) or MITM-terminates TLS to inject secrets — the same routing
// used for transparently-redirected TLS, so websockets/HTTP-2/pinning keep
// working for env-proxy-honoring clients too.
func (s *Server) handleConnect(clientConn net.Conn, br *bufio.Reader, req *http.Request, binding *Binding) {
	host := req.Host
	hostname := stripPort(host)
	port := portOrDefault(host, "443")

	// Enforce domain allowlist.
	if !binding.isAllowed(hostname) {
		s.log.Warn("proxy: blocked connection to non-allowed host", "host", hostname, "binding", binding.name)
		clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return
	}

	// Resolve the upstream before completing the tunnel. The proxy — not the
	// client — performs DNS, so a host that doesn't resolve has to be reported as
	// a failed CONNECT (a non-2xx reply, before "200 Connection Established"). If
	// we established the tunnel first and only failed afterwards, the client would
	// see a successful connection and could not turn the failure into a non-zero
	// exit. Replying 502 to the CONNECT makes curl exit non-zero ("Received HTTP
	// code 502 from proxy after CONNECT") without exposing any proxy internals.
	if err := resolveHost(req.Context(), hostname); err != nil {
		s.log.Debug("proxy: upstream host did not resolve", "host", hostname, "error", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Tell the client the tunnel is established.
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	if !binding.injector.TargetsHost(hostname) {
		// No secret to inject → splice the raw TLS bytes end-to-end. The client
		// validates the real server's certificate itself, so pinning, ALPN/h2 and
		// websockets all work. br is the client-side source (it holds anything read
		// past the CONNECT line, normally nothing since the client waits for 200).
		s.spliceUpstream(clientConn, br, hostname, port)
		return
	}

	// A secret targets this host: terminate TLS so it can be injected. The client
	// sends its ClientHello only after the 200 above, so nothing is buffered in br
	// yet; run the TLS server on a reader that still drains br first for safety.
	s.mitmTLS(&connWithReader{Conn: clientConn, r: br}, hostname, host, binding)
}

// mitmTLS terminates TLS with the client using a cert minted for hostname, then
// forwards each decrypted request to the real upstream (injecting secrets and
// scrubbing them back out of responses). tlsSrc is the connection the TLS server
// runs on; host is the authority used to build upstream request URLs (may carry
// a non-default port).
func (s *Server) mitmTLS(tlsSrc net.Conn, hostname, host string, binding *Binding) {
	// TLS handshake with the client using a cert minted for this host.
	cert, err := s.ca.MintCert(hostname)
	if err != nil {
		s.log.Error("proxy: failed to mint cert", "host", hostname, "error", err)
		return
	}

	tlsConn := tls.Server(tlsSrc, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err := tlsConn.Handshake(); err != nil {
		s.log.Debug("proxy: TLS handshake failed", "host", hostname, "error", err)
		return
	}
	defer tlsConn.Close()

	// Read the actual HTTP request from the decrypted stream.
	clientReader := bufio.NewReader(tlsConn)

	for {
		innerReq, err := http.ReadRequest(clientReader)
		if err != nil {
			return // client done or error
		}

		// Set the full URL for the upstream request.
		innerReq.URL.Scheme = "https"
		innerReq.URL.Host = host
		innerReq.RequestURI = ""

		// Inject secrets into request headers.
		if binding.injector.HasSecrets() {
			s.injectHeaders(binding, hostname, innerReq)
		}

		// Inject secrets into request body.
		// TODO: Come back to this - we shouldn't load the entire body into memory
		// if innerReq.Body != nil && binding.injector.HasSecrets() {
		// 	body, err := io.ReadAll(innerReq.Body)
		// 	innerReq.Body.Close()
		// 	if err == nil {
		// 		replaced := binding.injector.ReplaceBody(hostname, body)
		// 		innerReq.Body = io.NopCloser(strings.NewReader(string(replaced)))
		// 		innerReq.ContentLength = int64(len(replaced))
		// 	}
		// }

		// Forward to the real upstream server.
		resp, err := http.DefaultTransport.(*http.Transport).RoundTrip(innerReq)
		if err != nil {
			// The tunnel is already up (the host resolved before we sent 200), so
			// the only channel left is the tunnel itself — a clean 502, which never
			// names the proxy. Resolution failures are caught before the 200 above.
			s.log.Debug("proxy: upstream request failed", "host", hostname, "error", err)
			writeUpstreamError(tlsConn, hostname)
			return
		}

		// Strip any real secret values back out of the response so the sandbox
		// only ever sees placeholders, even if the upstream echoes a secret back
		// (echo/debug routes, header-reflecting redirects, verbose 4xx) — NL-SEC-01.
		var repls []replacement
		if binding.injector.HasSecrets() {
			repls = binding.injector.responseReplacements(hostname)
		}

		// Stream the (scrubbed) response to the client; see writeResponse.
		if werr := writeResponse(tlsConn, resp, repls); werr != nil {
			s.log.Debug("proxy: writing response to client failed", "host", hostname, "error", werr)
			return
		}

		// If the client or server indicated close, stop.
		if resp.Close || innerReq.Close {
			return
		}
	}
}

// handleHTTP handles cleartext HTTP requests — both explicit-proxy requests
// (absolute-form request target: the client set HTTP_PROXY) and transparently
// redirected ones (origin-form target: eBPF connect4 rewrote a direct port-80
// dial). req is the first request already read from br; subsequent keep-alive
// requests are read from br in the loop. Secrets are never injected on cleartext
// (NL-SEC-02).
func (s *Server) handleHTTP(clientConn net.Conn, br *bufio.Reader, req *http.Request, binding *Binding) {
	for {
		hostname := stripPort(req.Host)

		// A transparently-redirected request arrives in origin-form (URL has a path
		// but no scheme/host); the client dialed the destination directly, unaware
		// of any proxy. Explicit-proxy requests carry a full absolute URL.
		transparent := req.URL.Host == ""

		// Enforce domain allowlist. A blocked transparent request is dropped rather
		// than answered: the client didn't knowingly talk to a proxy, and any HTTP
		// reply — even a bare 403 — would reveal an HTTP-aware middlebox where a
		// plain connection failure is expected (and would let curl exit 0). Dropping
		// matches the transparent-TLS path, which also drops on a blocked SNI. An
		// explicit-proxy client gets the protocol-correct 403 instead.
		if !binding.isAllowed(hostname) {
			s.log.Warn("proxy: blocked request to non-allowed host", "host", hostname, "binding", binding.name, "transparent", transparent)
			if !transparent {
				clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			}
			return
		}

		// Reconstruct the absolute target of an origin-form request from the Host
		// header before forwarding. Explicit-proxy requests already carry a full
		// absolute URL and are left as-is.
		if transparent {
			req.URL.Scheme = "http"
			req.URL.Host = req.Host
		}

		// Do NOT inject secrets here: a cleartext request is forwarded to an http://
		// upstream, so the real value would cross the network in the clear and be
		// visible to anyone on-path (NL-SEC-02). Placeholders are forwarded untouched
		// (they're opaque and leak nothing); secret injection is reserved for the
		// TLS-terminated path. Surface a warning when a placeholder actually appears
		// so a misconfiguration (or attempt to exfil a secret over cleartext) is
		// visible.
		if marker := binding.injector.Marker(); marker != "" && requestCarries(req, marker) {
			s.log.Warn("proxy: secret placeholder in a cleartext HTTP request; injection refused (use https)",
				"host", hostname, "binding", binding.name)
		}

		req.RequestURI = ""

		upstreamResp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			s.log.Debug("proxy: upstream request failed", "host", hostname, "error", err)
			if upstreamResolutionFailed(err) {
				// The host couldn't be resolved. We can't reproduce curl's own "could
				// not resolve host" (the proxy resolves, not the client), and a 502 body
				// would make curl exit 0. Dropping the connection makes curl fail with a
				// non-zero exit instead, with no proxy details in the error.
				return
			}
			writeUpstreamError(clientConn, hostname)
			return
		}

		reqClose := req.Close

		// No injection happened on this path, so there is no injected secret to
		// scrub back out; stream the response as-is.
		if werr := writeResponse(clientConn, upstreamResp, nil); werr != nil {
			s.log.Debug("proxy: writing response to client failed", "host", hostname, "error", werr)
			return
		}

		if reqClose || upstreamResp.Close {
			return
		}

		// Keep-alive: read the next request on this connection.
		req, err = http.ReadRequest(br)
		if err != nil {
			return // client done or error
		}
	}
}

// spliceUpstream dials hostname:port itself (performing its own DNS, so a
// spoofed client destination or shared IP can't matter) and copies bytes
// bidirectionally between the client and the upstream without terminating TLS.
// clientReader is the client-side source (a bufio.Reader holding any already-
// buffered bytes, e.g. a peeked ClientHello); clientConn is written to. Used for
// connections to hosts with no secret mapped, so end-to-end TLS — and thus
// certificate pinning, ALPN/HTTP-2 and websockets — is preserved.
func (s *Server) spliceUpstream(clientConn net.Conn, clientReader io.Reader, hostname, port string) {
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(hostname, port), dnsResolveTimeout)
	if err != nil {
		s.log.Debug("proxy: failed to dial upstream for splice", "host", hostname, "port", port, "error", err)
		return
	}
	// Bound the upstream half by the same idle timeout as the client half, so a
	// silent, half-open peer can't pin a goroutine forever (the client half is
	// already an idleConn; the raw dialed upstream is not).
	if s.idleTimeout > 0 {
		upstream = &idleConn{Conn: upstream, idle: s.idleTimeout}
	}
	defer upstream.Close()

	// Copy both directions. When one side reaches EOF, half-close the peer's write
	// side so it sees end-of-stream and can finish its own direction, rather than
	// fully closing (which would truncate an in-flight response on the other half).
	// Wait for both copies before the deferred Close tears everything down.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(upstream, clientReader)
		halfCloseWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, upstream)
		halfCloseWrite(clientConn)
	}()
	wg.Wait()
}

// halfCloseWrite shuts down the write half of conn when it supports it (TCP and
// the proxy's idleConn wrapper do), signaling EOF to the peer without discarding
// data still arriving on the read half. Best-effort: a conn without CloseWrite
// (or already closing) is left to the deferred full Close.
func halfCloseWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// portOrDefault returns the port from a "host:port" authority, or def when no
// port is present (a bare hostname). It tolerates IPv6 literals via net.SplitHostPort.
func portOrDefault(hostport, def string) string {
	if _, port, err := net.SplitHostPort(hostport); err == nil && port != "" {
		return port
	}
	return def
}

// connWithReader is a net.Conn whose reads are served from r (a bufio.Reader
// holding bytes already peeked off the connection, e.g. a ClientHello) while
// writes and all other methods delegate to the underlying Conn. It lets a
// tls.Server consume a ClientHello that was sniffed for its SNI without losing
// those bytes.
type connWithReader struct {
	net.Conn
	r io.Reader
}

func (c *connWithReader) Read(b []byte) (int, error) { return c.r.Read(b) }

// dnsResolveTimeout caps the pre-CONNECT upstream name lookup so a slow or
// unreachable resolver can't hang tunnel setup.
const dnsResolveTimeout = 10 * time.Second

// resolveHost looks up hostname through the same resolver the proxy's transport
// dials with (net.DefaultResolver, which honors the --dns override), so the
// pre-CONNECT check agrees with what the upstream request would do. An IP
// literal resolves to itself. It returns the lookup error (a *net.DNSError)
// when the host cannot be resolved.
func resolveHost(ctx context.Context, hostname string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, dnsResolveTimeout)
	defer cancel()
	_, err := net.DefaultResolver.LookupHost(ctx, hostname)
	return err
}

// upstreamResolutionFailed reports whether err (from an upstream RoundTrip) is a
// DNS name-resolution failure — the host could not be resolved — as opposed to a
// connection refused, timeout, or other transport error.
func upstreamResolutionFailed(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

// writeUpstreamError writes a framed HTTP/1.1 502 to the client for an upstream
// failure that happens after the request is already committed (a CONNECT tunnel
// that's up, or a plain-HTTP request mid-flight). The body is generic and never
// names the proxy — the sandboxed client must not learn it is behind a MITM.
// Resolution failures are handled earlier (a failed CONNECT or a dropped HTTP
// connection) so the client gets a non-zero exit rather than this 502.
func writeUpstreamError(w io.Writer, hostname string) {
	body := fmt.Sprintf("could not reach upstream host: %s\r\n", hostname)
	fmt.Fprint(w, "HTTP/1.1 502 Bad Gateway\r\n")
	fmt.Fprint(w, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(w, "Content-Length: %d\r\n", len(body))
	fmt.Fprint(w, "Connection: close\r\n")
	fmt.Fprint(w, "\r\n")
	io.WriteString(w, body)
}

// writeResponse re-frames resp as HTTP/1.1 and streams it to w, never buffering
// the whole body (NL-REQ-01). When repls is non-empty the body is streamed
// through a scrubber that rewrites real secret values back to placeholders
// (NL-SEC-01); since that changes the body length, such responses are framed
// with chunked transfer-encoding. The upstream body is always closed.
func writeResponse(w io.Writer, resp *http.Response, repls []replacement) error {
	resp.Proto, resp.ProtoMajor, resp.ProtoMinor = "HTTP/1.1", 1, 1
	upstreamBody := resp.Body

	if len(repls) > 0 {
		scrubHeader(resp.Header, repls)
	}

	resp.Header.Del("Transfer-Encoding")
	switch {
	case len(repls) > 0:
		// Scrubbing rewrites the body, so its length is no longer known up front;
		// stream it chunked. Trailers are scrubbed in place by the reader once the
		// body reaches EOF (see scrubbingReader.trailer).
		sr := newScrubbingReader(upstreamBody, repls)
		sr.trailer = resp.Trailer
		resp.Body = sr
		resp.ContentLength = -1
		resp.TransferEncoding = []string{"chunked"}
		resp.Header.Del("Content-Length")
	case resp.ContentLength < 0:
		// Unknown length (e.g. an HTTP/2 origin) — chunked so the HTTP/1.1 client
		// can detect end-of-body.
		resp.TransferEncoding = []string{"chunked"}
		resp.Header.Del("Content-Length")
	default:
		resp.TransferEncoding = nil
	}

	err := resp.Write(w)
	// resp.Write closes resp.Body on success; close the original upstream body
	// directly too (idempotent) so a mid-stream write error can't leak it.
	upstreamBody.Close()
	return err
}

// requestCarries reports whether the request's URL or any header value contains
// marker — a cheap check for a secret placeholder (used only for a warning).
func requestCarries(req *http.Request, marker string) bool {
	if strings.Contains(req.URL.String(), marker) {
		return true
	}
	for _, vals := range req.Header {
		for _, v := range vals {
			if strings.Contains(v, marker) {
				return true
			}
		}
	}
	return false
}

// injectHeaders replaces placeholder values in request headers with real secrets.
func (s *Server) injectHeaders(binding *Binding, hostname string, req *http.Request) {
	for key, vals := range req.Header {
		for i, v := range vals {
			replaced := binding.injector.ReplaceString(hostname, v)
			if replaced != v {
				req.Header[key][i] = replaced
				s.log.Debug("proxy: injected secret in header", "host", hostname, "header", key, "binding", binding.name)
			}
		}
	}
}
