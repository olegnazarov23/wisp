package main

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	vpncrypto "github.com/olegnazarov23/wisp/internal/crypto"
	"github.com/olegnazarov23/wisp/internal/mux"
	"github.com/olegnazarov23/wisp/internal/protocol"
	"github.com/olegnazarov23/wisp/internal/proxy"
	"github.com/olegnazarov23/wisp/internal/stats"
	"github.com/olegnazarov23/wisp/internal/transport"
	"github.com/olegnazarov23/wisp/pkg/config"
)

// Handler processes incoming connections.
type Handler struct {
	PasswordHashes map[string]bool
	FallbackAddr   string
	// FallbackH2Addr serves the cover site over HTTP/2 without TLS (h2c), for browsers that
	// negotiated h2; empty when the listener doesn't offer h2.
	FallbackH2Addr string
	WSConfig       *config.WSConfig
	CoverSiteDir   string
	EncryptionKey  string
	// UserNames maps password hash → username for logging.
	UserNames  map[string]string
	UserSpeeds map[string]int64 // username → bytes/sec (0 = unlimited)
	// AllowPrivate lets users reach loopback, private and link-local addresses through the
	// server: the server's own services, its LAN, cloud metadata.
	AllowPrivate bool
}

// maxHead bounds the request head read to route an HTTP request.
const maxHead = 16 << 10

// Handle processes a single TLS connection.
func (h *Handler) Handle(conn net.Conn) {
	defer recovered("connection")
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReaderSize(conn, maxHead)

	switch classify(br) {
	case kindHTTP2:
		if h.FallbackH2Addr != "" {
			h.fallbackTo(h.FallbackH2Addr, br, conn)
			return
		}
		h.fallback(br, conn)
	case kindHTTP:
		h.handleHTTP(br, conn)
	case kindTrojan:
		h.handleRawTrojan(br, conn)
	default:
		h.fallback(br, conn)
	}
}

// What a connection's first bytes are.
const (
	kindOther  = iota // neither of the below: the cover site answers it
	kindHTTP          // a request line's method, then a space
	kindHTTP2         // the HTTP/2 preface, "PRI * HTTP/2.0"
	kindTrojan        // a Trojan password hash: 56 lowercase hex digits
)

// classify waits only until the first bytes can be told apart. A web server answers garbage at
// once, so bytes that can't start a request line or a password hash go to the cover site without
// waiting for more.
func classify(br *bufio.Reader) int {
	for n := 1; ; n = br.Buffered() + 1 {
		if _, err := br.Peek(n); err != nil {
			return kindOther
		}
		b, _ := br.Peek(br.Buffered())
		switch {
		case b[0] >= 'A' && b[0] <= 'Z':
			for i, c := range b {
				if c == ' ' {
					if string(b[:i]) == "PRI" {
						return kindHTTP2
					}
					return kindHTTP
				}
				if c < 'A' || c > 'Z' || i == 20 {
					return kindOther
				}
			}
		case isHex(b[:1]):
			if !isHex(b[:min(len(b), protocol.HashLen)]) {
				return kindOther
			}
			if len(b) >= protocol.HashLen {
				return kindTrojan
			}
		default:
			return kindOther
		}
	}
}

// handleHTTP routes an HTTP request: a WebSocket upgrade or a POST stream on the configured path
// opens a tunnel, and anything else goes to the cover site byte for byte, as it was sent.
func (h *Handler) handleHTTP(br *bufio.Reader, conn net.Conn) {
	head, err := peekHead(br)
	if err != nil {
		h.fallback(br, conn)
		return
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		h.fallback(br, conn)
		return
	}

	if h.WSConfig != nil && h.WSConfig.Enabled && req.URL.Path == h.WSConfig.Path {
		if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
			br.Discard(len(head))
			h.handleWSUpgrade(br, conn, req)
			return
		}
		if req.Method == "POST" {
			br.Discard(len(head))
			h.handleGRPCStream(br, conn, req)
			return
		}
	}

	if h.CoverSiteDir != "" {
		br.Discard(len(head))
		conn.SetReadDeadline(time.Time{})
		h.serveCoverSite(conn, req)
		return
	}
	h.fallback(br, conn)
}

// peekHead returns the request head, through the blank line, without consuming it.
func peekHead(br *bufio.Reader) ([]byte, error) {
	for n := 1; n <= br.Size(); n = br.Buffered() + 1 {
		if _, err := br.Peek(n); err != nil {
			return nil, err
		}
		b, _ := br.Peek(br.Buffered())
		if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
			return b[:i+4], nil
		}
	}
	return nil, errors.New("request head too long")
}

// handleWSUpgrade completes WebSocket handshake, then runs a mux session.
func (h *Handler) handleWSUpgrade(br *bufio.Reader, conn net.Conn, req *http.Request) {
	key := req.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		httpError(conn, 400, "Bad Request")
		return
	}

	accept := transport.ComputeAcceptKey(key)
	resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n"+
		"\r\n", accept)

	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}

	conn.SetReadDeadline(time.Time{})

	// frames the client sent right behind its request are already in br
	var tunnelConn net.Conn = transport.NewWSConn(&bufferedReadConn{Reader: br, Conn: conn})
	tunnelConn, err := h.wrapEncryption(tunnelConn)
	if err != nil {
		log.Printf("ws encryption: %v", err)
		return
	}

	h.serveMux(tunnelConn, "ws")
}

// handleGRPCStream handles gRPC/HTTP POST streaming, then runs a mux session.
func (h *Handler) handleGRPCStream(br *bufio.Reader, conn net.Conn, req *http.Request) {
	conn.SetReadDeadline(time.Time{})

	// Send 200 OK — after this, raw bytes flow in both directions.
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/grpc\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}

	// Wrap conn so reads come from the buffered reader (may have POST body bytes).
	var tunnelConn net.Conn = &bufferedReadConn{Reader: br, Conn: conn}
	tunnelConn, err := h.wrapEncryption(tunnelConn)
	if err != nil {
		log.Printf("grpc encryption: %v", err)
		return
	}

	h.serveMux(tunnelConn, "grpc")
}

// handleRawTrojan handles Trojan straight over TLS: one proxied connection per TLS connection
// (Shadowrocket, v2rayNG and other Trojan clients), or a mux session (the wisp client).
func (h *Handler) handleRawTrojan(br *bufio.Reader, conn net.Conn) {
	hashBytes, err := br.Peek(protocol.HashLen)
	if err != nil {
		h.fallback(br, conn)
		return
	}

	if !isHex(hashBytes) {
		h.fallback(br, conn)
		return
	}

	if !h.authenticate(string(hashBytes)) {
		h.fallback(br, conn)
		return
	}

	// Authenticated: read the rest of the header, still within the read deadline.
	hash, req, err := protocol.ReadRequest(br)
	if err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	buffConn := &bufferedReadConn{Reader: br, Conn: conn}
	if req.Cmd == protocol.CmdMux {
		tunnelConn, err := h.wrapEncryption(buffConn)
		if err != nil {
			log.Printf("tls encryption: %v", err)
			return
		}
		h.serveMux(tunnelConn, "tls")
		return
	}

	user := h.UserNames[hash]
	if user == "" {
		user = "anonymous"
	}
	if stats.Global.IsOverLimit(user) {
		log.Printf("[%s] over bandwidth limit, rejecting", user)
		return
	}

	speed := h.UserSpeeds[user]
	wrapped := stats.WrapThrottled(buffConn, user, speed)
	defer wrapped.Close()

	h.dispatch(wrapped, req, "raw")
}

// serveMux runs a multiplexed session — accepts streams, each carrying a Trojan request.
// This is used for our custom desktop client. Each stream = one proxied connection.
func (h *Handler) serveMux(conn net.Conn, transport string) {
	session := mux.NewServer(conn)
	defer session.Close()

	for {
		stream, err := session.Accept()
		if err != nil {
			return // Session closed.
		}
		go h.handleStream(stream, transport)
	}
}

// handleStream processes a single mux stream (one Trojan request).
func (h *Handler) handleStream(stream net.Conn, transportName string) {
	defer recovered("stream")
	defer stream.Close()

	// a stream that doesn't send its request in time is dropped (streams have no deadlines)
	timer := time.AfterFunc(10*time.Second, func() { stream.Close() })
	hash, req, err := protocol.ReadRequest(stream)
	timer.Stop()
	if err != nil {
		// Might be noise traffic — silently ignore.
		return
	}

	if !h.authenticate(hash) {
		log.Printf("%s: stream auth failed", transportName)
		return
	}

	user := h.UserNames[hash]
	if user == "" {
		user = "anonymous"
	}

	// Check bandwidth quota.
	if stats.Global.IsOverLimit(user) {
		log.Printf("[%s] over bandwidth limit, rejecting", user)
		return
	}

	// Wrap stream with byte counting + speed limiting.
	speed := h.UserSpeeds[user]
	wrapped := stats.WrapThrottled(stream, user, speed)
	defer wrapped.Close()

	h.dispatch(wrapped, req, transportName)
}

// dispatch routes a Trojan request to TCP or UDP handler.
func (h *Handler) dispatch(conn net.Conn, req *protocol.Request, transportName string) {
	switch req.Cmd {
	case protocol.CmdConnect:
		h.handleTCP(conn, req)
	case protocol.CmdUDPAssociate:
		h.handleUDP(conn, req)
	default:
		log.Printf("%s: unsupported cmd %d", transportName, req.Cmd)
	}
}

// handleTCP proxies a TCP connection to the destination.
func (h *Handler) handleTCP(clientConn net.Conn, req *protocol.Request) {
	target := req.Address()
	destConn, err := h.dial("tcp", target)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		return
	}
	defer destConn.Close()
	proxy.Relay(clientConn, destConn)
}

// handleUDP handles UDP associate.
func (h *Handler) handleUDP(clientConn net.Conn, req *protocol.Request) {
	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Printf("udp listen: %v", err)
		return
	}
	defer udpConn.Close()

	errCh := make(chan error, 2)

	go func() {
		for {
			atyp, addr, port, payload, err := protocol.ReadUDPPacket(clientConn)
			if err != nil {
				errCh <- err
				return
			}
			var dst string
			switch atyp {
			case protocol.AtypDomain:
				ips, err := net.LookupIP(addr)
				if err != nil || len(ips) == 0 {
					continue
				}
				dst = net.JoinHostPort(ips[0].String(), fmt.Sprintf("%d", port))
			default:
				dst = net.JoinHostPort(addr, fmt.Sprintf("%d", port))
			}
			udpAddr, err := net.ResolveUDPAddr("udp", dst)
			if err != nil || (!h.AllowPrivate && private(udpAddr.IP)) {
				continue
			}
			udpConn.WriteTo(payload, udpAddr)
		}
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, remoteAddr, err := udpConn.ReadFrom(buf)
			if err != nil {
				errCh <- err
				return
			}
			ua := remoteAddr.(*net.UDPAddr)
			var atyp byte
			var addr string
			if ip4 := ua.IP.To4(); ip4 != nil {
				atyp = protocol.AtypIPv4
				addr = ip4.String()
			} else {
				atyp = protocol.AtypIPv6
				addr = ua.IP.String()
			}
			if err := protocol.WriteUDPPacket(clientConn, atyp, addr, uint16(ua.Port), buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()

	<-errCh
}

// wrapEncryption wraps a connection with inner encryption if configured.
func (h *Handler) wrapEncryption(conn net.Conn) (net.Conn, error) {
	if h.EncryptionKey == "" {
		return conn, nil
	}
	return vpncrypto.NewEncryptedConn(conn, h.EncryptionKey)
}

// authenticate checks a password hash using constant-time comparison.
func (h *Handler) authenticate(receivedHash string) bool {
	for knownHash := range h.PasswordHashes {
		if subtle.ConstantTimeCompare([]byte(receivedHash), []byte(knownHash)) == 1 {
			return true
		}
	}
	return false
}

// fallback forwards the connection to the fallback web server.
func (h *Handler) fallback(br *bufio.Reader, clientConn net.Conn) {
	h.fallbackTo(h.FallbackAddr, br, clientConn)
}

// fallbackTo forwards the connection to addr, starting with the bytes already read.
func (h *Handler) fallbackTo(addr string, br *bufio.Reader, clientConn net.Conn) {
	fallbackConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return
	}
	defer fallbackConn.Close()

	clientConn.SetReadDeadline(time.Time{})

	buffered := br.Buffered()
	if buffered > 0 {
		peeked, _ := br.Peek(buffered)
		fallbackConn.Write(peeked)
		br.Discard(buffered)
	}

	pass(&bufferedReadConn{Reader: br, Conn: clientConn}, fallbackConn)
}

// pass relays a connection to the cover site the way a reverse proxy does: once the site is done,
// the client's connection closes, as if the client had reached the site directly.
func pass(client, site net.Conn) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(site, client)
		if tc, ok := site.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	io.Copy(client, site)
	client.Close()
	site.Close()
	<-done
}

// serveCoverSite serves a file from the cover website directory.
func (h *Handler) serveCoverSite(conn net.Conn, req *http.Request) {
	rw := &rawResponseWriter{conn: conn}
	fs := http.FileServer(http.Dir(h.CoverSiteDir))
	fs.ServeHTTP(rw, req)
}

type rawResponseWriter struct {
	conn       net.Conn
	header     http.Header
	wroteHdr   bool
	statusCode int
}

func (w *rawResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *rawResponseWriter) WriteHeader(code int) {
	if w.wroteHdr {
		return
	}
	w.wroteHdr = true
	w.statusCode = code
	statusText := http.StatusText(code)
	fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", code, statusText)
	w.header.Write(w.conn)
	fmt.Fprint(w.conn, "\r\n")
}

func (w *rawResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHdr {
		w.WriteHeader(200)
	}
	return w.conn.Write(b)
}

func httpError(conn net.Conn, code int, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
	conn.Write([]byte(resp))
}

type bufferedReadConn struct {
	io.Reader
	net.Conn
}

func (c *bufferedReadConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

// CloseWrite half-closes the connection underneath when it can.
func (c *bufferedReadConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

func isHex(b []byte) bool {
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// recovered logs a panic, so one connection can't take the server down.
func recovered(where string) {
	if r := recover(); r != nil {
		log.Printf("%s: panic: %v", where, r)
	}
}

// private reports addresses that belong to the server's side of the network: loopback, private
// and link-local ranges (cloud metadata is 169.254.169.254), carrier-grade NAT, and the like.
func private(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || cgnat.Contains(ip)
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// dial connects to a user's destination, refusing private addresses unless AllowPrivate. The
// check runs on the address actually dialed, after name resolution, so DNS can't get around it.
func (h *Handler) dial(network, target string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	if !h.AllowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || private(ip) {
				return fmt.Errorf("%s is a private address", host)
			}
			return nil
		}
	}
	return d.Dial(network, target)
}
