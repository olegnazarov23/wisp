package main

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	vpncrypto "github.com/awisp/wisp/internal/crypto"
	"github.com/awisp/wisp/internal/mux"
	"github.com/awisp/wisp/internal/protocol"
	"github.com/awisp/wisp/internal/proxy"
	"github.com/awisp/wisp/internal/stats"
	"github.com/awisp/wisp/internal/transport"
	"github.com/awisp/wisp/pkg/config"
)

// Handler processes incoming connections.
type Handler struct {
	PasswordHashes map[string]bool
	FallbackAddr   string
	WSConfig       *config.WSConfig
	CoverSiteDir   string
	EncryptionKey  string
	// UserNames maps password hash → username for logging.
	UserNames  map[string]string
	UserSpeeds map[string]int64 // username → bytes/sec (0 = unlimited)
}

// Handle processes a single TLS connection.
func (h *Handler) Handle(conn net.Conn) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReaderSize(conn, 4096)

	firstBytes, err := br.Peek(3)
	if err != nil {
		h.fallback(br, conn)
		return
	}

	if isHTTPMethod(firstBytes) {
		h.handleHTTP(br, conn)
		return
	}

	h.handleRawTrojan(br, conn)
}

// handleHTTP routes HTTP requests: WS upgrade, gRPC POST, or fallback.
func (h *Handler) handleHTTP(br *bufio.Reader, conn net.Conn) {
	req, err := http.ReadRequest(br)
	if err != nil {
		h.fallback(br, conn)
		return
	}

	if h.WSConfig != nil && h.WSConfig.Enabled && req.URL.Path == h.WSConfig.Path {
		if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
			h.handleWSUpgrade(conn, req)
			return
		}
		if req.Method == "POST" {
			h.handleGRPCStream(br, conn, req)
			return
		}
	}

	conn.SetReadDeadline(time.Time{})
	if h.CoverSiteDir != "" {
		h.serveCoverSite(conn, req)
		return
	}
	h.fallbackHTTP(conn, req)
}

// handleWSUpgrade completes WebSocket handshake, then runs a mux session.
func (h *Handler) handleWSUpgrade(conn net.Conn, req *http.Request) {
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

	var tunnelConn net.Conn = transport.NewWSConn(conn)
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

// handleRawTrojan handles direct Trojan (non-HTTP) connections with mux.
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

	// Auth OK for raw mode — but raw mode uses legacy single-request path
	// (for Shadowrocket/iOS compatibility, which doesn't support mux).
	br.Discard(protocol.HashLen)
	conn.SetReadDeadline(time.Time{})

	crlf := make([]byte, 2)
	if _, err = io.ReadFull(br, crlf); err != nil {
		return
	}

	cmdAtyp := make([]byte, 2)
	if _, err = io.ReadFull(br, cmdAtyp); err != nil {
		return
	}

	req := &protocol.Request{Cmd: cmdAtyp[0], ATyp: cmdAtyp[1]}

	switch req.ATyp {
	case protocol.AtypIPv4:
		addr := make([]byte, 4)
		if _, err = io.ReadFull(br, addr); err != nil {
			return
		}
		req.DstAddr = net.IP(addr).String()
	case protocol.AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(br, lenBuf); err != nil {
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err = io.ReadFull(br, domain); err != nil {
			return
		}
		req.DstAddr = string(domain)
	case protocol.AtypIPv6:
		addr := make([]byte, 16)
		if _, err = io.ReadFull(br, addr); err != nil {
			return
		}
		req.DstAddr = net.IP(addr).String()
	default:
		return
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(br, portBuf); err != nil {
		return
	}
	req.DstPort = uint16(portBuf[0])<<8 | uint16(portBuf[1])

	if _, err = io.ReadFull(br, crlf); err != nil {
		return
	}

	user := h.UserNames[string(hashBytes)]
	if user == "" {
		user = "anonymous"
	}

	buffConn := &bufferedReadConn{Reader: br, Conn: conn}
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
	defer stream.Close()

	hash, req, err := protocol.ReadRequest(stream)
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
	destConn, err := net.DialTimeout("tcp", target, 10*time.Second)
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
			if err != nil {
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
	fallbackConn, err := net.DialTimeout("tcp", h.FallbackAddr, 5*time.Second)
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

	proxy.Relay(&bufferedReadConn{Reader: br, Conn: clientConn}, fallbackConn)
}

// fallbackHTTP forwards a parsed HTTP request to the fallback server.
func (h *Handler) fallbackHTTP(conn net.Conn, req *http.Request) {
	fallbackConn, err := net.DialTimeout("tcp", h.FallbackAddr, 5*time.Second)
	if err != nil {
		return
	}
	defer fallbackConn.Close()
	req.Write(fallbackConn)
	proxy.Relay(conn, fallbackConn)
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

func isHex(b []byte) bool {
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isHTTPMethod(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	s := string(b[:3])
	return s == "GET" || s == "POS" || s == "PUT" || s == "DEL" ||
		s == "HEA" || s == "OPT" || s == "PAT" || s == "CON"
}
