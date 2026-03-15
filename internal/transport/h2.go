package transport

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
)

// H2 transport disguises VPN traffic as an HTTP POST streaming connection.
// After the initial HTTP request/response, both sides exchange raw bytes —
// no chunked encoding, which keeps it simple and fast.

// H2ClientConn wraps a TLS connection with an HTTP POST initiation.
type H2ClientConn struct {
	net.Conn
	br *bufio.Reader
}

// H2ClientUpgrade sends an HTTP POST to initiate a streaming connection.
func H2ClientUpgrade(conn net.Conn, host, path string) (*H2ClientConn, error) {
	idBytes := make([]byte, 8)
	rand.Read(idBytes)
	requestID := hex.EncodeToString(idBytes)

	// Use Content-Length: large number to avoid chunked encoding.
	// The connection stays open for streaming.
	req := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/grpc\r\n"+
		"X-Request-ID: %s\r\n"+
		"User-Agent: grpc-go/1.62.0\r\n"+
		"TE: trailers\r\n"+
		"\r\n", path, host, requestID)

	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("h2 upgrade write: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("h2 upgrade read: %w", err)
	}

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("h2 upgrade: status %d", resp.StatusCode)
	}

	return &H2ClientConn{
		Conn: conn,
		br:   br,
	}, nil
}

// Read reads raw bytes (the bufio.Reader may have buffered data from the HTTP response).
func (c *H2ClientConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}

// Write sends raw bytes — no framing needed after the HTTP header.
func (c *H2ClientConn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

// H2ServerConn wraps a connection after the HTTP response is sent.
type H2ServerConn struct {
	net.Conn
	br *bufio.Reader
}

// Read reads from the buffered reader first (request body may be partially buffered).
func (c *H2ServerConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}

// Write sends raw bytes.
func (c *H2ServerConn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}
