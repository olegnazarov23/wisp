package transport

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// WebSocket opcodes.
const (
	opBinary = 2
	opClose  = 8
	opPing   = 9
	opPong   = 10
)

// wsGUID is the magic GUID from RFC 6455.
const wsGUID = "258EAFA5-E914-47DA-95CA-5AB5E44683DC"

// WSConn wraps a net.Conn with WebSocket framing.
// Implements net.Conn so it can be used transparently by the Trojan protocol layer.
type WSConn struct {
	net.Conn
	br     *bufio.Reader
	remain int // remaining bytes in current frame
}

// NewWSConn wraps an existing connection with WebSocket framing.
func NewWSConn(conn net.Conn) *WSConn {
	return &WSConn{
		Conn: conn,
		br:   bufio.NewReaderSize(conn, 32*1024),
	}
}

// Read reads data from WebSocket frames, stripping the framing.
func (c *WSConn) Read(b []byte) (int, error) {
	for {
		// If we have remaining data in the current frame, read it.
		if c.remain > 0 {
			n := len(b)
			if n > c.remain {
				n = c.remain
			}
			n, err := c.br.Read(b[:n])
			c.remain -= n
			return n, err
		}

		// Read next frame header.
		op, length, mask, err := c.readFrameHeader()
		if err != nil {
			return 0, err
		}

		switch op {
		case opBinary:
			if mask != nil {
				// Masked frame (from client): read, unmask, return.
				return c.readMasked(b, length, mask)
			}
			c.remain = length
			continue

		case opPing:
			// Read ping payload and respond with pong.
			payload := make([]byte, length)
			if _, err := io.ReadFull(c.br, payload); err != nil {
				return 0, err
			}
			if mask != nil {
				unmask(payload, mask)
			}
			c.writeFrame(opPong, payload)
			continue

		case opPong:
			// Discard pong.
			io.CopyN(io.Discard, c.br, int64(length))
			continue

		case opClose:
			return 0, io.EOF

		default:
			// Skip unknown frames.
			io.CopyN(io.Discard, c.br, int64(length))
			continue
		}
	}
}

// Write writes data as a WebSocket binary frame.
func (c *WSConn) Write(b []byte) (int, error) {
	if err := c.writeFrame(opBinary, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *WSConn) readFrameHeader() (op byte, length int, mask []byte, err error) {
	// First 2 bytes: FIN+opcode, mask+length.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c.br, hdr); err != nil {
		return 0, 0, nil, err
	}

	op = hdr[0] & 0x0F
	masked := (hdr[1] & 0x80) != 0
	length = int(hdr[1] & 0x7F)

	// Extended payload length.
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return 0, 0, nil, err
		}
		length = int(ext[0])<<8 | int(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return 0, 0, nil, err
		}
		length = int(ext[0])<<56 | int(ext[1])<<48 | int(ext[2])<<40 | int(ext[3])<<32 |
			int(ext[4])<<24 | int(ext[5])<<16 | int(ext[6])<<8 | int(ext[7])
	}

	// Masking key (4 bytes if masked).
	if masked {
		mask = make([]byte, 4)
		if _, err := io.ReadFull(c.br, mask); err != nil {
			return 0, 0, nil, err
		}
	}

	return op, length, mask, nil
}

func (c *WSConn) readMasked(b []byte, length int, mask []byte) (int, error) {
	n := len(b)
	if n > length {
		n = length
	}
	n, err := io.ReadFull(c.br, b[:n])
	if err != nil {
		return n, err
	}
	unmask(b[:n], mask)
	c.remain = length - n
	return n, nil
}

func (c *WSConn) writeFrame(op byte, payload []byte) error {
	// Build frame header.
	var hdr []byte
	plen := len(payload)

	if plen < 126 {
		hdr = []byte{0x80 | op, byte(plen)}
	} else if plen < 65536 {
		hdr = []byte{0x80 | op, 126, byte(plen >> 8), byte(plen)}
	} else {
		hdr = []byte{0x80 | op, 127,
			byte(plen >> 56), byte(plen >> 48), byte(plen >> 40), byte(plen >> 32),
			byte(plen >> 24), byte(plen >> 16), byte(plen >> 8), byte(plen),
		}
	}

	// Write header + payload in one write to avoid fragmentation.
	buf := make([]byte, 0, len(hdr)+plen)
	buf = append(buf, hdr...)
	buf = append(buf, payload...)
	_, err := c.Conn.Write(buf)
	return err
}

func unmask(data, mask []byte) {
	for i := range data {
		data[i] ^= mask[i%4]
	}
}

// --- Client-side WebSocket handshake ---

// ClientUpgrade performs a WebSocket upgrade handshake over an existing connection.
// The path should be the secret WebSocket endpoint path.
func ClientUpgrade(conn net.Conn, host, path string) (*WSConn, error) {
	// Generate random key.
	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)
	key := base64.StdEncoding.EncodeToString(keyBytes)

	// Send upgrade request.
	req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"+
		"\r\n", path, host, key)

	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("ws upgrade write: %w", err)
	}

	// Read response.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("ws upgrade read: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 101 {
		return nil, fmt.Errorf("ws upgrade failed: status %d", resp.StatusCode)
	}

	// Verify accept key.
	expectedAccept := ComputeAcceptKey(key)
	if resp.Header.Get("Sec-WebSocket-Accept") != expectedAccept {
		return nil, fmt.Errorf("ws upgrade: invalid accept key")
	}

	wsConn := &WSConn{
		Conn: conn,
		br:   br,
	}
	return wsConn, nil
}

// --- Server-side WebSocket handshake ---

// ServerUpgrade reads an HTTP upgrade request from br and completes the handshake.
// Returns a WSConn for framed communication.
func ServerUpgrade(conn net.Conn, br *bufio.Reader) (*WSConn, error) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("read upgrade request: %w", err)
	}

	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("not a websocket upgrade")
	}

	key := req.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, fmt.Errorf("missing Sec-WebSocket-Key")
	}

	accept := ComputeAcceptKey(key)

	resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n"+
		"\r\n", accept)

	if _, err := conn.Write([]byte(resp)); err != nil {
		return nil, fmt.Errorf("write upgrade response: %w", err)
	}

	return &WSConn{
		Conn: conn,
		br:   br,
	}, nil
}

// ComputeAcceptKey computes the Sec-WebSocket-Accept value for a given key.
func ComputeAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte(wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
