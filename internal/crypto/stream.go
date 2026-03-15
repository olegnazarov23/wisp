package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptedConn wraps a net.Conn with ChaCha20-Poly1305 authenticated encryption.
// This provides a second encryption layer inside TLS, protecting against:
// - TLS MITM attacks (e.g., government-issued CA certificates)
// - Future TLS vulnerabilities
// - Server compromise (data in transit is still encrypted)
//
// Each frame: [2 bytes: ciphertext length][24 bytes: nonce][ciphertext + 16 bytes tag]
// ChaCha20-Poly1305 provides both encryption and authentication.
type EncryptedConn struct {
	net.Conn
	aead    cipher.AEAD
	readBuf []byte // buffered decrypted data from partial reads
}

// NewEncryptedConn creates an encrypted connection using a shared password.
// The password is derived into a 256-bit key using SHA256.
// Both sides must use the same password.
func NewEncryptedConn(conn net.Conn, password string) (*EncryptedConn, error) {
	// Derive a 256-bit key from the password.
	key := sha256.Sum256([]byte(password))

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	return &EncryptedConn{
		Conn: conn,
		aead: aead,
	}, nil
}

// Write encrypts data and writes it as a framed message.
func (c *EncryptedConn) Write(plaintext []byte) (int, error) {
	if len(plaintext) == 0 {
		return 0, nil
	}

	// Encrypt in chunks to avoid huge allocations.
	written := 0
	for len(plaintext) > 0 {
		chunk := plaintext
		if len(chunk) > 16384 { // 16KB chunks, matching TLS record size.
			chunk = chunk[:16384]
		}

		n, err := c.writeEncrypted(chunk)
		written += n
		if err != nil {
			return written, err
		}
		plaintext = plaintext[len(chunk):]
	}
	return written, nil
}

func (c *EncryptedConn) writeEncrypted(plaintext []byte) (int, error) {
	// Generate a random nonce for each message.
	nonce := make([]byte, c.aead.NonceSize()) // 24 bytes for XChaCha20.
	if _, err := rand.Read(nonce); err != nil {
		return 0, fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt: ciphertext includes the 16-byte Poly1305 tag.
	ciphertext := c.aead.Seal(nil, nonce, plaintext, nil)

	// Frame: [2 bytes: ciphertext length][nonce][ciphertext]
	ciphertextLen := len(ciphertext)
	frameLen := 2 + len(nonce) + ciphertextLen
	frame := make([]byte, frameLen)

	frame[0] = byte(ciphertextLen >> 8)
	frame[1] = byte(ciphertextLen)
	copy(frame[2:], nonce)
	copy(frame[2+len(nonce):], ciphertext)

	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}

	return len(plaintext), nil
}

// Read decrypts and returns data.
func (c *EncryptedConn) Read(b []byte) (int, error) {
	// Return buffered data first.
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Read frame header: 2 bytes ciphertext length.
	var hdr [2]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return 0, err
	}
	ciphertextLen := int(hdr[0])<<8 | int(hdr[1])

	if ciphertextLen == 0 {
		return 0, nil
	}

	// Read nonce.
	nonceSize := c.aead.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(c.Conn, nonce); err != nil {
		return 0, fmt.Errorf("read nonce: %w", err)
	}

	// Read ciphertext.
	ciphertext := make([]byte, ciphertextLen)
	if _, err := io.ReadFull(c.Conn, ciphertext); err != nil {
		return 0, fmt.Errorf("read ciphertext: %w", err)
	}

	// Decrypt and authenticate.
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("decrypt: %w", err)
	}

	// Copy as much as fits into the caller's buffer.
	n := copy(b, plaintext)
	if n < len(plaintext) {
		// Buffer the rest for the next Read call.
		c.readBuf = plaintext[n:]
	}

	return n, nil
}
