package padding

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
)

// PaddedConn wraps a net.Conn with traffic padding to defeat statistical analysis.
// Each write is padded to a random size from a set of common TLS record sizes,
// making traffic patterns indistinguishable from normal HTTPS browsing.
//
// Frame format: [2 bytes: original length][original data][random padding]
// Total frame size is rounded up to one of the target sizes.
type PaddedConn struct {
	net.Conn
	// TargetSizes are common TLS record sizes browsers produce.
	// Frames are padded up to the nearest target size.
	TargetSizes []int
	MinPad      int // Minimum padding bytes to add.
	MaxPad      int // Maximum padding bytes to add (on top of target rounding).
}

// DefaultTargetSizes mimics common browser TLS record sizes.
var DefaultTargetSizes = []int{
	128, 256, 512, 1024, 1460, 2048, 4096, 8192, 16384,
}

// NewPaddedConn wraps a connection with default padding settings.
func NewPaddedConn(conn net.Conn) *PaddedConn {
	return &PaddedConn{
		Conn:        conn,
		TargetSizes: DefaultTargetSizes,
		MinPad:      16,
		MaxPad:      64,
	}
}

// Write pads data and writes a framed message.
func (c *PaddedConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	origLen := len(b)
	if origLen > 65535 {
		// Too large for a single padded frame — write in chunks.
		written := 0
		for len(b) > 0 {
			chunk := b
			if len(chunk) > 32768 {
				chunk = chunk[:32768]
			}
			n, err := c.writeFrame(chunk)
			written += n
			if err != nil {
				return written, err
			}
			b = b[len(chunk):]
		}
		return written, nil
	}

	return c.writeFrame(b)
}

func (c *PaddedConn) writeFrame(b []byte) (int, error) {
	origLen := len(b)

	// Choose a target frame size.
	// Frame overhead: 2 bytes for length prefix.
	minFrame := origLen + 2 + c.MinPad
	targetSize := c.selectTargetSize(minFrame)

	// Add random extra padding within bounds.
	extra := 0
	if c.MaxPad > c.MinPad {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(c.MaxPad-c.MinPad)))
		extra = int(n.Int64())
	}
	totalSize := targetSize + extra

	// Build the padded frame.
	frame := make([]byte, totalSize)
	binary.BigEndian.PutUint16(frame[0:2], uint16(origLen))
	copy(frame[2:2+origLen], b)

	// Fill padding with random bytes (not zeros — zeros are detectable).
	if padLen := totalSize - 2 - origLen; padLen > 0 {
		rand.Read(frame[2+origLen:])
	}

	_, err := c.Conn.Write(frame)
	if err != nil {
		return 0, err
	}
	return origLen, nil
}

// Read reads a padded frame and returns the original data.
func (c *PaddedConn) Read(b []byte) (int, error) {
	// Read the 2-byte length prefix.
	var lenBuf [2]byte
	if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
		return 0, err
	}
	origLen := int(binary.BigEndian.Uint16(lenBuf[:]))

	if origLen == 0 {
		return 0, nil
	}

	// We need to read the rest of the frame, but we don't know the total
	// frame size from just the length prefix. So we read exactly origLen
	// bytes of data, then we need to consume the padding.
	//
	// Problem: without knowing total frame size, we can't strip padding.
	// Solution: encode the total frame size too.
	//
	// Actually, let's use a simpler approach: send [2B total_len][2B orig_len][data][padding].

	// For simplicity in this version, we'll just read origLen bytes.
	// The sender ensures that after origLen bytes, the padding follows.
	// But we can't know where the frame ends without total length.
	// Let's restructure.

	return 0, fmt.Errorf("use PaddedConnV2 instead")
}

// PaddedConnV2 uses a cleaner frame format:
// [2 bytes: total frame length][2 bytes: payload length][payload][random padding]
type PaddedConnV2 struct {
	net.Conn
	TargetSizes []int
	MinPad      int
	MaxPad      int
}

func NewPaddedConnV2(conn net.Conn) *PaddedConnV2 {
	return &PaddedConnV2{
		Conn:        conn,
		TargetSizes: DefaultTargetSizes,
		MinPad:      16,
		MaxPad:      64,
	}
}

func (c *PaddedConnV2) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	origLen := len(b)
	if origLen > 32768 {
		written := 0
		for len(b) > 0 {
			chunk := b
			if len(chunk) > 32768 {
				chunk = chunk[:32768]
			}
			n, err := c.writePaddedFrame(chunk)
			written += n
			if err != nil {
				return written, err
			}
			b = b[len(chunk):]
		}
		return written, nil
	}

	return c.writePaddedFrame(b)
}

func (c *PaddedConnV2) writePaddedFrame(b []byte) (int, error) {
	origLen := len(b)

	// Overhead: 4 bytes header (2 total + 2 payload).
	minFrame := origLen + 4 + c.MinPad
	targetSize := selectTarget(c.TargetSizes, minFrame)

	extra := 0
	if c.MaxPad > c.MinPad {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(c.MaxPad-c.MinPad)))
		extra = int(n.Int64())
	}
	totalSize := targetSize + extra
	payloadSize := totalSize - 4 // Subtract header.

	frame := make([]byte, totalSize)
	binary.BigEndian.PutUint16(frame[0:2], uint16(payloadSize))
	binary.BigEndian.PutUint16(frame[2:4], uint16(origLen))
	copy(frame[4:4+origLen], b)

	// Random padding.
	if padLen := totalSize - 4 - origLen; padLen > 0 {
		rand.Read(frame[4+origLen:])
	}

	_, err := c.Conn.Write(frame)
	if err != nil {
		return 0, err
	}
	return origLen, nil
}

func (c *PaddedConnV2) Read(b []byte) (int, error) {
	// Read total payload size (includes real data + padding).
	var hdr [4]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return 0, err
	}

	payloadSize := int(binary.BigEndian.Uint16(hdr[0:2]))
	origLen := int(binary.BigEndian.Uint16(hdr[2:4]))

	if origLen > payloadSize || origLen > len(b) {
		return 0, fmt.Errorf("invalid padded frame: orig=%d payload=%d", origLen, payloadSize)
	}

	// Read original data into the caller's buffer.
	if _, err := io.ReadFull(c.Conn, b[:origLen]); err != nil {
		return 0, err
	}

	// Discard padding.
	padLen := payloadSize - origLen
	if padLen > 0 {
		_, err := io.CopyN(io.Discard, c.Conn, int64(padLen))
		if err != nil {
			return origLen, err
		}
	}

	return origLen, nil
}

func (c *PaddedConn) selectTargetSize(minSize int) int {
	return selectTarget(c.TargetSizes, minSize)
}

func selectTarget(targets []int, minSize int) int {
	for _, t := range targets {
		if t >= minSize {
			return t
		}
	}
	// If payload is larger than all targets, round up to nearest multiple of the largest.
	largest := targets[len(targets)-1]
	return ((minSize + largest - 1) / largest) * largest
}
