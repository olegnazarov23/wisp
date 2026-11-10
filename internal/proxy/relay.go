package proxy

import (
	"io"
	"net"
	"sync"
)

// Relay bidirectionally copies data between two connections, until both directions end. When
// one direction ends, the receiving side is told: a half-close where the connection supports it
// (TCP, mux streams), and otherwise both connections close, so neither end waits forever.
func Relay(left, right net.Conn) error {
	var wg sync.WaitGroup
	var leftErr, rightErr error

	wg.Add(2)

	// left -> right
	go func() {
		defer wg.Done()
		_, leftErr = io.Copy(right, left)
		closeWrite(right, left)
	}()

	// right -> left
	go func() {
		defer wg.Done()
		_, rightErr = io.Copy(left, right)
		closeWrite(left, right)
	}()

	wg.Wait()

	if leftErr != nil {
		return leftErr
	}
	return rightErr
}

// closeWrite ends dst's writing side, or both connections if dst can't half-close.
func closeWrite(dst, src net.Conn) {
	if cw, ok := dst.(interface{ CloseWrite() error }); ok && cw.CloseWrite() == nil {
		return
	}
	dst.Close()
	src.Close()
}
