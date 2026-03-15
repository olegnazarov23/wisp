package proxy

import (
	"io"
	"net"
	"sync"
)

// Relay bidirectionally copies data between two connections.
// Returns when either direction encounters an error or EOF.
func Relay(left, right net.Conn) error {
	var wg sync.WaitGroup
	var leftErr, rightErr error

	wg.Add(2)

	// left -> right
	go func() {
		defer wg.Done()
		_, leftErr = io.Copy(right, left)
		// Signal the other side that we're done writing.
		if tc, ok := right.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// right -> left
	go func() {
		defer wg.Done()
		_, rightErr = io.Copy(left, right)
		if tc, ok := left.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()

	if leftErr != nil {
		return leftErr
	}
	return rightErr
}
