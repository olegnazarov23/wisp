package mux

import (
	"net"
	"sync/atomic"
	"testing"
)

// countingConn counts the writes made to it.
type countingConn struct {
	net.Conn
	writes atomic.Int64
}

func (c *countingConn) Write(b []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(b)
}

// A frame is one write: a header written on its own became a small TLS record of its own.
func TestFrameIsOneWrite(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		buf := make([]byte, 1<<16)
		for {
			if _, err := b.Read(buf); err != nil {
				return
			}
		}
	}()

	conn := &countingConn{Conn: a}
	s := NewClient(conn)
	defer s.Close()
	st, err := s.Open()
	if err != nil {
		t.Fatal(err)
	}
	before := conn.writes.Load()
	if _, err := st.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if n := conn.writes.Load() - before; n != 1 {
		t.Fatalf("a data frame took %d writes", n)
	}
}
