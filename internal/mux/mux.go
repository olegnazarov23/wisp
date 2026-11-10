package mux

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Lightweight stream multiplexer over a single connection.
// Allows multiple logical streams (each representing a proxied connection)
// over one physical TLS connection — mimicking how HTTP/2 browsers reuse connections.
//
// Frame format:
//   [4 bytes: stream ID][2 bytes: flags][2 bytes: payload length][payload]
//
// Flags:
//   0x01 = SYN  (new stream)
//   0x02 = FIN  (close stream)
//   0x04 = DATA (data frame)

const (
	flagSYN  uint16 = 0x01
	flagFIN  uint16 = 0x02
	flagDATA uint16 = 0x04

	headerSize   = 8
	maxFrameSize = 32768 // 32KB — matches common TLS record size.
)

// Session manages a multiplexed connection.
type Session struct {
	conn     net.Conn
	streams  map[uint32]*Stream
	mu       sync.RWMutex
	nextID   atomic.Uint32
	acceptCh chan *Stream
	writeMu  sync.Mutex // serializes writes to the underlying conn.
	closed   atomic.Bool
	closeCh  chan struct{}
}

// NewClient creates a client-side mux session (uses odd stream IDs).
func NewClient(conn net.Conn) *Session {
	s := newSession(conn)
	s.nextID.Store(1) // Odd IDs for client-initiated streams.
	return s
}

// NewServer creates a server-side mux session (accepts streams from client).
func NewServer(conn net.Conn) *Session {
	s := newSession(conn)
	s.nextID.Store(2) // Even IDs for server-initiated streams (unused for now).
	return s
}

func newSession(conn net.Conn) *Session {
	s := &Session{
		conn:     conn,
		streams:  make(map[uint32]*Stream),
		acceptCh: make(chan *Stream, 64),
		closeCh:  make(chan struct{}),
	}
	go s.readLoop()
	return s
}

// Open creates a new stream (client-side).
func (s *Session) Open() (*Stream, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	id := s.nextID.Add(2) - 2 // Increment by 2 to keep odd/even separation.
	stream := newStream(id, s)

	s.mu.Lock()
	s.streams[id] = stream
	s.mu.Unlock()

	// Send SYN frame.
	if err := s.writeFrame(id, flagSYN, nil); err != nil {
		s.removeStream(id)
		return nil, err
	}

	return stream, nil
}

// Accept waits for a new stream from the remote side (server-side).
func (s *Session) Accept() (*Stream, error) {
	select {
	case stream := <-s.acceptCh:
		return stream, nil
	case <-s.closeCh:
		return nil, fmt.Errorf("session closed")
	}
}

// Close closes the entire session.
func (s *Session) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	close(s.closeCh)

	s.mu.Lock()
	for _, stream := range s.streams {
		stream.closeLocal()
	}
	s.streams = make(map[uint32]*Stream)
	s.mu.Unlock()

	return s.conn.Close()
}

// IsClosed returns whether the session is closed.
func (s *Session) IsClosed() bool {
	return s.closed.Load()
}

func (s *Session) readLoop() {
	defer s.Close()

	hdr := make([]byte, headerSize)
	for {
		if _, err := io.ReadFull(s.conn, hdr); err != nil {
			return
		}

		streamID := binary.BigEndian.Uint32(hdr[0:4])
		flags := binary.BigEndian.Uint16(hdr[4:6])
		length := binary.BigEndian.Uint16(hdr[6:8])

		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				return
			}
		}

		switch {
		case flags&flagSYN != 0:
			stream := newStream(streamID, s)
			s.mu.Lock()
			s.streams[streamID] = stream
			s.mu.Unlock()
			select {
			case s.acceptCh <- stream:
			case <-s.closeCh:
				return
			}

		case flags&flagFIN != 0:
			s.mu.RLock()
			stream, ok := s.streams[streamID]
			s.mu.RUnlock()
			if ok {
				stream.closeRemote()
			}

		case flags&flagDATA != 0:
			s.mu.RLock()
			stream, ok := s.streams[streamID]
			s.mu.RUnlock()
			if ok {
				stream.pushData(payload)
			}
		}
	}
}

func (s *Session) writeFrame(streamID uint32, flags uint16, payload []byte) error {
	hdr := make([]byte, headerSize)
	binary.BigEndian.PutUint32(hdr[0:4], streamID)
	binary.BigEndian.PutUint16(hdr[4:6], flags)
	binary.BigEndian.PutUint16(hdr[6:8], uint16(len(payload)))

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.conn.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := s.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// Stream is a single logical connection within a mux session.
type Stream struct {
	id      uint32
	session *Session
	readCh  chan []byte
	readBuf []byte
	closed  atomic.Bool
	closeCh chan struct{}
}

func newStream(id uint32, session *Session) *Stream {
	return &Stream{
		id:      id,
		session: session,
		readCh:  make(chan []byte, 256),
		closeCh: make(chan struct{}),
	}
}

func (st *Stream) Read(b []byte) (int, error) {
	// Drain buffered data first.
	if len(st.readBuf) > 0 {
		n := copy(b, st.readBuf)
		st.readBuf = st.readBuf[n:]
		return n, nil
	}

	select {
	case data := <-st.readCh:
		if data == nil {
			return 0, io.EOF
		}
		n := copy(b, data)
		if n < len(data) {
			st.readBuf = data[n:]
		}
		return n, nil
	case <-st.closeCh:
		return 0, io.EOF
	}
}

func (st *Stream) Write(b []byte) (int, error) {
	if st.closed.Load() {
		return 0, fmt.Errorf("stream closed")
	}

	written := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxFrameSize {
			chunk = chunk[:maxFrameSize]
		}
		if err := st.session.writeFrame(st.id, flagDATA, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}

func (st *Stream) Close() error {
	if st.closed.Swap(true) {
		return nil
	}
	st.session.writeFrame(st.id, flagFIN, nil)
	close(st.closeCh)
	st.session.removeStream(st.id)
	return nil
}

func (st *Stream) closeLocal() {
	if st.closed.Swap(true) {
		return
	}
	close(st.closeCh)
}

func (st *Stream) closeRemote() {
	st.pushData(nil) // Signal EOF.
}

func (st *Stream) pushData(data []byte) {
	select {
	case st.readCh <- data:
	case <-st.closeCh:
	}
}

// LocalAddr returns the local address of the underlying connection.
func (st *Stream) LocalAddr() net.Addr {
	return st.session.conn.LocalAddr()
}

// RemoteAddr returns the remote address of the underlying connection.
func (st *Stream) RemoteAddr() net.Addr {
	return st.session.conn.RemoteAddr()
}

// SetDeadline is a no-op (deadlines managed per-stream via context if needed).
func (st *Stream) SetDeadline(t time.Time) error      { return nil }
func (st *Stream) SetReadDeadline(t time.Time) error  { return nil }
func (st *Stream) SetWriteDeadline(t time.Time) error { return nil }
