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
	maxStreams   = 1024  // open streams per session; a SYN beyond that gets a FIN
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
	bytes    atomic.Int64 // payload bytes both ways, for rotating the connection
	draining atomic.Bool  // close once the last stream does
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
	defer func() { recover() }() // a bad frame ends this session, not the process

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
			s.bytes.Add(int64(length))
		}

		switch {
		case flags&flagSYN != 0:
			s.mu.Lock()
			if len(s.streams) >= maxStreams {
				s.mu.Unlock()
				s.writeFrame(streamID, flagFIN, nil)
				continue
			}
			stream := newStream(streamID, s)
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
	// one write per frame: a header written on its own became a TLS record of its own, a small
	// fixed-size record for every frame
	frame := make([]byte, headerSize+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], streamID)
	binary.BigEndian.PutUint16(frame[4:6], flags)
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	copy(frame[headerSize:], payload)
	s.bytes.Add(int64(len(payload)))

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	_, err := s.conn.Write(frame)
	return err
}

// Bytes is the payload carried both ways so far.
func (s *Session) Bytes() int64 {
	return s.bytes.Load()
}

// Streams is the number of open streams.
func (s *Session) Streams() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.streams)
}

// Drain closes the session once its last open stream closes: no new streams go to it.
func (s *Session) Drain() {
	s.draining.Store(true)
	if s.Streams() == 0 {
		s.Close()
	}
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	idle := len(s.streams) == 0
	s.mu.Unlock()
	if idle && s.draining.Load() {
		go s.Close()
	}
}

// Stream is a single logical connection within a mux session.
type Stream struct {
	id      uint32
	session *Session
	readCh  chan []byte
	readBuf []byte
	closed  atomic.Bool
	wrote   atomic.Bool // FIN sent: this side is done writing
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
	if st.closed.Load() || st.wrote.Load() {
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

// CloseWrite tells the other side this side is done sending (a FIN), and keeps reading.
func (st *Stream) CloseWrite() error {
	if st.closed.Load() || st.wrote.Swap(true) {
		return nil
	}
	return st.session.writeFrame(st.id, flagFIN, nil)
}

func (st *Stream) Close() error {
	if st.closed.Swap(true) {
		return nil
	}
	if !st.wrote.Swap(true) {
		st.session.writeFrame(st.id, flagFIN, nil)
	}
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
