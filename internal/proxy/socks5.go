package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	vpncrypto "github.com/awisp/wisp/internal/crypto"
	"github.com/awisp/wisp/internal/camouflage"
	"github.com/awisp/wisp/internal/mux"
	"github.com/awisp/wisp/internal/protocol"
	"github.com/awisp/wisp/internal/transport"
	"github.com/awisp/wisp/internal/tunnel"
)

// SOCKS5 constants.
const (
	socks5Version = 0x05
	authNone      = 0x00
	cmdConnect    = 0x01
	rsrvd         = 0x00
	repSuccess    = 0x00
	repFailure    = 0x01
)

// SOCKS5Server is a local SOCKS5 proxy that tunnels traffic through Trojan.
type SOCKS5Server struct {
	ServerAddr    string
	SNI           string
	Fingerprint   string
	PasswordHash  string
	Transport     string // "tls", "ws", or "grpc".
	WSPath        string
	EncryptionKey string
	EnableNoise   bool // Send fake traffic to blend in.

	// Mux session management — one persistent connection, many streams.
	muxSession *mux.Session
	muxMu      sync.Mutex
	noise      *camouflage.NoiseGenerator
}

// getMuxSession returns the current mux session, creating one if needed.
// All SOCKS5 connections share a single mux session over one TLS connection.
func (s *SOCKS5Server) getMuxSession() (*mux.Session, error) {
	s.muxMu.Lock()
	defer s.muxMu.Unlock()

	if s.muxSession != nil && !s.muxSession.IsClosed() {
		return s.muxSession, nil
	}

	// Establish a new connection.
	conn, err := s.dialTransport()
	if err != nil {
		return nil, err
	}

	// Wrap with encryption if configured.
	if s.EncryptionKey != "" {
		encConn, err := vpncrypto.NewEncryptedConn(conn, s.EncryptionKey)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("encryption: %w", err)
		}
		conn = encConn
	}

	s.muxSession = mux.NewClient(conn)
	log.Printf("mux session established to %s", s.ServerAddr)

	// Start noise generator if enabled.
	if s.EnableNoise {
		if s.noise != nil {
			s.noise.Stop()
		}
		session := s.muxSession
		s.noise = camouflage.NewNoiseGenerator(func(data []byte) error {
			// Send noise as a stream that immediately closes.
			stream, err := session.Open()
			if err != nil {
				return err
			}
			stream.Write(data)
			stream.Close()
			return nil
		})
		s.noise.Start()
	}

	return s.muxSession, nil
}

// dialTransport establishes the underlying transport connection.
func (s *SOCKS5Server) dialTransport() (net.Conn, error) {
	tlsConn, err := tunnel.DialTLS(s.ServerAddr, s.SNI, s.Fingerprint)
	if err != nil {
		return nil, err
	}

	switch s.Transport {
	case "ws":
		wsConn, err := transport.ClientUpgrade(tlsConn, s.SNI, s.WSPath)
		if err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("ws upgrade: %w", err)
		}
		return wsConn, nil

	case "grpc":
		grpcConn, err := transport.H2ClientUpgrade(tlsConn, s.SNI, s.WSPath)
		if err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("grpc upgrade: %w", err)
		}
		return grpcConn, nil

	default:
		return tlsConn, nil
	}
}

// ListenAndServe starts the SOCKS5 proxy.
func (s *SOCKS5Server) ListenAndServe(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on %s", addr)
	log.Printf("transport: %s | mux: enabled | noise: %v", s.Transport, s.EnableNoise)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("socks5 accept: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// --- SOCKS5 handshake ---
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != socks5Version {
		return
	}

	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	if _, err := conn.Write([]byte{socks5Version, authNone}); err != nil {
		return
	}

	// --- SOCKS5 request ---
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}

	if reqHeader[0] != socks5Version || reqHeader[1] != cmdConnect {
		s.sendReply(conn, repFailure, "0.0.0.0", 0)
		return
	}

	atyp := reqHeader[3]
	var dstAddr string
	var trojanAtyp byte

	switch atyp {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		dstAddr = net.IP(addr).String()
		trojanAtyp = protocol.AtypIPv4
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		dstAddr = string(domain)
		trojanAtyp = protocol.AtypDomain
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		dstAddr = net.IP(addr).String()
		trojanAtyp = protocol.AtypIPv6
	default:
		s.sendReply(conn, repFailure, "0.0.0.0", 0)
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	dstPort := binary.BigEndian.Uint16(portBuf)

	// --- Open a mux stream ---
	session, err := s.getMuxSession()
	if err != nil {
		log.Printf("mux session: %v", err)
		s.sendReply(conn, repFailure, "0.0.0.0", 0)
		return
	}

	stream, err := session.Open()
	if err != nil {
		// Session might be dead — clear it and retry once.
		s.muxMu.Lock()
		s.muxSession = nil
		s.muxMu.Unlock()

		session, err = s.getMuxSession()
		if err != nil {
			log.Printf("mux reconnect: %v", err)
			s.sendReply(conn, repFailure, "0.0.0.0", 0)
			return
		}
		stream, err = session.Open()
		if err != nil {
			log.Printf("mux open: %v", err)
			s.sendReply(conn, repFailure, "0.0.0.0", 0)
			return
		}
	}
	defer stream.Close()

	// Send Trojan request over the mux stream.
	req := &protocol.Request{
		Cmd:     protocol.CmdConnect,
		ATyp:    trojanAtyp,
		DstAddr: dstAddr,
		DstPort: dstPort,
	}
	if err := protocol.WriteRequest(stream, s.PasswordHash, req, nil); err != nil {
		log.Printf("trojan write: %v", err)
		s.sendReply(conn, repFailure, "0.0.0.0", 0)
		return
	}

	s.sendReply(conn, repSuccess, "0.0.0.0", 0)

	Relay(conn, stream)
}

func (s *SOCKS5Server) sendReply(conn net.Conn, rep byte, addr string, port uint16) {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		ip = net.IPv4zero.To4()
	}
	reply := []byte{
		socks5Version, rep, rsrvd, 0x01,
		ip[0], ip[1], ip[2], ip[3],
		byte(port >> 8), byte(port),
	}
	conn.Write(reply)
}
