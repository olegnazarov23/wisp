package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	// Trojan command types.
	CmdConnect      = 0x01
	CmdUDPAssociate = 0x03
	// CmdMux (trojan-go's value) opens a mux session: the rest of the connection is mux frames,
	// each stream starting with its own Trojan request.
	CmdMux = 0x7f

	// Address types (same as SOCKS5).
	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04

	// CRLF delimiter used in Trojan protocol.
	CRLF = "\r\n"

	// HashLen is the length of hex-encoded SHA224 hash.
	HashLen = 56
)

// Request represents a parsed Trojan request.
type Request struct {
	Cmd     byte
	ATyp    byte
	DstAddr string
	DstPort uint16
}

// Address returns "host:port" suitable for net.Dial.
func (r *Request) Address() string {
	return net.JoinHostPort(r.DstAddr, strconv.Itoa(int(r.DstPort)))
}

// WriteRequest writes a full Trojan request header to w.
// The header and first payload are combined into a single write
// to prevent TLS record splitting that could aid fingerprinting.
func WriteRequest(w io.Writer, passwordHash string, req *Request, payload []byte) error {
	// Calculate total size to write everything in one shot.
	// Format: hash(56) + CRLF + cmd(1) + atyp(1) + addr(variable) + port(2) + CRLF + payload
	addrBytes := encodeAddress(req.ATyp, req.DstAddr)
	totalLen := HashLen + 2 + 1 + 1 + len(addrBytes) + 2 + 2 + len(payload)

	buf := make([]byte, 0, totalLen)

	// Password hash.
	buf = append(buf, []byte(passwordHash)...)
	buf = append(buf, '\r', '\n')

	// Command and address type.
	buf = append(buf, req.Cmd)
	buf = append(buf, req.ATyp)

	// Destination address.
	buf = append(buf, addrBytes...)

	// Destination port (big-endian).
	buf = append(buf, byte(req.DstPort>>8), byte(req.DstPort))

	// CRLF.
	buf = append(buf, '\r', '\n')

	// First payload.
	buf = append(buf, payload...)

	_, err := w.Write(buf)
	return err
}

// ReadRequest reads and parses a Trojan request from r.
// It returns the password hash, the parsed request, and any trailing
// payload bytes that were read along with the header.
// The buffered parameter contains any bytes already read from the connection
// (used by the server when checking auth). Pass nil if reading fresh.
func ReadRequest(r io.Reader) (hash string, req *Request, err error) {
	// Read the 56-byte password hash.
	hashBuf := make([]byte, HashLen)
	if _, err := io.ReadFull(r, hashBuf); err != nil {
		return "", nil, fmt.Errorf("read hash: %w", err)
	}
	hash = string(hashBuf)

	// Read CRLF after hash.
	crlf := make([]byte, 2)
	if _, err := io.ReadFull(r, crlf); err != nil {
		return "", nil, fmt.Errorf("read CRLF after hash: %w", err)
	}
	if crlf[0] != '\r' || crlf[1] != '\n' {
		return "", nil, fmt.Errorf("expected CRLF after hash, got %x%x", crlf[0], crlf[1])
	}

	// Read command and address type.
	cmdAtyp := make([]byte, 2)
	if _, err := io.ReadFull(r, cmdAtyp); err != nil {
		return "", nil, fmt.Errorf("read cmd/atyp: %w", err)
	}

	req = &Request{
		Cmd:  cmdAtyp[0],
		ATyp: cmdAtyp[1],
	}

	// Read destination address based on type.
	switch req.ATyp {
	case AtypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return "", nil, fmt.Errorf("read IPv4: %w", err)
		}
		req.DstAddr = net.IP(addr).String()

	case AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", nil, fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", nil, fmt.Errorf("read domain: %w", err)
		}
		req.DstAddr = string(domain)

	case AtypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return "", nil, fmt.Errorf("read IPv6: %w", err)
		}
		req.DstAddr = net.IP(addr).String()

	default:
		return "", nil, fmt.Errorf("unsupported address type: %d", req.ATyp)
	}

	// Read destination port (big-endian).
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", nil, fmt.Errorf("read port: %w", err)
	}
	req.DstPort = binary.BigEndian.Uint16(portBuf)

	// Read trailing CRLF.
	if _, err := io.ReadFull(r, crlf); err != nil {
		return "", nil, fmt.Errorf("read trailing CRLF: %w", err)
	}

	return hash, req, nil
}

// WriteUDPPacket writes a Trojan UDP packet frame to w.
func WriteUDPPacket(w io.Writer, atyp byte, addr string, port uint16, payload []byte) error {
	addrBytes := encodeAddress(atyp, addr)

	buf := make([]byte, 0, 1+len(addrBytes)+2+2+2+len(payload))
	buf = append(buf, atyp)
	buf = append(buf, addrBytes...)
	buf = append(buf, byte(port>>8), byte(port))

	// Length of payload (2 bytes, big-endian).
	buf = append(buf, byte(len(payload)>>8), byte(len(payload)))
	buf = append(buf, '\r', '\n')
	buf = append(buf, payload...)

	_, err := w.Write(buf)
	return err
}

// ReadUDPPacket reads a Trojan UDP packet frame from r.
func ReadUDPPacket(r io.Reader) (atyp byte, addr string, port uint16, payload []byte, err error) {
	// Read address type.
	atypBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, atypBuf); err != nil {
		return 0, "", 0, nil, fmt.Errorf("read UDP atyp: %w", err)
	}
	atyp = atypBuf[0]

	// Read address.
	switch atyp {
	case AtypIPv4:
		ab := make([]byte, 4)
		if _, err := io.ReadFull(r, ab); err != nil {
			return 0, "", 0, nil, err
		}
		addr = net.IP(ab).String()

	case AtypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return 0, "", 0, nil, err
		}
		db := make([]byte, lb[0])
		if _, err := io.ReadFull(r, db); err != nil {
			return 0, "", 0, nil, err
		}
		addr = string(db)

	case AtypIPv6:
		ab := make([]byte, 16)
		if _, err := io.ReadFull(r, ab); err != nil {
			return 0, "", 0, nil, err
		}
		addr = net.IP(ab).String()

	default:
		return 0, "", 0, nil, fmt.Errorf("unsupported UDP address type: %d", atyp)
	}

	// Read port.
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return 0, "", 0, nil, err
	}
	port = binary.BigEndian.Uint16(portBuf)

	// Read payload length + CRLF.
	lenCRLF := make([]byte, 4) // 2 bytes length + 2 bytes CRLF
	if _, err := io.ReadFull(r, lenCRLF); err != nil {
		return 0, "", 0, nil, err
	}
	payloadLen := binary.BigEndian.Uint16(lenCRLF[:2])

	// Read payload.
	payload = make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, "", 0, nil, err
	}

	return atyp, addr, port, payload, nil
}

// encodeAddress encodes an address based on its type for the wire format.
func encodeAddress(atyp byte, addr string) []byte {
	switch atyp {
	case AtypIPv4:
		ip := net.ParseIP(addr).To4()
		return ip

	case AtypDomain:
		buf := make([]byte, 1+len(addr))
		buf[0] = byte(len(addr))
		copy(buf[1:], addr)
		return buf

	case AtypIPv6:
		ip := net.ParseIP(addr).To16()
		return ip

	default:
		return nil
	}
}

// AddrToTrojan converts a "host:port" string to Trojan address type, address, and port.
func AddrToTrojan(address string) (atyp byte, addr string, port uint16, err error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return 0, "", 0, err
	}

	p, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return 0, "", 0, err
	}
	port = uint16(p)

	ip := net.ParseIP(host)
	if ip == nil {
		// It's a domain name.
		return AtypDomain, host, port, nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return AtypIPv4, host, port, nil
	}
	return AtypIPv6, host, port, nil
}
