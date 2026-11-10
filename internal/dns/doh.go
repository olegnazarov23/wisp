package dns

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// DoHResolver resolves DNS queries using DNS-over-HTTPS.
// This prevents DNS leaks — your ISP never sees what domains you're accessing.
type DoHResolver struct {
	// URL is the DoH endpoint. Defaults to Google DNS.
	URL    string
	client *http.Client
}

// Common DoH providers (not blocked in most countries).
const (
	GoogleDoH  = "https://dns.google/dns-query"
	Quad9DoH   = "https://dns.quad9.net:5053/dns-query"
	AdGuardDoH = "https://dns.adguard-dns.com/dns-query"
)

// NewDoHResolver creates a resolver using the given DoH endpoint.
func NewDoHResolver(url string) *DoHResolver {
	if url == "" {
		url = GoogleDoH
	}
	return &DoHResolver{
		URL: url,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Resolve performs a DNS lookup via DoH and returns the IP addresses.
func (r *DoHResolver) Resolve(name string) ([]net.IP, error) {
	// Build a minimal DNS query (A record).
	query := buildDNSQuery(name, 1) // Type A = 1

	// Encode as base64url for GET request (RFC 8484).
	encoded := base64.RawURLEncoding.EncodeToString(query)

	req, err := http.NewRequest("GET", r.URL+"?dns="+encoded, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("doh status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return parseDNSResponse(body)
}

// buildDNSQuery constructs a minimal DNS query packet.
func buildDNSQuery(name string, qtype uint16) []byte {
	// DNS header: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
	buf := make([]byte, 0, 512)

	// Header.
	buf = append(buf, 0x00, 0x00) // ID = 0 (DoH doesn't need it).
	buf = append(buf, 0x01, 0x00) // Flags: RD=1 (recursion desired).
	buf = append(buf, 0x00, 0x01) // QDCOUNT = 1
	buf = append(buf, 0x00, 0x00) // ANCOUNT = 0
	buf = append(buf, 0x00, 0x00) // NSCOUNT = 0
	buf = append(buf, 0x00, 0x00) // ARCOUNT = 0

	// Question: encode domain name.
	buf = encodeDNSName(buf, name)

	// QTYPE and QCLASS.
	buf = append(buf, byte(qtype>>8), byte(qtype)) // Type A or AAAA
	buf = append(buf, 0x00, 0x01)                  // Class IN

	return buf
}

func encodeDNSName(buf []byte, name string) []byte {
	// Split domain into labels and encode.
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			if len(label) > 0 {
				buf = append(buf, byte(len(label)))
				buf = append(buf, []byte(label)...)
			}
			start = i + 1
		}
	}
	buf = append(buf, 0x00) // Root label.
	return buf
}

// parseDNSResponse extracts IP addresses from a DNS response packet.
func parseDNSResponse(data []byte) ([]net.IP, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	// Parse header.
	ancount := int(data[6])<<8 | int(data[7])
	if ancount == 0 {
		return nil, fmt.Errorf("no answers")
	}

	// Skip the question section.
	offset := 12
	// Skip QNAME.
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xC0 == 0xC0 {
			// Pointer.
			offset += 2
			break
		}
		offset += 1 + length
	}
	offset += 4 // Skip QTYPE(2) + QCLASS(2).

	// Parse answer records.
	var ips []net.IP
	for i := 0; i < ancount && offset < len(data); i++ {
		// Skip NAME (may be pointer).
		if offset >= len(data) {
			break
		}
		if data[offset]&0xC0 == 0xC0 {
			offset += 2 // Pointer.
		} else {
			for offset < len(data) {
				length := int(data[offset])
				if length == 0 {
					offset++
					break
				}
				offset += 1 + length
			}
		}

		if offset+10 > len(data) {
			break
		}

		rtype := int(data[offset])<<8 | int(data[offset+1])
		// rclass at offset+2
		// ttl at offset+4
		rdlength := int(data[offset+8])<<8 | int(data[offset+9])
		offset += 10

		if offset+rdlength > len(data) {
			break
		}

		if rtype == 1 && rdlength == 4 {
			// A record.
			ip := net.IPv4(data[offset], data[offset+1], data[offset+2], data[offset+3])
			ips = append(ips, ip)
		} else if rtype == 28 && rdlength == 16 {
			// AAAA record.
			ip := make(net.IP, 16)
			copy(ip, data[offset:offset+16])
			ips = append(ips, ip)
		}

		offset += rdlength
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no A/AAAA records found")
	}

	return ips, nil
}
