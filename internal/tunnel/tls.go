package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// RootCAs are the CAs the client trusts for the server's certificate: nil means the system's.
// Tests set their own.
var RootCAs *x509.CertPool

// NewTLSListener creates a TLS listener using real certificates.
// The server-side TLS config is tuned to look like a standard web server:
//   - Supports TLS 1.2+ (not just 1.3) because restricting to 1.3-only is a fingerprint
//   - ALPN offers h2 only with h2 true, when the cover site can answer HTTP/2: a browser that
//     negotiated h2 and got an HTTP/1.1 reply would show an error, to visitors and probes alike
func NewTLSListener(addr, certFile, keyFile string, h2 bool) (net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // Accept TLS 1.2 too — TLS 1.3-only is suspicious.
		NextProtos:   []string{"http/1.1"},
	}
	if h2 {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}

	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("tls listen: %w", err)
	}

	return listener, nil
}

// DialTLS connects to a remote server using uTLS to produce a TLS ClientHello
// that is byte-identical to a real browser. This is critical for defeating
// Russia's TSPU DPI which fingerprints TLS handshakes.
func DialTLS(addr, sni, fingerprint string) (net.Conn, error) {
	// Use a dialer with timeout and keepalive that mimics browser behavior.
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second, // Browsers use 30-45s keepalive.
	}

	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	clientHelloID := selectFingerprint(fingerprint)

	tlsConfig := &utls.Config{
		ServerName: sni,
		RootCAs:    RootCAs,
		// Do NOT set MinVersion to TLS 1.3 — let uTLS handle it.
		// Real browsers advertise TLS 1.2 in ClientHello but negotiate 1.3.
		// Setting MinVersion here would alter the ClientHello fingerprint.
		NextProtos: []string{"h2", "http/1.1"}, // ALPN like a real browser.
	}

	uConn := utls.UClient(rawConn, tlsConfig, clientHelloID)

	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	return uConn, nil
}

// DialTLSWithDialer is like DialTLS but uses a custom dialer.
// Useful for connecting through a specific network interface or local proxy.
func DialTLSWithDialer(dialer *net.Dialer, addr, sni, fingerprint string) (net.Conn, error) {
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	clientHelloID := selectFingerprint(fingerprint)

	tlsConfig := &utls.Config{
		ServerName: sni,
		RootCAs:    RootCAs,
		NextProtos: []string{"h2", "http/1.1"},
	}

	uConn := utls.UClient(rawConn, tlsConfig, clientHelloID)
	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	return uConn, nil
}

// selectFingerprint maps a fingerprint name to a uTLS ClientHelloID.
// For Russia, "chrome" is the safest — Chrome is the most popular browser.
func selectFingerprint(name string) utls.ClientHelloID {
	switch name {
	case "chrome":
		return utls.HelloChrome_Auto
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "random":
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}
