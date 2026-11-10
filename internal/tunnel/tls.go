package tunnel

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
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
	certs := &certReloader{certFile: certFile, keyFile: keyFile}
	if _, err := certs.get(nil); err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		GetCertificate: certs.get,
		MinVersion:     tls.VersionTLS12, // Accept TLS 1.2 too — TLS 1.3-only is suspicious.
		NextProtos:     []string{"http/1.1"},
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

// certReloader serves the certificate from its files and reads them again when they change, so a
// renewal (certbot replaces them every 60 days or so) takes effect without a restart.
type certReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime time.Time
	checked time.Time
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert != nil && time.Since(r.checked) < time.Minute {
		return r.cert, nil
	}
	r.checked = time.Now()
	fi, err := os.Stat(r.certFile) // follows certbot's symlinks into archive/
	if err == nil && r.cert != nil && fi.ModTime().Equal(r.modTime) {
		return r.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		if r.cert != nil {
			log.Printf("reload certificate: %v; keeping the one loaded", err)
			return r.cert, nil
		}
		return nil, err
	}
	if r.cert != nil {
		log.Printf("certificate reloaded from %s", r.certFile)
	}
	r.cert = &cert
	if fi != nil {
		r.modTime = fi.ModTime()
	}
	return r.cert, nil
}

// handshakeTimeout bounds a TLS handshake: some networks let the TCP connection through and then
// drop every packet, and the client would wait forever.
const handshakeTimeout = 15 * time.Second

// DialTLS connects to a remote server using uTLS to produce a TLS ClientHello
// that is byte-identical to a real browser. This is critical for defeating
// Russia's TSPU DPI which fingerprints TLS handshakes. With pins, the server's
// certificate must also carry one of the pinned keys.
func DialTLS(addr, sni, fingerprint string, pins []string) (net.Conn, error) {
	// Use a dialer with timeout and keepalive that mimics browser behavior.
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second, // Browsers use 30-45s keepalive.
	}
	return DialTLSWithDialer(dialer, addr, sni, fingerprint, pins)
}

// DialTLSWithDialer is like DialTLS but uses a custom dialer.
// Useful for connecting through a specific network interface or local proxy.
func DialTLSWithDialer(dialer *net.Dialer, addr, sni, fingerprint string, pins []string) (net.Conn, error) {
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
	if len(pins) > 0 {
		tlsConfig.VerifyPeerCertificate = verifyPins(pins)
	}

	uConn := utls.UClient(rawConn, tlsConfig, clientHelloID)
	rawConn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	rawConn.SetDeadline(time.Time{})

	return uConn, nil
}

// Pin is a certificate's pin: "sha256/" and the base64 SHA-256 of its public key, the format of
// HTTP public key pinning. A certificate renewed with the same key keeps its pin.
func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
}

// verifyPins accepts the server's certificate only if its key is one of pins. It runs after the
// usual checks, so a certificate from a CA the system trusts, a government's included, fails
// unless its key is pinned: TLS interception fails instead of reading the tunnel.
func verifyPins(pins []string) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("no server certificate")
		}
		leaf, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		got := Pin(leaf)
		for _, p := range pins {
			if p == got {
				return nil
			}
		}
		return fmt.Errorf("the server's key %s isn't pinned: someone may be intercepting TLS", got)
	}
}

// selectFingerprint maps a fingerprint name to a uTLS ClientHelloID. The presets are uTLS's
// current browsers (Chrome 155, Firefox 148, Safari 26.3): an old browser's handshake is rare
// enough to stand out, and censors single some out (Russia's TSPU blocks uTLS's Chrome 133). Edge
// is Chromium, so it gets Chrome's handshake; iOS gets Safari's.
func selectFingerprint(name string) utls.ClientHelloID {
	switch name {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari", "ios":
		return utls.HelloSafari_Auto
	default: // chrome, edge
		return utls.HelloChrome_Auto
	}
}
