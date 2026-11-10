package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olegnazarov23/wisp/internal/protocol"
	"github.com/olegnazarov23/wisp/internal/proxy"
	"github.com/olegnazarov23/wisp/internal/stats"
	"github.com/olegnazarov23/wisp/internal/tunnel"
	"github.com/olegnazarov23/wisp/pkg/config"
)

const (
	alicePassword = "alice-password-123"
	bobPassword   = "bob-password-456"
	innerKey      = "test-inner-key"
	wsPath        = "/stream-test"
)

// The client and the server from this repo, end to end over every transport, with a cover site
// and an echo server standing in for the internet.
func TestTransports(t *testing.T) {
	env := newEnv(t, false)
	for _, enc := range []string{"", innerKey} {
		addr := env.server(t, enc)
		for _, transport := range []string{"tls", "ws", "grpc"} {
			name := transport
			if enc != "" {
				name += "+encryption"
			}
			t.Run(name, func(t *testing.T) {
				client := &proxy.SOCKS5Server{
					ServerAddr:    addr,
					SNI:           "wisp.test",
					Fingerprint:   "chrome",
					PasswordHash:  config.HashPassword(alicePassword),
					Transport:     transport,
					WSPath:        wsPath,
					EncryptionKey: enc,
				}
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				go client.Serve(l)

				for i := range 3 {
					c := socksConnect(t, l.Addr().String(), env.echo)
					want := fmt.Sprintf("hello %d over %s", i, name)
					if _, err := c.Write([]byte(want)); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(want))
					if _, err := io.ReadFull(c, got); err != nil {
						t.Fatalf("read echo: %v", err)
					}
					if string(got) != want {
						t.Fatalf("echo: got %q, want %q", got, want)
					}
					c.Close()
				}
			})
		}
	}
}

// Trojan clients such as Shadowrocket: one proxied connection per TLS connection.
func TestPlainTrojan(t *testing.T) {
	env := newEnv(t, false)
	addr := env.server(t, innerKey)

	c := env.dialTLS(t, addr, "http/1.1")
	req := trojanRequest(t, env.echo)
	if err := protocol.WriteRequest(c, config.HashPassword(alicePassword), req, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo: got %q, %v", got, err)
	}
}

// A user over their quota gets nothing, over plain Trojan as over a mux session.
func TestQuota(t *testing.T) {
	env := newEnv(t, false)
	addr := env.server(t, "")
	stats.Global.GetOrCreate("bob").Upload.Add(100)
	stats.Global.SetLimit("bob", 50)
	defer stats.Global.SetLimit("bob", 0)

	c := env.dialTLS(t, addr, "http/1.1")
	if err := protocol.WriteRequest(c, config.HashPassword(bobPassword), trojanRequest(t, env.echo), []byte("ping")); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 4)); err == nil {
		t.Fatalf("got %d bytes back over quota", n)
	}
}

// What a prober or a browser sees: the cover site, whatever it sends.
func TestFallback(t *testing.T) {
	env := newEnv(t, false)
	addr := env.server(t, innerKey)

	for name, send := range map[string]string{
		"http":       "GET /page HTTP/1.1\r\nHost: wisp.test\r\nConnection: close\r\n\r\n",
		"wrong hash": strings.Repeat("a", protocol.HashLen) + "\r\n\x01\x01\x7f\x00\x00\x01\x00\x50\r\n",
		"garbage":    "\x16\x03\x01 not a request at all, long enough to pass the 56-byte peek\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			c := env.dialTLS(t, addr, "http/1.1")
			if _, err := c.Write([]byte(send)); err != nil {
				t.Fatal(err)
			}
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			reply, _ := io.ReadAll(io.LimitReader(c, 4096))
			if !strings.Contains(string(reply), "HTTP/1.1") {
				t.Fatalf("expected the cover site's answer, got %q", reply)
			}
		})
	}
}

// HTTP/2 is offered only when a cover site can answer it, and then the browser gets HTTP/2.
func TestHTTP2(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("fallback_h2=%v", h2), func(t *testing.T) {
			env := newEnv(t, h2)
			addr := env.server(t, "")
			client := &http.Client{Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{RootCAs: env.roots, ServerName: "wisp.test"},
				ForceAttemptHTTP2: true,
			}}
			resp, err := client.Get("https://" + addr + "/page")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			want := "HTTP/1.1"
			if h2 {
				want = "HTTP/2.0"
			}
			if resp.Proto != want || !strings.Contains(string(body), "cover site") {
				t.Fatalf("got %s %q, want %s from the cover site", resp.Proto, body, want)
			}
		})
	}
}

// One frame with a huge length used to crash the whole server, before any authentication.
func TestWebSocketBadFrames(t *testing.T) {
	env := newEnv(t, false)
	addr := env.server(t, innerKey)

	for name, frame := range map[string]string{
		"ping, 2^64-1 bytes":           "\x89\x7f\xff\xff\xff\xff\xff\xff\xff\xff",
		"masked binary, negative size": "\x82\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\x02\x03\x04",
		"ping, 126 bytes":              "\x89\x7e\x00\x7e",
	} {
		t.Run(name, func(t *testing.T) {
			c := env.dialTLS(t, addr, "http/1.1")
			upgrade := "GET " + wsPath + " HTTP/1.1\r\nHost: wisp.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
			start := time.Now()
			c.Write([]byte(upgrade + frame))
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			io.ReadAll(c)
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("the frame wasn't refused: the connection stayed open %v", d)
			}
		})
	}

	// and it's still serving
	c := env.dialTLS(t, addr, "http/1.1")
	protocol.WriteRequest(c, config.HashPassword(alicePassword), trojanRequest(t, env.echo), []byte("ping"))
	if got := readN(t, c, 4); string(got) != "ping" {
		t.Fatalf("echo after bad frames: %q", got)
	}
}

// The cover site gets requests exactly as sent, answers them as fast as it would directly, and
// its closing the connection closes it for the client too.
func TestFallbackFaithful(t *testing.T) {
	env := newEnv(t, false)
	addr := env.server(t, "")

	for _, tc := range []struct{ name, send, want string }{
		{"HTTP/1.0 stays 1.0", "GET /old HTTP/1.0\r\n\r\n", "GET /old HTTP/1.0"},
		{"pipelined requests", "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", "GET /b"},
		{"unlisted method, short", "TRACE / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", "TRACE /"},
		{"garbage", "garbage\r\n\r\n", "400 Bad Request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := env.dialTLS(t, addr, "http/1.1")
			start := time.Now()
			c.Write([]byte(tc.send))
			c.SetReadDeadline(time.Now().Add(8 * time.Second))
			reply, err := io.ReadAll(c)
			if err != nil {
				t.Fatalf("the connection didn't close with the cover site's: %v after %v", err, time.Since(start))
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("answered after %v", d)
			}
			if !strings.Contains(string(reply), tc.want) {
				t.Fatalf("got %q, want %q in it", reply, tc.want)
			}
		})
	}
}

// Users can't reach the server's own network unless allow_private says so.
func TestPrivateDestinations(t *testing.T) {
	env := newEnv(t, false)
	addr := env.server(t, "", func(h *Handler) { h.AllowPrivate = false })

	c := env.dialTLS(t, addr, "http/1.1")
	protocol.WriteRequest(c, config.HashPassword(alicePassword), trojanRequest(t, env.echo), []byte("ping"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 4)); err == nil {
		t.Fatalf("reached a loopback address: %d bytes back", n)
	}
}

// A destination that closes its side: the app sees the end, instead of waiting forever.
func TestClosePropagates(t *testing.T) {
	env := newEnv(t, false)
	addr := env.server(t, innerKey)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("hello"))
			c.Close()
		}
	}()

	for _, transport := range []string{"tls", "ws"} {
		t.Run(transport, func(t *testing.T) {
			client := &proxy.SOCKS5Server{
				ServerAddr: addr, SNI: "wisp.test", Fingerprint: "chrome", WSPath: wsPath,
				PasswordHash: config.HashPassword(alicePassword), Transport: transport, EncryptionKey: innerKey,
			}
			sl, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer sl.Close()
			go client.Serve(sl)

			c := socksConnect(t, sl.Addr().String(), l.Addr().String())
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			got, err := io.ReadAll(c)
			if err != nil || string(got) != "hello" {
				t.Fatalf("got %q, %v; want hello, then the end", got, err)
			}
		})
	}
}

type env struct {
	roots             *x509.CertPool
	certFile, keyFile string
	cover, coverH2    string
	echo              string
}

func newEnv(t *testing.T, h2 bool) *env {
	e := &env{}
	e.roots, e.certFile, e.keyFile = testCerts(t)
	tunnel.RootCAs = e.roots
	t.Cleanup(func() { tunnel.RootCAs = nil })

	cover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "cover site: %s %s %s\n", r.Method, r.URL.Path, r.Proto)
	})
	e.cover = serveHTTP(t, cover, false)
	if h2 {
		e.coverH2 = serveHTTP(t, cover, true)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	e.echo = l.Addr().String()
	return e
}

// server starts a wisp server with the users alice and bob and returns its address. Users may
// reach private addresses, the test's servers among them, unless an option says otherwise.
func (e *env) server(t *testing.T, encKey string, opts ...func(*Handler)) string {
	alice, bob := config.HashPassword(alicePassword), config.HashPassword(bobPassword)
	h := &Handler{
		PasswordHashes: map[string]bool{alice: true, bob: true},
		UserNames:      map[string]string{alice: "alice", bob: "bob"},
		UserSpeeds:     map[string]int64{},
		FallbackAddr:   e.cover,
		FallbackH2Addr: e.coverH2,
		WSConfig:       &config.WSConfig{Enabled: true, Path: wsPath},
		EncryptionKey:  encKey,
		AllowPrivate:   true,
	}
	for _, opt := range opts {
		opt(h)
	}
	l, err := tunnel.NewTLSListener("127.0.0.1:0", e.certFile, e.keyFile, e.coverH2 != "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go h.Handle(c)
		}
	}()
	return l.Addr().String()
}

func (e *env) dialTLS(t *testing.T, addr, alpn string) *tls.Conn {
	c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: e.roots, ServerName: "wisp.test", NextProtos: []string{alpn}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// serveHTTP serves h on a free local port, over HTTP/2 without TLS too with h2c.
func serveHTTP(t *testing.T, h http.Handler, h2c bool) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	if h2c {
		srv.Protocols = new(http.Protocols)
		srv.Protocols.SetHTTP1(true)
		srv.Protocols.SetUnencryptedHTTP2(true)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return l.Addr().String()
}

// socksConnect opens a SOCKS5 CONNECT to target (an IPv4 host:port) through the proxy at addr.
func socksConnect(t *testing.T, addr, target string) net.Conn {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if b := readN(t, c, 2); b[0] != 5 || b[1] != 0 {
		t.Fatalf("socks5 method reply %v", b)
	}
	host, port, _ := net.SplitHostPort(target)
	var p int
	fmt.Sscan(port, &p)
	req := append([]byte{5, 1, 0, 1}, net.ParseIP(host).To4()...)
	req = append(req, byte(p>>8), byte(p))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	if b := readN(t, c, 10); b[1] != 0 {
		t.Fatalf("socks5 connect reply %v", b)
	}
	return c
}

func readN(t *testing.T, r io.Reader, n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func trojanRequest(t *testing.T, target string) *protocol.Request {
	atyp, host, port, err := protocol.AddrToTrojan(target)
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.Request{Cmd: protocol.CmdConnect, ATyp: atyp, DstAddr: host, DstPort: port}
}

// testCerts makes a CA and a certificate for wisp.test it signed, and returns the CA as a pool
// and the certificate and key as files.
func testCerts(t *testing.T) (*x509.CertPool, string, string) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "wisp test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "wisp.test"}, DNSNames: []string{"wisp.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)

	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, certFile, keyFile
}
