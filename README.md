# Wisp

A stealth VPN that hides in plain sight. Your traffic looks like normal HTTPS browsing — undetectable by deep packet inspection, active probing, and traffic analysis.

## How it works

```
Your device ──HTTPS──> yoursite.com:443
                           │
                   ┌───────┴───────┐
                   │   Wisp auth   │
                   └───┬───────┬───┘
                    OK │       │ FAIL
                       ▼       ▼
                   VPN tunnel  Real website
```

To the outside world, your server is just a normal website. Wisp sits behind TLS on port 443 and authenticates clients using the [Trojan protocol](https://trojan-gfw.github.io/trojan/). Failed authentication? The connection is silently forwarded to your real website — probers, scanners, and censors see nothing unusual.

## Features

- **Undetectable traffic** — TLS 1.3 with real certificates. Browser-identical TLS fingerprints via [uTLS](https://github.com/refraction-networking/utls)
- **Active probe resistant** — Failed auth seamlessly falls through to your real website
- **Multiple transports** — Direct TLS, WebSocket, or gRPC-style streaming
- **Inner encryption** — ChaCha20-Poly1305 layer inside TLS (survives MITM with government CAs)
- **Connection multiplexing** — Single persistent TLS connection, like a real browser
- **Traffic camouflage** — Fake HTTP noise during idle periods defeats traffic analysis
- **Multi-user** — Named users with per-user bandwidth quotas and speed limits
- **iOS & Android** — Works with Shadowrocket, v2rayNG, and other Trojan-compatible clients
- **Admin stats** — Real-time per-user traffic monitoring via Unix socket
- **Zero config cover** — Serve a cover website directly or proxy to an existing one

## Quick start

### 1. Build

```bash
# Server (Linux)
GOOS=linux GOARCH=amd64 go build -o wisp-server ./cmd/server

# Client (macOS)
go build -o wisp-client ./cmd/client

# Client (Windows)
GOOS=windows GOARCH=amd64 go build -o wisp-client.exe ./cmd/client
```

### 2. Server setup

Get a VPS, point a domain at it, then:

```bash
# Get TLS certificate
certbot certonly --standalone -d yourdomain.com

# Create config
cp configs/server.example.yaml /etc/wisp/server.yaml
# Edit with your domain, cert paths, and passwords

# Run
./wisp-server -config /etc/wisp/server.yaml
```

### 3. Connect

**Desktop:**
```bash
./wisp-client -config client.yaml
# SOCKS5 proxy now running on 127.0.0.1:1080
# Configure your browser/system to use it
```

**iPhone (Shadowrocket):**
- Add server → Type: Trojan
- Address: `yourdomain.com`, Port: `443`
- Password: your password

**Android (v2rayNG):**
- Add server → Trojan
- Same settings as above

## Configuration

### Server

```yaml
listen: ":443"

tls:
  cert: "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
  key: "/etc/letsencrypt/live/yourdomain.com/privkey.pem"

users:
  - name: "alice"
    password: "strong-random-password"
  - name: "bob"
    password: "another-password"
    max_speed: "10MB"       # 10 MB/s speed cap (optional)
    max_bandwidth: "50GB"   # Monthly quota (optional)

fallback: "127.0.0.1:80"   # Your real website

websocket:
  enabled: true
  path: "/api/v1/stream"

encryption:
  enabled: true
  key: "shared-secret-key"
```

### Client

```yaml
server: "yourdomain.com:443"
password: "strong-random-password"
sni: "yourdomain.com"
listen: "127.0.0.1:1080"
fingerprint: "chrome"       # chrome, firefox, safari, edge, ios
transport: "grpc"           # tls, ws, grpc
ws_path: "/api/v1/stream"

encryption:
  enabled: true
  key: "shared-secret-key"
```

### Transport modes

| Mode | DPI sees | Speed | Best for |
|------|----------|-------|----------|
| `tls` | HTTPS connection | Fastest | Default use |
| `ws` | WebSocket upgrade | Fast | CDN compatibility |
| `grpc` | gRPC API stream | Fast | Maximum stealth |

## Monitoring

Check per-user traffic stats:

```bash
sudo curl -s --unix-socket /run/wisp-admin.sock http://localhost/stats/text
```

```
User          Upload      Download    Quota                    Conns  Last seen
alice         up: 1.2 GB  down: 8.4 GB  quota: unlimited       45     2s
bob           up: 500 MB  down: 2.1 GB  quota: 2.6 GB / 50 GB  12     1m30s
```

JSON endpoint also available at `/stats`.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Client                         │
│                                                  │
│  App → SOCKS5 → [Trojan] → [Encryption] → [Mux] │
│                     ↓                             │
│              [Transport: TLS/WS/gRPC]             │
│                     ↓                             │
│              [uTLS: Chrome fingerprint]            │
└─────────────────┬───────────────────────────────┘
                  │ Looks like normal HTTPS
                  ▼
┌─────────────────────────────────────────────────┐
│                   Server (:443)                   │
│                                                   │
│  TLS termination (real Let's Encrypt cert)        │
│       ↓                                           │
│  HTTP? → [Cover website / Fallback]               │
│  Auth OK? → [Encryption] → [Mux] → [Proxy]       │
│       ↓                              ↓            │
│  Per-user stats + speed limiting    Internet      │
└───────────────────────────────────────────────────┘
```

## Detection resistance

| Technique | What it defeats |
|-----------|----------------|
| TLS 1.3 + real cert | Content inspection |
| uTLS browser fingerprint | TLS ClientHello fingerprinting (TSPU) |
| Cover website fallback | Active probing |
| gRPC/WebSocket transport | Protocol detection |
| ChaCha20 inner encryption | Government CA MITM attacks |
| Connection multiplexing | Connection pattern analysis |
| Traffic noise injection | Idle traffic analysis |
| ALPN negotiation | ALPN-based filtering |

## Deployment tips

- **Domain**: Use a normal-looking domain (`.com`, `.io`, `.agency`). Register through a non-local registrar
- **VPS**: Hetzner, Oracle Cloud, or any provider whose IPs aren't mass-blocked in your region
- **Cover site**: Run a real website (WordPress, blog, business page) on the same server
- **Port**: Only expose port 443. No other ports should be open
- **Cert renewal**: Certbot auto-renews. Add pre/post hooks if another service uses port 80

## Building from source

Requires Go 1.22+.

```bash
git clone https://github.com/awisp/wisp.git
cd wisp
go build ./...
```

## License

MIT
