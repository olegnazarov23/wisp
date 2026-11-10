<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo/wisp-logo-dark.svg">
    <img alt="wisp" src="docs/logo/wisp-logo.svg" height="64">
  </picture>
</h1>

A stealth VPN that hides in plain sight. To the network, your traffic is ordinary HTTPS to an
ordinary website. Wisp is built to resist deep packet inspection, active probing and traffic
analysis.

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

To the outside world, your server is just a website. Wisp listens for TLS on port 443 and
authenticates clients with the [Trojan protocol](https://trojan-gfw.github.io/trojan/). A
connection that doesn't authenticate is passed to your real website, so probers, scanners and
censors see an ordinary site.

## Features

- **Looks like a browser.** TLS with a real certificate, and a client whose TLS handshake matches
  Chrome's, Firefox's or Safari's, via [uTLS](https://github.com/refraction-networking/utls).
- **Resists active probing.** Anyone who doesn't authenticate gets your website.
- **Three transports.** Trojan straight over TLS, WebSocket, or an HTTP stream that looks like gRPC.
- **Inner encryption (optional).** XChaCha20-Poly1305 inside TLS, with a key you share between
  server and clients, so content stays private even if TLS is intercepted, for example with a
  government-issued CA.
- **Multiplexing.** The desktop client carries all its connections over one TLS connection, like
  a browser.
- **Noise.** The client sends a small random message every 2 to 8 seconds, so an idle tunnel
  isn't silent.
- **Multiple users.** Named users, each with an optional speed limit and data quota.
- **Phones.** Shadowrocket, v2rayNG and other Trojan clients connect too.
- **Stats.** Per-user traffic over a local Unix socket.
- **Cover site.** Serve a directory of files, or pass visitors to a web server you already run.

## Quick start

### 1. Build

Requires Go 1.26 or newer.

```bash
# Server (Linux)
GOOS=linux GOARCH=amd64 go build -o wisp-server ./cmd/server

# Client (macOS)
go build -o wisp-client ./cmd/client

# Client (Windows)
GOOS=windows GOARCH=amd64 go build -o wisp-client.exe ./cmd/client
```

### 2. Set up the server

Get a VPS and point a domain at it. On Debian or Ubuntu, `scripts/install.sh` does the rest:
the certificate, a cover site behind Caddy, the config and a systemd service. Run it from the
checkout, with `wisp-server` built in the checkout's top directory:

```bash
sudo ./scripts/install.sh -d yourdomain.com -p 'a-long-random-password'
```

Or by hand:

```bash
# A TLS certificate
sudo certbot certonly --standalone -d yourdomain.com

# The config: set your domain, certificate paths and passwords
sudo mkdir -p /etc/wisp
sudo cp configs/server.example.yaml /etc/wisp/server.yaml

# Run (port 443 needs root, or CAP_NET_BIND_SERVICE)
sudo ./wisp-server -config /etc/wisp/server.yaml
```

### 3. Connect

**Desktop:**
```bash
./wisp-client -config client.yaml
# SOCKS5 proxy now running on 127.0.0.1:1080
# Point your browser or system proxy settings at it
```

**iPhone (Shadowrocket):**
- Add server → Type: Trojan
- Address: `yourdomain.com`, Port: `443`
- Password: your password

**Android (v2rayNG):**
- Add server → Trojan
- Same settings as above

Phone apps speak plain Trojan over TLS: they don't use the WebSocket or gRPC transports, the
inner encryption or multiplexing.

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
    max_speed: "10MB"       # 10 MB/s, shared by all of bob's connections (optional)
    max_bandwidth: "50GB"   # Data quota, counted since the server started (optional)

fallback: "127.0.0.1:80"        # Your real website
fallback_h2: "127.0.0.1:8080"   # The same site over HTTP/2 without TLS (h2c), optional

websocket:
  enabled: true
  path: "/api/v1/stream"    # Pick your own: anyone who knows it gets past the cover site

encryption:
  enabled: true
  key: "shared-secret-key"  # A long random string, the same on every client
```

Instead of `users`, a plain `passwords:` list works too; its traffic shows up as "anonymous".
`cover_site: /path/to/site` serves HTTP visitors from a directory of files instead of `fallback`.

Browsers ask for HTTP/2. Wisp offers it only when `fallback_h2` points at a server that speaks
HTTP/2 without TLS (Caddy with `protocols h1 h2c`, as `scripts/install.sh` sets it up); without it,
browsers use HTTP/1.1.

### Client

```yaml
server: "yourdomain.com:443"
password: "strong-random-password"
sni: "yourdomain.com"
listen: "127.0.0.1:1080"
fingerprint: "chrome"       # chrome, firefox, safari, edge, ios or random
transport: "tls"            # tls (the default), ws or grpc
ws_path: "/api/v1/stream"   # The server's websocket path, for ws and grpc

encryption:
  enabled: true
  key: "shared-secret-key"
```

### Transports

Each one runs inside TLS, so on the wire all three look like HTTPS to your site.

| Transport | Inside TLS | Use it |
|------|----------|-------|
| `tls` | A Trojan header, then the tunnel | By default: fastest |
| `ws` | A WebSocket upgrade on your path | Behind a CDN that passes WebSockets |
| `grpc` | An HTTP POST on your path, answered like gRPC | Where WebSockets get blocked |

## Monitoring

Check per-user traffic:

```bash
sudo curl -s --unix-socket /run/wisp-admin.sock http://localhost/stats/text
```

```
User          Upload      Download    Quota                       Conns  Last seen
alice         1.2 GB      8.4 GB      unlimited                      45  2s
bob           500.0 MB    2.1 GB      2.6 GB / 50.0 GB (5%)          12  1m30s
```

The same as JSON at `/stats`.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                       Client                        │
│                                                     │
│  App → SOCKS5 → [Trojan request per connection]     │
│                  → [Mux] → [Inner encryption]       │
│                  → [Transport: TLS / WS / gRPC]     │
│                  → [uTLS: a browser's handshake]    │
└──────────────────────────┬──────────────────────────┘
                           │ Looks like normal HTTPS
                           ▼
┌─────────────────────────────────────────────────────┐
│                   Server (:443)                     │
│                                                     │
│  TLS (a real certificate, e.g. Let's Encrypt)       │
│    → not authenticated: [cover site / fallback]     │
│    → authenticated: [Inner encryption] → [Mux]      │
│        → [Per-user stats and limits] → Internet     │
└─────────────────────────────────────────────────────┘
```

## Detection resistance

| Technique | What it counters |
|-----------|----------------|
| TLS with a real certificate | Reading the traffic |
| uTLS browser handshake | TLS ClientHello fingerprinting (e.g. Russia's TSPU) |
| Cover site for anyone who doesn't authenticate | Active probing |
| WebSocket and gRPC-style transports | Networks and CDNs that only pass web traffic |
| Inner encryption | Reading traffic through intercepted TLS (government CAs) |
| Multiplexing | Patterns in how many connections a client opens |
| Noise | Telling an idle tunnel from a busy one |
| HTTP/2 offered only with an HTTP/2 cover site | Probes that try HTTP/2 |

## Limits

- **TLS inside TLS.** Browsing HTTPS sites through any TLS tunnel shows a pattern: the inner
  handshakes' sizes and timing. Wisp doesn't pad traffic to hide it yet.
- **The WebSocket path is a password.** Anyone who knows it gets an upgrade instead of the cover
  site. Pick your own, and don't reuse the one in this README.
- **The install script's cover page** is the same on every server it installs, which makes them
  easy to find. Replace it with a site of your own.
- **Inner encryption** keeps content private from someone who intercepts TLS, but they can still
  tell it isn't a normal website. The key is one SHA-256 of the configured string, so make it long
  and random.
- **Noise** goes out every 2 to 8 seconds, all day, from client to server only. A browser doesn't
  do that, so it can stand out as much as it hides.
- **Quotas** are counted in memory: they start over when the server restarts.
- **Browser fingerprints** come from uTLS and are only as current as the uTLS version wisp was
  built with.

## Deployment tips

- **Domain**: Use a normal-looking domain (`.com`, `.io`, `.agency`). Register it through a
  registrar outside your country.
- **VPS**: Hetzner, Oracle Cloud, or any provider whose IPs aren't mass-blocked in your region.
- **Cover site**: Run a real website (WordPress, a blog, a business page) on the same server.
- **Port**: Only expose port 443. Close everything else.
- **Cert renewal**: Certbot renews automatically. Add pre/post hooks if another service uses port 80.

## Building from source

Requires Go 1.26 or newer.

```bash
git clone https://github.com/olegnazarov23/wisp.git
cd wisp
go build -o wisp-server ./cmd/server
go build -o wisp-client ./cmd/client
go test ./...
```

## Related projects

Wisp stands on the shoulders of these projects and draws inspiration from the broader anti-censorship community:

- **[Trojan](https://github.com/trojan-gfw/trojan)**: the original Trojan protocol, which showed that looking like HTTPS works. Wisp implements a compatible protocol.
- **[Xray-core](https://github.com/XTLS/Xray-core)**: a feature-rich proxy platform with VLESS, REALITY and XTLS, widely used against the Great Firewall.
- **[Shadowsocks](https://github.com/shadowsocks/shadowsocks-rust)**: the project that pioneered encrypted proxy protocols for getting past the Great Firewall.
- **[uTLS](https://github.com/refraction-networking/utls)**: makes Go's TLS handshakes match real browsers', which defeats TLS fingerprinting.
- **[Cloak](https://github.com/cbeuw/Cloak)**: a pluggable transport that multiplexes traffic through TLS with active-probe resistance.
- **[sing-box](https://github.com/SagerNet/sing-box)**: a universal proxy platform with wide protocol support and good mobile clients.
- **[V2Ray](https://github.com/v2fly/v2ray-core)**: a mature proxy platform with the VMess protocol and many transports.
- **[Tor](https://www.torproject.org/)**: the original censorship-resistance network. A different threat model, but a shared mission.

### Compatible clients

| Platform | App | Protocol |
|----------|-----|----------|
| iOS | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) | Trojan |
| iOS | [Quantumult X](https://apps.apple.com/app/quantumult-x/id1443988620) | Trojan |
| Android | [v2rayNG](https://github.com/2dust/v2rayNG) | Trojan |
| Android | [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid) | Trojan |
| Windows/macOS/Linux | Wisp client (this repo) | Everything: transports, mux, inner encryption |

## Contributing

Contributions welcome. If you're in a country with internet censorship and have ideas for
improving detection resistance, please open an issue or a pull request.

## License

MIT
