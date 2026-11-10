#!/bin/bash
set -euo pipefail

# Wisp server installation: run as root on a fresh Debian or Ubuntu server, from a checkout with
# wisp-server built next to this directory (see the README).

DOMAIN=""
PASSWORD=""
COVER_SITE="blog"  # Options: blog, business

# Percent-encodes a string for a URL.
urlencode() {
    local s="$1" out="" c i
    for (( i = 0; i < ${#s}; i++ )); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            *) out+=$(printf '%%%02X' "'$c") ;;
        esac
    done
    printf '%s' "$out"
}

usage() {
    echo "Usage: $0 -d <domain> -p <password> [-s blog|business]"
    echo ""
    echo "  -d    Your domain name (must already point to this server's IP)"
    echo "  -p    Password clients authenticate with"
    echo "  -s    Cover website style: blog (default) or business"
    exit 1
}

while getopts "d:p:s:" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        s) COVER_SITE="$OPTARG" ;;
        *) usage ;;
    esac
done

if [ -z "$DOMAIN" ] || [ -z "$PASSWORD" ]; then
    usage
fi

echo "=== Wisp server installation ==="
echo "Domain: $DOMAIN"
echo "Cover site: $COVER_SITE"
echo ""

# 1. Install dependencies.
echo "[1/6] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq caddy certbot > /dev/null

# 2. Obtain TLS certificate.
echo "[2/6] Obtaining TLS certificate..."
certbot certonly --standalone --non-interactive --agree-tos \
    --register-unsafely-without-email -d "$DOMAIN" || true

# Check if cert exists.
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
if [ ! -f "$CERT_DIR/fullchain.pem" ]; then
    echo "ERROR: Certificate not found. Make sure $DOMAIN points to this server."
    exit 1
fi

# 3. Deploy cover website.
echo "[3/6] Deploying cover website..."
WEBROOT="/var/www/cover"
mkdir -p "$WEBROOT"

if [ "$COVER_SITE" = "business" ]; then
    cat > "$WEBROOT/index.html" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Meridian Digital Solutions</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #333; }
        .header { background: #1a1a2e; color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 1.4em; }
        .nav a { color: #ccc; text-decoration: none; margin-left: 20px; }
        .hero { background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 100px 40px; text-align: center; }
        .hero h2 { font-size: 2.5em; margin-bottom: 20px; }
        .hero p { font-size: 1.2em; color: #aaa; max-width: 600px; margin: 0 auto; }
        .services { padding: 80px 40px; display: flex; justify-content: center; gap: 40px; flex-wrap: wrap; }
        .service { max-width: 300px; text-align: center; }
        .service h3 { margin: 15px 0; }
        .footer { background: #f5f5f5; padding: 40px; text-align: center; color: #666; }
    </style>
</head>
<body>
    <div class="header"><h1>Meridian Digital</h1><nav class="nav"><a href="#">Services</a><a href="#">About</a><a href="#">Contact</a></nav></div>
    <div class="hero"><h2>Digital Solutions for Modern Business</h2><p>We help companies transform their digital presence with cutting-edge technology and strategic consulting.</p></div>
    <div class="services">
        <div class="service"><h3>Cloud Infrastructure</h3><p>Scalable, secure cloud solutions tailored to your business needs.</p></div>
        <div class="service"><h3>Data Analytics</h3><p>Turn your data into actionable insights with our analytics platform.</p></div>
        <div class="service"><h3>Security Consulting</h3><p>Protect your assets with enterprise-grade security solutions.</p></div>
    </div>
    <div class="footer">&copy; 2025 Meridian Digital Solutions. All rights reserved.</div>
</body>
</html>
HTMLEOF
else
    cat > "$WEBROOT/index.html" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alex's Tech Notes</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Georgia, 'Times New Roman', serif; color: #333; max-width: 720px; margin: 0 auto; padding: 20px; }
        header { border-bottom: 1px solid #eee; padding: 30px 0; margin-bottom: 40px; }
        header h1 { font-size: 1.8em; }
        header p { color: #666; margin-top: 5px; }
        article { margin-bottom: 50px; }
        article h2 { font-size: 1.4em; margin-bottom: 10px; }
        article .meta { color: #999; font-size: 0.9em; margin-bottom: 15px; }
        article p { line-height: 1.8; margin-bottom: 15px; }
        footer { border-top: 1px solid #eee; padding-top: 20px; color: #999; font-size: 0.9em; }
    </style>
</head>
<body>
    <header><h1>Alex's Tech Notes</h1><p>Thoughts on software, systems, and the internet.</p></header>
    <article>
        <h2>On Building Reliable Distributed Systems</h2>
        <div class="meta">March 2, 2025</div>
        <p>After spending the better part of a decade building distributed systems, I've come to appreciate that the hardest problems aren't technical—they're about understanding failure modes that only emerge at scale.</p>
        <p>The CAP theorem is often cited but rarely internalized. In practice, most systems don't neatly fall into CP or AP categories. They exist on a spectrum, and the real engineering challenge is understanding where your specific use case sits on that spectrum.</p>
    </article>
    <article>
        <h2>Why I Switched to SQLite for Small Projects</h2>
        <div class="meta">February 15, 2025</div>
        <p>For years, I defaulted to PostgreSQL for everything. It's a fantastic database. But for small projects—personal tools, side projects, prototypes—it's overkill. SQLite has become my go-to, and here's why.</p>
        <p>The simplicity of a single-file database that requires zero configuration is hard to overstate. No connection pooling, no user management, no separate process to monitor. Just your application and a file.</p>
    </article>
    <footer>&copy; 2025 Alex's Tech Notes</footer>
</body>
</html>
HTMLEOF
fi

# Add robots.txt and favicon.
cat > "$WEBROOT/robots.txt" <<'EOF'
User-agent: *
Allow: /
Sitemap: https://DOMAIN_PLACEHOLDER/sitemap.xml
EOF
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/" "$WEBROOT/robots.txt"

# Simple favicon (1x1 transparent PNG).
echo -n "" > "$WEBROOT/favicon.ico"

# 4. Configure Caddy as fallback web server.
echo "[4/6] Configuring Caddy..."
cat > /etc/caddy/Caddyfile <<CADDYEOF
{
    servers {
        # HTTP/2 without TLS too, for browsers that negotiate h2 with wisp
        protocols h1 h2c
    }
}

:8080 {
    # only wisp talks to it: keep 443 the one open port
    bind 127.0.0.1
    root * /var/www/cover
    file_server
    header {
        Server "caddy"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }
    handle_errors {
        respond "{err.status_code} {err.status_text}"
    }
}
CADDYEOF

systemctl restart caddy
systemctl enable caddy

# 5. Create the server config and install the binary.
echo "[5/6] Configuring wisp..."
mkdir -p /etc/wisp
umask 077 # the config holds the password
cat > /etc/wisp/server.yaml <<CFGEOF
listen: ":443"
tls:
  cert: "$CERT_DIR/fullchain.pem"
  key: "$CERT_DIR/privkey.pem"
passwords:
  - "$PASSWORD"
fallback: "127.0.0.1:8080"
fallback_h2: "127.0.0.1:8080"
CFGEOF

chmod 600 /etc/wisp/server.yaml

# Copy the server binary (assumes it was built and placed alongside this script).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/../wisp-server" ]; then
    cp "$SCRIPT_DIR/../wisp-server" /usr/local/bin/wisp-server
    chmod +x /usr/local/bin/wisp-server
else
    echo "ERROR: wisp-server not found next to scripts/. Build it with:"
    echo "  GOOS=linux GOARCH=amd64 go build -o wisp-server ./cmd/server"
    exit 1
fi

# 6. Create systemd service.
echo "[6/6] Creating systemd service..."
cat > /etc/systemd/system/wisp.service <<'SVCEOF'
[Unit]
Description=Wisp server
After=network.target caddy.service
Wants=caddy.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/wisp-server -config /etc/wisp/server.yaml
Restart=always
RestartSec=3
LimitNOFILE=65535

# Security hardening.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
# the admin socket, /run/wisp-admin.sock
ReadWritePaths=/run
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable wisp
systemctl start wisp

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Server is running on port 443."
echo "Cover website is live at https://$DOMAIN"
echo ""
echo "WARNING: every server this script installs serves the same cover page, which makes them easy"
echo "to find. Replace /var/www/cover with a site of your own."
echo ""
echo "--- Client Configuration ---"
echo ""
echo "Desktop (client.yaml):"
echo "  server: \"$DOMAIN:443\""
echo "  password: \"$PASSWORD\""
echo "  sni: \"$DOMAIN\""
echo "  listen: \"127.0.0.1:1080\""
echo "  fingerprint: \"chrome\""
echo "  transport: \"tls\""
echo ""
echo "iPhone (Shadowrocket):"
echo "  Import URL: trojan://$(urlencode "$PASSWORD")@$DOMAIN:443#wisp"
echo "  Or manually: Type=Trojan, Address=$DOMAIN, Port=443, Password=$PASSWORD"
echo ""
