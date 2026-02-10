#!/usr/bin/env bash
# Generate self-signed TLS certificates for development/testing.
# For production, use Let's Encrypt or your CA's certificates.
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/nginx/certs"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/fullchain.pem" ] && [ -f "$CERT_DIR/privkey.pem" ]; then
    echo "Certificates already exist in $CERT_DIR — skipping."
    echo "Delete them and re-run to regenerate."
    exit 0
fi

echo "Generating self-signed TLS certificate..."
openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/privkey.pem" \
    -out "$CERT_DIR/fullchain.pem" \
    -subj "/CN=localhost/O=PayGuard Dev" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Certificates written to $CERT_DIR"
echo "  fullchain.pem  (public cert)"
echo "  privkey.pem    (private key)"
echo ""
echo "For production, replace these with real certificates from Let's Encrypt:"
echo "  certbot certonly --standalone -d yourdomain.com"
