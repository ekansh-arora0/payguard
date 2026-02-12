#!/usr/bin/env bash
# Setup Let's Encrypt certificates for PayGuard
# Usage: ./scripts/setup-letsencrypt.sh yourdomain.com [admin@yourdomain.com]

set -euo pipefail

DOMAIN="${1:-}"
EMAIL="${2:-admin@$DOMAIN}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain> [email]"
    echo "Example: $0 payguard.example.com admin@example.com"
    exit 1
fi

echo "Setting up Let's Encrypt for domain: $DOMAIN"
echo "Contact email: $EMAIL"

# Install certbot if not present
if ! command -v certbot &>/dev/null; then
    echo "Installing certbot..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update
        sudo apt-get install -y certbot
    elif command -v brew &>/dev/null; then
        brew install certbot
    else
        echo "ERROR: Cannot install certbot. Please install it manually."
        exit 1
    fi
fi

# Create cert directory
mkdir -p nginx/certs

# Generate certificates using certbot
# This requires port 80 to be available (temporarily)
echo "Requesting certificate from Let's Encrypt..."
sudo certbot certonly --standalone \
    -d "$DOMAIN" \
    --agree-tos \
    --email "$EMAIL" \
    --non-interactive \
    --preferred-challenges http

# Copy certificates to nginx directory
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
sudo cp "$CERT_DIR/fullchain.pem" nginx/certs/
sudo cp "$CERT_DIR/privkey.pem" nginx/certs/
sudo chmod 644 nginx/certs/*.pem

echo ""
echo "✅ Certificates installed successfully!"
echo ""
echo "Next steps:"
echo "1. Update .env: DOMAIN_NAME=$DOMAIN"
echo "2. Update nginx/nginx.conf: server_name $DOMAIN;"
echo "3. Update docker-compose.prod.yml if needed"
echo "4. Restart: docker compose -f docker-compose.prod.yml restart nginx"
echo ""
echo "Auto-renewal cron job:"
echo "  0 12 * * * certbot renew --quiet --deploy-hook 'docker compose -f /path/to/docker-compose.prod.yml restart nginx'"
