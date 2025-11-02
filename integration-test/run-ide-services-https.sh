#!/bin/bash

cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
set -e -x -u

source ./run-ide-services-base.sh

# Create directory for certificates
CERT_DIR=$(pwd)/https-certs

rm -rf "$CERT_DIR" || true
mkdir -p "$CERT_DIR"

# Generate self-signed certificate for OAuth2-bro
CERT_FILE="$CERT_DIR/oauth2-bro-cert.pem"
KEY_FILE="$CERT_DIR/oauth2-bro-key.pem"

echo "Generating self-signed certificate for OAuth2-bro HTTPS demo..."
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -days 365 \
  -subj "/CN=oauth2-bro/O=OAuth2-bro Demo" \
  -addext "subjectAltName=DNS:localhost,DNS:oauth2-bro,DNS:mock-auth,DNS:localhost,IP:127.0.0.1"

echo "Certificate generated successfully!"
echo "  Certificate: $CERT_FILE"
echo "  Private Key: $KEY_FILE"

## Make it rebuild oauth2-bro
docker compose -f "$DEMO_DIR/docker-compose.yml" -f "$(pwd)/docker-compose.https.override.yaml" rm -f mock-auth

docker compose -f "$DEMO_DIR/docker-compose.yml" -f "$(pwd)/docker-compose.https.override.yaml" up --build
