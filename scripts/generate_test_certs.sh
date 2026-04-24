#!/bin/bash
# Generate test CA + server cert + client cert for mTLS identity server
set -e

CERT_DIR="data/certs"
mkdir -p "$CERT_DIR"

echo "=== Generating CA ==="
openssl genrsa -out "$CERT_DIR/ca-key.pem" 2048
openssl req -new -x509 -key "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/ca.pem" -days 365 \
    -subj "/CN=RAMPART Test CA/O=RAMPART"

echo "=== Generating Server Cert ==="
openssl genrsa -out "$CERT_DIR/server-key.pem" 2048
openssl req -new -key "$CERT_DIR/server-key.pem" -out "$CERT_DIR/server.csr" \
    -subj "/CN=rampart-identity/O=RAMPART"
openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial -out "$CERT_DIR/server.pem" -days 365 \
    -extfile <(echo "subjectAltName=DNS:localhost,IP:0.0.0.0,IP:127.0.0.1")
rm "$CERT_DIR/server.csr"

echo "=== Generating Test Client Cert (simulating CAC) ==="
openssl genrsa -out "$CERT_DIR/client-key.pem" 2048
openssl req -new -key "$CERT_DIR/client-key.pem" -out "$CERT_DIR/client.csr" \
    -subj "/CN=DOE.JOHN.1234567890/O=TEST"
openssl x509 -req -in "$CERT_DIR/client.csr" -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial -out "$CERT_DIR/client.pem" -days 365 \
    -extfile <(echo "subjectAltName=email:john.doe@test.mil")
rm "$CERT_DIR/client.csr"

# Create PKCS12 for browser import
openssl pkcs12 -export -out "$CERT_DIR/client.p12" \
    -inkey "$CERT_DIR/client-key.pem" -in "$CERT_DIR/client.pem" \
    -certfile "$CERT_DIR/ca.pem" -passout pass:rampart

echo ""
echo "=== Done ==="
echo "Server cert: $CERT_DIR/server.pem"
echo "Server key:  $CERT_DIR/server-key.pem"
echo "CA cert:     $CERT_DIR/ca.pem"
echo "Client P12:  $CERT_DIR/client.p12 (password: rampart)"
echo ""
echo "Import client.p12 into Chrome: Settings > Privacy > Manage certificates > Import"
echo "Import ca.pem as a trusted CA in Chrome for the identity server"
