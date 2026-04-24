from __future__ import annotations

import secrets
import ssl
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from time import time
from typing import Optional
import json
import os

# In-memory nonce store: {nonce: (san, cn, timestamp)}
_nonce_store: dict[str, tuple[str, str, float]] = {}
NONCE_TTL = 120  # seconds


def create_nonce(san: str, cn: str = "") -> str:
    """Create a one-time nonce linked to a verified identity."""
    nonce = secrets.token_urlsafe(32)
    _nonce_store[nonce] = (san, cn, time())
    _cleanup_expired()
    return nonce


def consume_nonce(nonce: str) -> Optional[tuple[str, str]]:
    """Consume a nonce and return (san, cn). Returns None if invalid/expired."""
    _cleanup_expired()
    entry = _nonce_store.pop(nonce, None)
    if entry is None:
        return None
    san, cn, ts = entry
    if time() - ts > NONCE_TTL:
        return None
    return san, cn


def _cleanup_expired():
    now = time()
    expired = [k for k, (_, _, ts) in _nonce_store.items() if now - ts > NONCE_TTL]
    for k in expired:
        del _nonce_store[k]


class WhoAmIHandler(BaseHTTPRequestHandler):
    """HTTPS handler that reads client certificate and returns identity + nonce."""

    def do_GET(self):
        if self.path != "/whoami":
            self.send_response(404)
            self.end_headers()
            return

        # Get client certificate from TLS connection
        cert = self.connection.getpeercert()
        if not cert:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "No client certificate provided"}).encode())
            return

        # Extract SAN and CN
        san = _extract_san(cert)
        cn = _extract_cn(cert)

        if not san and not cn:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "No SAN or CN found in certificate"}).encode())
            return

        identity = san or cn
        nonce = create_nonce(identity, cn)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()
        self.wfile.write(json.dumps({
            "san": san,
            "cn": cn,
            "identity": identity,
            "nonce": nonce,
        }).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default logging


def _extract_san(cert: dict) -> str:
    """Extract email or DNS SAN from certificate."""
    for san_type, value in cert.get("subjectAltName", ()):
        if san_type in ("email", "rfc822Name"):
            return value
        if san_type == "DNS":
            return value
    return ""


def _extract_cn(cert: dict) -> str:
    """Extract CN from certificate subject."""
    for rdn in cert.get("subject", ()):
        for attr, value in rdn:
            if attr == "commonName":
                return value
    return ""


def start_identity_server(
    port: int = 8443,
    cert_file: str = "data/certs/server.pem",
    key_file: str = "data/certs/server-key.pem",
    ca_file: str = "data/certs/ca.pem",
):
    """Start the mTLS identity server in a background thread."""
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print(f"[IDENTITY] Certificate files not found ({cert_file}, {key_file}). Identity server disabled.")
        return

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    if os.path.exists(ca_file):
        ctx.load_verify_locations(ca_file)
    ctx.verify_mode = ssl.CERT_REQUIRED

    server = HTTPServer(("0.0.0.0", port), WhoAmIHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[IDENTITY] mTLS identity server running on https://0.0.0.0:{port}/whoami")
