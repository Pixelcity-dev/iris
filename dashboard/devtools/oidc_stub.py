#!/usr/bin/env python3
"""Minimal OIDC stub for local dashboard E2E testing only.

Simulates enough of Keycloak: discovery, authorization (auto-approves),
token exchange and userinfo. NOT for production use.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

SECRET = b"stub-oidc-secret"
# ISSUER is the ADVERTISED base URL (must be reachable from the client being
# tested, e.g. http://host.docker.internal:19090 when testing from containers).
import sys
ISSUER = (sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:19090").rstrip("/")

CODES = {}          # code -> verified
STATE = {}          # state -> True


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_access_token(sub="stub-user-123", username="pixie", email="pixie@pixelcity.dev"):
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({
        "sub": sub,
        "preferred_username": username,
        "email": email,
        "exp": int(time.time()) + 3600,
    }).encode())
    return f"{header}.{payload}."


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)

        # --- payments/plan/usage API stub ---
        if u.path == "/api/v1/plan":
            self._json({
                "tier": "free", "name": "Free",
                "scan_quota": 100, "scans_used": 12,
                "ai_pages_quota": 0, "ai_pages_used": 0,
            })
        elif u.path == "/api/v1/usage":
            self._json({"entries": [
                {"time": "2026-09-29T10:00:00Z", "scanner": "sast",
                 "target": "/repo/api", "findings": 3, "duration_seconds": 1.42},
                {"time": "2026-09-29T09:12:00Z", "scanner": "webscan",
                 "target": "https://pixelcity.top", "findings": 2, "duration_seconds": 0.31},
            ], "total": 2})

        elif u.path == "/realms/pixelcity/.well-known/openid-configuration":
            self._json({
                "issuer": ISSUER + "/realms/pixelcity",
                "authorization_endpoint": ISSUER + "/realms/pixelcity/protocol/openid-connect/auth",
                "token_endpoint": ISSUER + "/realms/pixelcity/protocol/openid-connect/token",
                "userinfo_endpoint": ISSUER + "/realms/pixelcity/protocol/openid-connect/userinfo",
                "end_session_endpoint": ISSUER + "/realms/pixelcity/protocol/openid-connect/logout",
                "jwks_uri": ISSUER + "/realms/pixelcity/protocol/openid-connect/certs",
            })

        elif u.path == "/realms/pixelcity/protocol/openid-connect/auth":
            # auto-approve: redirect straight back with a code
            code = secrets.token_urlsafe(24)
            CODES[code] = True
            state = q.get("state", [""])[0]
            self.send_response(302)
            self.send_header("Location",
                             f"{q.get('redirect_uri', ['/'])[0]}?code={code}&state={state}")
            self.end_headers()

        elif u.path == "/realms/pixelcity/protocol/openid-connect/userinfo":
            self._json({
                "sub": "stub-user-123",
                "preferred_username": "pixie",
                "email": "pixie@pixelcity.dev",
                "email_verified": True,
            })

        else:
            self._json({"error": "not_found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode())

        if u.path == "/realms/pixelcity/protocol/openid-connect/token":
            grant = form.get("grant_type", [""])[0]
            if grant == "authorization_code" and form.get("code", [""])[0] in CODES:
                tok = make_access_token()
                self._json({
                    "access_token": tok,
                    "refresh_token": secrets.token_urlsafe(32),
                    "id_token": tok,
                    "expires_in": 3600,
                    "refresh_expires_in": 7200,
                    "token_type": "Bearer",
                })
            else:
                self._json({"error": "invalid_grant"}, 400)
        elif u.path == "/api/v1/billing/checkout":
            plan = form.get("plan", ["pro"])[0]
            self._json({
                "url": f"https://payments.pixelcity.dev/checkout/stub-{plan}-123",
                "session_id": f"stub-{plan}-123", "plan": plan,
                "currency": "EUR", "amount_cents": 1900 if plan == "pro" else 49900,
            })
        else:
            self._json({"error": "not_found"}, 404)


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(f"OIDC stub listening on {host}:19090, advertising {ISSUER}", flush=True)
    HTTPServer((host, 19090), Handler).serve_forever()
