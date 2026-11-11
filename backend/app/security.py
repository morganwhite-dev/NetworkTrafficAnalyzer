"""Request security for a dashboard that can see everyone's traffic.

- Per-launch token: printed once in the terminal as ``/?t=…``; exchanged for
  an HttpOnly, SameSite=Strict cookie and stripped from the URL by redirect.
- Every /api route and the WebSocket need that cookie.
- State-changing requests and the WebSocket need an exact Origin match and
  (for HTTP) an ``X-NTA-Request: 1`` header, which a cross-site page can't
  send without a CORS preflight this server never approves.
- Host header validation (TrustedHostMiddleware, added in main.py) stops
  DNS-rebinding attacks against 127.0.0.1.
- Strict security headers and a CSP with no third-party scripts.
"""

from __future__ import annotations

import hmac
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import parse_qs

COOKIE = "nta_session"
SAFE_METHODS = {"GET", "HEAD"}
PUBLIC_PREFIXES = ("/static/", "/favicon")


def csp(port: int) -> str:
    ws = f"ws://127.0.0.1:{port} ws://localhost:{port}"
    return ("default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; font-src 'self'; "
            f"connect-src 'self' {ws}; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'")


def _headers(scope: dict[str, Any]) -> dict[str, str]:
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}


def _cookie_token(headers: dict[str, str]) -> str | None:
    raw = headers.get("cookie")
    if not raw:
        return None
    jar = SimpleCookie()
    try:
        jar.load(raw)
    except Exception:  # noqa: BLE001
        return None
    morsel = jar.get(COOKIE)
    return morsel.value if morsel else None


class SecurityMiddleware:
    def __init__(self, app: Any, token: str, origins: set[str], port: int) -> None:
        self.app = app
        self.token = token
        self.origins = origins
        self.csp = csp(port)

    def _token_ok(self, value: str | None) -> bool:
        return bool(value) and hmac.compare_digest(value.encode(), self.token.encode())

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "websocket":
            headers = _headers(scope)
            if headers.get("origin") not in self.origins or \
                    not self._token_ok(_cookie_token(headers)):
                await send({"type": "websocket.close", "code": 4403})
                return
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "/")
        method: str = scope.get("method", "GET")
        headers = _headers(scope)
        authed = self._token_ok(_cookie_token(headers))

        if path == "/" and scope.get("query_string"):
            qs = parse_qs(scope["query_string"].decode("latin-1"))
            given = (qs.get("t") or [None])[0]
            if self._token_ok(given):
                await self._redirect_with_cookie(send)
                return

        if not path.startswith(PUBLIC_PREFIXES):
            if not authed:
                await self._deny(send, path)
                return
            if method not in SAFE_METHODS:
                if headers.get("origin") not in self.origins or \
                        headers.get("x-nta-request") != "1":
                    await self._plain(send, 403, b"Cross-site request blocked.")
                    return

        no_store = path == "/" or path.startswith("/api/")

        async def send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                extra = [
                    (b"content-security-policy", self.csp.encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cross-origin-opener-policy", b"same-origin"),
                    (b"cross-origin-resource-policy", b"same-origin"),
                    (b"x-frame-options", b"DENY"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                ]
                if no_store:
                    extra.append((b"cache-control", b"no-store"))
                message.setdefault("headers", [])
                message["headers"] = list(message["headers"]) + extra
            await send(message)

        await self.app(scope, receive, send_with_headers)

    async def _redirect_with_cookie(self, send: Any) -> None:
        cookie = f"{COOKIE}={self.token}; HttpOnly; SameSite=Strict; Path=/"
        await send({"type": "http.response.start", "status": 303, "headers": [
            (b"location", b"/"), (b"set-cookie", cookie.encode()),
            (b"cache-control", b"no-store"), (b"referrer-policy", b"no-referrer")]})
        await send({"type": "http.response.body", "body": b""})

    async def _deny(self, send: Any, path: str) -> None:
        if path.startswith("/api/"):
            await self._plain(send, 401, b'{"detail":"Missing or invalid session token."}',
                              b"application/json")
            return
        body = LOCKED_PAGE.encode()
        await send({"type": "http.response.start", "status": 401, "headers": [
            (b"content-type", b"text/html; charset=utf-8"),
            (b"content-security-policy", b"default-src 'none'; style-src 'unsafe-inline'"),
            (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": body})

    async def _plain(self, send: Any, status: int, body: bytes,
                     ctype: bytes = b"text/plain; charset=utf-8") -> None:
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", ctype), (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": body})


LOCKED_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Locked</title>
<style>body{background:#0a0a0c;color:#d7dde8;font:13px/1.6 ui-monospace,Menlo,monospace;
display:grid;place-items:center;height:100vh;margin:0}main{max-width:440px;padding:24px;
border:1px solid #232a36;background:#12151c}b{color:#00f3ff}</style></head><body><main>
<p><b>Network Traffic Analyzer</b> is locked.</p>
<p>Open the link printed in the terminal where you started the app. It contains a one-time
token, so other pages and other users on this Mac can't read your traffic.</p></main>
</body></html>"""
