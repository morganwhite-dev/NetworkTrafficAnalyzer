"""Find credentials in cleartext application payloads and mask them.

Each finding records the byte range of the secret inside the payload so the
UI can blur exactly those bytes in the hex dump until the user clicks reveal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MASK = "••••"

SECRET_PARAM = re.compile(
    rb"(?i)(?:^|[?&;\s])((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|"
    rb"access[_-]?token|auth|session(?:id)?|sid|key))=([^&;\s#]+)"
)
AUTH_HEADER = re.compile(rb"(?im)^(authorization|proxy-authorization):[ \t]*(\S+)[ \t]+([^\r\n]+)")
COOKIE_HEADER = re.compile(rb"(?im)^(cookie):[ \t]*([^\r\n]+)")
USER_PARAM = re.compile(rb"(?i)(?:^|[?&;\s])(user(?:name)?|login|email)=([^&;\s#]+)")

LINE_COMMANDS = {
    21: [re.compile(rb"(?m)^(PASS) (\S+)")],                                # FTP
    110: [re.compile(rb"(?m)^(PASS) (\S+)"), re.compile(rb"(?m)^(APOP \S+) (\S+)")],  # POP3
    143: [re.compile(rb"(?im)^\S+ (LOGIN \S+) (\S+)")],                     # IMAP
    25: [re.compile(rb"(?im)^(AUTH PLAIN) (\S+)")],                         # SMTP
    587: [re.compile(rb"(?im)^(AUTH PLAIN) (\S+)")],
}

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ")


@dataclass(frozen=True)
class Secret:
    kind: str      # e.g. "HTTP form password", "HTTP Basic auth", "FTP PASS"
    field: str     # parameter or header name, safe to display
    start: int     # byte offset inside the payload
    end: int


def _http_secrets(payload: bytes) -> list[Secret]:
    found: list[Secret] = []
    head, _, body = payload.partition(b"\r\n\r\n")
    request_line = head.split(b"\r\n", 1)[0]
    # Query string on the request line.
    for m in SECRET_PARAM.finditer(request_line):
        found.append(Secret("HTTP query secret", m.group(1).decode(errors="replace").lower(),
                            m.start(2), m.end(2)))
    for m in AUTH_HEADER.finditer(head):
        scheme = m.group(2).decode(errors="replace")
        found.append(Secret(f"HTTP {scheme} auth", m.group(1).decode().lower(),
                            m.start(3), m.end(3)))
    for m in COOKIE_HEADER.finditer(head):
        found.append(Secret("HTTP cookie", "cookie", m.start(2), m.end(2)))
    if body:
        offset = len(head) + 4
        for m in SECRET_PARAM.finditer(body):
            name = m.group(1).decode(errors="replace").lower()
            kind = "HTTP form password" if name.startswith("pass") or name == "pwd" \
                else "HTTP form secret"
            found.append(Secret(kind, name, offset + m.start(2), offset + m.end(2)))
    return found


def find_secrets(payload: bytes, dport: int | None) -> list[Secret]:
    """Return secrets in a client-to-server payload. Never raises."""
    if not payload:
        return []
    try:
        if payload.startswith(HTTP_METHODS):
            return _http_secrets(payload[:65536])
        patterns = LINE_COMMANDS.get(dport or -1, [])
        out: list[Secret] = []
        for pat in patterns:
            for m in pat.finditer(payload[:8192]):
                out.append(Secret(f"{m.group(1).decode(errors='replace').split()[0]} credentials",
                                  m.group(1).decode(errors="replace").split()[0].lower(),
                                  m.start(2), m.end(2)))
        return out
    except Exception:  # noqa: BLE001 - hostile input must never crash the pipeline
        return []


def http_username(payload: bytes) -> str | None:
    m = USER_PARAM.search(payload[:65536])
    if not m:
        return None
    return m.group(2).decode("utf-8", "replace")[:64]


def mask_text(text: str) -> str:
    """Mask secrets inside a display string such as an HTTP request line."""
    def sub(m: re.Match[str]) -> str:
        return f"{m.group(1)}={MASK}"
    return re.sub(
        r"(?i)((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?token|auth|"
        r"session(?:id)?|sid|key))=([^&;\s#]+)",
        sub,
        text,
    )
