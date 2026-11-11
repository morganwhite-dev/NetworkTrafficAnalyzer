"""Minimal, bounds-checked TLS ClientHello reader that pulls out the SNI.

Scapy's full TLS layer needs the `cryptography` package and does far more
than we need. Reading the server name by hand is ~40 lines and every index is
checked, so a malformed handshake just returns None.
"""

from __future__ import annotations


def is_tls_record(payload: bytes) -> bool:
    return len(payload) >= 5 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03


def client_hello_sni(payload: bytes) -> str | None:
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        p = 5 + 4            # record header + handshake header
        p += 2 + 32          # client version + random
        sid_len = payload[p]
        p += 1 + sid_len
        cs_len = int.from_bytes(payload[p:p + 2], "big")
        p += 2 + cs_len
        comp_len = payload[p]
        p += 1 + comp_len
        ext_total = int.from_bytes(payload[p:p + 2], "big")
        p += 2
        end = min(len(payload), p + ext_total)
        while p + 4 <= end:
            ext_type = int.from_bytes(payload[p:p + 2], "big")
            ext_len = int.from_bytes(payload[p + 2:p + 4], "big")
            p += 4
            if ext_type == 0x0000 and p + 5 <= end:
                name_len = int.from_bytes(payload[p + 3:p + 5], "big")
                raw = payload[p + 5:p + 5 + name_len]
                if raw and len(raw) == name_len:
                    name = raw.decode("ascii", "replace").lower()
                    if all(c.isalnum() or c in ".-_" for c in name):
                        return name[:253]
                return None
            p += ext_len
    except (IndexError, ValueError):
        return None
    return None
