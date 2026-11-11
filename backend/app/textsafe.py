"""Helpers for turning attacker-controlled bytes into safe display strings."""

from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


def clean(value: object, limit: int = 160) -> str:
    """Decode, strip control/ANSI/bidi characters and cap the length.

    Packet fields (DNS names, HTTP hosts, SNI) come straight off the wire, so
    they can carry terminal escape codes or right-to-left overrides. Anything
    shown in the UI or written to a log goes through here first.
    """
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    else:
        text = str(value)
    text = _CONTROL.sub("", text.replace("\t", " ").replace("\n", " ").replace("\r", " "))
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text
