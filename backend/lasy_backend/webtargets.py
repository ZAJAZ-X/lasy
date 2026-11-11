"""Parse web target input: URLs, host:port, or 'host port' (comma/newline separated)."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from .targets import TargetKind, _classify

HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000}


def default_scheme(port: int) -> str:
    return "http" if port in HTTP_PORTS else "https"


def base_url(host: str, port: int, scheme: str) -> str:
    h = f"[{host}]" if ":" in host else host
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{h}" if default else f"{scheme}://{h}:{port}"


def parse_web_inputs(text: str, default_port: int = 443) -> tuple[list[dict], list[str]]:
    tokens = [t for t in re.split(r"[,\s;]+", text or "") if t]
    out: list[dict] = []
    bad: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        i += 1
        scheme = None
        port = None
        if "://" in tok:
            u = urlparse(tok)
            scheme = (u.scheme or "").lower()
            host = u.hostname or ""
            port = u.port or (80 if scheme == "http" else 443)
        else:
            t = _classify(tok)
            host, port = t.value, t.port
            if t.kind not in (TargetKind.IP, TargetKind.DOMAIN, TargetKind.URL):
                bad.append(tok)
                continue
            if port is None and i < len(tokens) and tokens[i].isdigit():   # "host 8443"
                port = int(tokens[i])
                i += 1
        if not host or scheme not in (None, "http", "https"):
            bad.append(tok)
            continue
        port = port or default_port
        if not 1 <= port <= 65535:
            bad.append(tok)
            continue
        item = {"host": host.lower(), "port": int(port), "scheme": scheme or default_scheme(int(port))}
        if item not in out:
            out.append(item)
    return out, bad
