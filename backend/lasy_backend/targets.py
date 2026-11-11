"""Parse and classify the mixed target input a pentester pastes in.

Accepts IPs, CIDR ranges, domains and URLs separated by commas, newlines,
spaces, semicolons or tabs. Classifies each token so the rest of the app can
decide how to treat it (a CIDR expands differently from a single host, a URL
needs its scheme/path stripped, etc.).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

_SEPARATORS = re.compile(r"[,\s;]+")
# Permissive hostname check: labels of letters/digits/hyphens, a dotted name.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


class TargetKind(str, Enum):
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Target:
    raw: str          # exactly what the user typed
    value: str        # normalised value handed to tools (host/ip/cidr)
    kind: TargetKind
    port: int | None = None   # only when a URL/host carried an explicit port


def _classify(token: str) -> Target:
    t = token.strip().strip("'\"")
    if not t:
        return Target(token, token, TargetKind.UNKNOWN)

    # URL -> strip to host (+ port if present)
    if "://" in t or t.startswith("//"):
        parsed = urlparse(t if "://" in t else "http:" + t)
        host = parsed.hostname or ""
        port = parsed.port
        if host:
            # the host inside a URL may itself be an IP
            try:
                ipaddress.ip_address(host)
                return Target(token, host, TargetKind.IP, port)
            except ValueError:
                return Target(token, host, TargetKind.URL, port)
        return Target(token, t, TargetKind.UNKNOWN)

    # host:port (but not IPv6 which also has colons) -> split once
    if t.count(":") == 1 and not t.startswith("["):
        head, _, tail = t.partition(":")
        if tail.isdigit():
            inner = _classify(head)
            if inner.kind in (TargetKind.IP, TargetKind.DOMAIN):
                return Target(token, inner.value, inner.kind, int(tail))

    # CIDR
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
            return Target(token, str(net), TargetKind.CIDR)
        except ValueError:
            pass

    # bare IP
    try:
        ipaddress.ip_address(t)
        return Target(token, t, TargetKind.IP)
    except ValueError:
        pass

    # domain
    if _DOMAIN_RE.match(t):
        return Target(token, t.lower(), TargetKind.DOMAIN)

    return Target(token, t, TargetKind.UNKNOWN)


def parse_targets(text: str) -> list[Target]:
    """Tokenise, classify and de-duplicate. Order is preserved."""
    seen: set[tuple[str, int | None]] = set()
    out: list[Target] = []
    for tok in _SEPARATORS.split(text or ""):
        if not tok.strip():
            continue
        tgt = _classify(tok)
        key = (tgt.value, tgt.port)
        if key in seen:
            continue
        seen.add(key)
        out.append(tgt)
    return out


def expand_for_scan(targets: list[Target]) -> list[str]:
    """The literal list of host entries to write into an nmap -iL file.

    CIDRs are passed through verbatim (nmap expands them natively); everything
    else contributes its host/ip value.
    """
    out: list[str] = []
    for t in targets:
        if t.kind == TargetKind.UNKNOWN:
            continue
        out.append(t.value)
    # keep order, drop dupes
    seen: set[str] = set()
    uniq = []
    for v in out:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def table_hosts(targets: list[Target]) -> list[str]:
    """Hosts that must appear in a results table regardless of scan outcome.

    Single IPs and domains always get a row (even if down -> all dashes).
    CIDR ranges are excluded here; only responding hosts from a CIDR get rows,
    added later from scan results.
    """
    return [t.value for t in targets if t.kind in (TargetKind.IP, TargetKind.DOMAIN)]


MAX_RANGE_ADDRESSES = 65536


def oversized_ranges(targets: list[Target]) -> list[str]:
    """CIDR ranges too large to scan sensibly (more than a /16)."""
    out = []
    for t in targets:
        if t.kind == TargetKind.CIDR:
            try:
                if ipaddress.ip_network(t.value, strict=False).num_addresses > MAX_RANGE_ADDRESSES:
                    out.append(t.value)
            except ValueError:
                pass
    return out


def range_error(big: list[str]) -> str:
    return (f"{', '.join(big)} is too large (over {MAX_RANGE_ADDRESSES:,} addresses). "
            "Split it into smaller ranges, for example /16 blocks, and scan them separately.")
