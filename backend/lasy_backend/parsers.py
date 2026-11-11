"""Turn raw tool output into structured findings / endpoints."""
from __future__ import annotations

import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def F(sev: str, title: str, target: str, evidence: str = "", **extra) -> dict:
    return {"severity": sev, "title": title, "target": target, "evidence": evidence, "extra": extra or None}


# ---------------------------------------------------------------------------
# nmap ssl-cert / ssl-enum-ciphers (XML)
# ---------------------------------------------------------------------------
def _elems(tb: ET.Element | None) -> dict[str, str]:
    return {e.get("key"): (e.text or "") for e in tb.findall("elem")} if tb is not None else {}


def _name_matches(host: str, names: list[str]) -> bool:
    host = host.lower()
    for n in names:
        n = n.lower().strip()
        if n == host:
            return True
        if n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:]:
            return True
    return False


def parse_nmap_ssl(xml_path: str | Path, label: str, host: str) -> list[dict]:
    findings: list[dict] = []
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError):
        return [F("info", "No usable nmap output", label, "nmap did not produce a readable XML result.")]
    ports = root.findall("host/ports/port")
    if not ports:
        return [F("info", "Host did not respond", label, "nmap reported no ports for this target.")]
    is_ip = True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_ip = False
    for port in ports:
        state = port.find("state").get("state") if port.find("state") is not None else "unknown"
        scripts = {s.get("id"): s for s in port.findall("script")}
        if state != "open":
            findings.append(F("info", f"Port is {state}", label, f"TLS checks skipped: port state is {state}."))
            continue
        if not scripts:
            findings.append(F("info", "No TLS service detected", label,
                              "The port is open but ssl-cert and ssl-enum-ciphers returned nothing "
                              "(plain HTTP or a non-TLS service)."))
            continue
        cert = scripts.get("ssl-cert")
        if cert is not None:
            findings += _cert_findings(cert, label, host, is_ip)
        enum = scripts.get("ssl-enum-ciphers")
        if enum is not None:
            findings += _cipher_findings(enum, label)
    return findings


def _cert_findings(cert: ET.Element, label: str, host: str, is_ip: bool) -> list[dict]:
    out: list[dict] = []
    t = {tb.get("key"): tb for tb in cert.findall("table")}
    subject, issuer = _elems(t.get("subject")), _elems(t.get("issuer"))
    validity = _elems(t.get("validity"))
    sig = (cert.find("elem[@key='sig_algo']").text or "") if cert.find("elem[@key='sig_algo']") is not None else ""
    pub = _elems(t.get("pubkey"))
    cn = subject.get("commonName", "")
    sans: list[str] = []
    for ext in (t.get("extensions").findall("table") if t.get("extensions") is not None else []):
        e = _elems(ext)
        if "Subject Alternative Name" in e.get("name", ""):
            sans = [x.strip()[4:] for x in e.get("value", "").split(",") if x.strip().startswith("DNS:")]
            if is_ip:
                sans += [x.strip().split(":", 1)[1] for x in e.get("value", "").split(",") if "IP Address" in x]
    names = ([cn] if cn else []) + sans
    ev = f"Subject: {cn or '-'} | Issuer: {issuer.get('commonName', issuer.get('organizationName', '-'))} | " \
         f"Valid: {validity.get('notBefore', '?')} to {validity.get('notAfter', '?')}"
    out.append(F("info", "Certificate details", label, ev))

    try:
        na = datetime.fromisoformat(validity["notAfter"].replace("Z", "").split("+")[0])
        days = (na - datetime.now(timezone.utc).replace(tzinfo=None)).days
        if days < 0:
            out.append(F("high", "SSL certificate has expired", label, f"Expired {-days} day(s) ago ({validity['notAfter']})."))
        elif days <= 30:
            out.append(F("medium", "SSL certificate expires within 30 days", label, f"Expires in {days} day(s) ({validity['notAfter']})."))
        elif days <= 90:
            out.append(F("low", "SSL certificate expires within 90 days", label, f"Expires in {days} day(s) ({validity['notAfter']})."))
    except (KeyError, ValueError):
        pass
    if subject and subject == issuer:
        out.append(F("medium", "Self-signed SSL certificate", label, f"Subject and issuer are identical ({cn or issuer})."))
    low = sig.lower()
    if "md5" in low or "sha1" in low:
        out.append(F("medium", f"Certificate signed with a weak algorithm ({sig})", label, f"Signature algorithm: {sig}"))
    try:
        bits = int(pub.get("bits", "0"))
        if pub.get("type", "").lower() == "rsa" and 0 < bits < 2048:
            out.append(F("high", f"Weak RSA key ({bits} bits)", label, f"Public key: RSA {bits} bits; 2048 or more is expected."))
    except ValueError:
        pass
    if names:
        if is_ip:
            if not _name_matches(host, names) and host not in names:
                out.append(F("low", "Certificate does not list the IP address", label,
                             f"Certificate names: {', '.join(names[:6])}"))
        elif not _name_matches(host, names):
            out.append(F("medium", "Certificate name does not match the host", label,
                         f"Requested {host}; certificate names: {', '.join(names[:8])}"))
    return out


_PROTO_SEV = {"SSLv2": "high", "SSLv3": "high", "TLSv1.0": "medium", "TLSv1.1": "medium"}
_NAMED_WEAK = [
    (r"NULL|EXPORT|anon|_DES_40", "high", "NULL, export or anonymous cipher suites supported"),
    (r"RC4", "medium", "RC4 cipher suites supported"),
    (r"3DES|DES_EDE|_DES_", "medium", "3DES cipher suites supported (SWEET32)"),
]


def _cipher_findings(enum: ET.Element, label: str) -> list[dict]:
    out: list[dict] = []
    seen_protos: list[str] = []
    named: dict[str, list[str]] = {}
    weak: dict[str, list[str]] = {"high": [], "medium": [], "low": []}
    for ptb in enum.findall("table"):
        proto = ptb.get("key")
        if not proto or not proto.startswith(("SSL", "TLS")):
            continue
        seen_protos.append(proto)
        ciphers = [_elems(c) for c in (ptb.find("table[@key='ciphers']").findall("table")
                                        if ptb.find("table[@key='ciphers']") is not None else [])]
        if proto in _PROTO_SEV:
            out.append(F(_PROTO_SEV[proto], f"{proto} is enabled", label,
                         f"{len(ciphers)} cipher suite(s) offered over {proto}, which is deprecated."))
        for c in ciphers:
            name, grade = c.get("name", ""), c.get("strength", "")
            for rx, sev, title in _NAMED_WEAK:
                if re.search(rx, name):
                    named.setdefault(title + "|" + sev, []).append(f"{proto}: {name}")
            if grade == "F":
                weak["high"].append(f"{proto}: {name}")
            elif grade in ("E", "D"):
                weak["medium"].append(f"{proto}: {name}")
            elif grade == "C":
                weak["low"].append(f"{proto}: {name}")
        for w in [(e.text or "") for e in ptb.findall("table[@key='warnings']/elem")]:
            wl = w.lower()
            if "diffie" in wl or "dh " in wl or "key exchange" in wl:
                out.append(F("medium", f"Weak key exchange on {proto}", label, w))
            elif "sweet32" in wl or "64-bit" in wl:
                out.append(F("medium", f"64-bit block cipher (SWEET32) on {proto}", label, w))
            elif "rc4" in wl:
                out.append(F("medium", f"RC4 in use on {proto}", label, w))
            elif "cbc" in wl:
                out.append(F("low", f"CBC-mode ciphers on {proto}", label, w))
            else:
                out.append(F("low", f"TLS warning on {proto}", label, w))
    for key, items in named.items():
        title, sev = key.rsplit("|", 1)
        out.append(F(sev, title, label, "; ".join(items[:8]) + (" …" if len(items) > 8 else "")))
    for sev, items in weak.items():
        if items:
            grade = {"high": "F", "medium": "D/E", "low": "C"}[sev]
            out.append(F(sev, f"Weak cipher suites supported (grade {grade})", label,
                         "; ".join(items[:8]) + (f" … (+{len(items) - 8} more)" if len(items) > 8 else "")))
    if seen_protos and not any(p in seen_protos for p in ("TLSv1.2", "TLSv1.3")):
        out.append(F("medium", "Neither TLS 1.2 nor TLS 1.3 is supported", label,
                     f"Only {', '.join(seen_protos)} offered."))
    elif seen_protos:
        out.append(F("info", "Supported protocols", label, ", ".join(seen_protos)))
    return out


# ---------------------------------------------------------------------------
# testssl.sh (flat JSON)
# ---------------------------------------------------------------------------
_TESTSSL_NAMES = {
    "SSLv2": "SSLv2 is offered", "SSLv3": "SSLv3 is offered", "TLS1": "TLS 1.0 is offered",
    "TLS1_1": "TLS 1.1 is offered", "heartbleed": "Heartbleed (CVE-2014-0160)", "CCS": "CCS injection (CVE-2014-0224)",
    "ticketbleed": "Ticketbleed (CVE-2016-9244)", "ROBOT": "ROBOT attack", "secure_renego": "Secure renegotiation",
    "secure_client_renego": "Client-initiated renegotiation", "CRIME_TLS": "CRIME (TLS compression)",
    "BREACH": "BREACH (HTTP compression)", "POODLE_SSL": "POODLE (SSLv3)", "fallback_SCSV": "TLS_FALLBACK_SCSV",
    "SWEET32": "SWEET32 (64-bit block ciphers)", "FREAK": "FREAK", "DROWN": "DROWN", "LOGJAM": "Logjam",
    "BEAST": "BEAST", "LUCKY13": "Lucky13", "RC4": "RC4 ciphers", "HSTS": "HTTP Strict Transport Security",
    "cert_chain_of_trust": "Certificate chain of trust", "cert_expirationStatus": "Certificate expiration",
    "cert_trust": "Certificate trust", "cert_signatureAlgorithm": "Certificate signature algorithm",
    "cert_keySize": "Certificate key size", "OCSP_stapling": "OCSP stapling",
    "cipherlist_NULL": "NULL ciphers offered", "cipherlist_aNULL": "Anonymous NULL ciphers offered",
    "cipherlist_EXPORT": "Export ciphers offered", "cipherlist_LOW": "Low-strength ciphers offered",
    "cipherlist_3DES_IDEA": "3DES/IDEA ciphers offered", "cipherlist_OBSOLETED": "Obsoleted ciphers offered",
}
_TESTSSL_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "WARN": "low"}


def parse_testssl(json_path: str | Path, label: str) -> list[dict]:
    try:
        data = json.loads(Path(json_path).read_text())
    except (OSError, ValueError):
        return [F("info", "No usable testssl.sh output", label, "testssl.sh did not write a readable JSON result.")]
    if isinstance(data, dict):
        data = data.get("scanResult", [{}])[0].get("vulnerabilities", []) if "scanResult" in data else []
    out: list[dict] = []
    seen = set()
    for e in data:
        sev = _TESTSSL_SEV.get(str(e.get("severity", "")).upper())
        if not sev:
            continue
        ident = e.get("id", "")
        title = _TESTSSL_NAMES.get(ident.split(" ")[0], ident.replace("_", " "))
        finding = str(e.get("finding", "")).strip()
        key = (ident, finding)
        if key in seen:
            continue
        seen.add(key)
        out.append(F(sev, f"{title}: {finding[:90]}" if finding else title, label,
                     f"{ident}: {finding}" + (f" ({e['cve']})" if e.get("cve") else ""), cve=e.get("cve")))
    if not out:
        out.append(F("info", "testssl.sh reported no issues", label, "No findings above informational level."))
    return out


# ---------------------------------------------------------------------------
# nuclei (JSONL)
# ---------------------------------------------------------------------------
def parse_nuclei(jsonl_path: str | Path, label: str) -> list[dict]:
    out: list[dict] = []
    try:
        lines = Path(jsonl_path).read_text(errors="ignore").splitlines()
    except OSError:
        return out
    for ln in lines:
        try:
            j = json.loads(ln)
        except ValueError:
            continue
        info = j.get("info", {})
        sev = str(info.get("severity", "info")).lower()
        sev = sev if sev in SEV_ORDER else "info"
        ev = [f"template: {j.get('template-id', '?')}"]
        if j.get("matcher-name"):
            ev.append(f"matcher: {j['matcher-name']}")
        if j.get("extracted-results"):
            ev.append("extracted: " + ", ".join(map(str, j["extracted-results"][:5])))
        cls = info.get("classification") or {}
        cve = cls.get("cve-id")
        out.append(F(sev, info.get("name", j.get("template-id", "Nuclei finding")),
                     j.get("matched-at") or j.get("host") or label, " | ".join(ev),
                     cve=cve, references=(info.get("reference") or [])[:4],
                     description=(info.get("description") or "")[:400]))
    out.sort(key=lambda f: SEV_ORDER[f["severity"]])
    return out


# ---------------------------------------------------------------------------
# nikto (text)
# ---------------------------------------------------------------------------
_NIKTO_SKIP = re.compile(r"^\+ (Target |Start Time|End Time|SSL Info|Scan terminated|\d+ host\(s\)|\d+ requests|"
                         r"No CGI Directories|Nikto|Using |Platform|Multiple IPs|ERROR:|No web server found)", re.I)
_NIKTO_RULES = [
    (r"cve-\d{4}-\d+.*(remote code|rce|execute arbitrary|command execution)|remote code execution", "high", "Known remote code execution issue"),
    (r"cve-\d{4}-\d+|osvdb-\d+.*(vulnerab)|may be vulnerable|is vulnerable", "medium", "Known vulnerability reported"),
    (r"outdated|end of life|end-of-life|eol\b|appears to be outdated", "medium", "Outdated server software"),
    (r"directory indexing|index of /|directory listing", "medium", "Directory listing enabled"),
    (r"\b(trace|track)\b.*(enabled|method|allowed)|http trace", "medium", "HTTP TRACE method enabled"),
    (r"(backup|\.bak|\.old|\.orig|\.swp|\.sql|\.tar|\.zip|\.gz).*(found|file)|backup.*file", "medium", "Backup or archive file exposed"),
    (r"phpinfo|server-status|server-info|phpmyadmin|adminer|/admin", "medium", "Sensitive or administrative page exposed"),
    (r"default (file|page|account|password|credentials|install)|apache default", "low", "Default file or page present"),
    (r"x-frame-options|anti-clickjacking", "low", "Missing X-Frame-Options header (clickjacking)"),
    (r"x-content-type-options", "low", "Missing X-Content-Type-Options header"),
    (r"strict-transport-security|hsts", "low", "Missing Strict-Transport-Security header"),
    (r"content-security-policy", "low", "Missing Content-Security-Policy header"),
    (r"cookie.*(httponly|secure)", "low", "Cookie missing HttpOnly/Secure flag"),
    (r"etag|inode", "low", "ETag header discloses inode information"),
    (r"allowed http methods", "info", "HTTP methods advertised"),
    (r"uncommon header|x-powered-by|x-aspnet|server banner", "info", "Technology disclosed in response headers"),
    (r"robots\.txt|sitemap", "info", "robots.txt / sitemap entries"),
    (r"interesting|might be|worth", "low", "Potentially interesting resource"),
]


def parse_nikto(lines: list[str], label: str) -> list[dict]:
    out: list[dict] = []
    for raw in lines:
        ln = raw.strip()
        if not ln.startswith("+ ") or _NIKTO_SKIP.match(ln):
            continue
        body = ln[2:].strip()
        m = re.match(r"^(/\S*|[A-Z]+):\s*(.*)$", body)
        loc, msg = (m.group(1), m.group(2)) if m else ("", body)
        if body.lower().startswith("server:"):
            out.append(F("info", "Server banner", label, body))
            continue
        sev, title = "info", msg[:90]
        for rx, s, t in _NIKTO_RULES:
            if re.search(rx, body, re.I):
                sev, title = s, t
                break
        target = label + (loc if loc.startswith("/") else "")
        out.append(F(sev, title, target, body[:600]))
    out.sort(key=lambda f: SEV_ORDER[f["severity"]])
    return out


# ---------------------------------------------------------------------------
# content discovery tools -> normalised endpoints
# ---------------------------------------------------------------------------
def _ep(base: str, path_or_url: str, status: int, size: int, words, lines, redirect, tool: str) -> dict:
    u = urlparse(path_or_url if "://" in path_or_url else base.rstrip("/") + "/" + path_or_url.lstrip("/"))
    return {"origin": base.rstrip("/"), "path": u.path or "/", "status": int(status), "size": int(size or 0),
            "words": words, "lines": lines, "redirect": redirect or "", "tool": tool}


def parse_ffuf(json_path: str | Path, base: str) -> list[dict]:
    try:
        data = json.loads(Path(json_path).read_text())
    except (OSError, ValueError):
        return []
    return [_ep(base, r.get("url", ""), r.get("status", 0), r.get("length", 0), r.get("words"),
                r.get("lines"), r.get("redirectlocation"), "ffuf") for r in data.get("results", [])]


_FEROX = re.compile(r"^(\d{3}|WLD)\s+([A-Z]+)\s+(\d+)l\s+(\d+)w\s+(\d+)c\s+(\S+)(?:\s+=>\s+(\S+))?")


def parse_ferox(lines: list[str], base: str) -> list[dict]:
    out = []
    for ln in lines:
        m = _FEROX.match(ln.strip())
        if not m or m.group(1) == "WLD":
            continue
        out.append(_ep(base, m.group(6), int(m.group(1)), int(m.group(5)), int(m.group(4)),
                       int(m.group(3)), m.group(7), "feroxbuster"))
    return out


_DIRSEARCH = re.compile(r"^\[\d{2}:\d{2}:\d{2}\]\s+(\d{3})\s+-\s+(\d+(?:\.\d+)?)\s*([KMG]?B)\s+-\s+(\S+)"
                        r"(?:\s+->\s+(?:REDIRECTS TO:\s*)?(\S+))?")
_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}


def parse_dirsearch(lines: list[str], base: str) -> list[dict]:
    out = []
    for ln in lines:
        m = _DIRSEARCH.match(ln.strip())
        if not m:
            continue
        out.append(_ep(base, m.group(4), int(m.group(1)), int(float(m.group(2)) * _UNITS[m.group(3)]),
                       None, None, m.group(5), "dirsearch"))
    return out
