"""nmap helpers: command construction, grepable-output parsing, privilege check."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from . import db

_ENTRY_SPLIT = re.compile(r",\s(?=\d+/(?:open\|filtered|closed\|filtered|open|closed|filtered|unfiltered)/)")
_HOST_RE = re.compile(r"^Host: (\S+) \((.*?)\)")

SETCAP_HINT = ("sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "
               "$(readlink -f $(which nmap))")


def use_sudo() -> bool:
    return db.get_setting("nmap_use_sudo", "0") == "1"


def nmap_argv(args: list[str]) -> list[str]:
    base = ["sudo", "-n", "nmap"] if use_sudo() else ["nmap"]
    return base + list(args)


def nmap_env() -> dict:
    """File capabilities only take effect when nmap is told it is privileged."""
    if os.geteuid() == 0 or use_sudo():
        return {}
    return {"NMAP_PRIVILEGED": "1"}


def pretty_service(svc: str) -> str:
    svc = (svc or "").strip()
    if not svc:
        return "-"
    if svc.startswith("ssl|"):
        inner = svc[4:]
        return "https" if inner == "http" else f"ssl/{inner}"
    return svc


def is_complete(path: str | Path) -> bool:
    try:
        return "# Nmap done" in Path(path).read_text(errors="ignore")
    except OSError:
        return False


def has_header(path: str | Path) -> bool:
    try:
        return "scan initiated" in Path(path).read_text(errors="ignore")[:4000]
    except OSError:
        return False


def parse_gnmap(path: str | Path) -> dict[str, dict]:
    """ip -> {hostname, up, ports:[{port, proto, state, service, version}]}.
    Works on partial files, which is what makes the live table possible."""
    hosts: dict[str, dict] = {}
    try:
        text = Path(path).read_text(errors="ignore")
    except OSError:
        return hosts
    for line in text.splitlines():
        if not line.startswith("Host: "):
            continue
        parts = line.split("\t")
        m = _HOST_RE.match(parts[0])
        if not m:
            continue
        ip, name = m.group(1), m.group(2)
        rec = hosts.setdefault(ip, {"hostname": "", "up": False, "ports": []})
        if name:
            rec["hostname"] = name
        for p in parts[1:]:
            if p.startswith("Status: "):
                rec["up"] = p.split(": ", 1)[1].strip().lower() == "up"
            elif p.startswith("Ports: "):
                rec["up"] = True
                for ent in _ENTRY_SPLIT.split(p[7:]):
                    f = ent.strip().split("/")
                    if len(f) < 5 or not f[0].isdigit():
                        continue
                    version = f[6].strip() if len(f) > 6 else ""
                    rec["ports"].append({
                        "port": int(f[0]), "state": f[1], "proto": f[2],
                        "service": f[4], "version": version,
                    })
    return hosts


def merge_hosts(dst: dict[str, dict], src: dict[str, dict]) -> None:
    for ip, rec in src.items():
        cur = dst.setdefault(ip, {"hostname": "", "up": False, "ports": []})
        cur["hostname"] = cur["hostname"] or rec["hostname"]
        cur["up"] = cur["up"] or rec["up"]
        seen = {(p["port"], p["proto"]) for p in cur["ports"]}
        for p in rec["ports"]:
            if (p["port"], p["proto"]) not in seen:
                cur["ports"].append(p)
                seen.add((p["port"], p["proto"]))


def error_hint(lines: list[str]) -> str:
    blob = "\n".join(lines).lower()
    if "requires root" in blob or "operation not permitted" in blob or "dnet" in blob or "privileg" in blob:
        return ("nmap needs raw-socket permission for this scan type. Run once in Kali: "
                + SETCAP_HINT)
    return ""


def privilege_check() -> dict:
    """Run a harmless raw-socket scan against loopback to confirm no-sudo scanning works."""
    try:
        env = {**os.environ, **nmap_env()}
        out = subprocess.run(nmap_argv(["-sS", "-Pn", "-p", "1", "127.0.0.1"]),
                             capture_output=True, text=True, timeout=25, env=env)
        text = (out.stdout + out.stderr)
        ok = out.returncode == 0 and "requires root" not in text.lower() and "not permitted" not in text.lower()
        return {"ok": ok, "detail": "" if ok else (text.strip().splitlines() or ["nmap failed"])[-1],
                "fix": "" if ok else SETCAP_HINT}
    except FileNotFoundError:
        return {"ok": False, "detail": "nmap is not installed", "fix": "sudo apt install nmap"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "detail": str(exc), "fix": SETCAP_HINT}
