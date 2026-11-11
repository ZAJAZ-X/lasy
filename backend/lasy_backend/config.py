"""Runtime configuration.

The database, scan input lists and terminal replay logs live on the Linux side.
Only tool OUTPUT (results) is written to the Windows mount (results_root).
"""
from __future__ import annotations

import getpass
import os
import shutil
import socket
import subprocess
from pathlib import Path

APP_NAME = "lasy"
HOST = "127.0.0.1"
PORT = int(os.environ.get("LASY_PORT", "8847"))

DATA_DIR = Path(os.environ.get("LASY_DATA_DIR", Path.home() / ".local/share/lasy"))
LOG_DIR = DATA_DIR / "logs"
WORK_DIR = DATA_DIR / "work"          # scan input files, tool scratch
TERM_DIR = DATA_DIR / "term"          # raw terminal replay logs
DB_PATH = DATA_DIR / "lasy.db"
PID_FILE = DATA_DIR / "lasy.pid"
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"

# (key, binary candidates, install hint, purpose)
TOOLS = [
    ("nmap", ["nmap"], "sudo apt install nmap", "Port scanning, TLS scripts, host discovery"),
    ("dig", ["dig"], "sudo apt install dnsutils", "Nameserver lookup"),
    ("testssl", ["testssl.sh", "testssl"], "sudo apt install testssl.sh", "Deep TLS audit"),
    ("nuclei", ["nuclei"], "sudo apt install nuclei", "Template-based vulnerability scanner"),
    ("nikto", ["nikto"], "sudo apt install nikto", "Web server scanner"),
    ("ffuf", ["ffuf"], "sudo apt install ffuf", "Fast content discovery"),
    ("feroxbuster", ["feroxbuster"], "sudo apt install feroxbuster", "Recursive content discovery"),
    ("dirsearch", ["dirsearch"], "sudo apt install dirsearch", "Path discovery"),
    ("subfinder", ["subfinder"], "sudo apt install subfinder", "Subdomain enumeration"),
    ("amass", ["amass"], "sudo apt install amass", "Subdomain enumeration (passive)"),
    ("assetfinder", ["assetfinder"], "sudo apt install assetfinder", "Subdomain enumeration"),
    ("knockpy", ["knockpy"], "pipx install knock-subdomains", "Subdomain enumeration (best effort)"),
]


def find_tool(key: str) -> str | None:
    """Return the binary NAME to execute for a tool key (or None)."""
    for k, cands, _hint, _p in TOOLS:
        if k == key:
            for c in cands:
                if shutil.which(c):
                    return c
    return None


def tool_hint(key: str) -> str:
    for k, _c, hint, _p in TOOLS:
        if k == key:
            return hint
    return ""


def tool_available(name: str) -> bool:
    return find_tool(name) is not None or shutil.which(name) is not None


def _detect_windows_user() -> str | None:
    for cmd in (["cmd.exe", "/c", "echo %USERNAME%"],
                ["powershell.exe", "-NoProfile", "-Command", "$env:USERNAME"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            name = out.stdout.strip()
            if name and "%" not in name:
                return name
        except Exception:
            continue
    users = Path("/mnt/c/Users")
    if users.is_dir():
        for d in sorted(users.iterdir()):
            if d.is_dir() and d.name.lower() not in {"public", "default", "default user", "all users"}:
                return d.name
    return None


def default_results_root() -> str:
    user = _detect_windows_user()
    return f"/mnt/c/Users/{user}/lasy" if user else str(Path.home() / "lasy-results")


def _detect_prompt() -> tuple[str, str]:
    """The real user and host of this machine, so the terminal prompt matches the person's own Kali shell."""
    try:
        user = getpass.getuser()
    except Exception:
        user = "kali"
    return user or "kali", (socket.gethostname().split(".")[0] or "kali")


def _first_existing(paths: list[str]) -> str | None:
    for p in paths:
        if Path(p).exists():
            return p
    return None


def default_settings() -> dict[str, str]:
    from . import settings_spec
    base = {
        "setup_complete": "0",
        "results_root": default_results_root(),
        "kali_prompt_user": _detect_prompt()[0],
        "kali_prompt_host": _detect_prompt()[1],
        "nmap_max_parallel": "4",
        "nmap_batch_size": "8",
        "nmap_fullscan_chunk": "16384",
        "nmap_timing": "4",
        "nmap_udp_retries": "1",
        "nmap_use_sudo": "0",
        "nmap_extra_args": "",
        "seclists_root": _first_existing([
            "/usr/share/seclists", "/usr/share/wordlists/seclists", "/usr/share/SecLists",
            str(Path.home() / "SecLists"), str(Path.home() / "seclists"), "/opt/SecLists", "/opt/seclists"])
        or "/usr/share/seclists",
    }
    for key, value in settings_spec.defaults().items():
        base.setdefault(key, value)
    return base


BASE_KEYS = ["setup_complete", "results_root", "kali_prompt_user", "kali_prompt_host", "nmap_max_parallel", "nmap_batch_size",
             "nmap_fullscan_chunk", "nmap_timing", "nmap_udp_retries", "nmap_use_sudo", "nmap_extra_args", "seclists_root"]


def allowed_keys() -> set[str]:
    """Every setting key, without running the (slow) Windows-user detection."""
    from . import settings_spec
    return set(BASE_KEYS) | set(settings_spec.defaults())


def ensure_dirs() -> None:
    for d in (DATA_DIR, LOG_DIR, WORK_DIR, TERM_DIR):
        d.mkdir(parents=True, exist_ok=True)
