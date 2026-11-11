"""`lasy doctor`: checks everything lasy depends on and says how to fix what is missing."""
from __future__ import annotations

import os
import shutil
import sys
import urllib.request
from pathlib import Path

from . import config, db, nmaptools

G, R, Y, D, B, X = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"


def ok(msg: str) -> None:
    print(f"  {G}✓{X} {msg}")


def bad(msg: str, fix: str = "") -> None:
    print(f"  {R}✗{X} {msg}" + (f"\n      {Y}fix:{X} {fix}" if fix else ""))


def warn(msg: str, fix: str = "") -> None:
    print(f"  {Y}!{X} {msg}" + (f"\n      {Y}fix:{X} {fix}" if fix else ""))


def main() -> int:
    problems = 0
    db.init_db()
    print(f"{B}lasy doctor{X}\n")
    print(f"{B}Environment{X}")
    ok(f"Python {sys.version.split()[0]}")
    if Path("/proc/version").exists() and "microsoft" in Path("/proc/version").read_text().lower():
        ok("Running inside WSL")
    else:
        warn("This does not look like WSL (the Windows browser launch and /mnt paths expect it)")
    opener = shutil.which("wslview") or shutil.which("powershell.exe") or shutil.which("cmd.exe")
    ok(f"Windows browser launcher: {Path(opener).name}") if opener else warn(
        "No way to open the Windows browser automatically", "sudo apt install wslu  (or open the URL by hand)")

    print(f"\n{B}Storage{X}")
    root = db.get_setting("results_root")
    if db.get_setting("setup_complete") != "1":
        warn("First-run setup has not been completed yet", "run lasy and choose your results folder")
    try:
        Path(root).mkdir(parents=True, exist_ok=True)
        (Path(root) / ".lasy_probe").write_text("x")
        (Path(root) / ".lasy_probe").unlink()
        ok(f"Results folder is writable: {root}")
    except Exception as exc:  # noqa: BLE001
        problems += 1
        bad(f"Results folder is not writable: {root} ({exc.__class__.__name__})",
            "check the drive is mounted (ls /mnt/c) and fix the path in Settings")
    ok(f"Database and work files (Linux side): {config.DATA_DIR}")

    print(f"\n{B}Tools{X}")
    for key, cands, hint, purpose in config.TOOLS:
        found = config.find_tool(key)
        if found:
            ok(f"{key:12s} {D}{shutil.which(found)}{X}")
        else:
            critical = key in ("nmap", "dig")
            problems += 1 if critical else 0
            (bad if critical else warn)(f"{key:12s} not installed ({purpose})", hint)

    print(f"\n{B}Scanning without sudo{X}")
    if shutil.which("nmap"):
        res = nmaptools.privilege_check()
        if res["ok"]:
            ok("nmap can use raw sockets without a password (SYN and UDP scans will work)")
        else:
            problems += 1
            bad(f"nmap raw sockets not available: {res['detail']}", res["fix"])

    print(f"\n{B}Wordlists and templates{X}")
    sl = db.get_setting("seclists_root", "/usr/share/seclists")
    if os.path.isdir(sl):
        ok(f"SecLists found: {sl}")
    else:
        warn("SecLists not found (directory discovery wordlist suggestions need it)", "sudo apt install seclists")
    tpl = [Path.home() / "nuclei-templates", Path.home() / ".local/nuclei-templates"]
    if shutil.which("nuclei"):
        ok("nuclei templates present") if any(p.is_dir() for p in tpl) else warn(
            "nuclei templates not downloaded yet", "nuclei -update-templates")

    print(f"\n{B}Backend{X}")
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{config.PORT}/api/health", timeout=2)
        ok(f"lasy is running on http://127.0.0.1:{config.PORT}")
    except Exception:
        warn("lasy is not running right now", "start it with: lasy")
    print()
    print(f"{G}All essential checks passed.{X}" if not problems else f"{R}{problems} essential problem(s) above.{X}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
