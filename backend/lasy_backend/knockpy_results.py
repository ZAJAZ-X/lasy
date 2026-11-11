"""Full subdomain names from knockpy.

knockpy prints its results in a Rich table whose Domain column is a fixed 26 characters wide and cuts longer
names with an ellipsis, so the screen text alone loses part of many real names. knockpy also saves every scan
completely in its own database; lasy reads the full list from there (read-only) and uses the screen text only
as a fallback. Older knockpy versions that write a JSON report file into the working folder are handled too."""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

_SAVED = re.compile(r"Saved report #\s*(\d+)")


def db_path() -> Path:
    """Same rule knockpy uses: $KNOCKPY_DB, otherwise ~/.knockpy/reports.db."""
    custom = os.getenv("KNOCKPY_DB")
    return Path(custom).expanduser() if custom else Path.home() / ".knockpy" / "reports.db"


def saved_report_ids(lines: list[str]) -> list[int]:
    return [int(m.group(1)) for ln in lines for m in [_SAVED.search(ln)] if m]


def _valid(name: object, domain: str) -> str | None:
    if not isinstance(name, str):
        return None
    n = name.strip().lower().lstrip("*.").strip(".")
    return n if n.endswith("." + domain.lower()) and "*" not in n and " " not in n else None


def names_from_report(domain: str, report_ids: list[int], started: datetime, search: bool = True) -> set[str]:
    """Names from knockpy's saved report: the one it announced. Only if it announced none AND the run exited cleanly
    (search=True) fall back to this domain's newest report created after we started."""
    p = db_path()
    if not p.is_file():
        return set()
    blobs: list[str] = []
    try:
        conn = sqlite3.connect(p.as_uri() + "?mode=ro", uri=True, timeout=5)
        try:
            if report_ids:
                for rid in report_ids:
                    blobs += [r[0] for r in conn.execute("SELECT results_json FROM scans WHERE id = ?", (rid,))]
            elif search:
                since = started.strftime("%Y-%m-%d %H:%M:%S")   # knockpy stores UTC; reports from before this run never qualify
                blobs += [r[0] for r in conn.execute(
                    "SELECT results_json FROM scans WHERE target = ? AND created_at >= ? ORDER BY id DESC LIMIT 1",
                    (domain, since))]
        finally:
            conn.close()
    except Exception:   # different knockpy version, locked or unreadable database: fall back to the screen text
        return set()
    names: set[str] = set()
    for blob in blobs:
        try:
            data = json.loads(blob)
        except (TypeError, ValueError):
            continue
        for item in (data if isinstance(data, list) else [data]):
            n = _valid(item.get("domain") if isinstance(item, dict) else None, domain)
            if n and n != domain.lower():
                names.add(n)
    return names


def names_from_json_files(domain: str, folder: Path | None) -> set[str]:
    """Older knockpy writes <domain>_<date>.json into the working folder."""
    out: set[str] = set()
    if not folder or not folder.is_dir():
        return out
    rx = re.compile(r"(?i)(?<![A-Za-z0-9_.*-])((?:[a-z0-9_*-]+\.)+" + re.escape(domain) + r")(?!\.?[A-Za-z0-9-])")
    for f in folder.glob("*.json"):
        try:
            for m in rx.finditer(f.read_text(errors="ignore")):
                n = _valid(m.group(1), domain)
                if n and n != domain.lower():
                    out.add(n)
        except OSError:
            continue
    return out


def full_names(domain: str, lines: list[str], started: datetime, folder: Path | None, clean_exit: bool = True) -> set[str]:
    return names_from_report(domain, saved_report_ids(lines), started, search=clean_exit) | names_from_json_files(domain, folder)
