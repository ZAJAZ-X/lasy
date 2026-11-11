"""Database engine, settings, project folders and small scan helpers."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine, select

from . import config
from .models import Finding, Project, Scan, Setting, Severity

config.ensure_dirs()
_engine = create_engine(
    f"sqlite:///{config.DB_PATH}",
    connect_args={"check_same_thread": False, "timeout": 30},
)


@event.listens_for(_engine, "connect")
def _pragmas(conn, _rec):  # WAL + busy timeout: safe with several concurrent scans
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA busy_timeout=30000")
    cur.close()


def init_db() -> None:
    SQLModel.metadata.create_all(_engine)
    with _engine.begin() as c:  # lightweight migration for older installs
        cols = {r[1] for r in c.exec_driver_sql("PRAGMA table_info(scan)")}
        if "parent_id" not in cols:
            c.exec_driver_sql("ALTER TABLE scan ADD COLUMN parent_id INTEGER")
        if "meta" not in cols:
            c.exec_driver_sql("ALTER TABLE scan ADD COLUMN meta JSON")
    with Session(_engine) as s:
        existing = {row.key for row in s.exec(select(Setting)).all()}
        for k, v in config.default_settings().items():
            if k not in existing:
                s.add(Setting(key=k, value=v))
        s.commit()


def get_session() -> Session:
    return Session(_engine)


# --- settings -------------------------------------------------------------
def get_setting(key: str, default: str = "") -> str:
    try:
        with get_session() as s:
            row = s.get(Setting, key)
            return row.value if row else default
    except Exception:
        return default


def set_setting(key: str, value: str) -> None:
    with get_session() as s:
        row = s.get(Setting, key)
        if row:
            row.value = value
        else:
            row = Setting(key=key, value=value)
        s.add(row)
        s.commit()


def all_settings() -> dict[str, str]:
    with get_session() as s:
        return {r.key: r.value for r in s.exec(select(Setting)).all() if not r.key.startswith("p.")}


# --- projects -------------------------------------------------------------
_SLUG_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def slugify(name: str) -> str:
    return _SLUG_RE.sub("_", name.strip()).strip("_") or "project"


_SUBDIRS = ("nmap", "webapt", "subdomain", "nameserver", "hostup", "exports")


def create_project_folder(slug: str) -> Path:
    root = Path(get_setting("results_root", config.default_results_root()))
    folder = root / slug
    for sub in _SUBDIRS:
        (folder / sub).mkdir(parents=True, exist_ok=True)
    return folder


def work_dir(slug: str) -> Path:
    d = config.WORK_DIR / slug
    d.mkdir(parents=True, exist_ok=True)
    return d


# --- scan helpers ---------------------------------------------------------
def get_scan(sid: int) -> Scan | None:
    with get_session() as s:
        return s.get(Scan, sid)


def get_project(pid: int) -> Project | None:
    with get_session() as s:
        return s.get(Project, pid)


def patch_meta(sid: int, **kv: Any) -> dict:
    with get_session() as s:
        sc = s.get(Scan, sid)
        if not sc:
            return {}
        m = dict(sc.meta or {})
        m.update(kv)
        sc.meta = m
        s.add(sc)
        s.commit()
        return m


def update_batch(sid: int, idx: int, **kv: Any) -> None:
    with get_session() as s:
        sc = s.get(Scan, sid)
        if not sc:
            return
        m = dict(sc.meta or {})
        batches = [dict(b) for b in m.get("batches", [])]
        for b in batches:
            if b["idx"] == idx:
                b.update(kv)
        m["batches"] = batches
        sc.meta = m
        s.add(sc)
        s.commit()


def save_findings(sid: int, findings: list[dict]) -> None:
    with get_session() as s:
        for old in s.exec(select(Finding).where(Finding.scan_id == sid)).all():
            s.delete(old)
        for f in findings:
            sev = f.get("severity", "info")
            s.add(Finding(
                scan_id=sid, severity=Severity(sev), title=f["title"][:300],
                target=f.get("target", ""), evidence=(f.get("evidence") or "")[:4000],
                extra=f.get("extra"),
            ))
        s.commit()


def list_findings(sid: int) -> list[Finding]:
    with get_session() as s:
        return list(s.exec(select(Finding).where(Finding.scan_id == sid)).all())
