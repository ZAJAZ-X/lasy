"""Database models (SQLite via SQLModel)."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from sqlalchemy import Column
from sqlalchemy.types import JSON
from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ScanState(str, Enum):
    pending = "pending"          # created, never started
    queued = "queued"
    running = "running"
    paused = "paused"
    interrupted = "interrupted"  # process died (restart/sleep); resumable
    done = "done"
    failed = "failed"
    canceled = "canceled"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Project(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    slug: str = Field(index=True, unique=True)
    folder: str
    created_at: datetime = Field(default_factory=_now)


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(index=True, foreign_key="project.id")
    parent_id: Optional[int] = Field(default=None, index=True)
    kind: str = Field(index=True)
    label: str
    state: ScanState = Field(default=ScanState.queued, index=True)
    command: str = ""
    resumable: bool = False
    output_paths: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    result_json: Any = Field(default=None, sa_column=Column(JSON))
    meta: Any = Field(default=None, sa_column=Column(JSON))
    error: str = ""
    progress: float = 0.0
    created_at: datetime = Field(default_factory=_now)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(index=True, foreign_key="scan.id")
    severity: Severity = Field(index=True)
    title: str
    target: str = ""
    evidence: str = ""
    extra: Any = Field(default=None, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_now)


class WebTarget(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(index=True, foreign_key="project.id")
    host: str
    port: int
    scheme: str = "https"
    source: str = "manual"
    created_at: datetime = Field(default_factory=_now)


class Setting(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str = ""
