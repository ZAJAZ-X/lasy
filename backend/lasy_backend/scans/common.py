"""Helpers shared by scan implementations."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path


def stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def write_input_file(folder: Path, name: str, hosts: list[str]) -> Path:
    """Persist the exact target list used for a scan (nothing overwritten)."""
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}-{stamp()}.txt"
    path.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    return path


def out_file(folder: Path, name: str, ext: str = "txt") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{name}-{stamp()}.{ext}"
