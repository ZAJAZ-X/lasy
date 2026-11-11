"""Nameserver lookup with dig. Lightweight: no pause/resume."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from .. import commands
from ..engine import ScanContext
from ..models import Project

_NS = re.compile(r"^\S+\s+\d+\s+IN\s+NS\s+(\S+)", re.I)


def parse_answer(lines: list[str]) -> list[str]:
    out, in_answer = [], False
    for ln in lines:
        if ln.startswith(";; ANSWER SECTION:"):
            in_answer = True
            continue
        if in_answer and (ln.startswith(";;") or not ln.strip()):
            in_answer = False
            continue
        if in_answer:
            m = _NS.match(ln.strip())
            if m:
                ns = m.group(1).rstrip(".").lower()
                if ns not in out:
                    out.append(ns)
    return out


def build(project: Project, domains: list[str]):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    async def body(ctx: ScanContext) -> None:
        out = Path(project.folder) / "nameserver" / f"nameserver-{stamp}.txt"
        rows: list[dict] = []
        for i, domain in enumerate(domains):
            captured: list[str] = []
            await ctx.run(commands.dig_argv(commands.cfg(), domain), result_file=out, append_result=i > 0, line_sink=captured)
            found = parse_answer(captured)
            if not found:
                ctx.emit(f"[lasy] No NS records returned for {domain}. If this is a subdomain, "
                         "query the registered domain instead.")
                rows.append({"domain": domain, "nameserver": None})
            for ns in found:
                rows.append({"domain": domain, "nameserver": ns})
        ctx.add_output(out)
        ctx.store_result({"rows": rows, "multi": len(domains) > 1})

    return body
