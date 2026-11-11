"""Host up/down check via `nmap -sn`. Lightweight: no pause/resume.

Every IP or domain you enter gets a row. CIDR ranges contribute rows only for
hosts that actually respond (a /24 would otherwise add 250 empty rows).
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from .. import db, nmaptools
from ..engine import ScanContext, StageError
from ..models import Project
from ..targets import TargetKind, oversized_ranges, parse_targets, range_error

_REPORT = re.compile(r"Nmap scan report for (\S+)(?:\s+\(([0-9a-fA-F:.]+)\))?")


def build(project: Project, text: str):
    targets = [t for t in parse_targets(text) if t.kind != TargetKind.UNKNOWN]
    explicit = [t.value for t in targets if t.kind != TargetKind.CIDR]
    cidrs = [t.value for t in targets if t.kind == TargetKind.CIDR]
    if not explicit and not cidrs:
        raise ValueError("Enter at least one IP address, domain or CIDR range.")
    if oversized_ranges(targets):
        raise ValueError(range_error(oversized_ranges(targets)))
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    async def body(ctx: ScanContext) -> None:
        work = db.work_dir(project.slug) / f"hostup-{stamp}"
        work.mkdir(parents=True, exist_ok=True)
        infile = work / "hosts.txt"
        infile.write_text("\n".join(dict.fromkeys(explicit + cidrs)) + "\n")
        out = Path(project.folder) / "hostup" / f"hostup-{stamp}.txt"
        captured: list[str] = []
        await ctx.run(nmaptools.nmap_argv(["-sn", "-iL", str(infile)]), result_file=out,
                      line_sink=captured, env=nmaptools.nmap_env(),
                      display=["nmap", "-sn", "-iL", "hosts.txt"])
        ctx.add_output(out)
        blob = "\n".join(captured)
        if "requires root" in blob.lower() or "operation not permitted" in blob.lower():
            raise StageError(nmaptools.error_hint(captured))

        up_tokens: set[str] = set()
        up_order: list[str] = []
        last = None
        for line in captured:
            m = _REPORT.search(line)
            if m:
                last = (m.group(1), m.group(2))
            elif "Host is up" in line and last:
                for tok in last:
                    if tok:
                        up_tokens.add(tok.lower())
                up_order.append(last[1] or last[0])
        rows = [{"host": h, "status": "Up" if h.lower() in up_tokens else "Down"} for h in explicit]
        listed = {h.lower() for h in explicit}
        for ip in up_order:
            if ip.lower() not in listed and ip.lower() not in {r["host"].lower() for r in rows}:
                rows.append({"host": ip, "status": "Up"})
        ctx.store_result({"rows": rows})

    return body
