"""Subdomain enumeration: five sources run in parallel, merged, resolved and probed.

Sources: subfinder, knockpy (best effort), amass (passive), assetfinder, crt.sh.
A source that is missing, times out or fails just contributes less; it never
breaks the run. Results keep per-tool lists so unique finds can be shown.
"""
from __future__ import annotations

import asyncio
import csv
import re
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

from .. import commands, db, knockpy_results
from ..engine import ScanContext, ToolMissing
from ..models import Project

SUB_TOOLS = ["subfinder", "knockpy", "amass", "assetfinder", "crtsh"]
LABEL = {"subfinder": "subfinder", "knockpy": "knockpy", "amass": "amass (passive)",
         "assetfinder": "assetfinder", "crtsh": "crt.sh (built-in)"}
UA = {"User-Agent": "Mozilla/5.0 (compatible; lasy)"}


def extract(lines: list[str], domain: str) -> set[str]:
    rx = re.compile(r"(?i)(?<![A-Za-z0-9_.*-])((?:[a-z0-9_*-]+\.)+" + re.escape(domain) + r")(?!\.?[A-Za-z0-9-])")
    found: set[str] = set()
    for ln in lines:
        for m in rx.finditer(ln):
            name = m.group(1).lower().lstrip("*.").strip(".")
            if name and "*" not in name and name != domain.lower():
                found.add(name)
    return found


async def _src_cli(ctx: ScanContext, tool: str, domain: str, ddir: Path, ch: str) -> set[str]:
    c = commands.cfg()
    out = ddir / f"{tool}.txt"
    limit = commands.source_limit(c, tool)
    argv = commands.SOURCE_ARGV[tool](c, domain)
    tried: list[list[str]] = []
    found: set[str] = set()
    started = datetime.now(timezone.utc)
    scratch = None
    if tool == "knockpy":   # run in a scratch folder so older versions' JSON reports do not land in the app folder
        scratch = db.work_dir("_tools") / "knockpy" / f"{started:%Y%m%d-%H%M%S}-{domain.replace('/', '_')}"
        scratch.mkdir(parents=True, exist_ok=True)
    while argv is not None:
        lines: list[str] = []
        code = await ctx.run(argv, channel=ch, result_file=out, append_result=bool(tried), line_sink=lines,
                             timeout=limit, cwd=scratch)
        tried.append(argv)
        found = extract(lines, domain)
        if tool == "knockpy":   # its on-screen table cuts long names; read the complete list from its saved report
            full = knockpy_results.full_names(domain, lines, started, scratch, clean_exit=(code == 0))
            if full - found:
                ctx.emit(f"[lasy] knockpy's on-screen table cuts long names. Read {len(full - found)} more complete name(s) "
                         "from its saved report.", ch)
            found |= full
        if found:
            break
        # the installed version may not know a flag: try a gentler form instead of giving up
        argv = commands.retry_argv(c, tool, argv, lines, code, domain, tried)
    ctx.add_output(out)
    if tool == "knockpy" and found:
        full_file = ddir / "knockpy_subdomains.txt"
        full_file.write_text("\n".join(sorted(found)) + "\n")
        ctx.add_output(full_file)
    return found


async def _src_crtsh(ctx: ScanContext, domain: str, ddir: Path, ch: str) -> set[str]:
    import httpx
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    ctx.emit(f"Querying crt.sh certificate transparency logs for {domain} …", ch)
    data = None
    for attempt in (1, 2, 3):
        try:
            async with httpx.AsyncClient(timeout=45, headers=UA) as c:
                r = await c.get(url)
                r.raise_for_status()
                data = r.json()
                break
        except Exception as exc:  # noqa: BLE001
            ctx.emit(f"attempt {attempt} failed: {exc.__class__.__name__}", ch)
            await asyncio.sleep(3)
    if data is None:
        raise RuntimeError("crt.sh did not respond (it is often overloaded)")
    names: set[str] = set()
    for row in data:
        for n in str(row.get("name_value", "")).split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith("." + domain.lower()) and "*" not in n:
                names.add(n)
    out = ddir / "crtsh.txt"
    out.write_text("\n".join(sorted(names)) + ("\n" if names else ""))
    ctx.add_output(out)
    ctx.emit(f"{len(names)} unique names found.", ch)
    return names


async def resolve_all(names: list[str], limit: int | None = None) -> dict[str, str | None]:
    loop = asyncio.get_running_loop()
    limit = limit or int(commands.cfg().get("sub_resolve_concurrency") or 50)
    sem = asyncio.Semaphore(limit)
    result: dict[str, str | None] = {}

    async def one(n: str) -> None:
        async with sem:
            try:
                info = await asyncio.wait_for(loop.getaddrinfo(n, None, family=socket.AF_INET), 8)
                result[n] = info[0][4][0]
            except Exception:
                try:
                    info = await asyncio.wait_for(loop.getaddrinfo(n, None, family=socket.AF_INET6), 8)
                    result[n] = info[0][4][0]
                except Exception:
                    result[n] = None

    await asyncio.gather(*[one(n) for n in names])
    return result


async def probe_all(names: list[str], limit: int | None = None) -> dict[str, tuple[int | None, str | None]]:
    import httpx
    c = commands.cfg()
    limit = limit or int(c.get("sub_probe_concurrency") or 40)
    sem = asyncio.Semaphore(limit)
    result: dict[str, tuple[int | None, str | None]] = {}
    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=int(c.get("sub_probe_timeout") or 8), headers=UA) as client:
        async def one(n: str) -> None:
            async with sem:
                for scheme in ("https", "http"):
                    try:
                        r = await client.get(f"{scheme}://{n}/")
                        loc = r.headers.get("location")
                        result[n] = (r.status_code, urljoin(str(r.url), loc) if loc else None)
                        return
                    except Exception:
                        continue
                result[n] = (None, None)

        await asyncio.gather(*[one(n) for n in names])
    return result


def classify(ip: str | None, status: int | None, location: str | None) -> tuple[str, str | None]:
    """Accessibility rule: 4xx -> No, 3xx -> Yes + redirect target, other responses -> Yes,
    no IP or no HTTP response -> '-'."""
    if not ip or status is None:
        return "-", None
    if 400 <= status < 500:
        return "no", None
    if 300 <= status < 400:
        return "yes", location
    return "yes", None


def build(project: Project, domains: list[str], tools: list[str]):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    tools = [t for t in SUB_TOOLS if t in tools] or list(SUB_TOOLS)

    async def body(ctx: ScanContext) -> None:
        run_dir = Path(project.folder) / "subdomain" / f"enum-{stamp}"
        by_tool: dict[str, set[str]] = {t: set() for t in tools}
        status: dict[str, dict] = {t: {"state": "ok", "note": ""} for t in tools}

        for domain in domains:
            ddir = run_dir / domain.replace("/", "_")
            ddir.mkdir(parents=True, exist_ok=True)
            for t in tools:
                ctx.add_channel(f"{t}:{domain}", f"{LABEL[t]} · {domain}")

            async def one(t: str):
                ch = f"{t}:{domain}"
                try:
                    found = await (_src_crtsh(ctx, domain, ddir, ch) if t == "crtsh"
                                   else _src_cli(ctx, t, domain, ddir, ch))
                    return t, found
                except ToolMissing as exc:
                    status[t] = {"state": "missing", "note": str(exc)}
                except Exception as exc:  # noqa: BLE001
                    ctx.emit(f"[lasy] {LABEL[t]} failed: {exc}", ch)
                    status[t] = {"state": "failed", "note": str(exc)}
                return t, set()

            for t, found in await asyncio.gather(*[one(t) for t in tools]):
                by_tool[t] |= found

        merged = sorted(set().union(*by_tool.values()))
        ctx.add_channel("resolve", "Resolution and reachability")
        ctx.emit(f"Merged {len(merged)} unique subdomain(s). Resolving to IP addresses …", "resolve")
        wildcards: dict[str, str] = {}
        for domain in domains:   # a random name that resolves means the zone has a wildcard record
            probe = f"lasy-{uuid.uuid4().hex[:12]}.{domain}"
            hit = (await resolve_all([probe])).get(probe)
            if hit:
                wildcards[domain] = hit
                ctx.emit(f"Wildcard DNS detected for {domain}: random names resolve to {hit}. "
                         "Names with that IP may not be real hosts.", "resolve")
        ips = await resolve_all(merged)
        live = [n for n in merged if ips.get(n)]
        ctx.emit(f"{len(live)} resolved. Checking HTTP(S) reachability …", "resolve")
        probes = await probe_all(live)

        rows = []
        for n in merged:
            st, loc = probes.get(n, (None, None))
            acc, redirect = classify(ips.get(n), st, loc)
            root = next((d for d in domains if n.endswith("." + d)), "")
            rows.append({"domain": n, "ip": ips.get(n), "accessible": acc, "redirect": redirect,
                         "status": st, "tools": [t for t in tools if n in by_tool[t]],
                         "wildcard": bool(ips.get(n) and wildcards.get(root) == ips.get(n))})
        unique = {t: sorted(n for n in by_tool[t]
                            if not any(n in by_tool[o] for o in tools if o != t)) for t in tools}
        ctx.emit(f"Done: {sum(1 for r in rows if r['accessible'] == 'yes')} reachable, "
                 f"{sum(1 for r in rows if r['accessible'] == 'no')} returned 4xx.", "resolve")

        (run_dir / "subdomains_merged.txt").write_text("\n".join(merged) + ("\n" if merged else ""))
        with open(run_dir / "subdomains_resolved.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["subdomain", "ip", "accessible", "redirect", "http_status", "found_by"])
            for r in rows:
                w.writerow([r["domain"], r["ip"] or "-", r["accessible"], r["redirect"] or "",
                            r["status"] or "", ";".join(r["tools"])])
        with open(run_dir / "unique_by_tool.txt", "w") as f:
            for t in tools:
                f.write(f"# {LABEL[t]}: {len(unique[t])} found only by this tool\n")
                f.write("\n".join(unique[t]) + ("\n" if unique[t] else "") + "\n")
        for name in ("subdomains_merged.txt", "subdomains_resolved.csv", "unique_by_tool.txt"):
            ctx.add_output(run_dir / name)
        summary = {t: {"found": len(by_tool[t]), "unique": len(unique[t]), **status[t]} for t in tools}
        ctx.store_result({"rows": rows, "by_tool": {t: sorted(v) for t, v in by_tool.items()},
                          "unique": unique, "summary": summary, "domains": domains, "wildcards": wildcards,
                          "labels": {t: LABEL[t] for t in tools}})

    return body
