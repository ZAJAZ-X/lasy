"""External Pentest nmap workflow.

A *session* holds the target list and eight *stage* scans. Each stage is split
into *batches* (a few hosts per nmap process, optionally per port range) that run
in parallel up to a configurable cap. Every batch writes its own -oA files, so a
pause or restart loses at most the host (or port chunk) that was in flight.
"""
from __future__ import annotations

import asyncio
import ipaddress
import shlex
from datetime import datetime
from pathlib import Path

from .. import db, nmaptools
from ..engine import ScanContext, StageError, engine
from ..models import Project, Scan, ScanState
from ..targets import TargetKind, oversized_ranges, parse_targets, range_error

STAGES: dict[str, dict] = {
    "tcp_top": dict(n=1, label="TCP top 1000 ports", core=True, default=True, bg=False, proto="tcp",
                    dirname="01_tcp_top1000", cmd="nmap -Pn --top-ports 1000 --open -T4",
                    desc="Fast sweep of the 1000 most common TCP ports."),
    "tcp_enum": dict(n=2, label="Service and script scan on open TCP ports", core=False, default=True,
                     bg=False, proto="tcp", needs="tcp_top", dirname="02_tcp_service_scan",
                     cmd="nmap -Pn -sV -sC -p <open ports>",
                     desc="Version detection and default scripts on the open TCP ports found above."),
    "udp_top": dict(n=3, label="UDP top 1000 ports", core=True, default=True, bg=False, proto="udp",
                    dirname="03_udp_top1000", cmd="nmap -sU -Pn --top-ports 1000 --open -T4",
                    desc="Baseline UDP sweep. Always part of a full run."),
    "udp_enum": dict(n=4, label="Service and script scan on open UDP ports", core=False, default=True,
                     bg=False, proto="udp", needs="udp_top", dirname="04_udp_service_scan",
                     cmd="nmap -sU -Pn -sV -sC -p <open ports>",
                     desc="Version detection and default scripts on the open UDP ports found above."),
    "tcp_full": dict(n=5, label="TCP all ports (background)", core=False, default=True, bg=True,
                     proto="tcp", dirname="05_tcp_all_ports", cmd="nmap -Pn -p- --open -T4",
                     desc="Full 65535-port TCP scan, split into port chunks so it can resume."),
    "udp_full": dict(n=6, label="UDP all ports (background)", core=False, default=False, bg=True,
                     proto="udp", dirname="06_udp_all_ports", cmd="nmap -sU -Pn -p- --open -T4",
                     desc="Full UDP scan. Very slow (hours to days); off by default."),
    "tcp_full_enum": dict(n=7, label="Service scan on new TCP ports from the full scan", core=False,
                          default=True, bg=False, proto="tcp", auto_of="tcp_full", top="tcp_top",
                          dirname="07_tcp_allports_new_ports", cmd="nmap -Pn -sV -sC -p <new ports>",
                          desc="Runs automatically for ports the full scan found beyond the top 1000."),
    "udp_full_enum": dict(n=8, label="Service scan on new UDP ports from the full scan", core=False,
                          default=True, bg=False, proto="udp", auto_of="udp_full", top="udp_top",
                          dirname="08_udp_allports_new_ports", cmd="nmap -sU -Pn -sV -sC -p <new ports>",
                          desc="Runs automatically for ports the full scan found beyond the top 1000."),
}
FG_ORDER = ["tcp_top", "tcp_enum", "udp_top", "udp_enum"]
BG_ORDER = ["tcp_full", "udp_full"]
MERGE_ORDER = ["tcp_top", "udp_top", "tcp_full", "udp_full",
               "tcp_enum", "udp_enum", "tcp_full_enum", "udp_full_enum"]
ENUM_KEYS = {"tcp_enum", "udp_enum", "tcp_full_enum", "udp_full_enum"}
ACTIVE = (ScanState.queued, ScanState.running)

_locks: dict[int, asyncio.Lock] = {}


def _int(key: str, default: int) -> int:
    try:
        return max(1, int(db.get_setting(key, str(default))))
    except ValueError:
        return default


def chunks(items: list, n: int) -> list[list]:
    return [items[i:i + n] for i in range(0, len(items), n)] or []


# --------------------------------------------------------------------------
# sessions
# --------------------------------------------------------------------------
def create_session(project: Project, text: str, cidr_discovery: bool = True) -> Scan:
    targets = parse_targets(text)
    valid = [t for t in targets if t.kind != TargetKind.UNKNOWN]
    invalid = [t.raw for t in targets if t.kind == TargetKind.UNKNOWN]
    if not valid:
        raise ValueError("No valid targets found. Enter IP addresses, CIDR ranges or domains.")
    if oversized_ranges(valid):
        raise ValueError(range_error(oversized_ranges(valid)))
    explicit: list[str] = []
    domains: list[str] = []
    cidrs: list[str] = []
    for t in valid:
        if t.kind == TargetKind.CIDR:
            cidrs.append(t.value)
        elif t.value not in explicit:
            explicit.append(t.value)
            if t.kind in (TargetKind.DOMAIN, TargetKind.URL):
                domains.append(t.value)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = Path(project.folder) / "nmap" / f"scan-{stamp}"
    folder.mkdir(parents=True, exist_ok=True)
    work = db.work_dir(project.slug) / f"nmap-{stamp}"
    work.mkdir(parents=True, exist_ok=True)
    (work / "targets.txt").write_text("\n".join(explicit + cidrs) + "\n")
    meta = dict(explicit=explicit, domains=domains, cidrs=cidrs, cidr_discovery=cidr_discovery,
                discovered=None, folder=str(folder), work=str(work), stamp=stamp, invalid=invalid)
    with db.get_session() as s:
        sess = Scan(project_id=project.id, kind="nmap_session", label=f"Nmap scan {stamp}",
                    state=ScanState.done, meta=meta)
        s.add(sess)
        s.commit()
        s.refresh(sess)
        for key, st in STAGES.items():
            s.add(Scan(project_id=project.id, parent_id=sess.id, kind=f"nmap_{key}", label=st["label"],
                       state=ScanState.pending, resumable=True,
                       meta={"stage": key, "selected": st["default"], "batches": [], "channels": [], "run": 0}))
        s.commit()
        s.refresh(sess)
        return sess


def stage_rows(sess_id: int) -> dict[str, Scan]:
    from sqlmodel import select
    with db.get_session() as s:
        rows = s.exec(select(Scan).where(Scan.parent_id == sess_id)).all()
        return {(r.meta or {}).get("stage"): r for r in rows}


def stage_key(scan: Scan) -> str:
    return (scan.meta or {}).get("stage", "")


# --------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------
def load_results(sess_id: int, key: str) -> dict[str, dict]:
    sc = stage_rows(sess_id).get(key)
    merged: dict[str, dict] = {}
    if not sc:
        return merged
    for b in (sc.meta or {}).get("batches", []):
        nmaptools.merge_hosts(merged, nmaptools.parse_gnmap(b["base"] + ".gnmap"))
    return merged


def discovery_hosts(sess_meta: dict) -> list[str]:
    return list(sess_meta.get("discovered") or [])


def build_table(sess_id: int) -> dict:
    sess = db.get_scan(sess_id)
    sm = sess.meta
    stages = stage_rows(sess_id)
    parsed = {k: load_results(sess_id, k) for k in MERGE_ORDER}
    domains = {d.lower() for d in sm.get("domains", [])}

    ip_label: dict[str, str] = {}
    for res in parsed.values():
        for ip, rec in res.items():
            if rec["hostname"] and rec["hostname"].lower() in domains:
                ip_label[ip] = rec["hostname"].lower()

    ports: dict[str, dict[tuple, dict]] = {}
    up_ips: set[str] = set()
    for key in MERGE_ORDER:
        is_enum = key in ENUM_KEYS
        for ip, rec in parsed[key].items():
            label = ip_label.get(ip, ip)
            if rec["up"] and key.endswith("top"):
                up_ips.add(label)
            for p in rec["ports"]:
                if p["state"] != "open":
                    continue
                ent = ports.setdefault(label, {}).setdefault(
                    (p["port"], p["proto"]), {"service": "", "version": ""})
                svc = nmaptools.pretty_service(p["service"])
                if svc != "-" and (is_enum or not ent["service"]):
                    ent["service"] = svc
                if p["version"] and (is_enum or not ent["version"]):
                    ent["version"] = p["version"]

    live_cidr = set(discovery_hosts(sm)) if sm.get("cidr_discovery") else set()
    order = list(sm.get("explicit", []))
    extras = sorted(
        {l for l in ports if l not in order} | (live_cidr - set(order)),
        key=lambda x: (0, ipaddress.ip_address(x)) if _is_ip(x) else (1, x),
    )
    rows = []
    for host in order + [e for e in extras if e not in order]:
        plist = []
        for (port, proto), ent in sorted(ports.get(host, {}).items()):
            plist.append({"port": f"{port}/{proto}", "service": ent["service"] or "-",
                          "version": ent["version"] or "-"})
        rows.append({"host": host, "ports": plist})
    started = [s for s in stages.values() if s.state != ScanState.pending]
    return {
        "columns": ["Sl No.", "Host/IP Address", "Open Port", "Service Detection", "Server Type/Version"],
        "rows": rows,
        "stats": {"hosts": len(rows), "with_open_ports": sum(1 for r in rows if r["ports"]),
                  "open_ports": sum(len(r["ports"]) for r in rows)},
        "running": any(s.state in ACTIVE for s in stages.values()),
        "started": bool(started),
        "invalid": sm.get("invalid", []),
    }


def _is_ip(x: str) -> bool:
    try:
        ipaddress.ip_address(x)
        return True
    except ValueError:
        return False


WEB_PORTS = {80, 81, 443, 591, 8000, 8008, 8080, 8081, 8088, 8443, 8444, 8888, 9000, 9090, 9443}
TLS_PORTS = {443, 444, 8443, 8444, 9443, 7443}


def web_candidates(sess_id: int) -> list[dict]:
    out = []
    for row in build_table(sess_id)["rows"]:
        for p in row["ports"]:
            port = int(p["port"].split("/")[0])
            if p["port"].endswith("/udp"):
                continue
            svc = p["service"].lower()
            if "http" in svc or port in WEB_PORTS:
                tls = svc.startswith("https") or svc.startswith("ssl") or port in TLS_PORTS
                out.append({"host": row["host"], "port": port, "scheme": "https" if tls else "http",
                            "service": p["service"]})
    return out


# --------------------------------------------------------------------------
# planning
# --------------------------------------------------------------------------
def _stage_dir(sm: dict, key: str, run: int) -> Path:
    name = STAGES[key]["dirname"] + (f"_run{run}" if run > 1 else "")
    d = Path(sm["folder"]) / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _timing() -> str:
    return f"-T{_int('nmap_timing', 4)}"


def _udp_retries() -> list[str]:
    return ["--max-retries", str(_int("nmap_udp_retries", 1))]


def _split_families(hosts: list[str]) -> list[tuple[list[str], list[str]]]:
    v6 = [h for h in hosts if ":" in h]
    v4 = [h for h in hosts if ":" not in h]
    groups = []
    if v4:
        groups.append((v4, []))
    if v6:
        groups.append((v6, ["-6"]))
    return groups


def _make_batches(sm: dict, key: str, run: int, items: list[tuple[list[str], list[str], str]]) -> list[dict]:
    """items: (hosts, args, label_suffix) -> batch dicts with input files written."""
    sdir = _stage_dir(sm, key, run)
    try:
        user_extra = shlex.split(db.get_setting("nmap_extra_args", ""))
    except ValueError:
        user_extra = []
    wdir = Path(sm["work"]) / f"{key}-run{run}"
    wdir.mkdir(parents=True, exist_ok=True)
    batches = []
    for i, (hosts, args, suffix) in enumerate(items, start=1):
        name = f"batch{i:02d}"
        infile = wdir / f"{name}.txt"
        infile.write_text("\n".join(hosts) + "\n")
        batches.append({
            "idx": i, "channel": f"b{i}", "name": name, "state": "pending", "args": args + user_extra,
            "infile": str(infile), "base": str(sdir / name), "n_hosts": len(hosts),
            "label": f"Batch {i} · {len(hosts)} host{'s' if len(hosts) != 1 else ''}{suffix}",
        })
    return batches


def _port_ranges() -> list[tuple[int, int]]:
    width = max(1024, _int("nmap_fullscan_chunk", 16384))
    out, lo = [], 1
    while lo <= 65535:
        hi = min(65535, lo + width - 1)
        out.append((lo, hi))
        lo = hi + 1
    return out


async def ensure_hosts(ctx: ScanContext, sess_id: int) -> list[str]:
    """Explicit hosts plus, for CIDR ranges, the live hosts found by discovery."""
    lock = _locks.setdefault(sess_id, asyncio.Lock())
    async with lock:
        sm = db.get_scan(sess_id).meta
        hosts = list(sm["explicit"])
        cidrs = sm.get("cidrs", [])
        if cidrs and sm.get("discovered") is None:
            if sm.get("cidr_discovery", True):
                ctx.add_channel("discovery", "Host discovery (ranges)")
                ddir = Path(sm["folder"]) / "00_discovery"
                ddir.mkdir(parents=True, exist_ok=True)
                infile = Path(sm["work"]) / "ranges.txt"
                infile.write_text("\n".join(cidrs) + "\n")
                base = ddir / "discovery"
                await ctx.run(
                    nmaptools.nmap_argv(["-sn", "-PE", "-PS22,80,443,3389", "-PA80,443", "-PP",
                                         "-oA", str(base), "-iL", str(infile)]),
                    channel="discovery", env=nmaptools.nmap_env(),
                    display=["nmap", "-sn", "-PE", "-PS22,80,443,3389", "-PA80,443", "-PP",
                             "-oA", "discovery", "-iL", "ranges.txt"])
                if ctx.paused:
                    return []
                found = [ip for ip, r in nmaptools.parse_gnmap(str(base) + ".gnmap").items() if r["up"]]
                (ddir / "live_hosts.txt").write_text("\n".join(found) + ("\n" if found else ""))
                ctx.add_output(ddir / "live_hosts.txt")
                db.patch_meta(sess_id, discovered=found)
                ctx.emit(f"[lasy] {len(found)} live host(s) found in the given range(s).", "discovery")
            else:
                found = []
                for c in cidrs:
                    net = ipaddress.ip_network(c, strict=False)
                    if net.num_addresses > 1024:
                        raise StageError(f"{c} is too large to scan without host discovery. "
                                         "Enable discovery or use a /22 or smaller range.")
                    found += [str(h) for h in net.hosts()]
                db.patch_meta(sess_id, discovered=found)
            sm = db.get_scan(sess_id).meta
        for h in discovery_hosts(sm):
            if h not in hosts:
                hosts.append(h)
        return hosts


async def wait_stage(sess_id: int, key: str) -> None:
    while stage_rows(sess_id)[key].state in ACTIVE:
        await asyncio.sleep(2)


def _require(sess_id: int, key: str) -> None:
    st = stage_rows(sess_id)[key]
    if st.state == ScanState.pending:
        raise StageError(f"Run “{STAGES[key]['label']}” first. There are no results to build on yet.")
    if st.state in ACTIVE:
        raise StageError(f"“{STAGES[key]['label']}” is still running. Wait for it to finish.")


async def plan(ctx: ScanContext, sess_id: int, key: str, run: int) -> list[dict]:
    st = STAGES[key]
    sm = db.get_scan(sess_id).meta
    size = _int("nmap_batch_size", 8)
    udp = st["proto"] == "udp"
    t = _timing()

    if key in ("tcp_top", "udp_top"):
        hosts = await ensure_hosts(ctx, sess_id)
        if not hosts:
            if not ctx.paused:
                ctx.note("No live hosts were found, so there is nothing to scan.")
            return []
        base = (["-sU"] if udp else []) + ["-Pn", "--top-ports", "1000", "--open", "-v", t]
        if udp:
            base += _udp_retries()
        items = []
        for group, extra in _split_families(hosts):
            for ch in chunks(group, size):
                items.append((ch, base + extra, ""))
        return _make_batches(sm, key, run, items)

    if key in ("tcp_full", "udp_full"):
        hosts = await ensure_hosts(ctx, sess_id)
        if not hosts:
            if not ctx.paused:
                ctx.note("No live hosts were found, so there is nothing to scan.")
            return []
        items = []
        for group, extra in _split_families(hosts):
            for ch in chunks(group, size):
                for lo, hi in _port_ranges():
                    args = (["-sU"] if udp else []) + ["-Pn", "-p", f"{lo}-{hi}", "--open", "-v", t]
                    if udp:
                        args += _udp_retries()
                    items.append((ch, args + extra, f" · ports {lo}-{hi}"))
        return _make_batches(sm, key, run, items)

    # enumeration stages
    proto = st["proto"]
    if key in ("tcp_enum", "udp_enum"):
        _require(sess_id, st["needs"])
        res = load_results(sess_id, st["needs"])
        wanted = {ip: sorted({p["port"] for p in r["ports"] if p["state"] == "open"}) for ip, r in res.items()}
    else:  # auto enum after a full scan: only ports beyond the top-1000 results
        full, top = load_results(sess_id, st["auto_of"]), None
        if stage_rows(sess_id)[st["top"]].state in ACTIVE:
            ctx.emit("[lasy] waiting for the top-1000 scan to finish before comparing ports…")
            await wait_stage(sess_id, st["top"])
        top = load_results(sess_id, st["top"])
        wanted = {}
        for ip, r in full.items():
            known = {p["port"] for p in top.get(ip, {"ports": []})["ports"] if p["state"] == "open"}
            new = sorted({p["port"] for p in r["ports"] if p["state"] == "open"} - known)
            wanted[ip] = new
    wanted = {ip: ports for ip, ports in wanted.items() if ports}
    if not wanted:
        label = "TCP" if proto == "tcp" else "UDP"
        ctx.note(f"No open {label} ports to enumerate" + (" beyond the top-1000 results." if key not in ("tcp_enum", "udp_enum") else "."))
        return []
    ports = sorted({p for ps in wanted.values() for p in ps})
    args = (["-sU"] if udp else []) + ["-Pn", "-sV", "-sC", "-p", ",".join(map(str, ports)), "-v", t]
    if udp:
        args += _udp_retries()
    items = []
    for group, extra in _split_families(list(wanted)):
        for ch in chunks(group, size):
            items.append((ch, args + extra, ""))
    return _make_batches(sm, key, run, items)


# --------------------------------------------------------------------------
# execution
# --------------------------------------------------------------------------
async def _run_one(ctx: ScanContext, b: dict) -> None:
    gn = Path(b["base"] + ".gnmap")
    resume = b["state"] == "interrupted" and gn.exists() and nmaptools.has_header(gn)
    if resume:
        args = ["--resume", str(gn)]
        display = ["nmap", "--resume", gn.name]
    else:
        args = b["args"] + ["-oA", b["base"], "-iL", b["infile"]]
        display = ["nmap"] + b["args"] + ["-oA", b["name"], "-iL", "ip.txt"]
    db.update_batch(ctx.scan_id, b["idx"], state="running", resumed=resume)
    tail: list[str] = []
    code = await ctx.run(nmaptools.nmap_argv(args), channel=b["channel"], display=display,
                         env=nmaptools.nmap_env(), line_sink=tail)
    complete = nmaptools.is_complete(gn)
    if code == 0 and complete:
        db.update_batch(ctx.scan_id, b["idx"], state="done", error="")
    elif ctx.paused or (not complete and code != 0 and ctx.engine.is_paused(ctx.scan_id)):
        db.update_batch(ctx.scan_id, b["idx"], state="interrupted")
    else:
        msg = nmaptools.error_hint(tail) or next((l for l in reversed(tail) if l.strip()), "nmap exited with an error")
        db.update_batch(ctx.scan_id, b["idx"], state="failed", error=msg[:300])


def _write_combined(ctx: ScanContext, sm: dict, key: str, run: int, batches: list[dict]) -> None:
    parts = []
    for b in batches:
        p = Path(b["base"] + ".nmap")
        if p.exists():
            parts.append(p.read_text(errors="replace").rstrip() + "\n")
    if parts:
        name = STAGES[key]["dirname"] + (f"_run{run}" if run > 1 else "") + "_results.txt"
        out = Path(sm["folder"]) / name
        out.write_text("\n".join(parts))
        ctx.add_output(out)


def make_body(scan_id: int, key: str):
    async def body(ctx: ScanContext) -> None:
        sc = db.get_scan(scan_id)
        sess_id = sc.parent_id
        meta = sc.meta or {}
        mode = meta.get("pending_mode", "fresh")
        if mode == "resume" and meta.get("batches"):
            batches = meta["batches"]
            run = meta.get("run", 1)
        else:
            run = int(meta.get("run", 0)) + 1
            ctx.engine.reset_terminal(scan_id)
            db.patch_meta(scan_id, batches=[], channels=[], note="", run=run)
            batches = await plan(ctx, sess_id, key, run)
            chans = list((db.get_scan(scan_id).meta or {}).get("channels", []))
            for b in batches:
                chans.append({"id": b["channel"], "label": b["label"]})
            db.patch_meta(scan_id, batches=batches, channels=chans)
            if not batches:
                return
        sm = db.get_scan(sess_id).meta
        sem = ctx.engine.limiter("nmap", _int("nmap_max_parallel", 4))
        total = len(batches)

        async def one(b: dict) -> None:
            async with sem:
                if ctx.paused:
                    return
                await _run_one(ctx, b)
                cur = (db.get_scan(scan_id).meta or {}).get("batches", [])
                ctx.set_progress(sum(1 for x in cur if x["state"] == "done") / max(1, total))

        await asyncio.gather(*[one(b) for b in batches if b["state"] != "done"])
        cur = (db.get_scan(scan_id).meta or {}).get("batches", [])
        _write_combined(ctx, sm, key, run, cur)
        if ctx.paused:
            return
        failed = [b for b in cur if b["state"] == "failed"]
        if failed:
            raise StageError(f"{len(failed)} of {total} batch(es) failed. {failed[0].get('error', '')}".strip())
        auto = next((k for k, v in STAGES.items() if v.get("auto_of") == key), None)
        if auto:
            start_stage(stage_rows(sess_id)[auto].id, "fresh")

    return body


def start_stage(scan_id: int, mode: str = "fresh") -> None:
    sc = db.get_scan(scan_id)
    key = stage_key(sc)
    db.patch_meta(scan_id, pending_mode=mode)
    engine.start(scan_id, make_body(scan_id, key), fresh=(mode != "resume"))


async def run_all(sess_id: int) -> None:
    """Idempotent chain: starts selected background scans, then runs the selected
    foreground stages in order, skipping finished ones and resuming unfinished ones."""
    rows = stage_rows(sess_id)

    def selected(k: str) -> bool:
        st = STAGES[k]
        return st["core"] or bool((rows[k].meta or {}).get("selected", st["default"]))

    for k in BG_ORDER:
        if not selected(k) and not (rows[k].meta or {}).get("selected"):
            continue
        sc = stage_rows(sess_id)[k]
        if sc.state in (ScanState.pending, ScanState.failed, ScanState.canceled, ScanState.paused, ScanState.interrupted):
            start_stage(sc.id, "resume" if (sc.meta or {}).get("batches") else "fresh")
    for k in FG_ORDER:
        if not selected(k):
            continue
        sc = stage_rows(sess_id)[k]
        if sc.state == ScanState.done:
            continue
        if sc.state in ACTIVE:
            pass
        else:   # paused, interrupted, failed or canceled stages keep their finished batches
            start_stage(sc.id, "resume" if (sc.meta or {}).get("batches") else "fresh")
        await engine.wait(sc.id)
        if stage_rows(sess_id)[k].state != ScanState.done:
            return  # paused, failed or canceled: stop the chain
