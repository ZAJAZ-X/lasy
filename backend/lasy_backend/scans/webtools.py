"""Web App PT tools.

Each tool runs once per target (several only accept one target, so lasy loops), shows its
real output in a per-target terminal tab, saves raw output to the project's webapt folder,
and returns parsed findings. A tool that cannot reach its target is reported as an ERROR for
that target, never as "no findings", and work finished before a failure or a Stop is kept.
"""
from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime
from pathlib import Path

from .. import commands, config, db, discovery, nmaptools, parsers
from ..engine import ScanContext, StageError, ToolMissing
from ..models import Project
from ..webtargets import base_url

WEB_TOOLS = [
    {"key": "nmap_ssl", "label": "Nmap SSL scripts", "bin": "nmap", "tls": True,
     "desc": "ssl-cert and ssl-enum-ciphers: certificate checks, TLS versions and weak ciphers."},
    {"key": "testssl", "label": "testssl.sh", "bin": "testssl", "tls": True,
     "desc": "Deep TLS audit: protocols, ciphers, known TLS attacks and certificate chain."},
    {"key": "nikto", "label": "Nikto", "bin": "nikto", "tls": False,
     "desc": "Web server scanner: misconfigurations, dangerous files and outdated software."},
    {"key": "nuclei", "label": "Nuclei", "bin": "nuclei", "tls": False,
     "desc": "Template-based vulnerability scanner for known CVEs and exposures."},
    {"key": "ffuf", "label": "ffuf", "bin": "ffuf", "tls": False, "dir": True,
     "desc": "Fast content discovery with automatic wildcard calibration."},
    {"key": "feroxbuster", "label": "feroxbuster", "bin": "feroxbuster", "tls": False, "dir": True,
     "desc": "Recursive content discovery: finds nested directories ffuf does not."},
    {"key": "dirsearch", "label": "dirsearch", "bin": "dirsearch", "tls": False, "dir": True,
     "desc": "Path discovery with built-in extension handling and redirects."},
]
TOOL_MAP = {t["key"]: t for t in WEB_TOOLS}
DIR_TOOLS = {t["key"] for t in WEB_TOOLS if t.get("dir")}
STATUS_CODES = "200,204,301,302,307,308,401,403,405,500"


class ToolRunError(RuntimeError):
    """The tool ran but could not scan this target (unreachable, not TLS, crashed...)."""


# (regex, plain-language explanation). Checked against the tail of the tool's output.
FAIL_PATTERNS = [
    (r"connection refused|econnrefused", "The target refused the connection. The port is closed or filtered."),
    (r"no route to host|network is unreachable|enetunreach", "There is no network route to the target."),
    (r"name or service not known|could not resolve|no such host|temporary failure in name resolution|"
     r"failed to resolve|unable to resolve|nodename nor servname", "The host name could not be resolved."),
    (r"doesn'?t seem to be a tls/ssl enabled server|does not seem to be a tls|wrong version number|"
     r"unexpected eof|first record does not look like a tls|not a tls", "This port does not speak TLS. If it serves plain HTTP, change its scheme to http."),
    (r"can'?t connect|cannot connect|unable to open a socket|could not connect|connection error|"
     r"failed to establish|max retries exceeded|failed to connect|error sending request", "The tool could not connect to the target."),
    (r"timed out|time out|i/o timeout|deadline exceeded|context deadline", "The target did not respond in time."),
    (r"too many errors|error rate", "Too many request errors. The target may be rate-limiting or filtering the scan (WAF)."),
    (r"no web server found", "No web server answered on this host and port."),
    (r"permission denied|operation not permitted", "A permission error stopped the tool. For nmap, check the no-sudo setup in Settings."),
]
UNREACHABLE = re.compile("|".join(p for p, _ in FAIL_PATTERNS), re.I)


def explain(lines: list[str], default: str) -> str:
    blob = "\n".join(lines[-200:])
    for rx, msg in FAIL_PATTERNS:
        if re.search(rx, blob, re.I):
            return msg
    last = next((l.strip() for l in reversed(lines) if l.strip()), "")
    return default + (f" Last output: {last[:160]}" if last else "")


def _dead(lines: list[str], code: int, label: str) -> None:
    """Call when a tool produced nothing: decide between 'clean, nothing found' and 'failed'."""
    blob = "\n".join(lines[-200:])
    if code not in (0, None) or UNREACHABLE.search(blob) or any(l.strip().startswith("+ ERROR") for l in lines):
        raise ToolRunError(explain(lines, f"{label} did not complete."))


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


def _need(key: str) -> str:
    name = config.find_tool(key)
    if not name:
        raise ToolMissing(f"'{key}' is not installed.")
    return name


def _tls_only(t: dict) -> None:
    if t["scheme"] == "http":
        raise StageError("Plain HTTP target: TLS checks do not apply. Change the scheme to https to test it.")


def _exts(cfg: dict) -> list[str]:
    return [e.strip().lstrip(".") for e in cfg.get("extensions", []) if e.strip()]


def _wordlist(cfg: dict) -> str:
    wl = cfg.get("wordlist", "")
    if not wl or not Path(wl).is_file():
        raise StageError("The selected wordlist was not found. Choose another under Directory discovery setup "
                         "(install SecLists with: sudo apt install seclists).")
    if Path(wl).stat().st_size == 0:
        raise StageError("The selected wordlist is empty. Choose another under Directory discovery setup.")
    return wl


async def _nmap_ssl(ctx: ScanContext, folder: Path, t: dict, ch: str, cfg: dict):
    _tls_only(t)
    host, port, tag = t["host"], t["port"], f"{_safe(t['host'])}_{t['port']}"
    label = f"{host}:{port}"
    findings: list[dict] = []
    for script in ("ssl-cert", "ssl-enum-ciphers"):
        txt, xml = folder / f"{tag}_{script}.txt", folder / f"{tag}_{script}.xml"
        lines: list[str] = []
        code = await ctx.run(nmaptools.nmap_argv(["-Pn", "-p", str(port), "--script", script,
                                                  "-oN", str(txt), "-oX", str(xml), host]),
                             channel=ch, env=nmaptools.nmap_env(), line_sink=lines, timeout=300)
        ctx.add_output(txt)
        hint = nmaptools.error_hint(lines)
        if hint:
            raise ToolRunError(hint)
        if re.search(r"failed to resolve", "\n".join(lines), re.I):
            raise ToolRunError("The host name could not be resolved.")
        if code != 0 or not xml.exists():
            raise ToolRunError(explain(lines, "nmap did not complete (it failed or hit the 5 minute limit)."))
        findings += parsers.parse_nmap_ssl(xml, label, host)
    state_only = ("Port is", "Host did not respond", "No TLS service detected", "No usable nmap output")
    if findings and all(f["title"].startswith(state_only) for f in findings):
        raise ToolRunError(findings[0]["evidence"])
    seen, uniq = set(), []
    for f in findings:
        k = (f["title"], f["target"], f["evidence"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq, []


async def _testssl(ctx: ScanContext, folder: Path, t: dict, ch: str, cfg: dict):
    _tls_only(t)
    binary = _need("testssl")
    tag = f"{_safe(t['host'])}_{t['port']}"
    js, txt, lines = folder / f"{tag}_testssl.json", folder / f"{tag}_testssl.txt", []
    if js.exists():
        js.unlink()
    c = commands.cfg()
    code = await ctx.run(commands.testssl_argv(c, binary, str(js), f"{t['host']}:{t['port']}"), channel=ch, result_file=txt,
                         line_sink=lines, timeout=commands.limit_seconds(c, "testssl_limit", 30))
    ctx.add_output(txt)
    if not js.exists() or js.stat().st_size < 3:
        raise ToolRunError(explain(lines, "testssl.sh did not produce a result."))
    ctx.add_output(js)
    return parsers.parse_testssl(js, f"{t['host']}:{t['port']}"), []


async def _nuclei(ctx: ScanContext, folder: Path, t: dict, ch: str, cfg: dict):
    _need("nuclei")
    url, tag = base_url(t["host"], t["port"], t["scheme"]), f"{_safe(t['host'])}_{t['port']}"
    txt, jl, lines = folder / f"{tag}_nuclei.txt", folder / f"{tag}_nuclei.jsonl", []
    c = commands.cfg()
    code = await ctx.run(commands.nuclei_argv(c, url, str(txt), str(jl)), channel=ch, line_sink=lines,
                         timeout=commands.limit_seconds(c, "nuclei_limit", 60))
    ctx.add_output(txt)
    if jl.exists():
        ctx.add_output(jl)
    found = parsers.parse_nuclei(jl, f"{t['host']}:{t['port']}")
    if not found:
        _dead(lines, code, "Nuclei")
    return found, []


async def _nikto(ctx: ScanContext, folder: Path, t: dict, ch: str, cfg: dict):
    _need("nikto")
    url, tag = base_url(t["host"], t["port"], t["scheme"]), f"{_safe(t['host'])}_{t['port']}"
    txt, lines = folder / f"{tag}_nikto.txt", []
    c = commands.cfg()
    code = await ctx.run(commands.nikto_argv(c, url), channel=ch, result_file=txt, line_sink=lines, timeout=commands.nikto_limit(c))
    ctx.add_output(txt)
    found = parsers.parse_nikto(lines, f"{t['host']}:{t['port']}")
    if not found:
        _dead(lines, code, "Nikto")
    return found, []


async def _ffuf(ctx: ScanContext, folder: Path, t: dict, ch: str, cfg: dict):
    _need("ffuf")
    wl, base = _wordlist(cfg), base_url(t["host"], t["port"], t["scheme"])
    tag = f"{_safe(t['host'])}_{t['port']}"
    js, lines = folder / f"{tag}_ffuf.json", []
    c = commands.cfg()
    argv = commands.ffuf_argv(c, base, wl, str(js), cfg.get("threads", 40), _exts(cfg))
    code = await ctx.run(argv, channel=ch, line_sink=lines, timeout=commands.limit_seconds(c, "ffuf_limit", 120))
    if js.exists():
        ctx.add_output(js)
    eps = parsers.parse_ffuf(js, base)
    if not eps:
        _dead(lines, code, "ffuf")
    return [], eps


async def _ferox(ctx: ScanContext, folder: Path, t: dict, ch: str, cfg: dict):
    _need("feroxbuster")
    wl, base = _wordlist(cfg), base_url(t["host"], t["port"], t["scheme"])
    tag = f"{_safe(t['host'])}_{t['port']}"
    txt, lines = folder / f"{tag}_feroxbuster.txt", []
    c = commands.cfg()
    argv = commands.ferox_argv(c, base, wl, str(txt), cfg.get("threads", 40), _exts(cfg))
    code = await ctx.run(argv, channel=ch, line_sink=lines, timeout=commands.limit_seconds(c, "ferox_limit", 120))
    ctx.add_output(txt)
    eps = parsers.parse_ferox(lines, base)
    if not eps and txt.exists():
        eps = parsers.parse_ferox(txt.read_text(errors="ignore").splitlines(), base)
    if not eps:
        _dead(lines, code, "feroxbuster")
    return [], eps


async def _dirsearch(ctx: ScanContext, folder: Path, t: dict, ch: str, cfg: dict):
    _need("dirsearch")
    wl, base = _wordlist(cfg), base_url(t["host"], t["port"], t["scheme"])
    tag = f"{_safe(t['host'])}_{t['port']}"
    txt, lines = folder / f"{tag}_dirsearch.txt", []
    c = commands.cfg()
    argv = commands.dirsearch_argv(c, base, wl, cfg.get("threads", 30), _exts(cfg))
    scratch = db.work_dir("_tools") / "dirsearch"
    scratch.mkdir(parents=True, exist_ok=True)
    code = await ctx.run(argv, channel=ch, result_file=txt, line_sink=lines, cwd=scratch,
                         timeout=commands.limit_seconds(c, "dirsearch_limit", 120))
    ctx.add_output(txt)
    eps = parsers.parse_dirsearch(lines, base)
    if not eps:
        _dead(lines, code, "dirsearch")
    return [], eps


RUNNERS = {"nmap_ssl": _nmap_ssl, "testssl": _testssl, "nuclei": _nuclei, "nikto": _nikto,
           "ffuf": _ffuf, "feroxbuster": _ferox, "dirsearch": _dirsearch}


def build(project: Project, tool: str, targets: list[dict], cfg: dict):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    meta = TOOL_MAP[tool]

    async def body(ctx: ScanContext) -> None:
        if not config.find_tool(meta["bin"]):
            raise ToolMissing(f"'{meta['bin']}' is not installed.")
        folder = Path(project.folder) / "webapt" / f"{tool}-{stamp}"
        folder.mkdir(parents=True, exist_ok=True)
        findings: list[dict] = []
        endpoints: list[dict] = []
        summary: list[dict] = []
        t_start = time.monotonic()

        def finish(partial: bool) -> dict:
            warnings: list[str] = []
            result: dict = {"targets": summary, "folder": folder.name, "partial": partial,
                            "duration": round(time.monotonic() - t_start)}
            fnd = findings
            if tool in DIR_TOOLS:
                scored = discovery.analyze(endpoints)
                fnd = discovery.to_findings(scored)
                result["endpoints"] = scored[:4000]
                result["total_endpoints"] = len(scored)
                noisy = sum(1 for e in scored if e["noise"])
                if len(scored) >= 20 and noisy / len(scored) >= 0.8:
                    warnings.append("Most responses look like wildcard or soft-404 pages, so the results are mostly "
                                    "noise. The site may use catch-all routing or a WAF; review the ranked list with care.")
            bad = [s for s in summary if s["status"] == "error"]
            if bad and len(bad) < len(summary):
                warnings.append(f"{len(bad)} of {len(summary)} target(s) could not be scanned. See Targets and files.")
            if partial:
                warnings.append("This run was stopped before it finished. The results cover only the targets scanned so far.")
            result["warnings"] = warnings
            db.save_findings(ctx.scan_id, fnd)
            ctx.store_result(result)
            return result

        try:
            for i, t in enumerate(targets, 1):
                ch, label, t0 = f"t{i}", f"{t['host']}:{t['port']}", time.monotonic()
                ctx.add_channel(ch, label)
                try:
                    f, e = await RUNNERS[tool](ctx, folder, t, ch, cfg)
                    findings += f
                    endpoints += e
                    summary.append({"target": label, "status": "ok", "count": len(f) + len(e)})
                except ToolMissing:
                    raise
                except StageError as exc:
                    ctx.emit(f"[lasy] Skipped: {exc}", ch)
                    summary.append({"target": label, "status": "skipped", "note": str(exc)})
                except ToolRunError as exc:
                    ctx.emit(f"[lasy] {meta['label']} could not scan {label}: {exc}", ch)
                    summary.append({"target": label, "status": "error", "note": str(exc)})
                except Exception as exc:  # noqa: BLE001
                    ctx.emit(f"[lasy] Unexpected error on {label}: {exc}", ch)
                    summary.append({"target": label, "status": "error", "note": f"Unexpected error: {exc}"})
                summary[-1]["seconds"] = round(time.monotonic() - t0)
                ctx.set_progress(i / len(targets))
        except asyncio.CancelledError:
            finish(partial=True)     # keep what was found before the Stop
            raise
        except ToolMissing:
            raise
        result = finish(partial=False)
        if not any(s["status"] == "ok" for s in summary):
            first = next((s.get("note", "") for s in summary), "")
            raise StageError("No target could be scanned. " + first)

    return body
