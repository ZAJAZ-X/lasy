"""HTTP + WebSocket API."""
from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, WebSocket
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlmodel import select

from . import commands, config, db, discovery, excel, nmaptools, settings_spec, wordlists
from .engine import engine, term_path
from .models import Finding, Project, Scan, ScanState, WebTarget
from .scans import ept, hostup, nameserver, subdomain, webtools
from .targets import TargetKind, parse_targets
from .webtargets import base_url, parse_web_inputs

router = APIRouter(prefix="/api")
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ProjectIn(BaseModel):
    name: str


class SettingsIn(BaseModel):
    values: dict[str, str]


class SetupIn(BaseModel):
    results_root: str


class TextIn(BaseModel):
    text: str = ""
    targets: str = ""


class SubIn(BaseModel):
    targets: str
    tools: list[str] = []


class SessionIn(BaseModel):
    targets: str
    cidr_discovery: bool = True


class RunIn(BaseModel):
    mode: str = "fresh"


class SelectIn(BaseModel):
    selected: bool


class WebAddIn(BaseModel):
    text: str = ""
    items: list[dict] = []
    source: str = "manual"
    replace: bool = False


class WebRunIn(BaseModel):
    tool: str


class SchemeIn(BaseModel):
    scheme: str


# ------------------------------------------------------------------ helpers
def _project(pid: int) -> Project:
    p = db.get_project(pid)
    if not p:
        raise HTTPException(404, "Project not found.")
    return p


def scan_dict(sc: Scan, full: bool = False) -> dict:
    m = sc.meta or {}
    running = sc.state in (ScanState.queued, ScanState.running)
    return {
        "id": sc.id, "project_id": sc.project_id, "parent_id": sc.parent_id, "kind": sc.kind,
        "label": sc.label, "state": sc.state.value if hasattr(sc.state, "value") else sc.state,
        "resumable": sc.resumable, "error": sc.error, "progress": sc.progress,
        "result_json": sc.result_json if (full or not running) else None,
        "outputs": [os.path.basename(p) for p in (sc.output_paths or [])],
        "channels": m.get("channels", []), "note": m.get("note", ""),
        "batches": [{k: b.get(k) for k in ("idx", "channel", "label", "state", "error", "resumed")}
                    for b in m.get("batches", [])],
        "created_at": sc.created_at.isoformat() if sc.created_at else None,
        "started_at": sc.started_at.isoformat() if sc.started_at else None,
        "finished_at": sc.finished_at.isoformat() if sc.finished_at else None,
        "duration": (round((sc.finished_at - sc.started_at).total_seconds())
                     if sc.started_at and sc.finished_at else None),
        "items": m.get("items"), "order": m.get("order"),
    }


def _new_scan(pid: int, kind: str, label: str, meta: dict | None = None) -> Scan:
    with db.get_session() as s:
        sc = Scan(project_id=pid, kind=kind, label=label, state=ScanState.queued, meta=meta or {})
        s.add(sc)
        s.commit()
        s.refresh(sc)
        return sc


def _exports_dir(project: Project) -> Path:
    d = Path(project.folder) / "exports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _download(path: Path) -> FileResponse:
    return FileResponse(path, filename=path.name, media_type=XLSX,
                        headers={"Content-Disposition": f'attachment; filename="{path.name}"'})


def _preflight(project: Project) -> None:
    """Refuse to start a scan whose results folder is unreachable (unmounted drive, deleted folder)."""
    d = Path(project.folder)
    try:
        d.mkdir(parents=True, exist_ok=True)
        probe = d / ".lasy_write_test"
        probe.write_text("ok")
        probe.unlink()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            400, f"This project's results folder is not reachable ({exc.__class__.__name__}). If your Windows drive "
                 "is not mounted in WSL, mount it or restart WSL, then try again. You can also change the results "
                 "folder under Settings.")


_INT_RULES = {"nmap_max_parallel": ("Parallel batches", 1, 32), "nmap_batch_size": ("Hosts per batch", 1, 64),
              "nmap_fullscan_chunk": ("Full-scan port chunk size", 1024, 65535),
              "nmap_timing": ("Timing template", 0, 5), "nmap_udp_retries": ("UDP max retries", 0, 10)}
_FORBIDDEN_ARGS = {"-oN", "-oX", "-oA", "-oG", "-oS", "-iL", "-iR", "--resume", "--append-output", "-sn"}


def _validate_settings(vals: dict[str, str]) -> None:
    errs: list[str] = []
    for k, (label, lo, hi) in _INT_RULES.items():
        if k in vals:
            try:
                n = int(str(vals[k]).strip())
                if not lo <= n <= hi:
                    raise ValueError
            except ValueError:
                errs.append(f"{label} must be a whole number from {lo} to {hi}.")
    if "nmap_use_sudo" in vals and str(vals["nmap_use_sudo"]).strip() not in ("0", "1"):
        errs.append("Use sudo for nmap must be 0 or 1.")
    if vals.get("nmap_extra_args", "").strip():
        try:
            bad = [t for t in shlex.split(vals["nmap_extra_args"]) if t.split("=")[0] in _FORBIDDEN_ARGS]
            if bad:
                errs.append(f"Extra nmap arguments cannot include {', '.join(bad)}: lasy manages input and output files itself.")
        except ValueError:
            errs.append("Extra nmap arguments could not be read. Check the quotes.")
    if "seclists_root" in vals and vals["seclists_root"].strip() and not os.path.isabs(vals["seclists_root"].strip()):
        errs.append("SecLists location must be an absolute path such as /usr/share/seclists.")
    if errs:
        raise HTTPException(400, " ".join(errs))


def _check_root(root: str) -> None:
    p = Path(root)
    try:
        p.mkdir(parents=True, exist_ok=True)
        probe = p / ".lasy_write_test"
        probe.write_text("ok")
        probe.unlink()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            400, f"Can't write to that path ({exc.__class__.__name__}). Make sure the Windows drive is "
                 "mounted (for example /mnt/c/Users/<you>/lasy) and the folder is reachable.")


# ------------------------------------------------------------------ health / setup / settings
@router.get("/health")
async def health():
    tools = []
    for key, cands, hint, purpose in config.TOOLS:
        found = config.find_tool(key)
        tools.append({"key": key, "found": bool(found), "binary": found or cands[0],
                      "install": hint, "purpose": purpose})
    root = db.get_setting("seclists_root", "/usr/share/seclists")
    return {"ok": True, "tools": tools, "seclists": os.path.isdir(root), "seclists_root": root}


@router.get("/health/nmap")
async def health_nmap():
    return await asyncio.to_thread(nmaptools.privilege_check)


@router.get("/setup")
async def setup_status():
    return {"complete": db.get_setting("setup_complete", "0") == "1",
            "results_root": db.get_setting("results_root", config.default_results_root()),
            "detected": config.default_results_root(),
            "ui": {"mascot": db.get_setting("ui_mascot", "1") == "1", "size": db.get_setting("ui_text_size", "large"),
                   "style": db.get_setting("ui_style", "glass")}}


@router.post("/setup")
async def setup_save(payload: SetupIn):
    root = payload.results_root.strip()
    if not root:
        raise HTTPException(400, "Enter a path for your results folder.")
    await asyncio.to_thread(_check_root, root)
    db.set_setting("results_root", root)
    db.set_setting("setup_complete", "1")
    return {"ok": True, "results_root": root}


@router.get("/settings")
async def get_settings():
    return db.all_settings()


@router.put("/settings")
async def put_settings(payload: SettingsIn):
    vals = {k: (v.strip() if isinstance(v, str) else v) for k, v in payload.values.items()}
    _validate_settings(vals)
    spec_errs = settings_spec.validate(vals)
    if spec_errs:
        raise HTTPException(400, " ".join(spec_errs))
    if "results_root" in vals and vals["results_root"].strip() != db.get_setting("results_root"):
        await asyncio.to_thread(_check_root, vals["results_root"].strip())
        vals["results_root"] = vals["results_root"].strip()
    allowed = config.allowed_keys()
    for k, v in vals.items():
        if k in allowed:
            db.set_setting(k, v)
    return db.all_settings()


@router.get("/settings/schema")
async def settings_schema():
    return {"categories": settings_spec.CATEGORIES}


@router.post("/settings/preview")
async def settings_preview(payload: SettingsIn):
    """The exact command each tool will run with the given (possibly unsaved) values."""
    return commands.preview(payload.values)


@router.post("/targets/preview")
async def targets_preview(payload: TextIn):
    ts = parse_targets(payload.text)
    return {"items": [{"raw": t.raw, "value": t.value, "kind": t.kind.value, "port": t.port} for t in ts]}


# ------------------------------------------------------------------ projects
@router.get("/projects")
async def list_projects():
    with db.get_session() as s:
        out = []
        for p in s.exec(select(Project).order_by(Project.created_at.desc())).all():
            scans = s.exec(select(Scan).where(Scan.project_id == p.id)).all()
            out.append({"id": p.id, "name": p.name, "slug": p.slug, "created_at": p.created_at.isoformat(),
                        "scan_count": len([x for x in scans if x.kind != "nmap_session" and x.parent_id is None]),
                        "last_activity": max([x.created_at for x in scans], default=p.created_at).isoformat()})
        return out


@router.post("/projects")
async def create_project(payload: ProjectIn):
    name = payload.name.strip()
    if not name:
        raise HTTPException(400, "Project name is required.")
    slug = db.slugify(name)
    with db.get_session() as s:
        if s.exec(select(Project).where((Project.name == name) | (Project.slug == slug))).first():
            raise HTTPException(409, "A project with that name already exists.")
        try:
            folder = db.create_project_folder(slug)
        except OSError as exc:
            raise HTTPException(400, f"Could not create the project folder: {exc}. Check the results path in Settings.")
        proj = Project(name=name, slug=slug, folder=str(folder))
        s.add(proj)
        s.commit()
        s.refresh(proj)
        return {"id": proj.id, "name": proj.name, "slug": proj.slug}


def _folder_stats(path: Path, cap: int = 50000) -> dict:
    total = files = 0
    truncated = False
    try:
        for root, _dirs, names in os.walk(path):
            for n in names:
                files += 1
                try:
                    total += os.path.getsize(os.path.join(root, n))
                except OSError:
                    pass
                if files >= cap:
                    truncated = True
                    break
            if truncated:
                break
    except OSError:
        pass
    return {"size_bytes": total, "files": files, "truncated": truncated}


def _running_count(pid: int) -> int:
    with db.get_session() as s:
        rows = s.exec(select(Scan).where(Scan.project_id == pid)).all()
    n = sum(1 for r in rows if r.state in (ScanState.queued, ScanState.running))
    if n == 0 and (engine.group_running(f"web:{pid}") or any(engine.group_running(f"session:{r.id}") for r in rows if r.kind == "nmap_session")):
        n = 1
    return n


@router.get("/projects/{pid}/summary")
async def project_summary(pid: int):
    """What deleting this project would remove (shown in the confirmation dialog)."""
    p = _project(pid)
    with db.get_session() as s:
        scans = s.exec(select(Scan).where(Scan.project_id == pid)).all()
        ids = [x.id for x in scans]
        findings = len(s.exec(select(Finding).where(Finding.scan_id.in_(ids))).all()) if ids else 0
    folder = Path(p.folder)
    stats = await asyncio.to_thread(_folder_stats, folder) if folder.is_dir() else {"size_bytes": 0, "files": 0, "truncated": False}
    return {"name": p.name, "folder_name": os.path.basename(p.folder), "folder_exists": folder.is_dir(),
            "scans": sum(1 for x in scans if x.parent_id is None and x.kind != "web_runall"), "findings": findings,
            "running": _running_count(pid), **stats}


def _check_deletable(p: Project) -> Path:
    """The project's results folder, only if it is clearly this project's own. Otherwise refuse."""
    folder = Path(p.folder)
    real = Path(os.path.realpath(folder))
    root = Path(os.path.realpath(db.get_setting("results_root", config.default_results_root())))
    why = ""
    if not folder.is_absolute() or len(real.parts) < 3:
        why = "it is too close to the top of the drive"
    elif real in (Path("/"), Path.home(), root):
        why = "it is the results root or your home folder"
    elif os.path.basename(str(folder).rstrip("/")) != p.slug:
        why = "its name does not match the project"
    elif root.is_relative_to(real):
        why = "your results folder setting is inside it"
    if why:
        raise HTTPException(400, f"For safety lasy will not delete {folder.name or str(folder)}: {why}. "
                                 "Delete it yourself in Windows Explorer, then use “Remove from lasy only”.")
    return folder


def _remove_tree(folder: Path) -> list[str]:
    errors: list[str] = []
    if folder.is_symlink():
        folder.unlink()      # remove the link, never what it points to
        return errors

    def on_error(func, path, exc_info):
        try:
            os.chmod(path, 0o700)    # Windows read-only attribute
            func(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            errors.append(f"{os.path.basename(path)}: {exc.strerror or exc}")

    if folder.exists():
        shutil.rmtree(folder, onerror=on_error)
    return errors


class DeleteIn(BaseModel):
    confirm_name: str = ""
    delete_files: bool = True


@router.post("/projects/{pid}/delete")
async def delete_project(pid: int, payload: DeleteIn):
    p = _project(pid)
    if payload.confirm_name != p.name:
        raise HTTPException(400, "Type the project name exactly to confirm.")
    running = _running_count(pid)
    if running:
        raise HTTPException(409, f"{running} scan{'s are' if running != 1 else ' is'} still running in this project. Stop "
                                 f"{'them' if running != 1 else 'it'} first, then delete the project.")
    with db.get_session() as s:
        ids = [x.id for x in s.exec(select(Scan).where(Scan.project_id == pid)).all()]
    files_deleted = False
    if payload.delete_files:
        folder = _check_deletable(p)
        if folder.exists() or folder.is_symlink():
            errors = await asyncio.to_thread(_remove_tree, folder)
            if errors:
                raise HTTPException(409, "Some files could not be deleted. They may be open in Windows (close any Explorer "
                                         f"windows or programs using the folder) and then try again. First problem: {errors[0]}. "
                                         "The project was not removed from lasy.")
            files_deleted = True
    with db.get_session() as s:
        for f in s.exec(select(Finding).where(Finding.scan_id.in_(ids))).all() if ids else []:
            s.delete(f)
        for sc in s.exec(select(Scan).where(Scan.project_id == pid)).all():
            s.delete(sc)
        for t in s.exec(select(WebTarget).where(WebTarget.project_id == pid)).all():
            s.delete(t)
        from .models import Setting
        for st in s.exec(select(Setting).where(Setting.key.like(f"p.{pid}.%"))).all():
            s.delete(st)
        proj = s.get(Project, pid)
        if proj:
            s.delete(proj)
        s.commit()
    for sid in ids:                      # Linux-side leftovers: terminal replays, in-memory buffers
        engine.reset_terminal(sid)
    await asyncio.to_thread(shutil.rmtree, config.WORK_DIR / p.slug, True)
    return {"ok": True, "files_deleted": files_deleted, "name": p.name}


@router.get("/projects/{pid}")
async def get_project(pid: int):
    p = _project(pid)
    return {"id": p.id, "name": p.name, "slug": p.slug, "folder_name": os.path.basename(p.folder),
            "created_at": p.created_at.isoformat()}


# ------------------------------------------------------------------ generic scans
@router.get("/scans/{sid}")
async def get_scan(sid: int, full: bool = False):
    sc = db.get_scan(sid)
    if not sc:
        raise HTTPException(404, "Scan not found.")
    return scan_dict(sc, full)


@router.get("/projects/{pid}/scans")
async def list_scans(pid: int, kind: str | None = None):
    with db.get_session() as s:
        q = select(Scan).where(Scan.project_id == pid, Scan.parent_id == None)  # noqa: E711
        if kind:
            q = q.where(Scan.kind == kind)
        return [scan_dict(x) for x in s.exec(q.order_by(Scan.created_at.desc())).all()]


@router.post("/scans/{sid}/pause")
async def pause_scan(sid: int):
    await engine.pause(sid)
    return scan_dict(db.get_scan(sid))


@router.post("/scans/{sid}/cancel")
async def cancel_scan(sid: int):
    await engine.cancel(sid)
    await asyncio.sleep(0.1)
    return scan_dict(db.get_scan(sid))


@router.websocket("/ws/scans/{sid}")
async def ws_terminal(ws: WebSocket, sid: int, channel: str = "main"):
    await ws.accept()
    key = f"{sid}:{channel}"

    def loader() -> str:
        p = term_path(sid, channel)
        if p.exists():
            with open(p, encoding="utf-8", errors="replace", newline="") as f:
                return f.read()
        return ""

    snap, q = engine.hub.attach(key, loader)
    getter = asyncio.create_task(q.get())
    recv = asyncio.create_task(ws.receive())
    try:
        if snap:
            await ws.send_text(snap)
        while True:
            done, _ = await asyncio.wait({getter, recv}, return_when=asyncio.FIRST_COMPLETED)
            if recv in done:
                break
            await ws.send_text(getter.result())
            getter = asyncio.create_task(q.get())
    except Exception:
        pass
    finally:
        getter.cancel()
        recv.cancel()
        engine.hub.detach(key, q)


# ------------------------------------------------------------------ nameserver / host up / subdomain
@router.post("/projects/{pid}/nameserver")
async def run_nameserver(pid: int, payload: TextIn):
    project = _project(pid)
    domains = [t.value for t in parse_targets(payload.targets) if t.kind in (TargetKind.DOMAIN, TargetKind.URL)]
    if not domains:
        raise HTTPException(400, "Enter at least one domain, for example example.com.")
    _preflight(project)
    sc = _new_scan(pid, "nameserver", "Nameserver lookup")
    engine.start(sc.id, nameserver.build(project, list(dict.fromkeys(domains))))
    return scan_dict(db.get_scan(sc.id))


@router.post("/projects/{pid}/hostup")
async def run_hostup(pid: int, payload: TextIn):
    project = _project(pid)
    try:
        body = hostup.build(project, payload.targets)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    _preflight(project)
    sc = _new_scan(pid, "hostup", "Host up / down check")
    engine.start(sc.id, body)
    return scan_dict(db.get_scan(sc.id))


@router.post("/projects/{pid}/subdomain")
async def run_subdomain(pid: int, payload: SubIn):
    project = _project(pid)
    domains = [t.value for t in parse_targets(payload.targets) if t.kind in (TargetKind.DOMAIN, TargetKind.URL)]
    if not domains:
        raise HTTPException(400, "Enter at least one root domain, for example example.com.")
    _preflight(project)
    sc = _new_scan(pid, "subdomain", "Subdomain enumeration")
    engine.start(sc.id, subdomain.build(project, list(dict.fromkeys(domains)), payload.tools))
    return scan_dict(db.get_scan(sc.id))


@router.get("/scans/{sid}/export")
async def export_scan(sid: int):
    sc = db.get_scan(sid)
    if not sc or not sc.result_json:
        raise HTTPException(404, "There are no results to export yet.")
    project = _project(sc.project_id)
    d = _exports_dir(project)
    rows = sc.result_json.get("rows", [])
    if sc.kind == "nameserver":
        out = excel.export_nameserver(rows, d / f"nameserver-{_stamp()}.xlsx")
    elif sc.kind == "hostup":
        out = excel.export_hostup(rows, d / f"host-status-{_stamp()}.xlsx")
    elif sc.kind == "subdomain":
        out = excel.export_subdomain(sc.result_json, d / f"subdomains-{_stamp()}.xlsx")
    else:
        raise HTTPException(400, "Export is not available for this scan type.")
    return _download(out)


# ------------------------------------------------------------------ nmap (EPT)
def _stage_dict(st_key: str, sc: Scan) -> dict:
    st = ept.STAGES[st_key]
    m = sc.meta or {}
    bs = m.get("batches", [])
    counts = {k: sum(1 for b in bs if b["state"] == k) for k in ("done", "running", "interrupted", "failed", "pending")}
    counts["total"] = len(bs)
    state = sc.state.value
    long_running = st["proto"] == "udp" or "full" in st_key or len(bs) >= 3
    return {
        "id": sc.id, "key": st_key, "n": st["n"], "label": st["label"], "desc": st["desc"], "cmd": st["cmd"],
        "core": st["core"], "bg": st["bg"], "auto": bool(st.get("auto_of")), "auto_of": st.get("auto_of"),
        "selected": True if st["core"] else bool(m.get("selected", st["default"])),
        "state": state, "progress": sc.progress, "error": sc.error, "note": m.get("note", ""),
        "batches": counts, "channels": m.get("channels", []),
        "can_pause": state == "running" and long_running,
        "can_resume": state in ("paused", "interrupted") or (
            state in ("failed", "canceled") and counts["done"] > 0 and (counts["total"] - counts["done"]) > 0),
        "resume_kind": "retry" if state in ("failed", "canceled") else "resume",
        "has_output": state != "pending",
    }


def _session_dict(sess: Scan) -> dict:
    stages = ept.stage_rows(sess.id)
    sm = sess.meta
    out = [_stage_dict(k, stages[k]) for k in ept.STAGES]
    return {
        "id": sess.id, "project_id": sess.project_id, "label": sess.label,
        "created_at": sess.created_at.isoformat(), "folder_name": os.path.basename(sm["folder"]),
        "targets": {"explicit": len(sm["explicit"]), "domains": len(sm["domains"]), "cidrs": sm["cidrs"],
                    "discovered": None if sm.get("discovered") is None else len(sm["discovered"]),
                    "invalid": sm.get("invalid", []), "cidr_discovery": sm.get("cidr_discovery", True)},
        "stages": out,
        "running": any(s["state"] in ("queued", "running") for s in out),
        "run_all_active": engine.group_running(f"session:{sess.id}"),
    }


def _session(sid: int) -> Scan:
    sc = db.get_scan(sid)
    if not sc or sc.kind != "nmap_session":
        raise HTTPException(404, "Scan session not found.")
    return sc


@router.post("/projects/{pid}/nmap/sessions")
async def create_nmap_session(pid: int, payload: SessionIn):
    project = _project(pid)
    _preflight(project)
    try:
        sess = ept.create_session(project, payload.targets, payload.cidr_discovery)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return _session_dict(sess)


@router.get("/projects/{pid}/nmap/sessions")
async def list_nmap_sessions(pid: int):
    with db.get_session() as s:
        rows = s.exec(select(Scan).where(Scan.project_id == pid, Scan.kind == "nmap_session")
                      .order_by(Scan.created_at.desc())).all()
    out = []
    for r in rows:
        d = _session_dict(r)
        out.append({"id": r.id, "label": r.label, "created_at": d["created_at"], "targets": d["targets"],
                    "running": d["running"],
                    "stages_done": sum(1 for s in d["stages"] if s["state"] == "done")})
    return out


@router.get("/nmap/sessions/{sid}")
async def get_nmap_session(sid: int):
    return _session_dict(_session(sid))


@router.put("/nmap/stages/{scan_id}/select")
async def select_stage(scan_id: int, payload: SelectIn):
    sc = db.get_scan(scan_id)
    if not sc or not sc.kind.startswith("nmap_"):
        raise HTTPException(404, "Stage not found.")
    if ept.STAGES[ept.stage_key(sc)]["core"]:
        raise HTTPException(400, "This core stage always runs as part of a full run.")
    db.patch_meta(scan_id, selected=payload.selected)
    return {"ok": True}


@router.post("/nmap/stages/{scan_id}/run")
async def run_stage(scan_id: int, payload: RunIn):
    sc = db.get_scan(scan_id)
    if not sc or not sc.kind.startswith("nmap_") or sc.kind == "nmap_session":
        raise HTTPException(404, "Stage not found.")
    if engine.is_running(scan_id):
        raise HTTPException(409, "This scan is already running.")
    _preflight(_project(sc.project_id))
    mode = "resume" if payload.mode == "resume" and (sc.meta or {}).get("batches") else "fresh"
    ept.start_stage(scan_id, mode)
    await asyncio.sleep(0.05)
    return _stage_dict(ept.stage_key(sc), db.get_scan(scan_id))


@router.post("/nmap/sessions/{sid}/run-all")
async def run_all(sid: int):
    sess = _session(sid)
    _preflight(_project(sess.project_id))
    engine.track_group(f"session:{sid}", ept.run_all(sid))
    await asyncio.sleep(0.05)
    return _session_dict(_session(sid))


@router.post("/nmap/sessions/{sid}/pause")
async def pause_session(sid: int):
    _session(sid)
    engine.cancel_group(f"session:{sid}")
    for sc in ept.stage_rows(sid).values():
        if engine.is_running(sc.id):
            await engine.pause(sc.id)
    await asyncio.sleep(0.2)
    return _session_dict(_session(sid))


@router.get("/nmap/sessions/{sid}/table")
async def nmap_table(sid: int):
    _session(sid)
    return await asyncio.to_thread(ept.build_table, sid)


@router.get("/nmap/sessions/{sid}/export")
async def nmap_export(sid: int):
    sess = _session(sid)
    project = _project(sess.project_id)
    table = await asyncio.to_thread(ept.build_table, sid)
    out = excel.export_nmap(table["rows"], _exports_dir(project) / f"nmap-results-{_stamp()}.xlsx")
    return _download(out)


@router.get("/nmap/sessions/{sid}/web-candidates")
async def nmap_web_candidates(sid: int):
    _session(sid)
    return await asyncio.to_thread(ept.web_candidates, sid)


# ------------------------------------------------------------------ web app pentest
def _targets(pid: int) -> list[dict]:
    with db.get_session() as s:
        rows = s.exec(select(WebTarget).where(WebTarget.project_id == pid).order_by(WebTarget.id)).all()
        return [{"id": r.id, "host": r.host, "port": r.port, "scheme": r.scheme, "source": r.source,
                 "url": base_url(r.host, r.port, r.scheme)} for r in rows]


@router.get("/projects/{pid}/web/targets")
async def web_targets(pid: int):
    return _targets(pid)


@router.post("/projects/{pid}/web/targets")
async def web_targets_add(pid: int, payload: WebAddIn):
    _project(pid)
    bad: list[str] = []
    items = payload.items
    if payload.text.strip():
        items, bad = parse_web_inputs(payload.text)
    if not items and not payload.replace:
        raise HTTPException(400, "No valid targets found. Use host:port, https://host:port or host port."
                            + (f" Could not read: {', '.join(bad[:5])}" if bad else ""))
    with db.get_session() as s:
        if payload.replace:
            for r in s.exec(select(WebTarget).where(WebTarget.project_id == pid)).all():
                s.delete(r)
        existing = {(r.host, r.port, r.scheme) for r in s.exec(select(WebTarget).where(WebTarget.project_id == pid)).all()}
        added = 0
        for it in items:
            key = (str(it["host"]).lower(), int(it["port"]), it.get("scheme", "https"))
            if key in existing:
                continue
            existing.add(key)
            s.add(WebTarget(project_id=pid, host=key[0], port=key[1], scheme=key[2], source=payload.source))
            added += 1
        s.commit()
    return {"added": added, "invalid": bad, "targets": _targets(pid)}


@router.patch("/web/targets/{tid}")
async def web_target_scheme(tid: int, payload: SchemeIn):
    if payload.scheme not in ("http", "https"):
        raise HTTPException(400, "Scheme must be http or https.")
    with db.get_session() as s:
        r = s.get(WebTarget, tid)
        if not r:
            raise HTTPException(404, "Target not found.")
        r.scheme = payload.scheme
        s.add(r)
        s.commit()
    return {"ok": True}


@router.delete("/web/targets/{tid}")
async def web_target_delete(tid: int):
    with db.get_session() as s:
        r = s.get(WebTarget, tid)
        if r:
            s.delete(r)
            s.commit()
    return {"ok": True}


def _dir_cfg(pid: int) -> dict:
    root = db.get_setting("seclists_root", "/usr/share/seclists")
    raw = db.get_setting(f"p.{pid}.dirconf", "")
    try:
        cfg = json.loads(raw) if raw else {}
    except ValueError:
        cfg = {}
    profile = cfg.get("profile", "generic")
    if profile not in wordlists.PROFILES:
        profile = "generic"
    wl = cfg.get("wordlist") or wordlists.default_for(profile, root)
    exts = cfg.get("extensions")
    if exts is None:
        exts = wordlists.PROFILES[profile]["exts"]
    return {"profile": profile, "wordlist": wl, "extensions": exts, "threads": int(cfg.get("threads", 40))}


@router.get("/projects/{pid}/web/dirconfig")
async def get_dirconfig(pid: int, profile: str | None = None):
    cfg = _dir_cfg(pid)
    root = db.get_setting("seclists_root", "/usr/share/seclists")
    prof = profile or cfg["profile"]
    lists = await asyncio.to_thread(wordlists.suggest, prof, root)
    if profile and profile != cfg["profile"]:
        cfg = {**cfg, "profile": profile, "wordlist": wordlists.default_for(profile, root),
               "extensions": wordlists.PROFILES[profile]["exts"]}
    nfiles = len(cfg["extensions"]) + 1
    return {"config": cfg, "profiles": wordlists.profile_catalog(), "wordlists": lists,
            "seclists": os.path.isdir(root), "request_multiplier": nfiles}


@router.put("/projects/{pid}/web/dirconfig")
async def put_dirconfig(pid: int, payload: dict):
    cfg = {"profile": payload.get("profile", "generic"), "wordlist": payload.get("wordlist", ""),
           "extensions": [str(e).strip().lstrip(".") for e in payload.get("extensions", []) if str(e).strip()],
           "threads": max(1, min(200, int(payload.get("threads", 40))))}
    db.set_setting(f"p.{pid}.dirconf", json.dumps(cfg))
    return _dir_cfg(pid)


def _plan(pid: int) -> dict:
    """Order and on/off choice for the 'run all' sequence (saved per project)."""
    keys = [t["key"] for t in webtools.WEB_TOOLS]
    try:
        raw = json.loads(db.get_setting(f"p.{pid}.webplan", "") or "{}")
    except ValueError:
        raw = {}
    order = [k for k in raw.get("order", []) if k in keys]
    order += [k for k in keys if k not in order]
    enabled = {k: bool(raw.get("enabled", {}).get(k, True)) for k in keys}
    return {"order": order, "enabled": enabled}


@router.put("/projects/{pid}/web/plan")
async def put_plan(pid: int, payload: dict):
    db.set_setting(f"p.{pid}.webplan", json.dumps({"order": payload.get("order", []), "enabled": payload.get("enabled", {})}))
    return _plan(pid)


def _latest_web_scans(pid: int) -> dict[str, Scan]:
    with db.get_session() as s:
        rows = s.exec(select(Scan).where(Scan.project_id == pid, Scan.kind.like("web_%"))
                      .order_by(Scan.created_at.desc())).all()
    latest: dict[str, Scan] = {}
    for r in rows:
        if r.kind != "web_runall":
            latest.setdefault(r.kind[4:], r)
    return latest


def _brief(sc: Scan) -> dict:
    """Scan summary without the (large) endpoint list, for dashboards that poll."""
    d = scan_dict(sc)
    if d["result_json"]:
        d["result_json"] = {k: v for k, v in d["result_json"].items() if k != "endpoints"}
    return d


def _blocker(pid: int, tool: str, targets: list[dict], cfg: dict) -> str:
    """Why this tool cannot run right now ('' when it can)."""
    meta = webtools.TOOL_MAP[tool]
    if not config.find_tool(meta["bin"]):
        return f"{meta['label']} is not installed. Install it with: {config.tool_hint(meta['bin'])}"
    if not targets:
        return "Add at least one target first."
    if meta.get("tls") and all(t["scheme"] == "http" for t in targets):
        return "Every target uses plain HTTP, so TLS checks do not apply. Switch a target to https to test it."
    if tool in webtools.DIR_TOOLS:
        wl = cfg.get("wordlist", "")
        if not wl or not os.path.isfile(wl):
            return "No usable wordlist is selected. Choose one under Directory discovery setup."
        if os.path.getsize(wl) == 0:
            return "The selected wordlist is empty. Choose another under Directory discovery setup."
    return ""


def _runall_latest(pid: int) -> Scan | None:
    with db.get_session() as s:
        return s.exec(select(Scan).where(Scan.project_id == pid, Scan.kind == "web_runall")
                      .order_by(Scan.created_at.desc())).first()


@router.get("/projects/{pid}/web/tools")
async def web_tools(pid: int):
    latest = _latest_web_scans(pid)
    plan = _plan(pid)
    out = []
    for pos, key in enumerate(plan["order"], 1):
        t = webtools.TOOL_MAP[key]
        sc = latest.get(key)
        counts: dict[str, int] = {}
        if sc:
            for f in db.list_findings(sc.id):
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        out.append({"key": key, "position": pos, "enabled": plan["enabled"][key], "label": t["label"],
                    "desc": t["desc"], "dir": bool(t.get("dir")),
                    "available": bool(config.find_tool(t["bin"])), "install": config.tool_hint(t["bin"]),
                    "scan": _brief(sc) if sc else None, "counts": counts})
    ra = _runall_latest(pid)
    return {"tools": out, "run_all_active": engine.group_running(f"web:{pid}"),
            "run_all": scan_dict(ra) if ra else None}


def _start_web(pid: int, tool: str) -> Scan:
    project = _project(pid)
    targets = _targets(pid)
    cfg = _dir_cfg(pid) if tool in webtools.DIR_TOOLS else {}
    why = _blocker(pid, tool, targets, cfg)
    if why:
        raise HTTPException(400, why)
    _preflight(project)
    meta = {"targets": [{"host": t["host"], "port": t["port"], "scheme": t["scheme"]} for t in targets],
            "channels": [], "cfg": cfg}
    sc = _new_scan(pid, f"web_{tool}", webtools.TOOL_MAP[tool]["label"], meta)
    engine.start(sc.id, webtools.build(project, tool, meta["targets"], cfg))
    return sc


@router.post("/projects/{pid}/web/run")
async def web_run(pid: int, payload: WebRunIn):
    if payload.tool not in webtools.TOOL_MAP:
        raise HTTPException(400, "Unknown tool.")
    if engine.group_running(f"web:{pid}"):
        raise HTTPException(409, "A full run is in progress. Stop it first, or wait for it to finish.")
    latest = _latest_web_scans(pid).get(payload.tool)
    if latest and engine.is_running(latest.id):
        raise HTTPException(409, "This tool is already running.")
    sc = _start_web(pid, payload.tool)
    return scan_dict(db.get_scan(sc.id))


def _ra_set(rid: int, tool: str, **kv) -> None:
    sc = db.get_scan(rid)
    items = dict((sc.meta or {}).get("items", {}))
    items[tool] = {**items.get(tool, {}), **kv}
    db.patch_meta(rid, items=items)


def _ra_finish(rid: int, state: ScanState) -> None:
    items = (db.get_scan(rid).meta or {}).get("items", {})
    counts: dict[str, int] = {}
    for it in items.values():
        counts[it["state"]] = counts.get(it["state"], 0) + 1
    with db.get_session() as s:
        sc = s.get(Scan, rid)
        sc.state, sc.result_json, sc.finished_at = state, {"counts": counts}, datetime.now(timezone.utc)
        sc.progress = 1.0
        s.add(sc)
        s.commit()


@router.post("/projects/{pid}/web/run-all")
async def web_run_all(pid: int, payload: dict | None = None):
    project = _project(pid)
    if not _targets(pid):
        raise HTTPException(400, "Add at least one target first.")
    if engine.group_running(f"web:{pid}"):
        raise HTTPException(409, "A full run is already in progress.")
    plan = _plan(pid)
    order = [k for k in (payload or {}).get("tools", []) if k in webtools.TOOL_MAP] or \
            [k for k in plan["order"] if plan["enabled"][k]]
    if not order:
        raise HTTPException(400, "Select at least one tool to run.")
    _preflight(project)
    with db.get_session() as s:
        ra = Scan(project_id=pid, kind="web_runall", label="Full run", state=ScanState.running,
                  started_at=datetime.now(timezone.utc),
                  meta={"order": order, "items": {k: {"state": "waiting", "note": "", "scan_id": None} for k in order}})
        s.add(ra)
        s.commit()
        s.refresh(ra)
    rid = ra.id

    async def chain() -> None:
        try:
            for tool in order:   # strictly one after another, in the chosen order
                _ra_set(rid, tool, state="running")
                cfg = _dir_cfg(pid) if tool in webtools.DIR_TOOLS else {}
                why = _blocker(pid, tool, _targets(pid), cfg)
                if why:
                    _ra_set(rid, tool, state="skipped", note=why)
                    continue
                try:
                    sc = _start_web(pid, tool)
                except HTTPException as exc:
                    _ra_set(rid, tool, state="failed", note=str(exc.detail))
                    continue
                _ra_set(rid, tool, scan_id=sc.id)
                await engine.wait(sc.id)
                fin = db.get_scan(sc.id)
                _ra_set(rid, tool, state=fin.state.value, note=fin.error or "")
            _ra_finish(rid, ScanState.done)
        except asyncio.CancelledError:
            for tool, it in (db.get_scan(rid).meta or {}).get("items", {}).items():
                if it["state"] in ("waiting", "running"):
                    _ra_set(rid, tool, state="canceled", note="Stopped before this tool finished.")
            _ra_finish(rid, ScanState.canceled)
            raise
        except Exception as exc:  # noqa: BLE001
            _ra_finish(rid, ScanState.failed)
            raise exc

    engine.track_group(f"web:{pid}", chain())
    await asyncio.sleep(0.05)
    return scan_dict(db.get_scan(rid))


@router.post("/projects/{pid}/web/stop")
async def web_stop(pid: int):
    engine.cancel_group(f"web:{pid}")
    for sc in _latest_web_scans(pid).values():
        if engine.is_running(sc.id):
            await engine.cancel(sc.id)
    return {"ok": True}


@router.get("/projects/{pid}/web/tools/{tool}/history")
async def web_tool_history(pid: int, tool: str):
    with db.get_session() as s:
        rows = s.exec(select(Scan).where(Scan.project_id == pid, Scan.kind == f"web_{tool}")
                      .order_by(Scan.created_at.desc())).all()[:30]
    out = []
    for r in rows:
        counts: dict[str, int] = {}
        for f in db.list_findings(r.id):
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        d = scan_dict(r)
        out.append({"id": r.id, "state": d["state"], "created_at": d["created_at"], "duration": d["duration"], "counts": counts})
    return out


def _finding_dict(f: Finding, tool: str = "") -> dict:
    return {"id": f.id, "scan_id": f.scan_id, "severity": f.severity.value, "title": f.title,
            "target": f.target, "evidence": f.evidence, "extra": f.extra, "tool": tool}


@router.get("/scans/{sid}/findings")
async def scan_findings(sid: int):
    sc = db.get_scan(sid)
    if not sc:
        raise HTTPException(404, "Scan not found.")
    rows = [_finding_dict(f, sc.label) for f in db.list_findings(sid)]
    rows.sort(key=lambda r: SEV_ORDER[r["severity"]])
    return rows


@router.get("/scans/{sid}/findings/export")
async def scan_findings_export(sid: int):
    sc = db.get_scan(sid)
    if not sc:
        raise HTTPException(404, "Scan not found.")
    rows = [_finding_dict(f, sc.label) for f in db.list_findings(sid)]
    if not rows:
        raise HTTPException(404, "This scan has no findings to export.")
    rows.sort(key=lambda r: SEV_ORDER[r["severity"]])
    out = excel.export_findings(rows, _exports_dir(_project(sc.project_id)) / f"{sc.kind[4:]}-findings-{_stamp()}.xlsx")
    return _download(out)


def _all_findings(pid: int) -> list[dict]:
    rows: list[dict] = []
    for tool, sc in _latest_web_scans(pid).items():
        for f in db.list_findings(sc.id):
            rows.append(_finding_dict(f, sc.label))
    rows.sort(key=lambda r: (SEV_ORDER[r["severity"]], r["tool"], r["title"]))
    return rows


@router.get("/projects/{pid}/web/findings")
async def web_findings(pid: int):
    rows = _all_findings(pid)
    counts = {k: sum(1 for r in rows if r["severity"] == k) for k in SEV_ORDER}
    return {"findings": rows, "counts": counts}


@router.get("/projects/{pid}/web/findings/export")
async def web_findings_export(pid: int):
    project = _project(pid)
    rows = _all_findings(pid)
    if not rows:
        raise HTTPException(404, "There are no findings to export yet.")
    return _download(excel.export_findings(rows, _exports_dir(project) / f"web-findings-{_stamp()}.xlsx"))


@router.get("/projects/{pid}/web/discovery")
async def web_discovery(pid: int):
    """Merge content-discovery results from every tool into one ranked view."""
    latest = _latest_web_scans(pid)
    raw: list[dict] = []
    used: list[str] = []
    for key in webtools.DIR_TOOLS:
        sc = latest.get(key)
        if not sc or not sc.result_json:
            continue
        used.append(webtools.TOOL_MAP[key]["label"])
        for e in sc.result_json.get("endpoints", []):
            for tool, status in (e.get("statuses") or {key: e["status"]}).items():
                raw.append({"origin": e["origin"], "path": e["path"], "status": status, "size": e["size"],
                            "redirect": e.get("redirect", ""), "tool": tool})
    scored = await asyncio.to_thread(discovery.analyze, raw)
    return {"endpoints": scored[:5000], "tools": used,
            "counts": {p: sum(1 for e in scored if e["priority"] == p and not e["noise"])
                       for p in ("high", "medium", "low", "info")},
            "noise": sum(1 for e in scored if e["noise"])}
