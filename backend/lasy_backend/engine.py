"""The scan engine.

Every tool runs inside a real pseudo-terminal so colours, progress bars and
line buffering behave exactly like a normal Kali shell. Raw terminal bytes are
streamed to the browser (xterm.js) over WebSocket and also stored in a Linux-side
replay log so a finished (or interrupted) scan can be viewed again later.

Pausing a scan stops its processes gracefully (Ctrl-C style, so nmap flushes its
log); resuming relaunches unfinished units. State survives a backend restart
because it lives in SQLite, not in memory.
"""
from __future__ import annotations

import asyncio
import codecs
import fcntl
import logging
import os
import pty
import re
import shlex
import signal
import struct
import termios
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

from sqlmodel import select

from . import config, db
from .models import Scan, ScanState

log = logging.getLogger("lasy.engine")

COLS, ROWS = 120, 40


class ToolMissing(RuntimeError):
    """A required binary is not installed."""


class StageError(RuntimeError):
    """A user-facing precondition failure (shown as the scan's error)."""


ANSI_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>78]"
)


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


class LineAssembler:
    """Turns a raw terminal stream into clean text lines (ANSI stripped,
    carriage-return progress frames collapsed)."""

    def __init__(self) -> None:
        self.buf = ""
        self.pending_cr = False

    def feed(self, text: str) -> list[str]:
        text = ANSI_RE.sub("", text)
        if self.pending_cr:
            text = "\r" + text
            self.pending_cr = False
        if text.endswith("\r"):
            text = text[:-1]
            self.pending_cr = True
        out: list[str] = []
        parts = re.split(r"(\r\n|\n|\r)", text)
        for i in range(0, len(parts), 2):
            seg = parts[i]
            sep = parts[i + 1] if i + 1 < len(parts) else None
            self.buf += seg
            if sep is None:
                break
            if sep == "\r":
                self.buf = ""
            else:
                out.append(self.buf)
                self.buf = ""
        return out

    def finish(self) -> list[str]:
        rest, self.buf = self.buf, ""
        return [rest] if rest.strip() else []


class TerminalHub:
    """In-memory terminal buffers + live subscribers, keyed '<scan>:<channel>'."""

    MAX_CHARS = 8_000_000

    def __init__(self) -> None:
        self.chunks: dict[str, list[str]] = defaultdict(list)
        self.sizes: dict[str, int] = defaultdict(int)
        self.subs: dict[str, set[asyncio.Queue]] = defaultdict(set)

    def publish(self, key: str, text: str) -> None:
        self.chunks[key].append(text)
        self.sizes[key] += len(text)
        while self.sizes[key] > self.MAX_CHARS and len(self.chunks[key]) > 1:
            self.sizes[key] -= len(self.chunks[key].pop(0))
        for q in list(self.subs[key]):
            q.put_nowait(text)

    def attach(self, key: str, loader: Callable[[], str] | None):
        if key not in self.chunks and loader:
            text = loader()
            if text:
                self.chunks[key].append(text)
                self.sizes[key] = len(text)
        snap = "".join(self.chunks.get(key, []))
        q: asyncio.Queue = asyncio.Queue()
        self.subs[key].add(q)
        return snap, q

    def detach(self, key: str, q: asyncio.Queue) -> None:
        self.subs[key].discard(q)

    def release(self, prefix: str) -> None:
        for key in [k for k in self.chunks if k.startswith(prefix) and not self.subs.get(k)]:
            self.chunks.pop(key, None)
            self.sizes.pop(key, None)


def term_path(scan_id: int, channel: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", channel)
    return config.TERM_DIR / f"{scan_id}-{safe}.log"


def _shorten(arg: str) -> str:
    """Display only: absolute paths become their file name."""
    if arg.startswith("/") and len(arg) > 1:
        return os.path.basename(arg.rstrip("/")) or arg
    return arg


def _display_tokens(argv: list[str]) -> list[str]:
    toks = list(argv)
    if toks[:2] == ["sudo", "-n"]:
        toks = toks[2:]
    return [_shorten(a) for a in toks]


def _shq(tok: str) -> str:
    return shlex.quote(tok) if re.search(r"[^\w@%+=:,./-]", tok) else tok


ScanBody = Callable[["ScanContext"], Awaitable[None]]


class Engine:
    def __init__(self) -> None:
        self.hub = TerminalHub()
        self._procs: dict[int, set[asyncio.subprocess.Process]] = defaultdict(set)
        self._tasks: dict[int, asyncio.Task] = {}
        self._groups: dict[str, asyncio.Task] = {}
        self._paused: set[int] = set()
        self._limiters: dict[str, tuple[int, asyncio.Semaphore]] = {}
        self._idle: set[str] = set()

    # -- concurrency limiter ------------------------------------------------
    def limiter(self, name: str, n: int) -> asyncio.Semaphore:
        n = max(1, int(n))
        cur = self._limiters.get(name)
        if cur is None or cur[0] != n:
            cur = (n, asyncio.Semaphore(n))
            self._limiters[name] = cur
        return cur[1]

    # -- state --------------------------------------------------------------
    def recover_on_startup(self) -> None:
        """Processes do not survive a restart: flag unfinished work as interrupted."""
        with db.get_session() as s:
            rows = s.exec(select(Scan).where(Scan.state.in_([ScanState.running, ScanState.queued]))).all()
            for sc in rows:
                if sc.resumable:
                    sc.state = ScanState.interrupted
                    m = dict(sc.meta or {})
                    if m.get("batches"):
                        m["batches"] = [
                            {**b, "state": "interrupted"} if b.get("state") == "running" else b
                            for b in m["batches"]
                        ]
                        sc.meta = m
                else:
                    sc.state = ScanState.failed
                    sc.error = sc.error or "lasy was restarted before this scan finished. Run it again."
                s.add(sc)
            s.commit()

    def _set_state(self, scan_id: int, state: ScanState, **fields) -> None:
        with db.get_session() as s:
            sc = s.get(Scan, scan_id)
            if not sc:
                return
            sc.state = state
            for k, v in fields.items():
                setattr(sc, k, v)
            s.add(sc)
            s.commit()

    def _interrupt_batches(self, scan_id: int) -> None:
        sc = db.get_scan(scan_id)
        m = dict((sc.meta if sc else None) or {})
        if m.get("batches"):
            m["batches"] = [{**b, "state": "interrupted"} if b.get("state") == "running" else b
                            for b in m["batches"]]
            db.patch_meta(scan_id, batches=m["batches"])

    def is_running(self, scan_id: int) -> bool:
        t = self._tasks.get(scan_id)
        return bool(t and not t.done())

    def is_paused(self, scan_id: int) -> bool:
        return scan_id in self._paused

    # -- terminal text ------------------------------------------------------
    def _ps1(self) -> str:
        user = db.get_setting("kali_prompt_user", "kali")
        host = db.get_setting("kali_prompt_host", "kali")
        return (f"\x1b[32m┌──(\x1b[1;34m{user}㉿{host}\x1b[0;32m)-[\x1b[1;39m~\x1b[0;32m]\r\n"
                f"\x1b[32m└─\x1b[1;34m$\x1b[0m ")

    def _out(self, scan_id: int, channel: str, text: str) -> None:
        key = f"{scan_id}:{channel}"
        self.hub.publish(key, text)
        try:
            with open(term_path(scan_id, channel), "a", encoding="utf-8", errors="replace") as f:
                f.write(text)
        except OSError:
            pass

    def emit(self, scan_id: int, channel: str, text: str) -> None:
        key = f"{scan_id}:{channel}"
        prefix = "\r\n" if key in self._idle else ""
        self._idle.discard(key)
        self._out(scan_id, channel, prefix + text.replace("\r\n", "\n").replace("\n", "\r\n") + "\r\n")

    def reset_terminal(self, scan_id: int) -> None:
        for p in config.TERM_DIR.glob(f"{scan_id}-*.log"):
            try:
                p.unlink()
            except OSError:
                pass
        for key in [k for k in self.hub.chunks if k.startswith(f"{scan_id}:")]:
            self.hub.chunks.pop(key, None)
            self.hub.sizes.pop(key, None)
            self._idle.discard(key)

    # -- running a command --------------------------------------------------
    async def run_command(
        self, scan_id: int, argv: list[str], *, channel: str = "main",
        result_file: str | Path | None = None, append_result: bool = False,
        display: list[str] | None = None, line_sink: list[str] | None = None,
        env: dict | None = None, cwd: str | Path | None = None,
        timeout: float | None = None, show_prompt: bool = True,
    ) -> int:
        key = f"{scan_id}:{channel}"
        if show_prompt:
            cmd = " ".join(_shq(t) for t in (display or _display_tokens(argv)))
            if key in self._idle:
                self._out(scan_id, channel, cmd + "\r\n")
            else:
                self._out(scan_id, channel, self._ps1() + cmd + "\r\n")
            self._idle.discard(key)

        rfile = None
        if result_file:
            Path(result_file).parent.mkdir(parents=True, exist_ok=True)
            rfile = open(result_file, "a" if append_result else "w", encoding="utf-8", errors="replace")

        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
        penv = {**os.environ, "TERM": "xterm-256color", "COLUMNS": str(COLS), "LINES": str(ROWS),
                "PYTHONUNBUFFERED": "1"}
        penv.setdefault("LANG", "C.UTF-8")
        if env:
            penv.update(env)
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdin=asyncio.subprocess.DEVNULL, stdout=slave, stderr=slave,
                env=penv, cwd=str(cwd) if cwd else None, start_new_session=True,
            )
        except FileNotFoundError:
            os.close(master)
            os.close(slave)
            if rfile:
                rfile.close()
            name = argv[2] if argv[:2] == ["sudo", "-n"] and len(argv) > 2 else argv[0]
            self._out(scan_id, channel, f"\x1b[31mbash: {name}: command not found\x1b[0m\r\n")
            self._out(scan_id, channel, self._ps1())
            self._idle.add(key)
            raise ToolMissing(f"'{name}' is not installed.")
        os.close(slave)
        self._procs[scan_id].add(proc)

        loop = asyncio.get_running_loop()
        q: asyncio.Queue = asyncio.Queue()

        def on_readable() -> None:
            try:
                data = os.read(master, 65536)
            except OSError:
                data = b""
            if data:
                q.put_nowait(data)
            else:
                try:
                    loop.remove_reader(master)
                except Exception:
                    pass
                q.put_nowait(None)

        loop.add_reader(master, on_readable)
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        asm = LineAssembler()
        watchdog = None

        def sink_lines(lines: list[str]) -> None:
            for ln in lines:
                if rfile:
                    rfile.write(ln + "\n")
                if line_sink is not None:
                    line_sink.append(ln)

        if timeout:
            async def _watch():
                await asyncio.sleep(timeout)
                self._out(scan_id, channel, "\r\n\x1b[33m[lasy] time limit reached, stopping this tool\x1b[0m\r\n")
                await self._kill_group(proc)
            watchdog = asyncio.create_task(_watch())

        try:
            while True:
                data = await q.get()
                if data is None:
                    break
                text = decoder.decode(data)
                if text:
                    self._out(scan_id, channel, text)
                    sink_lines(asm.feed(text))
            sink_lines(asm.finish())
            code = await proc.wait()
        finally:
            if watchdog:
                watchdog.cancel()
            try:
                loop.remove_reader(master)
            except Exception:
                pass
            try:
                os.close(master)
            except OSError:
                pass
            if proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            self._procs[scan_id].discard(proc)
            if rfile:
                rfile.close()
        self._out(scan_id, channel, self._ps1())
        self._idle.add(key)
        return code

    async def _kill_group(self, proc: asyncio.subprocess.Process, grace: float = 6.0) -> None:
        if proc.returncode is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGINT)   # Ctrl-C: lets nmap flush its log
        except (ProcessLookupError, PermissionError):
            pass
        try:
            await asyncio.wait_for(proc.wait(), grace)
        except asyncio.TimeoutError:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

    async def _stop_procs(self, scan_id: int) -> None:
        procs = list(self._procs.get(scan_id, []))
        if procs:
            await asyncio.gather(*[self._kill_group(p) for p in procs], return_exceptions=True)

    # -- orchestration ------------------------------------------------------
    def start(self, scan_id: int, body: ScanBody, fresh: bool = True) -> None:
        if self.is_running(scan_id):
            return
        self._paused.discard(scan_id)
        if fresh:
            self.reset_terminal(scan_id)
        self._set_state(scan_id, ScanState.queued, error="")
        self._tasks[scan_id] = asyncio.create_task(self._supervise(scan_id, body))

    async def _supervise(self, scan_id: int, body: ScanBody) -> None:
        self._set_state(scan_id, ScanState.running, started_at=datetime.now(timezone.utc),
                        finished_at=None)
        ctx = ScanContext(self, scan_id)
        try:
            await body(ctx)
            if scan_id in self._paused:
                self._set_state(scan_id, ScanState.paused)
            else:
                self._set_state(scan_id, ScanState.done, finished_at=datetime.now(timezone.utc), progress=1.0)
        except asyncio.CancelledError:
            self._interrupt_batches(scan_id)
            self._set_state(scan_id, ScanState.canceled, finished_at=datetime.now(timezone.utc))
            raise
        except (StageError, ToolMissing) as exc:
            hint = ""
            if isinstance(exc, ToolMissing):
                m = re.match(r"'(.+)' is not installed", str(exc))
                hint = f" Install it with: {config.tool_hint(m.group(1))}" if m and config.tool_hint(m.group(1)) else ""
            self._set_state(scan_id, ScanState.failed, error=str(exc) + hint,
                            finished_at=datetime.now(timezone.utc))
        except Exception as exc:  # noqa: BLE001
            log.exception("scan %s failed", scan_id)
            self._set_state(scan_id, ScanState.failed, error=str(exc) or exc.__class__.__name__,
                            finished_at=datetime.now(timezone.utc))
        finally:
            self._tasks.pop(scan_id, None)
            self.hub.release(f"{scan_id}:")

    async def pause(self, scan_id: int) -> None:
        if not self.is_running(scan_id):
            return
        self._paused.add(scan_id)
        self._set_state(scan_id, ScanState.paused)
        asyncio.create_task(self._stop_procs(scan_id))

    async def cancel(self, scan_id: int) -> None:
        await self._stop_procs(scan_id)
        t = self._tasks.get(scan_id)
        if t:
            t.cancel()

    async def wait(self, scan_id: int) -> None:
        t = self._tasks.get(scan_id)
        if t:
            await asyncio.wait([t])

    def track_group(self, key: str, coro) -> None:
        old = self._groups.get(key)
        if old and not old.done():
            old.cancel()
        self._groups[key] = asyncio.create_task(coro)

    def cancel_group(self, key: str) -> None:
        t = self._groups.get(key)
        if t and not t.done():
            t.cancel()

    def group_running(self, key: str) -> bool:
        t = self._groups.get(key)
        return bool(t and not t.done())


class ScanContext:
    def __init__(self, engine: Engine, scan_id: int) -> None:
        self.engine = engine
        self.scan_id = scan_id

    @property
    def paused(self) -> bool:
        return self.engine.is_paused(self.scan_id)

    async def run(self, argv: list[str], **kw) -> int:
        return await self.engine.run_command(self.scan_id, argv, **kw)

    def emit(self, text: str, channel: str = "main") -> None:
        self.engine.emit(self.scan_id, channel, text)

    def add_channel(self, cid: str, label: str) -> None:
        sc = db.get_scan(self.scan_id)
        chans = list((sc.meta or {}).get("channels", []))
        if not any(c["id"] == cid for c in chans):
            chans.append({"id": cid, "label": label})
            db.patch_meta(self.scan_id, channels=chans)

    def note(self, text: str) -> None:
        db.patch_meta(self.scan_id, note=text)

    def store_result(self, obj) -> None:
        with db.get_session() as s:
            sc = s.get(Scan, self.scan_id)
            if sc:
                sc.result_json = obj
                s.add(sc)
                s.commit()

    def add_output(self, path: str | Path) -> None:
        with db.get_session() as s:
            sc = s.get(Scan, self.scan_id)
            if sc:
                paths = list(sc.output_paths or [])
                if str(path) not in paths:
                    paths.append(str(path))
                    sc.output_paths = paths
                    s.add(sc)
                    s.commit()

    def set_progress(self, value: float) -> None:
        self.engine._set_state(self.scan_id, ScanState.running, progress=max(0.0, min(1.0, value)))


engine = Engine()
