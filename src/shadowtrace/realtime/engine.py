"""Real-time event bus, watchers, and continuous attribution."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Deque, Optional

from shadowtrace.attribution.clustering import run_attribution_pipeline
from shadowtrace.config import Settings, ensure_dirs, get_settings
from shadowtrace.db.store import Event, Store
from shadowtrace.detection.detectors import run_all_detectors
from shadowtrace.ingest.logs import (
    parse_http_access_line,
    parse_jsonl_line,
    parse_ssh_auth_line,
)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EngineStatus:
    running: bool = False
    mode: str = "idle"
    events_total: int = 0
    events_last_minute: int = 0
    last_event_at: str | None = None
    last_attribution_at: str | None = None
    watched_paths: list[str] = field(default_factory=list)
    capture_iface: str | None = None
    stream_bind: str | None = None
    errors: list[str] = field(default_factory=list)
    recent_events: list[dict[str, Any]] = field(default_factory=list)


class RealtimeEngine:
    """Singleton-ish process engine for live ingest + attribution."""

    def __init__(self, store: Store | None = None, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        ensure_dirs()
        self.store = store or Store(self.settings.db_path)
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._subscribers: list[Callable[[dict[str, Any]], None]] = []
        self._async_queues: list[asyncio.Queue] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._pending: Deque[Event] = deque()
        self._minute_hits: Deque[float] = deque()
        self._dirty = False
        self._last_attr = 0.0
        self.status = EngineStatus()
        self._attr_interval = float(getattr(self.settings, "attr_interval_sec", 5.0))
        self._flush_batch = int(getattr(self.settings, "flush_batch", 25))

    # ---- pub/sub -----------------------------------------------------
    def subscribe(self, callback: Callable[[dict[str, Any]], None]) -> None:
        with self._lock:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[dict[str, Any]], None]) -> None:
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def register_async_queue(self, q: asyncio.Queue) -> None:
        with self._lock:
            self._async_queues.append(q)

    def unregister_async_queue(self, q: asyncio.Queue) -> None:
        with self._lock:
            if q in self._async_queues:
                self._async_queues.remove(q)

    def _emit(self, message: dict[str, Any]) -> None:
        message.setdefault("ts", utcnow())
        with self._lock:
            subs = list(self._subscribers)
            queues = list(self._async_queues)
        for cb in subs:
            try:
                cb(message)
            except Exception:
                pass
        for q in queues:
            try:
                q.put_nowait(message)
            except Exception:
                try:
                    while not q.empty():
                        q.get_nowait()
                    q.put_nowait(message)
                except Exception:
                    pass

    # ---- ingest ------------------------------------------------------
    def ingest_events(self, events: list[Event], source: str = "api") -> int:
        if not events:
            return 0
        with self._lock:
            self._pending.extend(events)
            self.status.events_total += len(events)
            self.status.last_event_at = utcnow()
            now = time.time()
            for _ in events:
                self._minute_hits.append(now)
            while self._minute_hits and now - self._minute_hits[0] > 60:
                self._minute_hits.popleft()
            self.status.events_last_minute = len(self._minute_hits)
            for e in events[-15:]:
                self.status.recent_events.append(
                    {
                        "ts": e.ts,
                        "src_ip": e.src_ip,
                        "event_type": e.event_type,
                        "dst_port": e.dst_port,
                        "username": e.username,
                        "path": e.path,
                        "source": source,
                    }
                )
            self.status.recent_events = self.status.recent_events[-40:]
            self._dirty = True
        self._emit(
            {
                "type": "events",
                "count": len(events),
                "source": source,
                "sample": [
                    {"src_ip": e.src_ip, "event_type": e.event_type, "ts": e.ts}
                    for e in events[:5]
                ],
            }
        )
        if len(self._pending) >= self._flush_batch:
            self.flush()
        return len(events)

    def ingest_line(self, line: str, kind: str = "auto", source: str = "tail") -> bool:
        line = line.strip()
        if not line or line.startswith("#"):
            return False
        ev: Event | None = None
        if kind == "jsonl" or (kind == "auto" and line.startswith("{")):
            ev = parse_jsonl_line(line)
        elif kind == "ssh" or (kind == "auto" and "sshd" in line):
            ev = parse_ssh_auth_line(line)
        elif kind == "http" or (kind == "auto" and "[" in line and '"' in line):
            ev = parse_http_access_line(line)
        else:
            ev = parse_jsonl_line(line) or parse_ssh_auth_line(line) or parse_http_access_line(line)
        if not ev:
            return False
        self.ingest_events([ev], source=source)
        return True

    def flush(self) -> int:
        with self._lock:
            batch = list(self._pending)
            self._pending.clear()
        if not batch:
            return 0
        n = self.store.insert_events(batch)
        return n

    def maybe_attribute(self, force: bool = False) -> dict[str, Any] | None:
        with self._lock:
            dirty = self._dirty
            due = force or (dirty and (time.time() - self._last_attr) >= self._attr_interval)
        if not due:
            return None
        self.flush()
        result = run_attribution_pipeline(self.store, self.settings)
        findings = run_all_detectors(self.store.list_events(limit=50000))
        with self._lock:
            self._dirty = False
            self._last_attr = time.time()
            self.status.last_attribution_at = utcnow()
        payload = {
            "type": "attribution",
            "stats": result["stats"],
            "clusters": result["clusters"],
            "attributions": result["attributions"][:50],
            "findings": findings,
        }
        self._emit(payload)
        return payload

    def snapshot(self) -> dict[str, Any]:
        self.flush()
        with self._lock:
            st = {
                "running": self.status.running,
                "mode": self.status.mode,
                "events_total": self.status.events_total,
                "events_last_minute": self.status.events_last_minute,
                "last_event_at": self.status.last_event_at,
                "last_attribution_at": self.status.last_attribution_at,
                "watched_paths": list(self.status.watched_paths),
                "capture_iface": self.status.capture_iface,
                "stream_bind": self.status.stream_bind,
                "errors": list(self.status.errors[-10:]),
                "recent_events": list(self.status.recent_events),
            }
        st["db"] = self.store.stats()
        return st

    # ---- workers -----------------------------------------------------
    def _attr_loop(self) -> None:
        while not self._stop.wait(1.0):
            try:
                self.maybe_attribute(force=False)
            except Exception as exc:
                with self._lock:
                    self.status.errors.append(f"attribution: {exc}")
                self._emit({"type": "error", "message": str(exc)})

    def _tail_file(self, path: Path, kind: str) -> None:
        path = Path(path)
        with self._lock:
            if str(path) not in self.status.watched_paths:
                self.status.watched_paths.append(str(path))
        # Wait for file to appear
        while not self._stop.is_set() and not path.exists():
            self._stop.wait(0.5)
        if self._stop.is_set():
            return
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                # Follow from end for live; also optionally catch up last N lines
                fh.seek(0, 2)
                while not self._stop.is_set():
                    line = fh.readline()
                    if line:
                        self.ingest_line(line, kind=kind, source=f"tail:{path.name}")
                        continue
                    # handle truncation/rotation
                    try:
                        if path.exists() and fh.tell() > path.stat().st_size:
                            fh.seek(0, 0)
                    except OSError:
                        pass
                    self._stop.wait(0.2)
        except Exception as exc:
            with self._lock:
                self.status.errors.append(f"tail {path}: {exc}")
            self._emit({"type": "error", "message": f"tail {path}: {exc}"})

    def _live_capture(self, iface: str | None, bpf: str, count_limit: int = 0) -> None:
        try:
            from shadowtrace.ingest.live_capture import sniff_to_events
        except Exception as exc:
            with self._lock:
                self.status.errors.append(f"capture import: {exc}")
            return

        with self._lock:
            self.status.capture_iface = iface or "default"

        def on_batch(events: list[Event]) -> None:
            self.ingest_events(events, source="pcap-live")

        try:
            sniff_to_events(
                iface=iface,
                bpf=bpf,
                stop_event=self._stop,
                on_batch=on_batch,
                batch_size=20,
                count_limit=count_limit,
            )
        except Exception as exc:
            with self._lock:
                self.status.errors.append(f"capture: {exc}")
            self._emit({"type": "error", "message": f"capture: {exc}"})

    def _udp_stream(self, host: str, port: int, kind: str) -> None:
        import socket

        with self._lock:
            self.status.stream_bind = f"udp://{host}:{port}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.settimeout(0.5)
        try:
            while not self._stop.is_set():
                try:
                    data, _addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                text = data.decode("utf-8", errors="replace")
                for line in text.splitlines():
                    self.ingest_line(line, kind=kind, source="udp")
        finally:
            sock.close()

    def start(
        self,
        watch_paths: list[Path] | None = None,
        kind: str = "auto",
        iface: str | None = None,
        bpf: str = "tcp or udp",
        udp_host: str | None = None,
        udp_port: int | None = None,
        enable_capture: bool = False,
    ) -> None:
        if self.status.running:
            return
        self._stop.clear()
        self.status.running = True
        self.status.mode = "live"
        self._threads = [
            threading.Thread(target=self._attr_loop, name="shadowtrace-attr", daemon=True)
        ]
        for p in watch_paths or []:
            t = threading.Thread(
                target=self._tail_file,
                args=(Path(p), kind),
                name=f"tail-{Path(p).name}",
                daemon=True,
            )
            self._threads.append(t)
        if enable_capture:
            t = threading.Thread(
                target=self._live_capture,
                args=(iface, bpf, 0),
                name="shadowtrace-capture",
                daemon=True,
            )
            self._threads.append(t)
        if udp_host is not None and udp_port is not None:
            t = threading.Thread(
                target=self._udp_stream,
                args=(udp_host, udp_port, kind),
                name="shadowtrace-udp",
                daemon=True,
            )
            self._threads.append(t)
        for t in self._threads:
            t.start()
        self._emit({"type": "status", "status": self.snapshot()})

    def stop(self) -> None:
        self._stop.set()
        self.flush()
        try:
            self.maybe_attribute(force=True)
        except Exception:
            pass
        for t in self._threads:
            t.join(timeout=2.0)
        self._threads.clear()
        self.status.running = False
        self.status.mode = "idle"
        self._emit({"type": "status", "status": self.snapshot()})


_ENGINE: RealtimeEngine | None = None
_ENGINE_LOCK = threading.Lock()


def get_engine() -> RealtimeEngine:
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is None:
            _ENGINE = RealtimeEngine()
        return _ENGINE
