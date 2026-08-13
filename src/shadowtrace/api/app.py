"""FastAPI backend + live GUI for SHADOWTRACE."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from shadowtrace import __version__
from shadowtrace.attribution.clustering import run_attribution_pipeline
from shadowtrace.attribution.graph import build_actor_graph
from shadowtrace.attribution.similarity import compare_fingerprints
from shadowtrace.config import DATA_DIR, ensure_dirs, get_settings
from shadowtrace.db.store import Event, Store
from shadowtrace.detection.detectors import run_all_detectors
from shadowtrace.features.fingerprint import build_fingerprint_for_ip, rebuild_all_fingerprints
from shadowtrace.ingest.logs import ingest_file
from shadowtrace.realtime.engine import get_engine

STATIC_DIR = Path(__file__).resolve().parent.parent / "gui" / "static"
UPLOAD_DIR = DATA_DIR / "uploads"


def get_store() -> Store:
    return get_engine().store


app = FastAPI(
    title="SHADOWTRACE",
    description="Real-time attacker behavioral fingerprinting & actor attribution",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CompareRequest(BaseModel):
    ip_a: str
    ip_b: str


class MonitorStartRequest(BaseModel):
    paths: list[str] = Field(default_factory=list)
    kind: str = "auto"
    capture: bool = False
    iface: str | None = None
    bpf: str | None = None
    udp_port: int | None = None
    udp_host: str = "0.0.0.0"


class EventIn(BaseModel):
    ts: str | None = None
    src_ip: str
    event_type: str
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    username: str | None = None
    path: str | None = None
    tool_hint: str | None = None
    session_id: str | None = None
    duration: float | None = None


class EventsBatch(BaseModel):
    events: list[EventIn]


@app.on_event("startup")
def _startup() -> None:
    ensure_dirs()
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    get_engine()


@app.get("/api/health")
def health() -> dict[str, Any]:
    eng = get_engine().snapshot()
    return {
        "status": "ok",
        "version": __version__,
        "name": "SHADOWTRACE",
        "live": eng["running"],
        "mode": eng["mode"],
    }


@app.get("/api/live/status")
def live_status() -> dict[str, Any]:
    return get_engine().snapshot()


@app.post("/api/live/start")
def live_start(body: MonitorStartRequest) -> dict[str, Any]:
    settings = get_settings()
    engine = get_engine()
    if engine.status.running:
        raise HTTPException(409, "Monitor already running — stop it first")
    if not body.paths and not body.capture and body.udp_port is None:
        raise HTTPException(400, "Provide paths, capture=true, and/or udp_port")
    engine.start(
        watch_paths=[Path(p) for p in body.paths],
        kind=body.kind,
        iface=body.iface,
        bpf=body.bpf or settings.default_bpf,
        udp_host=body.udp_host if body.udp_port else None,
        udp_port=body.udp_port,
        enable_capture=body.capture or body.iface is not None,
    )
    return {"ok": True, "status": engine.snapshot()}


@app.post("/api/live/stop")
def live_stop() -> dict[str, Any]:
    engine = get_engine()
    engine.stop()
    return {"ok": True, "status": engine.snapshot()}


@app.post("/api/live/attribute")
def live_attribute() -> dict[str, Any]:
    result = get_engine().maybe_attribute(force=True)
    return result or {"type": "attribution", "message": "nothing to attribute"}


@app.post("/api/events")
def post_events(body: EventsBatch) -> dict[str, Any]:
    """Push events into the live pipeline (SIEM / agent / script)."""
    from datetime import datetime, timezone

    events: list[Event] = []
    for e in body.events:
        raw = {}
        if e.duration is not None:
            raw["duration"] = e.duration
        events.append(
            Event(
                ts=e.ts or datetime.now(timezone.utc).isoformat(),
                src_ip=e.src_ip,
                event_type=e.event_type,
                dst_ip=e.dst_ip,
                dst_port=e.dst_port,
                protocol=e.protocol,
                username=e.username,
                path=e.path,
                tool_hint=e.tool_hint,
                raw=raw,
                session_id=e.session_id,
            )
        )
    n = get_engine().ingest_events(events, source="api")
    return {"ingested": n}


@app.get("/api/stats")
def stats() -> dict[str, Any]:
    snap = get_engine().snapshot()
    return {**snap["db"], "live": snap}


@app.get("/api/events")
def list_events(
    src_ip: Optional[str] = None,
    limit: int = Query(500, ge=1, le=20000),
    event_type: Optional[str] = None,
) -> dict[str, Any]:
    events = get_store().list_events(src_ip=src_ip, limit=limit, event_type=event_type)
    return {"count": len(events), "events": events}


@app.get("/api/fingerprints")
def list_fingerprints() -> dict[str, Any]:
    fps = get_store().list_fingerprints()
    return {"count": len(fps), "fingerprints": fps}


@app.get("/api/fingerprints/{src_ip}")
def get_fingerprint(src_ip: str) -> dict[str, Any]:
    store = get_store()
    fp = store.get_fingerprint(src_ip)
    if not fp:
        fp = build_fingerprint_for_ip(store, src_ip)
    return fp


@app.post("/api/fingerprint/rebuild")
def rebuild_fingerprints() -> dict[str, Any]:
    fps = rebuild_all_fingerprints(get_store())
    return {"count": len(fps), "fingerprints": fps}


@app.post("/api/attribute")
def attribute() -> dict[str, Any]:
    result = get_engine().maybe_attribute(force=True)
    if not result:
        result = run_attribution_pipeline(get_store())
        result = {
            "type": "attribution",
            "stats": result["stats"],
            "clusters": result["clusters"],
            "attributions": result["attributions"],
            "findings": run_all_detectors(get_store().list_events(limit=50000)),
        }
    return result


@app.get("/api/clusters")
def clusters() -> dict[str, Any]:
    return {"clusters": get_store().list_clusters()}


@app.get("/api/attributions")
def attributions(min_score: float = 0.0) -> dict[str, Any]:
    return {"attributions": get_store().list_attributions(min_score=min_score)}


@app.post("/api/compare")
def compare(body: CompareRequest) -> dict[str, Any]:
    store = get_store()
    fp_a = build_fingerprint_for_ip(store, body.ip_a)
    fp_b = build_fingerprint_for_ip(store, body.ip_b)
    if fp_a["event_count"] == 0 or fp_b["event_count"] == 0:
        raise HTTPException(400, "One or both IPs have no events")
    return compare_fingerprints(fp_a, fp_b)


@app.get("/api/graph")
def graph(min_score: Optional[float] = None) -> dict[str, Any]:
    store = get_store()
    return build_actor_graph(
        store.list_attributions(),
        store.list_fingerprints(),
        store.list_clusters(),
        min_score=min_score,
    )


@app.get("/api/detections")
def detections() -> dict[str, Any]:
    events = get_store().list_events(limit=100000)
    return {"findings": run_all_detectors(events)}


@app.post("/api/ingest/upload")
async def upload_ingest(
    file: UploadFile = File(...),
    kind: str = Query("auto"),
) -> dict[str, Any]:
    ensure_dirs()
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / (file.filename or "upload.bin")
    with dest.open("wb") as f:
        shutil.copyfileobj(file.file, f)
    if kind == "zeek":
        from shadowtrace.ingest.zeek_parser import parse_zeek_tsv

        events = parse_zeek_tsv(dest)
    elif kind == "pcap":
        from shadowtrace.ingest.scapy_capture import ingest_pcap

        events = ingest_pcap(dest)
    else:
        events = ingest_file(dest, kind=kind)
    n = get_engine().ingest_events(events, source="upload")
    get_engine().flush()
    get_engine().maybe_attribute(force=True)
    return {"ingested": n, "path": str(dest)}


@app.post("/api/reset")
def reset_db() -> dict[str, str]:
    engine = get_engine()
    if engine.status.running:
        raise HTTPException(409, "Stop live monitor before resetting")
    engine.store.clear_all()
    return {"status": "cleared"}


@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket) -> None:
    await websocket.accept()
    engine = get_engine()
    queue: asyncio.Queue = asyncio.Queue(maxsize=64)
    engine.register_async_queue(queue)
    try:
        await websocket.send_json({"type": "hello", "status": engine.snapshot()})
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                await websocket.send_json(msg)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping", "status": engine.snapshot()})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        engine.unregister_async_queue(queue)


# Static GUI
if STATIC_DIR.exists():
    assets = STATIC_DIR / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")
