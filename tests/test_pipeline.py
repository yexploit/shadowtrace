"""Pipeline + real-time engine tests."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from shadowtrace.attribution.clustering import run_attribution_pipeline
from shadowtrace.db.store import Store
from shadowtrace.ingest.logs import ingest_file, parse_jsonl_line
from shadowtrace.realtime.engine import RealtimeEngine
from tests.fixtures import make_multi_actor_events


def test_attribution_links_same_behavior_across_ips(tmp_path: Path) -> None:
    store = Store(tmp_path / "test.db")
    events = make_multi_actor_events()
    assert len(events) > 50
    store.insert_events(events)
    result = run_attribution_pipeline(store)
    multi = [c for c in result["clusters"] if len(c["members"]) > 1]
    assert multi
    persona_a = {"10.0.0.21", "10.0.0.73", "185.220.101.44"}
    decoy = "203.0.113.88"
    best = max(multi, key=lambda c: (len(set(c["members"]) & persona_a), c["confidence"]))
    assert len(set(best["members"]) & persona_a) >= 2
    assert decoy not in best["members"]


def test_realtime_tail_and_attribute(tmp_path: Path) -> None:
    log = tmp_path / "live.jsonl"
    log.write_text("", encoding="utf-8")
    store = Store(tmp_path / "rt.db")
    engine = RealtimeEngine(store=store)
    engine._attr_interval = 0.5  # noqa: SLF001 — test speedup
    engine.start(watch_paths=[log], kind="jsonl")
    try:
        lines = []
        for ev in make_multi_actor_events()[:80]:
            obj = {
                "ts": ev.ts,
                "src_ip": ev.src_ip,
                "event_type": ev.event_type,
                "dst_port": ev.dst_port,
                "protocol": ev.protocol,
                "username": ev.username,
                "path": ev.path,
                "tool_hint": ev.tool_hint,
            }
            if ev.raw and "duration" in ev.raw:
                obj["duration"] = ev.raw["duration"]
            import json

            lines.append(json.dumps({k: v for k, v in obj.items() if v is not None}))
        with log.open("a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
                fh.flush()
                time.sleep(0.01)
        deadline = time.time() + 8
        while time.time() < deadline:
            engine.flush()
            if store.stats()["events"] >= 40:
                break
            time.sleep(0.2)
        assert store.stats()["events"] >= 40
        result = engine.maybe_attribute(force=True)
        assert result is not None
        assert result["stats"]["events"] >= 40
    finally:
        engine.stop()


def test_ingest_jsonl_batch(tmp_path: Path) -> None:
    path = tmp_path / "batch.jsonl"
    events = make_multi_actor_events()[:30]
    import json

    path.write_text(
        "\n".join(
            json.dumps(
                {
                    "ts": e.ts,
                    "src_ip": e.src_ip,
                    "event_type": e.event_type,
                    "dst_port": e.dst_port,
                    "protocol": e.protocol,
                    "username": e.username,
                    "path": e.path,
                }
            )
            for e in events
        )
        + "\n",
        encoding="utf-8",
    )
    parsed = ingest_file(path, kind="jsonl")
    assert len(parsed) == 30
    assert parse_jsonl_line(path.read_text(encoding="utf-8").splitlines()[0]) is not None
