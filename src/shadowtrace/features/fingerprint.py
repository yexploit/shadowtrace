"""Build and persist behavioral fingerprints per source IP."""

from __future__ import annotations

from typing import Any

from shadowtrace.db.store import Store
from shadowtrace.features.extractor import (
    FEATURE_KEYS,
    extract_features,
    human_labels,
    summary_metrics,
)


def vector_to_array(vector: dict[str, float]) -> list[float]:
    return [float(vector.get(k, 0.0)) for k in FEATURE_KEYS]


def build_fingerprint_for_ip(store: Store, src_ip: str) -> dict[str, Any]:
    events = store.list_events(src_ip=src_ip, limit=50000)
    vector = extract_features(events)
    labels = human_labels(vector, events)
    summary = summary_metrics(vector)
    store.upsert_fingerprint(
        src_ip=src_ip,
        vector=vector,
        labels=labels,
        summary=summary,
        event_count=len(events),
    )
    return {
        "src_ip": src_ip,
        "event_count": len(events),
        "vector": vector,
        "labels": labels,
        "summary": summary,
    }


def rebuild_all_fingerprints(store: Store) -> list[dict[str, Any]]:
    ips = store.distinct_ips()
    return [build_fingerprint_for_ip(store, ip) for ip in ips]
