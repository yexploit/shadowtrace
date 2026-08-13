"""Behavioral feature extraction from raw security events."""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any


FEATURE_KEYS = [
    "scan_interval_mean",
    "scan_interval_cv",
    "port_sequential_score",
    "port_diversity",
    "username_diversity",
    "username_entropy",
    "ssh_burst_score",
    "ssh_fail_ratio",
    "http_sequence_score",
    "http_path_diversity",
    "dns_periodicity",
    "session_duration_mean",
    "protocol_mix_ssh",
    "protocol_mix_http",
    "protocol_mix_dns",
    "protocol_mix_scan",
    "tool_consistency",
    "event_rate",
]


def _parse_ts(ts: str) -> float:
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts).timestamp()
    except Exception:
        try:
            return float(ts)
        except Exception:
            return 0.0


def _entropy(values: list[str]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    n = len(values)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    # normalize by max entropy for |alphabet|
    k = len(counts)
    if k <= 1:
        return 0.0
    return min(1.0, ent / math.log2(k))


def _cv(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = statistics.mean(values)
    if mean == 0:
        return 0.0
    return min(3.0, statistics.pstdev(values) / abs(mean)) / 3.0


def _sequential_port_score(ports: list[int]) -> float:
    if len(ports) < 3:
        return 0.0
    diffs = [ports[i + 1] - ports[i] for i in range(len(ports) - 1)]
    # sequential if many diffs are +1 or small positive constant
    ones = sum(1 for d in diffs if d == 1)
    small = sum(1 for d in diffs if 1 <= d <= 5)
    return max(ones / len(diffs), 0.7 * small / len(diffs))


def _burst_score(timestamps: list[float], window: float = 5.0) -> float:
    if len(timestamps) < 3:
        return 0.0
    ts = sorted(timestamps)
    max_in_window = 1
    j = 0
    for i in range(len(ts)):
        while ts[i] - ts[j] > window:
            j += 1
        max_in_window = max(max_in_window, i - j + 1)
    # normalize: 20+ events in 5s => 1.0
    return min(1.0, max_in_window / 20.0)


def _periodicity_score(timestamps: list[float]) -> float:
    if len(timestamps) < 4:
        return 0.0
    ts = sorted(timestamps)
    intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    intervals = [x for x in intervals if x > 0]
    if len(intervals) < 3:
        return 0.0
    # low CV => periodic
    return max(0.0, 1.0 - _cv(intervals) * 1.5)


def _http_sequence_score(paths: list[str]) -> float:
    """Reward repeating ordered subsequences (scanner-like path order)."""
    if len(paths) < 4:
        return 0.0
    # bigrams
    bigrams = list(zip(paths, paths[1:]))
    counts = Counter(bigrams)
    repeats = sum(c for c in counts.values() if c > 1)
    return min(1.0, repeats / max(1, len(bigrams) * 0.4))


def _raw_dict(e: dict[str, Any]) -> dict[str, Any]:
    raw = e.get("raw_json") if "raw_json" in e else e.get("raw")
    if isinstance(raw, str):
        import json

        try:
            return json.loads(raw)
        except Exception:
            return {}
    return raw if isinstance(raw, dict) else {}


def extract_features(events: list[dict[str, Any]]) -> dict[str, float]:
    """Build a normalized feature vector for one source IP's events."""
    if not events:
        return {k: 0.0 for k in FEATURE_KEYS}

    timestamps = [_parse_ts(e["ts"]) for e in events]
    timestamps = [t for t in timestamps if t > 0]

    scan_events = [
        e
        for e in events
        if e.get("event_type") in ("port_scan", "syn_scan", "connect_scan")
    ]
    scan_ts = sorted(_parse_ts(e["ts"]) for e in scan_events if _parse_ts(e["ts"]) > 0)
    intervals: list[float] = []
    if len(scan_ts) >= 2:
        intervals = [scan_ts[i + 1] - scan_ts[i] for i in range(len(scan_ts) - 1) if scan_ts[i + 1] > scan_ts[i]]
    elif len(timestamps) >= 2:
        st = sorted(timestamps)
        intervals = [st[i + 1] - st[i] for i in range(len(st) - 1) if st[i + 1] > st[i]]

    ports = [
        int(e["dst_port"])
        for e in (scan_events or events)
        if e.get("dst_port") is not None
    ]
    usernames = [e["username"] for e in events if e.get("username")]
    paths = [e["path"] for e in events if e.get("path") and e.get("event_type", "").startswith("http")]
    tools = [e["tool_hint"] for e in events if e.get("tool_hint")]
    types = [e["event_type"] for e in events]
    n = len(events)

    ssh_events = [e for e in events if e["event_type"] in ("ssh_auth", "ssh_fail", "ssh_success")]
    ssh_fails = sum(1 for e in ssh_events if e["event_type"] == "ssh_fail")
    ssh_ts = [_parse_ts(e["ts"]) for e in ssh_events]

    dns_ts = [_parse_ts(e["ts"]) for e in events if e["event_type"] == "dns_query"]

    durations: list[float] = []
    for e in events:
        raw = _raw_dict(e)
        if "duration" in raw:
            try:
                durations.append(float(raw["duration"]))
            except Exception:
                pass

    scan_interval_mean = statistics.mean(intervals) if intervals else 0.0
    scan_interval_norm = 1.0 / (1.0 + scan_interval_mean) if intervals else 0.0

    span = (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 1.0
    event_rate = min(1.0, (n / max(span, 1.0)) / 5.0)

    unique_users = len(set(usernames))
    username_div = min(1.0, unique_users / 20.0) if usernames else 0.0

    unique_ports = len(set(ports))
    port_div = min(1.0, unique_ports / 50.0) if ports else 0.0

    tool_consistency = 0.0
    if tools:
        top = Counter(tools).most_common(1)[0][1]
        tool_consistency = top / len(tools)

    vector = {
        "scan_interval_mean": round(scan_interval_norm, 4),
        "scan_interval_cv": round(1.0 - _cv(intervals), 4) if intervals else 0.0,
        "port_sequential_score": round(_sequential_port_score(ports), 4),
        "port_diversity": round(port_div, 4),
        "username_diversity": round(username_div, 4),
        "username_entropy": round(_entropy(usernames), 4),
        "ssh_burst_score": round(_burst_score(ssh_ts, window=3.0), 4),
        "ssh_fail_ratio": round(ssh_fails / max(1, len(ssh_events)), 4) if ssh_events else 0.0,
        "http_sequence_score": round(_http_sequence_score(paths), 4),
        "http_path_diversity": round(min(1.0, len(set(paths)) / 30.0), 4) if paths else 0.0,
        "dns_periodicity": round(_periodicity_score(dns_ts), 4),
        "session_duration_mean": round(
            min(1.0, 1.0 / (1.0 + (statistics.mean(durations) if durations else 10.0))),
            4,
        ),
        "protocol_mix_ssh": round(sum(1 for t in types if t.startswith("ssh")) / n, 4),
        "protocol_mix_http": round(sum(1 for t in types if t.startswith("http")) / n, 4),
        "protocol_mix_dns": round(sum(1 for t in types if t.startswith("dns")) / n, 4),
        "protocol_mix_scan": round(
            sum(1 for t in types if t in ("port_scan", "syn_scan", "connect_scan")) / n, 4
        ),
        "tool_consistency": round(tool_consistency, 4),
        "event_rate": round(event_rate, 4),
    }
    return vector


def human_labels(vector: dict[str, float], events: list[dict[str, Any]]) -> dict[str, str]:
    """Readable fingerprint labels matching the SHADOWTRACE concept card."""
    scan_events = [
        e
        for e in events
        if e.get("event_type") in ("port_scan", "syn_scan", "connect_scan")
    ]
    scan_ts = sorted(_parse_ts(e["ts"]) for e in scan_events if _parse_ts(e["ts"]) > 0)
    intervals: list[float] = []
    if len(scan_ts) >= 2:
        intervals = [scan_ts[i + 1] - scan_ts[i] for i in range(len(scan_ts) - 1)]
    mean_iv = statistics.mean(intervals) if intervals else None

    ports = [int(e["dst_port"]) for e in scan_events if e.get("dst_port") is not None]
    seq = vector.get("port_sequential_score", 0)

    labels = {
        "scan_interval": f"{mean_iv:.1f}s" if mean_iv is not None else "n/a",
        "ports": "sequential" if seq >= 0.55 else ("mixed" if seq >= 0.25 else "random"),
        "username_diversity": (
            "high"
            if vector.get("username_diversity", 0) >= 0.45
            else ("medium" if vector.get("username_diversity", 0) >= 0.2 else "low")
        ),
        "ssh_attempts": (
            "bursty"
            if vector.get("ssh_burst_score", 0) >= 0.4
            else ("steady" if vector.get("ssh_burst_score", 0) >= 0.15 else "sparse")
        ),
        "http_requests": (
            "ordered"
            if vector.get("http_sequence_score", 0) >= 0.4
            else "varied"
        ),
        "dns_behavior": (
            "periodic"
            if vector.get("dns_periodicity", 0) >= 0.55
            else "irregular"
        ),
        "session_duration": (
            "short"
            if vector.get("session_duration_mean", 0) >= 0.55
            else "long"
        ),
    }
    return labels


def summary_metrics(vector: dict[str, float]) -> dict[str, float]:
    """High-level fingerprint dimensions shown in the concept UI."""
    return {
        "temporal_signature": round(
            0.5 * vector.get("scan_interval_cv", 0)
            + 0.3 * vector.get("scan_interval_mean", 0)
            + 0.2 * vector.get("dns_periodicity", 0),
            4,
        ),
        "enumeration_pattern": round(
            0.55 * vector.get("port_sequential_score", 0)
            + 0.25 * vector.get("port_diversity", 0)
            + 0.20 * vector.get("protocol_mix_scan", 0),
            4,
        ),
        "protocol_sequence": round(
            0.35 * vector.get("protocol_mix_ssh", 0)
            + 0.25 * vector.get("protocol_mix_http", 0)
            + 0.20 * vector.get("http_sequence_score", 0)
            + 0.20 * vector.get("tool_consistency", 0),
            4,
        ),
        "username_behavior": round(
            0.55 * vector.get("username_diversity", 0)
            + 0.30 * vector.get("username_entropy", 0)
            + 0.15 * vector.get("ssh_fail_ratio", 0),
            4,
        ),
    }
