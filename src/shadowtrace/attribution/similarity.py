"""Pairwise behavioral similarity & same-actor scoring."""

from __future__ import annotations

from typing import Any

import numpy as np

from shadowtrace.config import Settings, get_settings
from shadowtrace.features.extractor import FEATURE_KEYS
from shadowtrace.features.fingerprint import vector_to_array


def cosine_similarity(a: list[float], b: list[float]) -> float:
    va = np.asarray(a, dtype=float)
    vb = np.asarray(b, dtype=float)
    na = np.linalg.norm(va)
    nb = np.linalg.norm(vb)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(va, vb) / (na * nb))


def dimension_breakdown(
    summary_a: dict[str, float],
    summary_b: dict[str, float],
    vector_a: dict[str, float],
    vector_b: dict[str, float],
) -> dict[str, float]:
    def sim(x: float, y: float) -> float:
        return max(0.0, 1.0 - abs(x - y))

    return {
        "temporal_signature": round(
            sim(summary_a.get("temporal_signature", 0), summary_b.get("temporal_signature", 0)),
            4,
        ),
        "enumeration_pattern": round(
            sim(summary_a.get("enumeration_pattern", 0), summary_b.get("enumeration_pattern", 0)),
            4,
        ),
        "protocol_sequence": round(
            sim(summary_a.get("protocol_sequence", 0), summary_b.get("protocol_sequence", 0)),
            4,
        ),
        "username_behavior": round(
            sim(summary_a.get("username_behavior", 0), summary_b.get("username_behavior", 0)),
            4,
        ),
        "burst_alignment": round(
            sim(vector_a.get("ssh_burst_score", 0), vector_b.get("ssh_burst_score", 0)),
            4,
        ),
        "http_sequence": round(
            sim(vector_a.get("http_sequence_score", 0), vector_b.get("http_sequence_score", 0)),
            4,
        ),
        "dns_periodicity": round(
            sim(vector_a.get("dns_periodicity", 0), vector_b.get("dns_periodicity", 0)),
            4,
        ),
    }


def composite_score(breakdown: dict[str, float], settings: Settings | None = None) -> float:
    s = settings or get_settings()
    score = (
        s.weight_temporal * breakdown["temporal_signature"]
        + s.weight_enumeration * breakdown["enumeration_pattern"]
        + s.weight_protocol * breakdown["protocol_sequence"]
        + s.weight_username * breakdown["username_behavior"]
        + s.weight_burst * breakdown["burst_alignment"]
        + s.weight_http_seq * breakdown["http_sequence"]
        + s.weight_dns * breakdown["dns_periodicity"]
    )
    return round(float(score), 4)


def compare_fingerprints(
    fp_a: dict[str, Any],
    fp_b: dict[str, Any],
    settings: Settings | None = None,
) -> dict[str, Any]:
    s = settings or get_settings()
    vec_a = fp_a["vector"]
    vec_b = fp_b["vector"]
    cos = cosine_similarity(vector_to_array(vec_a), vector_to_array(vec_b))
    breakdown = dimension_breakdown(fp_a["summary"], fp_b["summary"], vec_a, vec_b)
    # blend weighted dimensions with cosine on full vector
    weighted = composite_score(breakdown, s)
    score = round(0.70 * weighted + 0.30 * cos, 4)
    same = score >= s.same_actor_threshold
    probable = score >= s.probable_actor_threshold
    return {
        "ip_a": fp_a["src_ip"],
        "ip_b": fp_b["src_ip"],
        "score": score,
        "cosine": round(cos, 4),
        "breakdown": breakdown,
        "same_actor": same,
        "probable_same_actor": probable,
        "likely_same_actor_pct": int(round(score * 100)),
    }


def pairwise_all(
    fingerprints: list[dict[str, Any]],
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for i in range(len(fingerprints)):
        for j in range(i + 1, len(fingerprints)):
            results.append(compare_fingerprints(fingerprints[i], fingerprints[j], settings))
    results.sort(key=lambda x: x["score"], reverse=True)
    return results
