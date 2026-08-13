"""Cluster source IPs into probable same-operator groups."""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.metrics.pairwise import cosine_distances

from shadowtrace.config import Settings, get_settings
from shadowtrace.db.store import Store
from shadowtrace.features.fingerprint import rebuild_all_fingerprints, vector_to_array
from shadowtrace.attribution.similarity import compare_fingerprints, pairwise_all


def _distance_matrix(vectors: list[list[float]]) -> np.ndarray:
    X = np.asarray(vectors, dtype=float)
    if X.size == 0:
        return np.zeros((0, 0))
    norms = np.linalg.norm(X, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    Xn = X / norms
    dist = cosine_distances(Xn)
    np.fill_diagonal(dist, 0.0)
    return dist


class _UnionFind:
    def __init__(self, items: list[str]) -> None:
        self.parent = {x: x for x in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def cluster_fingerprints(
    fingerprints: list[dict[str, Any]],
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    """Cluster primarily by high pairwise composite similarity (union-find).

    Falls back to DBSCAN on cosine distance when no strong edges exist.
    """
    s = settings or get_settings()
    if len(fingerprints) < 2:
        if not fingerprints:
            return []
        return [
            {
                "label": "Cluster #01",
                "confidence": 1.0,
                "members": [fingerprints[0]["src_ip"]],
                "notes": "single observed source",
            }
        ]

    ips = [fp["src_ip"] for fp in fingerprints]
    pairs = pairwise_all(fingerprints, s)
    uf = _UnionFind(ips)
    strong_edges = 0
    for p in pairs:
        if p["score"] >= s.same_actor_threshold:
            uf.union(p["ip_a"], p["ip_b"])
            strong_edges += 1

    groups: dict[str, list[str]] = {}
    if strong_edges > 0:
        for ip in ips:
            root = uf.find(ip)
            groups.setdefault(root, []).append(ip)
    else:
        # Soft fallback: DBSCAN on cosine distance
        vectors = [vector_to_array(fp["vector"]) for fp in fingerprints]
        dist = _distance_matrix(vectors)
        model = DBSCAN(
            eps=s.dbscan_eps,
            min_samples=min(s.dbscan_min_samples, len(ips)),
            metric="precomputed",
        )
        labels = model.fit_predict(dist)
        next_noise = int(max(labels)) + 1 if len(labels) else 0
        for ip, lab in zip(ips, labels):
            lab = int(lab)
            if lab == -1:
                lab = next_noise
                next_noise += 1
            groups.setdefault(str(lab), []).append(ip)

    fp_map = {fp["src_ip"]: fp for fp in fingerprints}
    clusters: list[dict[str, Any]] = []
    ordered = sorted(
        groups.items(),
        key=lambda kv: (0 if len(kv[1]) == 1 else 1, -len(kv[1]), min(kv[1])),
    )
    for idx, (_, members) in enumerate(ordered, start=1):
        conf = 1.0
        note = "singleton"
        if len(members) >= 2:
            scores = []
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    scores.append(
                        compare_fingerprints(fp_map[members[i]], fp_map[members[j]], s)["score"]
                    )
            conf = float(np.mean(scores)) if scores else 0.5
            note = (
                "probable same operator"
                if conf >= s.probable_actor_threshold
                else "weak linkage"
            )
        clusters.append(
            {
                "label": f"Cluster #{idx:02d}",
                "confidence": round(conf, 4),
                "members": sorted(members),
                "notes": note,
            }
        )
    return clusters


def run_attribution_pipeline(store: Store, settings: Settings | None = None) -> dict[str, Any]:
    s = settings or get_settings()
    fps = rebuild_all_fingerprints(store)
    pairs = pairwise_all(fps, s)
    store.replace_attributions(pairs)
    clusters = cluster_fingerprints(fps, s)
    store.replace_clusters(clusters)
    store.set_meta(
        "last_attribution",
        __import__("datetime")
        .datetime.now(__import__("datetime").timezone.utc)
        .isoformat(),
    )
    return {
        "fingerprints": fps,
        "attributions": pairs,
        "clusters": clusters,
        "stats": store.stats(),
    }
