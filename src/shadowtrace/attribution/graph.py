"""NetworkX graph of IPs linked by behavioral similarity."""

from __future__ import annotations

from typing import Any

import networkx as nx

from shadowtrace.config import get_settings


def build_actor_graph(
    attributions: list[dict[str, Any]],
    fingerprints: list[dict[str, Any]] | None = None,
    clusters: list[dict[str, Any]] | None = None,
    min_score: float | None = None,
) -> dict[str, Any]:
    s = get_settings()
    threshold = min_score if min_score is not None else s.probable_actor_threshold
    G = nx.Graph()

    ip_to_cluster: dict[str, str] = {}
    if clusters:
        for c in clusters:
            for ip in c["members"]:
                ip_to_cluster[ip] = c["label"]

    fp_map = {fp["src_ip"]: fp for fp in (fingerprints or [])}

    for fp in fingerprints or []:
        G.add_node(
            fp["src_ip"],
            event_count=fp.get("event_count", 0),
            cluster=ip_to_cluster.get(fp["src_ip"]),
            summary=fp.get("summary", {}),
            labels=fp.get("labels", {}),
        )

    for a in attributions:
        if a["score"] < threshold:
            continue
        for ip in (a["ip_a"], a["ip_b"]):
            if ip not in G:
                G.add_node(ip, cluster=ip_to_cluster.get(ip))
        G.add_edge(
            a["ip_a"],
            a["ip_b"],
            weight=a["score"],
            same_actor=a.get("same_actor", False),
            breakdown=a.get("breakdown", {}),
        )

    # Ensure isolated fingerprint nodes exist
    for ip, fp in fp_map.items():
        if ip not in G:
            G.add_node(ip, event_count=fp.get("event_count", 0))

    nodes = []
    for n, data in G.nodes(data=True):
        nodes.append({"id": n, **{k: v for k, v in data.items() if k != "id"}})

    edges = []
    for u, v, data in G.edges(data=True):
        edges.append({"source": u, "target": v, **data})

    components = [sorted(list(c)) for c in nx.connected_components(G)]
    return {
        "nodes": nodes,
        "edges": edges,
        "components": components,
        "node_count": G.number_of_nodes(),
        "edge_count": G.number_of_edges(),
    }
