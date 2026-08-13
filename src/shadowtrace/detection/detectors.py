"""Lightweight detectors that tag / enrich events for SOC workflows."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def detect_port_scan(events: list[dict[str, Any]], port_threshold: int = 15) -> list[dict[str, Any]]:
    by_ip: dict[str, set[int]] = defaultdict(set)
    for e in events:
        if e.get("dst_port") is not None and e.get("event_type") in (
            "port_scan",
            "syn_scan",
            "connect_scan",
            "conn",
        ):
            by_ip[e["src_ip"]].add(int(e["dst_port"]))
    findings = []
    for ip, ports in by_ip.items():
        if len(ports) >= port_threshold:
            findings.append(
                {
                    "type": "port_scan",
                    "src_ip": ip,
                    "unique_ports": len(ports),
                    "severity": "medium" if len(ports) < 40 else "high",
                    "detail": f"{len(ports)} distinct destination ports probed",
                }
            )
    return findings


def detect_ssh_bruteforce(
    events: list[dict[str, Any]], fail_threshold: int = 10
) -> list[dict[str, Any]]:
    fails: dict[str, int] = defaultdict(int)
    users: dict[str, set[str]] = defaultdict(set)
    for e in events:
        if e.get("event_type") == "ssh_fail":
            fails[e["src_ip"]] += 1
            if e.get("username"):
                users[e["src_ip"]].add(e["username"])
    findings = []
    for ip, count in fails.items():
        if count >= fail_threshold:
            findings.append(
                {
                    "type": "ssh_bruteforce",
                    "src_ip": ip,
                    "failures": count,
                    "usernames": len(users[ip]),
                    "severity": "high",
                    "detail": f"{count} SSH failures across {len(users[ip])} usernames",
                }
            )
    return findings


def detect_reverse_shell_hints(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Heuristic flags for long outbound sessions (SOC investigation aid)."""
    findings = []
    by_ip: dict[str, list[float]] = defaultdict(list)
    for e in events:
        raw = e.get("raw_json") or e.get("raw") or {}
        if isinstance(raw, str):
            import json

            try:
                raw = json.loads(raw)
            except Exception:
                raw = {}
        dur = raw.get("duration") if isinstance(raw, dict) else None
        if dur is not None:
            try:
                by_ip[e["src_ip"]].append(float(dur))
            except Exception:
                pass
        if e.get("event_type") == "reverse_shell_hint":
            findings.append(
                {
                    "type": "reverse_shell_hint",
                    "src_ip": e["src_ip"],
                    "severity": "high",
                    "detail": "explicit reverse-shell hint event",
                }
            )
    for ip, durs in by_ip.items():
        long_ones = [d for d in durs if d >= 120]
        if len(long_ones) >= 2:
            findings.append(
                {
                    "type": "long_session",
                    "src_ip": ip,
                    "severity": "medium",
                    "detail": f"{len(long_ones)} sessions ≥120s (possible C2 / reverse shell)",
                }
            )
    return findings


def run_all_detectors(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    out.extend(detect_port_scan(events))
    out.extend(detect_ssh_bruteforce(events))
    out.extend(detect_reverse_shell_hints(events))
    return out
