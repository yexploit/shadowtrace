"""Synthetic event generators for unit tests only (not a product demo)."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from shadowtrace.db.store import Event

HTTP_SEQ_A = [
    "/",
    "/admin",
    "/wp-login.php",
    "/.env",
    "/api/v1/health",
    "/robots.txt",
    "/admin",
    "/wp-login.php",
]

USERNAMES_A = [
    "root", "admin", "ubuntu", "test", "oracle", "postgres", "deploy", "git",
    "nginx", "ftp", "user", "pi", "centos", "mysql", "backup", "support",
    "guest", "webmaster", "apache", "dev",
]
USERNAMES_B = ["admin", "root", "user"]


def _ts(base: datetime, seconds: float) -> str:
    return (base + timedelta(seconds=seconds)).isoformat()


def _persona_a(src_ip: str, base: datetime, seed: int) -> list[Event]:
    rng = random.Random(seed)
    events: list[Event] = []
    t = 0.0
    for i in range(40):
        events.append(
            Event(
                ts=_ts(base, t),
                src_ip=src_ip,
                dst_ip="10.0.0.50",
                dst_port=20 + i,
                protocol="tcp",
                event_type="port_scan",
                tool_hint="nmap-like",
                raw={"duration": 0.05},
            )
        )
        t += 0.78 + rng.uniform(-0.05, 0.05)
    burst_t = t + 2
    for i, user in enumerate(USERNAMES_A):
        if i > 0 and i % 8 == 0:
            burst_t += 10
        else:
            burst_t += rng.uniform(0.02, 0.12)
        events.append(
            Event(
                ts=_ts(base, burst_t),
                src_ip=src_ip,
                dst_ip="10.0.0.50",
                dst_port=22,
                protocol="ssh",
                event_type="ssh_fail",
                username=user,
                tool_hint="hydra-like",
                raw={"duration": 0.35},
            )
        )
    http_t = burst_t + 3
    for _ in range(2):
        for path in HTTP_SEQ_A:
            events.append(
                Event(
                    ts=_ts(base, http_t),
                    src_ip=src_ip,
                    dst_ip="10.0.0.50",
                    dst_port=80,
                    protocol="http",
                    event_type="http_request",
                    path=path,
                    tool_hint="curl-seq",
                    raw={"duration": 0.2},
                )
            )
            http_t += 0.9
    for i in range(12):
        events.append(
            Event(
                ts=_ts(base, t + i * 12.0),
                src_ip=src_ip,
                dst_ip="8.8.8.8",
                dst_port=53,
                protocol="dns",
                event_type="dns_query",
                path=f"probe-{i}.evil.example",
                tool_hint="dns",
                raw={"duration": 0.01},
            )
        )
    return events


def _persona_b(src_ip: str, base: datetime, seed: int) -> list[Event]:
    rng = random.Random(seed)
    events: list[Event] = []
    t = 0.0
    ports = list(range(1000, 1100))
    rng.shuffle(ports)
    for port in ports[:35]:
        events.append(
            Event(
                ts=_ts(base, t),
                src_ip=src_ip,
                dst_ip="10.0.0.50",
                dst_port=port,
                protocol="tcp",
                event_type="port_scan",
                tool_hint="masscan-like",
                raw={"duration": 12.0},
            )
        )
        t += rng.uniform(4.0, 9.0)
    for i in range(6):
        events.append(
            Event(
                ts=_ts(base, t + i * 18),
                src_ip=src_ip,
                dst_ip="10.0.0.50",
                dst_port=22,
                protocol="ssh",
                event_type="ssh_fail",
                username=rng.choice(USERNAMES_B),
                tool_hint="manual",
                raw={"duration": 25.0},
            )
        )
    for i in range(8):
        events.append(
            Event(
                ts=_ts(base, t + 120 + i * 11),
                src_ip=src_ip,
                dst_ip="10.0.0.50",
                dst_port=443,
                protocol="http",
                event_type="http_request",
                path=f"/p{rng.randint(1000,9999)}",
                tool_hint="browser",
                raw={"duration": 8.0},
            )
        )
    dns_t = t
    for i in range(8):
        dns_t += rng.uniform(1.0, 40.0)
        events.append(
            Event(
                ts=_ts(base, dns_t),
                src_ip=src_ip,
                dst_ip="1.1.1.1",
                dst_port=53,
                protocol="dns",
                event_type="dns_query",
                path=f"rand{rng.randint(1,9999)}.net",
                tool_hint="dns",
                raw={"duration": 0.5},
            )
        )
    return events


def make_multi_actor_events() -> list[Event]:
    base = datetime(2026, 8, 13, 18, 0, 0, tzinfo=timezone.utc)
    events: list[Event] = []
    events.extend(_persona_a("10.0.0.21", base, 42))
    events.extend(_persona_a("10.0.0.73", base + timedelta(minutes=25), 43))
    events.extend(_persona_a("185.220.101.44", base + timedelta(minutes=55), 44))
    events.extend(_persona_b("203.0.113.88", base + timedelta(minutes=10), 99))
    events.sort(key=lambda e: e.ts)
    return events
