"""Parse SSH auth logs, HTTP access logs, and generic JSONL event streams."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from shadowtrace.db.store import Event


SSH_FAIL_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
SSH_ACCEPT_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)"
)
# ISO-ish auth patterns
SSH_ISO_FAIL = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?).*Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
SSH_ISO_ACCEPT = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?).*Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+)"
)

COMBINED_LOG = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]+" (?P<status>\d+)'
)


def _year_fix_ts(mon_day_time: str, year: int | None = None) -> str:
    year = year or datetime.now(timezone.utc).year
    # e.g. "Aug 13 20:01:02"
    dt = datetime.strptime(f"{year} {mon_day_time}", "%Y %b %d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc).isoformat()


def parse_ssh_auth_line(line: str) -> Event | None:
    line = line.strip()
    if not line:
        return None
    for pattern, etype in (
        (SSH_ISO_FAIL, "ssh_fail"),
        (SSH_ISO_ACCEPT, "ssh_success"),
        (SSH_FAIL_RE, "ssh_fail"),
        (SSH_ACCEPT_RE, "ssh_success"),
    ):
        m = pattern.search(line)
        if not m:
            continue
        ts = m.group("ts")
        if "T" in ts or "-" in ts[:5]:
            iso = ts.replace(" ", "T")
            if not iso.endswith("Z") and "+" not in iso:
                iso += "Z"
        else:
            iso = _year_fix_ts(ts)
        return Event(
            ts=iso,
            src_ip=m.group("ip"),
            event_type=etype,
            dst_port=22,
            protocol="ssh",
            username=m.group("user"),
            tool_hint="ssh",
            raw={"line": line},
        )
    return None


def parse_http_access_line(line: str) -> Event | None:
    m = COMBINED_LOG.search(line.strip())
    if not m:
        return None
    # 13/Aug/2026:20:01:02 +0000
    ts_raw = m.group("ts")
    try:
        dt = datetime.strptime(ts_raw.split()[0], "%d/%b/%Y:%H:%M:%S")
        iso = dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        iso = datetime.now(timezone.utc).isoformat()
    return Event(
        ts=iso,
        src_ip=m.group("ip"),
        event_type="http_request",
        dst_port=80,
        protocol="http",
        path=m.group("path"),
        tool_hint="http",
        raw={"method": m.group("method"), "status": m.group("status"), "line": line},
    )


def parse_jsonl_line(line: str) -> Event | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    return Event(
        ts=str(obj.get("ts") or datetime.now(timezone.utc).isoformat()),
        src_ip=str(obj["src_ip"]),
        event_type=str(obj.get("event_type") or obj.get("type") or "unknown"),
        dst_ip=obj.get("dst_ip"),
        dst_port=obj.get("dst_port"),
        protocol=obj.get("protocol"),
        username=obj.get("username"),
        path=obj.get("path"),
        tool_hint=obj.get("tool_hint"),
        raw=obj,
        session_id=obj.get("session_id"),
    )


def ingest_file(path: Path, kind: str = "auto") -> list[Event]:
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    events: list[Event] = []
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        ev: Event | None = None
        if kind == "jsonl" or (kind == "auto" and line.strip().startswith("{")):
            ev = parse_jsonl_line(line)
        elif kind == "ssh" or (kind == "auto" and "sshd" in line):
            ev = parse_ssh_auth_line(line)
        elif kind == "http" or (kind == "auto" and '"' in line and "[" in line):
            ev = parse_http_access_line(line)
        else:
            ev = parse_jsonl_line(line) or parse_ssh_auth_line(line) or parse_http_access_line(line)
        if ev:
            events.append(ev)
    return events


def ingest_paths(paths: Iterable[Path], kind: str = "auto") -> list[Event]:
    out: list[Event] = []
    for p in paths:
        out.extend(ingest_file(Path(p), kind=kind))
    return out
