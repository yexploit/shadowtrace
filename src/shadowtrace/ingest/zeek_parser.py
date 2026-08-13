"""Parse Zeek TSV log exports (conn.log, ssh.log, http.log, dns.log)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shadowtrace.db.store import Event


def _zeek_ts(val: str) -> str:
    try:
        # Zeek epoch float
        return datetime.fromtimestamp(float(val), tz=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def parse_zeek_tsv(path: Path) -> list[Event]:
    """Parse a Zeek log with #fields header into SHADOWTRACE events."""
    path = Path(path)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    fields: list[str] = []
    events: list[Event] = []
    log_type = path.name.split(".")[0].lower()  # conn, ssh, http, dns

    for line in lines:
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not line.strip():
            continue
        if not fields:
            continue
        cols = line.split("\t")
        row = {fields[i]: cols[i] if i < len(cols) else "-" for i in range(len(fields))}
        ev = _row_to_event(row, log_type)
        if ev:
            events.append(ev)
    return events


def _safe_int(v: str | None) -> int | None:
    if v is None or v in ("-", ""):
        return None
    try:
        return int(float(v))
    except Exception:
        return None


def _row_to_event(row: dict[str, str], log_type: str) -> Event | None:
    ts = _zeek_ts(row.get("ts", "0"))
    src = row.get("id.orig_h") or row.get("orig_h") or row.get("src_ip")
    if not src or src == "-":
        return None
    dst = row.get("id.resp_h") or row.get("resp_h") or row.get("dst_ip")
    dport = _safe_int(row.get("id.resp_p") or row.get("resp_p") or row.get("dst_port"))

    if log_type == "ssh" or "auth_success" in row or "client" in row and "server" in row:
        success = row.get("auth_success", "-")
        etype = "ssh_success" if success == "T" else "ssh_fail" if success == "F" else "ssh_auth"
        return Event(
            ts=ts,
            src_ip=src,
            dst_ip=dst,
            dst_port=dport or 22,
            protocol="ssh",
            event_type=etype,
            username=row.get("user") if row.get("user") not in (None, "-") else None,
            tool_hint=row.get("client") if row.get("client") not in (None, "-") else "ssh",
            raw=row,
        )

    if log_type == "http" or "method" in row and "uri" in row:
        return Event(
            ts=ts,
            src_ip=src,
            dst_ip=dst,
            dst_port=dport or 80,
            protocol="http",
            event_type="http_request",
            path=row.get("uri") if row.get("uri") != "-" else None,
            tool_hint="http",
            raw=row,
        )

    if log_type == "dns" or "query" in row:
        return Event(
            ts=ts,
            src_ip=src,
            dst_ip=dst,
            dst_port=dport or 53,
            protocol="dns",
            event_type="dns_query",
            path=row.get("query") if row.get("query") != "-" else None,
            tool_hint="dns",
            raw=row,
        )

    # conn.log — treat scanning-like short connections
    duration = row.get("duration", "-")
    try:
        dur_f = float(duration) if duration not in ("-", "") else None
    except Exception:
        dur_f = None
    proto = row.get("proto", "tcp")
    service = row.get("service", "-")
    etype = "port_scan" if dur_f is not None and dur_f < 0.2 else "conn"
    return Event(
        ts=ts,
        src_ip=src,
        dst_ip=dst,
        dst_port=dport,
        protocol=proto,
        event_type=etype,
        tool_hint=service if service != "-" else proto,
        raw={**row, "duration": dur_f},
    )


def ingest_zeek_dir(directory: Path) -> list[Event]:
    directory = Path(directory)
    events: list[Event] = []
    for name in ("ssh.log", "http.log", "dns.log", "conn.log"):
        p = directory / name
        if p.exists():
            events.extend(parse_zeek_tsv(p))
    # also pick up any *.log
    for p in sorted(directory.glob("*.log")):
        if p.name in ("ssh.log", "http.log", "dns.log", "conn.log"):
            continue
        events.extend(parse_zeek_tsv(p))
    return events
