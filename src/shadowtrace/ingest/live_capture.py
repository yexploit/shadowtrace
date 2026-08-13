"""Live packet capture → behavioral events (defensive monitoring only)."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Callable

from shadowtrace.db.store import Event


def sniff_to_events(
    iface: str | None,
    bpf: str,
    stop_event: threading.Event,
    on_batch: Callable[[list[Event]], None],
    batch_size: int = 20,
    count_limit: int = 0,
) -> None:
    """Sniff packets with Scapy until stop_event is set.

    Requires admin/root on most systems. Read-only observation.
    """
    try:
        from scapy.all import DNS, IP, TCP, UDP, sniff  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "Scapy is required for live capture. Install with: pip install scapy"
        ) from exc

    buffer: list[Event] = []
    seen = 0
    lock = threading.Lock()

    def flush() -> None:
        nonlocal buffer
        with lock:
            if not buffer:
                return
            batch = buffer
            buffer = []
        on_batch(batch)

    def handle(pkt) -> None:  # noqa: ANN001
        nonlocal seen, buffer
        if stop_event.is_set():
            return
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat()
        ev: Event | None = None
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            if flags & 0x02 and not (flags & 0x10):
                ev = Event(
                    ts=ts,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    dst_port=int(tcp.dport),
                    protocol="tcp",
                    event_type="syn_scan",
                    tool_hint="live-capture",
                    raw={"flags": flags},
                )
            elif int(tcp.dport) == 22 or int(tcp.sport) == 22:
                ev = Event(
                    ts=ts,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    dst_port=22,
                    protocol="ssh",
                    event_type="ssh_auth",
                    tool_hint="live-capture",
                    raw={},
                )
            elif int(tcp.dport) in (80, 443, 8080, 8443):
                ev = Event(
                    ts=ts,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    dst_port=int(tcp.dport),
                    protocol="http",
                    event_type="http_request",
                    tool_hint="live-capture",
                    raw={},
                )
        elif pkt.haslayer(UDP) and pkt.haslayer(DNS):
            dns = pkt[DNS]
            qname = None
            try:
                if dns.qd is not None:
                    qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
            except Exception:
                qname = None
            ev = Event(
                ts=ts,
                src_ip=ip.src,
                dst_ip=ip.dst,
                dst_port=53,
                protocol="dns",
                event_type="dns_query",
                path=qname,
                tool_hint="live-capture",
                raw={},
            )
        if not ev:
            return
        with lock:
            buffer.append(ev)
            seen += 1
            ready = len(buffer) >= batch_size
        if ready:
            flush()
        if count_limit and seen >= count_limit:
            stop_event.set()

    # poll stop via short sniff windows so we can exit cleanly on Windows
    while not stop_event.is_set():
        sniff(
            iface=iface,
            filter=bpf,
            prn=handle,
            store=False,
            timeout=1,
            quiet=True,
        )
        flush()
        if count_limit and seen >= count_limit:
            break
        time.sleep(0.01)
