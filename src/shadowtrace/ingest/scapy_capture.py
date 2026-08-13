"""Optional Scapy-based PCAP / live summary ingest (defensive analysis only)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from shadowtrace.db.store import Event


def pcap_available() -> bool:
    try:
        import scapy  # noqa: F401

        return True
    except Exception:
        return False


def ingest_pcap(path: Path, max_packets: int = 5000) -> list[Event]:
    """Summarize TCP SYNs / UDP DNS from a PCAP into behavioral events.

    Requires scapy. Does not perform attacks — read-only traffic analysis.
    """
    if not pcap_available():
        raise RuntimeError(
            "Scapy is not installed. Install with: pip install scapy"
        )

    from scapy.all import DNS, IP, TCP, UDP, rdpcap  # type: ignore

    path = Path(path)
    packets = rdpcap(str(path), count=max_packets)
    events: list[Event] = []

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat()
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            if flags & 0x02 and not (flags & 0x10):
                events.append(
                    Event(
                        ts=ts,
                        src_ip=ip.src,
                        dst_ip=ip.dst,
                        dst_port=int(tcp.dport),
                        protocol="tcp",
                        event_type="syn_scan",
                        tool_hint="pcap",
                        raw={"flags": flags},
                    )
                )
            elif int(tcp.dport) == 22 or int(tcp.sport) == 22:
                events.append(
                    Event(
                        ts=ts,
                        src_ip=ip.src,
                        dst_ip=ip.dst,
                        dst_port=22,
                        protocol="ssh",
                        event_type="ssh_auth",
                        tool_hint="pcap",
                        raw={},
                    )
                )
        elif pkt.haslayer(UDP) and pkt.haslayer(DNS):
            dns = pkt[DNS]
            qname = None
            try:
                if dns.qd is not None:
                    qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
            except Exception:
                qname = None
            events.append(
                Event(
                    ts=ts,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    dst_port=53,
                    protocol="dns",
                    event_type="dns_query",
                    path=qname,
                    tool_hint="pcap",
                    raw={},
                )
            )
    return events
