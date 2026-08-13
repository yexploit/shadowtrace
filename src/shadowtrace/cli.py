"""SHADOWTRACE CLI - real-time monitor, ingest, attribute, GUI."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import List, Optional

import typer
from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from shadowtrace import __version__
from shadowtrace.config import ensure_dirs, get_settings
from shadowtrace.db.store import Store

app = typer.Typer(
    name="shadowtrace",
    help="SHADOWTRACE - real-time attacker behavioral fingerprinting (CLI + GUI).",
    no_args_is_help=True,
    add_completion=False,
)
console = Console(safe_box=True)


def _store() -> Store:
    ensure_dirs()
    return Store(get_settings().db_path)


@app.callback()
def main() -> None:
    """Live behavioral attribution for hostile activity across changing IPs."""
    pass


@app.command("version")
def version_cmd() -> None:
    """Show version."""
    console.print(f"SHADOWTRACE v{__version__}")


@app.command("init-db")
def init_db(reset: bool = typer.Option(False, "--reset", help="Wipe existing data")) -> None:
    """Initialize the SQLite database."""
    store = _store()
    if reset:
        store.clear_all()
        console.print("[yellow]Database reset.[/yellow]")
    console.print(f"[green]OK[/green] database at {get_settings().db_path}")


@app.command("monitor")
def monitor_cmd(
    path: Optional[List[Path]] = typer.Option(
        None,
        "--path",
        "-p",
        help="Log file to follow (repeatable). SSH/HTTP/JSONL auto-detected.",
    ),
    kind: str = typer.Option("auto", "--kind", "-k", help="auto|jsonl|ssh|http"),
    iface: Optional[str] = typer.Option(
        None,
        "--iface",
        "-i",
        help="Network interface for live capture (needs admin/root + scapy).",
    ),
    capture: bool = typer.Option(
        False,
        "--capture",
        help="Enable live packet capture (Scapy).",
    ),
    bpf: Optional[str] = typer.Option(None, "--bpf", help="BPF filter for capture"),
    udp_port: Optional[int] = typer.Option(
        None,
        "--udp-port",
        help="Listen for JSONL/syslog-like UDP event lines (default off).",
    ),
    udp_host: str = typer.Option("0.0.0.0", "--udp-host"),
    serve: bool = typer.Option(False, "--serve", help="Also start GUI/API"),
    host: Optional[str] = typer.Option(None, "--host"),
    port: Optional[int] = typer.Option(None, "--port"),
) -> None:
    """Start real-time monitoring: tail logs, optional live capture / UDP stream."""
    from shadowtrace.realtime.engine import get_engine

    settings = get_settings()
    engine = get_engine()
    paths = list(path or [])
    if not paths and not capture and udp_port is None:
        console.print(
            "[red]Provide at least one source:[/red] --path LOG, --capture, or --udp-port N"
        )
        raise typer.Exit(2)

    engine.start(
        watch_paths=paths,
        kind=kind,
        iface=iface,
        bpf=bpf or settings.default_bpf,
        udp_host=udp_host if udp_port else None,
        udp_port=udp_port,
        enable_capture=capture or iface is not None,
    )

    console.print(
        Panel.fit(
            "[bold]SHADOWTRACE live monitor[/bold]\n"
            f"watching: {', '.join(str(p) for p in paths) or '(none)'}\n"
            f"capture: {'on' if (capture or iface) else 'off'}"
            + (f" ({iface or 'default'})" if (capture or iface) else "")
            + "\n"
            f"udp: {f'{udp_host}:{udp_port}' if udp_port else 'off'}\n"
            "Ctrl+C to stop",
            border_style="cyan",
        )
    )

    if serve:
        import threading

        def _serve() -> None:
            serve_cmd(host=host, port=port, with_engine=False)

        threading.Thread(target=_serve, daemon=True).start()
        h = host or settings.api_host
        p = port or settings.api_port
        console.print(f"GUI: http://{h}:{p}/")

    try:
        with Live(console=console, refresh_per_second=2) as live:
            while True:
                snap = engine.snapshot()
                table = Table(box=box.SIMPLE, expand=False)
                table.add_column("metric")
                table.add_column("value")
                table.add_row("mode", snap["mode"])
                table.add_row("events (session)", str(snap["events_total"]))
                table.add_row("events / min", str(snap["events_last_minute"]))
                table.add_row("db events", str(snap["db"].get("events", 0)))
                table.add_row("fingerprints", str(snap["db"].get("fingerprints", 0)))
                table.add_row("clusters", str(snap["db"].get("clusters", 0)))
                table.add_row("last event", snap["last_event_at"] or "-")
                table.add_row("last attribute", snap["last_attribution_at"] or "-")
                if snap["recent_events"]:
                    last = snap["recent_events"][-1]
                    table.add_row(
                        "latest",
                        f"{last.get('src_ip')} {last.get('event_type')} {last.get('ts', '')[:19]}",
                    )
                live.update(table)
                time.sleep(0.5)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping...[/yellow]")
    finally:
        engine.stop()
        console.print("[green]Monitor stopped. Final attribution flushed.[/green]")


@app.command("watch")
def watch_cmd(
    path: Path = typer.Argument(..., help="Log file to follow"),
    kind: str = typer.Option("auto", "--kind", "-k"),
    serve: bool = typer.Option(False, "--serve"),
) -> None:
    """Follow a single log file in real time (alias for monitor -p)."""
    monitor_cmd(path=[path], kind=kind, serve=serve)


@app.command("capture")
def capture_cmd(
    iface: Optional[str] = typer.Option(None, "--iface", "-i"),
    bpf: Optional[str] = typer.Option(None, "--bpf"),
    serve: bool = typer.Option(False, "--serve"),
) -> None:
    """Live packet capture to behavioral events (requires admin/root + scapy)."""
    monitor_cmd(path=None, iface=iface, capture=True, bpf=bpf, serve=serve)


@app.command("ingest")
def ingest_cmd(
    path: Path = typer.Argument(..., help="File or directory to ingest"),
    kind: str = typer.Option(
        "auto",
        "--kind",
        "-k",
        help="auto|jsonl|ssh|http|zeek|pcap",
    ),
    attribute_after: bool = typer.Option(
        True, "--attribute/--no-attribute", help="Run attribution after ingest"
    ),
) -> None:
    """Batch-ingest historical logs, Zeek exports, or PCAP summaries."""
    from shadowtrace.realtime.engine import get_engine

    store = _store()
    path = Path(path)
    events = []
    if kind == "zeek" or (path.is_dir() and kind == "auto" and any(path.glob("*.log"))):
        from shadowtrace.ingest.zeek_parser import ingest_zeek_dir, parse_zeek_tsv

        if path.is_dir():
            events = ingest_zeek_dir(path)
        else:
            events = parse_zeek_tsv(path)
    elif kind == "pcap":
        from shadowtrace.ingest.scapy_capture import ingest_pcap

        events = ingest_pcap(path)
    else:
        from shadowtrace.ingest.logs import ingest_file, ingest_paths

        if path.is_dir():
            files = list(path.glob("*.jsonl")) + list(path.glob("*.log")) + list(path.glob("*.txt"))
            events = ingest_paths(files, kind=kind)
        else:
            events = ingest_file(path, kind=kind)

    engine = get_engine()
    n = engine.ingest_events(events, source="batch")
    engine.flush()
    console.print(f"[green]Ingested {n} events[/green] from {path}")
    if attribute_after and n:
        result = engine.maybe_attribute(force=True)
        if result:
            multi = [c for c in result["clusters"] if len(c["members"]) > 1]
            console.print(
                f"Attribution complete - {len(result['clusters'])} clusters, "
                f"{len(multi)} multi-IP operator groups"
            )


@app.command("fingerprint")
def fingerprint_cmd(
    ip: Optional[str] = typer.Option(None, "--ip", help="Single source IP"),
) -> None:
    """Build behavioral fingerprints from stored events."""
    from shadowtrace.features.fingerprint import build_fingerprint_for_ip, rebuild_all_fingerprints

    store = _store()
    if ip:
        fps = [build_fingerprint_for_ip(store, ip)]
    else:
        fps = rebuild_all_fingerprints(store)

    table = Table(title="Attacker Fingerprints", box=box.SIMPLE_HEAVY)
    table.add_column("Source IP")
    table.add_column("Events", justify="right")
    table.add_column("Temporal")
    table.add_column("Enumeration")
    table.add_column("Protocol")
    table.add_column("Username")
    table.add_column("Labels")
    for fp in fps:
        s = fp["summary"]
        labels = fp["labels"]
        label_str = (
            f"scan={labels.get('scan_interval')} ports={labels.get('ports')} "
            f"users={labels.get('username_diversity')}"
        )
        table.add_row(
            fp["src_ip"],
            str(fp["event_count"]),
            f"{s['temporal_signature']:.2f}",
            f"{s['enumeration_pattern']:.2f}",
            f"{s['protocol_sequence']:.2f}",
            f"{s['username_behavior']:.2f}",
            label_str,
        )
    console.print(table)


@app.command("attribute")
def attribute_cmd(
    json_out: bool = typer.Option(False, "--json", help="Print JSON"),
) -> None:
    """Compare fingerprints and cluster probable same operators."""
    from shadowtrace.attribution.clustering import run_attribution_pipeline

    store = _store()
    result = run_attribution_pipeline(store)
    if json_out:
        console.print_json(
            data={
                "clusters": result["clusters"],
                "attributions": result["attributions"][:20],
                "stats": result["stats"],
            }
        )
        return

    console.print(Panel.fit("[bold]Actor Attribution[/bold]", border_style="cyan"))
    for c in result["clusters"]:
        members = ", ".join(c["members"])
        style = "bold green" if len(c["members"]) > 1 and "probable" in c["notes"] else "white"
        console.print(
            f"[{style}]{c['label']}[/{style}] - {c['notes']} "
            f"(confidence {c['confidence']*100:.0f}%)\n  members: {members}"
        )

    pairs = [p for p in result["attributions"] if p["probable_same_actor"]]
    if pairs:
        table = Table(title="High-similarity pairs", box=box.SIMPLE)
        table.add_column("IP A")
        table.add_column("IP B")
        table.add_column("Score", justify="right")
        table.add_column("Same?")
        for p in pairs[:15]:
            table.add_row(
                p["ip_a"],
                p["ip_b"],
                f"{p['likely_same_actor_pct']}%",
                "YES" if p["same_actor"] else "probable",
            )
        console.print(table)


@app.command("compare")
def compare_cmd(
    ip_a: str = typer.Argument(...),
    ip_b: str = typer.Argument(...),
) -> None:
    """Compare two source IPs' behavioral fingerprints."""
    from shadowtrace.attribution.similarity import compare_fingerprints
    from shadowtrace.features.fingerprint import build_fingerprint_for_ip

    store = _store()
    fp_a = build_fingerprint_for_ip(store, ip_a)
    fp_b = build_fingerprint_for_ip(store, ip_b)
    result = compare_fingerprints(fp_a, fp_b)
    console.print(
        Panel(
            f"[bold]Likely same actor: {result['likely_same_actor_pct']}%[/bold]\n"
            f"cosine={result['cosine']:.3f}  composite={result['score']:.3f}",
            title="ATTACKER FINGERPRINT MATCH",
            border_style="cyan",
        )
    )
    table = Table(box=box.SIMPLE)
    table.add_column("Dimension")
    table.add_column("Score", justify="right")
    for k, v in result["breakdown"].items():
        table.add_row(k.replace("_", " "), f"{v:.2f}")
    console.print(table)


@app.command("detect")
def detect_cmd() -> None:
    """Run SOC-style detectors (port scan, SSH brute, reverse-shell hints)."""
    from shadowtrace.detection.detectors import run_all_detectors

    store = _store()
    events = store.list_events(limit=100000)
    findings = run_all_detectors(events)
    if not findings:
        console.print("[green]No detector findings.[/green]")
        return
    table = Table(title="Detections", box=box.SIMPLE_HEAVY)
    table.add_column("Type")
    table.add_column("IP")
    table.add_column("Severity")
    table.add_column("Detail")
    for f in findings:
        table.add_row(f["type"], f["src_ip"], f["severity"], f["detail"])
    console.print(table)


@app.command("graph")
def graph_cmd(
    out: Path = typer.Option(Path("data/actor_graph.json"), "--out", "-o"),
) -> None:
    """Export NetworkX actor graph as JSON."""
    from shadowtrace.attribution.graph import build_actor_graph

    store = _store()
    g = build_actor_graph(
        store.list_attributions(),
        store.list_fingerprints(),
        store.list_clusters(),
    )
    ensure_dirs()
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(g, indent=2), encoding="utf-8")
    console.print(
        f"[green]Graph written[/green] -> {out} "
        f"({g['node_count']} nodes, {g['edge_count']} edges)"
    )


@app.command("status")
def status_cmd() -> None:
    """Show real-time engine + database status."""
    from shadowtrace.realtime.engine import get_engine

    snap = get_engine().snapshot()
    console.print_json(data=snap)


@app.command("serve")
def serve_cmd(
    host: Optional[str] = typer.Option(None, "--host"),
    port: Optional[int] = typer.Option(None, "--port"),
    with_engine: bool = typer.Option(
        True,
        "--engine/--no-engine",
        help="Keep real-time engine available via API",
    ),
) -> None:
    """Start the FastAPI + live GUI dashboard (Windows & Linux)."""
    import uvicorn

    settings = get_settings()
    h = host or settings.api_host
    p = port or settings.api_port
    if with_engine:
        from shadowtrace.realtime.engine import get_engine

        get_engine()  # ensure singleton exists for API control
    console.print(
        Panel.fit(
            f"[bold]SHADOWTRACE live GUI[/bold]\n"
            f"http://{h}:{p}/\nAPI docs: http://{h}:{p}/docs\n"
            f"WebSocket: ws://{h}:{p}/ws/live",
            border_style="cyan",
        )
    )
    uvicorn.run(
        "shadowtrace.api.app:app",
        host=h,
        port=p,
        reload=False,
        log_level="info",
    )


@app.command("stats")
def stats_cmd() -> None:
    """Show database statistics."""
    console.print(_store().stats())


@app.command("gui")
def gui_cmd(
    host: Optional[str] = typer.Option(None, "--host"),
    port: Optional[int] = typer.Option(None, "--port"),
) -> None:
    """Alias for serve - launch the graphical dashboard."""
    serve_cmd(host=host, port=port)


if __name__ == "__main__":
    app()
