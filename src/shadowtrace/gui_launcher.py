"""GUI launcher used by shadowtrace_gui.py and the shadowtrace_gui console script."""

from __future__ import annotations

import argparse
import sys
import webbrowser


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SHADOWTRACE GUI - live behavioral attribution dashboard",
    )
    parser.add_argument("--host", default=None, help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (default: 8787)")
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open a browser tab automatically",
    )
    args = parser.parse_args(argv)

    try:
        import uvicorn
    except ImportError:
        print(
            "Missing dependencies. From the project folder run:\n"
            "  python -m pip install -r requirements.txt\n"
            "  python -m pip install -e .",
            file=sys.stderr,
        )
        return 1

    from shadowtrace.config import ensure_dirs, get_settings
    from shadowtrace.realtime.engine import get_engine

    ensure_dirs()
    get_engine()

    settings = get_settings()
    host = args.host or settings.api_host
    port = args.port or settings.api_port
    url = f"http://{host}:{port}/"

    print("SHADOWTRACE GUI")
    print(f"  dashboard : {url}")
    print(f"  api docs  : http://{host}:{port}/docs")
    print(f"  websocket : ws://{host}:{port}/ws/live")
    print("  stop with Ctrl+C")
    print()

    if not args.no_browser and host in ("127.0.0.1", "localhost", "0.0.0.0"):
        browse = f"http://127.0.0.1:{port}/" if host == "0.0.0.0" else url
        try:
            webbrowser.open(browse)
        except Exception:
            pass

    uvicorn.run(
        "shadowtrace.api.app:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
