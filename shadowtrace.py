#!/usr/bin/env python3
"""SHADOWTRACE CLI.

    python shadowtrace.py --help
    python3 shadowtrace.py monitor -p /var/log/auth.log

GUI: python3 shadowtrace_gui.py
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
PKG = SRC / "shadowtrace"


def _prepare_path() -> None:
    # Prefer src/ over project root so this file is not imported as the package.
    root_s = str(ROOT)
    while root_s in sys.path:
        sys.path.remove(root_s)
    while "" in sys.path:
        sys.path.remove("")
    src_s = str(SRC)
    if src_s in sys.path:
        sys.path.remove(src_s)
    sys.path.insert(0, src_s)


def _load_package() -> None:
    _prepare_path()
    existing = sys.modules.get("shadowtrace")
    if existing is not None:
        ef = Path(getattr(existing, "__file__", "") or "").resolve()
        if ef == Path(__file__).resolve():
            del sys.modules["shadowtrace"]
            for key in [k for k in sys.modules if k.startswith("shadowtrace.")]:
                del sys.modules[key]
        else:
            return

    spec = importlib.util.spec_from_file_location(
        "shadowtrace",
        PKG / "__init__.py",
        submodule_search_locations=[str(PKG)],
    )
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load shadowtrace package from src/")
    module = importlib.util.module_from_spec(spec)
    sys.modules["shadowtrace"] = module
    spec.loader.exec_module(module)


def main() -> int:
    try:
        _load_package()
        from shadowtrace.cli import app
    except ImportError as exc:
        print(
            "Missing dependencies or package import failed.\n"
            f"  detail: {exc}\n"
            "From the project folder run:\n"
            "  python -m pip install -r requirements.txt\n"
            "  python -m pip install -e .",
            file=sys.stderr,
        )
        return 1
    app()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
