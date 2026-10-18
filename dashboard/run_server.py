"""Start the CPES dashboard API (and the built frontend, if present).

    python dashboard/run_server.py            # http://127.0.0.1:8790
    python dashboard/run_server.py --port 9000

Binds to 127.0.0.1 only: the lab corpora contain identifiers that must not be
served to a network.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE)]


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--reload", action="store_true", help="auto-reload on code changes (development)")
    args = parser.parse_args()
    uvicorn.run("cpes_dashboard.app:app", host="127.0.0.1", port=args.port, reload=args.reload, reload_dirs=[str(HERE / "cpes_dashboard")] if args.reload else None)


if __name__ == "__main__":
    main()
