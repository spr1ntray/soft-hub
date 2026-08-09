from __future__ import annotations

import argparse
import importlib.metadata
import json
import signal
import sys
import threading
import webbrowser
from pathlib import Path

from .api import HubApplication, create_server
from .config import APP_VERSION


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Soft Hub local control plane")
    parser.add_argument("--data-dir", type=Path, default=None)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--desktop", action="store_true")
    parser.add_argument("--no-open", action="store_true")
    parser.add_argument("--max-concurrent", type=int, default=4)
    return parser


def main() -> int:
    if sys.version_info[:2] != (3, 12):
        raise SystemExit(f"Soft Hub {APP_VERSION} требует Python 3.12.x")
    cryptography_version = tuple(
        int(part) for part in importlib.metadata.version("cryptography").split(".")[:2]
    )
    if not (cryptography_version >= (50, 0) and cryptography_version < (51, 0)):
        raise SystemExit("Soft Hub требует cryptography>=50,<51; обновите зависимости")
    arguments = build_parser().parse_args()
    application = HubApplication(arguments.data_dir, max_concurrent=arguments.max_concurrent)
    server, token = create_server(application, port=arguments.port)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/#token={token}"

    def stop(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print("SOFT_HUB_READY " + json.dumps({"url": url, "port": port}), flush=True)
    if not arguments.desktop and not arguments.no_open:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
