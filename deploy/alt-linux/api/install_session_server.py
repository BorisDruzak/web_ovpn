from __future__ import annotations

import argparse
from collections.abc import Sequence

from alt_deploy.config import Settings
from install_session_api import create_install_session_server


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-address", required=True)
    parser.add_argument("--listen-port", required=True, type=_port)
    parsed = parser.parse_args(argv)
    server = create_install_session_server(
        Settings.from_env(),
        listen_address=parsed.listen_address,
        listen_port=parsed.listen_port,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
