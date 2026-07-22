from __future__ import annotations

import http.client
import json
import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from static_server import StaticAssetServer, StaticRequestHandler


@contextmanager
def running_server(root: Path) -> Iterator[tuple[str, int]]:
    server = StaticAssetServer(
        ("127.0.0.1", 0),
        StaticRequestHandler,
        asset_root=root,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield str(host), int(port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request(
    address: tuple[str, int],
    method: str,
    target: str,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection(*address, timeout=3)
    try:
        connection.request(method, target)
        response = connection.getresponse()
        body = response.read()
        return response.status, dict(response.getheaders()), body
    finally:
        connection.close()


def seed_assets(root: Path) -> None:
    (root / "bootstrap").mkdir(parents=True)
    (root / "metadata").mkdir(parents=True)
    (root / "registration" / "ready").mkdir(parents=True)
    (root / "bootstrap" / "bootstrap.sh").write_bytes(b"#!/bin/bash\n")
    (root / "metadata" / "autoinstall.scm").write_bytes(b"(fixture)\n")
    (root / "registration" / "ready" / "private.json").write_bytes(
        b'{"private":true}\n'
    )


def test_health_is_bounded_json(tmp_path: Path) -> None:
    seed_assets(tmp_path)

    with running_server(tmp_path) as address:
        status, headers, body = request(address, "GET", "/health")

    assert status == 200
    assert json.loads(body) == {"status": "ok"}
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_only_allowlisted_assets_are_served(tmp_path: Path) -> None:
    seed_assets(tmp_path)

    with running_server(tmp_path) as address:
        bootstrap = request(address, "GET", "/bootstrap/bootstrap.sh")
        metadata = request(address, "GET", "/metadata/autoinstall.scm")
        head = request(address, "HEAD", "/bootstrap/bootstrap.sh")
        registration = request(
            address,
            "GET",
            "/registration/ready/private.json",
        )
        root = request(address, "GET", "/")
        directory = request(address, "GET", "/bootstrap/")

    assert bootstrap[0] == 200
    assert bootstrap[2] == b"#!/bin/bash\n"
    assert metadata[0] == 200
    assert metadata[2] == b"(fixture)\n"
    assert head[0] == 200
    assert head[2] == b""
    assert head[1]["Content-Length"] == str(len(b"#!/bin/bash\n"))
    assert registration[0] == 404
    assert root[0] == 404
    assert directory[0] == 404


def test_traversal_and_ambiguous_paths_are_rejected(tmp_path: Path) -> None:
    seed_assets(tmp_path)
    targets = (
        "/bootstrap/../registration/ready/private.json",
        "/bootstrap/%2e%2e/registration/ready/private.json",
        "/bootstrap/%2Fregistration/ready/private.json",
        "/bootstrap/%5cregistration/ready/private.json",
        "/bootstrap//bootstrap.sh",
        "/bootstrap/%00bootstrap.sh",
        "/bootstrap/%zzbootstrap.sh",
    )

    with running_server(tmp_path) as address:
        results = [request(address, "GET", target) for target in targets]

    assert [result[0] for result in results] == [404] * len(targets)


def test_symlinks_and_special_files_are_rejected_without_blocking(
    tmp_path: Path,
) -> None:
    seed_assets(tmp_path)
    outside = tmp_path / "outside-secret"
    outside.write_bytes(b"outside\n")
    (tmp_path / "bootstrap" / "link").symlink_to(outside)
    outside_dir = tmp_path / "outside-dir"
    outside_dir.mkdir()
    (outside_dir / "secret").write_bytes(b"secret\n")
    (tmp_path / "metadata" / "linked").symlink_to(
        outside_dir,
        target_is_directory=True,
    )
    fifo = tmp_path / "bootstrap" / "pipe"
    os.mkfifo(fifo)

    with running_server(tmp_path) as address:
        link = request(address, "GET", "/bootstrap/link")
        linked_dir = request(address, "GET", "/metadata/linked/secret")
        pipe = request(address, "GET", "/bootstrap/pipe")

    assert link[0] == 404
    assert linked_dir[0] == 404
    assert pipe[0] == 404


def test_mutating_http_methods_are_rejected(tmp_path: Path) -> None:
    seed_assets(tmp_path)

    with running_server(tmp_path) as address:
        status, headers, body = request(
            address,
            "POST",
            "/bootstrap/bootstrap.sh",
        )

    assert status == 405
    assert headers["Allow"] == "GET, HEAD"
    assert body == b""


def test_systemd_unit_runs_allowlisted_server_unprivileged() -> None:
    root = Path(__file__).resolve().parents[2]
    unit = (
        root
        / "deploy"
        / "alt-linux"
        / "systemd"
        / "alt-deploy-http.service"
    ).read_text(encoding="utf-8")

    assert "User=altserver" in unit
    assert "Group=altserver" in unit
    assert "ExecStart=/usr/bin/python3 /opt/alt-deploy-api/static_server.py" in unit
    assert "http.server" not in unit
    assert "ProtectSystem=strict" in unit
    assert "ProtectHome=true" in unit
    assert "NoNewPrivileges=true" in unit
    assert "ReadWritePaths=/srv/alt-deploy" not in unit
