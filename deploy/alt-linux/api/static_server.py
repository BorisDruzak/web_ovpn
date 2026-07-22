#!/usr/bin/python3

from __future__ import annotations

import json
import mimetypes
import os
import re
import stat
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO
from urllib.parse import unquote_to_bytes, urlsplit


LISTEN_ADDRESS = "0.0.0.0"
LISTEN_PORT = 8087
ASSET_ROOT = Path("/srv/alt-deploy")
_ALLOWED_NAMESPACES = frozenset({"bootstrap", "metadata"})
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_MAX_TARGET_LENGTH = 4096
_CHUNK_SIZE = 64 * 1024


class StaticAssetServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        asset_root: Path,
    ) -> None:
        self.asset_root = Path(asset_root)
        super().__init__(server_address, handler_class)


class StaticRequestHandler(BaseHTTPRequestHandler):
    server_version = "ALTDeployStatic/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def asset_server(self) -> StaticAssetServer:
        server = self.server
        if not isinstance(server, StaticAssetServer):
            raise RuntimeError("Static asset server is not configured")
        return server

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _common_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")

    def _empty_response(
        self,
        status: int,
        *,
        allow: str | None = None,
    ) -> None:
        self.send_response(status)
        self._common_headers()
        if allow is not None:
            self.send_header("Allow", allow)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _health(self, *, send_body: bool) -> None:
        raw = json.dumps(
            {"status": "ok"},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        self.send_response(200)
        self._common_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if send_body:
            self.wfile.write(raw)

    @staticmethod
    def _percent_escapes_are_valid(path: str) -> bool:
        index = 0
        while True:
            index = path.find("%", index)
            if index < 0:
                return True
            if not _PERCENT_ESCAPE.fullmatch(path[index : index + 3]):
                return False
            index += 3

    def _asset_parts(self) -> tuple[str, tuple[str, ...]] | None:
        if len(self.path) > _MAX_TARGET_LENGTH:
            return None
        try:
            raw_path = urlsplit(self.path).path
        except ValueError:
            return None
        if not self._percent_escapes_are_valid(raw_path):
            return None
        lowered = raw_path.lower()
        if "%2f" in lowered or "%5c" in lowered:
            return None
        try:
            decoded = unquote_to_bytes(raw_path).decode("utf-8", "strict")
        except (UnicodeDecodeError, ValueError):
            return None
        if (
            not decoded.startswith("/")
            or "\\" in decoded
            or "\x00" in decoded
            or "//" in decoded
            or any(ord(character) < 32 or ord(character) == 127 for character in decoded)
        ):
            return None
        pieces = decoded.split("/")
        if len(pieces) < 3 or pieces[0] != "":
            return None
        namespace = pieces[1]
        segments = tuple(pieces[2:])
        if namespace not in _ALLOWED_NAMESPACES:
            return None
        if not segments or any(
            not segment
            or segment in {".", ".."}
            or len(segment.encode("utf-8")) > 255
            for segment in segments
        ):
            return None
        return namespace, segments

    @staticmethod
    def _directory_flags() -> int:
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        return flags

    @staticmethod
    def _file_flags() -> int:
        flags = os.O_RDONLY | os.O_NONBLOCK
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        return flags

    def _open_asset(
        self,
        namespace: str,
        segments: tuple[str, ...],
    ) -> tuple[BinaryIO, os.stat_result] | None:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                self.asset_server.asset_root,
                self._directory_flags(),
            )
            for segment in (namespace, *segments[:-1]):
                next_descriptor = os.open(
                    segment,
                    self._directory_flags(),
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_descriptor
            file_descriptor = os.open(
                segments[-1],
                self._file_flags(),
                dir_fd=descriptor,
            )
            metadata = os.fstat(file_descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                os.close(file_descriptor)
                return None
            return os.fdopen(file_descriptor, "rb", closefd=True), metadata
        except OSError:
            return None
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _serve_asset(self, *, send_body: bool) -> None:
        parts = self._asset_parts()
        if parts is None:
            self._empty_response(404)
            return
        opened = self._open_asset(*parts)
        if opened is None:
            self._empty_response(404)
            return
        stream, metadata = opened
        try:
            content_type = mimetypes.guess_type(parts[1][-1])[0]
            self.send_response(200)
            self._common_headers()
            self.send_header(
                "Content-Type",
                content_type or "application/octet-stream",
            )
            self.send_header("Content-Length", str(metadata.st_size))
            self.end_headers()
            if send_body:
                while True:
                    chunk = stream.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            return
        finally:
            stream.close()

    def _read(self, *, send_body: bool) -> None:
        try:
            path = urlsplit(self.path).path
        except ValueError:
            self._empty_response(404)
            return
        if path == "/health":
            self._health(send_body=send_body)
            return
        self._serve_asset(send_body=send_body)

    def do_GET(self) -> None:
        self._read(send_body=True)

    def do_HEAD(self) -> None:
        self._read(send_body=False)

    def _method_not_allowed(self) -> None:
        self._empty_response(405, allow="GET, HEAD")

    do_POST = _method_not_allowed
    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed


def main() -> None:
    root = Path(os.environ.get("ALT_DEPLOY_STATIC_ROOT", str(ASSET_ROOT)))
    address = os.environ.get("ALT_DEPLOY_STATIC_ADDRESS", LISTEN_ADDRESS)
    try:
        port = int(os.environ.get("ALT_DEPLOY_STATIC_PORT", str(LISTEN_PORT)))
    except ValueError as exc:
        raise SystemExit("Invalid ALT static server port") from exc
    server = StaticAssetServer(
        (address, port),
        StaticRequestHandler,
        asset_root=root,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
