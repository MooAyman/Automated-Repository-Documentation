"""HTTP wrapper for the repository map.

    GET  /health  -> ok
    POST /map     -> application/json repository map

Accepts already-sanitized repository-analyzer JSON only.
Does not clone repositories, parse source, or resolve references.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mapper import MapError, build

PORT = int(os.environ.get("PORT", "8080"))
MAX_REQUEST_BYTES = int(os.environ.get("MAX_REQUEST_BYTES", str(2 * 1024 * 1024)))

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("repository-map")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "repository-map/1.0"

    def log_message(self, fmt: str, *args) -> None:
        log.info("%s %s", self.address_string(), fmt % args)

    def _respond(self, status: int, body: str, content_type: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path in ("/health", "/healthz", "/"):
            self._respond(200, "ok", "text/plain; charset=utf-8")
            return
        self._respond(404, f"unknown path: {self.path}", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/map":
            self._respond(404, f"unknown path: {self.path}", "text/plain; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length > MAX_REQUEST_BYTES:
            self._respond(413, "request body too large", "text/plain; charset=utf-8")
            return
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            log.warning("invalid JSON request body (%d bytes): %s", length, exc)
            self._respond(400, f"invalid JSON request body: {exc}", "text/plain; charset=utf-8")
            return
        try:
            result = build(payload)
        except MapError as exc:
            log.warning("map rejected (%d bytes): %s", length, exc)
            self._respond(400, f"invalid map request: {exc}", "text/plain; charset=utf-8")
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("unexpected map error")
            self._respond(500, f"unexpected map error: {exc}", "text/plain; charset=utf-8")
            return
        body = json.dumps(result, ensure_ascii=False)
        log.info(
            "mapped %d modules (%d symbols, %d relationships, %d request bytes)",
            len(result["modules"]),
            len(result["symbols"]),
            len(result["relationships"]),
            length,
        )
        self._respond(200, body, "application/json; charset=utf-8")


def main() -> int:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log.info("repository-map listening on port %d", PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
