"""HTTP wrapper for the documentation renderer.

    GET  /health  -> ok
    POST /render  -> text/html

Request body (JSON):
    {"documentation": { ... Agent outputSchema ... }}
or the six-key document itself.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from renderer import RenderError, persist_html, render, safe_output_filename

PORT = int(os.environ.get("PORT", "8080"))
MAX_REQUEST_BYTES = int(os.environ.get("MAX_REQUEST_BYTES", str(2 * 1024 * 1024)))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "").strip()

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("documentation-renderer")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "documentation-renderer/1.0"

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
        if path == "/files":
            self._list_files()
            return
        if path.startswith("/files/"):
            self._get_file(path[len("/files/"):])
            return
        self._respond(404, f"unknown path: {self.path}", "text/plain; charset=utf-8")

    def _list_files(self) -> None:
        if not OUTPUT_DIR:
            self._respond(404, "OUTPUT_DIR is not configured", "text/plain; charset=utf-8")
            return
        root = Path(OUTPUT_DIR)
        names = sorted(p.name for p in root.glob("*.html") if p.is_file()) if root.is_dir() else []
        self._respond(200, "\n".join(names) + ("\n" if names else ""), "text/plain; charset=utf-8")

    def _get_file(self, name: str) -> None:
        if not OUTPUT_DIR:
            self._respond(404, "OUTPUT_DIR is not configured", "text/plain; charset=utf-8")
            return
        filename = safe_output_filename(name)
        dest = Path(OUTPUT_DIR).resolve() / filename
        if not dest.is_file() or dest.parent != Path(OUTPUT_DIR).resolve():
            self._respond(404, f"file not found: {filename}", "text/plain; charset=utf-8")
            return
        self._respond(200, dest.read_text(encoding="utf-8"), "text/html; charset=utf-8")

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/render":
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
        persist = bool(isinstance(payload, dict) and payload.get("persist"))
        repository_name = ""
        if isinstance(payload, dict):
            repository_name = str(payload.get("repositoryName") or "").strip()
        try:
            page = render(payload)
        except RenderError as exc:
            log.warning("render rejected (%d bytes persist=%s): %s", length, persist, exc)
            self._respond(400, f"invalid documentation: {exc}", "text/plain; charset=utf-8")
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("unexpected render error")
            self._respond(500, f"unexpected render error: {exc}", "text/plain; charset=utf-8")
            return
        artifact = None
        if OUTPUT_DIR:
            try:
                artifact = persist_html(page, repository_name, OUTPUT_DIR)
                log.info("wrote artifact %s (%d bytes)", artifact["filename"], artifact["bytes"])
            except RenderError as exc:
                log.warning("artifact write failed: %s", exc)
                if persist:
                    self._respond(500, f"HTML rendering failed: {exc}", "text/plain; charset=utf-8")
                    return
        log.info("rendered documentation (%d bytes)", len(page))
        if persist:
            if artifact is None:
                self._respond(500, "HTML rendering failed: OUTPUT_DIR is not configured", "text/plain; charset=utf-8")
                return
            self._respond(200, json.dumps(artifact, ensure_ascii=False), "application/json; charset=utf-8")
            return
        self._respond(200, page, "text/html; charset=utf-8")


def main() -> int:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log.info("documentation-renderer listening on port %d", PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
