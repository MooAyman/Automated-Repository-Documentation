"""Minimal HTTP wrapper around the repository collector.

Exposes the collector as an endpoint that an ARK `Tool` of `type: http` can call.
Standard library only - no web framework is needed for three endpoints.

    GET  /health    -> "ok"
    POST /collect   -> text/plain repository dump
    POST /changes   -> application/json commit file changes

Request body for /collect (JSON):
    {"repository": "<url or local path>", "ref": "<optional branch/tag>",
     "max_file_bytes": 80000, "max_total_bytes": 209715200}

Request body for /changes (JSON):
    {"repository": "<url or local path>", "ref": "<optional new ref>",
     "previousCommit": "<optional SHA>", "newCommit": "<optional SHA>"}
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from changes import detect_changes
from collector import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_TOTAL_BYTES,
    CollectorError,
    collect_into,
    redact,
    render,
    source_identity,
)

PORT = int(os.environ.get("PORT", "8080"))
LOCAL_REPO_ROOT = os.environ.get("LOCAL_REPO_ROOT", "").strip() or None
MAX_REQUEST_BYTES = 64 * 1024

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("repository-collector")


def _positive_int(value, fallback: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return fallback
    return parsed if parsed > 0 else fallback


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "repository-collector/1.0"

    def log_message(self, fmt: str, *args) -> None:  # route access logs through logging
        log.info("%s %s", self.address_string(), fmt % args)

    def _respond(self, status: int, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if self.path.rstrip("/") in ("/health", "/healthz", ""):
            self._respond(200, "ok")
        else:
            self._respond(404, f"unknown path: {self.path}")

    def do_POST(self) -> None:
        path = self.path.rstrip("/")
        if path == "/changes":
            self._changes()
            return
        if path != "/collect":
            self._respond(404, f"unknown path: {self.path}")
            return

        length = _positive_int(self.headers.get("Content-Length"), 0)
        if length > MAX_REQUEST_BYTES:
            self._respond(413, "request body too large")
            return
        raw = self.rfile.read(length) if length else b"{}"

        try:
            payload = json.loads(raw or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("body must be a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            self._respond(400, f"invalid JSON request body: {exc}")
            return

        repository = str(payload.get("repository") or payload.get("url") or "").strip()
        ref = str(payload.get("ref") or "").strip()
        max_file_bytes = _positive_int(payload.get("max_file_bytes"), DEFAULT_MAX_FILE_BYTES)
        max_total_bytes = _positive_int(payload.get("max_total_bytes"), DEFAULT_MAX_TOTAL_BYTES)

        if not repository:
            self._respond(400, "field 'repository' is required (a git URL or a local path)")
            return

        host, name = source_identity(repository)
        started = time.monotonic()
        log.info(
            "collecting host=%s repo=%s requested_ref=%s",
            host,
            name,
            ref or "<default>",
        )
        try:
            collection = collect_into(
                repository,
                ref=ref,
                max_file_bytes=max_file_bytes,
                max_total_bytes=max_total_bytes,
                local_root=LOCAL_REPO_ROOT,
            )
        except CollectorError as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            log.warning(
                "collection failed host=%s repo=%s requested_ref=%s result=error elapsed_ms=%d: %s",
                host,
                name,
                ref or "<default>",
                elapsed_ms,
                redact(str(exc)),
            )
            self._respond(exc.status, redact(str(exc)))
            return
        except Exception as exc:  # noqa: BLE001 - surface the error to the agent, keep serving
            elapsed_ms = int((time.monotonic() - started) * 1000)
            log.exception(
                "unexpected collection error host=%s repo=%s requested_ref=%s elapsed_ms=%d",
                host,
                name,
                ref or "<default>",
                elapsed_ms,
            )
            self._respond(500, f"unexpected error collecting repository: {redact(str(exc))}")
            return

        dump = render(collection)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        log.info(
            "collected host=%s repo=%s requested_ref=%s resolved_ref=%s commit=%s files=%d bytes=%d elapsed_ms=%d result=ok",
            collection.host or host,
            collection.name,
            ref or "<default>",
            collection.resolved_ref or "<default>",
            (collection.commit or "")[:12],
            len(collection.included),
            len(dump),
            elapsed_ms,
        )
        self._respond(200, dump)

    def _changes(self) -> None:
        length = _positive_int(self.headers.get("Content-Length"), 0)
        if length > MAX_REQUEST_BYTES:
            self._respond(413, "request body too large")
            return
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("body must be a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            self._respond(400, f"invalid JSON request body: {exc}")
            return

        repository = str(payload.get("repository") or payload.get("url") or "").strip()
        ref = str(payload.get("ref") or "").strip()
        previous = str(payload.get("previousCommit") or "").strip()
        new_commit = str(payload.get("newCommit") or "").strip()
        if not repository:
            self._respond(400, "field 'repository' is required (a git URL or a local path)")
            return

        host, name = source_identity(repository)
        started = time.monotonic()
        log.info(
            "detecting changes host=%s repo=%s previous=%s new=%s requested_ref=%s",
            host,
            name,
            (previous or "<none>")[:12],
            (new_commit or "<none>")[:12],
            ref or "<default>",
        )
        try:
            result = detect_changes(
                repository,
                previous_commit=previous,
                ref=ref,
                new_commit=new_commit,
                local_root=LOCAL_REPO_ROOT,
            )
        except CollectorError as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            log.warning(
                "change detection failed host=%s repo=%s result=error elapsed_ms=%d: %s",
                host,
                name,
                elapsed_ms,
                redact(str(exc)),
            )
            self._respond(exc.status, redact(str(exc)))
            return
        except Exception as exc:  # noqa: BLE001
            elapsed_ms = int((time.monotonic() - started) * 1000)
            log.exception(
                "unexpected change detection error host=%s repo=%s elapsed_ms=%d",
                host,
                name,
                elapsed_ms,
            )
            self._respond(500, f"unexpected error detecting changes: {redact(str(exc))}")
            return

        body = json.dumps(result, ensure_ascii=False)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        log.info(
            "detected changes host=%s repo=%s mode=%s previous=%s new=%s files=%d elapsed_ms=%d result=ok",
            host,
            name,
            result["mode"],
            (result["previousCommit"] or "<none>")[:12],
            (result["newCommit"] or "")[:12],
            len(result["changed"]),
            elapsed_ms,
        )
        self._respond(200, body, "application/json; charset=utf-8")


def main() -> int:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log.info("repository-collector listening on port %d", PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
