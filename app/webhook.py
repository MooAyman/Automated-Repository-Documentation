"""GitHub/GitLab push webhook trigger.

Validates the event, extracts repository/before/after, and starts the existing
#5-A → #5-B → #5-C documentation plan in the background. The HTTP handler
does not clone, analyze, call a model, or generate documentation.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from ark_client import execute_documentation_plan, plan_documentation, run_ark_pipeline
from validation import ValidationError, validate_commit_sha, validate_repository_url

log = logging.getLogger("documentation-webhook")

ZERO_SHA = "0" * 40
MAX_REQUEST_BYTES = int(os.environ.get("WEBHOOK_MAX_BYTES", str(1024 * 1024)))
DEFAULT_HOST = os.environ.get("WEBHOOK_HOST", "0.0.0.0").strip() or "0.0.0.0"
DEFAULT_PORT = int(os.environ.get("WEBHOOK_PORT", "8787"))

_server: ThreadingHTTPServer | None = None
_server_lock = threading.Lock()
_triggers: list[dict[str, Any]] = []


class WebhookError(ValueError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _header(headers: dict[str, str], name: str) -> str:
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    return lowered.get(name.lower(), "")


def _normalize_url(raw: str) -> str:
    return validate_repository_url((raw or "").strip())


def parse_github_push(payload: dict[str, Any]) -> dict[str, str]:
    repo = payload.get("repository") if isinstance(payload.get("repository"), dict) else {}
    url = str(repo.get("clone_url") or repo.get("html_url") or "")
    before = str(payload.get("before") or "")
    after = str(payload.get("after") or "")
    return _event("github", url, before, after, str(payload.get("ref") or ""))


def parse_gitlab_push(payload: dict[str, Any]) -> dict[str, str]:
    project = payload.get("project") if isinstance(payload.get("project"), dict) else {}
    url = str(project.get("http_url") or project.get("git_http_url") or "")
    before = str(payload.get("before") or "")
    after = str(payload.get("after") or payload.get("checkout_sha") or "")
    return _event("gitlab", url, before, after, str(payload.get("ref") or ""))


def _event(provider: str, url: str, before: str, after: str, ref: str) -> dict[str, str]:
    try:
        repository = _normalize_url(url)
    except ValidationError as exc:
        raise WebhookError(f"repository URL is invalid: {exc}", 400) from exc
    after_sha = (after or "").strip()
    if not after_sha or after_sha.lower() == ZERO_SHA:
        raise WebhookError("push after SHA is required", 400)
    try:
        after_sha = validate_commit_sha(after_sha, required=True)
    except ValidationError as exc:
        raise WebhookError(f"after SHA is invalid: {exc}", 400) from exc
    before_sha = (before or "").strip()
    if before_sha.lower() == ZERO_SHA:
        before_sha = ""
    elif before_sha:
        try:
            before_sha = validate_commit_sha(before_sha, required=True)
        except ValidationError as exc:
            raise WebhookError(f"before SHA is invalid: {exc}", 400) from exc
    return {
        "provider": provider,
        "repository": repository,
        "before": before_sha,
        "after": after_sha,
        "ref": ref.replace("refs/heads/", "").replace("refs/tags/", ""),
    }


def parse_push_event(headers: dict[str, str], payload: dict[str, Any] | str | bytes) -> dict[str, str]:
    if isinstance(payload, (bytes, bytearray)):
        try:
            payload = json.loads(payload.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WebhookError(f"invalid JSON: {exc}", 400) from exc
    if isinstance(payload, str):
        try:
            payload = json.loads(payload or "{}")
        except json.JSONDecodeError as exc:
            raise WebhookError(f"invalid JSON: {exc}", 400) from exc
    if not isinstance(payload, dict):
        raise WebhookError("event body must be a JSON object", 400)

    github_event = _header(headers, "X-GitHub-Event")
    gitlab_event = _header(headers, "X-Gitlab-Event")
    if github_event:
        if github_event.lower() != "push":
            raise WebhookError(f"unsupported GitHub event: {github_event}", 400)
        return parse_github_push(payload)
    if gitlab_event:
        if "push" not in gitlab_event.lower():
            raise WebhookError(f"unsupported GitLab event: {gitlab_event}", 400)
        return parse_gitlab_push(payload)
    if payload.get("repository") and payload.get("after"):
        return parse_github_push(payload)
    if payload.get("project") and (payload.get("after") or payload.get("checkout_sha")):
        return parse_gitlab_push(payload)
    raise WebhookError("event is not a GitHub or GitLab push", 400)


def verify_signature(headers: dict[str, str], raw_body: bytes, secret: str = "") -> None:
    expected = (secret or os.environ.get("WEBHOOK_SECRET") or "").strip()
    if not expected:
        return
    github_sig = _header(headers, "X-Hub-Signature-256")
    gitlab_token = _header(headers, "X-Gitlab-Token")
    if gitlab_token:
        if not hmac.compare_digest(gitlab_token, expected):
            raise WebhookError("invalid webhook token", 401)
        return
    if github_sig.startswith("sha256="):
        digest = hmac.new(expected.encode("utf-8"), raw_body, "sha256").hexdigest()
        if not hmac.compare_digest(github_sig, f"sha256={digest}"):
            raise WebhookError("invalid webhook signature", 401)
        return
    raise WebhookError("webhook signature is required", 401)


def start_documentation(
    event: dict[str, str],
    *,
    run_pipeline: Callable[[dict], dict] | None = None,
    registry_path: str | None = None,
    join: bool = False,
) -> threading.Thread:
    """Enqueue the existing documentation plan. Does not do the work here."""

    def _run() -> None:
        plan = plan_documentation(
            event["repository"],
            event.get("ref") or "",
            current_sha=event["after"],
            registry_path=registry_path,
        )
        plan["ref"] = event.get("ref") or ""
        record = {
            "repository": event["repository"],
            "before": event.get("before") or "",
            "after": event["after"],
            "previousCommit": plan.get("previousCommit") or "",
            "currentCommit": plan.get("currentCommit") or "",
            "status": plan.get("status"),
        }
        _triggers.append(record)
        if not plan.get("runPipeline"):
            record["result"] = plan.get("status")
            return
        runner = run_pipeline or run_ark_pipeline
        result = execute_documentation_plan(plan, run_pipeline=runner, registry_path=registry_path)
        record["result"] = result.get("status")
        record["documentationVersion"] = result.get("documentationVersion")

    thread = threading.Thread(target=_run, name="documentation-webhook", daemon=True)
    thread.start()
    if join:
        thread.join()
    return thread


def process_webhook(
    headers: dict[str, str],
    raw_body: bytes,
    *,
    run_pipeline: Callable[[dict], dict] | None = None,
    registry_path: str | None = None,
    secret: str = "",
    join: bool = False,
) -> dict[str, Any]:
    verify_signature(headers, raw_body, secret)
    event = parse_push_event(headers, raw_body)
    start_documentation(event, run_pipeline=run_pipeline, registry_path=registry_path, join=join)
    return {
        "accepted": True,
        "repository": event["repository"],
        "before": event["before"],
        "after": event["after"],
        "ref": event.get("ref") or "",
        "provider": event["provider"],
    }


def recent_triggers() -> list[dict[str, Any]]:
    return list(_triggers)


def reset_triggers() -> None:
    _triggers.clear()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    run_pipeline: Callable[[dict], dict] | None = None
    registry_path: str | None = None

    def log_message(self, fmt: str, *args) -> None:
        log.info("%s %s", self.address_string(), fmt % args)

    def _respond(self, status: int, body: dict[str, Any] | str) -> None:
        if isinstance(body, dict):
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            content_type = "application/json; charset=utf-8"
        else:
            payload = str(body).encode("utf-8")
            content_type = "text/plain; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path in ("/health", "/healthz", "/"):
            self._respond(200, "ok")
            return
        self._respond(404, f"unknown path: {self.path}")

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/")
        if path not in ("/webhook", "/webhook/github", "/webhook/gitlab"):
            self._respond(404, f"unknown path: {self.path}")
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length > MAX_REQUEST_BYTES:
            self._respond(413, "request body too large")
            return
        raw = self.rfile.read(length) if length else b"{}"
        headers = {key: value for key, value in self.headers.items()}
        try:
            accepted = process_webhook(
                headers,
                raw,
                run_pipeline=self.run_pipeline,
                registry_path=self.registry_path,
            )
        except WebhookError as exc:
            self._respond(exc.status, {"accepted": False, "error": str(exc)})
            return
        self._respond(202, accepted)


def webhook_enabled() -> bool:
    """Streamlit starts the listener unless WEBHOOK_ENABLED is an explicit off value."""
    return os.environ.get("WEBHOOK_ENABLED", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def start_server(
    host: str = "",
    port: int = DEFAULT_PORT,
    *,
    run_pipeline: Callable[[dict], dict] | None = None,
    registry_path: str | None = None,
) -> ThreadingHTTPServer:
    global _server
    with _server_lock:
        if _server is not None:
            return _server
        Handler.run_pipeline = run_pipeline
        Handler.registry_path = registry_path
        server = ThreadingHTTPServer((host or DEFAULT_HOST, port), Handler)
        thread = threading.Thread(target=server.serve_forever, name="webhook-http", daemon=True)
        thread.start()
        _server = server
        log.info("webhook listening on %s:%d", host or DEFAULT_HOST, port)
        return server


def ensure_started() -> ThreadingHTTPServer | None:
    if not webhook_enabled():
        return None
    try:
        return start_server()
    except OSError as exc:
        log.warning("webhook not started: %s", exc)
        return None
