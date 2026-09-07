"""Submit and watch ARK Queries for Agent/repository-pipeline.

This is a host-side client. It validates URL and ref, consults the
last-documented SHA registry, then applies a Query when needed.
It does not call the collector or renderer.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable

from documentation_registry import (
    lookup,
    record_success,
    repository_identity,
    same_commit,
)
from validation import ValidationError, validate_commit_sha, validate_pipeline_input

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "out"
NAMESPACE = os.environ.get("ARK_NAMESPACE", "default")
PIPELINE_AGENT = "repository-pipeline"
QUERY_TIMEOUT = "15m"
POLL_SECONDS = 3
WAIT_SECONDS = 900

_DNS1123 = re.compile(r"[^a-z0-9-]+")
_HTML_NAME = re.compile(r"([A-Za-z0-9._-]+\.html)")


def parse_ls_remote(stdout: str) -> str:
    """Pick the peeled commit SHA from ``git ls-remote`` output.

    Annotated tags emit the tag object first and ``^{}`` for the commit.
    """
    peeled: list[str] = []
    plain: list[str] = []
    for line in (stdout or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            sha = validate_commit_sha(parts[0], required=True)
        except ValidationError:
            continue
        name = parts[1] if len(parts) > 1 else ""
        if name.endswith("^{}"):
            peeled.append(sha)
        else:
            plain.append(sha)
    chosen = (peeled or plain)
    if not chosen:
        raise RuntimeError("could not resolve commit SHA: empty ls-remote output")
    return chosen[0]


def resolve_commit_sha(repository_url: str, ref: str = "") -> str:
    """Resolve the current remote commit without cloning the repository."""
    url, ref = validate_pipeline_input(repository_url, ref)
    args = ["git", "ls-remote", "--", url, ref or "HEAD"]
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"could not resolve commit SHA: {err}")
    return parse_ls_remote(result.stdout)


def documented_commit(repository_url: str, *, registry_path: str | Path | None = None) -> str:
    record = lookup(repository_url, registry_path)
    return str((record or {}).get("commitSha") or "")


def plan_documentation(
    repository_url: str,
    ref: str = "",
    *,
    resolver: Callable[[str, str], str] | None = None,
    registry_path: str | Path | None = None,
    current_sha: str = "",
) -> dict:
    """Decide whether to run the pipeline or return already_documented.

    Persistence lives in the JSON registry, not Streamlit memory or HTML.
    """
    url, ref = validate_pipeline_input(repository_url, ref)
    identity = repository_identity(url)
    stored = lookup(url, registry_path)
    previous = str((stored or {}).get("commitSha") or "")
    current = (current_sha or "").strip()
    if current:
        current = validate_commit_sha(current, required=True)
    else:
        resolve = resolver or resolve_commit_sha
        try:
            current = resolve(url, ref)
        except Exception:
            current = ""

    if stored and current and same_commit(previous, current):
        return {
            "status": "already_documented",
            "mode": "already_documented",
            "repository": url,
            "identity": identity,
            "currentCommit": previous,
            "previousCommit": previous,
            "documentationVersion": int(stored.get("documentationVersion") or 1),
            "artifact": str(stored.get("artifact") or ""),
            "runPipeline": False,
        }

    if not stored:
        return {
            "status": "first_run",
            "mode": "full",
            "repository": url,
            "identity": identity,
            "currentCommit": current,
            "previousCommit": "",
            "documentationVersion": 0,
            "artifact": "",
            "runPipeline": True,
        }

    return {
        "status": "needs_documentation",
        "mode": "incremental",
        "repository": url,
        "identity": identity,
        "currentCommit": current,
        "previousCommit": previous,
        "documentationVersion": int(stored.get("documentationVersion") or 1),
        "artifact": str(stored.get("artifact") or ""),
        "runPipeline": True,
    }


def complete_documentation(
    repository_url: str,
    commit_sha: str,
    artifact: str = "",
    *,
    registry_path: str | Path | None = None,
) -> dict:
    """Persist the documented SHA only after a successful generation."""
    return record_success(
        repository_url,
        commit_sha,
        artifact=artifact,
        path=registry_path,
    )


def execute_documentation_plan(
    plan: dict,
    *,
    run_pipeline: Callable[[dict], dict] | None = None,
    registry_path: str | Path | None = None,
) -> dict:
    """Run or skip documentation. Persist SHA only when generation succeeds."""
    if plan.get("status") == "already_documented":
        return dict(plan)

    if run_pipeline is None:
        raise RuntimeError("run_pipeline is required unless the commit is already documented")

    outcome = run_pipeline(plan)
    if not outcome.get("ok"):
        stored = lookup(plan["repository"], registry_path)
        return {
            "status": "failed",
            "mode": plan.get("mode") or "full",
            "repository": plan["repository"],
            "identity": plan.get("identity") or repository_identity(plan["repository"]),
            "currentCommit": plan.get("currentCommit") or "",
            "previousCommit": str((stored or {}).get("commitSha") or plan.get("previousCommit") or ""),
            "documentationVersion": int((stored or {}).get("documentationVersion") or plan.get("documentationVersion") or 0),
            "artifact": str((stored or {}).get("artifact") or ""),
            "error": str(outcome.get("error") or "documentation failed"),
            "runPipeline": False,
        }

    artifact = str(outcome.get("artifact") or "")
    sha = str(plan.get("currentCommit") or "")
    if not sha:
        return {
            "status": "documented",
            "mode": plan.get("mode") or "full",
            "repository": plan["repository"],
            "identity": plan.get("identity") or repository_identity(plan["repository"]),
            "currentCommit": "",
            "previousCommit": plan.get("previousCommit") or "",
            "documentationVersion": int(plan.get("documentationVersion") or 0),
            "artifact": artifact,
            "persisted": False,
            "runPipeline": False,
        }

    record = complete_documentation(
        plan["repository"],
        sha,
        artifact,
        registry_path=registry_path,
    )
    return {
        "status": "documented",
        "mode": plan.get("mode") or "full",
        "repository": record["repository"],
        "identity": record["identity"],
        "currentCommit": record["commitSha"],
        "previousCommit": plan.get("previousCommit") or "",
        "documentationVersion": record["documentationVersion"],
        "artifact": record.get("artifact") or artifact,
        "persisted": True,
        "runPipeline": False,
    }


def build_input(
    repository_url: str,
    ref: str = "",
    previous_commit: str = "",
    new_commit: str = "",
) -> str:
    """Build Query input. First/full runs omit previousCommit (V1.3.0 sentence)."""
    url, ref = validate_pipeline_input(repository_url, ref)
    previous = validate_commit_sha(previous_commit)
    current = validate_commit_sha(new_commit)
    message = f"Document this repository: {url}"
    if ref:
        message = f"{message} ref: {ref}"
    if previous:
        message = f"{message} previousCommit: {previous}"
    if current:
        message = f"{message} newCommit: {current}"
    return message


def query_name(repository_url: str) -> str:
    slug = repository_url.rstrip("/").rsplit("/", 1)[-1]
    slug = slug.removesuffix(".git").lower()
    slug = _DNS1123.sub("-", slug).strip("-") or "repo"
    slug = slug[:24]
    stamp = time.strftime("%H%M%S")
    return f"ui-{slug}-{stamp}"[:63]


def artifact_path(filename: str) -> Path:
    name = Path(filename).name
    if name != filename or not name.endswith(".html"):
        raise ValueError(f"unsafe artifact name: {filename!r}")
    return OUT_DIR / name


def filename_from_response(content: str) -> str | None:
    names = _HTML_NAME.findall(content or "")
    return names[-1] if names else None


def _kubectl(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def apply_pipeline_query(name: str, message: str) -> None:
    body = {
        "apiVersion": "ark.mckinsey.com/v1alpha1",
        "kind": "Query",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {
                "project": "repository-documentation",
                "type": "ui",
                "target": "pipeline",
            },
        },
        "spec": {
            "input": message,
            "target": {"type": "agent", "name": PIPELINE_AGENT},
            "timeout": QUERY_TIMEOUT,
        },
    }
    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    try:
        json.dump(body, handle, ensure_ascii=False)
        handle.close()
        result = _kubectl(["kubectl", "apply", "-f", handle.name])
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"kubectl apply failed: {err}")


def get_query(name: str) -> dict | None:
    result = _kubectl(["kubectl", "get", "query", name, "-n", NAMESPACE, "-o", "json"])
    if result.returncode != 0 or not result.stdout:
        return None
    return json.loads(result.stdout)


def wait_for_query(
    name: str,
    timeout_s: int = WAIT_SECONDS,
    on_phase: Callable[[str | None], None] | None = None,
) -> dict:
    deadline = time.time() + timeout_s
    last_phase = object()
    while time.time() < deadline:
        obj = get_query(name)
        phase = (obj.get("status") or {}).get("phase") if obj else None
        if phase != last_phase:
            if on_phase:
                on_phase(phase)
            last_phase = phase
        if obj and phase == "done":
            return obj
        if obj and phase in ("error", "canceled"):
            return obj
        time.sleep(POLL_SECONDS)
    raise TimeoutError(f"timed out waiting for query {name}")


def query_response(obj: dict) -> str:
    return ((obj.get("status") or {}).get("response") or {}).get("content") or ""


if __name__ == "__main__":
    assert build_input("https://github.com/a/b") == (
        "Document this repository: https://github.com/a/b"
    )
    assert build_input("https://github.com/a/b", " develop ") == (
        "Document this repository: https://github.com/a/b ref: develop"
    )
    assert build_input(
        "https://github.com/a/b",
        "main",
        previous_commit="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        new_commit="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ) == (
        "Document this repository: https://github.com/a/b ref: main "
        "previousCommit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
        "newCommit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )
    try:
        build_input("/tmp/repo")
        raise AssertionError("local paths must fail validation")
    except ValidationError:
        pass
    name = query_name("https://github.com/MooAyman/github-mcp-chatbot.git")
    assert name.startswith("ui-github-mcp-chatbot-")
    assert filename_from_response("Output:\ngithub-mcp-chatbot.html") == (
        "github-mcp-chatbot.html"
    )
    print("ark_client checks passed")
