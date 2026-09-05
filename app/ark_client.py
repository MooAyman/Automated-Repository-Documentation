"""Submit and watch ARK Queries for Agent/repository-pipeline.

This is a host-side client. It does not call the collector or renderer.
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

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "out"
NAMESPACE = os.environ.get("ARK_NAMESPACE", "default")
PIPELINE_AGENT = "repository-pipeline"
QUERY_TIMEOUT = "15m"
POLL_SECONDS = 3
WAIT_SECONDS = 900

_DNS1123 = re.compile(r"[^a-z0-9-]+")
_HTML_NAME = re.compile(r"([A-Za-z0-9._-]+\.html)")


def build_input(repository_url: str, ref: str = "") -> str:
    url = repository_url.strip()
    if not url:
        raise ValueError("repository URL is required")
    message = f"Document this repository: {url}"
    ref = ref.strip()
    if ref:
        message = f"{message} ref: {ref}"
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
    name = query_name("https://github.com/MooAyman/github-mcp-chatbot.git")
    assert name.startswith("ui-github-mcp-chatbot-")
    assert filename_from_response("Output:\ngithub-mcp-chatbot.html") == (
        "github-mcp-chatbot.html"
    )
    print("ark_client checks passed")
