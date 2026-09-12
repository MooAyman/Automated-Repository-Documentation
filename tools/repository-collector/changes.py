"""Deterministic Git change detection.

Compares two commits in a repository the collector can already open.
Path inclusion matches ``/collect``. Per-file size and binary/NUL checks
annotate eligibility; they do not hide a Git change. The total collection
budget is not applied here.
Does not return file contents, sanitize dumps, parse AST, or call a model.
Optional ``include_diffs`` adds truncated git patches; the default response
still omits file contents.
"""

from __future__ import annotations

import os
import subprocess
from collections import deque
from pathlib import Path
from typing import Any

from collector import (
    DEFAULT_MAX_FILE_BYTES,
    CollectorError,
    _SHA_RE,
    _run_git,
    _skip_reason,
    build_git_env,
    content_skip_reason,
    is_collectable_path,
    is_remote,
    source_identity,
    strip_userinfo,
    validate_remote_url,
)
from sanitizer import sanitize

SCHEMA_VERSION = "1"
MAX_DIFF_CHARS = 8000
STATUS_BY_CODE = {
    "A": "added",
    "M": "modified",
    "T": "modified",
    "D": "deleted",
    "R": "renamed",
    "C": "added",
}


def _sha_or_empty(value: str, label: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if not _SHA_RE.match(text):
        raise CollectorError(f"{label} must be a git commit SHA", status=400)
    return text


def _parse_name_status(text: str) -> list[dict[str, str]]:
    changed: list[dict[str, str]] = []
    for raw in (text or "").splitlines():
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        parts = line.split("\t")
        code = (parts[0] or "")[:1]
        status = STATUS_BY_CODE.get(code)
        if not status:
            path = (parts[-1] or "").strip() if len(parts) >= 2 else ""
            if path:
                changed.append({"path": path, "status": "modified"})
            continue
        if status == "renamed" and len(parts) >= 3:
            changed.append({"path": parts[2], "status": "renamed", "from": parts[1]})
            continue
        if len(parts) >= 2:
            changed.append({"path": parts[-1], "status": status})
    return _filter_changed(changed)


def _filter_changed(changed: list[dict[str, str]]) -> list[dict[str, str]]:
    """Keep only paths ``/collect`` would treat as eligible repository content.

    Renames are rewritten when only one side is eligible:
    excluded → eligible is ``added``; eligible → excluded is ``deleted``.
    """
    filtered: list[dict[str, str]] = []
    for row in changed:
        path = row.get("path") or ""
        status = row.get("status") or ""
        if status == "renamed":
            old = row.get("from") or ""
            new_ok = is_collectable_path(path)
            old_ok = is_collectable_path(old)
            if new_ok and old_ok:
                filtered.append({"path": path, "status": "renamed", "from": old})
            elif new_ok:
                filtered.append({"path": path, "status": "added"})
            elif old_ok:
                filtered.append({"path": old, "status": "deleted"})
            continue
        if is_collectable_path(path):
            filtered.append({"path": path, "status": status})
    filtered.sort(key=lambda row: (row["path"], row["status"], row.get("from") or ""))
    return filtered


def _blob_size(repo_dir: str, commit: str, rel_path: str, url: str = "") -> int | None:
    result = _run_git(["cat-file", "-s", f"{commit}:{rel_path}"], cwd=repo_dir, url=url)
    if result.returncode != 0:
        return None
    try:
        return int((result.stdout or "").strip())
    except ValueError:
        return None


def _blob_prefix(repo_dir: str, commit: str, rel_path: str, url: str = "", limit: int = 8192) -> bytes | None:
    """Read a prefix of a blob. Does not return the bytes to callers of /changes."""
    try:
        proc = subprocess.Popen(
            ["git", "cat-file", "blob", f"{commit}:{rel_path}"],
            cwd=repo_dir,
            env=build_git_env(url),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    try:
        if proc.stdout is None:
            return None
        return proc.stdout.read(limit)
    finally:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.wait()


def _annotate_eligibility(
    repo_dir: str,
    previous: str,
    current: str,
    changed: list[dict[str, str]],
    url: str = "",
) -> list[dict[str, Any]]:
    """Attach per-file collectability. Never uses the total collection budget."""
    annotated: list[dict[str, Any]] = []
    for row in changed:
        status = row.get("status") or ""
        path = row.get("path") or ""
        commit = previous if status == "deleted" else current
        size = _blob_size(repo_dir, commit, path, url) if commit else None
        reason = ""
        if size is not None:
            reason = _skip_reason(Path(path).name, size, DEFAULT_MAX_FILE_BYTES)
        if not reason and status != "deleted" and commit:
            sample = _blob_prefix(repo_dir, commit, path, url)
            if sample is not None:
                reason = content_skip_reason(sample)
        item: dict[str, Any] = {
            "path": path,
            "status": status,
            "eligible": not bool(reason),
        }
        if row.get("from"):
            item["from"] = row["from"]
        if reason:
            item["reason"] = reason
        annotated.append(item)
    annotated.sort(key=lambda row: (row["path"], row["status"], row.get("from") or ""))
    return annotated


def _commit_parents(repo_dir: str, sha: str, url: str = "") -> list[str] | None:
    """Parent SHAs from the commit object. Ignores shallow grafts.

    None means the commit object is not readable.
    """
    result = _run_git(["cat-file", "-p", sha], cwd=repo_dir, url=url)
    if result.returncode != 0:
        return None
    parents: list[str] = []
    for line in (result.stdout or "").splitlines():
        if line.startswith("parent "):
            parts = line.split()
            if len(parts) >= 2:
                parents.append(parts[1])
            continue
        if line.startswith("author "):
            break
    return parents


def _require_ancestor(repo_dir: str, previous: str, current: str, url: str = "") -> None:
    """Fail closed only when commit objects prove previous is not an ancestor.

    Uses ``cat-file`` parent lines so a depth-1 clone still accepts the
    usual parent→child incremental window. Missing parent objects mean
    incomplete shallow history; keep the existing diff in that case.
    """
    if previous == current:
        return
    pending: deque[str] = deque([current])
    seen: set[str] = set()
    incomplete = False
    while pending and len(seen) < 256:
        sha = pending.popleft()
        if sha == previous:
            return
        if sha in seen:
            continue
        seen.add(sha)
        parents = _commit_parents(repo_dir, sha, url)
        if parents is None:
            incomplete = True
            continue
        if previous in parents:
            return
        pending.extend(parent for parent in parents if parent not in seen)
    if previous in seen or previous in pending:
        return
    if incomplete or pending:
        return
    raise CollectorError(
        f"previousCommit '{previous}' is not an ancestor of '{current}'",
        status=400,
    )


def _diff(repo_dir: str, previous: str, current: str, url: str = "") -> list[dict[str, Any]]:
    result = _run_git(
        ["diff", "--name-status", "--find-renames", "-M", previous, current],
        cwd=repo_dir,
        url=url,
    )
    if result.returncode not in (0, 1):
        raise CollectorError(
            f"previousCommit '{previous}' is not a valid diff base for '{current}'",
            status=400,
        )
    return _annotate_eligibility(
        repo_dir,
        previous,
        current,
        _parse_name_status(result.stdout),
        url=url,
    )


def _patches(
    repo_dir: str,
    previous: str,
    current: str,
    changed: list[dict[str, Any]],
    url: str = "",
) -> list[dict[str, str]]:
    """Truncated git patches for changed paths. Never used unless requested."""
    diffs: list[dict[str, str]] = []
    for row in changed:
        path = str(row.get("path") or "")
        src = str(row.get("from") or "")
        if not path:
            continue
        args = ["diff", "--find-renames", "-M", previous, current, "--"]
        if src:
            args.extend([src, path])
        else:
            args.append(path)
        result = _run_git(args, cwd=repo_dir, url=url)
        patch = result.stdout or ""
        if len(patch) > MAX_DIFF_CHARS:
            patch = patch[:MAX_DIFF_CHARS] + "\n... [diff truncated]\n"
        diffs.append({"path": path, "patch": sanitize(patch)})
    diffs.sort(key=lambda row: row["path"])
    return diffs


def _local_repo(source: str, local_root: str | None) -> str:
    repo_dir = os.path.abspath(os.path.expanduser(source))
    if local_root:
        allowed = os.path.abspath(local_root)
        if os.path.commonpath([allowed, repo_dir]) != allowed:
            raise CollectorError(
                f"local path '{source}' is outside the permitted root '{allowed}'",
                status=400,
            )
    if not os.path.isdir(repo_dir):
        raise CollectorError(f"local path '{source}' does not exist or is not a directory", status=400)
    probe = _run_git(["rev-parse", "--is-inside-work-tree"], cwd=repo_dir)
    if probe.returncode != 0 or (probe.stdout or "").strip() != "true":
        raise CollectorError(f"local path '{source}' is not a git repository", status=400)
    return repo_dir


def detect_changes(
    source: str,
    previous_commit: str = "",
    ref: str = "",
    new_commit: str = "",
    local_root: str | None = None,
    include_diffs: bool = False,
) -> dict[str, Any]:
    """Return a deterministic change list between two commits.

    Empty ``previous_commit`` is a first/full documentation run: no diff.
    """
    source = (source or "").strip()
    ref = (ref or "").strip()
    if not source:
        raise CollectorError("no repository was provided", status=400)

    previous = _sha_or_empty(previous_commit, "previousCommit")
    explicit_new = _sha_or_empty(new_commit, "newCommit")
    new_spec = explicit_new or ref

    if is_remote(source):
        validate_remote_url(source)
        from workspace import checkout_commit, ensure_commit, open_remote

        url = strip_userinfo(source)
        with open_remote(source, ref=ref, commit=explicit_new) as repo_dir:
            current = checkout_commit(repo_dir, new_spec or "HEAD", source, url=url)
            if not previous:
                return _result("full", "", current, [])
            old = ensure_commit(repo_dir, previous, source, url=url)
            if old == current:
                return _result("incremental", old, current, [], diffs=[] if include_diffs else None)
            _require_ancestor(repo_dir, old, current, url=url)
            changed = _diff(repo_dir, old, current, url=url)
            diffs = _patches(repo_dir, old, current, changed, url=url) if include_diffs else None
            return _result("incremental", old, current, changed, diffs=diffs)

    repo_dir = _local_repo(source, local_root)
    from workspace import ensure_commit

    current = ensure_commit(repo_dir, new_spec or "HEAD", source)
    if not previous:
        return _result("full", "", current, [])
    old = ensure_commit(repo_dir, previous, source)
    if old == current:
        return _result("incremental", old, current, [], diffs=[] if include_diffs else None)
    _require_ancestor(repo_dir, old, current)
    changed = _diff(repo_dir, old, current)
    diffs = _patches(repo_dir, old, current, changed) if include_diffs else None
    return _result("incremental", old, current, changed, diffs=diffs)


def _result(
    mode: str,
    previous: str,
    current: str,
    changed: list[dict[str, Any]],
    diffs: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "mode": mode,
        "previousCommit": previous,
        "newCommit": current,
        "changed": changed,
    }
    if diffs is not None:
        payload["diffs"] = diffs
    return payload


def describe_source(source: str) -> tuple[str, str]:
    return source_identity(source)
