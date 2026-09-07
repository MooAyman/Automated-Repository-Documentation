"""Short-lived clone reuse for one pipeline pair of /changes and /collect.

Not a general cache. A workspace is reused only for the same repository
identity and the same ref/commit, and only while a request is using it or
during a brief grace period so the next sequential call can attach.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import threading
import time
from contextlib import contextmanager
from typing import Iterator

import collector

GRACE_SECONDS = float(os.environ.get("WORKSPACE_GRACE_SECONDS", "90"))
_ROOT = os.path.join(tempfile.gettempdir(), "repository-collector-workspaces")
_lock = threading.RLock()
_workspaces: dict[tuple[str, str], "_Workspace"] = {}


class _Workspace:
    def __init__(self, key: tuple[str, str], path: str, url: str, ref: str, head: str, origin: str) -> None:
        self.key = key
        self.path = path
        self.url = url
        self.ref = ref
        self.head = head
        self.origin = origin
        self.refcount = 0
        self.last_release = 0.0
        self.shared = True
        self.lock = threading.RLock()


def reset() -> None:
    """Drop every workspace. Tests only."""
    with _lock:
        items = list(_workspaces.values())
        _workspaces.clear()
    for item in items:
        _remove(item.path)


def _canonical(source: str) -> str:
    return collector.strip_userinfo((source or "").strip()).rstrip("/").lower()


def _key(source: str, ref: str) -> tuple[str, str]:
    return (_canonical(source), (ref or "").strip())


def _same_sha(left: str, right: str) -> bool:
    """Exact canonical SHA equality. Prefix matches are not equal."""
    a = (left or "").strip().lower()
    b = (right or "").strip().lower()
    return bool(a) and a == b


def _head(repo_dir: str) -> str:
    result = collector._run_git(["rev-parse", "HEAD"], cwd=repo_dir)
    return (result.stdout or "").strip() if result.returncode == 0 else ""


def _origin_url(repo_dir: str) -> str:
    result = collector._run_git(["remote", "get-url", "origin"], cwd=repo_dir)
    if result.returncode != 0:
        return ""
    return collector.strip_userinfo((result.stdout or "").strip()).rstrip("/").lower()


def _resolved_commit(repo_dir: str, spec: str) -> str:
    if not spec:
        return ""
    result = collector._run_git(["rev-parse", "--verify", f"{spec}^{{commit}}"], cwd=repo_dir)
    return (result.stdout or "").strip() if result.returncode == 0 else ""


def _is_valid(item: _Workspace, commit: str = "") -> bool:
    git_dir = os.path.join(item.path, ".git")
    if not os.path.isdir(item.path) or not os.path.exists(git_dir):
        return False
    head = _head(item.path)
    if not head or not _same_sha(head, item.head):
        return False
    if commit:
        resolved = _resolved_commit(item.path, commit)
        if not resolved or not _same_sha(head, resolved):
            return False
    if _origin_url(item.path) != item.origin:
        return False
    return True


def _remove(path: str) -> None:
    if not path or not os.path.exists(path):
        return

    def _onexc(_func, name, exc) -> None:  # noqa: ARG001
        try:
            os.chmod(name, stat.S_IWRITE)
            os.remove(name)
        except OSError:
            if isinstance(exc, BaseException):
                raise exc

    shutil.rmtree(path, onexc=_onexc)


def _expire_unlocked(now: float) -> None:
    stale = []
    for key, item in list(_workspaces.items()):
        if item.refcount > 0:
            continue
        if now - item.last_release <= GRACE_SECONDS and _is_valid(item):
            continue
        stale.append(key)
    for key in stale:
        item = _workspaces.pop(key, None)
        if item is not None:
            _remove(item.path)


def _lookup(url: str, ref: str, commit: str) -> _Workspace | None:
    exact = _workspaces.get((url, ref))
    if exact and _is_valid(exact, commit):
        return exact
    if commit:
        for item in _workspaces.values():
            if item.url == url and _is_valid(item, commit):
                return item
    return None


def acquire(source: str, ref: str = "", commit: str = "") -> _Workspace:
    """Return a workspace for this repository/ref, cloning only when needed."""
    collector.validate_remote_url(source)
    url = _canonical(source)
    ref = (ref or "").strip()
    commit = (commit or "").strip()
    key = (url, ref)
    with _lock:
        _expire_unlocked(time.time())
        item = _lookup(url, ref, commit)
        if item is None:
            occupied = _workspaces.get(key)
            if occupied is not None and occupied.refcount == 0:
                _workspaces.pop(key, None)
                _remove(occupied.path)
                occupied = None
            dest = tempfile.mkdtemp(prefix="repo-ws-", dir=_ensure_root())
            try:
                collector.clone_remote(source, commit or ref, dest)
                head = _head(dest)
                if not head:
                    raise collector.CollectorError(
                        "Requested ref not found: clone did not resolve HEAD",
                        status=404,
                    )
                if commit:
                    head = checkout_commit(dest, commit, source)
                item = _Workspace(key, dest, url, ref, head, _origin_url(dest))
                if occupied is None:
                    _workspaces[key] = item
                else:
                    item.shared = False
            except Exception:
                _remove(dest)
                raise
        item.refcount += 1
        return item


def release(item: _Workspace) -> None:
    with _lock:
        item.refcount = max(0, item.refcount - 1)
        item.last_release = time.time()
        if item.refcount == 0 and not item.shared:
            _remove(item.path)
            return
        _expire_unlocked(time.time())


def _discard(item: _Workspace) -> None:
    with _lock:
        for key, existing in list(_workspaces.items()):
            if existing is item:
                _workspaces.pop(key, None)
        _remove(item.path)


@contextmanager
def open_remote(source: str, ref: str = "", commit: str = "") -> Iterator[str]:
    """Clone or reuse a remote workspace. Always leave HEAD on the new commit."""
    item = acquire(source, ref=ref, commit=commit)
    try:
        with item.lock:
            if _align_head(item, source, commit):
                yield item.path
                return
    finally:
        release(item)

    if item.refcount == 0:
        _discard(item)
    item = acquire(source, ref=ref, commit=commit)
    try:
        with item.lock:
            if not _align_head(item, source, commit):
                raise collector.CollectorError(
                    "could not check out requested commit",
                    status=409,
                )
            yield item.path
    finally:
        release(item)


def _align_head(item: _Workspace, source: str, commit: str) -> bool:
    """Checkout ``commit`` when given. False if HEAD cannot match the request."""
    try:
        if commit:
            item.head = checkout_commit(item.path, commit, source)
        return _is_valid(item, commit)
    except collector.CollectorError:
        return False


def checkout_commit(repo_dir: str, spec: str, source: str, url: str = "") -> str:
    """Fetch ``spec`` if needed and check out that exact commit.

    If the workspace cannot be moved to the requested SHA, raise so the
    caller can discard it. Does not apply the collection budget.
    """
    resolved = ensure_commit(repo_dir, spec, source, url)
    if _same_sha(_head(repo_dir), resolved):
        return resolved
    result = collector._run_git(
        ["checkout", "--force", "--detach", resolved],
        cwd=repo_dir,
        url=url,
    )
    if result.returncode != 0 or not _same_sha(_head(repo_dir), resolved):
        raise collector.CollectorError(
            f"could not check out requested commit {resolved[:12]}",
            status=409,
        )
    return resolved


def has_commit(repo_dir: str, spec: str) -> bool:
    result = collector._run_git(["rev-parse", "--verify", f"{spec}^{{commit}}"], cwd=repo_dir)
    return result.returncode == 0 and bool((result.stdout or "").strip())


def ensure_commit(repo_dir: str, spec: str, source: str, url: str = "") -> str:
    """Resolve ``spec`` to a commit, fetching only that object when the clone is shallow.

    Does not check out the fetched commit. Does not apply the collection budget.
    """
    if has_commit(repo_dir, spec):
        return _resolve(repo_dir, spec, source, url)
    _fetch_commit(repo_dir, spec, source, url)
    if not has_commit(repo_dir, spec):
        raise collector.CollectorError(
            f"Requested ref not found: '{spec}' does not exist in {collector.redact(collector.strip_userinfo(source))}",
            status=404,
        )
    return _resolve(repo_dir, spec, source, url)


def _resolve(repo_dir: str, spec: str, source: str, url: str = "") -> str:
    result = collector._run_git(
        ["rev-parse", "--verify", f"{spec}^{{commit}}"],
        cwd=repo_dir,
        url=url,
    )
    if result.returncode != 0 or not (result.stdout or "").strip():
        raise collector.CollectorError(
            f"Requested ref not found: '{spec}' does not exist in {collector.redact(collector.strip_userinfo(source))}",
            status=404,
        )
    return result.stdout.strip()


def _fetch_commit(repo_dir: str, spec: str, source: str, url: str = "") -> None:
    origin = url or _origin_url(repo_dir)
    if not origin:
        raise collector.CollectorError(
            f"Requested ref not found: '{spec}' is not in this checkout and cannot be fetched",
            status=404,
        )
    fetch = collector._run_git(
        ["fetch", "--depth", "1", "--no-tags", "origin", spec],
        cwd=repo_dir,
        url=origin,
    )
    if fetch.returncode == 0:
        return
    fetch = collector._run_git(
        ["fetch", "--no-tags", "origin", spec],
        cwd=repo_dir,
        url=origin,
    )
    if fetch.returncode != 0:
        raise collector.CollectorError(
            f"Requested ref not found: '{spec}' does not exist in {collector.redact(collector.strip_userinfo(source))}",
            status=404,
        )


def _ensure_root() -> str:
    os.makedirs(_ROOT, exist_ok=True)
    return _ROOT
