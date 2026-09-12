"""Deterministic incremental analysis scope from /changes + map/analyzer.

Does not parse source, clone repositories, or call a model.
Uses existing exact map/analyzer relationships only (one reverse hop).
"""

from __future__ import annotations

import json
from typing import Any

from mapper import MapError, build_map, file_of, normalize_path

SCHEMA_VERSION = "1"
CHANGE_STATUSES = {"added", "modified", "deleted", "renamed"}


class ImpactError(ValueError):
    """Invalid incremental-analysis request."""


def _as_object(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ImpactError(f"{name} must be a JSON object")
    return value


def _is_json_path(path: str) -> bool:
    return path.lower().endswith(".json")


def _changed_rows(changes: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in changes.get("changed") or []:
        if not isinstance(item, dict):
            continue
        path = normalize_path(str(item.get("path") or ""))
        status = str(item.get("status") or "")
        if not path or status not in CHANGE_STATUSES:
            continue
        src = normalize_path(str(item.get("from") or ""))
        key = (path, status, src)
        if key in seen:
            continue
        seen.add(key)
        row: dict[str, Any] = {
            "path": path,
            "status": status,
            "eligible": bool(item.get("eligible", True)),
        }
        if src:
            row["from"] = src
        reason = str(item.get("reason") or "")
        if reason:
            row["reason"] = reason
        if _is_json_path(path) or _is_json_path(src):
            row["eligible"] = False
            row.setdefault("reason", "excluded: json file")
        rows.append(row)
    rows.sort(key=lambda row: (row["path"], row["status"], row.get("from") or ""))
    return rows


def _changed_paths(rows: list[dict[str, Any]]) -> set[str]:
    paths: set[str] = set()
    for row in rows:
        paths.add(row["path"])
        if row.get("from"):
            paths.add(str(row["from"]))
    return paths


def _source_paths(rows: list[dict[str, Any]]) -> set[str]:
    """Changed paths that may be documentation/analysis source."""
    paths: set[str] = set()
    for row in rows:
        if row.get("eligible") and not _is_json_path(row["path"]):
            paths.add(row["path"])
        src = str(row.get("from") or "")
        if src and not _is_json_path(src) and row.get("status") == "renamed":
            paths.add(src)
    return paths


def _normalize_map(analysis: dict[str, Any], repository_map: dict[str, Any]) -> dict[str, Any]:
    if repository_map:
        if not isinstance(repository_map.get("modules"), list):
            raise ImpactError("repository map must include modules")
        return repository_map
    if analysis:
        try:
            return build_map(analysis)
        except MapError as exc:
            raise ImpactError(str(exc)) from exc
    return {}


def _dependents(repo_map: dict[str, Any]) -> dict[str, set[str]]:
    """Reverse exact module relationships: dependency → dependents."""
    known = {normalize_path(str(row.get("path") or "")) for row in repo_map.get("modules") or [] if isinstance(row, dict)}
    known.discard("")
    dependents: dict[str, set[str]] = {}

    def add(src: str, dst: str) -> None:
        if not src or not dst or src == dst:
            return
        dependents.setdefault(dst, set()).add(src)

    for edge in repo_map.get("moduleRelationships") or []:
        if not isinstance(edge, dict) or edge.get("certainty") != "exact":
            continue
        add(normalize_path(str(edge.get("from") or "")), normalize_path(str(edge.get("to") or "")))

    for ref in repo_map.get("relationships") or []:
        if not isinstance(ref, dict) or ref.get("certainty") != "exact":
            continue
        src = file_of(str(ref.get("from") or ""), known)
        dst = file_of(str(ref.get("to") or ""), known)
        if src and dst:
            add(src, dst)
    return dependents


def _symbols_by_path(repo_map: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in repo_map.get("symbols") or []:
        if not isinstance(item, dict) or not item.get("qualname"):
            continue
        path = normalize_path(str(item.get("path") or ""))
        if not path or _is_json_path(path):
            continue
        grouped.setdefault(path, []).append(
            {
                "kind": str(item.get("kind") or ""),
                "name": str(item.get("name") or ""),
                "qualname": str(item["qualname"]),
                "path": path,
            }
        )
    for rows in grouped.values():
        rows.sort(key=lambda row: (row["qualname"], row["kind"]))
    return grouped


def analyze_impact(
    changes: dict[str, Any] | None = None,
    analysis: dict[str, Any] | None = None,
    repository_map: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return changed files, one-hop dependents, and affected symbols/modules."""
    changes = _as_object(changes, "changes")
    analysis = _as_object(analysis, "analysis")
    repository_map = _as_object(repository_map, "repositoryMap")
    repo_map = _normalize_map(analysis, repository_map)

    changed = _changed_rows(changes)
    changed_paths = _changed_paths(changed)
    source_changed = _source_paths(changed)
    dependents = _dependents(repo_map)
    symbols = _symbols_by_path(repo_map)

    affected_map: dict[str, dict[str, Any]] = {}
    for path in sorted(source_changed):
        for dep in sorted(dependents.get(path) or ()):
            if dep in changed_paths or _is_json_path(dep):
                continue
            row = affected_map.setdefault(dep, {"path": dep, "reasons": []})
            reason = f"depends-on:{path}"
            if reason not in row["reasons"]:
                row["reasons"].append(reason)

    affected = [affected_map[path] for path in sorted(affected_map)]
    for row in affected:
        row["reasons"].sort()

    modules = sorted(source_changed | set(affected_map))
    affected_symbols: list[dict[str, Any]] = []
    for path in modules:
        affected_symbols.extend(symbols.get(path) or [])
    affected_symbols.sort(key=lambda row: (row["path"], row["qualname"], row["kind"]))

    return {
        "schemaVersion": SCHEMA_VERSION,
        "mode": str(changes.get("mode") or ("full" if not changed else "incremental")),
        "previousCommit": str(changes.get("previousCommit") or ""),
        "newCommit": str(changes.get("newCommit") or ""),
        "changed": changed,
        "affected": affected,
        "affectedModules": modules,
        "affectedSymbols": affected_symbols,
    }


def normalize_request(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ImpactError("request body must be a JSON object")
    if payload.get("repository") or payload.get("url") or payload.get("dump"):
        raise ImpactError("repository URL and dump are not accepted")
    changes = payload.get("changes")
    if changes is None and payload.get("changesJson") is not None:
        raw = payload.get("changesJson")
        if isinstance(raw, dict):
            changes = raw
        elif isinstance(raw, str) and raw.strip():
            try:
                changes = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ImpactError(f"changesJson is not valid JSON: {exc}") from exc
        else:
            raise ImpactError("changesJson must be /changes JSON")
    analysis = payload.get("analysis")
    if analysis is None and payload.get("analysisJson") is not None:
        raw = payload.get("analysisJson")
        if isinstance(raw, dict):
            analysis = raw
        elif isinstance(raw, str) and raw.strip():
            try:
                analysis = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ImpactError(f"analysisJson is not valid JSON: {exc}") from exc
        else:
            raise ImpactError("analysisJson must be analyzer JSON")
    repository_map = payload.get("repositoryMap") or payload.get("map")
    if repository_map is None and payload.get("repositoryMapJson") is not None:
        raw = payload.get("repositoryMapJson")
        if isinstance(raw, dict):
            repository_map = raw
        elif isinstance(raw, str) and raw.strip():
            try:
                repository_map = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ImpactError(f"repositoryMapJson is not valid JSON: {exc}") from exc
        else:
            raise ImpactError("repositoryMapJson must be repository-map JSON")
    return analyze_impact(changes, analysis, repository_map)
