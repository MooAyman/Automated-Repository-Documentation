"""Deterministic repository analyzer.

Accepts already-sanitized per-file source (preferred) or a sanitized
collector dump. Never clones repositories, never reads collector entries,
and never walks a filesystem repository.
"""

from __future__ import annotations

import re
from typing import Any

from languages import ANALYZERS, PYTHON, language_for

SCHEMA_VERSION = "1"
FILE_BANNER = re.compile(r"^={50}\nFILE: ([^\n]+)\n={50}\n?", re.MULTILINE)
EXCLUDED_HEADER = re.compile(r"^EXCLUDED FILES\n-+\n+", re.MULTILINE)


class AnalyzerError(ValueError):
    """Invalid analyzer request."""


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip().lstrip("./")


def files_from_dump(dump: str) -> list[dict[str, str]]:
    """Split a sanitized collector dump into per-file path/content pairs."""
    matches = list(FILE_BANNER.finditer(dump))
    files: list[dict[str, str]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(dump)
        files.append(
            {
                "path": normalize_path(match.group(1)),
                "content": dump[match.end() : end].strip("\n"),
            }
        )
    return files


def excluded_from_dump(dump: str) -> list[dict[str, str]]:
    """Read path/reason rows from the dump EXCLUDED FILES list. Never contents."""
    header = EXCLUDED_HEADER.search(dump or "")
    if not header:
        return []
    rest = dump[header.end() :]
    nxt = FILE_BANNER.search(rest)
    block = rest[: nxt.start()] if nxt else rest
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in block.splitlines():
        line = raw.strip()
        if not line or " — " not in line:
            continue
        path_text, reason = line.rsplit(" — ", 1)
        path = normalize_path(path_text)
        reason = reason.strip()
        if not path or not reason or path in seen:
            continue
        seen.add(path)
        rows.append({"path": path, "reason": reason})
    rows.sort(key=lambda row: row["path"])
    return rows


def normalize_request(payload: Any) -> list[dict[str, str]]:
    """Prefer sanitized ``files``; otherwise split a sanitized ``dump``."""
    if not isinstance(payload, dict):
        raise AnalyzerError("request body must be a JSON object")
    if payload.get("repository") or payload.get("url"):
        raise AnalyzerError("repository URL is not accepted")

    files_in = payload.get("files")
    if files_in is not None:
        if not isinstance(files_in, list):
            raise AnalyzerError("files must be an array of {path, content}")
        files: list[dict[str, str]] = []
        for item in files_in:
            if not isinstance(item, dict):
                raise AnalyzerError("each file must be an object with path and content")
            path = normalize_path(str(item.get("path") or ""))
            if not path:
                raise AnalyzerError("each file requires a path")
            content = item.get("content")
            if content is None:
                raise AnalyzerError("each file requires sanitized content")
            if not isinstance(content, str):
                raise AnalyzerError("file content must be a string")
            files.append({"path": path, "content": content})
        if not files:
            raise AnalyzerError("files must not be empty")
        return files

    dump = payload.get("dump")
    if isinstance(dump, str) or dump is None:
        # Empty or truncated dumps yield no files. The agent still has the
        # collector dump in context and must continue.
        return files_from_dump(dump or "")

    raise AnalyzerError("already-sanitized files or dump is required")


def analyze_files(files: list[dict[str, str]]) -> dict[str, Any]:
    parsed: list[dict[str, Any]] = []
    unparsed: list[dict[str, str]] = []
    python_files: list[dict[str, str]] = []

    for item in files:
        path = normalize_path(item["path"])
        language = language_for(path)
        if language == PYTHON:
            python_files.append({"path": path, "content": item["content"]})
        else:
            unparsed.append({"path": path, "reason": "unsupported"})

    references: list[dict[str, Any]] = []
    if python_files:
        py_parsed, py_unparsed, references = ANALYZERS[PYTHON].analyze_repository(python_files)
        parsed.extend(py_parsed)
        unparsed.extend(py_unparsed)

    parsed.sort(key=lambda row: row["path"])
    unparsed.sort(key=lambda row: row["path"])
    references.sort(key=lambda row: (row["lineno"], row["kind"], row["from"], row["to"]))
    return {
        "schemaVersion": SCHEMA_VERSION,
        "language": PYTHON,
        "files": parsed,
        "unparsed": unparsed,
        "references": references,
    }


def _ref_file(value: Any) -> str:
    text = str(value or "")
    return normalize_path(text.split("::", 1)[0] if text else "")


def splice_analysis(
    previous: dict[str, Any] | None,
    delta: dict[str, Any] | None,
    changed: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Replace analysis rows for every path in the delta, plus Git deletes.

    Unchanged files and inbound references from files outside the delta
    are kept. Does not invent symbols, APIs, or architecture.
    """
    previous = previous if isinstance(previous, dict) else {}
    delta = delta if isinstance(delta, dict) else {}
    deleted: set[str] = set()
    replaced: set[str] = set()
    for row in changed or []:
        if not isinstance(row, dict):
            continue
        path = normalize_path(str(row.get("path") or ""))
        src = normalize_path(str(row.get("from") or ""))
        status = str(row.get("status") or "")
        if status == "deleted" and path:
            deleted.add(path)
        elif status == "renamed":
            if src:
                deleted.add(src)
            if path:
                replaced.add(path)
        elif path:
            replaced.add(path)
    for row in (delta.get("files") or []) + (delta.get("unparsed") or []):
        if isinstance(row, dict):
            path = normalize_path(str(row.get("path") or ""))
            if path:
                replaced.add(path)
    drop = deleted | replaced

    def keep_row(row: Any) -> bool:
        return isinstance(row, dict) and normalize_path(str(row.get("path") or "")) not in drop

    def merge_rows(previous_rows: Any, delta_rows: Any) -> list[dict[str, Any]]:
        by_path: dict[str, dict[str, Any]] = {}
        for row in previous_rows or []:
            if keep_row(row):
                path = normalize_path(str(row.get("path") or ""))
                if path and path not in by_path:
                    by_path[path] = row
        for row in delta_rows or []:
            if not isinstance(row, dict):
                continue
            path = normalize_path(str(row.get("path") or ""))
            if path:
                by_path[path] = row
        return list(by_path.values())

    files = merge_rows(previous.get("files"), delta.get("files"))
    unparsed = merge_rows(previous.get("unparsed"), delta.get("unparsed"))

    refs: list[dict[str, Any]] = []
    for row in previous.get("references") or []:
        if not isinstance(row, dict):
            continue
        frm = _ref_file(row.get("from"))
        to = _ref_file(row.get("to"))
        if frm in drop or to in deleted:
            continue
        refs.append(row)
    refs.extend(row for row in (delta.get("references") or []) if isinstance(row, dict))

    files.sort(key=lambda row: row.get("path") or "")
    unparsed.sort(key=lambda row: row.get("path") or "")
    refs.sort(key=lambda row: (row.get("lineno") or 0, row.get("kind") or "", row.get("from") or "", row.get("to") or ""))
    return {
        "schemaVersion": str(previous.get("schemaVersion") or delta.get("schemaVersion") or SCHEMA_VERSION),
        "language": str(previous.get("language") or delta.get("language") or PYTHON),
        "files": files,
        "unparsed": unparsed,
        "references": refs,
    }


def analyze(payload: Any) -> dict[str, Any]:
    excluded = excluded_from_dump(payload.get("dump") or "") if isinstance(payload, dict) else []
    result = analyze_files(normalize_request(payload))
    seen = {row["path"] for row in result["files"]}
    seen.update(row["path"] for row in result["unparsed"])
    extra = [row for row in excluded if row["path"] not in seen]
    if extra:
        result["unparsed"].extend(extra)
        result["unparsed"].sort(key=lambda row: row["path"])
    return result
