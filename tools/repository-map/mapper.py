"""Deterministic Repository Map.

Consumes already-sanitized repository-analyzer JSON. Does not parse source,
resolve references, clone repositories, or call a model.
"""

from __future__ import annotations

import json
from typing import Any

SCHEMA_VERSION = "1"
RELATIONSHIP_KINDS = ("import", "inherit", "decorate", "call")


class MapError(ValueError):
    """Invalid repository-map request."""


def normalize_path(path: str) -> str:
    return str(path).replace("\\", "/").strip().lstrip("./")


def language_for(path: str) -> str | None:
    lowered = normalize_path(path).rsplit("/", 1)[-1].lower()
    if lowered.endswith(".py"):
        return "python"
    return None


def file_of(ref: str, known: set[str]) -> str | None:
    text = str(ref or "")
    path = text.split("::", 1)[0] if "::" in text else text
    path = normalize_path(path)
    if path in known:
        return path
    return None


def normalize_request(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise MapError("request body must be a JSON object")
    analysis = payload.get("analysis")
    if analysis is None and payload.get("analysisJson") is not None:
        raw = payload.get("analysisJson")
        if isinstance(raw, dict):
            analysis = raw
        elif isinstance(raw, str) and raw.strip():
            try:
                analysis = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise MapError(f"analysisJson is not valid JSON: {exc}") from exc
        else:
            raise MapError("analysisJson must be analyzer JSON")
    if not isinstance(analysis, dict):
        raise MapError("already-sanitized analyzer JSON is required")
    if not all(isinstance(analysis.get(key), list) for key in ("files", "unparsed", "references")):
        raise MapError("analysis must be repository-analyzer output")
    return analysis


def _module_row(path: str, status: str, reason: str | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {
        "path": path,
        "language": language_for(path),
        "status": status,
    }
    if reason:
        row["reason"] = reason
    return row


def _symbol_rows(path: str, file_row: dict[str, Any]) -> list[dict[str, Any]]:
    symbols: list[dict[str, Any]] = []
    for cls in file_row.get("classes") or []:
        if not isinstance(cls, dict) or not cls.get("qualname"):
            continue
        symbols.append(
            {
                "kind": "class",
                "name": str(cls.get("name") or ""),
                "qualname": str(cls["qualname"]),
                "path": path,
                "lineno": int(cls["lineno"]) if isinstance(cls.get("lineno"), int) else None,
            }
        )
    for fn in file_row.get("functions") or []:
        if not isinstance(fn, dict) or not fn.get("qualname"):
            continue
        kind = fn.get("kind") if fn.get("kind") in {"function", "method"} else "function"
        symbols.append(
            {
                "kind": kind,
                "name": str(fn.get("name") or ""),
                "qualname": str(fn["qualname"]),
                "path": path,
                "lineno": int(fn["lineno"]) if isinstance(fn.get("lineno"), int) else None,
            }
        )
    symbols.sort(key=lambda row: (row["path"], row["lineno"] is None, row["lineno"] or 0, row["kind"], row["qualname"]))
    return symbols


def _relationship_rows(references: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for ref in references:
        if not isinstance(ref, dict):
            continue
        kind = ref.get("kind")
        if kind not in RELATIONSHIP_KINDS:
            continue
        certainty = ref.get("certainty")
        if certainty not in {"exact", "unresolved"}:
            continue
        frm = str(ref.get("from") or "")
        to = str(ref.get("to") or "")
        if not frm or not to:
            continue
        lineno = ref.get("lineno")
        rows.append(
            {
                "kind": kind,
                "from": frm,
                "to": to,
                "lineno": int(lineno) if isinstance(lineno, int) else None,
                "certainty": certainty,
            }
        )
    rows.sort(key=lambda row: (row["lineno"] is None, row["lineno"] or 0, row["kind"], row["from"], row["to"]))
    return rows


def _directories(paths: list[str]) -> list[dict[str, str]]:
    init_dirs = {path.rsplit("/", 1)[0] for path in paths if path.endswith("/__init__.py") and "/" in path}
    if "__init__.py" in paths:
        init_dirs.add("")
    dirs: set[str] = set()
    for path in paths:
        parts = path.split("/")[:-1]
        prefix: list[str] = []
        for part in parts:
            prefix.append(part)
            dirs.add("/".join(prefix))
    rows = []
    for path in sorted(dirs):
        rows.append(
            {
                "path": path,
                "kind": "package" if path in init_dirs else "directory",
            }
        )
    return rows


def _tree(modules: list[dict[str, Any]]) -> dict[str, Any]:
    def node(name: str, kind: str, path: str | None = None) -> dict[str, Any]:
        item: dict[str, Any] = {"name": name, "kind": kind, "children": []}
        if path:
            item["path"] = path
        return item

    root = node("", "directory")
    index: dict[str, dict[str, Any]] = {"": root}

    for module in modules:
        path = module["path"]
        parts = path.split("/")
        current = ""
        for i, part in enumerate(parts):
            parent = current
            current = part if not parent else f"{parent}/{part}"
            if current in index:
                continue
            is_leaf = i == len(parts) - 1
            if is_leaf:
                leaf = {
                    "name": part,
                    "kind": "module",
                    "path": path,
                    "language": module.get("language"),
                    "status": module["status"],
                }
                if module.get("reason"):
                    leaf["reason"] = module["reason"]
                index[current] = leaf
                index[parent]["children"].append(leaf)
            else:
                directory = node(part, "directory", current)
                index[current] = directory
                index[parent]["children"].append(directory)

    def sort_children(item: dict[str, Any]) -> None:
        kids = item.get("children")
        if not kids:
            item.pop("children", None)
            return
        kids.sort(key=lambda child: (0 if child["kind"] == "directory" else 1, child["name"]))
        for child in kids:
            sort_children(child)

    sort_children(root)
    return root


def _module_relationships(
    relationships: list[dict[str, Any]], known: set[str]
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], set[str]] = {}
    for ref in relationships:
        if ref["certainty"] != "exact":
            continue
        src = file_of(ref["from"], known)
        dst = file_of(ref["to"], known)
        if not src or not dst or src == dst:
            continue
        grouped.setdefault((src, dst), set()).add(ref["kind"])
    rows = [
        {
            "from": src,
            "to": dst,
            "kinds": sorted(kinds),
            "certainty": "exact",
        }
        for (src, dst), kinds in grouped.items()
    ]
    rows.sort(key=lambda row: (row["from"], row["to"]))
    return rows


def build_map(analysis: dict[str, Any]) -> dict[str, Any]:
    modules: list[dict[str, Any]] = []
    symbols: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in analysis.get("files") or []:
        if not isinstance(item, dict):
            continue
        path = normalize_path(str(item.get("path") or ""))
        if not path or path in seen:
            continue
        seen.add(path)
        modules.append(_module_row(path, "parsed"))
        symbols.extend(_symbol_rows(path, item))

    for item in analysis.get("unparsed") or []:
        if not isinstance(item, dict):
            continue
        path = normalize_path(str(item.get("path") or ""))
        if not path or path in seen:
            continue
        seen.add(path)
        reason = str(item.get("reason") or "unparsed")
        status = "excluded" if reason.startswith(("excluded:", "omitted:")) else "unparsed"
        modules.append(_module_row(path, status, reason))

    modules.sort(key=lambda row: row["path"])
    relationships = _relationship_rows(analysis.get("references") or [])
    known = {row["path"] for row in modules}
    return {
        "schemaVersion": SCHEMA_VERSION,
        "modules": modules,
        "symbols": symbols,
        "relationships": relationships,
        "directories": _directories([row["path"] for row in modules]),
        "tree": _tree(modules),
        "moduleRelationships": _module_relationships(relationships, known),
    }


def build(payload: Any) -> dict[str, Any]:
    return build_map(normalize_request(payload))
