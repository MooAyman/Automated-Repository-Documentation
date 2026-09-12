"""Deterministic merge of previous documentation with an incremental update.

The host selects ``updateFields`` from Git impact plus path mentions already
present in the six-field document. Incremental Agents emit ``updates`` patches
for those fields only. Merge does not infer incrementality from a full-schema
regeneration, and does not invent semantic claims for Git path coverage.
"""

from __future__ import annotations

import copy
import re
from typing import Any

REQUIRED_ROOT = (
    "repositoryOverview",
    "repositoryStructure",
    "toolsAndTechnologies",
    "coreConceptsAndArchitecture",
    "categorizedTechnicalInformation",
    "developerOnboardingGuide",
)
REQUIRED_OVERVIEW = ("summary", "quickStart")
REQUIRED_ARCHITECTURE = ("summary", "requestFlow", "buildAndPackagingFlow")
REQUIRED_CATEGORIZED = (
    "mainApisAndEndpoints",
    "mainServicesAndMediators",
    "dtosSchemasMetadata",
    "securityComponents",
    "configurations",
    "entryPoints",
    "tests",
    "risksAndTechnicalDebt",
)
REQUIRED_ONBOARDING = (
    "first30Minutes",
    "howToInvestigateAProductionBug",
    "criticalFiles",
    "commonMistakes",
)

LEAF_FIELDS: tuple[tuple[str, ...], ...] = (
    ("repositoryOverview", "summary"),
    ("repositoryOverview", "quickStart"),
    ("repositoryStructure",),
    ("toolsAndTechnologies",),
    ("coreConceptsAndArchitecture", "summary"),
    ("coreConceptsAndArchitecture", "requestFlow"),
    ("coreConceptsAndArchitecture", "buildAndPackagingFlow"),
    *tuple(("categorizedTechnicalInformation", key) for key in REQUIRED_CATEGORIZED),
    *tuple(("developerOnboardingGuide", key) for key in REQUIRED_ONBOARDING),
)

_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9._-])((?:[A-Za-z0-9._-]+/)+[A-Za-z0-9._-]+\.[A-Za-z0-9]+|[A-Za-z0-9._-]+\.(?:py|md|ya?ml|toml|ini|cfg|txt|ts|js|go|rs|java))",
    re.I,
)
_FILE_HEADER = re.compile(r"^FILE: (.+)$", re.M)
_DUMP_FILE_BANNER = re.compile(r"^={20,}\nFILE: ([^\n]+)\n={20,}\n?", re.MULTILINE)
_DUMP_SECTION = re.compile(r"^={20,}\n(FILE|DIFF): ([^\n]+)\n={20,}\n?", re.MULTILINE)
_PLACEHOLDER_FILE = re.compile(
    r"\n={20,}\nFILE: ([^\n]+)\n={20,}\n+\(no current body:[^\n]*\)\n*",
)
UNCHANGED_PREFIX = "UNCHANGED:"
_README_NAMES = {"readme.md", "readme.rst", "readme.txt"}


def _is_json_path(path: str) -> bool:
    return path.lower().endswith(".json")


def _rel(path: str) -> str:
    return (path or "").replace("\\", "/").lstrip("./").strip()


def extract_paths(text: str) -> list[str]:
    """Relative-path mentions in a documentation section. JSON files are ignored."""
    found: list[str] = []
    seen: set[str] = set()
    for match in _PATH_RE.findall(text or ""):
        path = _rel(str(match))
        if not path or _is_json_path(path) or path in seen:
            continue
        seen.add(path)
        found.append(path)
    return found


def field_key(parts: tuple[str, ...]) -> str:
    return ".".join(parts)


LEAF_FIELD_KEYS = tuple(field_key(parts) for parts in LEAF_FIELDS)


def parse_field_key(key: str) -> tuple[str, ...]:
    return tuple(part for part in str(key or "").split(".") if part)


def get_field(document: dict[str, Any], parts: tuple[str, ...]) -> str:
    current: Any = document
    for part in parts:
        if not isinstance(current, dict):
            return ""
        current = current.get(part)
    return current if isinstance(current, str) else ""


def set_field(document: dict[str, Any], parts: tuple[str, ...], value: str) -> None:
    current: Any = document
    for part in parts[:-1]:
        nxt = current.setdefault(part, {})
        if not isinstance(nxt, dict):
            nxt = {}
            current[part] = nxt
        current = nxt
    current[parts[-1]] = value


def dump_file_headers(dump: str) -> list[str]:
    """``FILE:`` headers from a collector or incremental dump, excluding placeholders."""
    found: list[str] = []
    seen: set[str] = set()
    bodies = _file_bodies(dump)
    for path, body in bodies.items():
        if "no current body:" in (body or ""):
            continue
        if path in seen:
            continue
        seen.add(path)
        found.append(path)
    if bodies:
        return found
    for match in _FILE_HEADER.finditer(dump or ""):
        path = _rel(match.group(1))
        if not path or _is_json_path(path) or path in seen:
            continue
        seen.add(path)
        found.append(path)
    return found


def strip_placeholder_files(dump: str) -> str:
    """Drop renamed-away FILE stubs from an incremental dump."""
    return _PLACEHOLDER_FILE.sub("\n", dump or "")


def normalize_section_sources(value: Any) -> dict[str, list[str]]:
    """Accept {fieldKey: [paths]} provenance. JSON repository files are ignored."""
    rows: dict[str, list[str]] = {}
    if not isinstance(value, dict):
        return rows
    for key, paths in value.items():
        if not isinstance(paths, (list, tuple)):
            continue
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in paths:
            path = _rel(str(item or ""))
            if not path or _is_json_path(path) or path in seen:
                continue
            seen.add(path)
            cleaned.append(path)
        if cleaned:
            rows[str(key)] = cleaned
    return rows


def section_files(
    document: dict[str, Any] | None,
    explicit: dict[str, list[str]] | None = None,
) -> dict[str, list[str]]:
    """Minimum file-to-section metadata from the document plus optional provenance."""
    rows: dict[str, list[str]] = {}
    if isinstance(document, dict):
        declared = normalize_section_sources(document.get("sectionSources"))
        for parts in LEAF_FIELDS:
            key = field_key(parts)
            paths = extract_paths(get_field(document, parts))
            extra = list(declared.get(key) or [])
            combined = paths + [path for path in extra if path not in paths]
            if combined:
                rows[key] = combined
    if explicit:
        for key, paths in explicit.items():
            existing = rows.setdefault(str(key), [])
            for path in paths:
                text = _rel(str(path or ""))
                if text and not _is_json_path(text) and text not in existing:
                    existing.append(text)
    return rows


def impact_paths(impact: dict[str, Any] | None) -> set[str]:
    paths: set[str] = set()
    if not isinstance(impact, dict):
        return paths
    for row in impact.get("changed") or []:
        if not isinstance(row, dict):
            continue
        path = _rel(str(row.get("path") or ""))
        src = _rel(str(row.get("from") or ""))
        if path and not _is_json_path(path):
            paths.add(path)
        if src and not _is_json_path(src):
            paths.add(src)
    for row in impact.get("affected") or []:
        if isinstance(row, dict):
            path = _rel(str(row.get("path") or ""))
        else:
            path = _rel(str(row or ""))
        if path and not _is_json_path(path):
            paths.add(path)
    for path in impact.get("affectedModules") or []:
        text = _rel(str(path or ""))
        if text and not _is_json_path(text):
            paths.add(text)
    for path in impact.get("scopedFiles") or []:
        text = _rel(str(path or ""))
        if text and not _is_json_path(text):
            paths.add(text)
    return paths


def _base_name(path: str) -> str:
    return _rel(path).rsplit("/", 1)[-1].lower()


def _is_test_path(path: str) -> bool:
    lower = _rel(path).lower()
    base = _base_name(lower)
    return (
        lower.startswith("tests/")
        or lower.startswith("test/")
        or "/tests/" in f"/{lower}"
        or base.startswith("test_")
        or base.endswith("_test.py")
        or base.startswith("debug_")
    )


def _is_readme_path(path: str) -> bool:
    return _base_name(path) in _README_NAMES


def _is_build_path(path: str) -> bool:
    base = _base_name(path)
    return base.startswith("dockerfile") or "docker-compose" in base


def _is_config_path(path: str) -> bool:
    base = _base_name(path)
    lower = _rel(path).lower()
    return (
        base.endswith((".toml", ".ini", ".cfg"))
        or base.endswith(".example")
        or ".env" in base
        or "config" in base
        or "config" in lower
    )


def _fields_for_new_path(path: str) -> set[str]:
    fields = {"repositoryStructure"}
    if _is_test_path(path):
        fields.add("categorizedTechnicalInformation.tests")
    if _is_readme_path(path):
        fields.update({"repositoryOverview.summary", "repositoryOverview.quickStart"})
    if _is_build_path(path):
        fields.add("coreConceptsAndArchitecture.buildAndPackagingFlow")
    if _is_config_path(path):
        fields.add("categorizedTechnicalInformation.configurations")
    return fields


def _fields_for_modified_path(path: str) -> set[str]:
    fields: set[str] = set()
    if _is_readme_path(path):
        fields.update({"repositoryOverview.summary", "repositoryOverview.quickStart"})
    if _is_test_path(path):
        fields.add("categorizedTechnicalInformation.tests")
    if _is_build_path(path):
        fields.add("coreConceptsAndArchitecture.buildAndPackagingFlow")
    if _is_config_path(path):
        fields.add("categorizedTechnicalInformation.configurations")
    return fields


def select_update_fields(
    previous: dict[str, Any] | None,
    impact: dict[str, Any] | None,
) -> list[str]:
    """Leaf fields the LLM is allowed to rewrite for this impact scope."""
    if not isinstance(impact, dict) or impact.get("mode") == "full" or not impact.get("changed"):
        return []
    selected: set[str] = set()
    paths = impact_paths(impact)
    if isinstance(previous, dict):
        for parts in LEAF_FIELDS:
            mentions = {path for path in extract_paths(get_field(previous, parts)) if not _is_json_path(path)}
            if mentions & paths:
                selected.add(field_key(parts))
    for row in impact.get("changed") or []:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "")
        path = _rel(str(row.get("path") or ""))
        src = _rel(str(row.get("from") or ""))
        if path and _is_json_path(path) and (not src or _is_json_path(src)):
            continue
        if status in {"added", "deleted", "renamed"}:
            selected.add("repositoryStructure")
        if status in {"added", "renamed"} and path and not _is_json_path(path):
            selected.update(_fields_for_new_path(path))
        if status == "modified" and path and not _is_json_path(path):
            selected.update(_fields_for_modified_path(path))
    return [field_key(parts) for parts in LEAF_FIELDS if field_key(parts) in selected]


def previous_sections(
    previous: dict[str, Any] | None,
    fields: list[str] | tuple[str, ...] | None,
) -> dict[str, str]:
    """Previous text for the selected fields only."""
    rows: dict[str, str] = {}
    if not isinstance(previous, dict):
        return rows
    for key in fields or []:
        parts = parse_field_key(str(key))
        if parts:
            rows[str(key)] = get_field(previous, parts)
    return rows


def _file_bodies(dump: str) -> dict[str, str]:
    """Current FILE bodies only. Stops at the next FILE or DIFF banner."""
    bodies: dict[str, str] = {}
    matches = list(_DUMP_SECTION.finditer(dump or ""))
    if not matches:
        matches = list(_FILE_HEADER.finditer(dump or ""))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(dump or "")
            path = _rel(match.group(1))
            if path and not _is_json_path(path):
                bodies[path] = (dump or "")[match.end() : end]
        return bodies
    for index, match in enumerate(matches):
        if match.group(1) != "FILE":
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(dump or "")
        path = _rel(match.group(2))
        if path and not _is_json_path(path):
            bodies[path] = (dump or "")[match.end() : end]
    return bodies


def empty_document() -> dict[str, Any]:
    return {
        "repositoryOverview": {key: "" for key in REQUIRED_OVERVIEW},
        "repositoryStructure": "",
        "toolsAndTechnologies": "",
        "coreConceptsAndArchitecture": {key: "" for key in REQUIRED_ARCHITECTURE},
        "categorizedTechnicalInformation": {key: "" for key in REQUIRED_CATEGORIZED},
        "developerOnboardingGuide": {key: "" for key in REQUIRED_ONBOARDING},
    }


def generated_from_updates(updates: list[Any] | None) -> dict[str, Any]:
    """Sparse patch list → six-field document with empty unselected leaves."""
    document = empty_document()
    allowed = set(LEAF_FIELD_KEYS)
    for row in updates or []:
        if not isinstance(row, dict):
            continue
        key = str(row.get("field") or "").strip()
        if key not in allowed:
            continue
        text = row.get("text")
        if not isinstance(text, str):
            continue
        set_field(document, parse_field_key(key), text)
    return document


def in_scope_updates(updates: list[Any] | None, update_fields: list[str] | None) -> list[dict[str, str]]:
    allowed = {str(key) for key in (update_fields or [])}
    applied: list[dict[str, str]] = []
    for row in updates or []:
        if not isinstance(row, dict):
            continue
        key = str(row.get("field") or "").strip()
        text = row.get("text")
        if key not in allowed or not isinstance(text, str):
            continue
        if not text.strip() or is_unchanged_placeholder(text):
            continue
        applied.append({"field": key, "text": text})
    return applied


def grounded_paths(impact: dict[str, Any] | None, dump: str = "") -> list[str]:
    """Paths the LLM may cite: impact, FILE headers, and paths named in the dump."""
    paths = impact_paths(impact)
    paths.update(dump_file_headers(dump))
    paths.update(extract_paths(dump or ""))
    return sorted(path for path in paths if path and not _is_json_path(path))


def prepare_incremental_impact(
    previous: dict[str, Any] | None,
    impact: dict[str, Any] | None,
    scoped_dump: str = "",
    scoped_files: list[str] | None = None,
) -> dict[str, Any]:
    """Attach host-selected fields and grounded paths to impact JSON."""
    prepared = dict(impact or {})
    files = [_rel(path) for path in (scoped_files or []) if _rel(path) and not _is_json_path(path)]
    if not files:
        files = dump_file_headers(scoped_dump)
    if files:
        prepared["scopedFiles"] = files
    prepared["updateFields"] = select_update_fields(previous, prepared)
    prepared["groundedPaths"] = grounded_paths(prepared, scoped_dump)
    return prepared


def is_unchanged_placeholder(text: str) -> bool:
    """True when the Agent marked a field as out of incremental scope."""
    return (text or "").strip().startswith(UNCHANGED_PREFIX)


def _allowed_paths_for_field(
    parts: tuple[str, ...],
    previous: dict[str, Any],
    impact: dict[str, Any],
) -> set[str]:
    allowed = set(impact.get("groundedPaths") or [])
    if not allowed:
        allowed = set(grounded_paths(impact))
    allowed.update(extract_paths(get_field(previous, parts)))
    allowed.update(impact_paths(impact))
    return {path for path in allowed if path and not _is_json_path(path)}


def unsupported_paths(text: str, allowed: set[str]) -> list[str]:
    extra: list[str] = []
    seen: set[str] = set()
    for path in extract_paths(text):
        if path in allowed or path in seen:
            continue
        seen.add(path)
        extra.append(path)
    return extra


def _document_blob(document: dict[str, Any]) -> str:
    chunks = [get_field(document, parts) for parts in LEAF_FIELDS]
    return "\n".join(chunks)


def rewrite_stale_paths(document: dict[str, Any], impact: dict[str, Any] | None) -> dict[str, Any]:
    """Replace renamed paths and mark leftover deleted paths in every leaf."""
    if not isinstance(document, dict) or not isinstance(impact, dict):
        return document
    replacements: list[tuple[str, str]] = []
    deleted: list[str] = []
    for row in impact.get("changed") or []:
        if not isinstance(row, dict):
            continue
        path = _rel(str(row.get("path") or ""))
        src = _rel(str(row.get("from") or ""))
        status = str(row.get("status") or "")
        if status == "renamed" and src and path and not _is_json_path(src) and not _is_json_path(path):
            replacements.append((src, path))
        if status == "deleted" and path and not _is_json_path(path):
            deleted.append(path)
    replacements.sort(key=lambda item: len(item[0]), reverse=True)
    deleted.sort(key=len, reverse=True)
    for parts in LEAF_FIELDS:
        text = get_field(document, parts)
        updated = text
        for old, new in replacements:
            updated = updated.replace(old, new)
        for gone in deleted:
            marker = f"{gone} (removed)"
            if gone in updated and marker not in updated:
                updated = updated.replace(gone, marker)
        if updated != text:
            set_field(document, parts, updated)
    return document


def ensure_change_coverage(document: dict[str, Any], impact: dict[str, Any] | None) -> dict[str, Any]:
    """Deterministically mention added/renamed/deleted paths if omitted.

    Path-level Git coverage only. Does not invent APIs, architecture, or other
    semantic claims, including README prose.
    """
    if not isinstance(document, dict) or not isinstance(impact, dict):
        return document
    tests_key = ("categorizedTechnicalInformation", "tests")
    tests_text = get_field(document, tests_key)
    for row in impact.get("changed") or []:
        if not isinstance(row, dict) or not row.get("eligible", True):
            continue
        path = _rel(str(row.get("path") or ""))
        status = str(row.get("status") or "")
        if path and not _is_json_path(path) and status in {"added", "renamed"} and _is_test_path(path):
            if path not in tests_text:
                tests_text = (tests_text.rstrip() + f" `{path}` is included in the test suite.").strip()
                set_field(document, tests_key, tests_text)
    blob = _document_blob(document)
    notes: list[str] = []
    for row in impact.get("changed") or []:
        if not isinstance(row, dict) or not row.get("eligible", True):
            continue
        path = _rel(str(row.get("path") or ""))
        status = str(row.get("status") or "")
        if not path or _is_json_path(path):
            continue
        if status == "added" and path not in blob:
            notes.append(f"`{path}` was added.")
        elif status == "renamed" and path not in blob:
            notes.append(f"`{path}` is the current path after a rename.")
        elif status == "deleted" and path in blob and f"{path} (removed)" not in blob:
            notes.append(f"`{path}` was deleted.")
    if notes:
        current = get_field(document, ("repositoryStructure",))
        extra = " ".join(notes)
        if extra not in current:
            set_field(document, ("repositoryStructure",), (current.rstrip() + "\n" + extra).strip())
    return document


_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
_ROUTE_DECORATOR = re.compile(
    r"@(?:[A-Za-z_][\w]*)\.(get|post|put|patch|delete|head|options)\(\s*['\"]([^'\"]+)['\"]",
    re.I,
)
_ROUTE_PATH = re.compile(
    r"@(?:[A-Za-z_][\w]*)\.route\(\s*['\"]([^'\"]+)['\"]"
    r"(?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?",
    re.I,
)
_DIFF_BANNER = re.compile(r"^={20,}\nDIFF: ([^\n]+)\n={20,}\n?", re.MULTILINE)
_MAX_README_LINES = 8
_MAX_README_LINE_CHARS = 240
_MAX_README_CHARS = 800
_MAX_ROUTES = 50


def _route_label(method: str, path: str) -> str:
    return f"{method.upper()} {path}"


def _route_in_text(text: str, method: str, path: str) -> bool:
    method = method.upper()
    blob = text or ""
    return bool(
        re.search(rf"{re.escape(method)}\s+`?{re.escape(path)}`?", blob, re.I)
        or re.search(rf"`{re.escape(method)}\s+{re.escape(path)}`", blob, re.I)
    )


def extract_http_routes(dump: str) -> list[tuple[str, str]]:
    """Method+path pairs from FastAPI/Flask-style decorators in FILE bodies only."""
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for path, body in _file_bodies(dump).items():
        if not path.lower().endswith(".py"):
            continue
        for match in _ROUTE_DECORATOR.finditer(body or ""):
            method = match.group(1).upper()
            route = (match.group(2) or "").strip()
            if not route.startswith("/") or method not in _HTTP_METHODS:
                continue
            key = (method, route)
            if key in seen:
                continue
            seen.add(key)
            found.append(key)
            if len(found) >= _MAX_ROUTES:
                return found
        for match in _ROUTE_PATH.finditer(body or ""):
            route = (match.group(1) or "").strip()
            if not route.startswith("/"):
                continue
            raw_methods = match.group(2) or ""
            methods = [item.strip(" '\"\t").upper() for item in raw_methods.split(",") if item.strip(" '\"\t")]
            if not methods:
                methods = ["GET"]
            for method in methods:
                if method not in _HTTP_METHODS:
                    continue
                key = (method, route)
                if key in seen:
                    continue
                seen.add(key)
                found.append(key)
                if len(found) >= _MAX_ROUTES:
                    return found
    return found


def ensure_route_coverage(document: dict[str, Any], dump: str, *, scoped: bool) -> dict[str, Any]:
    """Append dump-grounded HTTP routes the LLM omitted. Does not invent routes."""
    if not isinstance(document, dict) or not (dump or "").strip():
        return document
    if scoped and not _file_bodies(dump):
        return document
    routes = extract_http_routes(dump)
    if not routes:
        return document
    apis_key = ("categorizedTechnicalInformation", "mainApisAndEndpoints")
    flow_key = ("coreConceptsAndArchitecture", "requestFlow")
    for parts in (apis_key, flow_key):
        current = get_field(document, parts)
        missing = [
            _route_label(method, path)
            for method, path in routes
            if not _route_in_text(current, method, path)
        ]
        if not missing:
            continue
        extra = " ".join(f"`{label}`" for label in missing)
        if extra not in current:
            set_field(document, parts, (current.rstrip() + "\n" + extra).strip())
    return document


def _diff_added_lines(dump: str, wanted: str) -> list[str]:
    wanted = _rel(wanted)
    lines: list[str] = []
    matches = list(_DIFF_BANNER.finditer(dump or ""))
    for index, match in enumerate(matches):
        path = _rel(match.group(1))
        if path.lower() != wanted.lower() and _base_name(path).lower() != _base_name(wanted).lower():
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(dump or "")
        patch = (dump or "")[match.end() : end]
        for raw in patch.splitlines():
            if not raw.startswith("+") or raw.startswith("+++"):
                continue
            text = raw[1:].strip()
            if text:
                lines.append(text)
    return lines


def _is_html_comment_line(line: str) -> bool:
    text = (line or "").strip()
    return text.startswith("<!--") and text.endswith("-->")


def _readme_new_lines(dump: str, already: str) -> list[str]:
    added = _diff_added_lines(dump, "README.md")
    if not added:
        bodies = _file_bodies(dump)
        body = ""
        for path, content in bodies.items():
            if _is_readme_path(path):
                body = content
                break
        if body:
            added = [line.strip() for line in body.splitlines() if line.strip() and line.strip() not in (already or "")]
            added = added[-_MAX_README_LINES:]
    out: list[str] = []
    total = 0
    for line in added:
        if line in (already or "") or line in out or _is_html_comment_line(line):
            continue
        clipped = line[:_MAX_README_LINE_CHARS]
        if total + len(clipped) > _MAX_README_CHARS:
            break
        out.append(clipped)
        total += len(clipped)
        if len(out) >= _MAX_README_LINES:
            break
    return out


def ensure_readme_coverage(
    document: dict[str, Any],
    impact: dict[str, Any] | None,
    dump: str,
) -> dict[str, Any]:
    """Append bounded new README lines when a README file was modified."""
    if not isinstance(document, dict) or not isinstance(impact, dict):
        return document
    modified = False
    for row in impact.get("changed") or []:
        if not isinstance(row, dict):
            continue
        path = _rel(str(row.get("path") or ""))
        if str(row.get("status") or "") == "modified" and _is_readme_path(path):
            modified = True
            break
    if not modified:
        return document
    selected = impact.get("updateFields")
    if not isinstance(selected, list):
        selected = select_update_fields(document, impact)
    allowed = {str(key) for key in selected}
    target = None
    if "repositoryOverview.summary" in allowed:
        target = ("repositoryOverview", "summary")
    elif "repositoryOverview.quickStart" in allowed:
        target = ("repositoryOverview", "quickStart")
    if target is None:
        return document
    current = get_field(document, target)
    already = _document_blob(document)
    extra = _readme_new_lines(dump, already)
    if not extra:
        return document
    block = "\n".join(extra)
    if block in current:
        return document
    set_field(document, target, (current.rstrip() + "\n" + block).strip())
    return document


def merge_documentation(
    previous: dict[str, Any] | None,
    generated: dict[str, Any],
    impact: dict[str, Any] | None = None,
    section_sources: dict[str, list[str]] | None = None,
    dump: str = "",
) -> dict[str, Any]:
    """Keep unaffected sections. Apply generated text only for host-selected fields."""
    del section_sources  # provenance is optional; selection is host-side updateFields
    if not isinstance(generated, dict):
        raise ValueError("generated documentation must be an object")
    if isinstance(generated.get("updates"), list):
        generated = generated_from_updates(generated.get("updates") or [])
    dump_text = (dump or "").strip() or str((impact or {}).get("scopedDump") or "")
    incremental = (
        isinstance(impact, dict)
        and impact.get("mode") != "full"
        and bool(impact.get("changed"))
    )
    if not previous or not incremental:
        out = copy.deepcopy(generated)
        ensure_route_coverage(out, dump_text, scoped=False)
        return out

    selected = impact.get("updateFields")
    if not isinstance(selected, list):
        selected = select_update_fields(previous, impact)
    allowed_keys = {str(key) for key in selected}

    merged = copy.deepcopy(previous)
    for parts in LEAF_FIELDS:
        key = field_key(parts)
        if key not in allowed_keys:
            continue
        new = get_field(generated, parts)
        if is_unchanged_placeholder(new) or not (new or "").strip():
            continue
        allowed = _allowed_paths_for_field(parts, previous, impact)
        if unsupported_paths(new, allowed):
            continue
        set_field(merged, parts, new)
    rewrite_stale_paths(merged, impact)
    ensure_change_coverage(merged, impact)
    dump_text = (dump or "").strip() or str((impact or {}).get("scopedDump") or "")
    ensure_readme_coverage(merged, impact, dump_text)
    ensure_route_coverage(merged, dump_text, scoped=True)
    return merged


def documentation_only(document: dict[str, Any]) -> dict[str, Any]:
    """Return the six-field document without extra metadata."""
    out: dict[str, Any] = {}
    for key in REQUIRED_ROOT:
        if key not in document:
            continue
        value = document[key]
        if key == "repositoryOverview":
            out[key] = {inner: str((value or {}).get(inner) or "") for inner in REQUIRED_OVERVIEW}
        elif key == "coreConceptsAndArchitecture":
            out[key] = {inner: str((value or {}).get(inner) or "") for inner in REQUIRED_ARCHITECTURE}
        elif key == "categorizedTechnicalInformation":
            out[key] = {inner: str((value or {}).get(inner) or "") for inner in REQUIRED_CATEGORIZED}
        elif key == "developerOnboardingGuide":
            out[key] = {inner: str((value or {}).get(inner) or "") for inner in REQUIRED_ONBOARDING}
        else:
            out[key] = value if isinstance(value, str) else ""
    return out
