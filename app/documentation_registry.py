"""Persistent last-documented commit registry.

Stores per-repository identity, documented SHA, and documentation version
in a JSON file. Not Streamlit memory and not the HTML artifact.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from validation import validate_commit_sha, validate_repository_url

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY_PATH = ROOT / "state" / "documentation-registry.json"
SCHEMA_VERSION = "1"


def registry_path(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    override = os.environ.get("DOCUMENTATION_REGISTRY", "").strip()
    return Path(override) if override else DEFAULT_REGISTRY_PATH


def repository_identity(repository_url: str) -> str:
    url = validate_repository_url(repository_url)
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    repo_path = (parts.path or "").rstrip("/")
    if repo_path.lower().endswith(".git"):
        repo_path = repo_path[:-4]
    repo_path = repo_path.lower()
    return f"{host}{repo_path}"


def same_commit(left: str, right: str) -> bool:
    """True only when both values are the same canonical commit SHA.

    Prefix matches are not equality: different commits must not compare equal.
    """
    try:
        a = validate_commit_sha(left)
        b = validate_commit_sha(right)
    except ValueError:
        return False
    if not a or not b:
        return False
    return a.lower() == b.lower()


def empty_registry() -> dict:
    return {"schemaVersion": SCHEMA_VERSION, "repositories": {}}


def load_registry(path: str | Path | None = None) -> dict:
    dest = registry_path(path)
    if not dest.is_file():
        return empty_registry()
    raw = json.loads(dest.read_text(encoding="utf-8") or "{}")
    if not isinstance(raw, dict) or not isinstance(raw.get("repositories"), dict):
        return empty_registry()
    return raw


def _identity_aliases(identity: str) -> list[str]:
    aliases = [identity]
    if identity.startswith("www."):
        aliases.append(identity[4:])
    else:
        aliases.append(f"www.{identity}")
    return aliases


def lookup(repository_url: str, path: str | Path | None = None) -> dict | None:
    identity = repository_identity(repository_url)
    repos = load_registry(path).get("repositories", {})
    for key in _identity_aliases(identity):
        record = repos.get(key)
        if isinstance(record, dict):
            return dict(record)
    return None


def record_success(
    repository_url: str,
    commit_sha: str,
    *,
    artifact: str = "",
    documentation: dict | None = None,
    section_files: dict | None = None,
    path: str | Path | None = None,
) -> dict:
    """Persist a SHA only after successful documentation.

    Same SHA does not create a new documentation version and does not replace
    the last successful documentation JSON.
    """
    url = validate_repository_url(repository_url)
    sha = validate_commit_sha(commit_sha, required=True)
    identity = repository_identity(url)
    dest = registry_path(path)
    data = load_registry(dest)
    existing = data["repositories"].get(identity)
    if not isinstance(existing, dict):
        legacy = data["repositories"].pop(f"www.{identity}", None)
        existing = legacy if isinstance(legacy, dict) else None
    if isinstance(existing, dict) and same_commit(str(existing.get("commitSha") or ""), sha):
        return dict(existing)

    version = 1
    if isinstance(existing, dict):
        try:
            version = int(existing.get("documentationVersion") or 0) + 1
        except (TypeError, ValueError):
            version = 1
        if version < 1:
            version = 1

    record = {
        "identity": identity,
        "repository": url,
        "commitSha": sha,
        "documentationVersion": version,
        "status": "documented",
        "artifact": str(artifact or (existing or {}).get("artifact") or ""),
        "updatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }
    if isinstance(documentation, dict):
        record["documentation"] = documentation
    elif isinstance(existing, dict) and isinstance(existing.get("documentation"), dict):
        record["documentation"] = existing["documentation"]
    if isinstance(section_files, dict):
        record["sectionFiles"] = section_files
    elif isinstance(existing, dict) and isinstance(existing.get("sectionFiles"), dict):
        record["sectionFiles"] = existing["sectionFiles"]
    data["schemaVersion"] = SCHEMA_VERSION
    data["repositories"][identity] = record
    _write_registry(dest, data)
    return dict(record)


def _write_registry(dest: Path, data: dict) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(dest.parent),
        prefix=".registry-",
        suffix=".tmp",
        delete=False,
    )
    try:
        handle.write(payload)
        handle.close()
        os.replace(handle.name, dest)
    except Exception:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise
