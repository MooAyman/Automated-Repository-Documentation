"""Deterministic host-side validation of pipeline URL and ref.

Runs before any ARK Query. Does not clone, resolve refs, or call a model.
Local filesystem paths are not accepted as pipeline input.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
MAX_REF_LENGTH = 255

_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.I)
_DRIVE_PATH_RE = re.compile(r"^[a-zA-Z]:[\\/]")
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~+-]+$")
_INVALID_REF_CHARS = re.compile(r"[\x00-\x1f\x7f ~^:?*\[\\]")


class ValidationError(ValueError):
    """Raised when the repository URL or ref is not valid pipeline input."""


def validate_pipeline_input(repository_url: str, ref: str = "") -> tuple[str, str]:
    """Return `(url, ref)` after validating both. Empty ref is allowed."""
    url = validate_repository_url(repository_url)
    checked_ref = validate_ref(ref)
    return url, checked_ref


def validate_repository_url(repository_url: str) -> str:
    raw = (repository_url or "").strip()
    if not raw:
        raise ValidationError("repository URL is required")
    if len(raw) > MAX_URL_LENGTH:
        raise ValidationError("repository URL is too long")
    if _is_local_path(raw):
        raise ValidationError(
            "local filesystem paths are not supported; "
            "provide an http or https GitHub or GitLab URL"
        )

    parts = urlsplit(raw)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValidationError(
            "repository URL must be an http or https GitHub or GitLab URL"
        )
    if parts.username is not None or parts.password is not None:
        raise ValidationError("repository URL must not contain embedded credentials")
    if "@" in (parts.netloc or ""):
        raise ValidationError("repository URL must not contain embedded credentials")
    if parts.query or parts.fragment:
        raise ValidationError("repository URL must not include a query string or fragment")

    host = (parts.hostname or "").lower()
    if not host:
        raise ValidationError("repository URL must include a host")

    path = parts.path or ""
    if "\\" in path:
        raise ValidationError("repository URL path is invalid")
    if not path.strip("/"):
        raise ValidationError("repository URL must include a repository path (owner/repository)")
    if "//" in path:
        raise ValidationError("repository URL path is invalid")

    trimmed = path.rstrip("/")
    git_suffix = trimmed.endswith(".git")
    if git_suffix:
        trimmed = trimmed[: -len(".git")]
    segments = [segment for segment in trimmed.strip("/").split("/") if segment]
    if len(segments) < 2:
        raise ValidationError("repository URL must include a repository path (owner/repository)")
    if any(segment in (".", "..", "-") for segment in segments):
        raise ValidationError("repository URL must be a git clone URL, not a website path")
    if not all(_SEGMENT_RE.match(segment) for segment in segments):
        raise ValidationError("repository URL path is invalid")

    if _is_github_host(host) and len(segments) != 2:
        raise ValidationError("GitHub URL path must be owner/repository")

    rebuilt_path = "/" + "/".join(segments)
    if git_suffix:
        rebuilt_path += ".git"
    return urlunsplit((scheme, _netloc(parts), rebuilt_path, "", ""))


def validate_commit_sha(value: str, *, required: bool = False) -> str:
    """Validate an optional documented commit SHA. Does not check existence."""
    text = (value or "").strip()
    if not text:
        if required:
            raise ValidationError("commit SHA is required")
        return ""
    if not _SHA_RE.match(text):
        raise ValidationError("commit SHA is invalid")
    return text


def validate_ref(ref: str) -> str:
    """Validate optional git ref syntax. Does not check that the ref exists."""
    value = (ref or "").strip()
    if not value:
        return ""
    if len(value) > MAX_REF_LENGTH:
        raise ValidationError("ref is too long")
    if _SHA_RE.match(value):
        return value
    if value.startswith("-"):
        raise ValidationError("ref must not start with '-'")
    if value in (".", "..", "@") or "@{" in value:
        raise ValidationError("ref syntax is invalid")
    if (
        value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or value.endswith(".")
        or value.endswith(".lock")
        or ".." in value
        or _INVALID_REF_CHARS.search(value)
    ):
        raise ValidationError("ref syntax is invalid")
    parts = value.split("/")
    if any(not part or part.startswith(".") or part.endswith(".") for part in parts):
        raise ValidationError("ref syntax is invalid")
    return value


def _is_local_path(raw: str) -> bool:
    if _DRIVE_PATH_RE.match(raw) or raw.startswith("\\\\"):
        return True
    if raw.startswith(("./", ".\\", "../", "..\\")):
        return True
    if raw.startswith("/") and not raw.startswith("//"):
        return True
    return False


def _is_github_host(host: str) -> bool:
    return host == "github.com" or host.endswith(".github.com")


def _netloc(parts) -> str:
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    if parts.port:
        return f"{host}:{parts.port}"
    return host
