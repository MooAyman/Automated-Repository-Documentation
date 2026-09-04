"""Deterministic repository collection.

Turns a GitHub/GitLab URL or a local path into a single plain-text dump that
preserves relative paths, directory structure and source code.

This module knows nothing about ARK, HTTP or LLMs. Its only responsibility is
repository acquisition and preparation.
"""

from __future__ import annotations

import base64
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

SEPARATOR = "=" * 50
RULE = "-" * 50

DEFAULT_MAX_FILE_BYTES = 80_000
DEFAULT_MAX_TOTAL_BYTES = 250_000
DEFAULT_CLONE_TIMEOUT_SECONDS = 300

# Directories that never carry first-party source code.
EXCLUDED_DIRS = {
    ".git", ".svn", ".hg", ".bzr",
    "node_modules", "bower_components", "jspm_packages",
    ".venv", "venv", "virtualenv", "site-packages", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".nox", ".eggs",
    "dist", "build", "out", "target", "bin", "obj", "Debug", "Release",
    ".next", ".nuxt", ".svelte-kit", ".parcel-cache", ".turbo", ".cache",
    "coverage", "htmlcov", ".nyc_output",
    ".gradle", ".mvn", ".terraform", ".serverless",
    ".idea", ".vs", ".fleet",
    "vendor", "Pods", "DerivedData",
}
EXCLUDED_DIR_SUFFIXES = (".egg-info",)

# Files that commonly hold credentials. `.env.example` and friends are allowed.
ALLOWED_ENV_FILES = {".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults"}
SECRET_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.development", ".env.test",
    "credentials", "credentials.json", "secrets.json", "secrets.yaml", "secrets.yml",
    ".netrc", "_netrc", ".npmrc", ".pypirc", ".dockercfg", ".git-credentials",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "service-account.json",
}
SECRET_SUFFIXES = (
    ".pem", ".key", ".pfx", ".p12", ".jks", ".keystore", ".ppk", ".asc", ".gpg", ".kdbx",
)

# Binary / non-source payloads, excluded by extension before any content sniff.
BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".icns", ".webp", ".tiff", ".svgz",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".lib", ".obj", ".pdb",
    ".pyc", ".pyo", ".pyd", ".class", ".wasm",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".webm", ".flac", ".ogg",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".db", ".sqlite", ".sqlite3", ".mdb", ".dat", ".pack", ".idx",
    ".model", ".pt", ".pth", ".onnx", ".h5", ".pkl", ".npy", ".npz", ".parquet",
}

# Machine-generated manifests: listed in the tree, content omitted (huge, low signal).
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "poetry.lock", "Pipfile.lock", "pdm.lock", "uv.lock", "composer.lock",
    "Cargo.lock", "go.sum", "Gemfile.lock", "mix.lock", "packages.lock.json",
}

_REMOTE_RE = re.compile(r"^(https?://|git://|ssh://|git\+https?://)", re.IGNORECASE)
_SCP_RE = re.compile(r"^[\w.+-]+@[\w.-]+:.+")
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.I)


class CollectorError(Exception):
    """Raised for input the caller can fix (bad URL, missing path, clone failure)."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class FileEntry:
    path: str
    size: int
    included: bool
    reason: str = ""
    text: str = ""


@dataclass
class Collection:
    name: str
    source: str
    host: str = ""
    requested_ref: str = ""
    resolved_ref: str = ""
    commit: str = ""
    entries: list[FileEntry] = field(default_factory=list)

    @property
    def included(self) -> list[FileEntry]:
        return [e for e in self.entries if e.included]

    @property
    def skipped(self) -> list[FileEntry]:
        return [e for e in self.entries if not e.included]


def is_remote(source: str) -> bool:
    return bool(_REMOTE_RE.match(source) or _SCP_RE.match(source))


def gitlab_token() -> str:
    return os.environ.get("GITLAB_TOKEN", "").strip()


def is_github_host(host: str | None) -> bool:
    if not host:
        return False
    lowered = host.lower()
    return lowered == "github.com" or lowered.endswith(".github.com")


def strip_userinfo(url: str) -> str:
    """Return `url` with any embedded userinfo removed. Never used as a credential channel."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        return url
    netloc = parts.hostname
    if parts.port:
        netloc = f"{parts.hostname}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def source_identity(source: str) -> tuple[str, str]:
    """Return (host_or_local, repository_name) with credentials stripped."""
    cleaned = strip_userinfo(source.strip())
    if _SCP_RE.match(cleaned):
        host = cleaned.split("@", 1)[1].split(":", 1)[0]
        return host, repository_name(cleaned)
    if is_remote(cleaned):
        host = urlsplit(cleaned).hostname or ""
        return host, repository_name(cleaned)
    return "local", repository_name(cleaned)


def redact(text: str) -> str:
    """Strip tokens and userinfo so logs and errors never carry credentials."""
    redacted = re.sub(r"(https?://)[^/\s@]+@", r"\1***@", text)
    redacted = re.sub(r"(?i)(authorization:\s*)\S+", r"\1***", redacted)
    redacted = re.sub(r"(?i)(private-token:\s*)\S+", r"\1***", redacted)
    token = gitlab_token()
    if token:
        redacted = redacted.replace(token, "***")
        encoded = base64.b64encode(f"oauth2:{token}".encode("utf-8")).decode("ascii")
        redacted = redacted.replace(encoded, "***")
    return redacted


def repository_name(source: str) -> str:
    cleaned = strip_userinfo(source).rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[: -len(".git")]
    name = cleaned.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return name or "repository"


def validate_remote_url(source: str) -> None:
    if _SCP_RE.match(source):
        path = source.split(":", 1)[-1].strip()
        if not path:
            raise CollectorError("Invalid repository URL", status=400)
        return
    parts = urlsplit(source)
    scheme = (parts.scheme or "").lower()
    if scheme in ("http", "https"):
        if not parts.hostname or not (parts.path or "").strip("/"):
            raise CollectorError("Invalid repository URL", status=400)
        return
    if scheme in ("ssh", "git", "git+http", "git+https"):
        if not parts.hostname:
            raise CollectorError("Invalid repository URL", status=400)
        return
    raise CollectorError("Invalid repository URL", status=400)


def clone_timeout_seconds() -> int:
    try:
        value = int(os.environ.get("CLONE_TIMEOUT_SECONDS", str(DEFAULT_CLONE_TIMEOUT_SECONDS)))
    except ValueError:
        return DEFAULT_CLONE_TIMEOUT_SECONDS
    return value if value > 0 else DEFAULT_CLONE_TIMEOUT_SECONDS


def build_git_env(url: str = "") -> dict[str, str]:
    """Environment for a git subprocess.

    GitLab authentication uses a host-scoped `http.extraHeader` via GIT_CONFIG_*
    so the token never appears on the command line or in the repository URL.
    GITLAB_TOKEN itself is not forwarded to the child process.
    """
    blocked = {"GITLAB_TOKEN", "GIT_TOKEN", "GIT_USERNAME", "GIT_ASKPASS"}
    env = {key: value for key, value in os.environ.items() if key not in blocked}
    env.setdefault("HOME", tempfile.gettempdir())
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"

    token = gitlab_token()
    parts = urlsplit(url) if url else urlsplit("")
    host = parts.hostname
    if (
        token
        and (parts.scheme or "").lower() in ("http", "https")
        and host
        and not is_github_host(host)
    ):
        basic = base64.b64encode(f"oauth2:{token}".encode("utf-8")).decode("ascii")
        env["GIT_CONFIG_COUNT"] = "1"
        env["GIT_CONFIG_KEY_0"] = f"http.https://{host}/.extraHeader"
        env["GIT_CONFIG_VALUE_0"] = f"Authorization: Basic {basic}"
    else:
        env["GIT_ASKPASS"] = "echo"
    return env


def _run_git(
    args: list[str],
    cwd: str | None = None,
    timeout: int | None = None,
    url: str = "",
) -> subprocess.CompletedProcess:
    env = build_git_env(url)
    try:
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            env=env,
            timeout=clone_timeout_seconds() if timeout is None else timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise CollectorError("Repository clone timed out", status=504) from exc


def classify_git_error(stderr: str, source: str, ref: str = "") -> CollectorError:
    text = redact((stderr or "").strip())
    low = text.lower()
    source_r = redact(strip_userinfo(source))

    if any(
        marker in low
        for marker in (
            "authentication failed",
            "access denied",
            "could not read username",
            "terminal prompts disabled",
            "invalid credentials",
            "http basic: access denied",
            "the requested url returned error: 401",
            "the requested url returned error: 403",
            "error: 401",
            "error: 403",
            "permission denied (publickey)",
        )
    ):
        return CollectorError("Git authentication failed", status=401)

    if ref and any(
        marker in low
        for marker in (
            "couldn't find remote ref",
            "could not find remote ref",
            "not our ref",
            "did not match any",
            "unknown revision",
            "bad revision",
            "remote branch",
            "not found in upstream",
            "pathspec",
            "invalid refspec",
        )
    ):
        return CollectorError(
            f"Requested ref not found: '{ref}' does not exist in {source_r}",
            status=404,
        )

    if any(
        marker in low
        for marker in (
            "repository not found",
            "the project you were looking for",
            "could not be found",
            "the requested url returned error: 404",
            "error: 404",
            "status code 404",
            "conq: not found",
        )
    ) or (not ref and "not found" in low):
        return CollectorError(
            f"Repository not found or inaccessible: {source_r}",
            status=404,
        )

    if ref and "not found" in low:
        return CollectorError(
            f"Requested ref not found: '{ref}' does not exist in {source_r}",
            status=404,
        )

    detail = text or "unknown error"
    return CollectorError(
        f"git clone failed for {source_r}"
        + (f" (ref '{ref}')" if ref else "")
        + f": {detail}",
        status=400,
    )


def _assert_ref_checked_out(repo_dir: str, requested: str) -> None:
    """Fail if HEAD is not the requested object. Never continue on the default branch."""
    head = _run_git(["rev-parse", "HEAD"], cwd=repo_dir)
    commit = (head.stdout or "").strip()
    if head.returncode != 0 or not commit:
        raise CollectorError(
            f"Requested ref not found: '{requested}' could not be resolved",
            status=404,
        )
    if _SHA_RE.match(requested) and not commit.lower().startswith(requested.lower()):
        raise CollectorError(
            f"Requested ref not found: checked-out commit {commit[:12]} does not match '{requested}'",
            status=404,
        )


def clone_remote(source: str, ref: str, dest: str) -> None:
    """Clone `source`. Empty ref → default branch. Otherwise fetch that ref only."""
    url = strip_userinfo(source)
    if not ref:
        result = _run_git(
            ["clone", "--depth", "1", "--single-branch", "--no-tags", "--", url, dest],
            url=url,
        )
        if result.returncode != 0:
            raise classify_git_error(result.stderr, url, ref)
        return

    os.makedirs(dest, exist_ok=True)
    init = _run_git(["init", "--", dest], url=url)
    if init.returncode != 0:
        raise classify_git_error(init.stderr, url, ref)
    remote = _run_git(["remote", "add", "origin", url], cwd=dest, url=url)
    if remote.returncode != 0:
        raise classify_git_error(remote.stderr, url, ref)

    fetch = _run_git(["fetch", "--depth", "1", "--no-tags", "origin", ref], cwd=dest, url=url)
    if fetch.returncode != 0:
        fetch = _run_git(["fetch", "--no-tags", "origin", ref], cwd=dest, url=url)
    if fetch.returncode != 0:
        raise classify_git_error(fetch.stderr, url, ref)

    checkout = _run_git(["checkout", "--force", "FETCH_HEAD"], cwd=dest, url=url)
    if checkout.returncode != 0:
        raise classify_git_error(checkout.stderr, url, ref)
    _assert_ref_checked_out(dest, ref)


def checkout_local_ref(source_dir: str, ref: str, dest: str) -> None:
    """Copy a local git repo and check out `ref`. Does not mutate the original."""
    clone = _run_git(["clone", "--", source_dir, dest])
    if clone.returncode != 0:
        raise classify_git_error(clone.stderr, source_dir, ref)
    checked = _run_git(["checkout", "--force", ref], cwd=dest)
    if checked.returncode != 0:
        raise CollectorError(
            f"Requested ref not found: '{ref}' does not exist in {source_dir}",
            status=404,
        )
    _assert_ref_checked_out(dest, ref)


def _git_metadata(repo_dir: str) -> tuple[str, str]:
    commit = _run_git(["rev-parse", "HEAD"], cwd=repo_dir)
    branch = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_dir)
    return (
        commit.stdout.strip() if commit.returncode == 0 else "",
        branch.stdout.strip() if branch.returncode == 0 else "",
    )


def _skip_dir(name: str) -> bool:
    return name in EXCLUDED_DIRS or name.endswith(EXCLUDED_DIR_SUFFIXES)


def _skip_reason(name: str, size: int, max_file_bytes: int) -> str:
    lower = name.lower()
    if lower in ALLOWED_ENV_FILES:
        return ""
    if lower in SECRET_FILENAMES or lower.startswith(".env."):
        return "excluded: potential secret"
    if lower.endswith(SECRET_SUFFIXES):
        return "excluded: potential credential/key file"
    if lower.endswith(tuple(BINARY_SUFFIXES)):
        return "excluded: binary file"
    if name in LOCKFILES:
        return "excluded: generated lock file"
    if size > max_file_bytes:
        return f"excluded: file size {size} bytes exceeds limit {max_file_bytes}"
    return ""


def _read_text(path: Path) -> str | None:
    """Return normalized text, or None when the file looks binary."""
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
        if text.count("\uFFFD") > max(16, len(text) // 100):
            return None
    return text.replace("\r\n", "\n").replace("\r", "\n")


def scan(root: str, max_file_bytes: int, max_total_bytes: int) -> list[FileEntry]:
    root_path = Path(root)
    candidates: list[tuple[str, Path, int]] = []

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = sorted(d for d in dirnames if not _skip_dir(d))
        for filename in filenames:
            full = Path(dirpath) / filename
            if full.is_symlink():
                continue
            rel = full.relative_to(root_path).as_posix()
            try:
                size = full.stat().st_size
            except OSError:
                continue
            candidates.append((rel, full, size))

    # Deterministic ordering: lexicographic on the POSIX relative path.
    candidates.sort(key=lambda item: item[0])

    entries: list[FileEntry] = []
    budget = max_total_bytes
    for rel, full, size in candidates:
        reason = _skip_reason(full.name, size, max_file_bytes)
        if reason:
            entries.append(FileEntry(rel, size, False, reason))
            continue
        text = _read_text(full)
        if text is None:
            entries.append(FileEntry(rel, size, False, "excluded: binary or undecodable content"))
            continue
        if len(text) > budget:
            entries.append(
                FileEntry(rel, size, False, f"omitted: total content budget of {max_total_bytes} bytes exhausted")
            )
            continue
        budget -= len(text)
        entries.append(FileEntry(rel, size, True, "", text))
    return entries


def render_tree(rel_paths: list[str]) -> str:
    tree: dict = {}
    for rel in rel_paths:
        parts = rel.split("/")
        node = tree
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node.setdefault(parts[-1], None)

    lines: list[str] = []

    def walk(node: dict, prefix: str) -> None:
        dirs = sorted(k for k, v in node.items() if isinstance(v, dict))
        files = sorted(k for k, v in node.items() if not isinstance(v, dict))
        entries = [(d, True) for d in dirs] + [(f, False) for f in files]
        for index, (name, is_dir) in enumerate(entries):
            last = index == len(entries) - 1
            lines.append(f"{prefix}{'└── ' if last else '├── '}{name}{'/' if is_dir else ''}")
            if is_dir:
                walk(node[name], prefix + ("    " if last else "│   "))

    walk(tree, "")
    return "\n".join(lines)


def render(collection: Collection) -> str:
    included = collection.included
    skipped = collection.skipped
    out: list[str] = [
        SEPARATOR,
        f"REPOSITORY: {collection.name}",
        SEPARATOR,
        "",
        f"SOURCE: {redact(collection.source)}",
    ]
    if collection.requested_ref:
        out.append(f"REQUESTED_REF: {collection.requested_ref}")
    if collection.resolved_ref:
        out.append(f"REF: {collection.resolved_ref}")
    if collection.commit:
        out.append(f"COMMIT: {collection.commit}")
    out += [
        f"FILES INCLUDED: {len(included)}",
        f"FILES EXCLUDED: {len(skipped)}",
        f"CONTENT BYTES: {sum(len(e.text) for e in included)}",
        "",
        "REPOSITORY STRUCTURE",
        RULE,
        "",
        render_tree([e.path for e in collection.entries]) or "(empty repository)",
        "",
    ]

    if skipped:
        out += ["", "EXCLUDED FILES", RULE, ""]
        out += [f"{e.path} — {e.reason}" for e in skipped]
        out.append("")

    for entry in included:
        out += ["", SEPARATOR, f"FILE: {entry.path}", SEPARATOR, "", entry.text.rstrip("\n"), ""]

    return "\n".join(out)


def collect_into(
    source: str,
    ref: str = "",
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    local_root: str | None = None,
) -> Collection:
    """Collect `source` into a Collection. Raises CollectorError on failure."""
    source = (source or "").strip()
    ref = (ref or "").strip()
    if not source:
        raise CollectorError("no repository was provided", status=400)

    host, name = source_identity(source)

    if is_remote(source):
        validate_remote_url(source)
        with tempfile.TemporaryDirectory(prefix="repo-collect-") as workdir:
            repo_dir = os.path.join(workdir, "repo")
            clone_remote(source, ref, repo_dir)
            commit, branch = _git_metadata(repo_dir)
            return Collection(
                name=name,
                source=strip_userinfo(source),
                host=host,
                requested_ref=ref,
                resolved_ref=ref or branch,
                commit=commit,
                entries=scan(repo_dir, max_file_bytes, max_total_bytes),
            )

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

    if ref:
        with tempfile.TemporaryDirectory(prefix="repo-collect-") as workdir:
            checked_out = os.path.join(workdir, "repo")
            checkout_local_ref(repo_dir, ref, checked_out)
            commit, branch = _git_metadata(checked_out)
            return Collection(
                name=name,
                source=repo_dir,
                host=host,
                requested_ref=ref,
                resolved_ref=ref or branch,
                commit=commit,
                entries=scan(checked_out, max_file_bytes, max_total_bytes),
            )

    commit, branch = _git_metadata(repo_dir)
    return Collection(
        name=name,
        source=repo_dir,
        host=host,
        requested_ref=ref,
        resolved_ref=ref or branch,
        commit=commit,
        entries=scan(repo_dir, max_file_bytes, max_total_bytes),
    )


def collect(
    source: str,
    ref: str = "",
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    local_root: str | None = None,
) -> str:
    """Collect `source` (remote URL or local path) into a deterministic text dump."""
    return render(collect_into(source, ref, max_file_bytes, max_total_bytes, local_root))
