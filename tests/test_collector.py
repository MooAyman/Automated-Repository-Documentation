"""Tests for the repository-documentation project.

Offline checks of the collector:  python tests/test_collector.py
Add the live clone test:          python tests/test_collector.py --network
Add the deployed end-to-end test:  python tests/test_collector.py --e2e

The --e2e mode exercises the deployed repository-pipeline flow and verifies
that documentation is generated successfully. Security verification covers
the sanitized dump, the HTTP /collect tool payload, and collector logs.
"""

from __future__ import annotations

import inspect
import json
import logging
import os
import copy
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "repository-collector"))

import collector  # noqa: E402

TARGET_REPO = "https://github.com/MooAyman/github-mcp-chatbot"
SELF_REPO = "https://github.com/MooAyman/Automated-Repository-Documentation"
PIPELINE_QUERY_NAME = "pipeline-github-mcp-chatbot"
COLLECTOR_LABEL = "component=collector"
NAMESPACE = os.environ.get("ARK_NAMESPACE", "default")
ROOT = Path(__file__).resolve().parents[1]
HTML_OUTPUT = ROOT / "out" / "github-mcp-chatbot.html"

_failures: list[str] = []


def check(condition: bool, label: str) -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")
    if not condition:
        _failures.append(label)


def build_fixture(root: Path) -> None:
    """A miniature repository exercising every filtering rule."""
    (root / "src" / "app").mkdir(parents=True)
    (root / "node_modules" / "left-pad").mkdir(parents=True)
    (root / "__pycache__").mkdir()
    (root / ".git").mkdir()

    (root / "src" / "app" / "main.py").write_text("print('hello')\r\n", encoding="utf-8")
    (root / "src" / "app" / "util.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "README.md").write_text("# Fixture\n", encoding="utf-8")

    (root / ".env").write_text("SECRET=supersecret\n", encoding="utf-8")
    (root / ".env.example").write_text("SECRET=changeme\n", encoding="utf-8")
    (root / "server.key").write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")
    (root / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")

    (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
    (root / "blob.txt").write_bytes(b"text\x00with-null-bytes")
    (root / "huge.py").write_text("x = 0\n" * 5000, encoding="utf-8")

    (root / "node_modules" / "left-pad" / "index.js").write_text("module.exports = 1\n", encoding="utf-8")
    (root / "__pycache__" / "main.cpython-312.pyc").write_bytes(b"\x00\x01")
    (root / ".git" / "config").write_text("[core]\n", encoding="utf-8")


def test_filtering_and_structure() -> None:
    print("\nfiltering and structure")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "fixture-repo"
        root.mkdir()
        build_fixture(root)

        entries = collector.scan(str(root), max_file_bytes=1000, max_total_bytes=100_000)
        included = {e.path for e in entries if e.included}
        skipped = {e.path: e.reason for e in entries if not e.included}

        check(included == {"README.md", ".env.example", "src/app/main.py", "src/app/util.py"},
              f"only source files included (got {sorted(included)})")
        check(".env" in skipped and "secret" in skipped[".env"], "`.env` excluded as a secret")
        check(".env.example" in included, "`.env.example` allowed")
        check("server.key" in skipped, "private key excluded")
        check("logo.png" in skipped, "binary excluded by extension")
        check("blob.txt" in skipped, "binary excluded by NUL-byte sniff")
        check("package-lock.json" in skipped, "lock file excluded")
        check("huge.py" in skipped and "exceeds limit" in skipped["huge.py"], "oversized file excluded")
        check(not any(p.startswith(("node_modules/", "__pycache__/", ".git/")) for p in included | set(skipped)),
              "dependency/cache/.git directories never walked")

        main = next(e for e in entries if e.path == "src/app/main.py")
        check("\r" not in main.text, "line endings normalized to LF")

        paths = [e.path for e in entries]
        check(paths == sorted(paths), "entries sorted deterministically")

        tree = collector.render_tree(paths)
        check("src/" in tree and "└── " in tree, "tree renders directories and connectors")
        check("app/" in tree, "tree renders nested directories")


def test_determinism_and_render() -> None:
    print("\ndeterminism and rendering")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "fixture-repo"
        root.mkdir()
        build_fixture(root)

        first = collector.collect(str(root))
        second = collector.collect(str(root))
        check(first == second, "repeated collection is byte-identical")
        check(first.startswith("=" * 50), "dump opens with the separator banner")
        check("REPOSITORY: fixture-repo" in first, "dump names the repository")
        check("REPOSITORY STRUCTURE" in first, "dump contains the structure section")
        check("FILE: src/app/main.py" in first, "dump contains per-file headers with relative paths")
        check("supersecret" not in first, "secret contents never reach the dump")
        check(first.index("FILE: README.md") < first.index("FILE: src/app/main.py"),
              "files emitted in deterministic path order")


def test_json_exclusion() -> None:
    print("\nJSON collection exclusion")
    analyzer_dir = str(ROOT / "tools" / "repository-analyzer")
    sys.path.insert(0, analyzer_dir)
    import analyzer  # noqa: E402
    sys.path.remove(analyzer_dir)

    sentinel = "JSON_COLLECTION_SENTINEL_ZX9Q"
    nested_sentinel = "NESTED_JSON_COLLECTION_SENTINEL_ZX9Q"
    reason = "excluded: json file"

    check(not collector.is_collectable_path("config.json"), "root .json path is not collectable")
    check(not collector.is_collectable_path("src/data/config.json"), "nested .json path is not collectable")
    check(collector.is_collectable_path("src/app.py"), "non-JSON source stays collectable")
    check(not collector.is_collectable_path(".env"), "existing secret exclusion is unchanged")
    check(not collector.is_collectable_path("package-lock.json"), "existing lockfile exclusion is unchanged")
    check(collector.path_skip_reason("settings.json") == reason, "JSON uses the central exclusion reason")
    check(collector.path_skip_reason("package-lock.json") == "excluded: generated lock file",
          "lockfile JSON keeps the more specific lockfile reason")
    check(collector.path_skip_reason("credentials.json") == "excluded: potential secret",
          "secret JSON keeps the more specific secret reason")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "json-repo"
        (root / "src" / "data").mkdir(parents=True)
        (root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        (root / "README.md").write_text("# Docs\n", encoding="utf-8")
        (root / "config.json").write_text(f'{{"token": "{sentinel}"}}\n', encoding="utf-8")
        (root / "src" / "data" / "nested.json").write_text(
            f'{{"nested": "{nested_sentinel}"}}\n', encoding="utf-8"
        )
        (root / ".env").write_text("SECRET=supersecret\n", encoding="utf-8")
        (root / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")

        first = collector.collect(str(root))
        second = collector.collect(str(root))
        check(first == second, "JSON exclusion is deterministic")
        check("FILE: src/app.py" in first and "VALUE = 1" in first, "non-JSON source is still collected")
        check("FILE: README.md" in first, "non-JSON docs are still collected")
        check("FILE: config.json" not in first, ".json files are excluded from the dump")
        check("FILE: src/data/nested.json" not in first, "nested .json files are excluded from the dump")
        check(sentinel not in first and nested_sentinel not in first, "JSON contents never appear in the dump")
        check("config.json — " in first and reason in first, "JSON is listed as excluded metadata")
        check("src/data/nested.json — " in first, "nested JSON is listed as excluded metadata")
        check("supersecret" not in first and "\nFILE: .env\n" not in first, "existing secret exclusion still works")
        check("FILE: package-lock.json" not in first, "existing lockfile exclusion still works")

        entries = collector.scan(str(root), collector.DEFAULT_MAX_FILE_BYTES, collector.DEFAULT_MAX_TOTAL_BYTES)
        by_path = {entry.path: entry for entry in entries}
        check(by_path["config.json"].included is False and by_path["config.json"].text == "",
              "JSON file body is omitted at scan time")
        check(by_path["src/data/nested.json"].included is False and by_path["src/data/nested.json"].text == "",
              "nested JSON file body is omitted at scan time")
        check(by_path["src/app.py"].included, "Python source remains included")

        analysis = analyzer.analyze({"dump": first})
        check(any(row["path"] == "src/app.py" for row in analysis["files"]),
              "non-JSON source still reaches analyzer")
        check(not any(row["path"].endswith(".json") for row in analysis["files"]),
              "JSON files do not reach analyzer as source content")
        unparsed = {row["path"]: row["reason"] for row in analysis["unparsed"]}
        check(unparsed.get("config.json") == reason, "analyzer sees JSON as excluded metadata")
        check(unparsed.get("src/data/nested.json") == reason, "analyzer sees nested JSON as excluded metadata")
        check(sentinel not in json.dumps(analysis) and nested_sentinel not in json.dumps(analysis),
              "JSON contents do not reach downstream analysis")


def test_budget_and_errors() -> None:
    print("\nbudget and error handling")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "fixture-repo"
        root.mkdir()
        build_fixture(root)

        check(collector.DEFAULT_MAX_TOTAL_BYTES == 200 * 1024 * 1024, "total repository budget is 200 MiB")
        check(collector.DEFAULT_MAX_FILE_BYTES == 80_000, "per-file size limit is unchanged")

        entries = collector.scan(str(root), max_file_bytes=1000, max_total_bytes=20)
        omitted = [e for e in entries if "budget" in e.reason]
        included = [e for e in entries if e.included]
        check(bool(omitted), "total content budget is enforced")
        check(sum(len(e.text) for e in included) <= 20, "included content stays within budget")
        check(all(e.text == "" for e in omitted), "budget-omitted files have no partial content")
        for entry in included:
            on_disk = (root / entry.path).read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
            check(entry.text == on_disk, "budget does not silently truncate included files")

    for bad, label in [("", "empty input"), (os.path.join(tempfile.gettempdir(), "no-such-repo-xyz"), "missing path")]:
        try:
            collector.collect(bad)
            check(False, f"{label} raises CollectorError")
        except collector.CollectorError:
            check(True, f"{label} raises CollectorError")

    check(collector.is_remote(TARGET_REPO), "https URL detected as remote")
    check(collector.is_remote("git@gitlab.com:group/project.git"), "scp-style GitLab URL detected as remote")
    check(not collector.is_remote("/workspace/my-repo"), "local path not treated as remote")
    check(collector.repository_name(TARGET_REPO) == "github-mcp-chatbot", "repository name derived from URL")
    check(collector.repository_name("https://gitlab.com/g/p.git") == "p", "`.git` suffix stripped from name")
    check("***@" in collector.redact("https://user:tok@gitlab.com/g/p.git"), "credentials redacted in URLs")


def _git_ok() -> bool:
    result = subprocess.run(
        ["git", "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.returncode == 0


def _git(cwd: str, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_AUTHOR_NAME"] = "Collector Test"
    env["GIT_AUTHOR_EMAIL"] = "collector-test@example.com"
    env["GIT_COMMITTER_NAME"] = env["GIT_AUTHOR_NAME"]
    env["GIT_COMMITTER_EMAIL"] = env["GIT_AUTHOR_EMAIL"]
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )


def build_git_fixture(root: Path) -> dict[str, str]:
    """A real git repo with main, a feature branch, a tag, and two commits."""
    _git(str(root), "init", "-b", "main")
    (root / "README.md").write_text("main-content\n", encoding="utf-8")
    _git(str(root), "add", "README.md")
    _git(str(root), "commit", "-m", "init")
    main_sha = _git(str(root), "rev-parse", "HEAD").stdout.strip()

    _git(str(root), "checkout", "-b", "feature")
    (root / "README.md").write_text("feature-content\n", encoding="utf-8")
    _git(str(root), "add", "README.md")
    _git(str(root), "commit", "-m", "feature")
    feature_sha = _git(str(root), "rev-parse", "HEAD").stdout.strip()
    _git(str(root), "tag", "v1.0")
    _git(str(root), "checkout", "main")
    return {"main": main_sha, "feature": feature_sha, "tag": "v1.0"}


def test_urls_and_invalid_input() -> None:
    print("\nURL parsing")
    check(collector.is_remote("https://github.com/owner/name"), "GitHub URL detected as remote")
    check(collector.is_remote("https://gitlab.com/group/project.git"), "gitlab.com URL detected as remote")
    check(collector.is_remote("https://gitlab.example.com/group/project"), "self-hosted GitLab URL detected as remote")
    check(
        collector.repository_name("https://gitlab.example.com/group/project.git") == "project",
        "`.git` suffix stripped from self-hosted GitLab name",
    )
    host, name = collector.source_identity("https://gitlab.example.com/group/project.git")
    check(host == "gitlab.example.com" and name == "project", "source identity uses host and project name")
    check(
        collector.strip_userinfo("https://oauth2:secret@gitlab.example.com/g/p.git")
        == "https://gitlab.example.com/g/p.git",
        "userinfo is stripped from clone URLs",
    )

    try:
        collector.collect("https://")
        check(False, "invalid URL raises CollectorError")
    except collector.CollectorError as exc:
        check("Invalid repository URL" in str(exc) and exc.status == 400, "invalid URL uses the documented error")

    try:
        collector.collect("https://gitlab.example.com/")
        check(False, "URL with empty path raises CollectorError")
    except collector.CollectorError as exc:
        check("Invalid repository URL" in str(exc), "empty GitLab path is an invalid URL")


def _fake_secrets() -> dict[str, str]:
    """Runtime-only fixtures so complete secret strings are not stored in Git."""
    jwt = ".".join(
        (
            __import__("base64").urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode("ascii").rstrip("="),
            __import__("base64").urlsafe_b64encode(b'{"sub":"redaction-fixture"}').decode("ascii").rstrip("="),
            "sig" + ("C" * 24),
        )
    )
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + ("MIIEowFake" * 8)
        + "\n-----END RSA PRIVATE KEY-----"
    )
    return {
        "private-key": pem,
        "jwt": jwt,
        "aws": "AKIA" + "IOSFODNN7EXAMPLE",
        "github": "ghp_" + ("A" * 36),
        "gitlab": "glpat-" + ("B" * 20),
        "google": "AIza" + ("C" * 35),
        "slack": "xoxb-" + ("1" * 12) + "-" + ("D" * 24),
        "stripe": "sk_test_" + ("E" * 24),
        "openai": "sk-" + ("F" * 48),
        "bearer": "Bearer " + ("G" * 32),
        "password-url": "https://oauth2:" + ("H" * 16) + "@gitlab.example.com/g/p.git",
        "email": "qa.redaction@" + "example.com",
        "phone": "+1-202-555-0181",
        "card": "4111-1111-1111-1111",
        "ssn": "078-05-1120",
    }


def test_dump_sanitization() -> None:
    print("\ndump sanitization")
    import sanitizer  # noqa: E402

    secrets = _fake_secrets()
    src = (ROOT / "tools" / "repository-collector" / "sanitizer.py").read_text(encoding="utf-8")
    check("import logging" not in src and "print(" not in src, "sanitizer does not log or print matches")

    sample = "\n".join(
        [
            "print('hello')",
            f"AWS_KEY={secrets['aws']}",
            f"GITHUB={secrets['github']}",
            f"GITLAB={secrets['gitlab']}",
            f"GOOGLE={secrets['google']}",
            f"SLACK={secrets['slack']}",
            f"STRIPE={secrets['stripe']}",
            f"OPENAI={secrets['openai']}",
            f"AUTH={secrets['bearer']}",
            f"CLONE={secrets['password-url']}",
            f"CONTACT={secrets['email']}",
            f"PHONE={secrets['phone']}",
            f"CARD={secrets['card']}",
            f"SSN={secrets['ssn']}",
            f"TOKEN={secrets['jwt']}",
            secrets["private-key"],
            "remote = git@github.com:org/demo.git",
            "id 1234567890123",
        ]
    )
    first = sanitizer.sanitize(sample)
    second = sanitizer.sanitize(sample)
    check(first == second, "sanitizer is deterministic")
    check("print('hello')" in first, "non-sensitive source is kept")
    check("git@github.com:org/demo.git" in first, "git SCP remotes are not treated as emails")
    check("1234567890123" in first, "non-card digit strings are kept")

    for kind, value in secrets.items():
        if kind == "password-url":
            secret_part = ("H" * 16)
            check(secret_part not in first, f"{kind} original value is not in the sanitized text")
        elif kind == "bearer":
            check(("G" * 32) not in first, "bearer token original value is not in the sanitized text")
        else:
            check(value not in first, f"{kind} original value is not in the sanitized text")

    for marker in (
        sanitizer.REDACTED["aws-access-key"],
        sanitizer.REDACTED["github-pat"],
        sanitizer.REDACTED["gitlab-pat"],
        sanitizer.REDACTED["google-api-key"],
        sanitizer.REDACTED["slack-token"],
        sanitizer.REDACTED["stripe-key"],
        sanitizer.REDACTED["openai-key"],
        sanitizer.REDACTED["bearer-token"],
        sanitizer.REDACTED["password"],
        sanitizer.REDACTED["email"],
        sanitizer.REDACTED["phone"],
        sanitizer.REDACTED["card"],
        sanitizer.REDACTED["ssn"],
        sanitizer.REDACTED["jwt"],
        sanitizer.REDACTED["private-key"],
    ):
        check(marker in first, f"placeholder {marker} is present")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "leaky-repo"
        (root / "src").mkdir(parents=True)
        (root / "src" / "config.py").write_text(sample, encoding="utf-8")
        (root / ".env").write_text("SECRET=supersecret\n", encoding="utf-8")
        (root / "secrets.yaml").write_text("password: supersecret\n", encoding="utf-8")

        entries = collector.scan(str(root), max_file_bytes=80_000, max_total_bytes=collector.DEFAULT_MAX_TOTAL_BYTES)
        included = {e.path for e in entries if e.included}
        skipped = {e.path for e in entries if not e.included}
        check("src/config.py" in included, "content scanner does not replace filename filtering")
        check(".env" in skipped, "`.env` is still excluded by filename")
        check("secrets.yaml" in skipped, "`secrets.yaml` is still excluded by filename")

        raw_entry = next(e for e in entries if e.path == "src/config.py")
        check(secrets["email"] in raw_entry.text, "scan() still holds file text before dump sanitization")

        dump = collector.collect(str(root))
        check("FILE: src/config.py" in dump, "sensitive file is still listed in the dump")
        check("supersecret" not in dump, "filename-filtered secret contents never reach the dump")
        for kind, value in secrets.items():
            if kind == "password-url":
                check(("H" * 16) not in dump, f"{kind} original value cannot appear in the dump")
            elif kind == "bearer":
                check(("G" * 32) not in dump, "bearer original value cannot appear in the dump")
            else:
                check(value not in dump, f"{kind} original value cannot appear in the dump")
        again = collector.collect(str(root))
        check(dump == again, "sanitized dump remains deterministic")


def test_structured_sanitization() -> None:
    print("\nstructured sanitization")
    import structured  # noqa: E402

    src = (ROOT / "tools" / "repository-collector" / "structured.py").read_text(encoding="utf-8")
    check("import logging" not in src and "print(" not in src, "structured sanitizer does not log or print matches")

    check(structured.is_sensitive_key("password"), "password is a sensitive key")
    check(structured.is_sensitive_key("api_key"), "api_key is a sensitive key")
    check(structured.is_sensitive_key("apiKey"), "apiKey is a sensitive key")
    check(structured.is_sensitive_key("customer_email"), "customer_email is a sensitive key")
    check(structured.is_sensitive_key("account_number"), "account_number is a sensitive key")
    check(not structured.is_sensitive_key("host"), "host is not a sensitive key")
    check(not structured.is_sensitive_key("public_key"), "public_key is not treated as private_key")

    json_password = "plain-json-password-value"
    json_apikey = "plain-json-apikey-value"
    json_email_field = "desk-user-local"
    yaml_token = "plain-yaml-token-value"
    yaml_access = "plain-yaml-access-key-value"
    yaml_phone = "ext-4242"
    yaml_block = "plain-yaml-private-block-value"
    public_host = "keep-public-hostname"
    public_name = "Keep Display Name"

    json_text = (
        "{\n"
        f'  "password": "{json_password}",\n'
        f'  "apiKey": "{json_apikey}",\n'
        f'  "user": {{"customer_email": "{json_email_field}", "name": "{public_name}"}},\n'
        '  "items": [{"token": "plain-json-array-token", "id": 7}]\n'
        "}\n"
    )
    yaml_text = (
        f"token: {yaml_token}\n"
        f"access_key: {yaml_access}\n"
        f"phone: {yaml_phone}\n"
        f"host: {public_host}\n"
        "database:\n"
        "  password: plain-yaml-nested-password\n"
        "  name: appdb\n"
        "services:\n"
        "  - passwd: plain-yaml-list-passwd\n"
        "private_key: |\n"
        f"  {yaml_block}\n"
        "  still-block-secret\n"
        "inline: {secret: plain-yaml-flow-secret, host: inline-host}\n"
    )

    json_out = structured.sanitize_structured("config.json", json_text)
    yaml_out = structured.sanitize_structured("values.yaml", yaml_text)
    check(json_out == structured.sanitize_structured("config.json", json_text), "JSON sanitizer is deterministic")
    check(yaml_out == structured.sanitize_structured("values.yaml", yaml_text), "YAML sanitizer is deterministic")

    for original in (
        json_password,
        json_apikey,
        json_email_field,
        "plain-json-array-token",
    ):
        check(original not in json_out, "JSON original sensitive value is redacted")
    check(public_name in json_out, "non-sensitive JSON values are kept")
    check('"password"' in json_out and '"apiKey"' in json_out, "JSON keys are preserved")
    check(structured.FIELD_PLACEHOLDER in json_out, "JSON uses the field placeholder")

    for original in (
        yaml_token,
        yaml_access,
        yaml_phone,
        "plain-yaml-nested-password",
        "plain-yaml-list-passwd",
        yaml_block,
        "still-block-secret",
        "plain-yaml-flow-secret",
    ):
        check(original not in yaml_out, "YAML original sensitive value is redacted")
    check(public_host in yaml_out and "appdb" in yaml_out, "non-sensitive YAML values are kept")
    check("inline-host" in yaml_out, "non-sensitive YAML flow values are kept")
    check("token:" in yaml_out and "access_key:" in yaml_out, "YAML keys are preserved")
    check("print('hello')" == structured.sanitize_structured("src/app.py", "print('hello')"),
          "non JSON/YAML files are unchanged by structured sanitizer")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "structured-repo"
        (root / "src").mkdir(parents=True)
        (root / "config.json").write_text(json_text, encoding="utf-8")
        (root / "deploy.yml").write_text(yaml_text, encoding="utf-8")
        (root / "src" / "app.py").write_text("print('hello')\nHOST = 'keep-public-hostname'\n", encoding="utf-8")
        (root / ".env").write_text("SECRET=supersecret\n", encoding="utf-8")

        dump = collector.collect(str(root))
        check("FILE: config.json" not in dump, "JSON files are excluded from the collected dump")
        check("FILE: deploy.yml" in dump, "YAML structured files remain in the dump")
        check("print('hello')" in dump, "non-structured source is kept")
        check("supersecret" not in dump, "filename filtering still drops `.env`")
        check(public_name not in dump, "JSON contents never appear in the dump")
        for original in (
            json_password,
            json_apikey,
            json_email_field,
            "plain-json-array-token",
            yaml_token,
            yaml_access,
            yaml_phone,
            "plain-yaml-nested-password",
            "plain-yaml-list-passwd",
            yaml_block,
            "still-block-secret",
            "plain-yaml-flow-secret",
        ):
            check(original not in dump, "original structured secret cannot appear in the dump")
        check(public_host in dump, "non-sensitive YAML values reach the dump")
        check(dump == collector.collect(str(root)), "structured dump remains deterministic")


def _assert_absent(haystack: str, values: dict[str, str], label: str) -> None:
    for name, value in values.items():
        check(value not in haystack, f"{label}: {name} original value is absent")


def test_security_verification() -> None:
    print("\nsecurity verification")
    import server as collector_server  # noqa: E402
    import sanitizer  # noqa: E402
    import structured  # noqa: E402

    secrets = _fake_secrets()
    regex_values = {
        "aws": secrets["aws"],
        "github": secrets["github"],
        "gitlab": secrets["gitlab"],
        "google": secrets["google"],
        "slack": secrets["slack"],
        "stripe": secrets["stripe"],
        "openai": secrets["openai"],
        "jwt": secrets["jwt"],
        "private-key": secrets["private-key"],
        "email": secrets["email"],
        "phone": secrets["phone"],
        "card": secrets["card"],
        "ssn": secrets["ssn"],
        "url-password": "H" * 16,
        "bearer": "G" * 32,
    }
    structured_values = {
        "json-password": "plain-json-password-value",
        "json-apikey": "plain-json-apikey-value",
        "json-token": "plain-json-customer-token",
        "json-account": "acct-field-only-999",
        "yaml-password": "plain-yaml-password-value",
        "yaml-api-key": "plain-yaml-apikey-value",
        "yaml-card-field": "card-field-only-4242",
    }
    pii_values = {
        "customer-email": secrets["email"],
        "customer-phone": secrets["phone"],
        "customer-card": secrets["card"],
        "customer-ssn": secrets["ssn"],
    }
    excluded_values = {
        ".env": "EXCL_ENV_ZX9Q_LEAK",
        ".env.production": "EXCL_ENVPROD_ZX9Q_LEAK",
        "secrets.yaml": "EXCL_SECRETS_YAML_ZX9Q_LEAK",
        "credentials.json": "EXCL_CREDS_JSON_ZX9Q_LEAK",
        "id_rsa": "EXCL_ID_RSA_ZX9Q_LEAK",
        "tls.pem": "EXCL_TLS_PEM_ZX9Q_LEAK",
        "app.key": "EXCL_APP_KEY_ZX9Q_LEAK",
        "service-account.json": "EXCL_SA_JSON_ZX9Q_LEAK",
        ".git-credentials": "EXCL_GITCRED_ZX9Q_LEAK",
    }
    forbidden = {**regex_values, **structured_values, **pii_values, **excluded_values}

    render_src = inspect.getsource(collector.render)
    collect_src = inspect.getsource(collector.collect)
    server_src = (ROOT / "tools" / "repository-collector" / "server.py").read_text(encoding="utf-8")
    docs = (ROOT / "agents" / "repository-documentation.yaml").read_text(encoding="utf-8")
    check(
        render_src.find("sanitize_structured") < render_src.find("dump = sanitize("),
        "structured redaction runs before regex sanitization in render()",
    )
    check("dump = sanitize(" in render_src, "render() regex-sanitizes dump text")
    check(
        render_src.find("dump = sanitize(") < render_src.find("apply_local_llm_detections"),
        "optional Local LLM runs only after deterministic sanitization",
    )
    check("return apply_local_llm_detections(dump)" in render_src, "render() returns the post-sanitization dump")
    check("return render(collect_into(" in collect_src, "collect() output is the sanitized dump")
    check("dump = render(collection)" in server_src, "HTTP /collect payload is render() output")
    check("self._respond(200, dump)" in server_src, "HTTP /collect returns the sanitized dump body")
    check("entry.text" not in server_src, "HTTP handler does not send unsanitized file bodies")
    tools_block = docs.split("prompt:", 1)[0]
    check(
        tools_block.count("type: http") == 1
        and "repository-collector" in tools_block
        and "repository-analyzer" not in tools_block
        and "repository-map" not in tools_block,
        "Documentation Agent receives repository content via collector only",
    )
    check("repository-changes" not in tools_block and "repository-impact" not in tools_block,
          "Documentation Agent does not call deterministic /changes or /impact")
    check("documentation-renderer" not in tools_block, "Documentation Agent does not receive renderer payloads")
    analyzer_src = (ROOT / "tools" / "repository-analyzer" / "analyzer.py").read_text(encoding="utf-8")
    check("collect_into" not in analyzer_src and "import collector" not in analyzer_src,
          "analyzer does not read raw collector entries")
    mapper_src = (ROOT / "tools" / "repository-map" / "mapper.py").read_text(encoding="utf-8")
    check("collect_into" not in mapper_src and "import collector" not in mapper_src,
          "repository map does not read raw collector entries")
    check("import ast" not in mapper_src and "analyze_repository" not in mapper_src,
          "repository map does not parse AST or resolve references")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "security-repo"
        (root / "src").mkdir(parents=True)
        (root / "src" / "leaks.py").write_text(
            "\n".join(
                [
                    "print('safe-source')",
                    f"AWS_KEY={secrets['aws']}",
                    f"GITHUB={secrets['github']}",
                    f"GITLAB={secrets['gitlab']}",
                    f"GOOGLE={secrets['google']}",
                    f"SLACK={secrets['slack']}",
                    f"STRIPE={secrets['stripe']}",
                    f"OPENAI={secrets['openai']}",
                    f"AUTH={secrets['bearer']}",
                    f"CLONE={secrets['password-url']}",
                    f"CONTACT={secrets['email']}",
                    f"PHONE={secrets['phone']}",
                    f"CARD={secrets['card']}",
                    f"SSN={secrets['ssn']}",
                    f"TOKEN={secrets['jwt']}",
                    secrets["private-key"],
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "customers.json").write_text(
            json.dumps(
                {
                    "password": structured_values["json-password"],
                    "api_key": structured_values["json-apikey"],
                    "customer": {
                        "customer_email": structured_values["json-token"],
                        "account_number": structured_values["json-account"],
                        "name": "Acme Storefront",
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "billing.yaml").write_text(
            "\n".join(
                [
                    f"password: {structured_values['yaml-password']}",
                    f"api_key: {structured_values['yaml-api-key']}",
                    f"card_number: {structured_values['yaml-card-field']}",
                    "host: keep-billing-host",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "pii.txt").write_text(
            "\n".join(
                [
                    f"email={pii_values['customer-email']}",
                    f"phone={pii_values['customer-phone']}",
                    f"card={pii_values['customer-card']}",
                    f"ssn={pii_values['customer-ssn']}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (root / ".env").write_text(f"SECRET={excluded_values['.env']}\n", encoding="utf-8")
        (root / ".env.production").write_text(
            f"SECRET={excluded_values['.env.production']}\n", encoding="utf-8"
        )
        (root / "secrets.yaml").write_text(
            f"password: {excluded_values['secrets.yaml']}\n", encoding="utf-8"
        )
        (root / "credentials.json").write_text(
            json.dumps({"token": excluded_values["credentials.json"]}) + "\n",
            encoding="utf-8",
        )
        (root / "id_rsa").write_text(excluded_values["id_rsa"] + "\n", encoding="utf-8")
        (root / "tls.pem").write_text(excluded_values["tls.pem"] + "\n", encoding="utf-8")
        (root / "app.key").write_text(excluded_values["app.key"] + "\n", encoding="utf-8")
        (root / "service-account.json").write_text(
            json.dumps({"private_key": excluded_values["service-account.json"]}) + "\n",
            encoding="utf-8",
        )
        (root / ".git-credentials").write_text(
            excluded_values[".git-credentials"] + "\n", encoding="utf-8"
        )

        dump = collector.collect(str(root))
        check("safe-source" in dump, "non-sensitive source still reaches the dump")
        check("Acme Storefront" not in dump, "JSON contents never reach the dump")
        check("FILE: customers.json" not in dump, "JSON files are excluded from the collected dump")
        check("keep-billing-host" in dump, "non-sensitive YAML fields still reach the dump")
        _assert_absent(dump, regex_values, "regex secrets in collector dump")
        _assert_absent(dump, structured_values, "JSON/YAML field values in collector dump")
        _assert_absent(dump, pii_values, "PII/financial values in collector dump")
        _assert_absent(dump, excluded_values, "filename/suffix-excluded file contents in collector dump")
        for marker in (
            sanitizer.REDACTED["aws-access-key"],
            sanitizer.REDACTED["email"],
            sanitizer.REDACTED["card"],
            structured.FIELD_PLACEHOLDER,
        ):
            check(marker in dump, f"sanitized dump contains {marker}")

        records: list[str] = []

        class _ListHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(self.format(record))

        handler = _ListHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        collector_server.log.addHandler(handler)
        previous_level = collector_server.log.level
        collector_server.log.setLevel(logging.DEBUG)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), collector_server.Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            port = httpd.server_address[1]
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/collect",
                data=json.dumps({"repository": str(root)}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read().decode("utf-8")
                status = response.status
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode("utf-8", errors="replace")
            status = exc.code
            check(False, f"HTTP /collect failed ({status}): {payload[:200]!r}")
            payload = ""
        finally:
            httpd.shutdown()
            httpd.server_close()
            collector_server.log.removeHandler(handler)
            collector_server.log.setLevel(previous_level)

        check(status == 200, "HTTP /collect returns 200 for the security fixture")
        check(payload == dump, "tool payload matches the sanitized collector dump")
        _assert_absent(payload, forbidden, "tool payload")
        joined_logs = "\n".join(records)
        _assert_absent(joined_logs, forbidden, "collector logs")


def _llm_env(**values: str | None) -> dict[str, str | None]:
    keys = ("LOCAL_LLM_ENABLED", "LOCAL_LLM_URL", "LOCAL_LLM_TIMEOUT_SECONDS")
    previous = {key: os.environ.get(key) for key in keys}
    for key in keys:
        os.environ.pop(key, None)
    for key, value in values.items():
        if value is not None:
            os.environ[key] = value
    return previous


def _restore_env(previous: dict[str, str | None]) -> None:
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def test_local_llm_detector() -> None:
    print("\nlocal LLM detector")
    import local_llm  # noqa: E402
    from http.server import BaseHTTPRequestHandler

    src = (ROOT / "tools" / "repository-collector" / "local_llm.py").read_text(encoding="utf-8")
    check("import logging" not in src, "Local LLM client does not log detections")

    previous = _llm_env()
    try:
        detector = local_llm.LocalLLMDetector.from_env()
        check(not detector.enabled, "Local LLM is disabled by default")
        check(detector.detect("token=super-secret") == [], "disabled detector returns no detections")
        check(local_llm.augment("already-sanitized") == "already-sanitized", "disabled augment is a no-op")
    finally:
        _restore_env(previous)

    previous = _llm_env(LOCAL_LLM_ENABLED="true", LOCAL_LLM_URL="http://127.0.0.1:65534", LOCAL_LLM_TIMEOUT_SECONDS="1")
    try:
        detector = local_llm.LocalLLMDetector.from_env()
        check(detector.enabled, "Local LLM enables when LOCAL_LLM_ENABLED and LOCAL_LLM_URL are set")
        original = "keep-this-text"
        check(detector.detect(original) == [], "unavailable endpoint yields no detections")
        check(local_llm.augment(original) == original, "unavailable endpoint leaves sanitized text unchanged")
    finally:
        _restore_env(previous)

    marker = "LLM_SPAN_ONLY"
    sanitized = f"prefix {marker} suffix"

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            text = body.get("text") or ""
            start = text.find(marker)
            payload = {
                "redacted_text": "untrusted-rewrite",
                "detections": [
                    {
                        "type": "secret",
                        "start": start,
                        "end": start + len(marker),
                        "value": marker,
                        "replacement": "untrusted-rewrite",
                    }
                ],
            }
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}"
        previous = _llm_env(LOCAL_LLM_ENABLED="true", LOCAL_LLM_URL=url, LOCAL_LLM_TIMEOUT_SECONDS="2")
        try:
            detector = local_llm.LocalLLMDetector.from_env()
            detections = detector.detect(sanitized)
            check(len(detections) == 1, "valid structured detections are parsed")
            check(detections[0].type == "secret" and detections[0].start >= 0, "detection has type and positions")
            redacted = local_llm.augment(sanitized, detector)
            check(marker not in redacted, "our redactor masks the detected span")
            check("untrusted-rewrite" not in redacted, "model-produced replacement text is ignored")
            check("[REDACTED:secret]" in redacted, "placeholder comes from our redactor")
            check(redacted.startswith("prefix ") and redacted.endswith(" suffix"), "surrounding sanitized text is kept")
        finally:
            _restore_env(previous)
    finally:
        httpd.shutdown()
        httpd.server_close()

    ignored = local_llm.parse_detections(
        {"redacted_text": "wiped", "detections": [{"type": "secret", "start": -1, "end": 4}]},
        10,
    )
    check(ignored == [], "invalid spans are dropped")
    applied = local_llm.apply_detections(
        "abcdefghij",
        [local_llm.Detection("secret", 2, 5)],
    )
    check(applied == "ab[REDACTED:secret]fghij", "apply_detections masks by start/end only")

    previous = _llm_env()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "llm-off-repo"
            root.mkdir()
            (root / "readme.md").write_text("hello from optional llm off\n", encoding="utf-8")
            dump = collector.collect(str(root))
            check("hello from optional llm off" in dump, "collector runs without a Local LLM endpoint")
    finally:
        _restore_env(previous)


def _host_modules():
    app_dir = str(ROOT / "app")
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)
    import ark_client  # noqa: E402
    import documentation_registry  # noqa: E402
    import validation  # noqa: E402

    return validation, ark_client, documentation_registry


def _expect_invalid(validate, error_type, url: str, ref: str, needle: str, label: str) -> None:
    try:
        validate(url, ref)
        check(False, label)
    except error_type as exc:
        check(needle.lower() in str(exc).lower(), f"{label} (got {exc!r})")
    except Exception as exc:
        check(False, f"{label} raised {type(exc).__name__}: {exc}")


def test_input_validation() -> None:
    print("\ninput validation")
    validation, ark_client, _registry = _host_modules()

    github, ref = validation.validate_pipeline_input("https://github.com/MooAyman/github-mcp-chatbot")
    check(github == "https://github.com/MooAyman/github-mcp-chatbot" and ref == "", "GitHub HTTPS URL is accepted")
    www, _ = validation.validate_pipeline_input("https://www.github.com/MooAyman/github-mcp-chatbot")
    check(www == "https://github.com/MooAyman/github-mcp-chatbot",
          "www.github.com is normalized to github.com")
    www_gl, _ = validation.validate_pipeline_input("https://www.gitlab.com/group/project")
    check(www_gl == "https://gitlab.com/group/project",
          "www.gitlab.com is normalized to gitlab.com")

    gitlab, _ = validation.validate_pipeline_input("https://gitlab.com/group/project.git/")
    check(gitlab == "https://gitlab.com/group/project.git", "gitlab.com URL is accepted and trailing slash stripped")

    hosted, hosted_ref = validation.validate_pipeline_input(
        "http://gitlab.example.com:8080/group/sub/project",
        " develop ",
    )
    check(
        hosted == "http://gitlab.example.com:8080/group/sub/project" and hosted_ref == "develop",
        "self-hosted GitLab HTTP URL with nested groups is accepted",
    )

    tagged, sha_ref = validation.validate_pipeline_input(
        TARGET_REPO,
        "v1.3.0",
    )
    check(tagged == TARGET_REPO and sha_ref == "v1.3.0", "tag ref syntax is accepted")
    _, commit = validation.validate_pipeline_input(TARGET_REPO, "abcdeff")
    check(commit == "abcdeff", "short commit SHA syntax is accepted")
    check(validation.validate_commit_sha("") == "", "empty previous commit SHA is allowed")
    check(validation.validate_commit_sha("abcdeff") == "abcdeff", "documented commit SHA syntax is accepted")
    try:
        validation.validate_commit_sha("not-a-sha")
        check(False, "invalid commit SHA is rejected")
    except validation.ValidationError as exc:
        check("commit sha" in str(exc).lower(), "invalid commit SHA uses a ValidationError")
    _, missing = validation.validate_pipeline_input(TARGET_REPO, "this-ref-does-not-exist-xyz")
    check(missing == "this-ref-does-not-exist-xyz", "ref existence is not checked here")
    _, branch = validation.validate_pipeline_input(TARGET_REPO, "feature/better-docs")
    check(branch == "feature/better-docs", "hierarchical branch names are accepted")

    message = ark_client.build_input("https://github.com/a/b", "main")
    check(
        message == "Document this repository: https://github.com/a/b ref: main",
        "build_input keeps the V1.3.0 Query sentence after validation",
    )

    cases = [
        ("", "", "required", "empty URL is rejected"),
        ("/tmp/repo", "", "local filesystem", "Unix local path is rejected"),
        (r"C:\Users\me\repo", "", "local filesystem", "Windows local path is rejected"),
        ("./repo", "", "local filesystem", "relative local path is rejected"),
        ("git@github.com:owner/repo.git", "", "http or https", "SCP Git URL is rejected"),
        ("git://github.com/owner/repo", "", "http or https", "git:// URL is rejected"),
        ("ssh://git@github.com/owner/repo", "", "http or https", "ssh:// URL is rejected"),
        ("https://user:token@github.com/owner/repo", "", "credential", "embedded userinfo is rejected"),
        ("https://github.com/owner", "", "owner/repository", "GitHub URL missing repository is rejected"),
        ("https://github.com/owner/repo/tree/main", "", "owner/repository", "GitHub web UI path is rejected"),
        ("https://gitlab.com/group/project/-/blob/main/README.md", "", "clone URL", "GitLab web UI path is rejected"),
        ("https://github.com/owner/repo?foo=1", "", "query string", "query string is rejected"),
        ("https://github.com/owner/repo#readme", "", "fragment", "fragment is rejected"),
        ("https://github.com/", "", "owner/repository", "URL with empty path is rejected"),
    ]
    for url, ref, needle, label in cases:
        _expect_invalid(validation.validate_pipeline_input, validation.ValidationError, url, ref, needle, label)

    ref_cases = [
        ("-bad", "must not start", "ref starting with '-' is rejected"),
        ("has space", "syntax", "ref with spaces is rejected"),
        ("foo..bar", "syntax", "ref with '..' is rejected"),
        ("foo~1", "syntax", "revision syntax is rejected"),
        ("@", "syntax", "lone '@' is rejected"),
        ("heads/.hidden", "syntax", "ref component starting with '.' is rejected"),
    ]
    for ref, needle, label in ref_cases:
        _expect_invalid(validation.validate_pipeline_input, validation.ValidationError, TARGET_REPO, ref, needle, label)

    try:
        ark_client.build_input("https://user:pass@github.com/a/b")
        check(False, "build_input rejects credentials before Query construction")
    except ark_client.ValidationError as exc:
        check("credential" in str(exc).lower(), "build_input credential error is a ValidationError")


def test_ref_handling() -> None:
    print("\nref handling")
    if not _git_ok():
        print("  skip  git is not available on PATH")
        return

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "git-repo"
        root.mkdir()
        shas = build_git_fixture(root)

        default_dump = collector.collect(str(root))
        check("main-content" in default_dump, "empty ref uses the default branch")
        check("feature-content" not in default_dump, "empty ref does not check out another branch")

        feature_dump = collector.collect(str(root), ref="feature")
        check("feature-content" in feature_dump, "explicit branch is collected")
        check("REQUESTED_REF: feature" in feature_dump, "requested branch is recorded")
        check("main-content" not in feature_dump, "explicit branch does not fall back to default")

        tag_dump = collector.collect(str(root), ref="v1.0")
        check("feature-content" in tag_dump, "explicit tag is collected")
        check("REQUESTED_REF: v1.0" in tag_dump, "requested tag is recorded")

        commit_dump = collector.collect(str(root), ref=shas["feature"])
        check("feature-content" in commit_dump, "explicit commit SHA is collected")
        check(f"COMMIT: {shas['feature']}" in commit_dump, "checked-out commit matches the requested SHA")

        short_sha = shas["main"][:8]
        main_from_sha = collector.collect(str(root), ref=short_sha)
        check("main-content" in main_from_sha, "abbreviated commit SHA is collected")
        check("feature-content" not in main_from_sha, "commit SHA does not fall back to a later branch")

        try:
            collector.collect(str(root), ref="no-such-ref")
            check(False, "nonexistent ref raises CollectorError")
        except collector.CollectorError as exc:
            check(
                "Requested ref not found" in str(exc) and exc.status == 404,
                "nonexistent ref fails clearly and does not fall back",
            )


def _change(
    path: str,
    status: str,
    src: str = "",
    *,
    eligible: bool = True,
    reason: str = "",
) -> dict:
    row: dict = {"path": path, "status": status, "eligible": eligible}
    if src:
        row["from"] = src
    if reason:
        row["reason"] = reason
    return row


def build_change_fixture(root: Path) -> dict[str, str]:
    """Two commits: add, modify, delete, rename, plus an unchanged file."""
    _git(str(root), "init", "-b", "main")
    (root / "stay.txt").write_text("unchanged\n", encoding="utf-8")
    (root / "keep.txt").write_text("version-one\n", encoding="utf-8")
    (root / "gone.txt").write_text("delete-me\n", encoding="utf-8")
    (root / "old_name.txt").write_text("rename-me\n", encoding="utf-8")
    _git(str(root), "add", "stay.txt", "keep.txt", "gone.txt", "old_name.txt")
    _git(str(root), "commit", "-m", "base")
    previous = _git(str(root), "rev-parse", "HEAD").stdout.strip()

    (root / "keep.txt").write_text("version-two\n", encoding="utf-8")
    (root / "added.txt").write_text("new-file\n", encoding="utf-8")
    _git(str(root), "rm", "gone.txt")
    _git(str(root), "mv", "old_name.txt", "new_name.txt")
    _git(str(root), "add", "keep.txt", "added.txt", "new_name.txt")
    _git(str(root), "commit", "-m", "changes")
    current = _git(str(root), "rev-parse", "HEAD").stdout.strip()
    return {"previous": previous, "current": current}


def test_git_change_detection() -> None:
    print("\nGit change detection")
    if not _git_ok():
        print("  skip  git is not available on PATH")
        return

    import changes  # noqa: E402
    import server as collector_server  # noqa: E402

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "change-repo"
        root.mkdir()
        shas = build_change_fixture(root)

        first = changes.detect_changes(str(root))
        check(first["schemaVersion"] == "1", "change schemaVersion is 1")
        check(first["mode"] == "full", "no previous SHA is a first/full run")
        check(first["previousCommit"] == "", "first run has an empty previousCommit")
        check(first["newCommit"] == shas["current"], "first run resolves HEAD as newCommit")
        check(first["changed"] == [], "first run does not invent a change list")
        check(first == changes.detect_changes(str(root)), "first-run detection is deterministic")

        result = changes.detect_changes(
            str(root),
            previous_commit=shas["previous"],
            new_commit=shas["current"],
        )
        check(result == changes.detect_changes(
            str(root),
            previous_commit=shas["previous"],
            new_commit=shas["current"],
        ), "incremental detection is deterministic")
        check(result["mode"] == "incremental", "two SHAs produce an incremental result")
        check(result["previousCommit"] == shas["previous"], "previousCommit is the resolved old SHA")
        check(result["newCommit"] == shas["current"], "newCommit is the resolved new SHA")
        by_path = {row["path"]: row for row in result["changed"]}
        check(by_path.get("added.txt") == _change("added.txt", "added"), "added file is reported")
        check(by_path.get("keep.txt") == _change("keep.txt", "modified"), "modified file is reported")
        check(by_path.get("gone.txt") == _change("gone.txt", "deleted"), "deleted file is reported")
        check(
            by_path.get("new_name.txt") == _change("new_name.txt", "renamed", "old_name.txt"),
            "renamed file is reported",
        )
        check("stay.txt" not in by_path, "unchanged file is omitted")
        check("version-two" not in json.dumps(result) and "delete-me" not in json.dumps(result),
              "change detection does not include file contents")

        same = changes.detect_changes(
            str(root),
            previous_commit=shas["current"],
            new_commit=shas["current"],
        )
        check(same["mode"] == "incremental" and same["changed"] == [],
              "unchanged repository yields an empty change list")

        try:
            changes.detect_changes(str(root), previous_commit="not-a-sha")
            check(False, "invalid previous SHA is rejected")
        except collector.CollectorError as exc:
            check(exc.status == 400 and "commit SHA" in str(exc), "invalid previous SHA is a 400")

        missing = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        try:
            changes.detect_changes(str(root), previous_commit=missing, new_commit=shas["current"])
            check(False, "missing previous SHA is rejected")
        except collector.CollectorError as exc:
            check(exc.status == 404 and "not found" in str(exc).lower(), "missing previous SHA is a 404")

        try:
            changes.detect_changes(str(root), new_commit="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            check(False, "missing new SHA is rejected")
        except collector.CollectorError as exc:
            check(exc.status == 404, "missing new SHA is a 404")

        parsed = {row["path"]: row["status"] for row in changes._parse_name_status(
            "U\tsrc/conflict.py\nX\tsrc/weird.py\nT\tsrc/typed.py\nM\tsrc/ok.py\n"
        )}
        check(parsed.get("src/conflict.py") == "modified", "unmerged git status is treated as modified")
        check(parsed.get("src/weird.py") == "modified", "unknown git status is treated as modified")
        check(parsed.get("src/typed.py") == "modified", "typechange git status is treated as modified")
        check(parsed.get("src/ok.py") == "modified", "modified git status is unchanged")

        _git(str(root), "checkout", "--orphan", "rewrite")
        (root / "orphan.txt").write_text("unrelated-history\n", encoding="utf-8")
        _git(str(root), "add", "orphan.txt")
        _git(str(root), "commit", "-m", "orphan")
        rewritten = _git(str(root), "rev-parse", "HEAD").stdout.strip()
        try:
            changes.detect_changes(
                str(root),
                previous_commit=shas["previous"],
                new_commit=rewritten,
            )
            check(False, "rewritten history is rejected")
        except collector.CollectorError as exc:
            check(exc.status == 400 and "not an ancestor" in str(exc),
                  "non-ancestor previousCommit is a 400")
        try:
            changes.detect_changes(
                str(root),
                previous_commit=shas["current"],
                new_commit=shas["previous"],
            )
            check(False, "backwards previousCommit is rejected")
        except collector.CollectorError as exc:
            check(exc.status == 400 and "not an ancestor" in str(exc),
                  "newer-to-older previousCommit is a 400")
        _git(str(root), "checkout", "--force", shas["current"])

        dump = collector.collect(str(root))
        check("version-two" in dump and "FILE: stay.txt" in dump, "collection of the same repo is unchanged")

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), collector_server.Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            port = httpd.server_address[1]
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/changes",
                data=json.dumps({
                    "repository": str(root),
                    "previousCommit": shas["previous"],
                    "newCommit": shas["current"],
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
                status = response.status
            check(status == 200 and payload == result, "POST /changes returns the same change JSON")
            empty = urllib.request.Request(
                f"http://127.0.0.1:{port}/changes",
                data=json.dumps({"repository": str(root)}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(empty, timeout=30) as response:
                full_payload = json.loads(response.read().decode("utf-8"))
            check(full_payload["mode"] == "full" and full_payload["changed"] == [],
                  "POST /changes without previousCommit is a first/full run")
        finally:
            httpd.shutdown()
            httpd.server_close()


def build_filtered_change_fixture(root: Path) -> dict[str, str]:
    """Eligible and excluded adds, edits, deletes, and renames in one repo."""
    _git(str(root), "init", "-b", "main")
    (root / "src").mkdir()
    (root / "node_modules" / "left-pad").mkdir(parents=True)
    (root / "src" / "main.py").write_text("print('v1')\n", encoding="utf-8")
    (root / "README.md").write_text("# Docs\n", encoding="utf-8")
    (root / "gone.txt").write_text("delete-me\n", encoding="utf-8")
    (root / "old_name.txt").write_text("rename-me\n", encoding="utf-8")
    (root / "leak.txt").write_text("was-public\n", encoding="utf-8")
    (root / ".env").write_text("SECRET=one\n", encoding="utf-8")
    (root / ".env.production").write_text("SECRET=prod\n", encoding="utf-8")
    (root / "secrets.yaml").write_text("token: a\n", encoding="utf-8")
    (root / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")
    (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
    (root / "node_modules" / "left-pad" / "index.js").write_text("module.exports = 1\n", encoding="utf-8")
    _git(str(root), "add", "-f", "-A")
    _git(str(root), "commit", "-m", "base")
    previous = _git(str(root), "rev-parse", "HEAD").stdout.strip()

    (root / "src" / "main.py").write_text("print('v2')\n", encoding="utf-8")
    (root / "src" / "added.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / ".env").write_text("SECRET=two\n", encoding="utf-8")
    (root / "package-lock.json").write_text('{"lockfileVersion": 3, "x": 1}\n', encoding="utf-8")
    (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x01")
    (root / "node_modules" / "left-pad" / "index.js").write_text("module.exports = 2\n", encoding="utf-8")
    (root / "server.key").write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")
    (root / "yarn.lock").write_text("# yarn\n", encoding="utf-8")
    (root / ".env.example").write_text("SECRET=changeme\n", encoding="utf-8")
    _git(str(root), "rm", "gone.txt")
    _git(str(root), "mv", "old_name.txt", "new_name.txt")
    _git(str(root), "mv", "leak.txt", ".env.local")
    _git(str(root), "mv", ".env.production", "config.md")
    _git(str(root), "mv", "secrets.yaml", "secrets.yml")
    _git(str(root), "add", "-f", "-A")
    _git(str(root), "commit", "-m", "mixed")
    current = _git(str(root), "rev-parse", "HEAD").stdout.strip()
    return {"previous": previous, "current": current}


def test_change_filtering() -> None:
    print("\nGit change filtering")
    if not _git_ok():
        print("  skip  git is not available on PATH")
        return

    import changes  # noqa: E402
    import server as collector_server  # noqa: E402

    check(collector.is_collectable_path("src/main.py"), "source path is collectable")
    check(collector.is_collectable_path("README.md"), "README is collectable")
    check(collector.is_collectable_path(".env.example"), "allowed env example is collectable")
    check(not collector.is_collectable_path(".env"), "`.env` is not collectable")
    check(not collector.is_collectable_path("package-lock.json"), "lockfile is not collectable")
    check(not collector.is_collectable_path("yarn.lock"), "yarn.lock is not collectable")
    check(not collector.is_collectable_path("server.key"), "private key is not collectable")
    check(not collector.is_collectable_path("logo.png"), "binary extension is not collectable")
    check(not collector.is_collectable_path("node_modules/left-pad/index.js"),
          "dependency directory is not collectable")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "filtered-repo"
        root.mkdir()
        shas = build_filtered_change_fixture(root)

        result = changes.detect_changes(
            str(root),
            previous_commit=shas["previous"],
            new_commit=shas["current"],
        )
        check(result == changes.detect_changes(
            str(root),
            previous_commit=shas["previous"],
            new_commit=shas["current"],
        ), "filtered change detection is deterministic")
        by_path = {row["path"]: row for row in result["changed"]}

        check(by_path.get("src/added.py") == _change("src/added.py", "added"),
              "eligible added file is returned")
        check(by_path.get(".env.example") == _change(".env.example", "added"),
              "allowed `.env.example` change is returned")
        check(by_path.get("src/main.py") == _change("src/main.py", "modified"),
              "eligible modified file is returned")
        check(by_path.get("gone.txt") == _change("gone.txt", "deleted"),
              "eligible deleted file is returned")
        check(
            by_path.get("new_name.txt") == _change("new_name.txt", "renamed", "old_name.txt"),
            "eligible-to-eligible rename is returned as renamed",
        )
        check(by_path.get("config.md") == _change("config.md", "added"),
              "excluded-to-eligible rename is returned as added")
        check(by_path.get("leak.txt") == _change("leak.txt", "deleted"),
              "eligible-to-excluded rename is returned as deleted")

        excluded = [
            ".env",
            ".env.local",
            ".env.production",
            "package-lock.json",
            "yarn.lock",
            "server.key",
            "logo.png",
            "node_modules/left-pad/index.js",
            "secrets.yaml",
            "secrets.yml",
        ]
        for path in excluded:
            check(path not in by_path, f"excluded path {path} is not returned")
        check("SECRET=two" not in json.dumps(result) and "delete-me" not in json.dumps(result),
              "filtered changes still omit file contents")

        dump = collector.collect(str(root))
        check("FILE: src/main.py" in dump and "print('v2')" in dump, "collect still includes eligible source")
        check("FILE: src/added.py" in dump, "collect still includes newly added eligible source")
        check("FILE: README.md" in dump, "collect still includes unchanged eligible files")
        check("FILE: .env.example" in dump, "collect still includes allowed env example")
        check("\nFILE: .env\n" not in dump and "SECRET=two" not in dump, "collect still excludes `.env`")
        check("FILE: package-lock.json" not in dump and "FILE: yarn.lock" not in dump,
              "collect still excludes lockfiles")
        check("FILE: server.key" not in dump, "collect still excludes private keys")
        check("FILE: logo.png" not in dump, "collect still excludes binaries")
        check("node_modules" not in dump, "collect still skips dependency directories")

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), collector_server.Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            port = httpd.server_address[1]
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/changes",
                data=json.dumps({
                    "repository": str(root),
                    "previousCommit": shas["previous"],
                    "newCommit": shas["current"],
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
            check(payload == result, "POST /changes returns the filtered change JSON")
        finally:
            httpd.shutdown()
            httpd.server_close()


def test_change_eligibility_and_budget() -> None:
    print("\nGit change eligibility and collection budget")
    if not _git_ok():
        print("  skip  git is not available on PATH")
        return

    import changes  # noqa: E402

    binary_reason = "excluded: binary or undecodable content"

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "budget-repo"
        root.mkdir()
        _git(str(root), "init", "-b", "main")
        (root / "keep.py").write_text("print('v1')\n", encoding="utf-8")
        (root / "gone_big.py").write_text("OLD-LINE\n" * 12_000, encoding="utf-8")
        (root / "blob.txt").write_bytes(b"text\x00with-null-bytes")
        (root / ".env").write_text("SECRET=one\n", encoding="utf-8")
        _git(str(root), "add", "-f", "-A")
        _git(str(root), "commit", "-m", "base")
        previous = _git(str(root), "rev-parse", "HEAD").stdout.strip()

        (root / "keep.py").write_text("print('v2')\n", encoding="utf-8")
        (root / "added.py").write_text("VALUE = 1\n", encoding="utf-8")
        (root / "huge.py").write_text("NEW-FILE-CONTENT\n" * 8_000, encoding="utf-8")
        (root / "blob.txt").write_bytes(b"text\x00changed-nulls")
        (root / ".env").write_text("SECRET=two\n", encoding="utf-8")
        _git(str(root), "rm", "-f", "gone_big.py")
        _git(str(root), "add", "-f", "-A")
        _git(str(root), "commit", "-m", "over-budget-mix")
        current = _git(str(root), "rev-parse", "HEAD").stdout.strip()

        result = changes.detect_changes(str(root), previous_commit=previous, new_commit=current)
        by_path = {row["path"]: row for row in result["changed"]}

        check(by_path.get("keep.py") == _change("keep.py", "modified"),
              "small modified file stays eligible")
        check(by_path.get("added.py") == _change("added.py", "added"),
              "small added file stays eligible")
        huge = by_path.get("huge.py") or {}
        check(
            huge.get("path") == "huge.py" and huge.get("status") == "added" and huge.get("eligible") is False
            and "exceeds limit" in str(huge.get("reason") or ""),
            "oversized added file is still reported as a Git change",
        )
        gone_big = by_path.get("gone_big.py") or {}
        check(
            gone_big.get("path") == "gone_big.py"
            and gone_big.get("status") == "deleted"
            and gone_big.get("eligible") is False
            and "exceeds limit" in str(gone_big.get("reason") or ""),
            "oversized deleted file uses previous-commit size, not current content",
        )
        check(
            by_path.get("blob.txt") == _change("blob.txt", "modified", eligible=False, reason=binary_reason),
            "NUL/binary changed file is still reported as a Git change",
        )
        check(".env" not in by_path, "path-excluded secret is still omitted from /changes")
        dumped = json.dumps(result)
        check("print('v2')" not in dumped and "SECRET=two" not in dumped and "changed-nulls" not in dumped,
              "eligibility annotation does not include file contents")

        tiny = collector.scan(str(root), max_file_bytes=80_000, max_total_bytes=20)
        check("keep.py" in by_path and "added.py" in by_path,
              "/changes still reports files that exceed the collect total budget")
        omitted = [e for e in tiny if "budget" in e.reason]
        check(bool(omitted), "/collect still enforces the total safety ceiling")
        check(all(e.text == "" for e in omitted), "/collect does not silently truncate when the ceiling is reached")
        included = [e for e in tiny if e.included]
        check(sum(len(e.text) for e in included) <= 20, "/collect included content stays within the ceiling")

        default_scan = collector.scan(
            str(root),
            max_file_bytes=collector.DEFAULT_MAX_FILE_BYTES,
            max_total_bytes=collector.DEFAULT_MAX_TOTAL_BYTES,
        )
        by_scan = {e.path: e for e in default_scan}
        check(not by_scan["huge.py"].included and "exceeds limit" in by_scan["huge.py"].reason,
              "per-file size limit still excludes oversized files from /collect")
        check(not by_scan["blob.txt"].included and "binary" in by_scan["blob.txt"].reason,
              "NUL/binary files are still excluded from /collect")
        check(by_scan["keep.py"].included and by_scan["added.py"].included,
              "/collect still includes path-eligible files under the per-file limit")
        check(".env" in by_scan and not by_scan[".env"].included, "/collect still excludes `.env`")


def test_excluded_file_visibility() -> None:
    print("\nexcluded file visibility")
    sys.path.insert(0, str(ROOT / "tools" / "repository-analyzer"))
    sys.path.insert(0, str(ROOT / "tools" / "repository-map"))
    import analyzer  # noqa: E402
    import mapper  # noqa: E402
    import changes  # noqa: E402

    sentinel = "OVERSIZE_UNIQUE_PAYLOAD_XYZ"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "visible-repo"
        root.mkdir()
        if _git_ok():
            _git(str(root), "init", "-b", "main")
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        (root / "huge.py").write_text(f"{sentinel} = 1\n" + ("x = 0\n" * 20_000), encoding="utf-8")
        (root / ".env").write_text("SECRET=should-not-leak\n", encoding="utf-8")
        if _git_ok():
            _git(str(root), "add", "-f", "-A")
            _git(str(root), "commit", "-m", "base")
            previous = _git(str(root), "rev-parse", "HEAD").stdout.strip()
            (root / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
            (root / "huge.py").write_text(f"{sentinel} = 2\n" + ("y = 1\n" * 20_000), encoding="utf-8")
            _git(str(root), "add", "-f", "-A")
            _git(str(root), "commit", "-m", "next")
            current = _git(str(root), "rev-parse", "HEAD").stdout.strip()

        dump = collector.collect(str(root))
        check("FILE: src/app.py" in dump and "VALUE =" in dump, "included file contents still reach the dump")
        check("FILE: huge.py" not in dump, "oversized file contents are omitted from the dump")
        check(sentinel not in dump, "no oversized file content leaks into the dump")
        check("should-not-leak" not in dump, "excluded secret contents do not leak")
        check("huge.py — " in dump and "exceeds limit" in dump, "oversized file remains visible with a reason")
        check("REPOSITORY STRUCTURE" in dump and "huge.py" in dump, "oversized file remains in the repository tree")
        check("EXCLUDED FILES" in dump, "dump exposes an EXCLUDED FILES metadata list")

        analysis = analyzer.analyze({"dump": dump})
        unparsed = {row["path"]: row for row in analysis["unparsed"]}
        check("huge.py" in unparsed, "analyzer still sees the oversized file")
        check("exceeds limit" in unparsed["huge.py"]["reason"], "analyzer keeps the exclusion reason")
        check("content" not in unparsed["huge.py"], "analyzer excluded metadata has no file contents")
        check(sentinel not in json.dumps(analysis), "oversized file content does not reach analyzer JSON")
        check(any(row["path"] == "src/app.py" for row in analysis["files"]),
              "included Python is still analyzed")

        mapped = mapper.build({"analysis": analysis})
        modules = {row["path"]: row for row in mapped["modules"]}
        check("huge.py" in modules, "repository map still sees the oversized file")
        check(modules["huge.py"]["status"] == "excluded", "repository map marks the file excluded, not missing")
        check("exceeds limit" in modules["huge.py"]["reason"], "repository map keeps the exclusion reason")
        check(sentinel not in json.dumps(mapped), "oversized file content does not reach the repository map")

        if _git_ok():
            changed = changes.detect_changes(str(root), previous_commit=previous, new_commit=current)
            by_path = {row["path"]: row for row in changed["changed"]}
            check(by_path.get("src/app.py", {}).get("status") == "modified",
                  "/changes still reports eligible modified files")
            check(by_path.get("huge.py", {}).get("eligible") is False, "/changes still marks oversized files ineligible")
            check("exceeds limit" in str(by_path.get("huge.py", {}).get("reason") or ""),
                  "/changes still carries the per-file exclusion reason")
            check(len(by_path) == 2, "/changes still lists only changed files, not the whole repository")
            check(sentinel not in json.dumps(changed), "/changes still omits file contents")


def _build_origin_with_history(root: Path) -> dict[str, str]:
    _git(str(root), "init", "-b", "main")
    (root / "keep.py").write_text("print('v1')\n", encoding="utf-8")
    (root / "gone.txt").write_text("delete-me\n", encoding="utf-8")
    (root / "old_name.txt").write_text("rename-me\n", encoding="utf-8")
    (root / ".env").write_text("SECRET=hidden\n", encoding="utf-8")
    _git(str(root), "add", "-f", "-A")
    _git(str(root), "commit", "-m", "base")
    previous = _git(str(root), "rev-parse", "HEAD").stdout.strip()
    (root / "keep.py").write_text("print('v2')\n", encoding="utf-8")
    (root / "added.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(str(root), "rm", "gone.txt")
    _git(str(root), "mv", "old_name.txt", "new_name.txt")
    _git(str(root), "add", "-f", "-A")
    _git(str(root), "commit", "-m", "next")
    _git(str(root), "branch", "feature")
    current = _git(str(root), "rev-parse", "HEAD").stdout.strip()
    return {"previous": previous, "current": current}


def test_workspace_reuse_and_shallow() -> None:
    print("\nworkspace reuse and shallow previous SHA")
    if not _git_ok():
        print("  skip  git is not available on PATH")
        return

    import changes  # noqa: E402
    import server as collector_server  # noqa: E402
    import workspace  # noqa: E402

    workspace.reset()
    url_a = "https://example.test/owner/repo"
    url_b = "https://example.test/owner/other"

    with tempfile.TemporaryDirectory() as tmp:
        origin_a = Path(tmp) / "origin-a"
        origin_b = Path(tmp) / "origin-b"
        origin_a.mkdir()
        origin_b.mkdir()
        shas = _build_origin_with_history(origin_a)
        _build_origin_with_history(origin_b)
        (origin_b / "only-b.py").write_text("other = 1\n", encoding="utf-8")
        _git(str(origin_b), "add", "only-b.py")
        _git(str(origin_b), "commit", "-m", "other")

        clones: list[tuple[str, str]] = []
        origins = {url_a: origin_a, url_b: origin_b}

        def fake_is_remote(source: str) -> bool:
            return source.startswith("https://example.test/")

        def fake_clone(source: str, ref: str, dest: str) -> None:
            clones.append((source, ref or ""))
            src = origins[source]
            dest_path = Path(dest)
            if dest_path.exists() and not any(dest_path.iterdir()):
                dest_path.rmdir()
            extra = ["--branch", ref] if ref and not collector._SHA_RE.match(ref) else []
            _git(str(dest_path.parent), "clone", "--depth", "1", "--no-local", *extra, str(src), dest)

        original_is_remote = collector.is_remote
        original_clone = collector.clone_remote
        original_changes_remote = changes.is_remote
        collector.is_remote = fake_is_remote
        collector.clone_remote = fake_clone
        changes.is_remote = fake_is_remote
        try:
            result = changes.detect_changes(
                url_a,
                previous_commit=shas["previous"],
                new_commit=shas["current"],
            )
            by_path = {row["path"]: row for row in result["changed"]}
            check(result["previousCommit"] == shas["previous"], "missing previous SHA was fetched")
            check(by_path.get("added.py", {}).get("status") == "added", "fetched previous SHA still detects adds")
            check(by_path.get("keep.py", {}).get("status") == "modified", "fetched previous SHA still detects edits")
            check(by_path.get("gone.txt", {}).get("status") == "deleted", "fetched previous SHA still detects deletes")
            check(by_path.get("new_name.txt", {}).get("status") == "renamed",
                  "fetched previous SHA still detects renames")
            first_clones = len(clones)

            dump = collector.collect(url_a)
            check(len(clones) == first_clones, "/changes then /collect reuse one workspace")
            check("print('v2')" in dump and "FILE: added.py" in dump, "reused workspace still collects current files")
            check("SECRET=hidden" not in dump and "\nFILE: .env\n" not in dump,
                  "workspace reuse does not bypass sanitization")

            collector.collect(url_b)
            check(any(source == url_b for source, _ref in clones),
                  "a different repository does not reuse the other workspace")

            workspace.reset()
            clones.clear()
            collector.collect(url_a, ref="main")
            collector.collect(url_a, ref="feature")
            check(len(clones) == 1, "idle same-URL workspace is reused across refs")
            reused = next(iter(workspace._workspaces.values()))
            check(workspace._same_sha(workspace._head(reused.path), shas["current"]),
                  "reused idle workspace checks out the requested ref")

            workspace.reset()
            clones.clear()
            collector.collect(url_a, ref=shas["current"])
            collector.collect(url_a, ref=shas["previous"])
            check(len(clones) == 1, "idle same-URL workspace is reused across SHAs")
            moved = next(iter(workspace._workspaces.values()))
            check(workspace._same_sha(workspace._head(moved.path), shas["previous"]),
                  "reused idle workspace HEAD matches the requested SHA")

            workspace.reset()
            clones.clear()
            held = workspace.acquire(url_a, ref=shas["current"], commit=shas["current"])
            try:
                collector.collect(url_a, ref=shas["previous"])
                check(len(clones) == 2, "in-use workspace is not reused for a different SHA")
                check(workspace._same_sha(workspace._head(held.path), shas["current"]),
                      "in-use workspace HEAD is not moved for another request")
            finally:
                workspace.release(held)

            workspace.reset()
            clones.clear()
            errors: list[str] = []

            def collect_one(target: str) -> None:
                try:
                    collector.collect(target)
                except Exception as exc:  # noqa: BLE001
                    errors.append(str(exc))

            first = threading.Thread(target=collect_one, args=(url_a,))
            second = threading.Thread(target=collect_one, args=(url_b,))
            first.start()
            second.start()
            first.join()
            second.join()
            check(not errors, "concurrent collections do not fail")
            check({source for source, _ref in clones} == {url_a, url_b},
                  "concurrent requests for different repositories stay isolated")

            workspace.reset()
            clones.clear()
            collector.collect(url_a)
            item = next(iter(workspace._workspaces.values()))
            git_dir = Path(item.path) / ".git"
            if git_dir.is_dir():
                for child in git_dir.rglob("*"):
                    if child.is_file():
                        child.chmod(0o666)
                import shutil

                shutil.rmtree(git_dir)
            clones_before = len(clones)
            collector.collect(url_a)
            check(len(clones) > clones_before, "a stale or invalid workspace is not reused")

            workspace.reset()
            clones.clear()
            shallow = Path(tmp) / "shallow-local"
            _git(str(tmp), "clone", "--depth", "1", "--no-local", str(origin_a), str(shallow))
            has_prev = workspace.has_commit(str(shallow), shas["previous"])
            check(not has_prev, "depth-1 clone does not contain the previous SHA")
            already = changes.detect_changes(
                str(shallow),
                previous_commit=shas["previous"],
                new_commit=shas["current"],
            )
            check(already["previousCommit"] == shas["previous"],
                  "previous SHA missing from a shallow local clone is fetched from origin")
            check(any(row["path"] == "added.py" for row in already["changed"]),
                  "diff after fetching the previous SHA is correct")

            _git(str(shallow), "fetch", "--depth", "1", "origin", shas["previous"])
            present = changes.detect_changes(
                str(shallow),
                previous_commit=shas["previous"],
                new_commit=shas["current"],
            )
            check(present["changed"] == already["changed"],
                  "previous SHA already in the shallow clone still diffs correctly")

            orphan = Path(tmp) / "orphan-shallow"
            _git(str(tmp), "clone", "--depth", "1", "--no-local", str(origin_a), str(orphan))
            _git(str(orphan), "remote", "remove", "origin")
            try:
                changes.detect_changes(
                    str(orphan),
                    previous_commit=shas["previous"],
                    new_commit=shas["current"],
                )
                check(False, "unavailable previous SHA fails explicitly")
            except collector.CollectorError as exc:
                check(exc.status == 404 and "not found" in str(exc).lower(),
                      "unavailable previous SHA is a 404")

            workspace.reset()
            clones.clear()
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), collector_server.Handler)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                port = httpd.server_address[1]
                change_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/changes",
                    data=json.dumps({
                        "repository": url_a,
                        "previousCommit": shas["previous"],
                        "newCommit": shas["current"],
                    }).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(change_req, timeout=30) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                collect_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/collect",
                    data=json.dumps({"repository": url_a, "ref": shas["current"]}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(collect_req, timeout=30) as response:
                    body = response.read().decode("utf-8")
                check(payload["changed"] and "print('v2')" in body,
                      "HTTP /changes then /collect reuse the same workspace")
                check(payload["newCommit"] == shas["current"] and f"COMMIT: {shas['current']}" in body,
                      "HTTP /changes and /collect use the same explicit newCommit")
                check(len(clones) == 1, "HTTP same-pipeline calls clone the remote once")
                collect_again = urllib.request.Request(
                    f"http://127.0.0.1:{port}/collect",
                    data=json.dumps({"repository": url_a, "ref": shas["current"]}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(collect_again, timeout=30) as response:
                    again = response.read().decode("utf-8")
                check(f"COMMIT: {shas['current']}" in again,
                      "a later Agent /collect still sees the pinned newCommit")
                check(len(clones) == 1, "host scope then Agent /collect reuse one clone")
            finally:
                httpd.shutdown()
                httpd.server_close()
        finally:
            collector.is_remote = original_is_remote
            collector.clone_remote = original_clone
            changes.is_remote = original_changes_remote
            workspace.reset()


def test_documentation_registry() -> None:
    print("\ndocumentation registry")
    _validation, ark_client, registry = _host_modules()

    sha1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    sha2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    url = "https://github.com/owner/repo"
    other = "https://github.com/owner/other"

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "documentation-registry.json"
        html = Path(tmp) / "repo.html"
        html.write_text(
            "<!DOCTYPE html><html><body>COMMIT: ffffffffffffffffffffffffffffffffffffffff</body></html>",
            encoding="utf-8",
        )

        check(registry.lookup(url, path) is None, "first run has no previous documented SHA")
        first = ark_client.plan_documentation(
            url,
            current_sha=sha1,
            registry_path=path,
        )
        check(first["status"] == "first_run", "no previous SHA is a first documentation run")
        check(first["mode"] == "full" and first["previousCommit"] == "", "first run has an empty previousCommit")
        check(first["runPipeline"] is True, "first run still documents the repository")
        check(first["documentationVersion"] == 0, "first run has no documentation version yet")
        check(registry.lookup(url, path) is None, "planning a first run does not persist a SHA")

        failed = ark_client.execute_documentation_plan(
            first,
            run_pipeline=lambda _plan: {"ok": False, "error": "renderer failed"},
            registry_path=path,
        )
        check(failed["status"] == "failed", "failed documentation is reported as failed")
        check(registry.lookup(url, path) is None, "failed documentation does not persist a SHA")
        check(ark_client.documented_commit(url, registry_path=path) == "",
              "failed first run leaves no documented commit")

        ran = {"count": 0}

        def succeed(_plan: dict) -> dict:
            ran["count"] += 1
            return {"ok": True, "artifact": "repo.html"}

        documented = ark_client.execute_documentation_plan(
            first,
            run_pipeline=succeed,
            registry_path=path,
        )
        check(documented["status"] == "documented", "successful documentation is reported as documented")
        check(documented["currentCommit"] == sha1, "successful documentation persists the current SHA")
        check(documented["documentationVersion"] == 1, "first successful run creates documentation version 1")
        stored = registry.lookup(url, path)
        check(stored is not None and stored["commitSha"] == sha1, "registry stores the documented SHA")
        check(stored["status"] == "documented", "registry marks the repository as documented")
        check(stored["identity"] == "github.com/owner/repo", "registry stores a stable repository identity")
        check(registry.repository_identity("https://www.github.com/owner/repo") == "github.com/owner/repo",
              "www.github.com uses the same repository identity")
        check(registry.lookup("https://www.github.com/owner/repo.git", path)["commitSha"] == sha1,
              "www.github.com looks up the already documented repository")
        www_plan = ark_client.plan_documentation(
            "https://www.github.com/owner/repo",
            current_sha=sha1,
            registry_path=path,
        )
        check(www_plan["status"] == "already_documented",
              "same repository via www.github.com is not treated as new")
        check(path.is_file() and html.read_text(encoding="utf-8").startswith("<!DOCTYPE html>"),
              "registry is a JSON file, not the generated HTML")
        check("ffffffffffffffffffffffffffffffffffffffff" not in path.read_text(encoding="utf-8"),
              "HTML commit text is not used as the documented SHA")

        later = ark_client.plan_documentation(
            "https://github.com/owner/repo.git",
            current_sha=sha2,
            registry_path=path,
        )
        check(later["status"] == "needs_documentation", "a new commit needs documentation")
        check(later["previousCommit"] == sha1, "later run reads the previously stored SHA")
        check(later["mode"] == "incremental", "stored SHA is the baseline for later incremental detection")
        check(later["documentationVersion"] == 1, "unreadied new commit does not bump the version")
        check(ark_client.documented_commit(url, registry_path=path) == sha1,
              "documented_commit exposes the stored SHA for /changes")

        failed_update = ark_client.execute_documentation_plan(
            later,
            run_pipeline=lambda _plan: {"ok": False, "error": "query error"},
            registry_path=path,
        )
        check(failed_update["status"] == "failed", "failed later run is reported as failed")
        check(ark_client.documented_commit(url, registry_path=path) == sha1,
              "failed documentation does not advance the stored SHA")
        check(registry.lookup(url, path)["documentationVersion"] == 1,
              "failed documentation does not create a new documentation version")

        updated = ark_client.execute_documentation_plan(
            later,
            run_pipeline=succeed,
            registry_path=path,
        )
        check(updated["currentCommit"] == sha2, "successful new commit persists the new SHA")
        check(updated["documentationVersion"] == 2, "a genuinely new commit increments the documentation version")

        same = ark_client.plan_documentation(
            url,
            current_sha=sha2,
            registry_path=path,
        )
        check(same["status"] == "already_documented", "same repository + same SHA is already_documented")
        check(same["runPipeline"] is False, "already_documented skips documentation regeneration")
        check(same["documentationVersion"] == 2, "already_documented keeps the existing documentation version")
        check(same["currentCommit"] == sha2 and same["previousCommit"] == sha2,
              "already_documented does not advance the stored SHA")

        skipped = ark_client.execute_documentation_plan(
            same,
            run_pipeline=succeed,
            registry_path=path,
        )
        check(skipped["status"] == "already_documented", "execute returns already_documented without running")
        check(ran["count"] == 2, "same SHA does not invoke documentation generation")
        check(registry.lookup(url, path)["documentationVersion"] == 2,
              "same SHA does not create a new documentation version")
        check(registry.lookup(url, path)["commitSha"] == sha2,
              "same SHA leaves the stored SHA unchanged")

        other_plan = ark_client.plan_documentation(other, current_sha=sha1, registry_path=path)
        check(other_plan["status"] == "first_run", "a different repository has its own documented SHA")

        missing_sha = {
            "status": "first_run",
            "mode": "full",
            "repository": other,
            "identity": "github.com/owner/other",
            "currentCommit": "",
            "previousCommit": "",
            "documentationVersion": 0,
            "artifact": "",
            "runPipeline": True,
        }
        original_resolve = ark_client.resolve_commit_sha
        ark_client.resolve_commit_sha = lambda _repository, _ref="": sha1
        try:
            recovered = ark_client.execute_documentation_plan(
                missing_sha,
                run_pipeline=succeed,
                registry_path=path,
            )
        finally:
            ark_client.resolve_commit_sha = original_resolve
        check(recovered.get("persisted") is True and recovered["currentCommit"] == sha1,
              "successful generation persists a SHA resolved after the Query")
        check(registry.lookup(other, path)["commitSha"] == sha1,
              "resolved SHA is stored so a later submit is not treated as new")

        check("session_state" not in Path(registry.__file__).read_text(encoding="utf-8"),
              "registry module does not depend on Streamlit session state")

        prefix_plan = ark_client.plan_documentation(
            url,
            current_sha=sha2[:7],
            registry_path=path,
        )
        check(
            prefix_plan["status"] != "already_documented",
            "a SHA prefix of the documented commit is not already_documented",
        )
        other_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc"
        different = ark_client.plan_documentation(url, current_sha=other_sha, registry_path=path)
        check(different["status"] == "needs_documentation",
              "a different full SHA is not treated as the documented commit")


def test_commit_pinning_and_eligibility() -> None:
    print("\ncommit pinning, SHA equality, and eligibility flips")
    _validation, ark_client, registry = _host_modules()

    previous_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    new_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    query = ark_client.build_input(
        "https://github.com/a/b",
        "main",
        previous_commit=previous_sha,
        new_commit=new_sha,
    )
    check(
        query == (
            "Document this repository: https://github.com/a/b ref: main "
            f"previousCommit: {previous_sha} newCommit: {new_sha}"
        ),
        "registry previousCommit and newCommit reach the Query",
    )
    check(
        ark_client.build_input("https://github.com/a/b")
        == "Document this repository: https://github.com/a/b",
        "first/full Query keeps the V1.3.0 sentence without SHA fields",
    )
    with tempfile.TemporaryDirectory() as plan_tmp:
        empty_registry = Path(plan_tmp) / "empty-registry.json"
        first_plan = ark_client.plan_documentation(
            "https://github.com/owner/repo",
            current_sha=new_sha,
            registry_path=empty_registry,
        )
        first_query = ark_client.build_input(
            first_plan["repository"],
            previous_commit=first_plan["previousCommit"],
            new_commit=first_plan["currentCommit"],
        )
        check(first_plan["status"] == "first_run" and first_plan["previousCommit"] == "",
              "first run still has no previousCommit")
        check("previousCommit:" not in first_query, "first run Query omits previousCommit")
        check(f"newCommit: {new_sha}" in first_query, "first run Query still pins newCommit when resolved")

    peeled = ark_client.parse_ls_remote(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/tags/v1.0.0\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/tags/v1.0.0^{}\n"
    )
    check(peeled == new_sha, "annotated tag resolution uses the peeled commit SHA")
    lightweight = ark_client.parse_ls_remote(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/heads/main\n"
    )
    check(lightweight == previous_sha, "non-tag ls-remote uses the commit SHA")
    first_doc = {"repositoryOverview": {"summary": "first", "quickStart": "a"}, "repositoryStructure": "s"}
    second_doc = {"repositoryOverview": {"summary": "second", "quickStart": "b"}, "repositoryStructure": "t"}
    doubled = json.dumps(first_doc, separators=(",", ":")) + "\n" + json.dumps(second_doc, separators=(",", ":"))
    parsed = ark_client.parse_documentation(doubled)
    check(parsed == second_doc, "concatenated Query JSON uses the last complete object")
    check(ark_client.parse_documentation(json.dumps(first_doc)) == first_doc,
          "single Query JSON object still parses")
    wrapped = json.dumps({"documentation": first_doc}, separators=(",", ":"))
    check(ark_client.parse_documentation(wrapped) == first_doc,
          "nested documentation objects still unwrap")

    check(registry.same_commit(new_sha, new_sha), "identical full SHAs compare equal")
    check(not registry.same_commit(new_sha, new_sha[:7]), "a 7-character SHA prefix is not full equality")
    check(not registry.same_commit(previous_sha, new_sha), "different commits are not equal")
    check(
        not registry.same_commit(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
            previous_sha,
        ),
        "near-matching full SHAs are not equal",
    )

    ui_src = (ROOT / "app" / "ui.py").read_text(encoding="utf-8")
    ark_src = Path(ark_client.__file__).read_text(encoding="utf-8")
    check("run_ark_pipeline" in ui_src, "Streamlit forwards registry SHAs through the existing Query runner")
    check("previous_commit=" in ark_src and "new_commit=" in ark_src,
          "Query input still carries previousCommit and newCommit")

    if not _git_ok():
        print("  skip  git-backed pinning tests (git is not available)")
        return

    import changes  # noqa: E402
    import workspace  # noqa: E402

    workspace.reset()
    url = "https://example.test/owner/pinned"

    with tempfile.TemporaryDirectory() as tmp:
        origin = Path(tmp) / "origin"
        origin.mkdir()
        _git(str(origin), "init", "-b", "main")
        (origin / "keep.py").write_text("print('v1')\n", encoding="utf-8")
        (origin / "grow.py").write_text("OLD_ELIGIBLE_BODY = 1\n" + ("x" * 70_000), encoding="utf-8")
        (origin / "shrink.py").write_text("OLD_EXCLUDED_BODY = 1\n" + ("y" * 90_000), encoding="utf-8")
        (origin / "aaa.py").write_text("a=1\n", encoding="utf-8")
        (origin / "zzz_budget.py").write_text("PREVIOUS_BUDGET_BODY = 1\n", encoding="utf-8")
        (origin / "gone.txt").write_text("delete-me\n", encoding="utf-8")
        (origin / "old_name.txt").write_text("rename-me\n", encoding="utf-8")
        _git(str(origin), "add", "-A")
        _git(str(origin), "commit", "-m", "base")
        previous = _git(str(origin), "rev-parse", "HEAD").stdout.strip()

        (origin / "keep.py").write_text("print('v2')\n", encoding="utf-8")
        (origin / "added.py").write_text("VALUE = 1\n", encoding="utf-8")
        (origin / "grow.py").write_text("NEW_OVERSIZE_BODY = 1\n" + ("z" * 90_000), encoding="utf-8")
        (origin / "shrink.py").write_text("NEW_ELIGIBLE_BODY = 1\n", encoding="utf-8")
        (origin / "zzz_budget.py").write_text("CURRENT_BUDGET_BODY = 1\n", encoding="utf-8")
        _git(str(origin), "rm", "gone.txt")
        _git(str(origin), "mv", "old_name.txt", "new_name.txt")
        _git(str(origin), "add", "-A")
        _git(str(origin), "commit", "-m", "next")
        current = _git(str(origin), "rev-parse", "HEAD").stdout.strip()

        old_entries = collector.collect_into(str(origin), ref=previous).entries
        new_entries = collector.collect_into(str(origin), ref=current).entries
        old_bodies = {entry.path: entry.text for entry in old_entries if entry.included}
        new_state = collector.current_commit_bodies(new_entries)
        new_by_path = {entry.path: entry for entry in new_entries}

        check(old_bodies.get("grow.py", "").startswith("OLD_ELIGIBLE_BODY"),
              "70 KB file is collectable in the previous commit")
        check(not new_by_path["grow.py"].included and new_state["grow.py"] == "",
              "90 KB file is excluded in the current commit")
        check("OLD_ELIGIBLE_BODY" not in new_state["grow.py"],
              "growing past 80 KB does not retain the old body as current content")
        current_dump = collector.collect(str(origin), ref=current)
        check("NEW_OVERSIZE_BODY" not in current_dump and "OLD_ELIGIBLE_BODY" not in current_dump,
              "excluded oversize contents are not sent to the dump/LLM")
        check("EXCLUDED FILES" in current_dump and "grow.py — " in current_dump,
              "current dump lists the newly ineligible file as excluded metadata")
        check("OLD_EXCLUDED_BODY" not in old_bodies.get("shrink.py", ""),
              "90 KB file has no previous body")
        check(new_state.get("shrink.py", "").startswith("NEW_ELIGIBLE_BODY"),
              "shrinking under 80 KB uses the current collectable body")
        check("OLD_EXCLUDED_BODY" not in new_state.get("shrink.py", ""),
              "newly collectable file does not keep an old excluded sentinel")

        tiny = collector.collect_into(str(origin), ref=current, max_total_bytes=10)
        tiny_state = collector.current_commit_bodies(tiny.entries)
        omitted = [entry for entry in tiny.entries if "budget" in entry.reason]
        check(bool(omitted), "total-budget omission is excluded metadata, not a silent keep")
        check(all(tiny_state[entry.path] == "" for entry in omitted),
              "budget-omitted files have no current body")
        check(all(old_bodies.get(entry.path, "") != tiny_state[entry.path] or not old_bodies.get(entry.path)
                  for entry in omitted if entry.path in old_bodies),
              "budget exclusion does not leave stale previous content")
        tiny_dump = collector.render(tiny)
        check("PREVIOUS_BUDGET_BODY" not in tiny_dump, "previous budgeted body is not current dump content")
        check("zzz_budget.py — " in tiny_dump and "EXCLUDED FILES" in tiny_dump,
              "budget-omitted file is listed as excluded metadata")

        changed = changes.detect_changes(str(origin), previous_commit=previous, new_commit=current)
        by_path = {row["path"]: row for row in changed["changed"]}
        check(changed["newCommit"] == current, "/changes reports the pinned newCommit")
        check(by_path.get("added.py", {}).get("status") == "added", "add remains reported")
        check(by_path.get("keep.py", {}).get("status") == "modified", "modify remains reported")
        check(by_path.get("gone.txt", {}).get("status") == "deleted", "delete remains reported")
        check(by_path.get("new_name.txt", {}).get("status") == "renamed", "rename remains reported")
        check(by_path.get("grow.py", {}).get("eligible") is False, "/changes marks the 80 KB grow as ineligible")
        check(by_path.get("shrink.py", {}).get("eligible") is True, "/changes marks the 80 KB shrink as eligible")
        check("max_total_bytes" not in Path(changes.__file__).read_text(encoding="utf-8"),
              "/changes is still not a collection-budget filter")
        check("NEW_OVERSIZE_BODY" not in json.dumps(changed),
              "/changes does not send excluded file contents")

        clones: list[tuple[str, str]] = []

        def fake_is_remote(source: str) -> bool:
            return source.startswith("https://example.test/")

        def fake_clone(source: str, ref: str, dest: str) -> None:
            clones.append((source, ref or ""))
            dest_path = Path(dest)
            if dest_path.exists() and not any(dest_path.iterdir()):
                dest_path.rmdir()
            extra = ["--branch", ref] if ref and not collector._SHA_RE.match(ref) else []
            _git(str(dest_path.parent), "clone", "--depth", "1", "--no-local", *extra, str(origin), dest)

        original_is_remote = collector.is_remote
        original_clone = collector.clone_remote
        original_changes_remote = changes.is_remote
        collector.is_remote = fake_is_remote
        collector.clone_remote = fake_clone
        changes.is_remote = fake_is_remote
        try:
            detected = changes.detect_changes(
                url,
                previous_commit=previous,
                new_commit=current,
            )
            collection = collector.collect_into(url, ref=current)
            dump = collector.render(collection)
            check(detected["newCommit"] == current, "/changes uses the explicit newCommit")
            check(collection.commit == current, "/collect persists the checked-out SHA")
            check(f"COMMIT: {current}" in dump, "collection dump is pinned to the requested SHA")
            check(detected["newCommit"] == collection.commit,
                  "/changes and /collect use the same exact newCommit")
            check("print('v2')" in dump and "FILE: added.py" in dump,
                  "collection at the pinned SHA includes that commit's tree")
            check("print('v1')" not in dump, "collection at newCommit does not use the previous tree")

            item = next(iter(workspace._workspaces.values()))
            _git(item.path, "checkout", "--force", "--detach", previous)
            check(workspace._head(item.path) == previous, "workspace HEAD can be moved off newCommit")
            clones_before = len(clones)
            recovered = collector.collect_into(url, ref=current)
            check(recovered.commit == current, "wrong-HEAD workspace is not reused as-is")
            check(f"COMMIT: {current}" in collector.render(recovered),
                  "collect after a wrong HEAD still pins the requested SHA")
            check("print('v2')" in collector.render(recovered),
                  "recovered collection uses the requested commit tree")
            check(len(clones) >= clones_before,
                  "a workspace whose HEAD does not match newCommit is discarded or realigned")
        finally:
            collector.is_remote = original_is_remote
            collector.clone_remote = original_clone
            changes.is_remote = original_changes_remote
            workspace.reset()


def test_git_errors() -> None:
    print("\ngit error classification")
    url = "https://gitlab.example.com/group/project"

    auth = collector.classify_git_error("fatal: Authentication failed for 'https://gitlab.example.com/g/p'", url, "")
    check(auth.status == 401 and str(auth) == "Git authentication failed", "auth failure is classified")

    prompts = collector.classify_git_error("fatal: could not read Username for 'https://gitlab.example.com': terminal prompts disabled", url, "")
    check(prompts.status == 401 and "Git authentication failed" in str(prompts), "missing credentials is auth failure")

    missing = collector.classify_git_error("ERROR: The project you were looking for could not be found.", url, "")
    check(missing.status == 404 and str(missing).startswith("Repository not found or inaccessible"), "missing repo is classified")

    missing_ref = collector.classify_git_error("fatal: couldn't find remote ref no-such-ref", url, "no-such-ref")
    check(missing_ref.status == 404 and str(missing_ref).startswith("Requested ref not found"), "missing ref is classified")

    original_run = collector.subprocess.run

    def boom(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["git", "clone"], timeout=1)

    collector.subprocess.run = boom
    try:
        collector.clone_remote("https://gitlab.example.com/group/project", "", os.path.join(tempfile.gettempdir(), "x"))
        check(False, "clone timeout raises CollectorError")
    except collector.CollectorError as exc:
        check(exc.status == 504 and str(exc) == "Repository clone timed out", "clone timeout is classified")
    finally:
        collector.subprocess.run = original_run


def test_gitlab_auth_abstraction() -> None:
    print("\ngitlab authentication")
    token = "glpat-test-token-value-not-real"
    previous = os.environ.get("GITLAB_TOKEN")
    os.environ["GITLAB_TOKEN"] = token
    try:
        gitlab_url = "https://gitlab.example.com/group/project.git"
        clone_url = collector.strip_userinfo(gitlab_url)
        check(token not in clone_url, "token is not included in the constructed repository URL")
        check(clone_url == gitlab_url, "public GitLab URL is unchanged")

        env = collector.build_git_env(gitlab_url)
        check("GITLAB_TOKEN" not in env, "GITLAB_TOKEN is not forwarded to the git process")
        check(env.get("GIT_CONFIG_COUNT") == "1", "host-scoped http extraHeader is configured")
        check(
            env.get("GIT_CONFIG_KEY_0") == "http.https://gitlab.example.com/.extraHeader",
            "extraHeader is scoped to the GitLab host",
        )
        header = env.get("GIT_CONFIG_VALUE_0", "")
        check(header.startswith("Authorization: Basic "), "git uses an HTTP Authorization header")
        check(token not in header, "raw token is not in the extraHeader value")
        payload = header.split()[-1]
        decoded = __import__("base64").b64decode(payload).decode("ascii")
        check(decoded == f"oauth2:{token}", "Basic auth uses oauth2 plus the token")

        github_env = collector.build_git_env("https://github.com/acme/repo")
        check("GIT_CONFIG_VALUE_0" not in github_env, "GitHub clones do not receive the GitLab token")

        leaked = collector.redact(f"Authorization: Basic {payload} token={token} url=https://oauth2:{token}@host/x")
        check(token not in leaked, "token is not included in redacted logs")
        check("Authorization: ***" in leaked, "Authorization headers are redacted")
        check("https://***@" in leaked, "credential-bearing URLs are redacted")

        captured: list[list[str]] = []
        original_run = collector.subprocess.run

        def fake_run(cmd, cwd=None, env=None, timeout=None, stdout=None, stderr=None, text=None):
            captured.append(list(cmd))
            check(env is None or token not in (env or {}), "token is not in the git child environment")
            check(all(token not in str(part) for part in cmd), "token is not passed as a command-line argument")
            stdout_text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" if "rev-parse" in cmd else ""
            return subprocess.CompletedProcess(cmd, 0, stdout=stdout_text, stderr="")

        collector.subprocess.run = fake_run
        try:
            with tempfile.TemporaryDirectory() as tmp:
                collector.clone_remote(gitlab_url, "main", os.path.join(tmp, "repo"))
        finally:
            collector.subprocess.run = original_run

        joined = " ".join(" ".join(cmd) for cmd in captured)
        check(token not in joined, "token never appears in any git argv")
        check("https://gitlab.example.com/group/project.git" in joined, "clone uses the URL without credentials")
    finally:
        if previous is None:
            os.environ.pop("GITLAB_TOKEN", None)
        else:
            os.environ["GITLAB_TOKEN"] = previous


def test_live_clone() -> None:
    print(f"\nlive clone of {TARGET_REPO}")
    dump = collector.collect(TARGET_REPO)
    check("REPOSITORY: github-mcp-chatbot" in dump, "target repository collected")
    check("FILE: backend/main.py" in dump, "known source file present with its relative path")
    check("COMMIT: " in dump, "commit recorded")
    print(f"  info  dump is {len(dump)} characters over "
          f"{dump.count('FILE: ')} files")

    named = collector.collect(TARGET_REPO, ref="main")
    check("REQUESTED_REF: main" in named, "explicit default-branch ref is recorded")
    check("FILE: backend/main.py" in named, "explicit branch still contains known source")

    try:
        collector.collect(TARGET_REPO, ref="this-ref-does-not-exist-xyz")
        check(False, "nonexistent remote ref raises CollectorError")
    except collector.CollectorError as exc:
        check("Requested ref not found" in str(exc), "nonexistent remote ref does not fall back")


def test_optional_gitlab_e2e() -> None:
    repo = os.environ.get("GITLAB_E2E_REPOSITORY", "").strip()
    if not repo:
        print("\nskipping private GitLab E2E (set GITLAB_E2E_REPOSITORY to enable)")
        return
    ref = os.environ.get("GITLAB_E2E_REF", "").strip()
    host, name = collector.source_identity(repo)
    print(f"\noptional GitLab E2E host={host} repo={name} requested_ref={ref or '<default>'}")
    dump = collector.collect(repo, ref=ref)
    check(f"REPOSITORY: {name}" in dump, "GitLab repository collected")
    check("COMMIT: " in dump, "GitLab commit recorded")
    if ref:
        check(f"REQUESTED_REF: {ref}" in dump, "requested GitLab ref is recorded")
        check(f"REF: {ref}" in dump, "resolved GitLab ref matches the request")


def _kubectl(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def collector_collect_count(since_time: str) -> int | None:
    """Count successful POST /collect access lines since since_time (RFC3339).

    Uses kubectl --since-time so the count is scoped to this Query, not a
    sliding --tail window that can drop older matching lines.
    """
    result = _kubectl(
        [
            "kubectl",
            "logs",
            "-n",
            NAMESPACE,
            "-l",
            COLLECTOR_LABEL,
            "--since-time",
            since_time,
        ]
    )
    if result.returncode != 0 or result.stdout is None:
        print(f"        could not read collector logs: {(result.stderr or '').strip()}")
        return None
    return len(re.findall(r'POST /collect HTTP/\d\.\d" 200', result.stdout))


def wait_for_query(name: str, timeout_s: int) -> dict | None:
    deadline = time.time() + timeout_s
    last_phase = None
    while time.time() < deadline:
        result = _kubectl(["kubectl", "get", "query", name, "-n", NAMESPACE, "-o", "json"])
        if result.returncode != 0 or not result.stdout:
            time.sleep(2)
            continue
        obj = json.loads(result.stdout)
        phase = (obj.get("status") or {}).get("phase")
        if phase != last_phase:
            print(f"        query {name} phase={phase}")
            last_phase = phase
        if phase == "done":
            return obj
        if phase in ("error", "canceled"):
            print(f"        query failed: {json.dumps(obj.get('status'), default=str)[:800]}")
            return obj
        time.sleep(3)
    print(f"        timed out waiting for query {name}")
    return None


def apply_query(body: dict) -> bool:
    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    try:
        json.dump(body, handle, ensure_ascii=False)
        handle.close()
        result = _kubectl(["kubectl", "apply", "-f", handle.name])
        if result.returncode != 0:
            print(f"        kubectl apply failed: {(result.stderr or result.stdout or '').strip()}")
            return False
        return True
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass


def _analyzer_modules():
    import importlib
    import importlib.util

    analyzer_dir = ROOT / "tools" / "repository-analyzer"
    analyzer_path = str(analyzer_dir)
    if analyzer_path not in sys.path:
        sys.path.insert(0, analyzer_path)
    analyzer = importlib.import_module("analyzer")
    server_name = "repository_analyzer_server"
    if server_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(server_name, analyzer_dir / "server.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[server_name] = module
        assert spec.loader is not None
        spec.loader.exec_module(module)
    return analyzer, sys.modules[server_name]


def _find(items: list[dict], name: str) -> dict | None:
    return next((item for item in items if item.get("name") == name), None)


def _refs(references: list[dict], kind: str, to: str | None = None, frm: str | None = None) -> list[dict]:
    found = []
    for ref in references:
        if ref.get("kind") != kind:
            continue
        if to is not None and ref.get("to") != to:
            continue
        if frm is not None and ref.get("from") != frm:
            continue
        found.append(ref)
    return found


ANALYZER_FIXTURE = """\
import os
from collections import deque

def helper(item):
    return item

class Base:
    pass

@dataclass
class Worker(Base):
    @override
    def run(self, item, extra, *args, flag, **kwargs):
        helper(item)
        self.save()
        unknown()
        os.path.join(item, extra)
        other.module.fn()

    def save(self):
        helper(self)

async def fetch(url):
    helper(url)
"""


def test_analyzer() -> None:
    print("\nAST analyzer")
    analyzer, analyzer_server = _analyzer_modules()

    src_dir = ROOT / "tools" / "repository-analyzer"
    for rel in ("analyzer.py", "server.py", "languages/python.py", "languages/__init__.py"):
        text = (src_dir / rel).read_text(encoding="utf-8")
        check("import subprocess" not in text and "git clone" not in text, f"{rel} does not shell out or clone")
        check("collect_into" not in text and "import collector" not in text, f"{rel} does not read collector entries")

    first = analyzer.analyze({"files": [{"path": "src/app.py", "content": ANALYZER_FIXTURE}]})
    second = analyzer.analyze({"files": [{"path": "src/app.py", "content": ANALYZER_FIXTURE}]})
    check(first == second, "analyzer output is deterministic")
    check(first["schemaVersion"] == "1", "schemaVersion is 1")
    check(first["language"] == "python", "supported language is python")
    check(len(first["files"]) == 1 and first["files"][0]["status"] == "parsed", "valid Python is parsed")
    check(first["unparsed"] == [], "valid Python is not unparsed")

    parsed = first["files"][0]
    check(parsed["path"] == "src/app.py", "parsed path is preserved")
    worker = _find(parsed["classes"], "Worker")
    base = _find(parsed["classes"], "Base")
    check(base is not None and base["qualname"] == "src/app.py::Base", "classes include Base")
    check(worker is not None and worker["bases"] == ["Base"], "inheritance surface names are recorded")
    check(worker["decorators"] == ["dataclass"], "class decorator names only")
    check(worker["qualname"] == "src/app.py::Worker", "class qualname uses path::Name")

    helper = _find(parsed["functions"], "helper")
    run = _find(parsed["functions"], "run")
    save = _find(parsed["functions"], "save")
    fetch = _find(parsed["functions"], "fetch")
    check(helper is not None and helper["kind"] == "function", "top-level functions are recorded")
    check(run is not None and run["kind"] == "method" and run["qualname"] == "src/app.py::Worker.run",
          "methods are recorded with class qualname")
    check(save is not None and save["kind"] == "method", "second method is recorded")
    check(fetch is not None and fetch["async"] is True and fetch["kind"] == "function",
          "async functions are recorded")
    check(run["parameters"] == ["self", "item", "extra", "args", "flag", "kwargs"],
          "parameter names only are recorded")
    check(run["decorators"] == ["override"], "method decorator names only")
    check("default" not in json.dumps(run), "parameter defaults are not emitted")

    import_kinds = {row["kind"] for row in parsed["imports"]}
    check("import" in import_kinds and "from" in import_kinds, "import and from-import facts are recorded")
    check(any(row["module"] == "os" for row in parsed["imports"]), "import module name is recorded")
    check(any(row["module"] == "collections" and "deque" in row["names"] for row in parsed["imports"]),
          "from-import names are recorded")

    refs = first["references"]
    inherit = _refs(refs, "inherit", to="src/app.py::Base", frm="src/app.py::Worker")
    check(len(inherit) == 1 and inherit[0]["certainty"] == "exact", "same-file inheritance is exact")
    decorate_worker = _refs(refs, "decorate", to="dataclass", frm="src/app.py::Worker")
    check(len(decorate_worker) == 1 and decorate_worker[0]["certainty"] == "unresolved",
          "unknown decorator stays unresolved")
    helper_call = _refs(refs, "call", to="src/app.py::helper", frm="src/app.py::Worker.run")
    check(len(helper_call) == 1 and helper_call[0]["certainty"] == "exact",
          "same-file direct call is exact")
    save_call = _refs(refs, "call", to="src/app.py::Worker.save", frm="src/app.py::Worker.run")
    check(len(save_call) == 1 and save_call[0]["certainty"] == "exact",
          "same-class self.method call is exact")
    unknown_call = _refs(refs, "call", to="unknown", frm="src/app.py::Worker.run")
    check(len(unknown_call) == 1 and unknown_call[0]["certainty"] == "unresolved",
          "unknown call stays unresolved")
    join_call = _refs(refs, "call", to="os.path.join")
    check(len(join_call) == 1 and join_call[0]["certainty"] == "unresolved",
          "imported dotted call is unresolved")
    foreign_call = _refs(refs, "call", to="other.module.fn")
    check(len(foreign_call) == 1 and foreign_call[0]["certainty"] == "unresolved",
          "cross-module call is unresolved")
    import_refs = _refs(refs, "import")
    check(import_refs and all(row["certainty"] == "unresolved" for row in import_refs),
          "import references stay unresolved")
    check(all("lineno" in row and row["kind"] in {"import", "inherit", "decorate", "call"} for row in refs),
          "references have kind, from, to, lineno, certainty")

    broken = analyzer.analyze({"files": [{"path": "broken.py", "content": "def broken(\n"}]})
    check(broken["files"] == [], "invalid Python is not parsed")
    check(broken["unparsed"] == [{"path": "broken.py", "reason": "SyntaxError"}],
          "invalid Python is unparsed with a reason")
    check(broken["references"] == [], "invalid Python produces no guessed references")

    mixed = analyzer.analyze(
        {
            "files": [
                {"path": "src/app.py", "content": "def local():\n    other()\n"},
                {"path": "src/other.py", "content": "def other():\n    return 1\n"},
                {"path": "config.json", "content": '{"token": "json-secret-value"}'},
                {"path": "values.yaml", "content": "password: yaml-secret-value\n"},
                {"path": "app.js", "content": "function other() { return 1; }\n"},
            ]
        }
    )
    check({row["path"] for row in mixed["files"]} == {"src/app.py", "src/other.py"},
          "only Python files are parsed")
    unsupported = {row["path"]: row["reason"] for row in mixed["unparsed"]}
    check(unsupported.get("config.json") == "unsupported", "JSON is unsupported")
    check(unsupported.get("values.yaml") == "unsupported", "YAML is unsupported")
    check(unsupported.get("app.js") == "unsupported", "non-Python languages are unsupported")
    cross = _refs(mixed["references"], "call", to="other", frm="src/app.py::local")
    check(len(cross) == 1 and cross[0]["certainty"] == "unresolved",
          "same-name other file is not guessed as exact")

    secrets = {
        "literal": "super-secret-password-xyz",
        "default": "sk-live-secret-value",
        "decorator": "decorator-secret-xyz",
        "argument": "argument-secret-xyz",
    }
    secret_src = (
        f'PASSWORD = "{secrets["literal"]}"\n'
        f'def connect(token="{secrets["default"]}"):\n'
        f'    @retry(api_key="{secrets["decorator"]}")\n'
        f"    def inner():\n"
        f'        call("{secrets["argument"]}")\n'
    )
    secret_out = analyzer.analyze({"files": [{"path": "leaky.py", "content": secret_src}]})
    serialized = json.dumps(secret_out)
    for name, value in secrets.items():
        check(value not in serialized, f"analyzer output omits {name} secret")
    check("PASSWORD" not in serialized and "token=" not in serialized, "analyzer omits source assignments")
    leaky = secret_out["files"][0]
    connect = _find(leaky["functions"], "connect")
    check(connect is not None and connect["parameters"] == ["token"], "secret default is dropped; name remains")
    inner = _find(leaky["functions"], "inner")
    check(inner is not None and inner["decorators"] == ["retry"], "decorator arguments are omitted")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "analyzer-repo"
        (root / "src").mkdir(parents=True)
        (root / "src" / "app.py").write_text(ANALYZER_FIXTURE, encoding="utf-8")
        (root / "notes.json").write_text('{"password": "dump-json-secret"}\n', encoding="utf-8")
        dump = collector.collect(str(root))
        from_dump = analyzer.analyze({"dump": dump})
        check(from_dump["schemaVersion"] == "1", "dump input uses schemaVersion 1")
        check(any(row["path"] == "src/app.py" for row in from_dump["files"]),
              "sanitized dump FILE sections are analyzed")
        check(not any(row["path"] == "notes.json" for row in from_dump["files"]),
              "JSON dump files are not analyzed as source content")
        check(any(row["path"] == "notes.json" and "json" in row["reason"] for row in from_dump["unparsed"]),
              "excluded JSON is analyzer metadata, not source")
        check("dump-json-secret" not in json.dumps(from_dump), "collector-redacted JSON secrets stay out of analyzer output")
        check(from_dump["files"][0]["classes"], "dump-derived Python facts are present")

    try:
        analyzer.analyze({"repository": "https://github.com/example/repo"})
        check(False, "repository URL without sanitized content is rejected")
    except analyzer.AnalyzerError:
        check(True, "repository URL without sanitized content is rejected")
    truncated = analyzer.analyze({"dump": "REPOSITORY TREE\nsrc/\n  app.py\n"})
    check(truncated["files"] == [] and truncated["references"] == [],
          "a truncated dump without FILE sections returns empty analysis")
    empty_dump = analyzer.analyze({"dump": ""})
    check(empty_dump["files"] == [], "an empty dump returns empty analysis instead of failing")

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), analyzer_server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        port = httpd.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as response:
            check(response.status == 200 and response.read().decode("utf-8") == "ok", "GET /health returns ok")
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/analyze",
            data=json.dumps({"files": [{"path": "src/app.py", "content": ANALYZER_FIXTURE}]}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
            status = response.status
        check(status == 200, "POST /analyze returns 200")
        check(payload["language"] == "python" and payload["files"], "POST /analyze returns analysis JSON")
        bad = urllib.request.Request(
            f"http://127.0.0.1:{port}/analyze",
            data=json.dumps({"repository": "https://github.com/example/repo"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(bad, timeout=5)
            check(False, "HTTP /analyze rejects a repository URL")
        except urllib.error.HTTPError as exc:
            check(exc.code == 400, "HTTP /analyze rejects a repository URL")
    finally:
        httpd.shutdown()
        httpd.server_close()

    previous = analyzer.analyze({
        "files": [
            {"path": "src/util.py", "content": "def helper():\n    return 1\n"},
            {"path": "src/app.py", "content": "from src.util import helper\n\ndef run():\n    helper()\n"},
        ]
    })
    delta = analyzer.analyze({
        "files": [{"path": "src/util.py", "content": "def helper():\n    return 2\n"}]
    })
    spliced = analyzer.splice_analysis(
        previous,
        delta,
        [{"path": "src/util.py", "status": "modified", "eligible": True}],
    )
    util = next(row for row in spliced["files"] if row["path"] == "src/util.py")
    app = next(row for row in spliced["files"] if row["path"] == "src/app.py")
    check(any(fn.get("name") == "helper" for fn in util.get("functions") or []),
          "splice replaces the changed file analysis")
    check(app["path"] == "src/app.py", "splice keeps unchanged file analysis")
    check(
        any(str(row.get("from") or "").startswith("src/app.py") for row in spliced["references"]),
        "splice keeps inbound references from unchanged files",
    )
    previous_full = analyzer.analyze({
        "files": [
            {"path": "src/util.py", "content": "def helper():\n    return 1\n"},
            {"path": "src/app.py", "content": "from src.util import helper\n\ndef run():\n    helper()\n"},
            {"path": "src/untied.py", "content": "VALUE = 1\n"},
        ]
    })
    delta_affected = analyzer.analyze({
        "files": [
            {"path": "src/util.py", "content": "def helper_v2():\n    return 2\n"},
            {"path": "src/app.py", "content": "from src.util import helper_v2\n\ndef run():\n    helper_v2()\n"},
        ]
    })
    refreshed = analyzer.splice_analysis(
        previous_full,
        delta_affected,
        [{"path": "src/util.py", "status": "modified", "eligible": True}],
    )
    util_v2 = next(row for row in refreshed["files"] if row["path"] == "src/util.py")
    app_v2 = next(row for row in refreshed["files"] if row["path"] == "src/app.py")
    check(any(fn.get("name") == "helper_v2" for fn in util_v2.get("functions") or []),
          "changed+affected splice re-analyzes the modified file")
    check(any(fn.get("name") == "run" for fn in app_v2.get("functions") or []),
          "changed+affected splice re-analyzes the affected dependent")
    check(
        any(
            str(row.get("from") or "").startswith("src/app.py")
            and "helper_v2" in str(row.get("to") or "")
            for row in refreshed["references"]
        ),
        "affected app.py references are refreshed",
    )
    check(
        not any(
            str(row.get("from") or "").startswith("src/app.py")
            and str(row.get("to") or "").endswith("::helper")
            for row in refreshed["references"]
        ),
        "stale inbound references from affected dependents are replaced",
    )
    check(any(row["path"] == "src/untied.py" for row in refreshed["files"]),
          "unrelated files stay in the spliced analysis")
    paths = [row["path"] for row in refreshed["files"]]
    check(len(paths) == len(set(paths)), "splice does not duplicate files[] rows")
    removed = analyzer.splice_analysis(
        spliced,
        {"files": [], "unparsed": [], "references": []},
        [{"path": "src/util.py", "status": "deleted", "eligible": True}],
    )
    check(all(row["path"] != "src/util.py" for row in removed["files"]),
          "splice drops deleted file analysis")
    check(
        not any("src/util.py" in str(row.get("to") or "") for row in removed["references"]),
        "splice drops references to deleted files",
    )


def test_analyzer_cross_file() -> None:
    print("\nAST cross-file references")
    analyzer, _ = _analyzer_modules()

    files = [
        {
            "path": "src/util.py",
            "content": (
                "def helper(item):\n"
                "    return item\n"
                "\n"
                "class Base:\n"
                "    def ready(self):\n"
                "        helper(self)\n"
                "\n"
                "def decorate(fn):\n"
                "    return fn\n"
            ),
        },
        {
            "path": "src/worker.py",
            "content": (
                "from src.util import helper, Base, decorate\n"
                "from src.util import helper as run_helper\n"
                "import src.util\n"
                "import src.util as utilmod\n"
                "\n"
                "@decorate\n"
                "class Worker(Base):\n"
                "    def run(self, item):\n"
                "        helper(item)\n"
                "        run_helper(item)\n"
                "        src.util.helper(item)\n"
                "        utilmod.helper(item)\n"
                "        Worker()\n"
                "        Base.ready(self)\n"
                "\n"
                "class Child(src.util.Base):\n"
                "    pass\n"
            ),
        },
        {
            "path": "src/untied.py",
            "content": "def local():\n    helper()\n",
        },
        {
            "path": "a.py",
            "content": "def process():\n    return 1\n",
        },
        {
            "path": "b.py",
            "content": "def process():\n    return 2\n",
        },
        {
            "path": "shadow.py",
            "content": (
                "from a import process\n"
                "from b import process\n"
                "\n"
                "def use():\n"
                "    process()\n"
            ),
        },
        {
            "path": "unique_star.py",
            "content": "def only_here():\n    return 1\n",
        },
        {
            "path": "star_user.py",
            "content": "from unique_star import *\n\ndef use():\n    only_here()\n",
        },
        {
            "path": "star_ambiguous.py",
            "content": (
                "from a import *\n"
                "from b import *\n"
                "\n"
                "def use():\n"
                "    process()\n"
            ),
        },
        {
            "path": "dynamic.py",
            "content": (
                "import src.util as utilmod\n"
                "\n"
                "def use(name):\n"
                "    getattr(utilmod, name)()\n"
                "    eval('helper')\n"
                "    __import__('src.util')\n"
            ),
        },
    ]
    result = analyzer.analyze({"files": files})
    check(result == analyzer.analyze({"files": files}), "cross-file analysis is deterministic")
    refs = result["references"]

    helper_from = _refs(refs, "import", to="src/util.py::helper", frm="src/worker.py")
    check(len(helper_from) == 2 and all(row["certainty"] == "exact" for row in helper_from),
          "from-import and alias import resolve to the unique function")
    check(_refs(refs, "import", to="src/util.py", frm="src/worker.py")
          and all(row["certainty"] == "exact" for row in _refs(refs, "import", to="src/util.py", frm="src/worker.py")),
          "import module and module alias resolve to the unique file")

    worker_run = "src/worker.py::Worker.run"
    for label, target in (
        ("from-import call", "src/util.py::helper"),
        ("import alias call", "src/util.py::helper"),
    ):
        found = _refs(refs, "call", to=target, frm=worker_run)
        check(any(row["certainty"] == "exact" for row in found), f"{label} is exact")
    helper_calls = _refs(refs, "call", to="src/util.py::helper", frm=worker_run)
    check(len(helper_calls) == 4 and all(row["certainty"] == "exact" for row in helper_calls),
          "from-import, alias, module.function, and module-alias.function resolve")
    same_file_ctor = _refs(refs, "call", to="src/worker.py::Worker", frm=worker_run)
    check(len(same_file_ctor) == 1 and same_file_ctor[0]["certainty"] == "exact",
          "same-file class reference stays exact")
    imported_method = _refs(refs, "call", to="src/util.py::Base.ready", frm=worker_run)
    check(len(imported_method) == 1 and imported_method[0]["certainty"] == "exact",
          "cross-file class method reference is exact")

    inherit_base = _refs(refs, "inherit", to="src/util.py::Base", frm="src/worker.py::Worker")
    check(len(inherit_base) == 1 and inherit_base[0]["certainty"] == "exact",
          "cross-file inheritance from imported class is exact")
    inherit_dotted = _refs(refs, "inherit", to="src/util.py::Base", frm="src/worker.py::Child")
    check(len(inherit_dotted) == 1 and inherit_dotted[0]["certainty"] == "exact",
          "cross-file inheritance via module.Class is exact")
    decorate = _refs(refs, "decorate", to="src/util.py::decorate", frm="src/worker.py::Worker")
    check(len(decorate) == 1 and decorate[0]["certainty"] == "exact",
          "cross-file decorator reference is exact")

    untied = _refs(refs, "call", to="helper", frm="src/untied.py::local")
    check(len(untied) == 1 and untied[0]["certainty"] == "unresolved",
          "same-name other file is not guessed without an import")
    shadow = _refs(refs, "call", to="process", frm="shadow.py::use")
    check(len(shadow) == 1 and shadow[0]["certainty"] == "unresolved",
          "ambiguous imported symbols stay unresolved")
    star_ok = _refs(refs, "call", to="unique_star.py::only_here", frm="star_user.py::use")
    check(len(star_ok) == 1 and star_ok[0]["certainty"] == "exact",
          "unique wildcard import resolves")
    star_bad = _refs(refs, "call", to="process", frm="star_ambiguous.py::use")
    check(len(star_bad) == 1 and star_bad[0]["certainty"] == "unresolved",
          "ambiguous wildcard imports stay unresolved")

    dynamic_calls = [row for row in refs if row["from"] == "dynamic.py::use" and row["kind"] == "call"]
    check(dynamic_calls and all(row["certainty"] == "unresolved" for row in dynamic_calls),
          "getattr/eval/__import__ stay unresolved")
    exact = [row for row in refs if row["certainty"] == "exact"]
    check(exact and all("::" in row["to"] or row["to"].endswith(".py") for row in exact),
          "exact targets use deterministic qualified names")

    secrets = {"hidden": "cross-file-secret-value-xyz"}
    secret_files = [
        {"path": "hold.py", "content": f'def leak(token="{secrets["hidden"]}"):\n    return token\n'},
        {"path": "use.py", "content": "from hold import leak\n\ndef run():\n    leak()\n"},
    ]
    secret_out = analyzer.analyze({"files": secret_files})
    check(secrets["hidden"] not in json.dumps(secret_out),
          "cross-file resolution does not emit sensitive values")
    leak_call = _refs(secret_out["references"], "call", to="hold.py::leak", frm="use.py::run")
    check(len(leak_call) == 1 and leak_call[0]["certainty"] == "exact",
          "resolved call still omits parameter defaults")


def _map_modules():
    import importlib
    import importlib.util

    map_dir = ROOT / "tools" / "repository-map"
    map_path = str(map_dir)
    if map_path not in sys.path:
        sys.path.insert(0, map_path)
    mapper = importlib.import_module("mapper")
    server_name = "repository_map_server"
    if server_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(server_name, map_dir / "server.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[server_name] = module
        assert spec.loader is not None
        spec.loader.exec_module(module)
    return mapper, sys.modules[server_name]


def _tree_child(tree: dict, *names: str) -> dict | None:
    current = tree
    for name in names:
        kids = current.get("children") or []
        current = next((child for child in kids if child.get("name") == name), None)
        if current is None:
            return None
    return current


def test_repository_map() -> None:
    print("\nrepository map")
    analyzer, _ = _analyzer_modules()
    mapper, map_server = _map_modules()

    src = (ROOT / "tools" / "repository-map" / "mapper.py").read_text(encoding="utf-8")
    server_src = (ROOT / "tools" / "repository-map" / "server.py").read_text(encoding="utf-8")
    check("import ast" not in src and "analyze_repository" not in src,
          "mapper does not parse AST or resolve references")
    check("import collector" not in src and "collect_into" not in src,
          "mapper does not read collector entries")
    check("import ast" not in server_src, "map server does not parse AST")

    analysis = analyzer.analyze(
        {
            "files": [
                {
                    "path": "src/util.py",
                    "content": (
                        "def helper(item):\n"
                        "    return item\n"
                        "\n"
                        "class Base:\n"
                        "    pass\n"
                        "\n"
                        "def decorate(fn):\n"
                        "    return fn\n"
                    ),
                },
                {
                    "path": "src/worker.py",
                    "content": (
                        "from src.util import helper, Base, decorate\n"
                        "\n"
                        "@decorate\n"
                        "class Worker(Base):\n"
                        "    def run(self, item):\n"
                        "        helper(item)\n"
                        "        unknown()\n"
                    ),
                },
                {
                    "path": "pkg/__init__.py",
                    "content": "VALUE = 1\n",
                },
                {
                    "path": "pkg/sub/mod.py",
                    "content": "def local():\n    return 1\n",
                },
                {
                    "path": "tests/test_app.py",
                    "content": "def test_ok():\n    assert True\n",
                },
                {"path": "broken.py", "content": "def broken(\n"},
                {"path": "config.json", "content": '{"token": "map-json-secret"}\n'},
                {"path": "values.yaml", "content": "password: map-yaml-secret\n"},
            ]
        }
    )
    first = mapper.build({"analysis": analysis})
    second = mapper.build({"analysisJson": json.dumps(analysis)})
    check(first == second, "repository map is deterministic")
    check(first["schemaVersion"] == "1", "map schemaVersion is 1")

    modules = {row["path"]: row for row in first["modules"]}
    check(modules["src/util.py"]["status"] == "parsed" and modules["src/util.py"]["language"] == "python",
          "parsed Python modules are recorded")
    check(modules["broken.py"]["status"] == "unparsed" and modules["broken.py"]["reason"] == "SyntaxError",
          "invalid Python is unparsed in the map")
    check(modules["config.json"]["status"] == "unparsed" and modules["config.json"]["reason"] == "unsupported",
          "unsupported files are unparsed in the map")
    check(modules["values.yaml"]["status"] == "unparsed", "YAML is unparsed, not analyzed")
    check("src" in {row["path"] for row in first["directories"]}, "directories include src")
    check(any(row["path"] == "pkg" and row["kind"] == "package" for row in first["directories"]),
          "__init__.py directories are packages")
    check(any(row["path"] == "pkg/sub" and row["kind"] == "directory" for row in first["directories"]),
          "nested directories without __init__.py stay directories")
    check(any(row["path"] == "tests" for row in first["directories"]),
          "multiple top-level directories are mapped")

    tree = first["tree"]
    check(tree["kind"] == "directory", "tree root is a directory")
    src_dir = _tree_child(tree, "src")
    util = _tree_child(tree, "src", "util.py")
    pkg_sub = _tree_child(tree, "pkg", "sub", "mod.py")
    tests_mod = _tree_child(tree, "tests", "test_app.py")
    check(src_dir is not None and src_dir["kind"] == "directory", "tree contains the src directory")
    check(util is not None and util["status"] == "parsed" and util["path"] == "src/util.py",
          "tree contains parsed modules")
    check(pkg_sub is not None and pkg_sub["path"] == "pkg/sub/mod.py", "tree contains nested modules")
    check(tests_mod is not None, "tree contains a second top-level directory")
    broken = _tree_child(tree, "broken.py")
    check(broken is not None and broken["status"] == "unparsed", "tree includes unparsed files")

    symbols = {row["qualname"]: row for row in first["symbols"]}
    check(symbols.get("src/util.py::Base", {}).get("kind") == "class", "map includes classes")
    check(symbols.get("src/util.py::helper", {}).get("kind") == "function", "map includes functions")
    check(symbols.get("src/worker.py::Worker.run", {}).get("kind") == "method", "map includes methods")
    check("src/worker.py::Worker" in symbols, "qualified names are preserved")

    rels = first["relationships"]
    imports = _refs(rels, "import", to="src/util.py::helper", frm="src/worker.py")
    check(imports and imports[0]["certainty"] == "exact", "map keeps resolved imports")
    inherit = _refs(rels, "inherit", to="src/util.py::Base", frm="src/worker.py::Worker")
    check(inherit and inherit[0]["certainty"] == "exact", "map keeps inheritance")
    decorate = _refs(rels, "decorate", to="src/util.py::decorate", frm="src/worker.py::Worker")
    check(decorate and decorate[0]["certainty"] == "exact", "map keeps decorators")
    resolved_call = _refs(rels, "call", to="src/util.py::helper", frm="src/worker.py::Worker.run")
    check(resolved_call and resolved_call[0]["certainty"] == "exact", "map keeps resolved calls")
    unresolved_call = _refs(rels, "call", to="unknown", frm="src/worker.py::Worker.run")
    check(unresolved_call and unresolved_call[0]["certainty"] == "unresolved",
          "map preserves unresolved references")

    module_rels = first["moduleRelationships"]
    worker_util = next((row for row in module_rels if row["from"] == "src/worker.py" and row["to"] == "src/util.py"), None)
    check(worker_util is not None and worker_util["certainty"] == "exact",
          "exact cross-file refs become module relationships")
    check("import" in worker_util["kinds"] and "call" in worker_util["kinds"],
          "module relationships list deterministic kinds only")
    check(all(row["certainty"] == "exact" for row in module_rels),
          "module relationships are not guessed from unresolved refs")

    serialized = json.dumps(first)
    check("map-json-secret" not in serialized and "map-yaml-secret" not in serialized,
          "repository map omits unsupported-file secrets")
    check("def helper" not in serialized and "return item" not in serialized,
          "repository map omits source snippets")

    secret_analysis = analyzer.analyze(
        {
            "files": [
                {
                    "path": "hold.py",
                    "content": 'def leak(token="map-secret-default-xyz"):\n    return token\n',
                },
                {"path": "use.py", "content": "from hold import leak\n\ndef run():\n    leak()\n"},
            ]
        }
    )
    secret_map = mapper.build({"analysis": secret_analysis})
    check("map-secret-default-xyz" not in json.dumps(secret_map),
          "repository map omits sensitive parameter defaults")

    try:
        mapper.build({"repository": "https://github.com/example/repo"})
        check(False, "map rejects a repository URL")
    except mapper.MapError:
        check(True, "map rejects a repository URL")
    try:
        mapper.build({"dump": "FILE: app.py\nprint(1)\n"})
        check(False, "map rejects a collector dump")
    except mapper.MapError:
        check(True, "map rejects a collector dump")

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), map_server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        port = httpd.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as response:
            check(response.status == 200 and response.read().decode("utf-8") == "ok", "GET /health returns ok")
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/map",
            data=json.dumps({"analysis": analysis}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
            status = response.status
        check(status == 200 and payload == first, "POST /map returns the same map JSON")
        bad = urllib.request.Request(
            f"http://127.0.0.1:{port}/map",
            data=json.dumps({"repository": "https://github.com/example/repo"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(bad, timeout=5)
            check(False, "HTTP /map rejects a repository URL")
        except urllib.error.HTTPError as exc:
            check(exc.code == 400, "HTTP /map rejects a repository URL")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_incremental_analysis() -> None:
    print("\nincremental analysis")
    analyzer, _ = _analyzer_modules()
    mapper, map_server = _map_modules()
    sys.path.insert(0, str(ROOT / "tools" / "repository-map"))
    import impact  # noqa: E402

    files = [
        {
            "path": "src/util.py",
            "content": "def helper(item):\n    return item\n",
        },
        {
            "path": "src/app.py",
            "content": (
                "from src.util import helper\n"
                "\n"
                "def run(item):\n"
                "    return helper(item)\n"
            ),
        },
        {
            "path": "src/unrelated.py",
            "content": "def unused():\n    return 2\n",
        },
        {
            "path": "src/unknown.py",
            "content": "def maybe():\n    missing()\n",
        },
        {
            "path": "notes.json",
            "content": '{"token": "json-should-not-be-source"}\n',
        },
    ]
    analysis = analyzer.analyze({"files": files})
    repo_map = mapper.build({"analysis": analysis})

    def change(path: str, status: str, src: str = "", eligible: bool = True, reason: str = "") -> dict:
        row = {"path": path, "status": status, "eligible": eligible}
        if src:
            row["from"] = src
        if reason:
            row["reason"] = reason
        return row

    previous = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    current = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    modified = impact.analyze_impact(
        {
            "schemaVersion": "1",
            "mode": "incremental",
            "previousCommit": previous,
            "newCommit": current,
            "changed": [change("src/util.py", "modified")],
        },
        analysis,
        repo_map,
    )
    check(modified == impact.analyze_impact(
        {
            "schemaVersion": "1",
            "mode": "incremental",
            "previousCommit": previous,
            "newCommit": current,
            "changed": [change("src/util.py", "modified")],
        },
        analysis,
        repo_map,
    ), "incremental analysis is deterministic")
    check(modified["schemaVersion"] == "1", "impact schemaVersion is 1")
    check(modified["previousCommit"] == previous and modified["newCommit"] == current,
          "impact preserves previousCommit and newCommit")
    check(modified["changed"][0]["path"] == "src/util.py" and modified["changed"][0]["status"] == "modified",
          "modified file is in the changed list")
    affected_paths = {row["path"] for row in modified["affected"]}
    check("src/app.py" in affected_paths, "a dependent of a modified file is affected")
    check("depends-on:src/util.py" in (modified["affected"][0]["reasons"] if modified["affected"] else []),
          "affected reason uses the reverse exact relationship")
    check("src/unrelated.py" not in affected_paths and "src/unrelated.py" not in modified["affectedModules"],
          "unrelated files are not affected")
    check("src/unknown.py" not in affected_paths, "unresolved/ambiguous calls do not create dependents")
    check(any(row["qualname"] == "src/util.py::helper" for row in modified["affectedSymbols"]),
          "changed-file symbols are listed")
    check(any(row["qualname"] == "src/app.py::run" for row in modified["affectedSymbols"]),
          "affected-module symbols are listed")

    added = impact.analyze_impact(
        {"mode": "incremental", "changed": [change("src/new.py", "added")]},
        analysis,
        repo_map,
    )
    check(added["changed"][0]["status"] == "added" and "src/new.py" in added["affectedModules"],
          "added file is in the incremental scope")
    check(added["affected"] == [], "an added file with no reverse dependents has no extra affected files")

    deleted = impact.analyze_impact(
        {"mode": "incremental", "changed": [change("src/util.py", "deleted")]},
        analysis,
        repo_map,
    )
    check("src/app.py" in {row["path"] for row in deleted["affected"]},
          "dependents of a deleted file are affected")

    renamed = impact.analyze_impact(
        {"mode": "incremental", "changed": [change("src/helpers.py", "renamed", "src/util.py")]},
        analysis,
        repo_map,
    )
    check(renamed["changed"][0]["from"] == "src/util.py", "rename keeps the source path")
    check("src/app.py" in {row["path"] for row in renamed["affected"]},
          "dependents of a renamed file stay affected")
    check("src/util.py" in renamed["affectedModules"] and "src/helpers.py" in renamed["affectedModules"],
          "rename includes both old and new paths in the module scope")

    json_change = impact.analyze_impact(
        {
            "mode": "incremental",
            "changed": [change("notes.json", "modified", eligible=False, reason="excluded: json file")],
        },
        analysis,
        repo_map,
    )
    check(json_change["changed"][0]["eligible"] is False, "JSON changes stay ineligible")
    check("notes.json" not in json_change["affectedModules"],
          "JSON files are not incremental analysis source")
    check("json-should-not-be-source" not in json.dumps(json_change),
          "JSON contents never enter incremental analysis")

    full = impact.analyze_impact({"mode": "full", "previousCommit": "", "newCommit": current, "changed": []})
    check(full["changed"] == [] and full["affected"] == [] and full["affectedModules"] == [],
          "full/first run has an empty incremental scope")

    same = impact.analyze_impact(modified, analysis)
    check(same["affectedModules"] == modified["affectedModules"],
          "impact can rebuild the map from analyzer JSON")

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), map_server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        port = httpd.server_address[1]
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/impact",
            data=json.dumps({
                "changes": {
                    "mode": "incremental",
                    "previousCommit": previous,
                    "newCommit": current,
                    "changed": [change("src/util.py", "modified")],
                },
                "analysis": analysis,
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
        check(payload == modified, "POST /impact returns the same incremental scope")
        bad = urllib.request.Request(
            f"http://127.0.0.1:{port}/impact",
            data=json.dumps({"repository": "https://github.com/example/repo"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(bad, timeout=5)
            check(False, "HTTP /impact rejects a repository URL")
        except urllib.error.HTTPError as exc:
            check(exc.code == 400, "HTTP /impact rejects a repository URL")
    finally:
        httpd.shutdown()
        httpd.server_close()


def _sample_docs(*, util: str, unrelated: str, added: str = "", structure: str = "src/util.py and src/unrelated.py") -> dict:
    return {
        "repositoryOverview": {
            "summary": f"Service uses `{util}` and `{unrelated}`.",
            "quickStart": "Run src/unrelated.py",
        },
        "repositoryStructure": structure,
        "toolsAndTechnologies": "Python",
        "coreConceptsAndArchitecture": {
            "summary": f"`{util}` is the helper.",
            "requestFlow": f"`{util}` is called from src/app.py",
            "buildAndPackagingFlow": "No build files.",
        },
        "categorizedTechnicalInformation": {
            "mainApisAndEndpoints": "None",
            "mainServicesAndMediators": f"`{util}`",
            "dtosSchemasMetadata": "None",
            "securityComponents": "None",
            "configurations": "None",
            "entryPoints": "src/app.py",
            "tests": "None",
            "risksAndTechnicalDebt": "None",
        },
        "developerOnboardingGuide": {
            "first30Minutes": f"Open `{unrelated}` first.",
            "howToInvestigateAProductionBug": f"Check `{util}`.",
            "criticalFiles": f"- {util}\n- {unrelated}",
            "commonMistakes": f"Do not ignore `{unrelated}`.",
        },
    }


def test_incremental_documentation() -> None:
    print("\nincremental documentation merge")
    _validation, ark_client, registry = _host_modules()
    sys.path.insert(0, str(ROOT / "tools" / "documentation-renderer"))
    import merge as documentation_merge  # noqa: E402
    import renderer  # noqa: E402

    previous = _sample_docs(util="src/util.py", unrelated="src/unrelated.py")
    generated = _sample_docs(
        util="src/util.py",
        unrelated="src/unrelated.py",
        structure="src/util.py, src/unrelated.py, src/new.py",
    )
    generated["repositoryOverview"]["summary"] = "REWRITTEN ALL including src/unrelated.py"
    generated["coreConceptsAndArchitecture"]["summary"] = "CHANGED helper in src/util.py"
    generated["developerOnboardingGuide"]["first30Minutes"] = "REWRITTEN unrelated onboarding and src/util.py"
    generated["developerOnboardingGuide"]["commonMistakes"] = "REWRITTEN src/unrelated.py mistakes"
    generated["repositoryStructure"] = "src/util.py, src/unrelated.py, src/new.py"

    impact_modified = {
        "mode": "incremental",
        "changed": [{"path": "src/util.py", "status": "modified", "eligible": True}],
        "affected": [{"path": "src/app.py", "reasons": ["depends-on:src/util.py"]}],
        "affectedModules": ["src/app.py", "src/util.py"],
    }
    merged = documentation_merge.merge_documentation(previous, generated, impact_modified)
    check(merged == documentation_merge.merge_documentation(previous, generated, impact_modified),
          "documentation merge is deterministic")
    check("CHANGED helper" in merged["coreConceptsAndArchitecture"]["summary"],
          "modified-file documentation is updated")
    check(merged["developerOnboardingGuide"]["first30Minutes"] == previous["developerOnboardingGuide"]["first30Minutes"],
          "unrelated documentation is preserved")
    check("REWRITTEN unrelated onboarding" not in merged["developerOnboardingGuide"]["first30Minutes"],
          "merge ignores Agent rewrites of fields the host did not select")
    check("REWRITTEN ALL" in merged["repositoryOverview"]["summary"],
          "overview mentioning the changed file is updated")
    check("notes.json" not in json.dumps(merged), "JSON files are not merge source")

    added_prev = previous
    added_gen = copy.deepcopy(generated)
    added_gen["repositoryStructure"] = "added src/new.py plus src/unrelated.py"
    added_impact = {
        "mode": "incremental",
        "changed": [{"path": "src/new.py", "status": "added", "eligible": True}],
        "affected": [],
        "affectedModules": ["src/new.py"],
    }
    added = documentation_merge.merge_documentation(added_prev, added_gen, added_impact)
    check("src/new.py" in added["repositoryStructure"], "added file updates repository structure")
    check(added["developerOnboardingGuide"]["first30Minutes"] == previous["developerOnboardingGuide"]["first30Minutes"],
          "added file does not rewrite unrelated onboarding")
    check(added["repositoryOverview"]["summary"] == previous["repositoryOverview"]["summary"],
          "adding a new module does not rewrite overview that never mentioned it")
    omitted = copy.deepcopy(added_gen)
    omitted["repositoryStructure"] = "src/util.py and src/unrelated.py only"
    covered = documentation_merge.merge_documentation(added_prev, omitted, added_impact)
    check("`src/new.py` was added." in covered["repositoryStructure"],
          "added file is injected when the Agent omits it")

    invented_gen = copy.deepcopy(generated)
    invented_gen["coreConceptsAndArchitecture"]["summary"] = (
        "CHANGED helper in src/util.py and also src/invented_secret.py"
    )
    invented = documentation_merge.merge_documentation(previous, invented_gen, impact_modified)
    check("src/invented_secret.py" not in invented["coreConceptsAndArchitecture"]["summary"],
          "unsupported file references are not applied")
    check(invented["coreConceptsAndArchitecture"]["summary"] == previous["coreConceptsAndArchitecture"]["summary"],
          "a field with invented paths keeps the previous text")

    readme_impact = {
        "mode": "incremental",
        "changed": [{"path": "README.md", "status": "modified", "eligible": True}],
        "affected": [],
        "affectedModules": ["README.md"],
        "updateFields": ["repositoryOverview.summary"],
    }
    readme_gen = copy.deepcopy(previous)
    readme_gen["repositoryOverview"]["summary"] = "Rewritten overview without the new README fact."
    readme_merged = documentation_merge.merge_documentation(previous, readme_gen, readme_impact)
    check(
        "AUDIT5B incremental probe: scoped documentation must mention this sentence."
        not in readme_merged["repositoryOverview"]["summary"],
        "merge does not invent README semantic claims without dump evidence",
    )
    banner = "=" * 50
    readme_dump = (
        f"{banner}\nFILE: README.md\n{banner}\n\nExisting README intro.\n\n"
        "AUDIT5B incremental probe: scoped documentation must mention this sentence.\n\n"
        f"{banner}\nDIFF: README.md\n{banner}\n\n"
        "@@ -1,1 +1,3 @@\n Existing README intro.\n"
        "+AUDIT5B incremental probe: scoped documentation must mention this sentence.\n"
    )
    readme_covered = documentation_merge.merge_documentation(
        previous, readme_gen, readme_impact, dump=readme_dump
    )
    check(
        "AUDIT5B incremental probe: scoped documentation must mention this sentence."
        in readme_covered["repositoryOverview"]["summary"],
        "modified README new lines are preserved from the sanitized diff",
    )
    probe_comment = "<!-- incremental-verify 2026-09-08: isolated README note for documentation webhook test -->"
    comment_dump = (
        f"{banner}\nFILE: README.md\n{banner}\n\nExisting README intro.\n\n"
        f"{probe_comment}\n\n"
        f"{banner}\nDIFF: README.md\n{banner}\n\n"
        f"@@ -1,1 +1,3 @@\n Existing README intro.\n"
        f"+{probe_comment}\n"
    )
    comment_covered = documentation_merge.merge_documentation(
        previous, readme_gen, readme_impact, dump=comment_dump
    )
    check(
        "incremental-verify 2026-09-08" not in comment_covered["repositoryOverview"]["summary"],
        "README HTML comments are not copied into documentation",
    )
    check(
        readme_covered["developerOnboardingGuide"]["first30Minutes"]
        == previous["developerOnboardingGuide"]["first30Minutes"],
        "README coverage does not rewrite unselected onboarding",
    )
    check(
        readme_merged["developerOnboardingGuide"]["first30Minutes"]
        == previous["developerOnboardingGuide"]["first30Minutes"],
        "README coverage without dump does not rewrite unselected onboarding",
    )
    route_banner = "=" * 50
    route_dump = (
        f"{route_banner}\nFILE: backend/main.py\n{route_banner}\n\n"
        "from fastapi import FastAPI\napp = FastAPI()\n"
        '@app.post("/chat")\nasync def chat():\n    return {}\n'
        '@app.get("/health")\nasync def health():\n    return {}\n'
    )
    omitted_routes = copy.deepcopy(previous)
    omitted_routes["categorizedTechnicalInformation"]["mainApisAndEndpoints"] = "None listed."
    omitted_routes["coreConceptsAndArchitecture"]["requestFlow"] = "Inferred from helpers."
    full_routes = documentation_merge.merge_documentation(
        None, omitted_routes, {"mode": "full"}, dump=route_dump
    )
    check(
        "`POST /chat`" in full_routes["categorizedTechnicalInformation"]["mainApisAndEndpoints"]
        and "`GET /health`" in full_routes["categorizedTechnicalInformation"]["mainApisAndEndpoints"],
        "full merge backfills dump-grounded HTTP routes into mainApisAndEndpoints",
    )
    check(
        "`POST /chat`" in full_routes["coreConceptsAndArchitecture"]["requestFlow"]
        and "`GET /health`" in full_routes["coreConceptsAndArchitecture"]["requestFlow"],
        "full merge backfills dump-grounded HTTP routes into requestFlow",
    )
    check(
        full_routes["developerOnboardingGuide"]["first30Minutes"]
        == omitted_routes["developerOnboardingGuide"]["first30Minutes"],
        "route coverage does not rewrite unrelated onboarding",
    )
    scoped_readme_only = documentation_merge.merge_documentation(
        previous,
        readme_gen,
        readme_impact,
        dump=readme_dump,
    )
    check(
        "POST /chat" not in scoped_readme_only["categorizedTechnicalInformation"]["mainApisAndEndpoints"]
        and "GET /health" not in scoped_readme_only["coreConceptsAndArchitecture"]["requestFlow"],
        "incremental merge does not invent routes absent from the scoped dump",
    )
    route_impact = {
        "mode": "incremental",
        "changed": [{"path": "backend/main.py", "status": "modified", "eligible": True}],
        "affected": [],
        "affectedModules": ["backend/main.py"],
        "updateFields": ["categorizedTechnicalInformation.mainApisAndEndpoints"],
    }
    route_gen = copy.deepcopy(previous)
    route_gen["categorizedTechnicalInformation"]["mainApisAndEndpoints"] = "Rewritten without routes."
    scoped_routes = documentation_merge.merge_documentation(
        previous, route_gen, route_impact, dump=route_dump
    )
    check(
        "`POST /chat`" in scoped_routes["categorizedTechnicalInformation"]["mainApisAndEndpoints"]
        and "`GET /health`" in scoped_routes["categorizedTechnicalInformation"]["mainApisAndEndpoints"],
        "incremental merge backfills routes when the route file is in the scoped dump",
    )
    check(
        scoped_routes["developerOnboardingGuide"]["first30Minutes"]
        == previous["developerOnboardingGuide"]["first30Minutes"],
        "incremental route coverage does not rewrite unselected onboarding",
    )
    patched = documentation_merge.merge_documentation(
        previous,
        {
            "updates": [
                {
                    "field": "coreConceptsAndArchitecture.summary",
                    "text": "CHANGED helper in src/util.py",
                }
            ]
        },
        impact_modified,
    )
    check("CHANGED helper" in patched["coreConceptsAndArchitecture"]["summary"],
          "updates[] patches are applied to selected fields")
    check(
        patched["developerOnboardingGuide"]["first30Minutes"]
        == previous["developerOnboardingGuide"]["first30Minutes"],
        "updates[] leave unselected fields unchanged",
    )

    test_add_impact = {
        "mode": "incremental",
        "changed": [{"path": "tests/new_test.py", "status": "added", "eligible": True}],
        "affected": [],
        "affectedModules": ["tests/new_test.py"],
    }
    test_add_gen = copy.deepcopy(previous)
    test_add_gen["categorizedTechnicalInformation"]["tests"] = "pytest only"
    test_add_gen["repositoryStructure"] = previous["repositoryStructure"]
    test_added = documentation_merge.merge_documentation(previous, test_add_gen, test_add_impact)
    check("tests/new_test.py" in test_added["categorizedTechnicalInformation"]["tests"],
          "added test files are mentioned in the tests section")

    class StaleMerge:
        @staticmethod
        def merge_documentation(previous, generated, impact=None, section_sources=None):
            return generated

        @staticmethod
        def documentation_only(document):
            return document

    try:
        StaleMerge.merge_documentation(None, previous, {"mode": "full"}, dump=route_dump)
        check(False, "stale merge_documentation rejects dump=")
    except TypeError as exc:
        check("dump" in str(exc), "live error is unexpected keyword argument dump")
    stale_out = ark_client._merge_persisted(
        StaleMerge, None, previous, {"mode": "full"}, route_dump
    )
    check(stale_out == previous, "persist merge does not TypeError on stale merge_documentation")
    captured = {}

    class CaptureMerge:
        @staticmethod
        def merge_documentation(previous, generated, impact=None, section_sources=None):
            captured["impact"] = impact
            return generated

        @staticmethod
        def documentation_only(document):
            return document

    ark_client._merge_persisted(CaptureMerge, None, previous, {"mode": "full"}, route_dump)
    check(
        "FILE: backend/main.py" in str((captured.get("impact") or {}).get("scopedDump") or ""),
        "stale merge still receives dump via impact.scopedDump",
    )
    persist_routes = ark_client._merge_persisted(
        documentation_merge, None, omitted_routes, {"mode": "full"}, route_dump
    )
    check(
        "`POST /chat`" in persist_routes["categorizedTechnicalInformation"]["mainApisAndEndpoints"],
        "current persist merge still backfills dump-grounded HTTP routes",
    )
    real_merge, real_renderer = ark_client._renderer_modules()

    class StalePersistMerge:
        merge_documentation = staticmethod(
            lambda previous, generated, impact=None, section_sources=None: generated
        )
        documentation_only = staticmethod(real_merge.documentation_only)

    original_modules = ark_client._renderer_modules
    original_out = ark_client.OUT_DIR
    ark_client._renderer_modules = lambda: (StalePersistMerge, real_renderer)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            ark_client.OUT_DIR = Path(tmp)
            filename, document = ark_client.persist_generated(
                {"repository": "https://github.com/example/persist-dump-compat"},
                omitted_routes,
                dump=route_dump,
            )
        check(bool(filename) and isinstance(document, dict),
              "persist_generated succeeds when loaded merge_documentation rejects dump=")
    except TypeError as exc:
        check(False, f"persist_generated must not raise dump TypeError ({exc})")
    finally:
        ark_client._renderer_modules = original_modules
        ark_client.OUT_DIR = original_out

    stale_mod = type(sys)("merge")
    def stale_merge_documentation(previous, generated, impact=None, section_sources=None):
        raise TypeError("merge_documentation() got an unexpected keyword argument 'dump'")
    stale_mod.merge_documentation = stale_merge_documentation
    stale_mod.__file__ = str(ROOT / "tools" / "documentation-renderer" / "stale-cached-merge.py")
    previous_merge = sys.modules.get("merge")
    previous_renderer = sys.modules.get("renderer")
    sys.modules["merge"] = stale_mod
    try:
        loaded_merge, loaded_renderer = ark_client._renderer_modules()
        check(loaded_merge is not stale_mod, "persist does not keep Streamlit's cached merge module")
        check(
            "dump" in inspect.signature(loaded_merge.merge_documentation).parameters,
            "persist execs tools/documentation-renderer/merge.py from disk",
        )
        disk_routes = loaded_merge.merge_documentation(
            None, omitted_routes, {"mode": "full"}, dump=route_dump
        )
        check(
            "`POST /chat`" in disk_routes["categorizedTechnicalInformation"]["mainApisAndEndpoints"],
            "disk merge accepts dump= even when sys.modules['merge'] rejects it",
        )
        check(loaded_renderer.merge_documentation is loaded_merge.merge_documentation,
              "renderer bindings come from the same on-disk merge")
    finally:
        if previous_merge is None:
            sys.modules.pop("merge", None)
        else:
            sys.modules["merge"] = previous_merge
        if previous_renderer is None:
            sys.modules.pop("renderer", None)
        else:
            sys.modules["renderer"] = previous_renderer

    readme_dump = (
        "INCREMENTAL DUMP\n"
        + ("=" * 50) + "\nFILE: README.md\n" + ("=" * 50) + "\n\n"
        "Existing README intro that is long enough to skip as not last.\n\n"
        "AUDIT5B incremental probe: scoped documentation must mention this sentence.\n\n"
        + ("=" * 50) + "\nFILE: extra.py\n" + ("=" * 50) + "\nprint(1)\n"
    )
    stub = (
        "\n" + ("=" * 50) + "\nFILE: tests/debug_github_tools.py\n" + ("=" * 50)
        + "\n\n(no current body: renamed away, excluded, or not collected at this commit)\n"
    )
    stripped = documentation_merge.strip_placeholder_files(readme_dump + stub)
    check("no current body" not in stripped and "FILE: tests/debug_github_tools.py" not in stripped,
          "renamed-away FILE stubs are stripped from the incremental dump")

    deleted_gen = _sample_docs(util="src/util.py", unrelated="src/unrelated.py", structure="src/unrelated.py only")
    deleted_gen["coreConceptsAndArchitecture"]["summary"] = "helper removed"
    deleted_gen["coreConceptsAndArchitecture"]["requestFlow"] = "src/app.py has no helper"
    deleted = documentation_merge.merge_documentation(
        previous,
        deleted_gen,
        {
            "mode": "incremental",
            "changed": [{"path": "src/util.py", "status": "deleted", "eligible": True}],
            "affected": [{"path": "src/app.py"}],
            "affectedModules": ["src/app.py", "src/util.py"],
        },
    )
    check("helper removed" in deleted["coreConceptsAndArchitecture"]["summary"],
          "deleted file updates sections that mentioned it")
    check(deleted["developerOnboardingGuide"]["first30Minutes"] == previous["developerOnboardingGuide"]["first30Minutes"],
          "deleted file leaves unrelated sections in place")

    stale_rename = _sample_docs(util="src/util.py", unrelated="src/unrelated.py", structure="src/util.py")
    renamed = documentation_merge.merge_documentation(
        previous,
        stale_rename,
        {
            "mode": "incremental",
            "changed": [{"path": "src/helpers.py", "status": "renamed", "from": "src/util.py", "eligible": True}],
            "affected": [{"path": "src/app.py"}],
            "affectedModules": ["src/app.py", "src/helpers.py", "src/util.py"],
        },
    )
    check("src/helpers.py" in renamed["coreConceptsAndArchitecture"]["summary"],
          "renamed file uses the new path in updated sections")
    check("src/util.py" not in renamed["coreConceptsAndArchitecture"]["summary"],
          "stale renamed paths are rewritten")
    check(renamed["developerOnboardingGuide"]["first30Minutes"] == previous["developerOnboardingGuide"]["first30Minutes"],
          "rename leaves unrelated sections in place")

    selected = documentation_merge.select_update_fields(previous, impact_modified)
    check("coreConceptsAndArchitecture.summary" in selected, "host selects fields that mention the changed file")
    check("developerOnboardingGuide.first30Minutes" not in selected,
          "host does not select fields that only mention unrelated files")
    check("repositoryOverview.summary" in selected, "host selects overview that cites the modified file")

    unchanged_gen = _sample_docs(util="src/util.py", unrelated="src/unrelated.py")
    unchanged_gen["coreConceptsAndArchitecture"]["summary"] = "CHANGED helper in src/util.py"
    unchanged_gen["developerOnboardingGuide"]["first30Minutes"] = "UNCHANGED: out of incremental scope."
    unchanged_gen["repositoryOverview"]["summary"] = "UNCHANGED: out of incremental scope."
    unchanged_merged = documentation_merge.merge_documentation(
        previous, unchanged_gen, impact_modified
    )
    check("CHANGED helper" in unchanged_merged["coreConceptsAndArchitecture"]["summary"],
          "in-scope generated text still replaces the previous section")
    check(
        unchanged_merged["developerOnboardingGuide"]["first30Minutes"]
        == previous["developerOnboardingGuide"]["first30Minutes"],
        "UNCHANGED placeholder keeps the previous onboarding section",
    )
    check(
        unchanged_merged["repositoryOverview"]["summary"]
        == previous["repositoryOverview"]["summary"],
        "UNCHANGED placeholder keeps the previous overview",
    )

    full = documentation_merge.merge_documentation(previous, generated, {"mode": "full", "changed": []})
    check(full == generated, "full generation uses the new documentation")

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "documentation-registry.json"
        out = Path(tmp) / "out"
        out.mkdir()
        url = "https://github.com/owner/repo"
        sha1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        sha2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        html = out / "repo.html"
        html.write_text("<!DOCTYPE html><html><body>first</body></html>", encoding="utf-8")

        first_plan = ark_client.plan_documentation(url, current_sha=sha1, registry_path=path)
        original_out = ark_client.OUT_DIR
        ark_client.OUT_DIR = out
        try:
            first = ark_client.execute_documentation_plan(
                first_plan,
                run_pipeline=lambda _plan: {
                    "ok": True,
                    "artifact": "repo.html",
                    "documentation": previous,
                    "analysis": {"files": [{"path": "src/app.py"}], "unparsed": [], "references": []},
                    "repositoryMap": {"modules": [{"path": "src/app.py"}], "symbols": [], "relationships": []},
                },
                registry_path=path,
            )
            check(first["status"] == "documented", "initial/full generation succeeds")
            stored = registry.lookup(url, path)
            check(stored["documentation"]["developerOnboardingGuide"]["first30Minutes"]
                  == previous["developerOnboardingGuide"]["first30Minutes"],
                  "successful full generation persists documentation JSON")
            seeded = ark_client.load_analysis_sidecar({"repository": url}, sha1)
            check(seeded is not None and seeded.get("commitSha") == sha1,
                  "successful full generation persists analysis sidecar at currentCommit")
            check(isinstance(first.get("analysis"), dict) and first["analysis"].get("files"),
                  "successful full generation returns analysis on the pipeline outcome")

            failed_plan = ark_client.plan_documentation(url, current_sha=sha2, registry_path=path)
            failed = ark_client.execute_documentation_plan(
                failed_plan,
                run_pipeline=lambda _plan: {"ok": False, "error": "renderer failed"},
                registry_path=path,
            )
            check(failed["status"] == "failed", "failed incremental update is reported as failed")
            after_fail = registry.lookup(url, path)
            check(after_fail["commitSha"] == sha1, "failed update does not advance the stored SHA")
            check(after_fail["documentation"] == stored["documentation"],
                  "failed update does not overwrite the last successful documentation")

            updated = ark_client.execute_documentation_plan(
                failed_plan,
                run_pipeline=lambda _plan: {
                    "ok": True,
                    "artifact": "repo.html",
                    "documentation": generated,
                    "impact": impact_modified,
                },
                registry_path=path,
            )
        finally:
            ark_client.OUT_DIR = original_out
        check(updated["status"] == "documented" and updated["currentCommit"] == sha2,
              "incremental modification persists the new SHA")
        latest = registry.lookup(url, path)
        check("CHANGED helper" in latest["documentation"]["coreConceptsAndArchitecture"]["summary"],
              "incremental modification updates affected documentation")
        check(
            latest["documentation"]["developerOnboardingGuide"]["first30Minutes"]
            == previous["developerOnboardingGuide"]["first30Minutes"],
            "incremental modification preserves unaffected documentation",
        )
        check(latest["sectionFiles"]["coreConceptsAndArchitecture.summary"],
              "lightweight section file metadata is stored with the document")

        same = ark_client.plan_documentation(url, current_sha=sha2, registry_path=path)
        skipped = ark_client.execute_documentation_plan(
            same,
            run_pipeline=lambda _plan: {"ok": True, "artifact": "repo.html", "documentation": generated},
            registry_path=path,
        )
        check(skipped["status"] == "already_documented", "same SHA does not regenerate documentation")
        check(registry.lookup(url, path)["documentation"] == latest["documentation"],
              "same SHA leaves the last successful documentation in place")

        rendered = renderer.render({
            "documentation": generated,
            "previousDocumentation": previous,
            "impact": impact_modified,
        })
        check("CHANGED helper" in rendered, "renderer merge updates affected HTML")
        check("src/unrelated.py" in rendered and "REWRITTEN unrelated onboarding" not in rendered,
              "renderer merge keeps unaffected HTML")

        production_generated = dict(generated)
        production_generated["incrementalImpact"] = json.dumps(impact_modified)
        production_generated["sectionSources"] = json.dumps({
            "coreConceptsAndArchitecture.summary": ["src/util.py"],
            "developerOnboardingGuide.first30Minutes": ["src/unrelated.py"],
        })
        with tempfile.TemporaryDirectory() as render_tmp:
            original_output = os.environ.get("OUTPUT_DIR")
            os.environ["OUTPUT_DIR"] = render_tmp
            try:
                sidecar = Path(render_tmp) / "repo.json"
                sidecar.write_text(json.dumps(previous), encoding="utf-8")
                production = renderer.resolve_document({
                    "documentation": production_generated,
                    "repositoryName": "repo",
                    "persist": True,
                })
            finally:
                if original_output is None:
                    os.environ.pop("OUTPUT_DIR", None)
                else:
                    os.environ["OUTPUT_DIR"] = original_output
        check("CHANGED helper" in production["coreConceptsAndArchitecture"]["summary"],
              "ARK renderer path merges using sidecar + incrementalImpact")
        check(
            production["developerOnboardingGuide"]["first30Minutes"]
            == previous["developerOnboardingGuide"]["first30Minutes"],
            "ARK renderer path preserves unrelated sections without request-level previousDocumentation",
        )
        check("incrementalImpact" not in production and "sectionSources" not in production,
              "renderer strips incremental extras from persisted documentation")

        query = ark_client.build_input(
            url,
            previous_commit=sha1,
            new_commit=sha2,
            previous_documentation=previous,
            impact=impact_modified,
            scoped_dump="INCREMENTAL SCOPE\nFILE: src/util.py\nhelper-v2\n",
        )
        check("incrementalImpact:" in query and "src/util.py" in query,
              "Query input carries compact incrementalImpact")
        check("incrementalDump:" in query and "helper-v2" in query,
              "Query input carries the scoped incremental dump")
        check("FILE: src/unrelated.py" not in query,
              "Query incremental dump does not include unrelated file bodies")
        check("previousDocumentation:" not in query,
              "Query input does not carry previous structured documentation")
        check("updateFields:" in query and "coreConceptsAndArchitecture.summary" in query,
              "Query input carries host-selected updateFields")
        check("previousSections:" in query and "Service uses `src/util.py`" in query,
              "Query input carries previous text only for selected fields")
        check("Open `src/unrelated.py` first." not in query,
              "Query previousSections omits unselected documentation fields")
        fat = dict(impact_modified)
        fat["scopedDump"] = "FILE: src/util.py\nONLY-SCOPED-BODY"
        fat["fullDumpBytes"] = 99999
        stripped = ark_client.build_input(url, previous_commit=sha1, new_commit=sha2, impact=fat)
        check("ONLY-SCOPED-BODY" in stripped, "scopedDump on the impact object is used as incrementalDump")
        check('"scopedDump"' not in stripped.split("incrementalImpact:", 1)[-1],
              "Query incrementalImpact JSON does not embed the dump again")
        check("99999" not in stripped.split("incrementalImpact:", 1)[-1],
              "Query incrementalImpact JSON drops dump size metadata")
        first_only = ark_client.build_input(url, new_commit=sha1)
        check("previousDocumentation:" not in first_only and "incrementalImpact:" not in first_only
              and "incrementalDump:" not in first_only,
              "first/full Query omits previousDocumentation, incrementalImpact, and incrementalDump")

        original_out = ark_client.OUT_DIR
        ark_client.OUT_DIR = out
        try:
            seeded = ark_client.seed_previous_sidecar({
                "repository": url,
                "previousDocumentation": previous,
            })
            impact_file = ark_client.seed_impact_sidecar(
                {"repository": url},
                impact_modified,
            )
        finally:
            ark_client.OUT_DIR = original_out
        check(seeded is not None and seeded.is_file(),
              "host seeds the previous documentation sidecar before the ARK Query")
        check(json.loads(seeded.read_text(encoding="utf-8"))["repositoryStructure"]
              == previous["repositoryStructure"],
              "seeded sidecar is documentation state, not repository source")
        check(impact_file is not None and impact_file.is_file(),
              "host seeds the impact sidecar before the ARK Query")
        check(impact_file.name.endswith(".impact.json"),
              "impact sidecar is not a repository source JSON file")

        with tempfile.TemporaryDirectory() as render_tmp:
            original_output = os.environ.get("OUTPUT_DIR")
            os.environ["OUTPUT_DIR"] = render_tmp
            try:
                Path(render_tmp, "repo.json").write_text(json.dumps(previous), encoding="utf-8")
                Path(render_tmp, "repo.impact.json").write_text(
                    json.dumps(impact_modified), encoding="utf-8"
                )
                sidecar_merge = renderer.resolve_document({
                    "documentation": generated,
                    "repositoryName": "repo",
                    "persist": True,
                })
            finally:
                if original_output is None:
                    os.environ.pop("OUTPUT_DIR", None)
                else:
                    os.environ["OUTPUT_DIR"] = original_output
        check("CHANGED helper" in sidecar_merge["coreConceptsAndArchitecture"]["summary"],
              "ARK renderer path merges using previous sidecar + impact sidecar")
        check(
            sidecar_merge["developerOnboardingGuide"]["first30Minutes"]
            == previous["developerOnboardingGuide"]["first30Minutes"],
            "impact sidecar preserves unrelated sections without Agent incrementalImpact",
        )

        applied = {"count": 0}

        def _block_apply(_name: str, _message: str, **_kwargs) -> None:
            applied["count"] += 1

        def _boom(_plan: dict) -> dict:
            raise RuntimeError("scope down")

        original_apply = ark_client.apply_pipeline_query
        ark_client.apply_pipeline_query = _block_apply
        try:
            blocked = ark_client.run_ark_pipeline(
                {
                    "mode": "incremental",
                    "repository": url,
                    "previousCommit": sha1,
                    "currentCommit": sha2,
                    "previousDocumentation": previous,
                },
                compute_scope=_boom,
            )
        finally:
            ark_client.apply_pipeline_query = original_apply
        check(blocked.get("ok") is False and applied["count"] == 0,
              "failed incremental scope does not apply a Query")

        captured = {"message": "", "count": 0}

        def _capture(_name: str, message: str, **_kwargs) -> None:
            captured["count"] += 1
            captured["message"] = message
            captured["agent"] = _kwargs.get("agent")
            raise RuntimeError("stop before wait")

        def _scoped(_plan: dict) -> dict:
            return {
                "mode": "incremental",
                "changed": [{"path": "src/util.py", "status": "modified", "eligible": True}],
                "affected": [],
                "affectedModules": ["src/util.py"],
                "scopedDump": "INCREMENTAL SCOPE\nFILE: src/util.py\nhelper-v2\n",
                "fullDumpBytes": 50_000,
            }

        def _missing_dump(_plan: dict) -> dict:
            return {
                "mode": "incremental",
                "changed": [{"path": "src/util.py", "status": "modified", "eligible": True}],
            }

        original_apply = ark_client.apply_pipeline_query
        ark_client.apply_pipeline_query = _capture
        try:
            ark_client.run_ark_pipeline(
                {
                    "mode": "incremental",
                    "repository": url,
                    "previousCommit": sha1,
                    "currentCommit": sha2,
                    "previousDocumentation": previous,
                },
                compute_scope=_scoped,
            )
            missing = ark_client.run_ark_pipeline(
                {
                    "mode": "incremental",
                    "repository": url,
                    "previousCommit": sha1,
                    "currentCommit": sha2,
                },
                compute_scope=_missing_dump,
            )
        finally:
            ark_client.apply_pipeline_query = original_apply
        check("incrementalDump:" in captured["message"] and "helper-v2" in captured["message"],
              "incremental Query receives the scoped dump, not a second collect")
        check(captured.get("agent") == ark_client.INCREMENTAL_AGENT,
              "incremental Query is routed to the incremental Agent")
        check("FILE: src/unrelated.py" not in captured["message"],
              "incremental Query does not include unrelated file bodies")
        check('"fullDumpBytes"' not in captured["message"].split("incrementalImpact:", 1)[-1],
              "incremental Query impact JSON does not include full-dump metadata")
        check(missing.get("ok") is False and captured["count"] == 1,
              "incremental scope without scopedDump does not apply a Query")

        def _fake_scope(_plan: dict) -> dict:
            payload = dict(impact_modified)
            payload["scopedDump"] = "INCREMENTAL SCOPE\nFILE: src/util.py\nCHANGED helper\n"
            return payload

        original_apply = ark_client.apply_pipeline_query
        original_wait = ark_client.wait_for_query
        original_out = ark_client.OUT_DIR
        ark_client.OUT_DIR = out
        ark_client.apply_pipeline_query = lambda name, message, **_kwargs: (
            applied.__setitem__("message", message)
            or applied.__setitem__("agent", _kwargs.get("agent"))
            or applied.__setitem__("count", applied["count"] + 1)
        )
        ark_client.wait_for_query = lambda name, **_kw: {
            "status": {"phase": "done", "response": {"content": json.dumps(generated)}}
        }
        html.write_text("<!DOCTYPE html><html><body>first</body></html>", encoding="utf-8")
        (out / "repo.json").write_text(json.dumps(generated), encoding="utf-8")
        try:
            applied["count"] = 0
            scoped = ark_client.run_ark_pipeline(
                {
                    "mode": "incremental",
                    "repository": url,
                    "previousCommit": sha1,
                    "currentCommit": sha2,
                    "previousDocumentation": previous,
                },
                compute_scope=_fake_scope,
            )
        finally:
            ark_client.apply_pipeline_query = original_apply
            ark_client.wait_for_query = original_wait
            ark_client.OUT_DIR = original_out
        check(scoped.get("ok") is True, "successful incremental Query returns ok")
        check((scoped.get("impact") or {}).get("changed") == impact_modified["changed"],
              "successful incremental Query keeps host-computed changes")
        check("updateFields" in (scoped.get("impact") or {}),
              "successful incremental Query impact includes host-selected updateFields")
        check("incrementalImpact:" in str(applied.get("message") or ""),
              "incremental Query input includes host-computed incrementalImpact")
        check("updateFields:" in str(applied.get("message") or ""),
              "incremental Query input includes host-selected updateFields")
        check("previousSections:" in str(applied.get("message") or ""),
              "incremental Query input includes previousSections for selected fields")
        check("previousDocumentation:" not in str(applied.get("message") or ""),
              "incremental Query input omits previousDocumentation")
        check(applied.get("agent") == ark_client.INCREMENTAL_AGENT,
              "incremental Query targets the incremental documentation Agent")

        banner = "=" * 50
        analysis_dump = (
            f"{banner}\nFILE: src/util.py\n{banner}\n\ndef helper():\n    return 2\n\n"
            f"{banner}\nFILE: src/app.py\n{banner}\n\nfrom src.util import helper\n\ndef run():\n    helper()\n\n"
            f"{banner}\nFILE: src/untied.py\n{banner}\n\nVALUE = 1\n"
        )
        delta_rows = ark_client._analysis_source_files(
            analysis_dump,
            {
                "changed": [{"path": "src/util.py", "status": "modified", "eligible": True}],
                "affected": [{"path": "src/app.py", "reasons": ["depends-on:src/util.py"]}],
            },
        )
        delta_paths = [row["path"] for row in delta_rows]
        check("src/util.py" in delta_paths and "src/app.py" in delta_paths,
              "delta analysis includes changed files and affected dependents")
        check("src/untied.py" not in delta_paths,
              "delta analysis does not include unrelated files")

        posts: list[str] = []
        original_apply = ark_client.apply_pipeline_query
        original_wait = ark_client.wait_for_query
        original_post = ark_client._cluster_post
        original_out = ark_client.OUT_DIR
        ark_client.OUT_DIR = out
        ark_client.apply_pipeline_query = lambda *_a, **_k: None
        ark_client.wait_for_query = lambda *_a, **_k: {
            "status": {"phase": "done", "response": {"content": json.dumps(previous)}}
        }
        ark_client._cluster_post = lambda path, payload, timeout=300: (
            posts.append(path) or analysis_dump
        )
        try:
            seeded_full = ark_client.run_ark_pipeline({
                "mode": "full",
                "repository": url,
                "currentCommit": sha1,
            })
            seeded_posts = list(posts)
            ark_client.wait_for_query = lambda *_a, **_k: {
                "status": {"phase": "error", "response": {"content": "query failed"}}
            }
            posts.clear()
            failed_query = ark_client.run_ark_pipeline({
                "mode": "full",
                "repository": url,
                "currentCommit": sha1,
            })
            failed_posts = list(posts)
            ark_client.wait_for_query = lambda *_a, **_k: {
                "status": {"phase": "done", "response": {"content": json.dumps(previous)}}
            }
            ark_client._cluster_post = lambda *_a, **_k: (_ for _ in ()).throw(
                RuntimeError("seed collect failed")
            )
            seed_fail = ark_client.run_ark_pipeline({
                "mode": "full",
                "repository": url,
                "currentCommit": sha1,
            })
        finally:
            ark_client.apply_pipeline_query = original_apply
            ark_client.wait_for_query = original_wait
            ark_client._cluster_post = original_post
            ark_client.OUT_DIR = original_out
        check(seeded_full.get("ok") is True, "successful full Query persist returns ok")
        check("/collect" in seeded_posts, "successful full persist seeds analysis via host /collect")
        check(isinstance(seeded_full.get("analysis"), dict),
              "successful full persist returns host analysis")
        check(isinstance(seeded_full.get("repositoryMap"), dict),
              "successful full persist returns host repositoryMap")
        check(failed_query.get("ok") is False, "failed Query does not succeed")
        check(not failed_posts, "failed Query does not seed analysis")
        check(seed_fail.get("ok") is True, "sidecar seed failure does not fail a successful full persist")
        check(seed_fail.get("analysis") is None, "failed sidecar seed leaves analysis unset")

        original_out = ark_client.OUT_DIR
        ark_client.OUT_DIR = out
        try:
            sidecar = ark_client.persist_analysis_sidecar(
                {"repository": url},
                {"files": [{"path": "src/util.py"}], "unparsed": [], "references": []},
                {"modules": [{"path": "src/util.py"}], "symbols": [], "relationships": []},
                sha1,
            )
            check(sidecar is not None and sidecar.is_file(),
                  "analysis sidecar is written beside the HTML artifact")
            loaded = ark_client.load_analysis_sidecar({"repository": url}, sha1)
            check(loaded is not None and loaded.get("commitSha") == sha1,
                  "analysis sidecar loads only when commitSha matches previousCommit")
            check(ark_client.load_analysis_sidecar({"repository": url}, sha2) is None,
                  "analysis sidecar is ignored when SHA does not match previousCommit")
            sidecar.write_text("{not-json", encoding="utf-8")
            check(ark_client.load_analysis_sidecar({"repository": url}, sha1) is None,
                  "corrupt analysis sidecar is ignored")
            ark_client.persist_analysis_sidecar(
                {"repository": url},
                {"files": [{"path": "src/util.py"}], "unparsed": [], "references": []},
                {"modules": [{"path": "src/util.py"}], "symbols": [], "relationships": []},
                sha1,
            )
            before_sidecar = json.loads((out / "repo.analysis.json").read_text(encoding="utf-8"))
            sha3 = "c" * 40
            fail_plan = {
                "status": "needs_documentation",
                "mode": "incremental",
                "repository": url,
                "currentCommit": sha3,
                "previousCommit": sha2,
                "previousDocumentation": previous,
                "runPipeline": True,
            }
            failed_sidecar = ark_client.execute_documentation_plan(
                fail_plan,
                run_pipeline=lambda _plan: {
                    "ok": False,
                    "error": "forced sidecar failure",
                    "analysis": {"files": [{"path": "src/new.py"}]},
                    "repositoryMap": {"modules": []},
                },
                registry_path=path,
            )
            after_sidecar = json.loads((out / "repo.analysis.json").read_text(encoding="utf-8"))
            check(failed_sidecar["status"] == "failed", "failed incremental run is reported as failed")
            check(after_sidecar == before_sidecar,
                  "failed incremental run does not rewrite the analysis sidecar")
            check(registry.lookup(url, path)["commitSha"] == sha2,
                  "failed incremental run does not advance the documented SHA")
        finally:
            ark_client.OUT_DIR = original_out


def test_incremental_context_optimization() -> None:
    print("\nincremental context optimization")
    if not _git_ok():
        print("  skip  git is not available on PATH")
        return

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "scope-repo"
        root.mkdir()
        shas = build_change_fixture(root)
        full = collector.collect(str(root))
        check("FILE: stay.txt" in full and "unchanged" in full, "full dump includes the unchanged file")
        check("FILE: keep.txt" in full and "version-two" in full, "full dump includes the modified file")
        check("FILE: added.txt" in full, "full dump includes the added file")
        check("FILE: new_name.txt" in full, "full dump includes the renamed file")
        check("FILE: gone.txt" not in full, "full dump omits the deleted file body")

        import changes  # noqa: E402

        detected = changes.detect_changes(
            str(root),
            previous_commit=shas["previous"],
            new_commit=shas["current"],
        )
        scoped = collector.scope_dump(full, detected)
        check("INCREMENTAL SCOPE" in scoped, "scoped dump is marked incremental")
        check("INCREMENTAL DUMP" in scoped, "scoped dump uses an incremental identity header")
        check("REPOSITORY STRUCTURE" not in scoped, "scoped dump omits the full repository tree")
        included = re.search(r"FILES INCLUDED: (\d+)", scoped)
        bodies = re.search(r"BODIES INCLUDED: (\d+)", scoped)
        real_bodies = [
            path for path, body in collector.dump_files(scoped)
            if "no current body" not in body
        ]
        check(
            included is not None and bodies is not None
            and int(included.group(1)) == int(bodies.group(1)) == len(real_bodies),
            "scoped dump FILES INCLUDED matches attached file bodies",
        )
        check("FILE: keep.txt" in scoped and "version-two" in scoped, "scoped dump includes modified file body")
        check("FILE: added.txt" in scoped and "new-file" in scoped, "scoped dump includes added file body")
        check("FILE: new_name.txt" in scoped, "scoped dump includes renamed file body")
        check("gone.txt" in scoped, "scoped dump records the deleted path")
        check("FILE: stay.txt" not in scoped, "scoped dump omits the unchanged file body")
        check("unchanged" not in scoped, "unchanged file contents do not reach the incremental dump")
        check("stay.txt" not in {path for path, _body in collector.dump_files(scoped)},
              "unchanged files are not FILE bodies in the incremental dump")
        check(collector.scope_dump(full, detected) == scoped, "scoped dump is deterministic")

        modify_only = {
            "mode": "incremental",
            "changed": [{"path": "keep.txt", "status": "modified", "eligible": True}],
            "affected": [],
            "affectedModules": ["keep.txt"],
        }
        tiny = collector.scope_dump(full, modify_only)
        check("FILE: keep.txt" in tiny and "version-two" in tiny, "modified-only scope includes that file")
        check("FILE: added.txt" not in tiny and "FILE: new_name.txt" not in tiny,
              "modified-only scope omits other changed files")
        check("FILE: stay.txt" not in tiny, "modified-only scope omits unrelated files")

        _validation, ark_client, _registry = _host_modules()
        sha1 = "a" * 40
        sha2 = "b" * 40
        query = ark_client.build_input(
            "https://github.com/owner/repo",
            previous_commit=sha1,
            new_commit=sha2,
            impact=detected,
            scoped_dump=scoped,
        )
        check("incrementalDump:" in query, "incremental Query carries incrementalDump")
        check("updateFields:" in query, "incremental Query carries host-selected updateFields")
        check("version-two" in query and "new-file" in query, "incremental Query includes changed file contents")
        check("unchanged" not in query, "incremental Query does not include unrelated file contents")
        padded = "UNRELATED-BODY-" + ("x" * 80_000)
        huge = full.replace("unchanged", padded, 1)
        check(padded in huge, "synthetic full dump contains a large unrelated body")
        scoped_huge = collector.scope_dump(huge, modify_only)
        check(padded not in scoped_huge, "large unrelated bodies are dropped from the incremental dump")
        check(len(scoped_huge) < len(huge) // 4,
              "incremental dump stays far smaller than a padded full dump")

        with_diffs = changes.detect_changes(
            str(root),
            previous_commit=shas["previous"],
            new_commit=shas["current"],
            include_diffs=True,
        )
        check(with_diffs.get("diffs"), "includeDiffs attaches git patches")
        keep_patch = next(row for row in with_diffs["diffs"] if row["path"] == "keep.txt")
        check("version-two" in keep_patch["patch"] or "+version-two" in keep_patch["patch"],
              "modified-file git diff carries the new content")
        default_changes = changes.detect_changes(
            str(root),
            previous_commit=shas["previous"],
            new_commit=shas["current"],
        )
        check("diffs" not in default_changes, "default /changes omits git patches")
        check("version-two" not in json.dumps(default_changes),
              "default change JSON still omits file contents")
        dumped = collector.append_diffs(scoped, with_diffs["diffs"])
        check("GIT DIFFS" in dumped and "DIFF: keep.txt" in dumped,
              "incremental dump attaches DIFF headers instead of reflectPhrases")
        check("FILE: keep.txt" in dumped, "scoped FILE bodies remain alongside diffs")

        partial = collector.collect_into(str(root), paths=["keep.txt"])
        included = [entry.path for entry in partial.entries if entry.included]
        check("keep.txt" in included, "path-filtered collect includes the requested file")
        check("stay.txt" not in included, "path-filtered collect omits unrelated files")

        huge_dump = "INCREMENTAL DUMP\nFILE: src/big.py\n" + ("x" * 280_000)
        huge_message = ark_client.build_input(
            "https://github.com/owner/repo",
            previous_commit=sha1,
            new_commit=sha2,
            impact=modify_only,
            scoped_dump=huge_dump,
        )
        check(len(huge_message.encode("utf-8")) > 262144,
              "incremental Query input exceeds the kubectl apply annotation limit")
        captured: list[list[str]] = []
        written: list[dict] = []

        def fake_kubectl(args: list[str]):
            captured.append(list(args))
            path = args[args.index("-f") + 1]
            written.append(json.loads(Path(path).read_text(encoding="utf-8")))
            return subprocess.CompletedProcess(args, 0, stdout="query/ui-large-input created\n", stderr="")

        original_kubectl = ark_client._kubectl
        ark_client._kubectl = fake_kubectl
        try:
            ark_client.apply_pipeline_query("ui-large-input-test", huge_message)
        finally:
            ark_client._kubectl = original_kubectl
        check(
            captured and captured[0][:3] == ["kubectl", "create", "-f"],
            "large Query is submitted with kubectl create, not apply",
        )
        body = written[0]
        manifest = json.dumps(body, ensure_ascii=False)
        check("last-applied-configuration" not in json.dumps(body.get("metadata") or {}),
              "Query manifest does not carry a last-applied annotation")
        check(len(manifest.encode("utf-8")) > 262144,
              "Query JSON is large enough that apply's last-applied annotation would be rejected")
        check((body.get("spec") or {}).get("input") == huge_message,
              "large incrementalDump still travels in spec.input")


def test_webhook_automation() -> None:
    print("\nwebhook automation")
    _validation, ark_client, registry = _host_modules()
    import webhook  # noqa: E402

    webhook.reset_triggers()
    src = Path(webhook.__file__).read_text(encoding="utf-8")
    check(webhook.webhook_enabled(), "webhook listener is enabled by default")
    previous_enabled = os.environ.get("WEBHOOK_ENABLED")
    os.environ["WEBHOOK_ENABLED"] = "false"
    try:
        check(not webhook.webhook_enabled() and webhook.ensure_started() is None,
              "WEBHOOK_ENABLED=false keeps the listener off")
    finally:
        if previous_enabled is None:
            os.environ.pop("WEBHOOK_ENABLED", None)
        else:
            os.environ["WEBHOOK_ENABLED"] = previous_enabled
    check("collect_into" not in src and "clone_remote" not in src,
          "webhook handler does not clone repositories")
    check("analyze_impact" not in src and "merge_documentation" not in src,
          "webhook handler does not run analysis or documentation merge")
    check("kafka" not in src.lower() and "celery" not in src.lower() and "redis" not in src.lower(),
          "webhook does not introduce a message broker")

    before = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    after = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    github = {
        "ref": "refs/heads/main",
        "before": before,
        "after": after,
        "repository": {"clone_url": "https://github.com/owner/repo.git"},
    }
    event = webhook.parse_push_event({"X-GitHub-Event": "push"}, github)
    check(event["repository"] == "https://github.com/owner/repo.git", "GitHub push identifies the clone URL")
    check(event["before"] == before and event["after"] == after, "GitHub push extracts before and after")
    check(event["provider"] == "github", "GitHub push is identified as github")

    gitlab = {
        "ref": "refs/heads/main",
        "before": before,
        "after": after,
        "project": {"http_url": "https://gitlab.com/group/project"},
    }
    gl_event = webhook.parse_push_event({"X-Gitlab-Event": "Push Hook"}, gitlab)
    check(gl_event["repository"] == "https://gitlab.com/group/project", "GitLab push identifies the project URL")
    check(gl_event["before"] == before and gl_event["after"] == after, "GitLab push extracts before and after")

    try:
        webhook.parse_push_event({"X-GitHub-Event": "issues"}, github)
        check(False, "non-push GitHub events are rejected")
    except webhook.WebhookError as exc:
        check(exc.status == 400 and "unsupported" in str(exc).lower(), "invalid GitHub event is a 400")
    try:
        webhook.parse_push_event({"X-GitHub-Event": "push"}, {"after": after})
        check(False, "push without a repository is rejected")
    except webhook.WebhookError:
        check(True, "push without a repository is rejected")
    try:
        webhook.parse_push_event(
            {"X-GitHub-Event": "push"},
            {"after": webhook.ZERO_SHA, "repository": {"clone_url": "https://github.com/owner/repo.git"}},
        )
        check(False, "deleted-branch after SHA is rejected")
    except webhook.WebhookError:
        check(True, "deleted-branch after SHA is rejected")

    docs = _sample_docs(util="src/util.py", unrelated="src/unrelated.py")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "documentation-registry.json"
        url = "https://github.com/owner/repo.git"
        registry.record_success(url, before, artifact="repo.html", documentation=docs, path=path)
        called: dict = {}

        def run_pipeline(plan: dict) -> dict:
            called["plan"] = dict(plan)
            return {
                "ok": True,
                "artifact": "repo.html",
                "documentation": docs,
                "impact": {
                    "mode": "incremental",
                    "changed": [{"path": "src/util.py", "status": "modified", "eligible": True}],
                    "affected": [],
                    "affectedModules": ["src/util.py"],
                },
            }

        accepted = webhook.process_webhook(
            {"X-GitHub-Event": "push"},
            json.dumps(github).encode("utf-8"),
            run_pipeline=run_pipeline,
            registry_path=str(path),
            join=True,
        )
        check(accepted["accepted"] is True, "valid push event is accepted")
        check(accepted["repository"] == url, "accepted payload identifies the repository")
        check(accepted["before"] == before and accepted["after"] == after,
              "accepted payload propagates before and after")
        check(called["plan"]["currentCommit"] == after, "webhook plan uses the after SHA as newCommit")
        check(called["plan"]["previousCommit"] == before, "webhook plan uses the registry SHA as previousCommit")
        check(called["plan"]["mode"] == "incremental", "webhook triggers the incremental documentation plan")
        check(called["plan"].get("previousDocumentation") == docs,
              "webhook incremental plan includes the last successful documentation")
        check(registry.lookup(url, path)["commitSha"] == after,
              "background incremental workflow persists the after SHA")
        www_event = webhook.parse_push_event(
            {"X-GitHub-Event": "push"},
            {
                "ref": "refs/heads/main",
                "before": before,
                "after": after,
                "repository": {"clone_url": "https://www.github.com/owner/repo.git"},
            },
        )
        check(www_event["repository"] == "https://github.com/owner/repo.git",
              "webhook www.github.com clone URL matches the documented repository")
        check(registry.lookup(www_event["repository"], path)["commitSha"] == after,
              "webhook www.github.com event finds the existing registry record")

        called.clear()
        same = webhook.process_webhook(
            {"X-GitHub-Event": "push"},
            json.dumps(github).encode("utf-8"),
            run_pipeline=run_pipeline,
            registry_path=str(path),
            join=True,
        )
        check(same["accepted"] is True, "same SHA push is still accepted as a trigger")
        check("plan" not in called, "same SHA does not run the documentation pipeline")
        check(webhook.recent_triggers()[-1]["result"] == "already_documented",
              "same SHA webhook result is already_documented")

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), webhook.Handler)
        webhook.Handler.run_pipeline = run_pipeline
        webhook.Handler.registry_path = str(path)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            port = httpd.server_address[1]
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/webhook",
                data=json.dumps(github).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-GitHub-Event": "push"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                check(response.status == 202, "HTTP webhook returns 202")
                payload = json.loads(response.read().decode("utf-8"))
            check(payload["accepted"] is True and payload["after"] == after,
                  "HTTP webhook returns the extracted SHAs")
            bad = urllib.request.Request(
                f"http://127.0.0.1:{port}/webhook",
                data=json.dumps({"action": "opened"}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-GitHub-Event": "issues"},
                method="POST",
            )
            try:
                urllib.request.urlopen(bad, timeout=5)
                check(False, "HTTP webhook rejects invalid events")
            except urllib.error.HTTPError as exc:
                check(exc.code == 400, "HTTP webhook rejects invalid events")
        finally:
            httpd.shutdown()
            httpd.server_close()
            webhook.Handler.run_pipeline = None
            webhook.Handler.registry_path = None
    webhook.reset_triggers()


def test_pipeline_config() -> None:
    pipeline = (ROOT / "agents" / "repository-pipeline.yaml").read_text(encoding="utf-8")
    docs = (ROOT / "agents" / "repository-documentation.yaml").read_text(encoding="utf-8")
    agent_tool = (ROOT / "tools" / "repository-documentation.yaml").read_text(encoding="utf-8")
    renderer_tool = (ROOT / "tools" / "documentation-renderer.yaml").read_text(encoding="utf-8")
    collector_tool = (ROOT / "tools" / "repository-collector.yaml").read_text(encoding="utf-8")

    check("name: repository-pipeline" in pipeline, "pipeline Agent exists")
    check(
        re.search(r"type:\s*agent\s*\n\s*name:\s*repository-documentation", pipeline) is not None,
        "pipeline Agent references the documentation Agent as an Agent Tool",
    )
    check(
        re.search(r"type:\s*http\s*\n\s*name:\s*documentation-renderer", pipeline) is not None,
        "pipeline Agent references the documentation renderer as an HTTP Tool",
    )
    tools_block = pipeline.split("prompt:", 1)[0]
    check("repository-collector" not in tools_block, "pipeline Agent does not call the collector")
    check("documentationJson" not in renderer_tool.split("http:", 1)[-1],
          "renderer HTTP body does not interpolate a documentationJson blob")
    check('printf "%q" .input.documentation.repositoryOverview.summary' in renderer_tool,
          "renderer HTTP body printf-quotes nested documentation fields")
    check("Do not pass `documentationJson`" in pipeline,
          "pipeline Agent does not copy documentation as one JSON string")
    check(
        re.search(r"type:\s*http\s*\n\s*name:\s*repository-collector", docs) is not None,
        "documentation Agent still references the repository-collector",
    )
    check("documentation-renderer" not in docs, "documentation Agent does not call the renderer")
    check("type: agent" in agent_tool and "name: repository-documentation" in agent_tool,
          "Agent-as-Tool wrapper exists")
    check("type: http" in renderer_tool, "renderer Tool remains HTTP")
    check("type: http" in collector_tool, "collector Tool remains HTTP")
    check("repository-pipeline" not in docs, "no circular dependency from documentation Agent to pipeline")
    check("repository-pipeline" not in agent_tool, "no circular dependency from Agent-as-Tool wrapper")
    values = (ROOT / "values.yaml").read_text(encoding="utf-8")
    check("hostDocker: true" in values, "renderer publishes on the Windows host")
    check(
        r"windowsPath: C:\Users\moham\source\repos\repository-documentation\out" in values,
        "renderer output bind is the Windows out/ directory",
    )
    ark_client_src = (ROOT / "app" / "ark_client.py").read_text(encoding="utf-8")
    ui_src = (ROOT / "app" / "ui.py").read_text(encoding="utf-8")
    check("validate_pipeline_input" in ark_client_src, "ark_client validates before building Query input")
    check("validate_pipeline_input" in ui_src, "Streamlit validates before applying a Query")
    collector_src = (ROOT / "tools" / "repository-collector" / "collector.py").read_text(encoding="utf-8")
    check("sanitize(" in collector_src, "collector dump is regex-sanitized before it is returned")
    check("sanitize_structured(" in collector_src, "collector dump is structured-field sanitized before regex")
    check("apply_local_llm_detections" in collector_src, "optional Local LLM is a post-pass after deterministic sanitization")
    analyzer_tool = (ROOT / "tools" / "repository-analyzer.yaml").read_text(encoding="utf-8")
    check("type: http" in analyzer_tool, "analyzer Tool is HTTP")
    check("/analyze" in analyzer_tool, "analyzer Tool posts to /analyze")
    check("repository" not in analyzer_tool.split("inputSchema:", 1)[1].split("http:", 1)[0],
          "analyzer Tool does not accept a repository URL")
    check(
        re.search(r"type:\s*http\s*\n\s*name:\s*repository-analyzer", docs) is None,
        "documentation Agent does not call repository-analyzer as a tool",
    )
    check("dump:" not in analyzer_tool.split("inputSchema:", 1)[1].split("http:", 1)[0],
          "analyzer Tool inputSchema does not accept a collector dump")
    check('"dump"' not in analyzer_tool.split("body:", 1)[-1],
          "analyzer Tool HTTP body does not interpolate a collector dump")
    check("repository-analyzer" not in tools_block, "pipeline Agent does not call the analyzer")
    check("repository-map" not in tools_block, "pipeline Agent does not call the repository map")
    check("repository-changes" not in tools_block, "pipeline Agent does not call change detection")
    check("repository-impact" not in tools_block, "pipeline Agent does not call incremental analysis")
    check("Do not call repository-collector, repository-analyzer, repository-map," in pipeline
          and "repository-changes" in pipeline and "repository-impact" in pipeline,
          "pipeline prompt keeps collection, analysis, mapping, changes, and impact off the orchestrator")
    changes_tool = (ROOT / "tools" / "repository-changes.yaml").read_text(encoding="utf-8")
    check("/changes" in changes_tool and "type: http" in changes_tool, "changes Tool posts to /changes")
    changes_src = (ROOT / "tools" / "repository-collector" / "changes.py").read_text(encoding="utf-8")
    check("is_collectable_path" in changes_src, "change detection reuses collector path inclusion rules")
    check("is not an ancestor" in changes_src,
          "change detection rejects a previousCommit that is not an ancestor")
    check('"status": "modified"' in changes_src and "STATUS_BY_CODE.get(code)" in changes_src,
          "unknown git name-status codes are kept as modified")
    check("max_total_bytes" not in changes_src and "DEFAULT_MAX_TOTAL_BYTES" not in changes_src,
          "change detection does not apply the total collection budget")
    check('"209715200"' in collector_tool, "collector Tool default total budget is 200 MiB")
    check("DEFAULT_MAX_TOTAL_BYTES = 200 * 1024 * 1024" in collector_src,
          "collector default total budget is 200 MiB")
    check("open_remote" in collector_src, "collect reuses the same-pipeline workspace")
    check('WORKSPACE_GRACE_SECONDS", "180"' in (ROOT / "tools" / "repository-collector" / "workspace.py").read_text(
        encoding="utf-8"
    ), "workspace grace covers the Agent collect after host scope")
    check("WORKSPACE_GRACE_SECONDS" in (ROOT / "templates" / "repository-collector.yaml").read_text(
        encoding="utf-8"
    ), "collector Deployment sets workspace grace")
    check("pin = current or ref" in ark_client_src and '"ref": pin' in ark_client_src,
          "host /changes and /collect pin the same newCommit workspace key")
    analyzer_src = (ROOT / "tools" / "repository-analyzer" / "analyzer.py").read_text(encoding="utf-8")
    check("excluded_from_dump" in analyzer_src, "analyzer reads excluded-file metadata from the dump")
    check("Excluded files and unwalked directories are unseen" not in docs,
          "documentation Agent does not treat excluded files as missing")
    check("ensure_commit" in changes_src, "change detection fetches a missing previous SHA")
    check((ROOT / "tools" / "repository-collector" / "workspace.py").is_file(),
          "collector workspace helper exists")
    check(
        re.search(r"type:\s*http\s*\n\s*name:\s*repository-changes", docs.split("prompt:", 1)[0]) is None,
        "documentation Agent does not expose repository-changes as a tool",
    )
    check("repository-analyzer" in values, "Helm values configure the analyzer")
    check("component: analyzer" in (ROOT / "templates" / "repository-analyzer.yaml").read_text(encoding="utf-8"),
          "analyzer Deployment/Service template exists")
    map_tool = (ROOT / "tools" / "repository-map.yaml").read_text(encoding="utf-8")
    check("type: http" in map_tool and "/map" in map_tool, "map Tool posts to /map")
    map_schema = map_tool.split("inputSchema:", 1)[1].split("http:", 1)[0]
    check("analysisJson:" in map_schema and "repository:" not in map_schema,
          "map Tool does not accept a repository URL")
    check(
        re.search(r"type:\s*http\s*\n\s*name:\s*repository-map", docs) is None,
        "documentation Agent does not call repository-map as a tool",
    )
    check("repository-map" in values, "Helm values configure the repository map")
    check("component: mapper" in (ROOT / "templates" / "repository-map.yaml").read_text(encoding="utf-8"),
          "map Deployment/Service template exists")
    registry_src = (ROOT / "app" / "documentation_registry.py").read_text(encoding="utf-8")
    check("documentation-registry.json" in registry_src, "documented SHA is stored in a JSON registry")
    check("read_text" not in registry_src or "out/" not in registry_src,
          "registry does not treat generated HTML as the source of truth")
    check("session_state" not in registry_src and "session_state" not in ark_client_src,
          "documented SHA is not stored only in Streamlit memory")
    check("already_documented" in ark_client_src, "ark_client returns already_documented for the same SHA")
    check("plan_documentation" in ui_src and "execute_documentation_plan" in ui_src,
          "Streamlit consults the registry before applying a Query")
    check("previousCommit" in pipeline and "newCommit" in pipeline,
          "pipeline Agent forwards supplied previousCommit and newCommit")
    check("Do not invent, infer, or look up commit SHAs" in pipeline,
          "pipeline Agent does not invent commit SHAs")
    check("previousCommit" in docs and "newCommit" in docs,
          "documentation Agent consumes Query previousCommit and newCommit")
    check("pass that exact SHA as" in docs and "collector `ref`" in docs,
          "documentation Agent pins collector ref to newCommit")
    check("first/full generation only" in docs or "This agent is first/full generation only" in docs,
          "full documentation Agent is full generation only")
    check("incrementalDump" not in docs,
          "full documentation Agent prompt does not own incrementalDump")
    check("UNCHANGED: out of incremental scope." not in docs,
          "full documentation Agent does not use UNCHANGED placeholders")
    incremental_docs = (ROOT / "agents" / "repository-documentation-incremental.yaml").read_text(encoding="utf-8")
    check("name: repository-documentation-incremental" in incremental_docs,
          "incremental documentation Agent exists")
    check("tools:" not in incremental_docs.split("spec:", 1)[-1].split("outputSchema:", 1)[0],
          "incremental documentation Agent has no collector/analyzer/map tools")
    check("updates:" in incremental_docs and "enum:" in incremental_docs,
          "incremental Agent uses a patch updates outputSchema")
    for key in (
        "repositoryOverview.summary",
        "developerOnboardingGuide.commonMistakes",
        "categorizedTechnicalInformation.tests",
    ):
        check(key in incremental_docs, f"incremental Agent enum includes {key}")
    check("GIT DIFFS" in incremental_docs or "DIFF:" in incremental_docs,
          "incremental Agent consumes git diffs instead of reflectPhrases")
    check("Always still collect" not in docs,
          "incremental runs are not instructed to collect the full repository")
    check("parse_ls_remote" in ark_client_src, "ls-remote prefers the peeled annotated-tag commit")
    check("current_commit_bodies" in collector_src,
          "collector exposes current-commit bodies without stale excluded content")
    check("checkout_commit" in (ROOT / "tools" / "repository-collector" / "workspace.py").read_text(
        encoding="utf-8"
    ), "workspace checks out the requested newCommit")
    check("tag: m17" in values, "collector image tag is m17")
    check("EXCLUDED_SOURCE_SUFFIXES" in collector_src and '".json"' in collector_src,
          "JSON exclusion is a single collector eligibility rule")
    check("tag: m4" in values, "analyzer image tag is m4")
    check("tag: m4" in values, "map image tag is m4")
    check("tag: m9" in values, "renderer image tag is m9")
    check("previousDocumentation" in pipeline,
          "pipeline Agent forwards supplied previousDocumentation")
    check("incrementalImpact" in pipeline,
          "pipeline Agent forwards supplied incrementalImpact")
    check("computed outside this" in pipeline,
          "pipeline Agent does not own deterministic change/impact computation")
    check("incrementalDump" in pipeline,
          "pipeline Agent forwards supplied incrementalDump")
    check("updateFields" in pipeline and "previousSections" in pipeline,
          "pipeline Agent forwards host-selected incremental fields")
    check("incrementalImpact" in incremental_docs and "Do not call `repository-changes`" in docs,
          "incremental Agent consumes impact; full Agent does not call change tools")
    check("compute_incremental_scope" in ark_client_src and "SCOPE_SCRIPT" in ark_client_src,
          "host computes incremental scope outside the LLM Agent")
    check("_cluster_post" in ark_client_src and '"/changes"' in ark_client_src
          and '"/collect"' in ark_client_src,
          "host scope posts /changes and /collect into the collector pod")
    check("def _seed_full_analysis" in ark_client_src,
          "host seeds analysis/map after successful full generation")
    check("splice_analysis" in ark_client_src and "load_analysis_sidecar" in ark_client_src,
          "host splices analysis from a SHA-tied sidecar when the SHA matches")
    check("_analysis_source_files" in ark_client_src,
          "incremental analysis covers changed union affected files")
    check("_idle_same_url" in (ROOT / "tools" / "repository-collector" / "workspace.py").read_text(
        encoding="utf-8"
    ), "collector reuses an idle workspace for the same repository URL")
    check("commitSha" in ark_client_src and "previousCommit" in ark_client_src,
          "analysis sidecar is rejected unless commitSha equals previousCommit")
    check("append_diffs" in ark_client_src or "includeDiffs" in ark_client_src,
          "incremental dump uses git diffs instead of reflectPhrases")
    check("INCREMENTAL_AGENT" in ark_client_src,
          "host routes incremental Queries to the incremental Agent")
    check('result["scopedDump"]' in ark_client_src and "scope_dump" in ark_client_src,
          "host returns a scoped dump for the incremental Agent")
    check("print(dump" not in ark_client_src,
          "host does not send the full dump through the LLM")
    check("incrementalDump" in ark_client_src and "scoped_dump" in ark_client_src,
          "host Query input carries incrementalDump instead of a second collect")
    check("updateFields" in ark_client_src and "previousSections" in ark_client_src,
          "host Query input carries selected fields instead of the full previous document")
    check("prepare_incremental_impact" in ark_client_src,
          "host attaches updateFields before the documentation Query")
    check("INCREMENTAL DUMP" in collector_src,
          "scoped dumps use an incremental header instead of the full-tree preamble")
    check("def _cluster_python" in ark_client_src and "kubectl" in ark_client_src
          and "exec" in ark_client_src,
          "incremental scope runs via kubectl exec into the collector")
    check("seed_impact_sidecar" in ark_client_src,
          "host writes an impact sidecar for the renderer merge")
    check("DOCS_AGENT" in ark_client_src and "persist_generated" in ark_client_src,
          "host Query is the documentation Agent; renderer persist is local")
    check('["kubectl", "create", "-f"' in ark_client_src,
          "host creates Query objects instead of kubectl apply")
    check('["kubectl", "apply", "-f"' not in ark_client_src,
          "host does not kubectl apply Query objects")
    merge_src = (ROOT / "tools" / "documentation-renderer" / "merge.py").read_text(encoding="utf-8")
    check("def ensure_route_coverage" in merge_src and "def extract_http_routes" in merge_src,
          "merge backfills dump-grounded HTTP routes after generation")
    check("def ensure_readme_coverage" in merge_src,
          "merge preserves new README lines from FILE/DIFF bodies")
    check("reflectPhrases" not in ark_client_src and "reflect_phrases" not in merge_src,
          "reflectPhrases is not used for modified-file content")
    check("dump=dump_text" in ark_client_src and "dump=scoped_dump" in ark_client_src,
          "host persist passes the collector dump into merge")
    check("def _merge_persisted" in ark_client_src,
          "host persist wraps merge_documentation dump compatibility")
    check("spec_from_file_location" in ark_client_src and '_load_renderer_file("merge", "merge.py")' in ark_client_src,
          "host persist execs documentation-renderer/merge.py from disk")
    check("importlib.reload(ark_client)" in ui_src,
          "Streamlit reloads ark_client so persist is not a pre-dump cached import")
    check("quote the new README lines" in incremental_docs,
          "incremental Agent is told to quote new README lines")
    check("Do not pass the collector dump to any other tool" in docs,
          "full Agent must not re-send the dump as another tool argument")
    check("incrementalImpact" not in docs.split("outputSchema:", 1)[-1].split("prompt:", 1)[0],
          "documentation Agent outputSchema stays the six documentation fields")
    check((ROOT / "app" / "webhook.py").is_file(), "webhook trigger module exists")
    check("ensure_started" in (ROOT / "app" / "ui.py").read_text(encoding="utf-8"),
          "Streamlit can start the in-process webhook listener")
    check('os.environ.get("WEBHOOK_ENABLED", "true")' in (ROOT / "app" / "webhook.py").read_text(
        encoding="utf-8"
    ), "webhook listener defaults on when Streamlit starts")
    check("run_ark_pipeline" in ark_client_src and "run_ark_pipeline" in (ROOT / "app" / "webhook.py").read_text(
        encoding="utf-8"
    ), "webhook reuses the existing ARK Query pipeline")
    impact_tool = (ROOT / "tools" / "repository-impact.yaml").read_text(encoding="utf-8")
    check("/impact" in impact_tool and "type: http" in impact_tool, "impact Tool posts to /impact")
    check("repository:" not in impact_tool.split("inputSchema:", 1)[1].split("http:", 1)[0],
          "impact Tool does not accept a repository URL")
    check(
        re.search(r"type:\s*http\s*\n\s*name:\s*repository-impact", docs.split("prompt:", 1)[0]) is None,
        "documentation Agent does not expose repository-impact as a tool",
    )
    check("state/" in (ROOT / ".gitignore").read_text(encoding="utf-8"),
          "documentation registry directory is gitignored")


_DUMP_FILE_HEADER = re.compile(r"(?m)^FILE: (.+)$")


def _assert_live_sensitive_protection(
    *,
    dump: str,
    html: str = "",
    documentation: dict | None = None,
    analysis: dict | None = None,
    forbidden: list[str] | None = None,
) -> None:
    """Live collector dump, HTML, and docs must keep secrets/JSON out."""
    check("FILE:" in (dump or ""), "live collector dump includes FILE bodies")
    headers = _DUMP_FILE_HEADER.findall(dump or "")
    json_files = [path for path in headers if path.lower().endswith(".json")]
    check(not json_files, "live collector dump excludes JSON FILE bodies")
    env_files = [
        path for path in headers
        if path.replace("\\", "/").rsplit("/", 1)[-1] == ".env"
    ]
    check(not env_files, "live collector dump excludes .env FILE bodies")
    blob = "\n".join(
        [
            dump or "",
            html or "",
            json.dumps(documentation or {}, ensure_ascii=False),
            json.dumps(analysis or {}, ensure_ascii=False),
        ]
    )
    for item in forbidden or []:
        check(item not in blob, "live dump/docs/HTML omit injected secret material")
    files = analysis.get("files") if isinstance(analysis, dict) else None
    if isinstance(files, list):
        json_src = [
            str(row.get("path") or "")
            for row in files
            if isinstance(row, dict) and str(row.get("path") or "").lower().endswith(".json")
        ]
        check(not json_src, "live analysis does not use JSON files as source")


def renderer_artifact(filename: str) -> str | None:
    host = ROOT / "out" / filename
    if host.is_file():
        return host.read_text(encoding="utf-8")
    print(f"        could not read artifact: {host} is missing")
    return None


def _verify_existing_repo_recognition(ark_client, repository: str, result: dict, reg: Path) -> None:
    """Same URL, www alias, webhook, same SHA, and failed update against a live first-run SHA."""
    import webhook  # noqa: E402

    sha = str(result.get("currentCommit") or "")
    other = "ffffffffffffffffffffffffffffffffffffffff"
    same = ark_client.plan_documentation(repository, current_sha=sha, registry_path=reg)
    check(same["status"] == "already_documented" and same.get("runPipeline") is False,
          "e2e same repository + same SHA returns already_documented")
    www = ark_client.plan_documentation(
        "https://www.github.com/MooAyman/github-mcp-chatbot",
        current_sha=sha,
        registry_path=reg,
    )
    check(www["status"] == "already_documented",
          "e2e www.github.com is recognized as the existing repository")
    changed = ark_client.plan_documentation(repository, current_sha=other, registry_path=reg)
    check(changed["status"] == "needs_documentation" and changed["mode"] == "incremental",
          "e2e a new SHA plans incremental generation, not a first/full run")
    failed = ark_client.execute_documentation_plan(
        changed,
        run_pipeline=lambda _plan: {"ok": False, "error": "forced incremental failure"},
        registry_path=reg,
    )
    check(failed["status"] == "failed", "e2e failed incremental update is reported as failed")
    check(ark_client.documented_commit(repository, registry_path=reg) == sha,
          "e2e failed incremental update preserves the previous documented SHA")
    webhook.reset_triggers()
    accepted = webhook.process_webhook(
        {"X-GitHub-Event": "push"},
        json.dumps({
            "ref": "refs/heads/main",
            "before": sha,
            "after": other,
            "repository": {"clone_url": repository + ".git"},
        }).encode("utf-8"),
        run_pipeline=lambda plan: {
            "ok": True,
            "artifact": result.get("artifact") or "github-mcp-chatbot.html",
            "documentation": plan.get("previousDocumentation") or {},
        },
        registry_path=str(reg),
        join=True,
    )
    check(accepted["accepted"] is True and accepted["after"] == other,
          "e2e webhook accepts a new-commit push")
    check(webhook.recent_triggers()[-1].get("result") == "documented",
          "e2e webhook incremental flow documents the new commit")
    check(ark_client.documented_commit(repository, registry_path=reg) == other,
          "e2e webhook incremental persist updates the documented SHA")
    same_push = webhook.process_webhook(
        {"X-GitHub-Event": "push"},
        json.dumps({
            "ref": "refs/heads/main",
            "before": other,
            "after": other,
            "repository": {"clone_url": repository + ".git"},
        }).encode("utf-8"),
        run_pipeline=lambda _plan: {"ok": True, "artifact": "github-mcp-chatbot.html"},
        registry_path=str(reg),
        join=True,
    )
    check(same_push["accepted"] is True, "e2e same-SHA webhook is accepted")
    check(webhook.recent_triggers()[-1].get("result") == "already_documented",
          "e2e same-SHA webhook returns already_documented")
    webhook.reset_triggers()


def test_pipeline_e2e() -> None:
    """Host documentation Agent Query and local renderer persist. No manual JSON copy."""
    print(f"\nhost documentation query (namespace {NAMESPACE})")
    _validation, ark_client, _registry = _host_modules()
    since_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tmp = tempfile.mkdtemp(prefix="e2e-reg-")
    reg = Path(tmp) / "e2e-registry.json"
    plan = ark_client.plan_documentation(TARGET_REPO, registry_path=reg)
    check(plan["status"] == "first_run" and plan.get("runPipeline") is True,
          "e2e full generation plans a first/full Query")
    result = ark_client.execute_documentation_plan(
        plan,
        run_pipeline=ark_client.run_ark_pipeline,
        registry_path=reg,
    )

    check(result.get("status") == "documented",
          f"host documentation succeeded (status={result.get('status')})")
    if result.get("status") != "documented":
        print(f"  info  error: {result.get('error')}")
        return
    check(result.get("artifact") == "github-mcp-chatbot.html",
          "host persist names the HTML artifact")

    html = renderer_artifact("github-mcp-chatbot.html")
    check(html is not None, "HTML artifact exists on the renderer volume")
    if not html:
        return
    check(html.lstrip().startswith("<!DOCTYPE html>"), "artifact is a standalone HTML document")
    check("backend/agent/agent.py" in html, "host HTML cites backend/agent/agent.py")
    check(re.search(r"POST\s+/chat", html, re.I) is not None, "host HTML mentions POST /chat")
    check(re.search(r"GET\s+/health", html, re.I) is not None, "host HTML mentions GET /health")
    if re.search(r"ChatRequest|ChatResponse|Pydantic", html):
        check(True, "host HTML mentions a grounded schema/DTO name")
    else:
        print("  info  host HTML omitted ChatRequest/ChatResponse/Pydantic (soft model wording)")
    check(re.search(r"OpenAI", html, re.I) is not None, "host HTML mentions OpenAI")
    check(re.search(r"Gemini", html, re.I) is not None, "host HTML mentions Gemini")
    check(re.search(r"GitHub MCP|github.?mcp|MCP", html) is not None, "host HTML mentions GitHub MCP")

    collects = collector_collect_count(since_time)
    analysis = result.get("analysis") if isinstance(result.get("analysis"), dict) else None
    check(
        analysis is not None and isinstance(analysis.get("files"), list),
        "successful full generation returns host-seeded analysis",
    )
    print(f"  info  full-gen POST /collect count={collects}")
    if collects is None:
        check(False, "collector logs are readable after the host Query")
    elif collects >= 2:
        check(True, "full host generation caused Agent collect plus sidecar seed")
    else:
        check(
            analysis is not None,
            f"full host generation seeded analysis (since={since_time}, collect log count={collects})",
        )

    check(HTML_OUTPUT.is_file(), f"HTML artifact exists on the Windows host ({HTML_OUTPUT})")
    if HTML_OUTPUT.is_file():
        host_html = HTML_OUTPUT.read_text(encoding="utf-8")
        check(host_html.lstrip().startswith("<!DOCTYPE html>"), "host HTML is a standalone document")
        check("backend/agent/agent.py" in host_html, "host HTML cites backend/agent/agent.py")
    print(f"  info  host persist wrote {len(html)} bytes to {HTML_OUTPUT}")
    print(f"  info  documented SHA {result.get('currentCommit')}")
    sidecar_data = ark_client.load_analysis_sidecar({"repository": TARGET_REPO}, str(result.get("currentCommit") or ""))
    check(
        sidecar_data is not None and sidecar_data.get("commitSha") == result.get("currentCommit"),
        "full generation persisted analysis sidecar at currentCommit",
    )
    print(f"  info  sidecar SHA {None if sidecar_data is None else sidecar_data.get('commitSha')}")
    print(f"  info  full tokenUsage={result.get('tokenUsage')} queryDurationMs={result.get('queryDurationMs')}")
    live_dump = ark_client._cluster_post(
        "/collect",
        {"repository": TARGET_REPO, "ref": str(result.get("currentCommit") or "")},
    )
    _assert_live_sensitive_protection(
        dump=live_dump,
        html=html or "",
        documentation=result.get("documentation") if isinstance(result.get("documentation"), dict) else None,
        analysis=analysis,
    )
    _run_incremental_e2e(ark_client, reg, result)
    latest = ark_client.documented_commit(TARGET_REPO, registry_path=reg) or result.get("currentCommit")
    if result.get("status") == "documented" and latest:
        _verify_existing_repo_recognition(
            ark_client,
            TARGET_REPO,
            {**result, "currentCommit": latest},
            reg,
        )


def _run_incremental_e2e(ark_client, registry_path: Path, full_result: dict) -> None:
    """Throwaway-branch incremental generation. Does not rewrite main."""
    print("\nhost incremental query")
    previous = str(full_result.get("currentCommit") or "")
    if not previous:
        check(False, "incremental e2e needs a documented SHA from full generation")
        return
    stamp = time.strftime("%Y%m%d%H%M%S")
    branch = f"docs-inc-e2e-{stamp}"
    probe = f"E2E-INC-PROBE {stamp}: scoped documentation must mention this sentence."
    added = "docs_e2e_added.py"
    clone = None
    original_out = ark_client.OUT_DIR
    git_env = dict(os.environ)
    git_env["GIT_AUTHOR_NAME"] = "docs-e2e"
    git_env["GIT_AUTHOR_EMAIL"] = "docs-e2e@example.com"
    git_env["GIT_COMMITTER_NAME"] = git_env["GIT_AUTHOR_NAME"]
    git_env["GIT_COMMITTER_EMAIL"] = git_env["GIT_AUTHOR_EMAIL"]
    try:
        clone = Path(tempfile.mkdtemp(prefix="inc-e2e-"))
        subprocess.run(
            ["git", "clone", TARGET_REPO, str(clone)],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        subprocess.run(
            ["git", "checkout", "-B", branch, previous],
            cwd=str(clone),
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        readme = clone / "README.md"
        readme.write_text(readme.read_text(encoding="utf-8") + f"\n{probe}\n", encoding="utf-8")
        (clone / added).write_text('"""Incremental e2e added module."""\nVALUE = 1\n', encoding="utf-8")
        github_pat = "ghp_" + ("A" * 36)
        json_leak = f"E2E_JSON_ZX9Q_LEAK_{stamp}"
        env_leak = f"E2E_ENV_ZX9Q_LEAK_{stamp}"
        (clone / "docs_e2e_secret.py").write_text(f'TOKEN = "{github_pat}"\n', encoding="utf-8")
        (clone / "docs_e2e_secret.json").write_text(json.dumps({"token": json_leak}) + "\n", encoding="utf-8")
        (clone / ".env").write_text(f"SECRET={env_leak}\n", encoding="utf-8")
        rename_src = None
        for candidate in (clone / "backend").rglob("*.py"):
            rel = candidate.relative_to(clone).as_posix()
            if rel.endswith("main.py") or rel.endswith("agent.py"):
                continue
            rename_src = rel
            break
        delete_rel = None
        for candidate in clone.rglob("*.md"):
            rel = candidate.relative_to(clone).as_posix()
            if rel.lower() in {"readme.md", "license.md"}:
                continue
            delete_rel = rel
            break
        if rename_src:
            dest = str(Path(rename_src).with_name(Path(rename_src).stem + "_e2e_renamed.py")).replace("\\", "/")
            subprocess.run(["git", "mv", rename_src, dest], cwd=str(clone), check=True, capture_output=True, text=True)
            rename_dst = dest
        else:
            rename_dst = None
        if delete_rel:
            subprocess.run(["git", "rm", "-f", delete_rel], cwd=str(clone), check=True, capture_output=True, text=True)
        subprocess.run(["git", "add", "-A"], cwd=str(clone), check=True, capture_output=True, text=True)
        subprocess.run(
            ["git", "add", "-f", ".env", "docs_e2e_secret.json", "docs_e2e_secret.py"],
            cwd=str(clone),
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["git", "commit", "-m", f"docs e2e incremental {stamp}"],
            cwd=str(clone),
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=git_env,
        )
        current = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(clone),
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        ).stdout.strip()
        subprocess.run(
            ["git", "push", "-u", "origin", branch],
            cwd=str(clone),
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        plan = ark_client.plan_documentation(TARGET_REPO, current_sha=current, registry_path=registry_path)
        check(plan["mode"] == "incremental" and plan["previousCommit"] == previous,
              "incremental e2e plans incremental generation from the full-run SHA")
        started = time.monotonic()
        result = ark_client.execute_documentation_plan(
            plan,
            run_pipeline=ark_client.run_ark_pipeline,
            registry_path=registry_path,
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
        check(result.get("status") == "documented" and result.get("currentCommit") == current,
              f"incremental e2e documented the throwaway commit (status={result.get('status')})")
        if result.get("status") != "documented":
            print(f"  info  incremental error: {result.get('error')}")
            return
        meta = result.get("scopeMeta") or {}
        check(meta.get("usedSidecar") is True and meta.get("collectMode") == "paths",
              "first incremental run uses the full-generation sidecar")
        print(f"  info  first-incremental usedSidecar={meta.get('usedSidecar')} collectMode={meta.get('collectMode')}")
        docs = result.get("documentation") or {}
        blob = json.dumps(docs)
        check(added.replace(".py", "") in blob or added in blob or f"`{added}` was added." in blob,
              "incremental e2e mentions the added file")
        if rename_dst:
            check(rename_dst in blob or Path(rename_dst).name in blob,
                  "incremental e2e mentions the renamed path")
            check(rename_src not in blob or f"{rename_src} (removed)" in blob or rename_dst in blob,
                  "incremental e2e does not keep the old rename path as current-only")
        if delete_rel:
            check(delete_rel not in blob or f"{delete_rel} (removed)" in blob or f"`{delete_rel}` was deleted." in blob,
                  "incremental e2e covers the deleted path")
        html_path = ark_client.OUT_DIR / "github-mcp-chatbot.html"
        html = html_path.read_text(encoding="utf-8") if html_path.is_file() else ""
        check(probe in blob or probe in html,
              "modified README content comes from git diffs/FILE bodies, not reflectPhrases")
        live_dump = ark_client._cluster_post("/collect", {"repository": TARGET_REPO, "ref": current})
        _assert_live_sensitive_protection(
            dump=live_dump,
            html=html,
            documentation=docs if isinstance(docs, dict) else None,
            analysis=result.get("analysis") if isinstance(result.get("analysis"), dict) else None,
            forbidden=[github_pat, json_leak, env_leak],
        )
        check("[REDACTED:github-pat]" in live_dump,
              "live dump redacts a GitHub PAT from an eligible file")
        sidecar_data = ark_client.load_analysis_sidecar({"repository": TARGET_REPO}, current)
        check(sidecar_data is not None and sidecar_data.get("commitSha") == current,
              "incremental e2e persists an analysis sidecar tied to the new commit SHA")
        check(ark_client.load_analysis_sidecar({"repository": TARGET_REPO}, previous) is None,
              "analysis sidecar for the new commit is not used as previousCommit")
        print(f"  info  incremental tokenUsage={result.get('tokenUsage')} queryDurationMs={result.get('queryDurationMs') or elapsed_ms}")
        print(f"  info  incremental scopeMeta={result.get('scopeMeta')}")
        print(f"  info  full tokenUsage={full_result.get('tokenUsage')} queryDurationMs={full_result.get('queryDurationMs')}")
        print(f"  info  add={added} rename={rename_src}->{rename_dst} delete={delete_rel}")

        (clone / "README.md").write_text(
            (clone / "README.md").read_text(encoding="utf-8") + f"\nsecond-inc {stamp}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "README.md"], cwd=str(clone), check=True, capture_output=True, text=True)
        subprocess.run(
            ["git", "commit", "-m", f"docs e2e incremental sidecar {stamp}"],
            cwd=str(clone),
            check=True,
            capture_output=True,
            text=True,
            env=git_env,
        )
        current2 = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(clone),
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        subprocess.run(["git", "push", "origin", branch], cwd=str(clone), check=True, capture_output=True, text=True)
        hit = ark_client.compute_incremental_scope({
            "repository": TARGET_REPO,
            "previousCommit": current,
            "currentCommit": current2,
        })
        check(hit.get("usedSidecar") is True and hit.get("collectMode") == "paths",
              "matching sidecar SHA analyzes only changed files")
        print(f"  info  sidecar-hit collectElapsedMs={hit.get('collectElapsedMs')} analyzeElapsedMs={hit.get('analyzeElapsedMs')} collectMode={hit.get('collectMode')}")
        sidecar = ark_client.analysis_sidecar_path({"repository": TARGET_REPO})
        sidecar.write_text(
            json.dumps({"commitSha": "0" * 40, "analysis": {"files": []}, "repositoryMap": {"modules": []}}),
            encoding="utf-8",
        )
        miss = ark_client.compute_incremental_scope({
            "repository": TARGET_REPO,
            "previousCommit": current,
            "currentCommit": current2,
        })
        check(miss.get("usedSidecar") is False and miss.get("collectMode") == "full",
              "SHA-mismatched sidecar falls back to full collect/analyze")
        print(f"  info  sidecar-miss collectElapsedMs={miss.get('collectElapsedMs')} analyzeElapsedMs={miss.get('analyzeElapsedMs')} collectMode={miss.get('collectMode')}")
        try:
            sidecar.unlink()
        except OSError:
            pass
        check("GIT DIFFS" in str(hit.get("scopedDump") or "") or "DIFF:" in str(hit.get("scopedDump") or ""),
              "incremental dump includes git diffs")
        check("reflectPhrases" not in json.dumps(hit.get("updateFields") or []),
              "incremental impact does not use reflectPhrases")
    except Exception as exc:
        check(False, f"incremental e2e raised {type(exc).__name__}: {exc}")
        print(f"  info  incremental e2e error: {exc}")
    finally:
        ark_client.OUT_DIR = original_out
        if clone is not None:
            subprocess.run(
                ["git", "push", "origin", "--delete", branch],
                cwd=str(clone),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            print(f"  info  deleted throwaway branch {branch}")
            import shutil
            shutil.rmtree(clone, ignore_errors=True)


def test_self_repo_incremental_e2e() -> None:
    """Incremental Query for Automated-Repository-Documentation (annotation overflow repo)."""
    ref = "v2-development"
    print(f"\nincremental Query create ({SELF_REPO} ref={ref})")
    _validation, ark_client, registry = _host_modules()
    current = ark_client.resolve_commit_sha(SELF_REPO, ref)
    check(bool(current), "self-repo e2e resolves the v2-development GitHub SHA")
    if not current:
        return
    subprocess.run(
        ["git", "fetch", "--no-tags", "origin", ref],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    parent = subprocess.run(
        ["git", "rev-parse", f"{current}^"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if parent.returncode != 0:
        subprocess.run(
            ["git", "fetch", "--no-tags", "origin", current],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        parent = subprocess.run(
            ["git", "rev-parse", f"{current}^"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    previous = (parent.stdout or "").strip()
    older = subprocess.run(
        ["git", "rev-parse", f"{current}~3"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if older.returncode == 0 and (older.stdout or "").strip():
        previous = (older.stdout or "").strip()
    check(bool(previous) and previous != current, "self-repo e2e has a parent SHA for incremental")
    if not previous or previous == current:
        return
    tmp = tempfile.mkdtemp(prefix="e2e-self-reg-")
    reg = Path(tmp) / "e2e-registry.json"
    stub = _sample_docs(util="app/ark_client.py", unrelated="README.md")
    registry.record_success(
        SELF_REPO,
        previous,
        artifact="automated-repository-documentation.html",
        documentation=stub,
        path=reg,
    )
    plan = ark_client.plan_documentation(SELF_REPO, ref, current_sha=current, registry_path=reg)
    check(
        plan.get("mode") == "incremental" and plan.get("previousCommit") == previous,
        "self-repo e2e plans incremental generation",
    )
    print(f"  info  self-repo previous={previous} current={current}")
    result = ark_client.execute_documentation_plan(
        plan,
        run_pipeline=ark_client.run_ark_pipeline,
        registry_path=reg,
    )
    err = str(result.get("error") or "")
    check(
        "Too long" not in err and "metadata.annotations" not in err,
        "self-repo incremental Query is not rejected for annotation size",
    )
    check("kubectl apply failed" not in err, "self-repo incremental does not use kubectl apply")
    check(
        result.get("status") == "documented",
        f"self-repo incremental documented (status={result.get('status')} error={err[:240]})",
    )
    check(
        int(result.get("queryDurationMs") or 0) > 0,
        "self-repo incremental submitted an ARK Query (did not skip)",
    )
    print(f"  info  self-repo status={result.get('status')} currentCommit={result.get('currentCommit')}")
    print(f"  info  self-repo tokenUsage={result.get('tokenUsage')} queryDurationMs={result.get('queryDurationMs')}")
    print(f"  info  self-repo scopeMeta={result.get('scopeMeta')}")
    print(f"  info  self-repo error={err[:300] if err else None}")


def test_renderer_unit() -> None:
    tests_dir = Path(__file__).resolve().parents[1] / "tools" / "documentation-renderer" / "tests"
    sys.path.insert(0, str(tests_dir))
    import test_renderer as renderer_tests  # noqa: E402

    renderer_tests.run(check)


def main() -> int:
    test_filtering_and_structure()
    test_determinism_and_render()
    test_json_exclusion()
    test_budget_and_errors()
    test_urls_and_invalid_input()
    test_dump_sanitization()
    test_structured_sanitization()
    test_security_verification()
    test_local_llm_detector()
    test_input_validation()
    test_ref_handling()
    test_git_change_detection()
    test_change_filtering()
    test_change_eligibility_and_budget()
    test_excluded_file_visibility()
    test_workspace_reuse_and_shallow()
    test_documentation_registry()
    test_commit_pinning_and_eligibility()
    test_git_errors()
    test_gitlab_auth_abstraction()
    test_renderer_unit()
    test_analyzer()
    test_analyzer_cross_file()
    test_repository_map()
    test_incremental_analysis()
    test_incremental_documentation()
    test_incremental_context_optimization()
    test_webhook_automation()
    test_pipeline_config()
    if "--network" in sys.argv:
        test_live_clone()
    else:
        print("\nskipping live clone test (pass --network to enable)")
    test_optional_gitlab_e2e()
    if "--e2e" in sys.argv:
        test_pipeline_e2e()
        test_self_repo_incremental_e2e()
    else:
        print("skipping deployed end-to-end test (pass --e2e to enable)")

    print()
    if _failures:
        print(f"{len(_failures)} check(s) failed:")
        for failure in _failures:
            print(f"  - {failure}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
