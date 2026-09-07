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
        check("FILE: config.json" in dump and "FILE: deploy.yml" in dump, "structured files remain in the dump")
        check("print('hello')" in dump, "non-structured source is kept")
        check("supersecret" not in dump, "filename filtering still drops `.env`")
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
        check(public_name in dump and public_host in dump, "non-sensitive structured values reach the dump")
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
        tools_block.count("type: http") == 4
        and "repository-collector" in tools_block
        and "repository-analyzer" in tools_block
        and "repository-map" in tools_block
        and "repository-changes" in tools_block,
        "Documentation Agent receives repository content via collector, then analyzer, map, and changes",
    )
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
        check("Acme Storefront" in dump, "non-sensitive JSON fields still reach the dump")
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
            check(len(clones) == 2, "different refs do not share the wrong workspace")

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
    check('previous_commit=plan.get("previousCommit")' in ui_src,
          "Streamlit forwards the registry previousCommit into Query input")
    check('new_commit=plan.get("currentCommit")' in ui_src,
          "Streamlit forwards the pinned newCommit into Query input")

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
        check(any(row["path"] == "notes.json" and row["reason"] == "unsupported" for row in from_dump["unparsed"]),
              "non-Python dump files are reported unsupported")
        check("dump-json-secret" not in json.dumps(from_dump), "collector-redacted JSON secrets stay out of analyzer output")
        check(from_dump["files"][0]["classes"], "dump-derived Python facts are present")

    try:
        analyzer.analyze({"repository": "https://github.com/example/repo"})
        check(False, "repository URL without sanitized content is rejected")
    except analyzer.AnalyzerError:
        check(True, "repository URL without sanitized content is rejected")

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


def test_pipeline_config() -> None:
    print("\npipeline configuration")
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
    check("documentationJson" in renderer_tool, "renderer Tool accepts documentationJson")
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
        re.search(r"type:\s*http\s*\n\s*name:\s*repository-analyzer", docs) is not None,
        "documentation Agent references the repository-analyzer",
    )
    check("repository-analyzer" not in tools_block, "pipeline Agent does not call the analyzer")
    check("repository-map" not in tools_block, "pipeline Agent does not call the repository map")
    check("repository-changes" not in tools_block, "pipeline Agent does not call change detection")
    check("Do not call repository-collector, repository-analyzer, repository-map, or" in pipeline
          and "repository-changes" in pipeline,
          "pipeline prompt keeps collection, analysis, mapping, and changes off the orchestrator")
    changes_tool = (ROOT / "tools" / "repository-changes.yaml").read_text(encoding="utf-8")
    check("/changes" in changes_tool and "type: http" in changes_tool, "changes Tool posts to /changes")
    changes_src = (ROOT / "tools" / "repository-collector" / "changes.py").read_text(encoding="utf-8")
    check("is_collectable_path" in changes_src, "change detection reuses collector path inclusion rules")
    check("max_total_bytes" not in changes_src and "DEFAULT_MAX_TOTAL_BYTES" not in changes_src,
          "change detection does not apply the total collection budget")
    check('"209715200"' in collector_tool, "collector Tool default total budget is 200 MiB")
    check("DEFAULT_MAX_TOTAL_BYTES = 200 * 1024 * 1024" in collector_src,
          "collector default total budget is 200 MiB")
    check("open_remote" in collector_src, "collect reuses the same-pipeline workspace")
    analyzer_src = (ROOT / "tools" / "repository-analyzer" / "analyzer.py").read_text(encoding="utf-8")
    check("excluded_from_dump" in analyzer_src, "analyzer reads excluded-file metadata from the dump")
    check("Excluded files and unwalked directories are unseen" not in docs,
          "documentation Agent does not treat excluded files as missing")
    check("ensure_commit" in changes_src, "change detection fetches a missing previous SHA")
    check((ROOT / "tools" / "repository-collector" / "workspace.py").is_file(),
          "collector workspace helper exists")
    check(
        re.search(r"type:\s*http\s*\n\s*name:\s*repository-changes", docs) is not None,
        "documentation Agent references repository-changes",
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
        re.search(r"type:\s*http\s*\n\s*name:\s*repository-map", docs) is not None,
        "documentation Agent references the repository-map",
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
    check("parse_ls_remote" in ark_client_src, "ls-remote prefers the peeled annotated-tag commit")
    check("current_commit_bodies" in collector_src,
          "collector exposes current-commit bodies without stale excluded content")
    check("checkout_commit" in (ROOT / "tools" / "repository-collector" / "workspace.py").read_text(
        encoding="utf-8"
    ), "workspace checks out the requested newCommit")
    check("tag: m12" in values, "collector image tag is m12")
    check("tag: m2" in values, "analyzer and map image tags remain m2")
    check("state/" in (ROOT / ".gitignore").read_text(encoding="utf-8"),
          "documentation registry directory is gitignored")


def renderer_artifact(filename: str) -> str | None:
    host = ROOT / "out" / filename
    if host.is_file():
        return host.read_text(encoding="utf-8")
    print(f"        could not read artifact: {host} is missing")
    return None


def test_pipeline_e2e() -> None:
    """One Query to Agent/repository-pipeline. No manual JSON copy."""
    print(f"\npipeline query {PIPELINE_QUERY_NAME} (namespace {NAMESPACE})")

    _kubectl(["kubectl", "delete", "query", PIPELINE_QUERY_NAME, "-n", NAMESPACE, "--ignore-not-found=true"])
    time.sleep(1)
    since_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    query = {
        "apiVersion": "ark.mckinsey.com/v1alpha1",
        "kind": "Query",
        "metadata": {
            "name": PIPELINE_QUERY_NAME,
            "namespace": NAMESPACE,
            "labels": {
                "project": "repository-documentation",
                "type": "e2e",
                "target": "pipeline",
            },
        },
        "spec": {
            "input": "Document this repository: https://github.com/MooAyman/github-mcp-chatbot",
            "target": {"type": "agent", "name": "repository-pipeline"},
            "timeout": "15m",
        },
    }
    if not apply_query(query):
        check(False, "pipeline Query was applied")
        return

    obj = wait_for_query(PIPELINE_QUERY_NAME, 900)
    if obj is None:
        check(False, "pipeline Query completed")
        return

    status = obj.get("status") or {}
    check(status.get("phase") == "done", f"pipeline Query completed (phase={status.get('phase')})")
    if status.get("phase") != "done":
        return

    content = (status.get("response") or {}).get("content") or ""
    check(bool(content), "pipeline Query produced a response")
    check("<!DOCTYPE html>" not in content, "pipeline final response is not the raw HTML document")
    check("Documentation generated" in content or "HTML rendered" in content,
          "pipeline reports documentation and render stages")
    check("github-mcp-chatbot.html" in content, "pipeline names the HTML artifact")

    html = renderer_artifact("github-mcp-chatbot.html")
    check(html is not None, "HTML artifact exists on the renderer volume")
    if not html:
        return
    check(html.lstrip().startswith("<!DOCTYPE html>"), "artifact is a standalone HTML document")
    check("backend/agent/agent.py" in html, "pipeline HTML cites backend/agent/agent.py")
    check(re.search(r"POST\s+/chat", html, re.I) is not None, "pipeline HTML mentions POST /chat")
    check(re.search(r"GET\s+/health", html, re.I) is not None, "pipeline HTML mentions GET /health")
    check("ChatRequest" in html, "pipeline HTML mentions ChatRequest")
    check("ChatResponse" in html, "pipeline HTML mentions ChatResponse")
    check(re.search(r"OpenAI", html, re.I) is not None, "pipeline HTML mentions OpenAI")
    check(re.search(r"Gemini", html, re.I) is not None, "pipeline HTML mentions Gemini")
    check(re.search(r"GitHub MCP|github.?mcp|MCP", html) is not None, "pipeline HTML mentions GitHub MCP")

    collects = collector_collect_count(since_time)
    if collects is None:
        check(False, "collector logs are readable after the pipeline Query")
    else:
        check(
            collects == 1,
            f"pipeline caused exactly one collector call (since={since_time}, count={collects})",
        )

    check(HTML_OUTPUT.is_file(), f"HTML artifact exists on the Windows host ({HTML_OUTPUT})")
    if HTML_OUTPUT.is_file():
        host_html = HTML_OUTPUT.read_text(encoding="utf-8")
        check(host_html.lstrip().startswith("<!DOCTYPE html>"), "host HTML is a standalone document")
        check("backend/agent/agent.py" in host_html, "host HTML cites backend/agent/agent.py")
    print(f"  info  pipeline wrote {len(html)} bytes to {HTML_OUTPUT}")
    preview = content[:400].encode("ascii", "backslashreplace").decode("ascii")
    print(f"  info  pipeline response: {preview!r}")


def test_renderer_unit() -> None:
    tests_dir = Path(__file__).resolve().parents[1] / "tools" / "documentation-renderer" / "tests"
    sys.path.insert(0, str(tests_dir))
    import test_renderer as renderer_tests  # noqa: E402

    renderer_tests.run(check)


def main() -> int:
    test_filtering_and_structure()
    test_determinism_and_render()
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
    test_pipeline_config()
    if "--network" in sys.argv:
        test_live_clone()
    else:
        print("\nskipping live clone test (pass --network to enable)")
    test_optional_gitlab_e2e()
    if "--e2e" in sys.argv:
        test_pipeline_e2e()
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
