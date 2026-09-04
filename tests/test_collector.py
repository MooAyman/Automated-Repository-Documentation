"""Tests for the repository-documentation project.

Offline checks of the collector:  python tests/test_collector.py
Add the live clone test:          python tests/test_collector.py --network
Add the deployed end-to-end test:  python tests/test_collector.py --e2e

The --e2e mode exercises the deployed repository-pipeline flow and verifies
that documentation is generated successfully.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
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

        entries = collector.scan(str(root), max_file_bytes=1000, max_total_bytes=20)
        omitted = [e for e in entries if "budget" in e.reason]
        check(bool(omitted), "total content budget is enforced")
        check(sum(len(e.text) for e in entries if e.included) <= 20, "included content stays within budget")

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


def collector_collect_count() -> int | None:
    result = _kubectl(
        ["kubectl", "logs", "-n", NAMESPACE, "-l", COLLECTOR_LABEL, "--tail=200"]
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


def renderer_artifact(filename: str) -> str | None:
    host = ROOT / "out" / filename
    if host.is_file():
        return host.read_text(encoding="utf-8")
    print(f"        could not read artifact: {host} is missing")
    return None


def test_pipeline_e2e() -> None:
    """One Query to Agent/repository-pipeline. No manual JSON copy."""
    print(f"\npipeline query {PIPELINE_QUERY_NAME} (namespace {NAMESPACE})")
    collects_before = collector_collect_count()

    _kubectl(["kubectl", "delete", "query", PIPELINE_QUERY_NAME, "-n", NAMESPACE, "--ignore-not-found=true"])
    time.sleep(1)

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

    collects_after = collector_collect_count()
    if collects_before is None or collects_after is None:
        check(False, "collector logs are readable after the pipeline Query")
    else:
        check(
            collects_after == collects_before + 1,
            f"pipeline caused exactly one collector call (before={collects_before}, after={collects_after})",
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
    test_ref_handling()
    test_git_errors()
    test_gitlab_auth_abstraction()
    test_renderer_unit()
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
