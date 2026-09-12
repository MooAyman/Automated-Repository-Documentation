"""Submit and watch ARK Queries for documentation Agents.

This is a host-side client. It validates URL and ref, consults the
last-documented SHA registry, and for incremental runs computes
deterministic /changes plus a scoped /collect (kubectl exec into the
collector). Analysis and map updates run on the host from SHA-tied
sidecars when the sidecar commit matches previousCommit. It then Queries
the full or incremental documentation Agent and persists HTML with the
renderer module. It does not ask an LLM to copy documentation JSON into
the renderer Tool. Agent/repository-pipeline remains available for raw
operator ``ark query``; the host CLI uses this planner instead.
"""

from __future__ import annotations

import importlib.util
import inspect
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

from documentation_registry import (
    lookup,
    record_success,
    repository_identity,
    same_commit,
)
from validation import ValidationError, validate_commit_sha, validate_pipeline_input

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "out"
_RENDERER_DIR = ROOT / "tools" / "documentation-renderer"
NAMESPACE = os.environ.get("ARK_NAMESPACE", "default")
COLLECTOR_DEPLOYMENT = os.environ.get("ARK_COLLECTOR_DEPLOYMENT", "repository-collector")
DOCS_AGENT = "repository-documentation"
INCREMENTAL_AGENT = "repository-documentation-incremental"
PIPELINE_AGENT = "repository-pipeline"  # kept for CLI ``ark query`` to Agent/repository-pipeline
QUERY_TIMEOUT = "15m"
POLL_SECONDS = 3
WAIT_SECONDS = 900
SCOPE_TIMEOUT_SECONDS = 360

# Runs in the collector pod. POSTs JSON to localhost collector endpoints.
# argv: url, json-payload, timeout-seconds
SCOPE_SCRIPT = r"""
import json
import sys
import urllib.error
import urllib.request

url = sys.argv[1]
payload = json.loads(sys.argv[2])
timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 300
req = urllib.request.Request(
    url,
    data=json.dumps(payload).encode("utf-8"),
    method="POST",
    headers={"Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        sys.stdout.write(resp.read().decode("utf-8", "replace"))
except urllib.error.HTTPError as exc:
    sys.stderr.write(exc.read().decode("utf-8", "replace"))
    raise SystemExit(exc.code if exc.code else 1)
"""

_DNS1123 = re.compile(r"[^a-z0-9-]+")
_HTML_NAME = re.compile(r"([A-Za-z0-9._-]+\.html)")


def parse_ls_remote(stdout: str) -> str:
    """Pick the peeled commit SHA from ``git ls-remote`` output.

    Annotated tags emit the tag object first and ``^{}`` for the commit.
    """
    peeled: list[str] = []
    plain: list[str] = []
    for line in (stdout or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            sha = validate_commit_sha(parts[0], required=True)
        except ValidationError:
            continue
        name = parts[1] if len(parts) > 1 else ""
        if name.endswith("^{}"):
            peeled.append(sha)
        else:
            plain.append(sha)
    chosen = (peeled or plain)
    if not chosen:
        raise RuntimeError("could not resolve commit SHA: empty ls-remote output")
    return chosen[0]


def resolve_commit_sha(repository_url: str, ref: str = "") -> str:
    """Resolve the current remote commit without cloning the repository."""
    url, ref = validate_pipeline_input(repository_url, ref)
    args = ["git", "ls-remote", "--", url, ref or "HEAD"]
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"could not resolve commit SHA: {err}")
    return parse_ls_remote(result.stdout)


def documented_commit(repository_url: str, *, registry_path: str | Path | None = None) -> str:
    record = lookup(repository_url, registry_path)
    return str((record or {}).get("commitSha") or "")


def plan_documentation(
    repository_url: str,
    ref: str = "",
    *,
    resolver: Callable[[str, str], str] | None = None,
    registry_path: str | Path | None = None,
    current_sha: str = "",
) -> dict:
    """Decide whether to run the pipeline or return already_documented.

    Persistence lives in the JSON registry, not Streamlit memory or HTML.
    """
    url, ref = validate_pipeline_input(repository_url, ref)
    identity = repository_identity(url)
    stored = lookup(url, registry_path)
    previous = str((stored or {}).get("commitSha") or "")
    current = (current_sha or "").strip()
    if current:
        current = validate_commit_sha(current, required=True)
    else:
        resolve = resolver or resolve_commit_sha
        try:
            current = resolve(url, ref)
        except Exception:
            current = ""

    if stored and current and same_commit(previous, current):
        return {
            "status": "already_documented",
            "mode": "already_documented",
            "repository": url,
            "identity": identity,
            "currentCommit": previous,
            "previousCommit": previous,
            "documentationVersion": int(stored.get("documentationVersion") or 1),
            "artifact": str(stored.get("artifact") or ""),
            "previousDocumentation": stored.get("documentation") if isinstance(stored.get("documentation"), dict) else None,
            "runPipeline": False,
        }

    previous_docs = stored.get("documentation") if isinstance(stored, dict) else None
    if not isinstance(previous_docs, dict):
        previous_docs = None

    if not stored:
        return {
            "status": "first_run",
            "mode": "full",
            "repository": url,
            "identity": identity,
            "currentCommit": current,
            "previousCommit": "",
            "documentationVersion": 0,
            "artifact": "",
            "previousDocumentation": None,
            "runPipeline": True,
        }

    return {
        "status": "needs_documentation",
        "mode": "incremental",
        "repository": url,
        "identity": identity,
        "currentCommit": current,
        "previousCommit": previous,
        "documentationVersion": int(stored.get("documentationVersion") or 1),
        "artifact": str(stored.get("artifact") or ""),
        "previousDocumentation": previous_docs,
        "runPipeline": True,
    }


def complete_documentation(
    repository_url: str,
    commit_sha: str,
    artifact: str = "",
    *,
    documentation: dict | None = None,
    section_files: dict | None = None,
    registry_path: str | Path | None = None,
) -> dict:
    """Persist the documented SHA only after a successful generation."""
    return record_success(
        repository_url,
        commit_sha,
        artifact=artifact,
        documentation=documentation,
        section_files=section_files,
        path=registry_path,
    )


def execute_documentation_plan(
    plan: dict,
    *,
    run_pipeline: Callable[[dict], dict] | None = None,
    registry_path: str | Path | None = None,
) -> dict:
    """Run or skip documentation. Persist SHA only when generation succeeds."""
    if plan.get("status") == "already_documented":
        return dict(plan)

    if run_pipeline is None:
        raise RuntimeError("run_pipeline is required unless the commit is already documented")

    outcome = run_pipeline(plan)
    if not outcome.get("ok"):
        stored = lookup(plan["repository"], registry_path)
        return {
            "status": "failed",
            "mode": plan.get("mode") or "full",
            "repository": plan["repository"],
            "identity": plan.get("identity") or repository_identity(plan["repository"]),
            "currentCommit": plan.get("currentCommit") or "",
            "previousCommit": str((stored or {}).get("commitSha") or plan.get("previousCommit") or ""),
            "documentationVersion": int((stored or {}).get("documentationVersion") or plan.get("documentationVersion") or 0),
            "artifact": str((stored or {}).get("artifact") or ""),
            "error": str(outcome.get("error") or "documentation failed"),
            "runPipeline": False,
        }

    artifact = str(outcome.get("artifact") or "")
    sha = str(plan.get("currentCommit") or "")
    generated = outcome.get("documentation") if isinstance(outcome.get("documentation"), dict) else None
    impact = outcome.get("impact") if isinstance(outcome.get("impact"), dict) else None
    previous_docs = plan.get("previousDocumentation") if isinstance(plan.get("previousDocumentation"), dict) else None
    merged = None
    if generated:
        merged = _merge_generated(previous_docs, generated, impact)
        _rewrite_merged_artifact(artifact, merged)
    if not sha:
        try:
            sha = resolve_commit_sha(plan["repository"], str(plan.get("ref") or ""))
        except Exception:
            sha = ""
    if not sha:
        return {
            "status": "documented",
            "mode": plan.get("mode") or "full",
            "repository": plan["repository"],
            "identity": plan.get("identity") or repository_identity(plan["repository"]),
            "currentCommit": "",
            "previousCommit": plan.get("previousCommit") or "",
            "documentationVersion": int(plan.get("documentationVersion") or 0),
            "artifact": artifact,
            "documentation": merged,
            "persisted": False,
            "runPipeline": False,
        }

    record = complete_documentation(
        plan["repository"],
        sha,
        artifact,
        documentation=merged,
        section_files=_section_files(merged) if merged else None,
        registry_path=registry_path,
    )
    persist_analysis_sidecar(
        plan,
        outcome.get("analysis") if isinstance(outcome.get("analysis"), dict) else None,
        outcome.get("repositoryMap") if isinstance(outcome.get("repositoryMap"), dict) else None,
        sha,
    )
    documented = {
        "status": "documented",
        "mode": plan.get("mode") or "full",
        "repository": record["repository"],
        "identity": record["identity"],
        "currentCommit": record["commitSha"],
        "previousCommit": plan.get("previousCommit") or "",
        "documentationVersion": record["documentationVersion"],
        "artifact": record.get("artifact") or artifact,
        "documentation": record.get("documentation") or merged,
        "persisted": True,
        "runPipeline": False,
    }
    if outcome.get("tokenUsage") is not None:
        documented["tokenUsage"] = outcome["tokenUsage"]
    if outcome.get("queryDurationMs") is not None:
        documented["queryDurationMs"] = outcome["queryDurationMs"]
    if isinstance(outcome.get("scopeMeta"), dict):
        documented["scopeMeta"] = outcome["scopeMeta"]
    if isinstance(outcome.get("analysis"), dict):
        documented["analysis"] = outcome["analysis"]
    if isinstance(outcome.get("repositoryMap"), dict):
        documented["repositoryMap"] = outcome["repositoryMap"]
    return documented


def document_repository(
    repository_url: str,
    ref: str = "",
    *,
    current_sha: str = "",
    registry_path: str | Path | None = None,
    run_pipeline: Callable[[dict], dict] | None = None,
    on_phase: Callable[[str | None], None] | None = None,
) -> dict:
    """Plan and execute documentation. Same path as Streamlit and the webhook."""
    url, ref = validate_pipeline_input(repository_url, ref)
    plan = plan_documentation(
        url,
        ref,
        current_sha=current_sha,
        registry_path=registry_path,
    )
    plan = dict(plan)
    plan["ref"] = ref
    if run_pipeline is None:
        run_pipeline = lambda documented_plan: run_ark_pipeline(documented_plan, on_phase=on_phase)
    return execute_documentation_plan(plan, run_pipeline=run_pipeline, registry_path=registry_path)


def _load_renderer_file(modname: str, filename: str):
    """Load a renderer tool module from disk. Streamlit caches sys.modules['merge']."""
    path = _RENDERER_DIR / filename
    spec = importlib.util.spec_from_file_location(modname, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[modname] = module
    spec.loader.exec_module(module)
    return module


def _renderer_modules():
    merge_mod = _load_renderer_file("merge", "merge.py")
    renderer_mod = _load_renderer_file("renderer", "renderer.py")
    return merge_mod, renderer_mod


def _merge_persisted(
    merge_mod,
    previous: dict | None,
    generated: dict,
    impact: dict | None,
    dump: str = "",
) -> dict:
    """Call merge_documentation with dump when the loaded merge accepts it.

    Streamlit can keep a stale ``merge`` module in ``sys.modules`` that predates
    the dump argument. Put dump on impact.scopedDump and omit the keyword so
    persist cannot raise TypeError. Current merge still reads scopedDump.
    """
    dump_text = (dump or "").strip() or str((impact or {}).get("scopedDump") or "")
    merge_fn = merge_mod.merge_documentation
    accepts_dump = False
    try:
        accepts_dump = "dump" in inspect.signature(merge_fn).parameters
    except (TypeError, ValueError):
        accepts_dump = False
    if accepts_dump:
        try:
            return merge_fn(previous, generated, impact, dump=dump_text)
        except TypeError as exc:
            if "dump" not in str(exc):
                raise
    merge_impact = dict(impact) if isinstance(impact, dict) else {"mode": "full"}
    if dump_text:
        merge_impact["scopedDump"] = dump_text
    return merge_fn(previous, generated, merge_impact)


def _merge_generated(previous: dict | None, generated: dict, impact: dict | None) -> dict:
    merge_mod, _renderer = _renderer_modules()
    if "incrementalImpact" in generated or "sectionSources" in generated:
        generated = {
            key: value
            for key, value in generated.items()
            if key not in {"incrementalImpact", "sectionSources"}
        }
    merged = merge_mod.merge_documentation(previous, generated, impact)
    return merge_mod.documentation_only(merged)


def _section_files(document: dict | None) -> dict | None:
    if not document:
        return None
    merge_mod, _renderer = _renderer_modules()
    return merge_mod.section_files(document)


def _rewrite_merged_artifact(artifact: str, document: dict | None) -> None:
    if not artifact or not document:
        return
    try:
        dest = artifact_path(artifact)
    except ValueError:
        return
    if not dest.parent.is_dir():
        return
    _merge_mod, renderer = _renderer_modules()
    page = renderer.render({"documentation": document})
    renderer.persist_html(page, dest.stem, str(dest.parent), document=document)


_SCOPE_META_KEYS = (
    "scopedDump",
    "fullDumpBytes",
    "scopedDumpBytes",
    "collectCount",
    "analysis",
    "repositoryMap",
    "usedSidecar",
    "collectMode",
    "collectElapsedMs",
    "analyzeElapsedMs",
    "diffs",
)


def documentation_impact(scope: dict | None) -> dict:
    """Impact JSON for merge and the Agent, without the scoped dump payload."""
    if not isinstance(scope, dict):
        return {}
    return {key: value for key, value in scope.items() if key not in _SCOPE_META_KEYS}


def build_input(
    repository_url: str,
    ref: str = "",
    previous_commit: str = "",
    new_commit: str = "",
    previous_documentation: dict | None = None,
    impact: dict | None = None,
    scoped_dump: str = "",
    update_fields: list[str] | None = None,
    previous_sections: dict | None = None,
) -> str:
    """Build Query input. First/full runs omit previousCommit (V1.3.0 sentence).

    Incremental runs attach compact ``incrementalImpact``, ``incrementalDump``,
    host-selected ``updateFields``, and ``previousSections`` for those fields
    only. The full previous document stays in the renderer sidecar.
    """
    url, ref = validate_pipeline_input(repository_url, ref)
    previous = validate_commit_sha(previous_commit)
    current = validate_commit_sha(new_commit)
    message = f"Document this repository: {url}"
    if ref:
        message = f"{message} ref: {ref}"
    if previous:
        message = f"{message} previousCommit: {previous}"
    if current:
        message = f"{message} newCommit: {current}"
    dump = (scoped_dump or "").strip()
    clean_impact = impact
    if isinstance(impact, dict):
        if not dump:
            dump = str(impact.get("scopedDump") or "").strip()
        clean_impact = documentation_impact(impact)
    fields = list(update_fields or [])
    sections = dict(previous_sections or {})
    if dump:
        message = f"{message}\n\nincrementalDump:\n{dump}"
    if isinstance(clean_impact, dict) and clean_impact:
        merge_mod, _renderer = _renderer_modules()
        if not fields or "updateFields" not in clean_impact:
            prepared = merge_mod.prepare_incremental_impact(
                previous_documentation if isinstance(previous_documentation, dict) else None,
                clean_impact,
                dump,
            )
            clean_impact = prepared
            fields = list(prepared.get("updateFields") or [])
        if not sections and fields and isinstance(previous_documentation, dict):
            sections = merge_mod.previous_sections(previous_documentation, fields)
    if fields:
        message = f"{message}\n\nupdateFields: " + json.dumps(fields, ensure_ascii=False)
    if sections:
        message = (
            f"{message}\n\npreviousSections: "
            + json.dumps(sections, ensure_ascii=False, separators=(",", ":"))
        )
    if isinstance(clean_impact, dict) and clean_impact:
        message = (
            f"{message}\n\nincrementalImpact: "
            + json.dumps(clean_impact, ensure_ascii=False, separators=(",", ":"))
        )
    return message


def repository_artifact_name(repository_url: str) -> str:
    """HTML basename the pipeline/renderer use for this repository."""
    slug = repository_url.rstrip("/").rsplit("/", 1)[-1]
    slug = slug.removesuffix(".git")
    _merge_mod, renderer = _renderer_modules()
    return renderer.safe_output_filename(slug)


def _artifact_sidecar(repository_url: str, suffix: str) -> Path:
    stem = Path(repository_artifact_name(repository_url)).stem
    return OUT_DIR / f"{stem}{suffix}"


def seed_previous_sidecar(plan: dict) -> Path | None:
    """Write last successful docs JSON so the renderer can merge."""
    docs = plan.get("previousDocumentation")
    if not isinstance(docs, dict) or not docs:
        return None
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    merge_mod, _renderer = _renderer_modules()
    sidecar = _artifact_sidecar(str(plan["repository"]), ".json")
    sidecar.write_text(
        json.dumps(merge_mod.documentation_only(docs), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return sidecar


def seed_impact_sidecar(plan: dict, impact: dict | None) -> Path | None:
    """Write host-computed impact JSON beside the documentation sidecar."""
    sidecar = _artifact_sidecar(str(plan["repository"]), ".impact.json")
    if not isinstance(impact, dict) or not impact:
        try:
            sidecar.unlink()
        except OSError:
            pass
        return None
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(
        json.dumps(impact, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return sidecar


def analysis_sidecar_path(plan: dict) -> Path:
    return _artifact_sidecar(str(plan["repository"]), ".analysis.json")


def load_analysis_sidecar(plan: dict, expected_sha: str) -> dict | None:
    """Load analysis/map only when commitSha exactly matches previousCommit."""
    expected = (expected_sha or "").strip()
    if not expected:
        return None
    path = analysis_sidecar_path(plan)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    if str(raw.get("commitSha") or "") != expected:
        return None
    analysis = raw.get("analysis")
    repo_map = raw.get("repositoryMap")
    if not isinstance(analysis, dict) or not isinstance(analysis.get("files"), list):
        return None
    if not isinstance(repo_map, dict) or not isinstance(repo_map.get("modules"), list):
        return None
    return raw


def persist_analysis_sidecar(
    plan: dict,
    analysis: dict | None,
    repo_map: dict | None,
    commit_sha: str,
) -> Path | None:
    """Persist analysis/map tied to the documented SHA. Never writes on failure."""
    sha = (commit_sha or "").strip()
    if not sha or not isinstance(analysis, dict) or not isinstance(repo_map, dict):
        return None
    if not isinstance(analysis.get("files"), list):
        return None
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sidecar = analysis_sidecar_path(plan)
    sidecar.write_text(
        json.dumps(
            {"commitSha": sha, "analysis": analysis, "repositoryMap": repo_map},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return sidecar


def _tool_modules():
    for extra in (
        ROOT / "tools" / "repository-analyzer",
        ROOT / "tools" / "repository-map",
        ROOT / "tools" / "repository-collector",
    ):
        path = str(extra)
        if path not in sys.path:
            sys.path.insert(0, path)
    import analyzer as repository_analyzer  # noqa: E402
    import collector as repository_collector  # noqa: E402
    import impact as repository_impact  # noqa: E402
    import mapper as repository_mapper  # noqa: E402

    return repository_analyzer, repository_mapper, repository_impact, repository_collector


def _cluster_post(path: str, payload: dict, timeout: int = 300) -> str:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    result = _cluster_python(
        COLLECTOR_DEPLOYMENT,
        SCOPE_SCRIPT,
        [f"http://127.0.0.1:8080{path}", body, str(timeout)],
    )
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"collector {path} failed: {err}")
    return result.stdout or ""


def _analysis_source_files(dump: str, impact: dict | None) -> list[dict[str, str]]:
    """Eligible non-deleted, non-JSON bodies from changed ∪ impact.affected."""
    collector = _tool_modules()[3]
    bodies = dict(collector.dump_files(dump or ""))
    files: list[dict[str, str]] = []
    seen: set[str] = set()
    impact = impact if isinstance(impact, dict) else {}

    def consider(row: object, *, require_eligible: bool) -> None:
        if not isinstance(row, dict):
            return
        status = str(row.get("status") or "")
        path = str(row.get("path") or "").replace("\\", "/").lstrip("./").strip()
        if not path or status == "deleted" or path in seen:
            return
        if require_eligible and not row.get("eligible", True):
            return
        if path.lower().endswith(".json"):
            return
        body = bodies.get(path)
        if body is None:
            return
        seen.add(path)
        files.append({"path": path, "content": body})

    for row in impact.get("changed") or []:
        consider(row, require_eligible=True)
    for row in impact.get("affected") or []:
        consider(row, require_eligible=False)
    return files


def compute_incremental_scope(plan: dict) -> dict:
    """Git /changes, then sidecar splice or full collect/analyze/map fallback."""
    url, ref = validate_pipeline_input(str(plan["repository"]), str(plan.get("ref") or ""))
    previous = validate_commit_sha(str(plan.get("previousCommit") or ""), required=True)
    current = validate_commit_sha(str(plan.get("currentCommit") or ""), required=True)
    pin = current or ref
    changes_text = _cluster_post(
        "/changes",
        {
            "repository": url,
            "ref": pin,
            "previousCommit": previous,
            "newCommit": current,
            "includeDiffs": True,
        },
    )
    try:
        changes = json.loads(changes_text.strip() or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"incremental /changes returned invalid JSON: {exc}") from exc
    if not isinstance(changes, dict) or "changed" not in changes:
        raise RuntimeError("incremental scope returned no changes object")

    analyzer, mapper, impact_mod, collector = _tool_modules()
    sidecar = load_analysis_sidecar(plan, previous)
    used_sidecar = False
    collect_mode = "full"
    dump = ""
    collect_ms = 0
    analyze_ms = 0

    def _collect(paths: list[str] | None) -> tuple[str, int]:
        payload: dict = {"repository": url, "ref": pin}
        if paths is not None:
            payload["paths"] = paths
        started = time.monotonic()
        text = _cluster_post("/collect", payload)
        elapsed = int((time.monotonic() - started) * 1000)
        return text, elapsed

    def _finish(impact: dict, analysis: dict, repo_map: dict, scoped: str) -> dict:
        result = dict(impact)
        result["scopedDump"] = scoped
        result["scopedFiles"] = [path for path, _body in collector.dump_files(scoped)]
        result["fullDumpBytes"] = len(dump)
        result["scopedDumpBytes"] = len(scoped)
        result["collectCount"] = 1 if dump else 0
        result["analysis"] = analysis
        result["repositoryMap"] = repo_map
        result["usedSidecar"] = used_sidecar
        result["collectMode"] = collect_mode
        result["collectElapsedMs"] = collect_ms
        result["analyzeElapsedMs"] = analyze_ms
        if "scopedDump" not in result:
            raise RuntimeError("incremental scope returned no scopedDump")
        return result

    if sidecar:
        try:
            impact = impact_mod.analyze_impact(changes, sidecar["analysis"], sidecar["repositoryMap"])
            body_paths, deleted = collector.impact_scope_paths(impact)
            deleted_set = set(deleted)
            collect_paths = [path for path in body_paths if path not in deleted_set]
            dump, collect_ms = _collect(collect_paths)
            collect_mode = "paths"
            started = time.monotonic()
            delta_files = _analysis_source_files(dump, impact)
            if delta_files:
                delta = analyzer.analyze({"files": delta_files})
            else:
                delta = {"files": [], "unparsed": [], "references": []}
            analysis = analyzer.splice_analysis(sidecar["analysis"], delta, impact.get("changed") or [])
            repo_map = mapper.build_map(analysis)
            analyze_ms = int((time.monotonic() - started) * 1000)
            used_sidecar = True
            scoped = collector.scope_dump(dump, impact)
            scoped = collector.append_diffs(scoped, changes.get("diffs") or [])
            return _finish(impact, analysis, repo_map, scoped)
        except Exception:
            used_sidecar = False
            collect_mode = "full"

    dump, collect_ms = _collect(None)
    collect_mode = "full"
    started = time.monotonic()
    analysis = analyzer.analyze({"dump": dump})
    repo_map = mapper.build_map(analysis)
    analyze_ms = int((time.monotonic() - started) * 1000)
    impact = impact_mod.analyze_impact(changes, analysis, repo_map)
    scoped = collector.scope_dump(dump, impact) if dump else "INCREMENTAL SCOPE\nSCOPE PATHS: (none)\n"
    scoped = collector.append_diffs(scoped, changes.get("diffs") or [])
    return _finish(impact, analysis, repo_map, scoped)


def query_name(repository_url: str) -> str:
    slug = repository_url.rstrip("/").rsplit("/", 1)[-1]
    slug = slug.removesuffix(".git").lower()
    slug = _DNS1123.sub("-", slug).strip("-") or "repo"
    slug = slug[:24]
    stamp = time.strftime("%H%M%S")
    return f"ui-{slug}-{stamp}"[:63]


def artifact_path(filename: str) -> Path:
    name = Path(filename).name
    if name != filename or not name.endswith(".html"):
        raise ValueError(f"unsafe artifact name: {filename!r}")
    return OUT_DIR / name


def parse_documentation(content: str) -> dict | None:
    """Extract the documentation Agent JSON from a Query response."""
    text = (content or "").strip()
    if not text:
        return None
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
        if text[:4].lower() == "json":
            text = text[4:].lstrip()
    data = None
    decoder = json.JSONDecoder()
    idx = 0
    n = len(text)
    while idx < n:
        while idx < n and text[idx].isspace():
            idx += 1
        if idx >= n:
            break
        if text[idx] != "{":
            nxt = text.find("{", idx)
            if nxt < 0:
                break
            idx = nxt
        try:
            obj, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            break
        if isinstance(obj, dict):
            data = obj
        idx = end
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("documentation"), dict):
        data = data["documentation"]
    elif isinstance(data.get("documentation"), str):
        try:
            nested = json.loads(data["documentation"])
        except json.JSONDecodeError:
            return None
        if isinstance(nested, dict):
            data = nested
    return data if isinstance(data, dict) else None


def _seed_full_analysis(plan: dict) -> tuple[str, dict | None, dict | None]:
    """Host collect/analyze/map after a successful Query. Never raises."""
    try:
        url, ref = validate_pipeline_input(str(plan["repository"]), str(plan.get("ref") or ""))
        current = str(plan.get("currentCommit") or "").strip()
        pin = current or ref
        dump = _cluster_post("/collect", {"repository": url, "ref": pin})
        analyzer, mapper, _impact, _collector = _tool_modules()
        analysis = analyzer.analyze({"dump": dump})
        repo_map = mapper.build_map(analysis)
        if not isinstance(analysis, dict) or not isinstance(analysis.get("files"), list):
            return dump, None, None
        if not isinstance(repo_map, dict) or not isinstance(repo_map.get("modules"), list):
            return dump, None, None
        return dump, analysis, repo_map
    except Exception:
        return "", None, None


def persist_generated(
    plan: dict,
    generated: dict,
    impact: dict | None = None,
    dump: str = "",
) -> tuple[str, dict]:
    """Merge against sidecars and write HTML with the renderer module."""
    merge_mod, renderer = _renderer_modules()
    repo_name = Path(repository_artifact_name(str(plan["repository"]))).stem
    previous = plan.get("previousDocumentation") if isinstance(plan.get("previousDocumentation"), dict) else None
    document = generated
    dump_text = (dump or "").strip() or str((impact or {}).get("scopedDump") or "")
    if isinstance(generated.get("updates"), list) or (previous and impact):
        document = _merge_persisted(merge_mod, previous, generated, impact, dump_text)
        document = merge_mod.documentation_only(document)
    else:
        document = _merge_persisted(merge_mod, None, generated, {"mode": "full"}, dump_text)
        document = merge_mod.documentation_only(document)
    previous_output = os.environ.get("OUTPUT_DIR")
    os.environ["OUTPUT_DIR"] = str(OUT_DIR)
    try:
        resolved = renderer.resolve_document(
            {
                "documentation": document,
                "repositoryName": repo_name,
                "persist": True,
            }
        )
        page = renderer.render({"documentation": resolved})
        info = renderer.persist_html(page, repo_name, str(OUT_DIR), document=resolved)
    finally:
        if previous_output is None:
            os.environ.pop("OUTPUT_DIR", None)
        else:
            os.environ["OUTPUT_DIR"] = previous_output
    return str(info["filename"]), resolved


def filename_from_response(content: str) -> str | None:
    names = _HTML_NAME.findall(content or "")
    return names[-1] if names else None


def run_ark_pipeline(
    plan: dict,
    on_phase: Callable[[str | None], None] | None = None,
    *,
    compute_scope: Callable[[dict], dict] | None = None,
) -> dict:
    """Query the documentation Agent, then persist with the renderer module."""
    impact = None
    analysis = None
    repo_map = None
    scope_meta: dict = {}
    try:
        incremental = str(plan.get("mode") or "") == "incremental" and bool(plan.get("previousCommit"))
        scoped_dump = ""
        if incremental:
            scope_fn = compute_scope or compute_incremental_scope
            scope = scope_fn(plan)
            if not isinstance(scope, dict) or "changed" not in scope:
                return {"ok": False, "error": "incremental scope returned no changes object"}
            if "scopedDump" not in scope:
                return {"ok": False, "error": "incremental scope returned no scopedDump"}
            previous_docs = plan.get("previousDocumentation")
            if not isinstance(previous_docs, dict):
                previous_docs = None
            merge_mod, _renderer = _renderer_modules()
            scoped_dump = merge_mod.strip_placeholder_files(str(scope.get("scopedDump") or ""))
            impact = merge_mod.prepare_incremental_impact(
                previous_docs,
                documentation_impact(scope),
                scoped_dump,
                scoped_files=list(scope.get("scopedFiles") or []),
            )
            analysis = scope.get("analysis") if isinstance(scope.get("analysis"), dict) else None
            repo_map = scope.get("repositoryMap") if isinstance(scope.get("repositoryMap"), dict) else None
            scope_meta = {
                "usedSidecar": bool(scope.get("usedSidecar")),
                "collectMode": str(scope.get("collectMode") or ""),
                "collectElapsedMs": scope.get("collectElapsedMs"),
                "analyzeElapsedMs": scope.get("analyzeElapsedMs"),
                "fullDumpBytes": scope.get("fullDumpBytes"),
                "scopedDumpBytes": scope.get("scopedDumpBytes"),
            }
            seed_impact_sidecar(plan, impact)
        else:
            seed_impact_sidecar(plan, None)
        seed_previous_sidecar(plan)
        previous_docs = plan.get("previousDocumentation")
        if not isinstance(previous_docs, dict):
            previous_docs = None
        update_fields = list((impact or {}).get("updateFields") or []) if incremental else []
        previous_sections = None
        if incremental and previous_docs and update_fields:
            merge_mod, _renderer = _renderer_modules()
            previous_sections = merge_mod.previous_sections(previous_docs, update_fields)
        if incremental and not update_fields:
            generated = {"updates": []}
            filename, documentation = persist_generated(plan, generated, impact, dump=scoped_dump)
            path = artifact_path(filename)
            if not path.is_file():
                return {"ok": False, "error": f"{filename} was named, but the file is not on disk yet."}
            return {
                "ok": True,
                "artifact": filename,
                "documentation": documentation,
                "impact": impact,
                "analysis": analysis,
                "repositoryMap": repo_map,
                "scopeMeta": scope_meta,
                "skippedQuery": True,
                "tokenUsage": None,
                "queryDurationMs": 0,
            }
        message = build_input(
            plan["repository"],
            str(plan.get("ref") or ""),
            previous_commit=str(plan.get("previousCommit") or ""),
            new_commit=str(plan.get("currentCommit") or ""),
            previous_documentation=previous_docs if incremental else None,
            impact=impact,
            scoped_dump=scoped_dump,
            update_fields=update_fields or None,
            previous_sections=previous_sections,
        )
        name = query_name(plan["repository"])
        agent = INCREMENTAL_AGENT if incremental else DOCS_AGENT
        started = time.monotonic()
        apply_pipeline_query(name, message, agent=agent)
        obj = wait_for_query(name, on_phase=on_phase)
        duration_ms = int((time.monotonic() - started) * 1000)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    phase = (obj.get("status") or {}).get("phase")
    content = query_response(obj)
    token_usage = query_token_usage(obj)
    if phase != "done":
        return {"ok": False, "error": content or f"Documentation Query stopped (phase={phase})"}
    generated = parse_documentation(content)
    if not generated:
        return {"ok": False, "error": "documentation Agent did not return valid JSON"}
    if incremental and update_fields:
        merge_mod, _renderer = _renderer_modules()
        if isinstance(generated.get("updates"), list):
            applied = merge_mod.in_scope_updates(generated.get("updates"), update_fields)
            if not applied:
                return {"ok": False, "error": "incremental Agent returned no in-scope updates"}
    dump = scoped_dump
    if not incremental:
        dump, analysis, repo_map = _seed_full_analysis(plan)
    try:
        filename, documentation = persist_generated(plan, generated, impact, dump=dump)
    except Exception as exc:
        return {"ok": False, "error": f"renderer persist failed: {exc}"}
    path = artifact_path(filename)
    if not path.is_file():
        return {"ok": False, "error": f"{filename} was named, but the file is not on disk yet."}
    return {
        "ok": True,
        "artifact": filename,
        "documentation": documentation,
        "impact": impact,
        "analysis": analysis,
        "repositoryMap": repo_map,
        "scopeMeta": scope_meta,
        "tokenUsage": token_usage,
        "queryDurationMs": duration_ms,
        "queryName": name,
        "agent": INCREMENTAL_AGENT if incremental else DOCS_AGENT,
    }


def _kubectl(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _cluster_python(deployment: str, script: str, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "kubectl",
            "exec",
            "-i",
            "-n",
            NAMESPACE,
            f"deploy/{deployment}",
            "--",
            "python",
            "-",
            *args,
        ],
        input=script,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=SCOPE_TIMEOUT_SECONDS,
    )


def apply_pipeline_query(name: str, message: str, agent: str = DOCS_AGENT) -> None:
    body = {
        "apiVersion": "ark.mckinsey.com/v1alpha1",
        "kind": "Query",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {
                "project": "repository-documentation",
                "type": "ui",
                "target": "documentation",
            },
        },
        "spec": {
            "input": message,
            "target": {"type": "agent", "name": agent or DOCS_AGENT},
            "timeout": QUERY_TIMEOUT,
        },
    }
    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    try:
        json.dump(body, handle, ensure_ascii=False)
        handle.close()
        result = _kubectl(["kubectl", "create", "-f", handle.name])
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"kubectl create failed: {err}")


def get_query(name: str) -> dict | None:
    result = _kubectl(["kubectl", "get", "query", name, "-n", NAMESPACE, "-o", "json"])
    if result.returncode != 0 or not result.stdout:
        return None
    return json.loads(result.stdout)


def wait_for_query(
    name: str,
    timeout_s: int = WAIT_SECONDS,
    on_phase: Callable[[str | None], None] | None = None,
) -> dict:
    deadline = time.time() + timeout_s
    last_phase = object()
    while time.time() < deadline:
        obj = get_query(name)
        phase = (obj.get("status") or {}).get("phase") if obj else None
        if phase != last_phase:
            if on_phase:
                on_phase(phase)
            last_phase = phase
        if obj and phase == "done":
            return obj
        if obj and phase in ("error", "canceled"):
            return obj
        time.sleep(POLL_SECONDS)
    raise TimeoutError(f"timed out waiting for query {name}")


def query_response(obj: dict) -> str:
    return ((obj.get("status") or {}).get("response") or {}).get("content") or ""


def query_token_usage(obj: dict) -> dict | None:
    status = obj.get("status") or {}
    usage = status.get("tokenUsage") or status.get("usage")
    if isinstance(usage, dict) and usage:
        return usage
    response = status.get("response") or {}
    nested = response.get("tokenUsage") or response.get("usage")
    return nested if isinstance(nested, dict) and nested else None


if __name__ == "__main__":
    assert build_input("https://github.com/a/b") == (
        "Document this repository: https://github.com/a/b"
    )
    assert build_input("https://github.com/a/b", " develop ") == (
        "Document this repository: https://github.com/a/b ref: develop"
    )
    assert build_input(
        "https://github.com/a/b",
        "main",
        previous_commit="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        new_commit="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ) == (
        "Document this repository: https://github.com/a/b ref: main "
        "previousCommit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
        "newCommit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )
    try:
        build_input("/tmp/repo")
        raise AssertionError("local paths must fail validation")
    except ValidationError:
        pass
    name = query_name("https://github.com/MooAyman/github-mcp-chatbot.git")
    assert name.startswith("ui-github-mcp-chatbot-")
    assert filename_from_response("Output:\ngithub-mcp-chatbot.html") == (
        "github-mcp-chatbot.html"
    )
    print("ark_client checks passed")
