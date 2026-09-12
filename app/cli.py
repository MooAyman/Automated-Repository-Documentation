"""Host CLI for the same documentation planner as Streamlit and the webhook.

    python app/cli.py https://github.com/org/repo
    python app/cli.py https://github.com/org/repo --ref develop
    python app/cli.py "Document this repository: https://github.com/org/repo ref: develop"

Raw ``ark query agent/repository-pipeline`` does not consult the registry.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Callable

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import ark_client  # noqa: E402
from validation import ValidationError  # noqa: E402

_URL = re.compile(r"https?://[^\s]+", re.I)
_REF = re.compile(r"(?i)(?:ref|branch):\s*(\S+)")


def parse_request(values: list[str], ref: str = "") -> tuple[str, str]:
    """Accept a URL, optional --ref, or the existing Document-this-repository sentence."""
    text = " ".join(value.strip() for value in values if value and value.strip())
    if not text:
        raise ValidationError("repository URL is required")
    match = _URL.search(text)
    if not match:
        raise ValidationError("repository URL is required")
    url = match.group(0).rstrip(".,;)]}")
    found = (ref or "").strip()
    if not found:
        extra = _REF.search(text)
        if extra:
            found = extra.group(1).strip()
    return ark_client.validate_pipeline_input(url, found)


def run(
    repository_url: str,
    ref: str = "",
    *,
    registry_path: str | Path | None = None,
    run_pipeline: Callable[[dict], dict] | None = None,
    current_sha: str = "",
    probe: Callable[[str, str], dict] | None = None,
) -> dict:
    """Same planner/execution as the UI and webhook."""
    return ark_client.document_repository(
        repository_url,
        ref,
        current_sha=current_sha,
        registry_path=registry_path,
        run_pipeline=run_pipeline,
        probe=probe,
    )


def _print_result(result: dict) -> int:
    status = str(result.get("status") or "")
    mode = str(result.get("mode") or "")
    artifact = str(result.get("artifact") or "")
    if status == "already_documented":
        print("Already documented")
        if artifact:
            print(f"Output:\n{artifact}")
        return 0
    if status == "failed":
        print(result.get("error") or "documentation failed")
        return 1
    print("✓ Repository collected")
    print("✓ Documentation generated")
    print("✓ HTML rendered")
    print()
    print("Output:")
    print(artifact or "(no artifact)")
    if mode:
        print(f"mode: {mode}")
    return 0


def main(argv: list[str] | None = None, run_pipeline: Callable[[dict], dict] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Document a GitHub or GitLab repository")
    parser.add_argument("repository", nargs="+", help="Repository URL or Document-this-repository sentence")
    parser.add_argument("--ref", default="", help="Branch, tag, or commit SHA")
    parser.add_argument("--registry", default="", help="Registry JSON path (default: state/documentation-registry.json)")
    args = parser.parse_args(argv)
    try:
        url, ref = parse_request(args.repository, args.ref)
        result = run(
            url,
            ref,
            registry_path=args.registry or None,
            run_pipeline=run_pipeline,
        )
    except (ValidationError, Exception) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return _print_result(result)


if __name__ == "__main__":
    sys.exit(main())
