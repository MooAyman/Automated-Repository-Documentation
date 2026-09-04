"""Unit tests for the deterministic documentation HTML renderer."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import renderer  # noqa: E402

REQUIRED_HEADINGS = [
    "1. Repository Overview",
    "2. Repository Structure",
    "3. Tools &amp; Technologies Used",
    "4. Core Concepts &amp; Architecture",
    "5. Categorized Technical Information",
    "6. Developer Onboarding Guide",
]
REQUIRED_SUBHEADINGS = [
    "Quick Start",
    "Request Flow",
    "Build &amp; Packaging Flow",
    "Main APIs / Endpoints",
    "Main Services / Mediators",
    "DTOs / Schemas / Metadata",
    "Security Components",
    "Configurations",
    "Entry Points",
    "Tests",
    "Risks / Technical Debt",
    "First 30 Minutes for a New Developer",
    "How to Investigate a Production Bug",
    "Critical Files You Must Understand",
    "Common Mistakes New Developers Make",
]


def sample_document(**overrides) -> dict:
    doc = {
        "repositoryOverview": {
            "summary": "Sample service that chats with a model.",
            "quickStart": "1. Install dependencies\n2. Run `python backend/main.py`",
        },
        "repositoryStructure": "backend/ holds the API. frontend/ is the UI.",
        "toolsAndTechnologies": "- Python\n- FastAPI\n- OpenAI",
        "coreConceptsAndArchitecture": {
            "summary": "A request hits FastAPI and is forwarded to the agent.",
            "requestFlow": "POST /chat → `backend/agent/agent.py` → model.",
            "buildAndPackagingFlow": "Docker builds the image from the root Dockerfile.",
        },
        "categorizedTechnicalInformation": {
            "mainApisAndEndpoints": "- `POST /chat`\n- `GET /health`",
            "mainServicesAndMediators": "The agent in `backend/agent/agent.py` mediates.",
            "dtosSchemasMetadata": "ChatRequest and ChatResponse live in the backend.",
            "securityComponents": "No authentication is present.",
            "configurations": "OPENAI_API_KEY is required.",
            "entryPoints": "`backend/main.py` starts the server.",
            "tests": "Unit tests live under tests/.",
            "risksAndTechnicalDebt": "API keys are read from the environment only.",
        },
        "developerOnboardingGuide": {
            "first30Minutes": "Read README.md, then backend/main.py.",
            "howToInvestigateAProductionBug": "Check GET /health, then agent logs.",
            "criticalFiles": "- backend/agent/agent.py\n- backend/main.py",
            "commonMistakes": "Forgetting to set the model API key.",
        },
    }
    doc.update(overrides)
    return doc


def run(check) -> None:
    print("\nrenderer unit tests")

    html = renderer.render({"documentation": sample_document()})
    check(html.startswith("<!DOCTYPE html>"), "standalone document starts with doctype")
    check("<html" in html and "</html>" in html, "html root element is present")
    check("<head>" in html and "<body>" in html, "head and body are present")
    check("<title>" in html and "</title>" in html, "page title is present")
    check('id="filter"' in html, "section filter control is present")
    check('class="sidebar"' in html and 'class="nav-tree"' in html, "sidebar navigation is present")
    check('id="overview"' in html and 'id="onboarding-mistakes"' in html, "section anchors are present")

    for heading in REQUIRED_HEADINGS:
        check(heading in html, f"section heading present: {heading}")
    for heading in REQUIRED_SUBHEADINGS:
        check(heading in html, f"subsection heading present: {heading}")

    check("backend/agent/agent.py" in html, "repository path survives rendering")
    check("POST /chat" in html and "GET /health" in html, "endpoints survive rendering")
    check("<code>" in html, "inline code is rendered")
    check("<ol>" in html and "<ul>" in html, "numbered and bullet lists are rendered")

    unwrapped = renderer.render(sample_document())
    check("1. Repository Overview" in unwrapped, "six-key document is accepted without a wrapper")

    empty = sample_document()
    empty["repositoryOverview"]["summary"] = ""
    empty["repositoryStructure"] = "   "
    empty_html = renderer.render(empty)
    check("Not provided." in empty_html, "empty strings render a placeholder instead of crashing")

    injected = sample_document()
    injected["repositoryOverview"]["summary"] = (
        'Intro <script>alert("xss")</script> and <img src=x onerror=alert(1)>'
    )
    injected["toolsAndTechnologies"] = "See [evil](javascript:alert(1)) and [ok](https://example.com/docs)."
    injected["repositoryStructure"] = (
        "Example:\n```python\n</code></pre><script>alert(1)</script>\nprint('<b>')\n```"
    )
    safe = renderer.render(injected)
    check("<script>alert" not in safe, "script tags from repository content are not emitted raw")
    check("<img src=x" not in safe, "raw HTML tags from repository content are not emitted")
    check("&lt;script&gt;" in safe, "script tags are HTML-escaped")
    check("&lt;img" in safe or "&lt;img src=x" in safe, "img tags are HTML-escaped")
    check("javascript:alert" not in safe or 'href="javascript:' not in safe,
          "javascript: links are not turned into hrefs")
    check('href="https://example.com/docs"' in safe, "safe https links are kept")
    check("&lt;/code&gt;&lt;/pre&gt;&lt;script&gt;" in safe, "fenced code content is escaped")
    check("&lt;b&gt;" in safe, "angle brackets inside code fences are escaped")
    check(safe.count("<script") == 1, "only the renderer’s own filter script is present")

    missing = sample_document()
    del missing["repositoryStructure"]
    try:
        renderer.render(missing)
        check(False, "missing required field raises RenderError")
    except renderer.RenderError as exc:
        check("repositoryStructure" in str(exc), f"missing field is named in the error ({exc})")

    missing_nested = sample_document()
    del missing_nested["repositoryOverview"]["quickStart"]
    try:
        renderer.render(missing_nested)
        check(False, "missing nested field raises RenderError")
    except renderer.RenderError as exc:
        check("quickStart" in str(exc), f"missing nested field is named in the error ({exc})")

    try:
        renderer.render({"documentation": "not-an-object"})
        check(False, "non-object documentation raises RenderError")
    except renderer.RenderError:
        check(True, "non-object documentation raises RenderError")

    as_string = renderer.render({"documentation": __import__("json").dumps(sample_document())})
    check("backend/agent/agent.py" in as_string, "documentation JSON string is accepted")

    check(renderer.safe_output_filename("github-mcp-chatbot") == "github-mcp-chatbot.html", "safe filename from repo name")
    check(renderer.safe_output_filename("../etc/passwd") == "passwd.html", "path traversal is stripped from filename")
    check(renderer.safe_output_filename("a/b\\c.git") == "c.html", "path and .git suffix are stripped")

    with __import__("tempfile").TemporaryDirectory() as tmp:
        page = renderer.render(sample_document())
        artifact = renderer.persist_html(page, "github-mcp-chatbot", tmp)
        written = Path(tmp) / "github-mcp-chatbot.html"
        check(artifact["filename"] == "github-mcp-chatbot.html", "persist returns the filename")
        check(written.is_file() and "POST /chat" in written.read_text(encoding="utf-8"),
              "persist writes standalone HTML to the output directory")


def main() -> int:
    failures: list[str] = []

    def check(condition: bool, label: str) -> None:
        print(f"  {'PASS' if condition else 'FAIL'}  {label}")
        if not condition:
            failures.append(label)

    run(check)
    print()
    if failures:
        print(f"{len(failures)} check(s) failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("all renderer checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
