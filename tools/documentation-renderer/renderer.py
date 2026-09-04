"""Deterministic HTML rendering of repository-documentation JSON.

No LLM. The Agent's outputSchema is the only document shape this module accepts.
"""

from __future__ import annotations

import html
import json
import os
import re
from pathlib import Path

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

NAV = (
    ("overview", "1. Repository Overview", (
        ("overview-quick-start", "Quick Start"),
    )),
    ("structure", "2. Repository Structure", ()),
    ("tools", "3. Tools & Technologies Used", ()),
    ("architecture", "4. Core Concepts & Architecture", (
        ("architecture-request-flow", "Request Flow"),
        ("architecture-build", "Build & Packaging Flow"),
    )),
    ("catalog", "5. Categorized Technical Information", (
        ("catalog-apis", "Main APIs / Endpoints"),
        ("catalog-services", "Main Services / Mediators"),
        ("catalog-dtos", "DTOs / Schemas / Metadata"),
        ("catalog-security", "Security Components"),
        ("catalog-config", "Configurations"),
        ("catalog-entry", "Entry Points"),
        ("catalog-tests", "Tests"),
        ("catalog-risks", "Risks / Technical Debt"),
    )),
    ("onboarding", "6. Developer Onboarding Guide", (
        ("onboarding-30min", "First 30 Minutes for a New Developer"),
        ("onboarding-bugs", "How to Investigate a Production Bug"),
        ("onboarding-files", "Critical Files You Must Understand"),
        ("onboarding-mistakes", "Common Mistakes New Developers Make"),
    )),
)

_SAFE_HREF = re.compile(r"^https?://[^\s\"'<>]+$", re.I)
_FENCE = re.compile(r"```([a-zA-Z0-9_+-]*)\n(.*?)```", re.S)
_INLINE_CODE = re.compile(r"`([^`]+)`")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_HEADING = re.compile(r"^(#{1,3})\s+(.+)$")
_UL = re.compile(r"^[-*]\s+(.+)$")
_OL = re.compile(r"^(\d+)[.)]\s+(.+)$")


class RenderError(ValueError):
    """Raised when the payload is not a valid documentation document."""


def _require_object(value: object, path: str) -> dict:
    if not isinstance(value, dict):
        raise RenderError(f"{path} must be an object")
    return value


def _require_string(value: object, path: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise RenderError(f"{path} must be a string")
    return value


def safe_output_filename(name: str) -> str:
    """Basename-only HTML filename. Rejects path traversal."""
    raw = (name or "").strip()
    raw = raw.replace("\\", "/").rstrip("/")
    raw = raw.rsplit("/", 1)[-1]
    if raw.lower().endswith(".html"):
        raw = raw[:-5]
    if raw.lower().endswith(".git"):
        raw = raw[:-4]
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip(".-")
    if not cleaned or cleaned in {".", ".."}:
        cleaned = "repository"
    return cleaned[:80] + ".html"


def persist_html(html_page: str, repository_name: str, output_dir: str | None = None) -> dict:
    """Write HTML under output_dir and return {ok, filename, path, bytes}."""
    directory = (output_dir if output_dir is not None else os.environ.get("OUTPUT_DIR", "") or "").strip()
    if not directory:
        raise RenderError("OUTPUT_DIR is not configured")
    root = Path(directory).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve()
    filename = safe_output_filename(repository_name)
    dest = (root / filename).resolve()
    if dest.parent != root:
        raise RenderError("invalid output path")
    dest.write_text(html_page, encoding="utf-8")
    return {
        "ok": True,
        "filename": filename,
        "path": str(dest),
        "bytes": len(html_page.encode("utf-8")),
    }


def extract_document(payload: object) -> dict:
    """Accept `{documentation: {...}|json-string}` or the six-key document itself."""
    data = _require_object(payload, "request body")
    if "documentation" in data:
        doc = data["documentation"]
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except json.JSONDecodeError as exc:
                raise RenderError(f"documentation is not valid JSON: {exc}") from exc
        data = _require_object(doc, "documentation")
    missing = [key for key in REQUIRED_ROOT if key not in data]
    if missing:
        raise RenderError("missing required fields: " + ", ".join(missing))
    extra = [key for key in data if key not in REQUIRED_ROOT]
    if extra:
        raise RenderError("unexpected fields: " + ", ".join(sorted(extra)))

    overview = _require_object(data["repositoryOverview"], "repositoryOverview")
    architecture = _require_object(data["coreConceptsAndArchitecture"], "coreConceptsAndArchitecture")
    categorized = _require_object(data["categorizedTechnicalInformation"], "categorizedTechnicalInformation")
    onboarding = _require_object(data["developerOnboardingGuide"], "developerOnboardingGuide")

    def check(obj: dict, required: tuple[str, ...], path: str) -> None:
        missing_inner = [key for key in required if key not in obj]
        if missing_inner:
            raise RenderError(f"{path} missing required fields: " + ", ".join(missing_inner))
        for key in required:
            _require_string(obj[key], f"{path}.{key}")

    check(overview, REQUIRED_OVERVIEW, "repositoryOverview")
    _require_string(data["repositoryStructure"], "repositoryStructure")
    _require_string(data["toolsAndTechnologies"], "toolsAndTechnologies")
    check(architecture, REQUIRED_ARCHITECTURE, "coreConceptsAndArchitecture")
    check(categorized, REQUIRED_CATEGORIZED, "categorizedTechnicalInformation")
    check(onboarding, REQUIRED_ONBOARDING, "developerOnboardingGuide")
    return data


def _inline(text: str) -> str:
    placeholders: list[str] = []

    def stash(fragment: str) -> str:
        placeholders.append(fragment)
        return f"\x00{len(placeholders) - 1}\x00"

    def code(match: re.Match[str]) -> str:
        return stash(f"<code>{html.escape(match.group(1))}</code>")

    def link(match: re.Match[str]) -> str:
        label, href = match.group(1), match.group(2).strip()
        if not _SAFE_HREF.match(href):
            return html.escape(match.group(0))
        return stash(
            f'<a href="{html.escape(href, quote=True)}" rel="noopener noreferrer">{html.escape(label)}</a>'
        )

    staged = _LINK.sub(link, text)
    staged = _INLINE_CODE.sub(code, staged)
    escaped = html.escape(staged)
    for index, fragment in enumerate(placeholders):
        escaped = escaped.replace(f"\x00{index}\x00", fragment)
    return escaped


def markdown_to_html(text: str) -> str:
    """Small Markdown subset. All text is escaped before tags are added."""
    if not text or not text.strip():
        return '<p class="empty">Not provided.</p>'

    parts: list[str] = []
    rest = text.replace("\r\n", "\n").replace("\r", "\n")
    fences: list[tuple[str, str]] = []

    def keep_fence(match: re.Match[str]) -> str:
        fences.append((match.group(1), match.group(2).rstrip("\n")))
        return f"\n\x01FENCE{len(fences) - 1}\x01\n"

    rest = _FENCE.sub(keep_fence, rest)
    lines = rest.split("\n")
    i = 0
    paragraph: list[str] = []

    def flush_paragraph() -> None:
        if paragraph:
            parts.append("<p>" + _inline(" ".join(paragraph)) + "</p>")
            paragraph.clear()

    while i < len(lines):
        line = lines[i]
        fence = re.match(r"^\x01FENCE(\d+)\x01$", line.strip())
        if fence:
            flush_paragraph()
            lang, code = fences[int(fence.group(1))]
            cls = f' class="lang-{html.escape(lang, quote=True)}"' if lang else ""
            parts.append(f"<pre><code{cls}>{html.escape(code)}</code></pre>")
            i += 1
            continue
        heading = _HEADING.match(line)
        if heading:
            flush_paragraph()
            level = min(len(heading.group(1)) + 2, 6)
            parts.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
            i += 1
            continue
        if _UL.match(line):
            flush_paragraph()
            items: list[str] = []
            while i < len(lines) and _UL.match(lines[i]):
                items.append("<li>" + _inline(_UL.match(lines[i]).group(1)) + "</li>")
                i += 1
            parts.append("<ul>" + "".join(items) + "</ul>")
            continue
        if _OL.match(line):
            flush_paragraph()
            items = []
            while i < len(lines) and _OL.match(lines[i]):
                items.append("<li>" + _inline(_OL.match(lines[i]).group(2)) + "</li>")
                i += 1
            parts.append("<ol>" + "".join(items) + "</ol>")
            continue
        if not line.strip():
            flush_paragraph()
            i += 1
            continue
        paragraph.append(line.strip())
        i += 1
    flush_paragraph()
    return "\n".join(parts) if parts else '<p class="empty">Not provided.</p>'


def _section(anchor: str, title: str, body: str, subsections: list[tuple[str, str, str]] | None = None) -> str:
    blocks = [f'<section id="{anchor}" class="doc-section" data-title="{html.escape(title, quote=True)}">']
    blocks.append(f"<h2>{html.escape(title)}</h2>")
    if body:
        blocks.append(f'<div class="prose">{markdown_to_html(body)}</div>')
    for sub_id, sub_title, sub_body in subsections or ():
        blocks.append(f'<article id="{sub_id}" class="doc-sub" data-title="{html.escape(sub_title, quote=True)}">')
        blocks.append(f"<h3>{html.escape(sub_title)}</h3>")
        blocks.append(f'<div class="prose">{markdown_to_html(sub_body)}</div>')
        blocks.append("</article>")
    blocks.append("</section>")
    return "\n".join(blocks)


def _nav_html() -> str:
    items = []
    for anchor, title, subs in NAV:
        children = "".join(
            f'<li><a href="#{sub_id}">{html.escape(label)}</a></li>' for sub_id, label in subs
        )
        nested = f"<ul>{children}</ul>" if children else ""
        items.append(f'<li><a href="#{anchor}">{html.escape(title)}</a>{nested}</li>')
    return "<ul class=\"nav-tree\">" + "".join(items) + "</ul>"


def _page_title(doc: dict) -> str:
    summary = doc["repositoryOverview"].get("summary") or ""
    first = summary.strip().split("\n", 1)[0].strip()
    if first:
        clipped = first[:80] + ("…" if len(first) > 80 else "")
        return f"Developer documentation — {clipped}"
    return "Repository developer documentation"


def render(payload: object) -> str:
    doc = extract_document(payload)
    overview = doc["repositoryOverview"]
    architecture = doc["coreConceptsAndArchitecture"]
    categorized = doc["categorizedTechnicalInformation"]
    onboarding = doc["developerOnboardingGuide"]
    title = _page_title(doc)

    main = "\n".join([
        _section("overview", "1. Repository Overview", overview["summary"], [
            ("overview-quick-start", "Quick Start", overview["quickStart"]),
        ]),
        _section("structure", "2. Repository Structure", doc["repositoryStructure"]),
        _section("tools", "3. Tools & Technologies Used", doc["toolsAndTechnologies"]),
        _section("architecture", "4. Core Concepts & Architecture", architecture["summary"], [
            ("architecture-request-flow", "Request Flow", architecture["requestFlow"]),
            ("architecture-build", "Build & Packaging Flow", architecture["buildAndPackagingFlow"]),
        ]),
        _section("catalog", "5. Categorized Technical Information", "", [
            ("catalog-apis", "Main APIs / Endpoints", categorized["mainApisAndEndpoints"]),
            ("catalog-services", "Main Services / Mediators", categorized["mainServicesAndMediators"]),
            ("catalog-dtos", "DTOs / Schemas / Metadata", categorized["dtosSchemasMetadata"]),
            ("catalog-security", "Security Components", categorized["securityComponents"]),
            ("catalog-config", "Configurations", categorized["configurations"]),
            ("catalog-entry", "Entry Points", categorized["entryPoints"]),
            ("catalog-tests", "Tests", categorized["tests"]),
            ("catalog-risks", "Risks / Technical Debt", categorized["risksAndTechnicalDebt"]),
        ]),
        _section("onboarding", "6. Developer Onboarding Guide", "", [
            ("onboarding-30min", "First 30 Minutes for a New Developer", onboarding["first30Minutes"]),
            ("onboarding-bugs", "How to Investigate a Production Bug", onboarding["howToInvestigateAProductionBug"]),
            ("onboarding-files", "Critical Files You Must Understand", onboarding["criticalFiles"]),
            ("onboarding-mistakes", "Common Mistakes New Developers Make", onboarding["commonMistakes"]),
        ]),
    ])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    :root {{
      --bg: #f4f1ea;
      --paper: #fffcf7;
      --ink: #1c1917;
      --muted: #57534e;
      --line: #e7e0d4;
      --accent: #9a3412;
      --accent-soft: #ffedd5;
      --code-bg: #1c1917;
      --code-ink: #f5f5f4;
      --nav-w: 18rem;
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      color: var(--ink);
      background: var(--bg);
      font: 16px/1.6 "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
    }}
    a {{ color: var(--accent); }}
    code {{
      font-family: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.88em;
      background: var(--accent-soft);
      padding: 0.08em 0.32em;
      border-radius: 4px;
    }}
    pre {{
      background: var(--code-bg);
      color: var(--code-ink);
      padding: 1rem 1.1rem;
      overflow-x: auto;
      border-radius: 8px;
    }}
    pre code {{ background: none; color: inherit; padding: 0; }}
    .shell {{ display: grid; grid-template-columns: var(--nav-w) 1fr; min-height: 100vh; }}
    .sidebar {{
      background: #1c1917;
      color: #f5f5f4;
      padding: 1.5rem 1.1rem 2rem;
      position: sticky;
      top: 0;
      height: 100vh;
      overflow: auto;
    }}
    .sidebar h1 {{ font-size: 1.05rem; letter-spacing: 0.04em; margin: 0 0 0.35rem; }}
    .sidebar p {{ color: #a8a29e; font-size: 0.85rem; margin: 0 0 1rem; }}
    .sidebar input {{
      width: 100%;
      border: 0;
      border-radius: 6px;
      padding: 0.55rem 0.7rem;
      margin-bottom: 1rem;
      background: #292524;
      color: #fafaf9;
    }}
    .nav-tree, .nav-tree ul {{ list-style: none; padding: 0; margin: 0; }}
    .nav-tree > li {{ margin: 0.45rem 0; }}
    .nav-tree a {{ color: #e7e5e4; text-decoration: none; font-size: 0.92rem; }}
    .nav-tree a:hover {{ color: #fdba74; }}
    .nav-tree ul {{ padding-left: 0.85rem; margin-top: 0.25rem; }}
    .nav-tree ul a {{ color: #a8a29e; font-size: 0.84rem; }}
    .content {{ padding: 0 0 4rem; }}
    .hero {{
      background: linear-gradient(180deg, #9a3412 0%, #7c2d12 100%);
      color: #fff7ed;
      padding: 2.4rem 2.5rem 2rem;
    }}
    .hero .kicker {{
      text-transform: uppercase;
      letter-spacing: 0.14em;
      font-size: 0.72rem;
      opacity: 0.85;
      margin: 0 0 0.4rem;
    }}
    .hero h1 {{ margin: 0; font-size: 2rem; line-height: 1.2; }}
    .doc {{ max-width: 52rem; padding: 2rem 2.5rem; }}
    .doc-section {{
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 1.4rem 1.6rem 1.6rem;
      margin: 0 0 1.25rem;
    }}
    .doc-section h2 {{ margin-top: 0; font-size: 1.45rem; }}
    .doc-sub {{ margin-top: 1.2rem; padding-top: 0.9rem; border-top: 1px solid var(--line); }}
    .doc-sub h3 {{ margin: 0 0 0.5rem; font-size: 1.08rem; }}
    .prose p {{ margin: 0.55rem 0; }}
    .prose ul, .prose ol {{ margin: 0.4rem 0 0.4rem 1.2rem; }}
    .empty {{ color: var(--muted); font-style: italic; }}
    .hidden {{ display: none !important; }}
    @media (max-width: 900px) {{
      .shell {{ grid-template-columns: 1fr; }}
      .sidebar {{ position: relative; height: auto; }}
      .hero, .doc {{ padding-left: 1.1rem; padding-right: 1.1rem; }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <aside class="sidebar">
      <h1>Repository docs</h1>
      <p>Deterministic render of structured analysis. Filter the outline below.</p>
      <input id="filter" type="search" placeholder="Filter sections…" autocomplete="off">
      <nav aria-label="Documentation">{_nav_html()}</nav>
    </aside>
    <div class="content">
      <header class="hero">
        <p class="kicker">Developer documentation</p>
        <h1>Codebase guide</h1>
      </header>
      <main class="doc">
        {main}
      </main>
    </div>
  </div>
  <script>
    (function () {{
      var input = document.getElementById("filter");
      if (!input) return;
      input.addEventListener("input", function () {{
        var q = input.value.toLowerCase().trim();
        document.querySelectorAll(".doc-section, .doc-sub").forEach(function (el) {{
          var title = (el.getAttribute("data-title") || "") + " " + (el.textContent || "");
          el.classList.toggle("hidden", q && title.toLowerCase().indexOf(q) === -1);
        }});
      }});
    }})();
  </script>
</body>
</html>
"""
