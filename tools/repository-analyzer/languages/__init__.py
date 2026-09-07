"""Language analyzers.

Only programming-language analyzers belong here. JSON/YAML are not analyzed.
Register a new suffix and analyzer class to add a language later.
"""

from __future__ import annotations

from .python import PythonAnalyzer

PYTHON = "python"

ANALYZERS = {
    PYTHON: PythonAnalyzer(),
}

SUFFIXES = {
    ".py": PYTHON,
}


def language_for(path: str) -> str | None:
    lowered = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if "." not in lowered:
        return None
    suffix = "." + lowered.rsplit(".", 1)[-1]
    return SUFFIXES.get(suffix)
