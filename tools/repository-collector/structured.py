"""Deterministic structured-field sanitizer for JSON and YAML.

Redacts values whose keys look sensitive. Regex sanitization in sanitizer.py
still runs on the dump afterwards. Does not log matched values or call a model.
"""

from __future__ import annotations

import json
import re
from typing import Any

FIELD_PLACEHOLDER = "[REDACTED:field]"

_SENSITIVE_TOKENS = {
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "credentials",
    "authorization",
    "bearer",
    "email",
    "phone",
    "telephone",
    "mobile",
    "ssn",
    "cvv",
    "cvc",
}

_SENSITIVE_PAIRS = {
    ("api", "key"),
    ("access", "key"),
    ("private", "key"),
    ("secret", "key"),
    ("account", "number"),
    ("card", "number"),
    ("client", "secret"),
    ("auth", "token"),
    ("access", "token"),
    ("refresh", "token"),
    ("session", "token"),
    ("id", "token"),
    ("customer", "email"),
}

_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_ACRONYM = re.compile(r"([A-Z]+)([A-Z][a-z])")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")
_YAML_LINE = re.compile(
    r"^([ \t]*)(-[ \t]+)?([\"']?)([A-Za-z0-9_.-]+)([\"']?)(\s*:)(\s*)(.*)$"
)
_FLOW_KEY = re.compile(r"(?P<q>[\"']?)(?P<key>[A-Za-z0-9_.-]+)(?P=q)\s*:")
_BLOCK_INDICATOR = re.compile(r"^[|>][+-]?\d*$")


def is_sensitive_key(name: str) -> bool:
    tokens = _tokenize(name)
    if not tokens:
        return False
    if any(token in _SENSITIVE_TOKENS for token in tokens):
        return True
    if any(pair in _SENSITIVE_PAIRS for pair in zip(tokens, tokens[1:])):
        return True
    joined = "".join(tokens)
    return joined in {"apikey", "passwd"} or any(
        joined.endswith(token) for token in ("password", "passwd", "secret", "token")
    )


def sanitize_structured(path: str, text: str) -> str:
    """Redact sensitive fields in JSON/YAML file text. Other files are unchanged."""
    if not text:
        return text
    kind = _kind(path)
    if kind == "json":
        return _sanitize_json(text)
    if kind == "yaml":
        return _sanitize_yaml(text)
    return text


def _kind(path: str) -> str | None:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.endswith(".json"):
        return "json"
    if name.endswith((".yaml", ".yml")):
        return "yaml"
    return None


def _tokenize(name: str) -> tuple[str, ...]:
    split = _CAMEL.sub(r"\1_\2", name)
    split = _ACRONYM.sub(r"\1_\2", split)
    split = _NON_ALNUM.sub("_", split)
    return tuple(part.lower() for part in split.split("_") if part)


def _walk(value: Any, parent_sensitive: bool = False) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, child in value.items():
            sensitive = parent_sensitive or (isinstance(key, str) and is_sensitive_key(key))
            if sensitive and not isinstance(child, (dict, list)):
                out[key] = FIELD_PLACEHOLDER
            else:
                out[key] = _walk(child, sensitive)
        return out
    if isinstance(value, list):
        return [_walk(item, parent_sensitive) for item in value]
    if parent_sensitive:
        return FIELD_PLACEHOLDER
    return value


def _sanitize_json(text: str) -> str:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return text
    if not isinstance(parsed, (dict, list)):
        return text
    cleaned = _walk(parsed)
    trailing = "\n" if text.endswith("\n") else ""
    return json.dumps(cleaned, indent=2, ensure_ascii=False) + trailing


def _sanitize_yaml(text: str) -> str:
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        json_cleaned = _sanitize_json(text)
        if json_cleaned != text:
            return json_cleaned
    return _sanitize_yaml_lines(text)


def _sanitize_yaml_lines(text: str) -> str:
    newline = "\n" if "\n" in text else "\n"
    ends_with_newline = text.endswith(("\n", "\r\n"))
    lines = text.splitlines()
    out: list[str] = []
    skip_until_indent: int | None = None
    for line in lines:
        indent = _indent(line)
        if skip_until_indent is not None:
            if line.strip() == "" or indent > skip_until_indent:
                continue
            skip_until_indent = None
        replaced = _redact_yaml_line(line)
        out.append(replaced)
        match = _YAML_LINE.match(line.rstrip("\r\n"))
        if not match:
            continue
        key = match.group(4)
        raw_value = match.group(8).strip()
        if is_sensitive_key(key) and _BLOCK_INDICATOR.match(raw_value.split("#", 1)[0].strip()):
            skip_until_indent = indent
    result = newline.join(out)
    if ends_with_newline:
        result += newline
    return result


def _redact_yaml_line(line: str) -> str:
    match = _YAML_LINE.match(line.rstrip("\r\n"))
    if not match:
        return _redact_flow(line)
    prefix, dash, q1, key, q2, colon, space, rest = match.groups()
    if q1 != q2:
        return _redact_flow(line)
    if not is_sensitive_key(key):
        return _redact_flow(line)
    value = rest.strip()
    if not value or value.startswith("#"):
        return line
    if _BLOCK_INDICATOR.match(value.split("#", 1)[0].strip()):
        return f"{prefix}{dash or ''}{q1}{key}{q2}{colon}{space or ' '}{FIELD_PLACEHOLDER}"
    if value[:1] in "{[":
        return f"{prefix}{dash or ''}{q1}{key}{q2}{colon}{space or ' '}{FIELD_PLACEHOLDER}"
    return f"{prefix}{dash or ''}{q1}{key}{q2}{colon}{space or ' '}{FIELD_PLACEHOLDER}"


def _redact_flow(text: str) -> str:
    out: list[str] = []
    pos = 0
    for match in _FLOW_KEY.finditer(text):
        if not is_sensitive_key(match.group("key")):
            continue
        value_at = match.end()
        while value_at < len(text) and text[value_at] in " \t":
            value_at += 1
        value_end = _scalar_end(text, value_at)
        out.append(text[pos:value_at])
        out.append(FIELD_PLACEHOLDER)
        pos = value_end
    out.append(text[pos:])
    return "".join(out)


def _scalar_end(text: str, start: int) -> int:
    if start >= len(text):
        return start
    quote = text[start]
    if quote in "\"'":
        i = start + 1
        while i < len(text):
            if text[i] == "\\" and quote == '"':
                i += 2
                continue
            if text[i] == quote:
                return i + 1
            i += 1
        return len(text)
    i = start
    while i < len(text) and text[i] not in ",#}]\n":
        i += 1
    return i


def _indent(line: str) -> int:
    stripped = line.lstrip(" \t")
    return len(line) - len(stripped)
