"""Deterministic regex sanitizer for collector dumps.

Redacts high-confidence secrets and PII in dump text before it is returned
to an Agent. Does not log matched values. Filename/suffix filtering stays
in collector.py; this module does not call a model.
"""

from __future__ import annotations

import re

REDACTED = {
    "private-key": "[REDACTED:private-key]",
    "jwt": "[REDACTED:jwt]",
    "aws-access-key": "[REDACTED:aws-access-key]",
    "github-pat": "[REDACTED:github-pat]",
    "gitlab-pat": "[REDACTED:gitlab-pat]",
    "google-api-key": "[REDACTED:google-api-key]",
    "slack-token": "[REDACTED:slack-token]",
    "stripe-key": "[REDACTED:stripe-key]",
    "openai-key": "[REDACTED:openai-key]",
    "bearer-token": "[REDACTED:bearer-token]",
    "password": "[REDACTED:password]",
    "email": "[REDACTED:email]",
    "phone": "[REDACTED:phone]",
    "card": "[REDACTED:card]",
    "ssn": "[REDACTED:ssn]",
}

# Specific patterns first so a later generic match cannot see the original value.
_SIMPLE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----"
            r".*?"
            r"-----END (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----",
            re.DOTALL,
        ),
        REDACTED["private-key"],
    ),
    (
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
        REDACTED["jwt"],
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        REDACTED["aws-access-key"],
    ),
    (
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        REDACTED["github-pat"],
    ),
    (
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        REDACTED["github-pat"],
    ),
    (
        re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        REDACTED["gitlab-pat"],
    ),
    (
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        REDACTED["google-api-key"],
    ),
    (
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        REDACTED["slack-token"],
    ),
    (
        re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        REDACTED["stripe-key"],
    ),
    (
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        REDACTED["openai-key"],
    ),
    (
        re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b"),
        REDACTED["openai-key"],
    ),
    (
        re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9]{40,}(?![A-Za-z0-9_-])"),
        REDACTED["openai-key"],
    ),
    (
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+=/]{24,}"),
        REDACTED["bearer-token"],
    ),
    (
        re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+):([^@\s]+)@"),
        r"\1:" + REDACTED["password"] + "@",
    ),
    (
        re.compile(
            r"(?<![A-Za-z0-9._%+-])"
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
            r"(?![A-Za-z0-9.-])"
            r"(?!:)"
        ),
        REDACTED["email"],
    ),
    (
        re.compile(r"\+[1-9](?:[\s.-]?\d){7,14}\b"),
        REDACTED["phone"],
    ),
    (
        re.compile(r"\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b"),
        REDACTED["phone"],
    ),
    (
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        REDACTED["ssn"],
    ),
)

_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def sanitize(text: str) -> str:
    """Return `text` with high-confidence secrets and PII replaced.

    Deterministic: the same input always yields the same output. Matched
    values are never written to logs.
    """
    if not text:
        return text
    result = text
    for pattern, replacement in _SIMPLE_PATTERNS:
        result = pattern.sub(replacement, result)
    return _redact_cards(result)


def _luhn_ok(digits: str) -> bool:
    total = 0
    double = False
    for char in reversed(digits):
        n = ord(char) - 48
        if double:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        double = not double
    return total % 10 == 0


def _looks_like_pan(digits: str) -> bool:
    if digits.startswith("4") and len(digits) in (13, 16, 19):
        return True
    if digits.startswith(("34", "37")) and len(digits) == 15:
        return True
    if digits.startswith(tuple(str(n) for n in range(51, 56))) and len(digits) == 16:
        return True
    if len(digits) == 16 and digits.startswith("22") and 2221 <= int(digits[:4]) <= 2720:
        return True
    if digits.startswith(("6011", "65")) and len(digits) == 16:
        return True
    return False


def _redact_cards(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits) and _looks_like_pan(digits):
            return REDACTED["card"]
        return match.group(0)

    return _CARD_RE.sub(repl, text)
