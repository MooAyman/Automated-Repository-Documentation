"""Optional Local LLM detector for extra sensitive-span findings.

Disabled by default. Receives already deterministic-sanitized text and returns
structured detections only. This module never trusts model-produced redactions;
our code applies start/end masking. Failures fall back to the input text.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
_TRUTHY = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Detection:
    type: str
    start: int
    end: int


class LocalLLMDetector:
    """HTTP client for a company Local LLM detection endpoint.

    Expected request:  POST {url}  JSON {"text": "<already sanitized>"}
    Expected response: JSON {"detections": [{"type": "secret", "start": 0, "end": 4}, ...]}
    Extra fields such as replacement text are ignored.
    """

    def __init__(
        self,
        enabled: bool = False,
        url: str = "",
        timeout: float = 3.0,
    ) -> None:
        self.enabled = bool(enabled) and bool((url or "").strip())
        self.url = (url or "").strip()
        self.timeout = timeout if timeout > 0 else 3.0

    @classmethod
    def from_env(cls) -> "LocalLLMDetector":
        raw_timeout = os.environ.get("LOCAL_LLM_TIMEOUT_SECONDS", "3").strip()
        try:
            timeout = float(raw_timeout)
        except ValueError:
            timeout = 3.0
        return cls(
            enabled=_env_enabled("LOCAL_LLM_ENABLED"),
            url=os.environ.get("LOCAL_LLM_URL", ""),
            timeout=timeout,
        )

    def detect(self, text: str) -> list[Detection]:
        """Return validated span detections, or [] if unused/unavailable/invalid."""
        if not self.enabled or not text:
            return []
        try:
            payload = json.dumps({"text": text}, ensure_ascii=False).encode("utf-8")
            request = urllib.request.Request(
                self.url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
            parsed = json.loads(raw.decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
            return []
        except Exception:
            return []
        return parse_detections(parsed, len(text))


def parse_detections(payload: object, text_length: int) -> list[Detection]:
    if isinstance(payload, dict):
        items = payload.get("detections")
    else:
        items = payload
    if not isinstance(items, list):
        return []
    detections: list[Detection] = []
    for item in items:
        parsed = _parse_one(item, text_length)
        if parsed is not None:
            detections.append(parsed)
    return detections


def apply_detections(text: str, detections: list[Detection]) -> str:
    """Mask spans in `text`. Overlaps keep the earlier span. Never uses model text."""
    if not text or not detections:
        return text
    kept: list[Detection] = []
    for det in sorted(detections, key=lambda item: (item.start, -item.end)):
        if det.start < 0 or det.end > len(text) or det.start >= det.end:
            continue
        if kept and det.start < kept[-1].end:
            continue
        kept.append(det)
    result = text
    for det in reversed(kept):
        result = result[: det.start] + _placeholder(det.type) + result[det.end :]
    return result


def augment(text: str, detector: LocalLLMDetector | None = None) -> str:
    """Apply optional Local LLM detections to already-sanitized text."""
    if not text:
        return text
    client = detector if detector is not None else LocalLLMDetector.from_env()
    if not client.enabled:
        return text
    detections = client.detect(text)
    if not detections:
        return text
    return apply_detections(text, detections)


def _parse_one(item: object, text_length: int) -> Detection | None:
    if not isinstance(item, dict):
        return None
    try:
        start = int(item["start"])
        end = int(item["end"])
    except (KeyError, TypeError, ValueError):
        return None
    if start < 0 or end > text_length or start >= end:
        return None
    kind = str(item.get("type") or "llm")
    if not _TYPE_RE.match(kind):
        kind = "llm"
    return Detection(type=kind, start=start, end=end)


def _placeholder(kind: str) -> str:
    return f"[REDACTED:{kind}]"


def _env_enabled(name: str) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return False
    return raw.strip().lower() in _TRUTHY
