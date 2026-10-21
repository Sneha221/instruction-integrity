"""Small, explainable input-side prompt-injection scanners.

These scanners are experimental baselines, not security boundaries.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass


PATTERNS = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "forget your instructions",
    "reveal the system prompt",
    "reveal the secret",
    "print the secret",
    "output the secret",
    "send the secret",
    "you are now",
    "new system prompt",
    "system override",
    "developer message",
    "act as the system",
)

ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
# A deliberately small homoglyph map; Unicode confusables are much broader.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "і": "i", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "Α": "a", "Β": "b", "Ε": "e", "Ι": "i",
    "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t",
    "Χ": "x",
})


@dataclass(frozen=True)
class ScanResult:
    flagged: bool
    matches: tuple[str, ...]


def normalize(text: str) -> str:
    """Apply NFKC, remove common invisible marks and map selected homoglyphs."""
    text = unicodedata.normalize("NFKC", text).translate(CONFUSABLES)
    text = "".join(ch for ch in text if ch not in ZERO_WIDTH)
    return " ".join(text.casefold().split())


def scan(text: str, mode: str = "keyword") -> ScanResult:
    """Return matched phrases for none, keyword, or normalized scanner mode."""
    if mode not in {"none", "keyword", "normalized"}:
        raise ValueError(f"unknown scanner mode: {mode}")
    if mode == "none":
        return ScanResult(False, ())
    haystack = " ".join(text.casefold().split()) if mode == "keyword" else normalize(text)
    hits = tuple(pattern for pattern in PATTERNS if pattern in haystack)
    return ScanResult(bool(hits), hits)
