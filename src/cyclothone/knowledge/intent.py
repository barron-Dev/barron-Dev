from __future__ import annotations

import re
from dataclasses import dataclass


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (kind, re.compile(pattern, re.IGNORECASE))
    for kind, pattern in (
        ("api", r"\b(api|endpoint|rest|sdk|curl|webhook|integration)\b"),
        ("pricing", r"\b(price|pricing|cost|plan|subscription|license|billing|quote|invoice)\b"),
        ("guide", r"\b(how|guide|tutorial|steps|setup|install|walkthrough|configure)\b"),
        ("concept", r"\b(what|explain|understand|mean|definition)\b"),
        ("partner", r"\b(partner|mssp|reseller|affiliate|channel)\b"),
        ("defense", r"\b(defense|gated|restricted|classified|military|sovereign)\b"),
        ("action", r"\b(enable|disable|deploy|configure|set up|turn on|turn off|isolate|block)\b"),
        ("support", r"\b(help|broken|error|bug|down|fail|ticket|issue|not working)\b"),
    )
)


@dataclass(frozen=True, slots=True)
class Intent:
    kind: str
    confidence: float
    matched: tuple[str, ...]


def classify(query: str) -> Intent:
    q = (query or "").strip()
    if not q:
        return Intent("unknown", 0.0, ())

    scores: dict[str, int] = {}
    matched: dict[str, list[str]] = {}
    for kind, pattern in _PATTERNS:
        hits = pattern.findall(q)
        if hits:
            scores[kind] = len(hits)
            matched[kind] = [str(hit) for hit in hits]

    if not scores:
        return Intent("unknown", 0.0, ())

    order = {kind: i for i, (kind, _) in enumerate(_PATTERNS)}
    best = max(scores, key=lambda kind: (scores[kind], -order[kind]))
    total = sum(scores.values())
    return Intent(
        best,
        round(scores[best] / max(total, 1), 3),
        tuple(matched[best]),
    )
