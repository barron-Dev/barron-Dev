from __future__ import annotations

"""Deterministic lexical signals for brand-domain discovery.

These functions produce reproducible candidate evidence. They never assert that
a domain is malicious: registration, DNS, TLS, page content and brand authority
must be independently established before a threat can be verified.
"""

import hashlib
import unicodedata
from urllib.parse import urlsplit

_CONFUSABLES = {
    "а": "a", "ɑ": "a", "α": "a", "в": "b", "Ь": "b",
    "с": "c", "ϲ": "c", "ԁ": "d", "е": "e", "ε": "e", "℮": "e",
    "ғ": "f", "ɡ": "g", "һ": "h", "і": "i", "ι": "i", "ј": "j",
    "κ": "k", "ӏ": "l", "ո": "n", "м": "m", "ո": "n",
    "о": "o", "ο": "o", "օ": "o", "р": "p", "ρ": "p",
    "զ": "q", "г": "r", "ѕ": "s", "τ": "t", "υ": "u",
    "ν": "v", "х": "x", "χ": "x", "у": "y", "γ": "y",
    "ᴢ": "z",
}

_KEYBOARD = {
    "q": (0, 0), "w": (1, 0), "e": (2, 0), "r": (3, 0), "t": (4, 0),
    "y": (5, 0), "u": (6, 0), "i": (7, 0), "o": (8, 0), "p": (9, 0),
    "a": (0.5, 1), "s": (1.5, 1), "d": (2.5, 1), "f": (3.5, 1),
    "g": (4.5, 1), "h": (5.5, 1), "j": (6.5, 1), "k": (7.5, 1),
    "l": (8.5, 1), "z": (1, 2), "x": (2, 2), "c": (3, 2),
    "v": (4, 2), "b": (5, 2), "n": (6, 2), "m": (7, 2),
}


def normalize_domain(value: str) -> str:
    """Return a stable Unicode skeleton for a host/domain input."""
    raw = (value or "").strip()
    if not raw:
        raise ValueError("domain is required")
    parsed = urlsplit(raw if "://" in raw else "//" + raw)
    host = (parsed.hostname or "").rstrip(".").casefold()
    if not host:
        raise ValueError("domain host is invalid")
    host = unicodedata.normalize("NFKC", host)
    try:
        # Decode IDNs so confusable mapping operates on the actual Unicode label.
        host = host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeEncodeError):
        pass
    host = unicodedata.normalize("NFKC", host).casefold()
    return "".join(_CONFUSABLES.get(ch, ch) for ch in host)


def damerau_levenshtein(left: str, right: str) -> int:
    """Optimal-string-alignment Damerau-Levenshtein distance."""
    a, b = normalize_domain(left), normalize_domain(right)
    rows, cols = len(a) + 1, len(b) + 1
    d = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        d[i][0] = i
    for j in range(cols):
        d[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,
                d[i][j - 1] + 1,
                d[i - 1][j - 1] + cost,
            )
            if (
                i > 1 and j > 1
                and a[i - 1] == b[j - 2]
                and a[i - 2] == b[j - 1]
            ):
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def keyboard_substitution_cost(left: str, right: str) -> float:
    """Sum physical QWERTY key distances for aligned substitutions."""
    a, b = normalize_domain(left), normalize_domain(right)
    total = 0.0
    for x, y in zip(a, b):
        if x == y:
            continue
        if x in _KEYBOARD and y in _KEYBOARD:
            px, py = _KEYBOARD[x], _KEYBOARD[y]
            total += ((px[0] - py[0]) ** 2 + (px[1] - py[1]) ** 2) ** 0.5
        else:
            total += 3.0
    total += 3.0 * abs(len(a) - len(b))
    return round(total, 4)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compare_domains(brand_domain: str, observed_domain: str) -> dict[str, object]:
    """Return reproducible lexical evidence; state is always candidate."""
    brand = normalize_domain(brand_domain)
    observed = normalize_domain(observed_domain)
    distance = damerau_levenshtein(brand, observed)
    return {
        "brand_skeleton": brand,
        "observed_skeleton": observed,
        "damerau_levenshtein": distance,
        "keyboard_substitution_cost": keyboard_substitution_cost(brand, observed),
        "exact_skeleton_match": brand == observed,
        "verification_state": "candidate",
        "verification_reason": "lexical_similarity_is_not_proof_of_impersonation",
    }
