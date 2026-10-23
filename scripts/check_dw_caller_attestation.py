#!/usr/bin/env python3
"""Blocking DW trust lint: caller-attested booleans and evidence-policy drift."""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "supabase" / "migrations"
FUNC_START = re.compile(
    r"create\s+(?:or\s+replace\s+)?function\s+([\w.]+)\s*\((.*?)\)\s*",
    re.IGNORECASE | re.DOTALL,
)
DROP_FUNC = re.compile(r"drop\s+function\s+(?:if\s+exists\s+)?([\w.]+)\s*\(", re.I)
SUSPECT = re.compile(
    r"\b(?:p_)?[a-z_]*(?:verified|proof|attested|corroborated|provenance_match|route_verified)"
    r"[a-z_]*\s+boolean\b",
    re.IGNORECASE,
)
CREATE_TABLE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?([a-z_][a-z0-9_]*)",
    re.IGNORECASE,
)
POLICY_ROW = re.compile(
    r"\(\s*'(dw_[a-z0-9_]+)'\s*,\s*(?:true|false)\s*,\s*array\s*\[",
    re.IGNORECASE,
)
POLICY_TABLE_PATTERNS = (
    re.compile(r"^dw_.*evidence.*$", re.I),
    re.compile(r"^dw_.*proofs$", re.I),
    re.compile(r"^dw_.*events$", re.I),
    re.compile(r"^dw_trust_.*$", re.I),
    re.compile(r"^dw_.*_(?:health|integrity|fingerprints|embeddings|credentials|assignments|pins|observations|translations|extractions)$", re.I),
    re.compile(r"^dw_discovery_.*$", re.I),
    re.compile(r"^dw_entity_.*$", re.I),
    re.compile(r"^dw_entities$", re.I),
    re.compile(r"^dw_content_.*$", re.I),
    re.compile(r"^dw_sanitized_.*$", re.I),
    re.compile(r"^dw_merkle_.*$", re.I),
)

def main() -> int:
    files = sorted(MIGRATIONS.rglob("*.sql"))
    source_by_file = [(p, p.read_text(encoding="utf-8", errors="replace")) for p in files]
    findings: list[str] = []
    function_findings: list[tuple[str, str]] = []
    dropped_names: set[str] = set()

    # Process in migration order; a later DROP removes the legacy signature from
    # the effective API surface. Findings return nonzero and fail CI.
    for path, source in source_by_file:
        for match in FUNC_START.finditer(source):
            name, args = match.group(1), match.group(2)
            suspects = [part.strip() for part in args.split(",") if SUSPECT.search(part)]
            if suspects:
                line = source.count("\n", 0, match.start()) + 1
                function_findings.append((
                    name.lower(),
                    f"{path.relative_to(ROOT)}:{line}: {name}: caller-attestation-shaped boolean(s): "
                    + ", ".join(suspects),
                ))
        for match in DROP_FUNC.finditer(source):
            dropped_names.add(match.group(1).lower())

    findings.extend(message for name, message in function_findings if name not in dropped_names)

    all_sql = "\n".join(source for _, source in source_by_file)
    registered = {m.group(1).lower() for m in POLICY_ROW.finditer(all_sql)}
    created: set[str] = set()
    for _, source in source_by_file:
        for match in CREATE_TABLE.finditer(source):
            name = match.group(1).lower()
            if any(pattern.fullmatch(name) for pattern in POLICY_TABLE_PATTERNS):
                created.add(name)
    for name in sorted(created - registered):
        findings.append(
            f"policy registry drift: {name} is created by a migration but has no dw_table_security_policy row"
        )

    if findings:
        print("DW TRUST LINT FAILED:", file=sys.stderr)
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("No active caller-attestation booleans or evidence/proof policy-registry drift found.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
