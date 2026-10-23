#!/usr/bin/env python3
"""Warn on caller-attested boolean parameters in PostgreSQL function migrations.

Initial rollout is warning-only. This intentionally scans all functions, not only
SECURITY DEFINER functions: SECURITY INVOKER RPCs can still trust forged claims.
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "supabase" / "migrations"
FUNC_START = re.compile(
    r"create\s+or\s+replace\s+function\s+([\w.]+)\s*\((.*?)\)\s*",
    re.IGNORECASE | re.DOTALL,
)
SUSPECT = re.compile(
    r"\b(?:p_)?[a-z_]*(?:verified|proof|attested|corroborated|provenance_match|route_verified)"
    r"[a-z_]*\s+boolean\b",
    re.IGNORECASE,
)

def main() -> int:
    findings: list[str] = []
    for path in sorted(MIGRATIONS.rglob("*.sql")):
        source = path.read_text(encoding="utf-8", errors="replace")
        for match in FUNC_START.finditer(source):
            name, args = match.group(1), match.group(2)
            suspects = [part.strip() for part in args.split(",") if SUSPECT.search(part)]
            if suspects:
                line = source.count("\n", 0, match.start()) + 1
                findings.append(
                    f"{path.relative_to(ROOT)}:{line}: {name}: caller-attestation-shaped boolean(s): "
                    + ", ".join(suspects)
                )
    if findings:
        print("CALLER-ATTESTATION SUSPECTED (warning-only rollout):", file=sys.stderr)
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("No caller-attestation-shaped boolean parameters found.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
