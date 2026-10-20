#!/usr/bin/env python3
"""Validate a CSV and write a local-only staging JSON envelope."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cyclothone.asset_posture.dataset_ingest import parse_asset_posture_csv


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", type=Path, help="path to the source CSV (not uploaded anywhere)")
    parser.add_argument("--output", type=Path, required=True, help="local staging JSON output path")
    parser.add_argument("--source-label", default="user_upload", help="provenance label; no source authenticity implied")
    args = parser.parse_args()

    source = args.csv_path.read_text(encoding="utf-8-sig")
    envelope = parse_asset_posture_csv(source, source_label=args.source_label)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"Staged {envelope['record_count']} normalized observations locally; "
        "production writes=0, live checks claimed=0, coverage claimed=0."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
