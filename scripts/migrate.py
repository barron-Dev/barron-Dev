#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import sys

from migrate_config import load_config
from runner import MigrationRunner


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="migrate",
        description="Cyclothone PostgreSQL/Supabase migration runner",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    up = sub.add_parser("up", help="apply pending migrations")
    up.add_argument("--target", help="apply only through this numeric version")
    up.add_argument("--yes", action="store_true")
    up.add_argument("--dry-run", action="store_true")
    up.add_argument("--verbose", action="store_true")

    down = sub.add_parser("down", help="rollback one migration with a .down.sql")
    down.add_argument("version")
    down.add_argument("--yes", action="store_true")
    down.add_argument("--verbose", action="store_true")

    status = sub.add_parser("status", help="show migration state and drift")
    status.add_argument("--verbose", action="store_true")

    return parser.parse_args()


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> int:
    args = parse_args()
    setup_logging(getattr(args, "verbose", False))

    cfg = load_config(
        dry_run=getattr(args, "dry_run", False),
        verbose=getattr(args, "verbose", False),
    )

    if getattr(args, "yes", False):
        object.__setattr__(cfg, "require_confirmation", False)

    runner = MigrationRunner(cfg)

    if args.cmd == "up":
        return runner.run(args.target)
    if args.cmd == "down":
        return runner.rollback(args.version)
    if args.cmd == "status":
        return runner.status()
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
