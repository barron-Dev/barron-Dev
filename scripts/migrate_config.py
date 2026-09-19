from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Config:
    database_url: str
    sql_dir: Path
    migrations_dir: Path
    require_confirmation: bool
    statement_timeout_ms: int
    lock_timeout_ms: int
    dry_run: bool
    verbose: bool
    applied_by: str


def load_config(*, dry_run: bool = False, verbose: bool = False) -> Config:
    url = (
        os.getenv("SUPABASE_DB_URL")
        or os.getenv("DATABASE_URL")
        or os.getenv("POSTGRES_URL")
    )
    if not url:
        raise SystemExit(
            "SUPABASE_DB_URL (or DATABASE_URL/POSTGRES_URL) is required."
        )

    parsed = urlsplit(url)
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise SystemExit("database URL must use postgresql:// or postgres://")

    root = Path(__file__).resolve().parent.parent
    timeout = int(os.getenv("MIGRATE_STATEMENT_TIMEOUT_MS", "60000"))
    lock_timeout = int(os.getenv("MIGRATE_LOCK_TIMEOUT_MS", "10000"))
    if timeout <= 0 or lock_timeout <= 0:
        raise SystemExit("migration timeouts must be positive")

    return Config(
        database_url=url,
        sql_dir=root / "sql",
        migrations_dir=root / "scripts" / "migrations",
        require_confirmation=os.getenv("MIGRATE_REQUIRE_CONFIRM", "1") == "1",
        statement_timeout_ms=timeout,
        lock_timeout_ms=lock_timeout,
        dry_run=dry_run,
        verbose=verbose,
        applied_by=os.getenv(
            "MIGRATE_APPLIED_BY",
            f"{os.getenv('USER', 'unknown')}@{os.getenv('HOSTNAME', 'unknown')}",
        ),
    )
