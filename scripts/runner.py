from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from migrate_config import Config
from checksum import file_sha256, human_name, version_from_name

logger = logging.getLogger("cyclothone.migrate")


@dataclass(frozen=True)
class Migration:
    version: str
    name: str
    path: Path
    checksum: str
    sql_body: str


@dataclass(frozen=True)
class Plan:
    pending: list[Migration]
    applied: list[tuple[str, str, str]]
    drift: list[tuple[Migration, str]]
    unknown: list[tuple[str, str]]


class MigrationRunner:
    META_FILE = "000_meta.sql"
    ADVISORY_LOCK_KEY = 0xC7C10740

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def _load_migrations(self) -> list[Migration]:
        if not self.cfg.sql_dir.exists():
            raise SystemExit(f"sql dir missing: {self.cfg.sql_dir}")

        migrations: list[Migration] = []
        seen: dict[str, Path] = {}

        for path in sorted(self.cfg.sql_dir.glob("*.sql")):
            if path.name.endswith(".down.sql"):
                continue
            version = version_from_name(path)
            if version in seen:
                raise SystemExit(
                    f"duplicate migration version {version}: "
                    f"{seen[version].name} and {path.name}"
                )
            seen[version] = path
            migrations.append(
                Migration(
                    version=version,
                    name=human_name(path),
                    path=path,
                    checksum=file_sha256(path),
                    sql_body=path.read_text(encoding="utf-8"),
                )
            )

        migrations.sort(key=lambda m: int(m.version))
        return migrations

    def _down_path_for(self, migration: Migration) -> Path:
        return migration.path.with_name(migration.path.stem + ".down.sql")

    def _connect(self) -> psycopg.Connection:
        conn = psycopg.connect(self.cfg.database_url, autocommit=False)
        with conn.cursor() as cur:
            cur.execute("select set_config('statement_timeout', %s, false)", (str(self.cfg.statement_timeout_ms),))
            cur.execute("select set_config('lock_timeout', %s, false)", (str(self.cfg.lock_timeout_ms),))
            cur.execute("select pg_advisory_lock(%s)", (self.ADVISORY_LOCK_KEY,))
        conn.commit()
        return conn

    def _ensure_meta(self, conn: psycopg.Connection) -> None:
        meta = self.cfg.migrations_dir / self.META_FILE
        if not meta.exists():
            raise SystemExit(f"meta migration missing: {meta}")
        with conn.cursor() as cur:
            cur.execute(meta.read_text(encoding="utf-8"))
        conn.commit()

    def _fetch_rows(self, conn: psycopg.Connection) -> list[dict]:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select version, name, checksum, status "
                "from schema_migrations order by version"
            )
            return list(cur.fetchall())

    def _build_plan(self, conn: psycopg.Connection, migrations: list[Migration]) -> Plan:
        rows = self._fetch_rows(conn)
        success = {r["version"]: r for r in rows if r["status"] == "success"}
        files = {m.version: m for m in migrations}

        pending: list[Migration] = []
        applied: list[tuple[str, str, str]] = []
        drift: list[tuple[Migration, str]] = []

        for migration in migrations:
            if migration.version == "000":
                continue
            row = success.get(migration.version)
            if row is None:
                pending.append(migration)
                continue
            applied.append(
                (migration.version, migration.name, migration.checksum)
            )
            if row["checksum"] != migration.checksum:
                drift.append((migration, row["checksum"]))

        unknown = [
            (version, row["name"])
            for version, row in success.items()
            if version not in files
        ]
        return Plan(pending=pending, applied=applied, drift=drift, unknown=unknown)

    @staticmethod
    def _confirm(prompt: str) -> bool:
        try:
            return input(prompt).strip().lower() == "yes"
        except EOFError:
            return False

    def _print_plan(self, plan: Plan) -> None:
        logger.info("applied: %d", len(plan.applied))
        for version, name, _ in plan.applied:
            logger.info("  ✓ %s %s", version, name)

        logger.info("pending: %d", len(plan.pending))
        for migration in plan.pending:
            logger.info("  → %s %s", migration.version, migration.name)

        if plan.drift:
            logger.error("checksum drift: %d", len(plan.drift))
            for migration, stored in plan.drift:
                logger.error(
                    "  ✗ %s expected=%s stored=%s",
                    migration.version,
                    migration.checksum[:16],
                    stored[:16],
                )

        if plan.unknown:
            logger.error("orphan applied rows: %d", len(plan.unknown))
            for version, name in plan.unknown:
                logger.error("  ? %s %s", version, name)

    def run(self, target_version: str | None = None) -> int:
        migrations = self._load_migrations()
        if target_version is not None and not target_version.isdigit():
            raise SystemExit("--target must be numeric")
        target = int(target_version) if target_version else None

        with self._connect() as conn:
            self._ensure_meta(conn)
            plan = self._build_plan(conn, migrations)
            self._print_plan(plan)

            if plan.drift or plan.unknown:
                logger.error("migration integrity check failed")
                return 2

            pending = [
                m for m in plan.pending
                if target is None or int(m.version) <= target
            ]
            if self.cfg.dry_run:
                logger.info("dry-run: %d migration(s) would apply", len(pending))
                return 0
            if not pending:
                logger.info("everything up to date")
                return 0
            if self.cfg.require_confirmation and not self._confirm(
                f"\nApply {len(pending)} migration(s)? type 'yes' to continue: "
            ):
                logger.info("aborted by operator")
                return 1

            for migration in pending:
                if not self._apply(conn, migration):
                    logger.error("migration %s failed — stopping", migration.version)
                    return 3

            logger.info("applied %d migration(s)", len(pending))
            return 0

    def _apply(self, conn: psycopg.Connection, migration: Migration) -> bool:
        logger.info("applying %s — %s", migration.version, migration.name)
        started = time.perf_counter()

        try:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(migration.sql_body)

                    duration_ms = int((time.perf_counter() - started) * 1000)
                    cur.execute(
                        "insert into schema_migrations "
                        "(version, name, checksum, applied_by, duration_ms, status, error) "
                        "values (%s,%s,%s,%s,%s,'success',null) "
                        "on conflict (version) do update set "
                        "name=excluded.name, checksum=excluded.checksum, "
                        "applied_by=excluded.applied_by, applied_at=now(), "
                        "duration_ms=excluded.duration_ms, status='success', error=null",
                        (
                            migration.version,
                            migration.name,
                            migration.checksum,
                            self.cfg.applied_by,
                            duration_ms,
                        ),
                    )
            logger.info("  ✓ %s in %dms", migration.version, duration_ms)
            return True
        except Exception as exc:
            conn.rollback()
            logger.exception("  ✗ %s failed", migration.version)

            try:
                with conn.transaction():
                    with conn.cursor() as cur:
                        cur.execute(
                            "insert into schema_migrations "
                            "(version,name,checksum,applied_by,duration_ms,status,error) "
                            "values (%s,%s,%s,%s,%s,'failed',%s) "
                            "on conflict (version) do update set "
                            "name=excluded.name, checksum=excluded.checksum, "
                            "applied_by=excluded.applied_by, applied_at=now(), "
                            "duration_ms=excluded.duration_ms, status='failed', error=excluded.error",
                            (
                                migration.version,
                                migration.name,
                                migration.checksum,
                                self.cfg.applied_by,
                                int((time.perf_counter() - started) * 1000),
                                str(exc)[:1000],
                            ),
                        )
                return False
            except Exception:
                conn.rollback()
                logger.exception("could not record migration failure")
                return False

    def status(self) -> int:
        migrations = self._load_migrations()
        with self._connect() as conn:
            self._ensure_meta(conn)
            plan = self._build_plan(conn, migrations)
            self._print_plan(plan)
            return 2 if plan.drift or plan.unknown else 0

    def rollback(self, version: str) -> int:
        if not version.isdigit():
            raise SystemExit("version must be numeric")
        with self._connect() as conn:
            self._ensure_meta(conn)
            migrations = {m.version: m for m in self._load_migrations()}
            migration = migrations.get(version.zfill(3))
            if migration is None:
                logger.error("migration %s not found", version)
                return 1

            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "select version,name,checksum,status from schema_migrations "
                    "where version=%s", (migration.version,)
                )
                row = cur.fetchone()

            if not row or row["status"] != "success":
                logger.error("version %s is not successfully applied", migration.version)
                return 1

            down = self._down_path_for(migration)
            if not down.exists():
                logger.error("no rollback file: %s", down.name)
                return 1

            if self.cfg.require_confirmation and not self._confirm(
                f"\nRollback {migration.version} ({migration.name})? type 'yes' to continue: "
            ):
                return 1

            try:
                with conn.transaction():
                    with conn.cursor() as cur:
                        cur.execute(down.read_text(encoding="utf-8"))
                        cur.execute(
                            "update schema_migrations set status='rolled_back', applied_at=now(), error=null "
                            "where version=%s", (migration.version,)
                        )
                logger.info("rolled back %s", migration.version)
                return 0
            except Exception:
                conn.rollback()
                logger.exception("rollback failed")
                return 3
