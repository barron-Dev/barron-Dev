from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from checksum import file_sha256, human_name, version_from_name
from migrate_config import Config
from runner import MigrationRunner


def _config(tmp_path: Path) -> Config:
    sql_dir = tmp_path / "sql"
    migrations_dir = tmp_path / "scripts" / "migrations"
    sql_dir.mkdir(parents=True)
    migrations_dir.mkdir(parents=True)
    return Config(
        database_url="postgresql://example.invalid/db",
        sql_dir=sql_dir,
        migrations_dir=migrations_dir,
        require_confirmation=False,
        statement_timeout_ms=60000,
        lock_timeout_ms=10000,
        dry_run=False,
        verbose=False,
        applied_by="test",
    )


def test_version_and_name_parsing(tmp_path: Path):
    p = tmp_path / "073_mission_graphs.sql"
    p.write_text("select 1;\n", encoding="utf-8")
    assert version_from_name(p) == "073"
    assert human_name(p) == "mission graphs"
    assert len(file_sha256(p)) == 64


def test_down_files_are_not_loaded(tmp_path: Path):
    cfg = _config(tmp_path)
    (cfg.sql_dir / "073_mission_graphs.sql").write_text("select 1;", encoding="utf-8")
    (cfg.sql_dir / "073_mission_graphs.down.sql").write_text("select 2;", encoding="utf-8")
    runner = MigrationRunner(cfg)
    migrations = runner._load_migrations()
    assert [m.version for m in migrations] == ["073"]


def test_duplicate_versions_fail_closed(tmp_path: Path):
    cfg = _config(tmp_path)
    (cfg.sql_dir / "051_alpha.sql").write_text("select 1;", encoding="utf-8")
    (cfg.sql_dir / "051_beta.sql").write_text("select 2;", encoding="utf-8")
    with pytest.raises(SystemExit, match="duplicate migration version"):
        MigrationRunner(cfg)._load_migrations()


def test_versions_sort_numerically(tmp_path: Path):
    cfg = _config(tmp_path)
    for name in ("099_late.sql", "100_next.sql", "9_old.sql"):
        (cfg.sql_dir / name).write_text("select 1;", encoding="utf-8")
    versions = [m.version for m in MigrationRunner(cfg)._load_migrations()]
    assert versions == ["009", "099", "100"]


def test_missing_sql_dir_fails_closed(tmp_path: Path):
    cfg = _config(tmp_path)
    cfg.sql_dir.rmdir()
    with pytest.raises(SystemExit, match="sql dir missing"):
        MigrationRunner(cfg)._load_migrations()
