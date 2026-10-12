from __future__ import annotations

from pathlib import Path

import pytest

from cyclothone.darkweb.pullers import Finding
from cyclothone.darkweb.request_worker import (
    _checkpoint_finding,
    _restore_checkpoint_finding,
)


ROOT = Path(__file__).resolve().parents[1]


def test_checkpoint_finding_round_trip_preserves_only_normalized_finding_fields():
    finding = Finding(
        source_id="telegram_public",
        kind="email",
        matched_value="person@example.com",
        context="Identifier appeared in a public channel.",
        severity="high",
        source_url="https://t.me/s/publicchannel",
        metadata={"channel": "publicchannel"},
    )

    restored = _restore_checkpoint_finding(_checkpoint_finding(finding))

    assert restored == finding


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"source_id": "telegram_public"},
        {
            "source_id": "telegram_public",
            "kind": "email",
            "matched_value": "person@example.com",
            "severity": "high",
            "metadata": [],
        },
        {
            "source_id": "telegram_public",
            "kind": "email",
            "matched_value": "person@example.com",
            "severity": "high",
            "context": 42,
        },
    ],
)
def test_checkpoint_restore_rejects_malformed_entries(payload):
    with pytest.raises(ValueError, match="invalid_darkweb_checkpoint_finding"):
        _restore_checkpoint_finding(payload)


def test_checkpoint_migration_uses_private_table_and_fenced_service_role_rpc():
    sql = (
        ROOT / "sql" / "20261012120000_darkweb_durable_source_checkpoints.sql"
    ).read_text(encoding="utf-8").lower()

    assert "create table if not exists public.service_request_execution_checkpoints" in sql
    assert "alter table public.service_request_execution_checkpoints enable row level security" in sql
    assert "revoke all on table public.service_request_execution_checkpoints from public, anon, authenticated" in sql
    assert "create or replace function public.checkpoint_service_request(" in sql
    assert "and processing_state = 'running'" in sql
    assert "and attempts = p_attempt" in sql
    assert "and locked_until > now()" in sql
    assert "pg_column_size(p_checkpoint) > 1048576" in sql
    assert "grant execute on function public.checkpoint_service_request(uuid,integer,jsonb,integer) to service_role" in sql


def test_terminal_completion_clears_checkpoint_only_after_fenced_update():
    sql = (
        ROOT / "sql" / "20261012120000_darkweb_durable_source_checkpoints.sql"
    ).read_text(encoding="utf-8").lower()

    assert "completed := found;" in sql
    assert "if completed then" in sql
    assert "delete from public.service_request_execution_checkpoints" in sql
    assert "return completed;" in sql
