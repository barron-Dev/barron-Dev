from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def _sql(name: str) -> str:
    return (ROOT / "sql" / name).read_text(encoding="utf-8")


def test_final_darkweb_migration_removes_unfenced_completion_overload():
    sql = _sql("20261010010000_darkweb_release_contract.sql").lower()

    assert "drop function if exists public.complete_service_request(uuid,text,text,jsonb,text)" in sql
    assert "drop function if exists public.complete_service_request(uuid,integer,text,text,jsonb,text)" in sql
    assert re.search(
        r"create or replace function public\.complete_service_request\s*\(\s*"
        r"p_id uuid,\s*p_attempt integer,\s*p_state text,\s*p_status text,\s*"
        r"p_result jsonb,\s*p_failure_code text default null\s*\) returns boolean",
        sql,
    )
    assert "and processing_state = 'running'" in sql
    assert "and attempts = p_attempt" in sql
    assert "and locked_until > now()" in sql
    assert "return found;" in sql


def test_darkweb_completion_and_sweeper_are_service_role_only():
    sql = _sql("20261010010000_darkweb_release_contract.sql").lower()

    assert "create or replace function public.sweep_expired_service_requests()" in sql
    assert "revoke all on function public.complete_service_request(uuid,integer,text,text,jsonb,text) from public, anon, authenticated" in sql
    assert "revoke all on function public.sweep_expired_service_requests() from public, anon, authenticated" in sql
    assert "grant execute on function public.complete_service_request(uuid,integer,text,text,jsonb,text) to service_role" in sql
    assert "grant execute on function public.sweep_expired_service_requests() to service_role" in sql


def test_api_lifespan_starts_and_stops_darkweb_request_worker():
    app = (ROOT / "src" / "cyclothone" / "api" / "app.py").read_text(encoding="utf-8")

    assert "from cyclothone.darkweb.request_worker import DarkWebRequestWorker" in app
    assert "darkweb_request_worker.start()" in app
    assert "application.state.darkweb_request_worker=darkweb_request_worker" in app
    assert "await darkweb_request_worker.stop()" in app
