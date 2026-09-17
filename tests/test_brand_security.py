from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_brand_rpc_is_service_role_only():
    sql = _read("sql/034_brand_protection.sql")
    assert "revoke all on function record_brand_threat" in sql
    assert "grant execute on function record_brand_threat" in sql
    assert "to service_role" in sql
    assert "to authenticated" not in sql.split("grant execute on function", 1)[-1]


def test_brand_rpc_binds_brand_to_tenant():
    sql = _read("sql/034_brand_protection.sql")
    assert "v_brand_tenant" in sql
    assert "v_brand_tenant <> p_tenant" in sql


def test_brand_routes_use_developer_auth_boundary():
    source = _read("src/cyclothone/api/routes/brand.py")
    tree = ast.parse(source)
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert "cyclothone.developer.auth" in imports
    assert "cyclothone.security.jwt" not in imports
    assert "cyclothone.api.deps" not in imports


def test_brand_routes_filter_tenant_on_threat_reads():
    source = _read("src/cyclothone/api/routes/brand.py")
    assert '.eq("tenant_id", str(principal.tenant_id))' in source


def test_brand_takedown_does_not_send_requests_automatically():
    source = _read("src/cyclothone/brand/takedown.py")
    assert "httpx" not in source
    assert "AsyncClient" not in source
    assert "request_takedown" in source
