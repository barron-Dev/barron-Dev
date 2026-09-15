from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sentinel.developer.crypto import expires, hash_secret, new_client_credentials, new_token, verify_pkce
from sentinel.storage.supabase_client import supabase


async def create_client(app_id: str, public_client: bool = False) -> dict[str, str]:
    client_id, secret, secret_hash = new_client_credentials()
    row = await supabase.insert_one("oauth_clients", {"app_id": app_id, "client_id": client_id, "client_secret_hash": None if public_client else secret_hash, "public_client": public_client})
    return {"id": str(row["id"]), "client_id": client_id, "client_secret": "" if public_client else secret}


async def issue_client_credentials(client_id: str, client_secret: str, requested_scope: list[str]) -> dict[str, Any]:
    client = await supabase.select_one("oauth_clients", "id,app_id,client_secret_hash,active,public_client", client_id=client_id)
    if not client or not client["active"] or client["public_client"] or hash_secret(client_secret) != client["client_secret_hash"]:
        raise ValueError("invalid_client")
    return await _issue(client["id"], client["app_id"], None, requested_scope)


async def create_authorization_code(client_id: str, user_id: str, redirect_uri: str, scope: list[str], code_challenge: str | None, method: str | None) -> str:
    client = await supabase.select_one("oauth_clients", "id,app_id,active", client_id=client_id)
    if not client or not client["active"]:
        raise ValueError("invalid_client")
    app = await supabase.select_one("developer_apps", "allowed_scopes,redirect_uris,active", id=client["app_id"])
    if not app or not app["active"] or redirect_uri not in (app.get("redirect_uris") or []) or not set(scope).issubset(set(app.get("allowed_scopes") or [])):
        raise ValueError("invalid_request")
    if not code_challenge or method not in {"S256", "plain"}:
        raise ValueError("invalid_request")
    code, code_hash = new_token("snc_")
    await supabase.insert_one("oauth_authorization_codes", {"code_hash": code_hash, "client_id": client["id"], "user_id": user_id, "app_id": client["app_id"], "redirect_uri": redirect_uri, "scope": sorted(set(scope)), "code_challenge": code_challenge, "code_challenge_method": method, "expires_at": expires(0.167).isoformat()})
    return code


async def exchange_authorization_code(code: str, client_id: str, redirect_uri: str, verifier: str) -> dict[str, Any]:
    row = await supabase.select_one("oauth_authorization_codes", "id,client_id,user_id,app_id,redirect_uri,scope,code_challenge,code_challenge_method,expires_at,consumed_at", code_hash=hash_secret(code))
    if not row or row["client_id"] != client_id or row["redirect_uri"] != redirect_uri or row.get("consumed_at"):
        raise ValueError("invalid_grant")
    if datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00")) <= datetime.now(UTC) or not verify_pkce(verifier, row["code_challenge"], row["code_challenge_method"]):
        raise ValueError("invalid_grant")
    await supabase.update("oauth_authorization_codes", {"consumed_at": datetime.now(UTC).isoformat()}, id=row["id"])
    return await _issue(row["client_id"], row["app_id"], row["user_id"], list(row.get("scope") or []), refresh=True)


async def _issue(client_id: str, app_id: str, user_id: str | None, scope: list[str], refresh: bool = False) -> dict[str, Any]:
    app = await supabase.select_one("developer_apps", "active,allowed_scopes", id=app_id)
    if not app or not app["active"] or not set(scope).issubset(set(app.get("allowed_scopes") or [])):
        raise ValueError("invalid_scope")
    token, token_hash = new_token("snt_")
    exp = expires(1)
    await supabase.insert_one("oauth_access_tokens", {"token_hash": token_hash, "client_id": client_id, "user_id": user_id, "app_id": app_id, "scope": sorted(set(scope)), "expires_at": exp.isoformat()})
    result: dict[str, Any] = {"access_token": token, "token_type": "Bearer", "expires_in": 3600, "scope": " ".join(sorted(set(scope)))}
    if refresh:
        refresh_token, refresh_hash = new_token("snr_")
        await supabase.insert_one("oauth_refresh_tokens", {"token_hash": refresh_hash, "client_id": client_id, "user_id": user_id, "app_id": app_id, "scope": sorted(set(scope)), "expires_at": expires(24 * 30).isoformat()})
        result["refresh_token"] = refresh_token
    return result
