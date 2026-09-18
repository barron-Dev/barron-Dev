from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from cyclothone.developer.api_keys import create_api_key
from cyclothone.developer.identity import DeveloperIdentity, app_owned_by_user, resolve_developer
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/developer", tags=["developer"])


async def _user_id(authorization: str | None = Header(None)) -> str:
    if not authorization:
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(401, "invalid bearer token", headers={"WWW-Authenticate": "Bearer"})
    try:
        user = await (await supabase._ensure()).auth.get_user(token.strip())
    except Exception as exc:
        raise HTTPException(401, "invalid bearer token", headers={"WWW-Authenticate": "Bearer"}) from exc
    if not user or not getattr(user, "user", None) or not getattr(user.user, "id", None):
        raise HTTPException(401, "invalid bearer token", headers={"WWW-Authenticate": "Bearer"})
    return str(user.user.id)


async def developer_identity(user_id: str = Depends(_user_id)) -> DeveloperIdentity:
    identity = await resolve_developer(user_id)
    if not identity:
        raise HTTPException(403, "developer access is not provisioned")
    return identity


class AppCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=5000)
    allowed_scopes: list[str] = Field(default_factory=list, max_length=50)
    redirect_uris: list[str] = Field(default_factory=list, max_length=20)


class AppUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=5000)
    allowed_scopes: list[str] | None = Field(default=None, max_length=50)
    redirect_uris: list[str] | None = Field(default=None, max_length=20)


class KeyCreate(BaseModel):
    scopes: list[str] = Field(default_factory=list, max_length=50)
    expires_at: str | None = None


@router.get("/me")
async def me(identity: DeveloperIdentity = Depends(developer_identity)) -> dict[str, str]:
    return {"user_id": identity.user_id, "tenant_id": identity.tenant_id}


@router.post("/apps", status_code=201)
async def create_app(body: AppCreate, identity: DeveloperIdentity = Depends(developer_identity)) -> dict[str, Any]:
    scopes = sorted(set(body.allowed_scopes))
    row = {
        "tenant_id": identity.tenant_id,
        "owner_user_id": identity.user_id,
        "name": body.name,
        "description": body.description,
        "allowed_scopes": scopes,
        "redirect_uris": body.redirect_uris,
    }
    try:
        return await supabase.insert_one("developer_apps", row)
    except Exception as exc:
        raise HTTPException(409, "application name already exists or is invalid") from exc


@router.get("/apps")
async def list_apps(identity: DeveloperIdentity = Depends(developer_identity)) -> list[dict[str, Any]]:
    async def _do():
        return await (
            await supabase._ensure()
        ).table("developer_apps").select(
            "id,tenant_id,owner_user_id,name,description,active,allowed_scopes,redirect_uris,created_at,updated_at"
        ).eq("tenant_id", identity.tenant_id).eq("owner_user_id", identity.user_id).order("created_at", desc=True).execute()

    return list((await supabase._retry(_do, attempts=2)).data or [])


async def _owned_app(app_id: str, identity: DeveloperIdentity) -> dict[str, Any]:
    app = await app_owned_by_user(app_id, identity.user_id)
    if not app or str(app.get("tenant_id")) != identity.tenant_id:
        raise HTTPException(404, "application not found")
    return app


@router.get("/apps/{app_id}")
async def get_app(app_id: str, identity: DeveloperIdentity = Depends(developer_identity)) -> dict[str, Any]:
    return await _owned_app(app_id, identity)


@router.patch("/apps/{app_id}")
async def update_app(app_id: str, body: AppUpdate, identity: DeveloperIdentity = Depends(developer_identity)) -> dict[str, Any]:
    await _owned_app(app_id, identity)
    values = body.model_dump(exclude_unset=True)
    if "allowed_scopes" in values:
        values["allowed_scopes"] = sorted(set(values["allowed_scopes"]))
    if not values:
        raise HTTPException(422, "no fields supplied")
    row = await supabase.update("developer_apps", values, id=app_id, tenant_id=identity.tenant_id, owner_user_id=identity.user_id)
    if not row:
        raise HTTPException(404, "application not found")
    return row


@router.post("/apps/{app_id}/deactivate")
async def deactivate_app(app_id: str, identity: DeveloperIdentity = Depends(developer_identity)) -> dict[str, Any]:
    await _owned_app(app_id, identity)
    row = await supabase.update("developer_apps", {"active": False}, id=app_id, tenant_id=identity.tenant_id, owner_user_id=identity.user_id)
    if not row:
        raise HTTPException(404, "application not found")
    return {"id": app_id, "active": False}


@router.post("/apps/{app_id}/keys", status_code=201)
async def issue_key(app_id: str, body: KeyCreate, identity: DeveloperIdentity = Depends(developer_identity)) -> dict[str, Any]:
    app = await _owned_app(app_id, identity)
    if not app.get("active"):
        raise HTTPException(409, "application is inactive")
    scopes = sorted(set(body.scopes))
    allowed = set(app.get("allowed_scopes") or [])
    if not set(scopes).issubset(allowed):
        raise HTTPException(403, {"error": "invalid_scope", "allowed_scopes": sorted(allowed)})
    try:
        return await create_api_key(app_id, scopes, body.expires_at)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/apps/{app_id}/keys")
async def list_keys(app_id: str, identity: DeveloperIdentity = Depends(developer_identity)) -> list[dict[str, Any]]:
    await _owned_app(app_id, identity)
    async def _do():
        return await (
            await supabase._ensure()
        ).table("developer_api_keys").select(
            "id,app_id,key_prefix,scopes,active,expires_at,last_used_at,created_at,revoked_at"
        ).eq("app_id", app_id).order("created_at", desc=True).execute()
    return list((await supabase._retry(_do, attempts=2)).data or [])


@router.post("/apps/{app_id}/keys/{key_id}/revoke")
async def revoke_key(app_id: str, key_id: str, identity: DeveloperIdentity = Depends(developer_identity)) -> dict[str, Any]:
    await _owned_app(app_id, identity)
    async def _do():
        return await (
            await supabase._ensure()
        ).table("developer_api_keys").update(
            {"active": False, "revoked_at": "now()"}
        ).eq("id", key_id).eq("app_id", app_id).execute()
    try:
        result = await supabase._retry(_do, attempts=2)
    except Exception:
        result = None
    if not result or not result.data:
        raise HTTPException(404, "API key not found")
    return {"id": key_id, "active": False, "revoked": True}
