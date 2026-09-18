from __future__ import annotations
from uuid import UUID
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from cyclothone.api.deps import require_role
from cyclothone.security.jwt import Principal
from cyclothone.lens.photo import PhotoFingerprintError, phash
from cyclothone.storage.supabase_client import supabase

router=APIRouter()

@router.post("/identities/{identity_id}/photo")
async def enroll_photo(identity_id: UUID, photo: UploadFile=File(...),
    principal: Principal=Depends(require_role("owner","admin","member")))->dict:
    if photo.content_type not in {"image/jpeg","image/png","image/webp"}:
        raise HTTPException(415,"only JPEG, PNG, and WebP are supported")
    data=await photo.read(5*1024*1024+1)
    if len(data)>5*1024*1024:
        raise HTTPException(413,"image exceeds 5 MiB")
    try: fingerprint=phash(data)
    except PhotoFingerprintError as exc: raise HTTPException(400,str(exc)) from exc
    async def _do():
        client=await supabase._ensure()
        return await client.rpc("lens_set_photo_fingerprint",{
            "p_tenant":str(principal.tenant_id),"p_identity":str(identity_id),"p_phash":fingerprint}).execute()
    try:
        await supabase._retry(_do,attempts=2)
    except Exception as exc:
        raise HTTPException(502,"photo enrollment could not be persisted") from exc
    return {"identity_id":str(identity_id),"photo_fingerprint":fingerprint,"raw_photo_stored":False}
