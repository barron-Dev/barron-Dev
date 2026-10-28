from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyclothone.ai.action_verifier import GENESIS_HASH, ActionEnvelope, sign_action_envelope
from cyclothone.storage.supabase_client import supabase


class ActionReceiptError(RuntimeError):
    """Receipt creation failed; callers must not dispatch the protected action."""


class ActionReceiptService:
    """Persist signed AI action receipts with externally held private-key material.

    The private key is supplied only by the backend secret manager environment.
    Only the public key is registered in trust_signing_keys. The database RPC
    independently recomputes hashes and verifies the signature before insertion.
    """

    def __init__(self, *, signing_key_id_env: str = "CYCLOTHONE_AI_ACTION_SIGNING_KID",
                 signing_key_pem_env: str = "CYCLOTHONE_AI_ACTION_SIGNING_PRIVATE_KEY_PEM") -> None:
        self.signing_key_id_env = signing_key_id_env
        self.signing_key_pem_env = signing_key_pem_env

    def _load_private_key(self) -> tuple[str, Ed25519PrivateKey]:
        key_id = os.getenv(self.signing_key_id_env, "").strip()
        pem = os.getenv(self.signing_key_pem_env, "")
        if not key_id or not pem:
            raise ActionReceiptError("AI_ACTION signing key is not provisioned in the backend secret manager")
        try:
            key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        except (TypeError, ValueError) as exc:
            raise ActionReceiptError("AI_ACTION private key is not valid unencrypted PEM") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise ActionReceiptError("AI_ACTION private key must be Ed25519")
        return key_id, key

    async def record_action(
        self, *, tenant_id: UUID, run_id: UUID, actor_id: str, agent_id: UUID | None,
        action_type: str, payload: dict[str, Any],
    ) -> dict[str, Any]:
        key_id, private_key = self._load_private_key()
        tenant, run = str(tenant_id), str(run_id)

        run_row = await supabase.select_one(
            "ai_runs", "id,tenant_id,agent_id", id=run, tenant_id=tenant
        )
        if not run_row:
            raise ActionReceiptError("canonical AI run does not belong to tenant")
        persisted_agent = str(run_row.get("agent_id") or "")
        if agent_id is None or persisted_agent != str(agent_id):
            raise ActionReceiptError("AI action agent does not match canonical run")

        registered = await supabase.select_one(
            "trust_signing_keys",
            "tenant_id,key_id,purpose,algorithm,public_key,status,not_before,not_after",
            tenant_id=tenant, key_id=key_id, purpose="AI_ACTION",
            algorithm="ED25519", status="ACTIVE",
        )
        if not registered:
            raise ActionReceiptError("tenant has no active registered AI_ACTION public key")
        registered_public_hex = str(registered.get("public_key") or "").lower()
        derived_public_hex = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
        if registered_public_hex != derived_public_hex:
            raise ActionReceiptError("AI_ACTION private key does not match registered public key")

        client = await supabase._ensure()
        head_response = await client.table("ai_action_verification_events").select(
            "sequence,event_hash"
        ).eq("tenant_id", tenant).eq("run_id", run).order(
            "sequence", desc=True
        ).limit(1).execute()
        heads = head_response.data or []
        if heads:
            sequence = int(heads[0]["sequence"]) + 1
            previous_hash = str(heads[0]["event_hash"])
        else:
            sequence, previous_hash = 1, GENESIS_HASH

        occurred_at = datetime.now(UTC)
        envelope: ActionEnvelope = sign_action_envelope(
            tenant_id=tenant,
            run_id=run,
            actor_id=actor_id,
            agent_id=str(agent_id),
            action_type=action_type,
            payload=payload,
            signer_key_id=key_id,
            signing_key=private_key,
            sequence=sequence,
            previous_hash=previous_hash,
            event_id=str(uuid4()),
            occurred_at=occurred_at,
        )
        params = {
            "p_tenant_id": tenant,
            "p_run_id": run,
            "p_event_id": envelope.event_id,
            "p_sequence": envelope.sequence,
            "p_actor_id": envelope.actor_id,
            "p_agent_id": envelope.agent_id,
            "p_action_type": envelope.action_type,
            "p_payload_canonical": envelope.payload_canonical,
            "p_payload_hash": envelope.payload_hash,
            "p_previous_hash": envelope.previous_hash,
            "p_event_hash": envelope.event_hash,
            "p_signer_key_id": envelope.signer_key_id,
            "p_signature_hex": envelope.signature_hex,
            "p_occurred_at_canonical": envelope.occurred_at,
        }
        try:
            committed = await supabase.rpc("commit_ai_action_verification_event", params)
        except Exception as exc:
            raise ActionReceiptError("database rejected or could not commit AI action receipt") from exc
        if isinstance(committed, list):
            committed = committed[0] if committed else None
        if not isinstance(committed, dict) or str(committed.get("event_hash") or "") != envelope.event_hash:
            raise ActionReceiptError("database did not return the committed AI action receipt")

        stored = await supabase.select_one(
            "ai_action_verification_events",
            "tenant_id,run_id,event_id,sequence,actor_id,agent_id,action_type,payload_hash,previous_hash,event_hash,signer_key_id,signature_hex,occurred_at_canonical",
            tenant_id=tenant, run_id=run, event_id=envelope.event_id,
        )
        if not stored:
            raise ActionReceiptError("durable AI action receipt read-back failed")
        expected = {
            "tenant_id": tenant, "run_id": run, "event_id": envelope.event_id,
            "sequence": sequence, "actor_id": actor_id, "agent_id": str(agent_id),
            "action_type": action_type, "payload_hash": envelope.payload_hash,
            "previous_hash": previous_hash, "event_hash": envelope.event_hash,
            "signer_key_id": key_id, "signature_hex": envelope.signature_hex,
            "occurred_at_canonical": envelope.occurred_at,
        }
        for field, value in expected.items():
            if str(stored.get(field)) != str(value):
                raise ActionReceiptError(f"durable AI action receipt read-back mismatch: {field}")
        return {"event_id": envelope.event_id, "event_hash": envelope.event_hash, "sequence": sequence}
