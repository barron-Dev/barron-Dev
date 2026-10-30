from __future__ import annotations

from uuid import UUID

from cyclothone.storage.supabase_client import supabase

PROVIDERS = {
    "cloudflare": ("abuse@cloudflare.com", None),
    "godaddy": ("abuse@godaddy.com", None),
    "namecheap": ("abuse@namecheap.com", None),
    "google": (None, "https://support.google.com/legal/troubleshooter/1114905"),
    "meta": (None, "https://www.facebook.com/help/contact/295309487309948"),
    "x": (None, "https://help.x.com/forms/impersonation"),
    "linkedin": (None, "https://www.linkedin.com/help/linkedin/ask/TS-RSI"),
    "tiktok": ("impersonation@tiktok.com", None),
    "apple": (None, "https://www.apple.com/legal/internet-services/itunes/appstorenotices/"),
}


class TakedownService:
    """Prepare evidence-backed abuse reports; dispatch requires a separate approval path."""

    async def prepare_request(
        self, *, tenant_id: UUID, threat_id: UUID, provider: str
    ) -> dict:
        provider = provider.strip().lower()
        if provider not in PROVIDERS:
            raise ValueError("unsupported takedown provider")

        async def load_threat():
            return await (
                await supabase._ensure()
            ).table("brand_threats").select("*").eq(
                "id", str(threat_id)
            ).eq("tenant_id", str(tenant_id)).limit(1).execute()

        rows = (await supabase._retry(load_threat, attempts=2)).data or []
        if not rows:
            raise ValueError("threat not found")
        threat = rows[0]
        if threat.get("verification_state") != "verified":
            raise ValueError("only independently verified threats can enter takedown preparation")

        async def load_brand():
            return await (
                await supabase._ensure()
            ).table("brands").select("*").eq(
                "id", threat["brand_id"]
            ).eq("tenant_id", str(tenant_id)).limit(1).execute()

        brands = (await supabase._retry(load_brand, attempts=2)).data or []
        if not brands:
            raise ValueError("brand not found")
        brand = brands[0]

        async def load_evidence():
            return await (
                await supabase._ensure()
            ).table("brand_evidence").select(
                "id,evidence_type,sha256,source_url,captured_at"
            ).eq("tenant_id", str(tenant_id)).eq(
                "threat_id", str(threat_id)
            ).order("captured_at", desc=True).limit(100).execute()

        evidence = (await supabase._retry(load_evidence, attempts=2)).data or []
        if not evidence:
            raise ValueError("verified threat has no persisted evidence manifest")
        if not all(len(str(item.get("sha256", ""))) == 64 for item in evidence):
            raise ValueError("evidence manifest contains an invalid digest")

        subject = f"Takedown request - {threat['kind']} impersonating {brand['name']}"
        body = self._compose(brand, threat, evidence)
        payload = {
            "tenant_id": str(tenant_id),
            "brand_id": str(brand["id"]),
            "threat_id": str(threat_id),
            "provider": provider,
            "subject": subject,
            "report_body": body,
            "status": "prepared",
            "dispatch_requested": False,
        }

        async def persist_request():
            return await (
                await supabase._ensure()
            ).table("brand_takedown_requests").insert(payload).execute()

        saved = (await supabase._retry(persist_request, attempts=2)).data or []
        if not saved:
            raise RuntimeError("takedown preparation was not persisted")

        async def mark_threat():
            return await (
                await supabase._ensure()
            ).table("brand_threats").update({
                "status": "takedown_requested",
                "takedown_provider": provider,
                "takedown_at": saved[0]["created_at"],
            }).eq("id", str(threat_id)).eq(
                "tenant_id", str(tenant_id)
            ).execute()

        await supabase._retry(mark_threat, attempts=2)
        email, form = PROVIDERS[provider]
        return {
            "request_id": saved[0]["id"],
            "threat_id": str(threat_id),
            "provider": provider,
            "subject": subject,
            "body": body,
            "contact_email": email,
            "contact_form": form,
            "status": "prepared",
            "dispatch_state": "not_dispatched",
            "requires_customer_authorization": True,
            "evidence_count": len(evidence),
            "evidence_hashes": [item["sha256"] for item in evidence],
        }

    @staticmethod
    def _compose(brand: dict, threat: dict, evidence: list[dict]) -> str:
        hashes = "\n".join(
            f"- {item['evidence_type']}: SHA-256 {item['sha256']}"
            for item in evidence
        )
        return (
            f"I represent {brand['name']} ({brand['primary_domain']}) and submit "
            "this evidence-backed report for review under the provider's applicable "
            "impersonation, abuse, or trademark process.\n\n"
            f"Identifier: {threat['identifier']}\n"
            f"URL: {threat.get('url') or 'n/a'}\n"
            f"Platform: {threat.get('platform') or 'web'}\n"
            f"Threat type: {threat['kind']}\n"
            f"Verification state: {threat.get('verification_state')}\n"
            f"Evidence SHA-256:\n{hashes}\n\n"
            "This report is prepared for authorized review. It has not been "
            "transmitted to the provider.\n\n"
            f"Regards,\n{brand['name']} Security Team\n{brand['primary_domain']}"
        )
