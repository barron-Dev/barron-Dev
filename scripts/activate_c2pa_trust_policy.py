from __future__ import annotations

import argparse
import base64
import hashlib
import os
from datetime import datetime, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID

from supabase import create_client

TRUST_LIST_REPO = "c2pa-org/conformance-public"
TRUST_LIST_PATH = "trust-list/C2PA-TRUST-LIST.json"
TSA_TRUST_LIST_PATH = "trust-list/C2PA-TSA-TRUST-LIST.json"
DEFAULT_COMMIT = "d6dec63476e2636095d1291d24b29ffa2d4e1ac0"
TRUSTED_STATUS = "http://c2pa.org/conformance/trust-list/trusted"


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_official_trust_list(commit: str, path: str = TRUST_LIST_PATH) -> tuple[dict, bytes, str]:
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise ValueError("A full lowercase 40-character Git commit SHA is required.")
    url = f"https://raw.githubusercontent.com/{TRUST_LIST_REPO}/{commit}/{path}"
    response = httpx.get(url, timeout=20.0, follow_redirects=False)
    response.raise_for_status()
    raw = response.content
    return response.json(), raw, url


def extract_trust_anchors(document: dict) -> tuple[list[str], list[str], list[str]]:
    lote = document.get("LoTE") or {}
    entities = lote.get("TrustedEntitiesList") or []
    pem_by_fingerprint: dict[str, str] = {}
    issuers: set[str] = set()
    for entity in entities:
        info = entity.get("TrustedEntityInformation") or {}
        names = info.get("TEName") or []
        issuer = next((n.get("value") for n in names if n.get("value")), "Unknown")
        for service in entity.get("TrustedEntityServices") or []:
            if service.get("ServiceStatus") != TRUSTED_STATUS:
                continue
            digital = ((service.get("ServiceInformation") or {}).get("ServiceDigitalIdentity") or {})
            for entry in digital.get("X509Certificates") or []:
                der = base64.b64decode(entry["val"], validate=True)
                cert = x509.load_der_x509_certificate(der)
                try:
                    constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
                except x509.ExtensionNotFound:
                    continue
                if not constraints.ca:
                    continue
                fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
                pem_by_fingerprint[fingerprint] = pem
                issuers.add(issuer)
    if not pem_by_fingerprint:
        raise ValueError("The official trust list contained no usable CA trust anchors.")
    fingerprints = sorted(pem_by_fingerprint)
    return [pem_by_fingerprint[f] for f in fingerprints], fingerprints, sorted(issuers)


def main() -> int:
    parser = argparse.ArgumentParser(description="Activate a pinned official C2PA trust-list snapshot in Cyclothone.")
    parser.add_argument("--commit", default=DEFAULT_COMMIT, help="Full commit SHA in c2pa-org/conformance-public.")
    parser.add_argument("--apply", action="store_true", help="Activate the policy using the Supabase service-role connection.")
    args = parser.parse_args()

    manifest_document, manifest_raw, manifest_uri = load_official_trust_list(args.commit, TRUST_LIST_PATH)
    tsa_document, tsa_raw, tsa_uri = load_official_trust_list(args.commit, TSA_TRUST_LIST_PATH)
    manifest_info = manifest_document["LoTE"]["ListAndSchemeInformation"]
    tsa_info = tsa_document["LoTE"]["ListAndSchemeInformation"]
    manifest_name = next((item.get("value") for item in manifest_info.get("SchemeName", []) if item.get("value")), "")
    tsa_name = next((item.get("value") for item in tsa_info.get("SchemeName", []) if item.get("value")), "")
    if manifest_name != "C2PA Trust List" or tsa_name != "C2PA TSA Trust List":
        raise SystemExit("The pinned CAI files are not the expected manifest and TSA trust lists.")

    manifest_issued = parse_time(manifest_info["ListIssueDateTime"])
    tsa_issued = parse_time(tsa_info["ListIssueDateTime"])
    manifest_next = parse_time(manifest_info["NextUpdate"])
    tsa_next = parse_time(tsa_info["NextUpdate"])
    issued = max(manifest_issued, tsa_issued)
    next_update = min(manifest_next, tsa_next)
    now = datetime.now(timezone.utc)
    if issued > now or next_update <= now:
        raise SystemExit("Refusing to activate an expired or not-yet-valid official CAI trust-list snapshot.")

    manifest_pems, manifest_fingerprints, manifest_issuers = extract_trust_anchors(manifest_document)
    tsa_pems, tsa_fingerprints, tsa_issuers = extract_trust_anchors(tsa_document)
    pems = manifest_pems
    fingerprints = manifest_fingerprints
    issuers = sorted(set(manifest_issuers) | set(tsa_issuers))

    source_uri = f"{manifest_uri}\\n{tsa_uri}"
    source_sha256 = hashlib.sha256(
        b"manifest\\x00" + manifest_raw + b"\\x00tsa\\x00" + tsa_raw
    ).hexdigest()
    sequence = min(
        manifest_info.get("LoTESequenceNumber", 0),
        tsa_info.get("LoTESequenceNumber", 0),
    )
    version = f"lote-{sequence}-{issued.date().isoformat()}"
    print({
        "policy_name": "Cyclothone Official C2PA + TSA Trust Lists",
        "policy_version": version,
        "source_uri": source_uri,
        "source_commit": args.commit,
        "source_sha256": source_sha256,
        "issued_at": issued.isoformat(),
        "next_update": next_update.isoformat(),
        "manifest_anchor_count": len(manifest_pems),
        "tsa_anchor_count": len(tsa_pems),
        "tsa_trust_anchor_count": len(tsa_pems),
        "trusted_entities": issuers,
        "apply": args.apply,
    })
    if not args.apply:
        print("Dry run only. Re-run with --apply after reviewing the official source snapshot.")
        return 0

    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_SECRET_KEY") or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not supabase_url or not supabase_key:
        raise SystemExit("SUPABASE_URL and SUPABASE_SECRET_KEY (or SUPABASE_SERVICE_ROLE_KEY) are required.")
    client = create_client(supabase_url, supabase_key)
    result = client.rpc("activate_c2pa_trust_policy", {
        "p_policy_name": "Cyclothone Official C2PA + TSA Trust Lists",
        "p_policy_version": version,
        "p_trusted_anchor_pems": pems,
        "p_trusted_anchor_sha256": fingerprints,
        "p_tsa_anchor_pems": tsa_pems,
        "p_tsa_anchor_sha256": tsa_fingerprints,
        "p_source_uri": source_uri,
        "p_source_commit": args.commit,
        "p_source_sha256": source_sha256,
        "p_source_issued_at": issued.isoformat(),
        "p_source_next_update": next_update.isoformat(),
    }).execute()
    print({"activated_policy_id": result.data})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
