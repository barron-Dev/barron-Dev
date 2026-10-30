from __future__ import annotations

import argparse
import base64
import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_bundle(path: str | Path, trusted_public_key_path: str | Path | None = None, original_media_path: str | Path | None = None) -> dict[str, Any]:
    with zipfile.ZipFile(path, "r") as archive:
        receipt = json.loads(archive.read("receipt.json"))
        report = json.loads(archive.read("c2pa-report.json"))

    payload = receipt["signed_payload"]
    canonical = receipt["signed_payload_canonical"].encode("utf-8")
    if canonical != canonical_json(payload):
        raise ValueError("Signed payload is not canonical JSON.")
    payload_hash = hashlib.sha256(canonical).hexdigest()
    if payload_hash != receipt["receipt_hash"]:
        raise ValueError("Receipt hash does not match the signed payload.")

    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(receipt["signing_public_key"], validate=True)
    )
    signature = bytes.fromhex(receipt["signature"])
    public_key.verify(signature, canonical)
    trusted_signer_key = None
    if trusted_public_key_path:
        trusted_key = serialization.load_pem_public_key(Path(trusted_public_key_path).read_bytes())
        if not isinstance(trusted_key, Ed25519PublicKey):
            raise ValueError("Trusted signer key must be Ed25519.")
        trusted_signer_key = (
            trusted_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            == public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        if not trusted_signer_key:
            raise ValueError("Bundle signing key does not match the independently trusted Cyclothone key.")

    original_media_hash_matches = None
    if original_media_path:
        digest = hashlib.sha256()
        with Path(original_media_path).open("rb") as media:
            for chunk in iter(lambda: media.read(1024 * 1024), b""):
                digest.update(chunk)
        original_media_hash_matches = digest.hexdigest() == receipt["media_sha256"]
        if not original_media_hash_matches:
            raise ValueError("Original media SHA-256 does not match the receipt.")

    checks = {
        "source_job_id": payload.get("source_job_id") == receipt.get("source_job_id"),
        "tenant_id": payload.get("tenant_id") == receipt.get("tenant_id"),
        "media_sha256": payload.get("media_sha256") == receipt.get("media_sha256"),
        "manifest_store_sha256": payload.get("manifest_store_sha256") == receipt.get("manifest_store_sha256"),
        "validation_state": payload.get("validation_state") == receipt.get("validation_state"),
        "trust_policy_version": payload.get("trust_policy_version") == receipt.get("trust_policy_version"),
        "previous_receipt_hash": payload.get("previous_receipt_hash") == receipt.get("previous_receipt_hash"),
    }
    if not all(checks.values()):
        raise ValueError(f"Receipt metadata mismatch: {checks}")

    manifest_store = report.get("manifest_store")
    manifest_hash_verified = None
    if manifest_store is not None and receipt.get("manifest_store_sha256"):
        manifest_hash_verified = hashlib.sha256(canonical_json(manifest_store)).hexdigest() == receipt["manifest_store_sha256"]
        if not manifest_hash_verified:
            raise ValueError("Manifest-store hash does not match the report.")

    return {
        "signature_valid": True,
        "trusted_signer_key": trusted_signer_key,
        "original_media_hash_matches": original_media_hash_matches,
        "receipt_hash_valid": True,
        "metadata_consistent": True,
        "manifest_store_hash_valid": manifest_hash_verified,
        "receipt_id": receipt["receipt_id"],
        "tenant_id": receipt["tenant_id"],
        "media_sha256": receipt["media_sha256"],
        "validation_state": receipt["validation_state"],
        "trust_policy_version": receipt["trust_policy_version"],
        "signing_key_id": receipt["signing_key_id"],
        "note": "The original media file is not embedded. Recompute media_sha256 against the separately retained original file.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify a Cyclothone .ctprove evidence bundle.")
    parser.add_argument("bundle", help="Path to a .ctprove ZIP bundle.")
    parser.add_argument("--trusted-public-key", help="PEM public key obtained independently from Cyclothone key distribution.")
    parser.add_argument("--media", help="Original media file to hash and compare with the signed receipt.")
    args = parser.parse_args()
    result = verify_bundle(args.bundle, args.trusted_public_key, args.media)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
