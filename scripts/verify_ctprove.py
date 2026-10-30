from __future__ import annotations

import argparse
import base64
import hashlib
import json
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_bundle(path: Path) -> dict:
    with zipfile.ZipFile(path, "r") as archive:
        receipt = json.loads(archive.read("receipt.json"))
        report = json.loads(archive.read("c2pa-report.json"))
        manifest_store = json.loads(archive.read("manifest-store.json"))
    payload = receipt["signed_payload"]
    computed_hash = hashlib.sha256(canonical_json(payload)).hexdigest()
    if computed_hash != receipt["receipt_hash"]:
        raise ValueError("Receipt hash does not match the signed payload.")
    if payload.get("media_sha256") != receipt["media_sha256"]:
        raise ValueError("Receipt media hash mismatch.")
    manifest_hash = hashlib.sha256(canonical_json(manifest_store)).hexdigest()
    if manifest_hash != receipt["manifest_store_sha256"]:
        raise ValueError("Manifest-store hash mismatch.")
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(receipt["signing_public_key"], validate=True))
    public_key.verify(bytes.fromhex(receipt["signature"]), canonical_json(payload))
    if payload.get("validation_state") != receipt.get("validation_state"):
        raise ValueError("Signed state does not match receipt state.")
    if payload.get("trust_policy_version") != receipt.get("trust_policy_version"):
        raise ValueError("Signed trust-policy version does not match receipt.")
    return {
        "verified": True,
        "receipt_id": receipt["receipt_id"],
        "validation_state": receipt["validation_state"],
        "media_sha256": receipt["media_sha256"],
        "manifest_store_sha256": manifest_hash,
        "receipt_hash": computed_hash,
        "signing_key_id": receipt["signing_key_id"],
        "c2pa_report_present": bool(report),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify a Cyclothone .ctprove bundle.")
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify_bundle(args.bundle), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
