import hashlib
import io
import json
import zipfile
from uuid import uuid4

import pytest

from sentinel.compliance.verification import EvidencePackVerifier


def _pack() -> tuple[bytes, str]:
    body = {
        "schema_version": "1.1",
        "tenant_id": str(uuid4()),
        "framework": {"name": "SOC 2"},
        "framework_id": "soc2",
        "period": {"start": "2026-01-01T00:00:00+00:00", "end": "2026-04-01T00:00:00+00:00"},
        "generated_at": "2026-04-01T00:00:00+00:00",
        "controls": [],
        "control_status": [],
        "evidence": [],
        "attestations": [],
        "audit_extract": [],
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
    manifest_sha = hashlib.sha256(canonical).hexdigest()
    manifest = {**body, "manifest_sha256": manifest_sha, "signature": "sig", "signer_kid": "kid"}
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2).encode()
    files = {"manifest.json": manifest_bytes, "controls.json": b"[]"}
    files["file_hashes.json"] = json.dumps({k: hashlib.sha256(v).hexdigest() for k, v in files.items()}, sort_keys=True, indent=2).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buf.getvalue(), manifest_sha


def test_zip_verifier_rejects_path_traversal():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("../escape.txt", b"bad")
    with pytest.raises(ValueError):
        EvidencePackVerifier._read_zip(buf.getvalue())


def test_pack_manifest_round_trip():
    pack, manifest_sha = _pack()
    files = EvidencePackVerifier._read_zip(pack)
    manifest = json.loads(files["manifest.json"])
    signed_body = dict(manifest)
    signed_body.pop("manifest_sha256")
    signed_body.pop("signature")
    signed_body.pop("signer_kid")
    canonical = json.dumps(signed_body, sort_keys=True, separators=(",", ":"), default=str).encode()
    assert hashlib.sha256(canonical).hexdigest() == manifest_sha
