"""Privacy-proof verification boundary; deliberately not a fake ZK implementation.

A valid ZK-SNARK/STARK must be checked by a circuit-specific, audited verifier with trusted
verification-key material. Hashes, elliptic-curve points, and signatures alone are not
zero-knowledge proofs. No raw biometric or embedding payload is accepted by this API.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol
import re

_HEX = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class PublicStatement:
    circuit_id: str
    circuit_version: str
    verifier_key_sha256: str
    statement_sha256: str
    proof_system: str
    proof_bytes: bytes


class ZKVerifier(Protocol):
    def verify(self, *, proof_system: str, circuit_id: str, circuit_version: str,
               verifier_key_sha256: str, statement_sha256: str, proof_bytes: bytes) -> bool: ...


def verify_private_attestation(statement: PublicStatement, *,
                               trusted_circuit_hashes: dict[str, str],
                               verifier: ZKVerifier | None) -> dict:
    if not statement.circuit_id or not statement.circuit_version:
        raise ValueError("circuit_identity_required")
    if not _HEX.fullmatch(statement.verifier_key_sha256) or not _HEX.fullmatch(statement.statement_sha256):
        raise ValueError("invalid_public_statement_hash")
    if trusted_circuit_hashes.get(statement.circuit_id) != statement.verifier_key_sha256:
        return {"status":"rejected","reason":"verifier_key_not_trusted",
                "raw_private_data_received":False}
    if not statement.proof_bytes:
        return {"status":"rejected","reason":"empty_proof","raw_private_data_received":False}
    if verifier is None:
        return {"status":"unavailable","reason":"audited_zk_verifier_not_configured",
                "raw_private_data_received":False}
    valid = verifier.verify(proof_system=statement.proof_system,
                            circuit_id=statement.circuit_id,
                            circuit_version=statement.circuit_version,
                            verifier_key_sha256=statement.verifier_key_sha256,
                            statement_sha256=statement.statement_sha256,
                            proof_bytes=statement.proof_bytes)
    return {"status":"verified" if valid else "rejected",
            "reason":"proof_valid" if valid else "proof_invalid",
            "raw_private_data_received":False}
