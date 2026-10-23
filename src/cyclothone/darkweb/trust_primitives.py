"""Side-effect-free Cyclothone DW trust primitives; no network or Tor access."""
from __future__ import annotations
import hashlib, hmac, re, unicodedata
from dataclasses import dataclass
from typing import Iterable, Sequence

ONION_V3_RE = re.compile(r"^[a-z2-7]{56}\.onion$", re.ASCII)

def validate_v3_hostname(hostname: str) -> bool:
    """Syntax check only; it does not prove ownership or reachability."""
    return bool(ONION_V3_RE.fullmatch(hostname))

def isolation_username(tenant_id: str, source_id: str, key: bytes) -> str:
    """Opaque stable SOCKS username. Runtime must enable and verify Tor SOCKS auth isolation."""
    if not tenant_id.strip() or not source_id.strip():
        raise ValueError("tenant_id and source_id are required")
    if len(key) < 32:
        raise ValueError("isolation HMAC key must be at least 32 bytes")
    msg = f"cyclothone-dw-v1\0{tenant_id}\0{source_id}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:32]

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def normalize_text(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())

def shingles(text: str, size: int = 5) -> set[str]:
    if not 2 <= size <= 12:
        raise ValueError("shingle size must be between 2 and 12")
    words = normalize_text(text).split()
    if len(words) < size:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i+size]) for i in range(len(words)-size+1)}

def minhash_signature(text: str, permutations: int = 128, shingle_size: int = 5) -> tuple[int, ...]:
    """Deterministic SHA-256 MinHash approximation; version parameters before persistence."""
    if not 1 <= permutations <= 256:
        raise ValueError("permutations must be between 1 and 256")
    tokens = shingles(text, shingle_size)
    if not tokens:
        return tuple([0xFFFFFFFF] * permutations)
    out=[]
    for i in range(permutations):
        prefix=f"cyclothone-minhash-v1:{i}:".encode()
        out.append(min(int.from_bytes(hashlib.sha256(prefix+t.encode()).digest()[:4],"big") for t in tokens))
    return tuple(out)

def minhash_similarity(left: Sequence[int], right: Sequence[int]) -> float:
    if not left or len(left) != len(right):
        raise ValueError("signatures must be non-empty and equal length")
    return sum(a == b for a,b in zip(left,right))/len(left)

def simhash64(text: str) -> str:
    tokens=shingles(text,3)
    if not tokens: return "0000000000000000"
    weights=[0]*64
    for token in tokens:
        value=int.from_bytes(hashlib.sha256(token.encode()).digest()[:8],"big")
        for bit in range(64): weights[bit] += 1 if value & (1<<bit) else -1
    return f"{sum(1<<bit for bit,w in enumerate(weights) if w>=0):016x}"

def cosine_distance(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or len(left)!=len(right): raise ValueError("vectors must be non-empty and equal length")
    dot=sum(a*b for a,b in zip(left,right)); ln=sum(a*a for a in left)**0.5; rn=sum(b*b for b in right)**0.5
    if ln==0 or rn==0: raise ValueError("zero-norm vector")
    return max(0.0,min(2.0,1.0-dot/(ln*rn)))

@dataclass(frozen=True)
class MirrorVerdict:
    status: str
    fingerprint: str | None
    signed_hosts: tuple[str,...]
    reason: str

def mirror_verdict(*, signature_valid: bool, signer_fingerprint: str | None,
                   pinned_fingerprint: str | None, signed_hosts: Iterable[str],
                   current_hostname: str) -> MirrorVerdict:
    """Consumes output from a real OpenPGP verifier; does not verify signatures itself."""
    hosts=tuple(sorted(set(h.lower().rstrip(".") for h in signed_hosts)))
    if not validate_v3_hostname(current_hostname):
        return MirrorVerdict("malformed_statement",signer_fingerprint,hosts,"invalid_current_v3_hostname")
    if not signature_valid:
        return MirrorVerdict("invalid_signature",signer_fingerprint,hosts,"cryptographic_verification_failed")
    if not signer_fingerprint or not pinned_fingerprint:
        return MirrorVerdict("unsigned",signer_fingerprint,hosts,"publisher_key_not_pinned")
    signer=re.sub(r"\s+","",signer_fingerprint).upper(); pinned=re.sub(r"\s+","",pinned_fingerprint).upper()
    if not hmac.compare_digest(signer,pinned):
        return MirrorVerdict("fingerprint_mismatch",signer_fingerprint,hosts,"signer_does_not_match_pin")
    if current_hostname.lower() not in hosts:
        return MirrorVerdict("host_not_in_signed_list",signer_fingerprint,hosts,"current_host_not_signed")
    return MirrorVerdict("verified",signer_fingerprint,hosts,"signature_pin_and_host_match")

def anomaly_score(distance: float, *, threshold: float, recency_weight: float=1.0) -> float:
    """Bounded review signal; never a standalone maliciousness verdict."""
    if not 0<=distance<=2 or not 0<threshold<=2 or not 0<=recency_weight<=1:
        raise ValueError("distance, threshold, or weight out of range")
    return min(1.0,max(0.0,distance/threshold)*recency_weight)
