"""Evidence integrity primitives; no network calls, archive writes, or timestamp submissions."""
from __future__ import annotations
import hashlib, json, re
from dataclasses import dataclass
from typing import Iterable

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def canonical_json_sha256(value: object) -> str:
    data=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")
    return sha256_hex(data)

def merkle_root(leaves: Iterable[str]) -> str:
    """Binary SHA-256 Merkle root; duplicate the final leaf when a level is odd."""
    level=list(leaves)
    if not level: raise ValueError("Merkle tree requires at least one leaf")
    for leaf in level:
        if len(leaf)!=64 or any(c not in "0123456789abcdef" for c in leaf): raise ValueError("invalid SHA-256 leaf")
    nodes=[bytes.fromhex(v) for v in level]
    while len(nodes)>1:
        if len(nodes)%2: nodes.append(nodes[-1])
        nodes=[hashlib.sha256(nodes[i]+nodes[i+1]).digest() for i in range(0,len(nodes),2)]
    return nodes[0].hex()

@dataclass(frozen=True)
class EntityMatch:
    score: float
    disposition: str

def entity_match_score(name_similarity: float, shared_anchor_count: int, same_language: bool) -> EntityMatch:
    """Candidate scoring only; never merges entities automatically."""
    if not 0<=name_similarity<=1 or shared_anchor_count<0: raise ValueError("invalid similarity or anchor count")
    score=max(0.0,min(1.0,name_similarity*0.6+min(shared_anchor_count*0.15,0.45)-(0 if same_language else 0.05)))
    disposition="auto_candidate" if score>=0.88 else "human_review" if score>=0.75 else "no_link"
    return EntityMatch(score,disposition)

def normalize_anchor(entity_type: str, value: str) -> str:
    """Conservative syntax normalizer; checksum-sensitive formats require validated parsers upstream."""
    raw=value.strip()
    if entity_type=="onion":
        host=raw.lower().removeprefix("http://").removeprefix("https://").split("/",1)[0].split(":",1)[0].rstrip(".")
        if not re.fullmatch(r"[a-z2-7]{56}\.onion",host):
            raise ValueError("invalid v3 onion hostname syntax")
        return host
    if entity_type=="pgp_key":\n        fingerprint="".join(raw.split()).upper()\n        if not re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})",fingerprint): raise ValueError("invalid PGP fingerprint syntax")\n        return fingerprint
    if entity_type=="eth_address":
        if len(raw)!=42 or not raw.startswith("0x") or any(c not in "0123456789abcdefABCDEF" for c in raw[2:]): raise ValueError("invalid ETH address syntax")
        return "0x"+raw[2:].lower()
    if entity_type=="domain":
        domain=raw.lower().rstrip(".")
        if not domain or "/" in domain or "@" in domain: raise ValueError("domain must be validated upstream")
        return domain
    if entity_type=="email":
        if raw.count("@")!=1: raise ValueError("invalid email syntax")
        local,domain=raw.rsplit("@",1)
        return local.lower()+"@"+domain.lower()
    raise ValueError("this entity type requires a type-specific validated normalizer")
