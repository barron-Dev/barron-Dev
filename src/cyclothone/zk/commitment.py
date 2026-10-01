from __future__ import annotations
import base64, hashlib, secrets
from dataclasses import dataclass

@dataclass(frozen=True)
class Commitment:
    metric: str
    bucket: int
    commitment_hex: str
    blinding_b64: str

class HashCommitment:
    """Versioned hiding commitment primitive. The blinding is never persisted in the proof."""
    DOMAIN=b"cyclothone.zk.commitment.v1\0"
    @staticmethod
    def commit(metric:str,bucket:int,blinding:bytes|None=None)->Commitment:
        if not metric or len(metric)>120: raise ValueError("invalid metric")
        if not -(1<<63)<=bucket<(1<<63): raise ValueError("bucket out of range")
        b=blinding if blinding is not None else secrets.token_bytes(32)
        if len(b)!=32: raise ValueError("blinding must be 32 bytes")
        h=hashlib.sha256(HashCommitment.DOMAIN+metric.encode("utf-8")+bucket.to_bytes(8,"little",signed=True)+b)
        return Commitment(metric,bucket,h.hexdigest(),base64.b64encode(b).decode("ascii"))
    @staticmethod
    def verify(metric:str,bucket:int,blinding_b64:str,commitment_hex:str)->bool:
        try:
            b=base64.b64decode(blinding_b64,validate=True)
            return secrets.compare_digest(HashCommitment.commit(metric,bucket,b).commitment_hex,commitment_hex.lower())
        except (ValueError,TypeError): return False
    @staticmethod
    def bucket_value(value:int,granularity:int=100)->int:
        if granularity<=0: raise ValueError("granularity must be positive")
        if value<0: raise ValueError("value must be non-negative")
        return (value//granularity)*granularity
