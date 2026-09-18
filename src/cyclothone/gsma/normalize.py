from __future__ import annotations
import hashlib
from dataclasses import dataclass

@dataclass(frozen=True)
class OperatorTarget:
    operator_id: str
    mcc_mnc: str
    country: str

class OperatorResolver:
    CC_TO_MCC={"234":"621","254":"639","229":"616","225":"602","233":"620","27":"655"}

    @classmethod
    def resolve(cls,e164:str,known_operators:list[dict])->OperatorTarget|None:
        if not e164.startswith("+"): return None
        digits=e164[1:]
        for n in (3,2,1):
            cc=digits[:n]
            mcc=cls.CC_TO_MCC.get(cc)
            if mcc:
                for op in known_operators:
                    if op.get("mcc_mnc","").startswith(mcc+"-"):
                        return OperatorTarget(op["id"],op["mcc_mnc"],op["country"])
        return None

    @staticmethod
    def hash_value(v:str)->str:
        return hashlib.sha256(v.strip().lower().encode()).hexdigest()
