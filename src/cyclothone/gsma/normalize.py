from __future__ import annotations
import hashlib
from dataclasses import dataclass

@dataclass(frozen=True)
class OperatorTarget:
    operator_id: str
    mcc_mnc: str
    country: str

class OperatorResolver:
    @classmethod
    def resolve(cls,e164:str,known_operators:list[dict])->OperatorTarget|None:
        if not e164.startswith("+"): return None
        digits=e164[1:]
        matches=[]
        for op in known_operators:
            if not op.get("enabled", True): continue
            for prefix in op.get("number_prefixes") or []:
                p=str(prefix).lstrip("+")
                if p and digits.startswith(p):
                    matches.append((len(p),op))
        if not matches: return None
        _,op=max(matches,key=lambda item:item[0])
        return OperatorTarget(op["id"],op["mcc_mnc"],op["country"])

    @staticmethod
    def hash_value(v:str)->str:
        return hashlib.sha256(v.strip().lower().encode()).hexdigest()
