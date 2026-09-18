from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any

PATTERNS: tuple[tuple[str,float,str,re.Pattern[str]], ...] = (
    ("instruction_override",.85,"instruction override",re.compile(r"\b(?:ignore|disregard|forget|override)\b.{0,40}\b(?:previous|prior|above|all)\b.{0,40}\b(?:instructions?|rules?|prompts?)\b",re.I|re.S)),
    ("role_hijack",.85,"role hijack",re.compile(r"\byou are (?:now|no longer)\b",re.I)),
    ("role_hijack",.75,"privileged role",re.compile(r"\b(?:act as|pretend to be|roleplay as|simulate)\b.{0,60}\b(?:admin|root|developer|system)\b",re.I|re.S)),
    ("system_prompt_leak",.8,"system prompt disclosure",re.compile(r"\b(?:reveal|show|print|output|repeat|tell me)\b.{0,60}\b(?:system prompt|initial instructions|your rules|original prompt)\b",re.I|re.S)),
    ("jailbreak",.9,"jailbreak marker",re.compile(r"\b(?:DAN|do anything now|developer mode|jailbreak|unrestricted mode)\b",re.I)),
    ("data_exfil",.85,"external exfiltration",re.compile(r"\b(?:send|post|upload|forward|exfiltrate|leak)\b.{0,60}\b(?:to|at)\b.{0,80}\bhttps?://",re.I|re.S)),
    ("tool_abuse",.7,"dangerous tool request",re.compile(r"\b(?:call|invoke|execute|run)\b.{0,30}\b(?:tool|function)\b.{0,50}\b(?:delete|drop|rm|format|admin)\b",re.I|re.S)),
    ("context_poison",.75,"credential memory injection",re.compile(r"\b(?:remember|store|save)\b.{0,50}\b(?:password|key|token|credential)\b",re.I|re.S)),
    ("prompt_leak",.65,"encoded prompt request",re.compile(r"\b(?:base64|rot13|hex|decode)\b.{0,40}\b(?:prompt|instruction)\b",re.I)),
    ("encoding_evasion",.6,"unicode control characters",re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff]{3,}")),
)
DANGEROUS_TOOLS={"delete_file","rm","drop_table","exec","eval","shell","delete_database","shutdown","format","destroy","send_email","send_sms","post_to_webhook","wire_transfer","create_user","grant_admin","revoke_user"}
SENSITIVE_ARGS=((re.compile(r"\.\./\.\./"),"path_traversal",.7),(re.compile(r"^/(etc|proc|sys|dev)/"),"system_path",.6),(re.compile(r"\$\("),"shell_subst",.8),(re.compile(r"[;&|`]"),"shell_meta",.6),(re.compile(r"https?://(?!localhost|127\.0\.0\.1)"),"external_url",.3))

@dataclass(frozen=True, slots=True)
class InjectionVerdict:
    score: float
    verdict: str
    categories: list[str]=field(default_factory=list)
    signals: list[dict[str,Any]]=field(default_factory=list)

class PromptInjectionDetector:
    def detect(self, content:str)->InjectionVerdict:
        if not content: return InjectionVerdict(0.0,"clean")
        normalized=self._normalize(content); score=0.0; categories=[]; signals=[]
        for cat,weight,label,pattern in PATTERNS:
            m=pattern.search(normalized)
            if m:
                signals.append({"category":cat,"label":label,"weight":weight,"snippet":normalized[max(0,m.start()-20):m.end()+20][:200]})
                score+=weight
                if cat not in categories: categories.append(cat)
        if self._has_hidden_payload(content):
            score+=.5; categories.append("encoding_evasion") if "encoding_evasion" not in categories else None
            signals.append({"category":"encoding_evasion","label":"hidden encoded instruction","weight":.5})
        score=min(score,1.0)
        return InjectionVerdict(score,"malicious" if score>=.8 else "suspicious" if score>=.45 else "clean",categories,signals)

    def check_tool_call(self,tool_name:str,args:dict[str,Any])->InjectionVerdict:
        score=.6 if tool_name in DANGEROUS_TOOLS else 0.0; categories=["tool_abuse"] if score else []; signals=[{"category":"tool_abuse","label":f"dangerous tool: {tool_name}","weight":.6}] if score else []
        flat=self._flatten(args)
        for pattern,label,weight in SENSITIVE_ARGS:
            if pattern.search(flat):
                score+=weight; signals.append({"category":"tool_abuse","label":label,"weight":weight});
                if "tool_abuse" not in categories: categories.append("tool_abuse")
        score=min(score,1.0)
        return InjectionVerdict(score,"malicious" if score>=.75 else "suspicious" if score>=.4 else "clean",categories,signals)

    @staticmethod
    def _normalize(s:str)->str:
        s=re.sub(r"[\u200b-\u200f\u202a-\u202e\ufeff]","",s)
        return re.sub(r"\s+"," ",s)

    @staticmethod
    def _has_hidden_payload(s:str)->bool:
        # Prompt-smuggling payloads are commonly short enough to evade the old
        # 80-character threshold. Require a bounded base64-looking token and
        # strict decoding so ordinary prose is not treated as encoded content.
        for m in re.finditer(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{32,}(?![A-Za-z0-9+/=])",s):
            candidate=m.group()
            if len(candidate) % 4:
                candidate += "=" * (-len(candidate) % 4)
            try:
                text=base64.b64decode(candidate,validate=True).decode("utf-8",errors="strict").lower()
            except (ValueError,UnicodeError):
                continue
            if any(k in text for k in ("ignore","system","instruction","execute","admin")):
                return True
        return False

    @staticmethod
    def _flatten(obj:Any,depth:int=0)->str:
        if depth>5:return ""
        if isinstance(obj,dict):return " ".join(PromptInjectionDetector._flatten(v,depth+1) for v in obj.values())
        if isinstance(obj,(list,tuple)):return " ".join(PromptInjectionDetector._flatten(v,depth+1) for v in obj)
        return str(obj)
