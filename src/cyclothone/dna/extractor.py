from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

TRAIT_DIMS: dict[str, int] = {
    "ttp.mitre_set": 128, "tooling.malware_family": 64, "tooling.tool_stack": 32,
    "timing.beacon_interval": 16, "timing.activity_hours": 24,
    "targeting.sector": 32, "targeting.geography": 48,
    "language.idioms": 64, "language.grammar_errors": 32,
    "crypto.address_pattern": 32, "crypto.ransom_note_style": 48,
    "infrastructure.asn": 32, "infrastructure.domain_pattern": 48,
    "infrastructure.cert_reuse": 32, "artifact.file_metadata": 48,
    "artifact.mutex": 32, "voice.prosody": 48, "visual.logo_phash": 32,
    "behavioral.process_tree": 128, "behavioral.timing_signature": 64,
}
TRAIT_OFFSETS: dict[str, int] = {}
_offset = 0
for _trait, _dim in TRAIT_DIMS.items():
    TRAIT_OFFSETS[_trait] = _offset
    _offset += _dim
TOTAL_DIM = _offset
SCHEMA_HASH = hashlib.sha256(
    "|".join(f"{k}:{v}" for k, v in TRAIT_DIMS.items()).encode("utf-8")
).hexdigest()
EXTRACTOR_VERSION = "rules-v2"


@dataclass(frozen=True)
class DNAFingerprint:
    vector: list[float]
    traits: dict[str, Any]
    trait_ids: list[str]
    confidence: float
    coverage: float
    schema_hash: str = SCHEMA_HASH
    extractor_version: str = EXTRACTOR_VERSION

    def __post_init__(self) -> None:
        if len(self.vector) != TOTAL_DIM:
            raise ValueError(f"vector must be {TOTAL_DIM} dimensions")
        if not 0 <= self.confidence <= 1 or not 0 <= self.coverage <= 1:
            raise ValueError("confidence/coverage out of range")
        if not all(math.isfinite(x) for x in self.vector):
            raise ValueError("DNA vector contains a non-finite value")


class DNAExtractor:
    """Deterministic, versioned feature extraction. It produces evidence, not identity."""

    def extract(self, payload: dict[str, Any]) -> DNAFingerprint:
        if not isinstance(payload, dict):
            raise TypeError("payload must be an object")
        vec = [0.0] * TOTAL_DIM
        traits: dict[str, Any] = {}
        trait_ids: list[str] = []

        def mark(trait: str) -> None:
            if trait not in trait_ids:
                trait_ids.append(trait)

        self._hash_list(payload.get("mitre_techniques"), "ttp.mitre_set", vec)
        if payload.get("mitre_techniques"):
            traits["mitre_set"] = sorted({str(x) for x in payload["mitre_techniques"]})
            mark("ttp.mitre_set")

        family = self._text(payload.get("malware_family"))
        if family:
            self._set_hash(family, "tooling.malware_family", vec)
            traits["malware_family"] = family
            mark("tooling.malware_family")

        tools = self._strings(payload.get("tools"))
        self._hash_list(tools, "tooling.tool_stack", vec)
        if tools:
            traits["tools"] = sorted(set(tools)); mark("tooling.tool_stack")

        interval = payload.get("beacon_interval_seconds")
        if isinstance(interval, (int, float)) and math.isfinite(interval) and interval > 0:
            self._set_bin(interval, "timing.beacon_interval", vec, 1, 86400)
            traits["beacon_interval"] = float(interval); mark("timing.beacon_interval")

        hours = payload.get("activity_hours") or []
        if isinstance(hours, list):
            counts = Counter(int(h) for h in hours if isinstance(h, (int, float)) and 0 <= h < 24)
            total = sum(counts.values())
            if total:
                off = TRAIT_OFFSETS["timing.activity_hours"]
                for h, c in counts.items(): vec[off + h] = c / total
                traits["activity_hours"] = sorted(counts); mark("timing.activity_hours")

        for field, trait in (("target_sectors","targeting.sector"),("target_countries","targeting.geography")):
            vals = self._strings(payload.get(field))
            self._hash_list(vals, trait, vec, upper=trait.endswith("geography"))
            if vals:
                traits[field] = sorted({v.upper() if trait.endswith("geography") else v for v in vals})
                mark(trait)

        text = self._text(payload.get("text_sample"))[:2000]
        if text:
            toks = re.findall(r"[^Wd_]{2,20}(?:['’][^Wd_]{1,20})?", text.casefold(), re.UNICODE)
            grams = [f"{a} {b}" for a,b in zip(toks,toks[1:])][:200]
            self._hash_list(grams, "language.idioms", vec); mark("language.idioms")
            errors = self._language_markers(text)
            self._hash_list(errors, "language.grammar_errors", vec)
            if errors: traits["language_markers"] = errors; mark("language.grammar_errors")

        addrs = self._strings(payload.get("crypto_addresses"))
        prefixes = [a[:8].casefold() for a in addrs if len(a) >= 8]
        self._hash_list(prefixes, "crypto.address_pattern", vec)
        if prefixes: traits["wallet_prefixes"] = sorted(set(prefixes)); mark("crypto.address_pattern")

        note = self._text(payload.get("ransom_note"))[:4000]
        if note:
            toks = re.findall(r"[^Wd_]{2,20}", note.casefold(), re.UNICODE)
            grams = [f"{a} {b} {c}" for a,b,c in zip(toks,toks[1:],toks[2:])][:300]
            self._hash_list(grams, "crypto.ransom_note_style", vec); traits["note_grams"] = len(grams); mark("crypto.ransom_note_style")

        for field, trait in (("asns","infrastructure.asn"),("cert_fingerprints","infrastructure.cert_reuse"),("mutexes","artifact.mutex")):
            vals = self._strings(payload.get(field))
            self._hash_list(vals, trait, vec)
            if vals: traits[field] = sorted(set(vals)); mark(trait)

        domains = self._strings(payload.get("domains"))
        patterns = sorted({self._domain_pattern(d) for d in domains if d})
        self._hash_list(patterns, "infrastructure.domain_pattern", vec)
        if patterns: traits["domain_patterns"] = patterns; mark("infrastructure.domain_pattern")

        meta = payload.get("file_metadata")
        if isinstance(meta, dict):
            vals = [f"{k}={meta[k]}" for k in ("pdb_path","compiler","compile_date","language") if meta.get(k)]
            self._hash_list(vals, "artifact.file_metadata", vec)
            if vals: traits["file_meta_keys"] = [v.split("=",1)[0] for v in vals]; mark("artifact.file_metadata")

        tree = payload.get("process_tree") or []
        edges = []
        if isinstance(tree, list):
            for e in tree[:200]:
                if isinstance(e, dict):
                    p,c = self._text(e.get("parent")),self._text(e.get("child"))
                    if p and c: edges.append(f"{p}>{c}")
        self._hash_list(edges, "behavioral.process_tree", vec)
        if edges: traits["process_tree_edges"] = sorted(set(edges)); mark("behavioral.process_tree")

        delays = payload.get("stage_delays_seconds") or []
        valid_delays = [float(d) for d in delays if isinstance(d,(int,float)) and math.isfinite(d) and d > 0] if isinstance(delays,list) else []
        for d in valid_delays: self._set_bin(d, "behavioral.timing_signature", vec, 1, 86400)
        if valid_delays: traits["delays"] = valid_delays; mark("behavioral.timing_signature")

        vp = payload.get("voice_prosody")
        if isinstance(vp, dict):
            vals = [f"{k}={float(v):.8g}" for k,v in vp.items() if isinstance(v,(int,float)) and math.isfinite(v)]
            self._hash_list([k for k,_ in (x.split("=",1) for x in vals)], "voice.prosody", vec)
            if vals: traits["voice_prosody"] = vp; mark("voice.prosody")

        ph = self._text(payload.get("logo_phash"))
        if ph:
            self._set_hash(ph, "visual.logo_phash", vec); traits["logo_phash"] = ph; mark("visual.logo_phash")

        vec = self._l2(vec)
        coverage = len(trait_ids) / len(TRAIT_DIMS)
        confidence = self._confidence(trait_ids, payload)
        return DNAFingerprint(vec, traits, sorted(trait_ids), round(confidence,4), round(coverage,4))

    @staticmethod
    def _text(v: Any) -> str:
        return v.strip() if isinstance(v,str) else ""

    @staticmethod
    def _strings(v: Any) -> list[str]:
        return [x.strip() for x in v if isinstance(x,str) and x.strip()] if isinstance(v,list) else []

    @staticmethod
    def _stable_hash(s: str, dim: int) -> int:
        return int.from_bytes(hashlib.sha256(s.encode("utf-8")).digest()[:8],"big") % dim

    def _set_hash(self, value: str, trait: str, vec: list[float]) -> None:
        vec[TRAIT_OFFSETS[trait] + self._stable_hash(value,TRAIT_DIMS[trait])] = 1.0

    def _hash_list(self, values: Any, trait: str, vec: list[float], upper: bool=False) -> None:
        if not isinstance(values,list): return
        for value in values:
            s = str(value).upper() if upper else str(value)
            if s: self._set_hash(s,trait,vec)

    def _set_bin(self, value: float, trait: str, vec: list[float], lo: float, hi: float) -> None:
        vec[TRAIT_OFFSETS[trait] + self._log_bucket(value,TRAIT_DIMS[trait],lo,hi)] = 1.0

    @staticmethod
    def _log_bucket(value: float, dim: int, lo: float, hi: float) -> int:
        value=max(lo,min(hi,value))
        if value <= lo: return 0
        if value >= hi: return dim-1
        n=(math.log(value)-math.log(lo))/(math.log(hi)-math.log(lo))
        return min(dim-1,max(0,int(n*dim)))

    @staticmethod
    def _domain_pattern(domain: str) -> str:
        label=domain.rsplit(".",1)[0].casefold()
        digits=sum(c.isdigit() for c in label)
        if label and digits > len(label)*0.4: return "numeric"
        vowels=sum(c in "aeiou" for c in label)
        if label and vowels < len(label)*0.15: return "low-vowel"
        if "-" in label: return "hyphenated"
        return "manual"

    @staticmethod
    def _language_markers(text: str) -> list[str]:
        # Linguistic markers only; deliberately avoids nationality/ethnicity labels.
        patterns = {
            "generic_salutation": r"\bdear\s+(customer|user|sir|madam)\b",
            "urgency_pair": r"\b(immediate|urgent)\s+(action|attention)\b",
            "needful_phrase": r"\bdo\s+the\s+needful\b",
            "revert_back": r"\brevert\s+back\b",
            "formal_kindly": r"\bkindly\b",
        }
        return sorted(k for k,p in patterns.items() if re.search(p,text,re.I))

    @staticmethod
    def _l2(vec: list[float]) -> list[float]:
        norm=math.sqrt(sum(x*x for x in vec))
        return vec if norm < 1e-12 else [x/norm for x in vec]

    @staticmethod
    def _confidence(traits: list[str], payload: dict[str,Any]) -> float:
        if not traits: return 0.0
        independent = min(len(traits), 12) / 12
        corroboration = min(
            sum(1 for k in ("mitre_techniques","tools","domains","asns","process_tree","text_sample")
                if payload.get(k)), 6
        ) / 6
        return min(0.95, 0.25 + 0.5*independent + 0.2*corroboration)
