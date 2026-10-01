from __future__ import annotations
import hashlib,json
from dataclasses import dataclass,field
DANGEROUS_TOPICS={"/cmd_vel","/cmd_vel_nav","/joint_trajectory","/arm_controller","/base_controller","/emergency_stop","/e_stop","/kill_switch"}
@dataclass
class SROS2Finding: kind:str; severity:str; detail:str; evidence:dict
@dataclass
class SROS2Audit:
    findings:list[SROS2Finding]=field(default_factory=list)
    def add(self,kind,severity,detail,evidence=None): self.findings.append(SROS2Finding(kind,severity,detail,evidence or {}))
class SROS2Auditor:
    def audit(self,inventory:dict)->SROS2Audit:
        a=SROS2Audit()
        if not inventory.get("sros2_enabled"):
            a.add("no_sros2","critical","SROS2 disabled; privileged DDS traffic is not protected.",{"framework":inventory.get("framework")}); return a
        ks=inventory.get("keystore_path","")
        if ks and inventory.get("keystore_perms") in ("0777","0775","0755"): a.add("keystore_world_readable","critical","SROS2 keystore is readable by non-owner users.",{"path":ks,"perms":inventory.get("keystore_perms")})
        for t in inventory.get("topics",[]):
            if t.get("name") in DANGEROUS_TOPICS and t.get("untrusted_publishers",0)>0: a.add("unauth_publisher","critical",f"Untrusted publisher on privileged topic {t['name']}.",{"topic":t["name"],"publishers":t.get("untrusted_publishers")})
        if inventory.get("governance",{}).get("default_rule")=="allow": a.add("permissive_governance","high","SROS2 governance default is ALLOW.",{})
        for c in inventory.get("certificates",[]):
            if c.get("days_until_expiry",999)<14: a.add("cert_expiring","medium",f"Certificate for {c.get('domain_id')} expires soon.",{"domain_id":c.get("domain_id")})
        present={t.get("name") for t in inventory.get("topics",[])}; covered={p.get("topic") for p in inventory.get("permissions",[])}
        for topic in DANGEROUS_TOPICS & present:
            if topic not in covered: a.add("uncovered_privileged_topic","high",f"Privileged topic {topic} has no explicit permission entry.",{"topic":topic})
        return a
    @staticmethod
    def fingerprint(inventory): return hashlib.sha256(json.dumps(inventory,sort_keys=True,default=str).encode()).hexdigest()
