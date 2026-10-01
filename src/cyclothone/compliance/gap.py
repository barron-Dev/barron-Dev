from __future__ import annotations

from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True, slots=True)
class Gap:
    control_id: str
    code: str
    title: str
    category: str
    status: str
    severity: str
    suggested_action: str
    effort: str
    framework_count: int

class GapAnalyzer:
    SEVERITY_BY_STATUS = {"failing": "high", "partial": "medium", "unknown": "medium"}
    ACTIONS = {
        "mfa_enforced": "Enable MFA on all administrative identities and verify enforcement telemetry.",
        "tls_enforced": "Enforce modern TLS and verify endpoint transport configuration.",
        "encryption_at_rest": "Verify encryption at rest for protected stores and recovery artifacts.",
        "endpoint_coverage": "Enroll missing production endpoints and verify telemetry coverage.",
        "detection_active": "Enable monitoring rules and verify recent security telemetry.",
        "ir_process": "Document the incident-response procedure and exercise it with a recorded case.",
        "backup_active": "Create and enable a recovery policy for required production data.",
        "backup_tested": "Perform and record a restore test against the recovery policy.",
        "siem_forwarding": "Configure an approved security-log destination and verify forwarding.",
        "audit_retention": "Verify that required audit records are retained for the applicable period.",
    }

    def analyze(self, controls: list[dict[str, Any]], statuses: dict[str, dict[str, Any]], framework_membership: dict[str, set[str]]) -> list[Gap]:
        gaps: list[Gap] = []
        for control in controls:
            cid = str(control["id"])
            status = str(statuses.get(cid, {}).get("status", "unknown"))
            if status in {"passing", "not_applicable"}:
                continue
            frameworks = framework_membership.get(cid, {str(control.get("framework", ""))})
            severity = self.SEVERITY_BY_STATUS.get(status, "low")
            if len(frameworks) >= 3 and severity == "medium":
                severity = "high"
            key = str(control.get("check_key", ""))
            gaps.append(Gap(cid, str(control.get("code", "")), str(control.get("title", "")), str(control.get("category", "governance")), status, severity, self.ACTIONS.get(key, "Review control implementation and collect objective evidence."), "low" if key in {"mfa_enforced", "tls_enforced", "encryption_at_rest"} else "medium", len(frameworks)))
        gaps.sort(key=lambda g: ({"high": 0, "medium": 1, "low": 2}[g.severity], -g.framework_count, g.code))
        return gaps
