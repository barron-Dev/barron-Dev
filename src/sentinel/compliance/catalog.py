from __future__ import annotations

from typing import Final

# Reference control catalog. These mappings support evidence collection and
# questionnaire preparation; they do not constitute legal advice, certification,
# or an auditor's conclusion.
CONTROLS: Final[list[dict[str, object]]] = [
    {"id":"soc2.CC6.1","framework":"soc2","code":"CC6.1","title":"Logical access security controls","category":"access","evidence_sources":["devices","audit_log"],"check_key":"endpoint_coverage"},
    {"id":"soc2.CC6.6","framework":"soc2","code":"CC6.6","title":"Boundary protection","category":"network","evidence_sources":["data_trust","detections"],"check_key":"detection_active"},
    {"id":"soc2.CC6.8","framework":"soc2","code":"CC6.8","title":"Prevent unauthorized software","category":"endpoint","evidence_sources":["devices","detections"],"check_key":"endpoint_coverage"},
    {"id":"soc2.CC7.1","framework":"soc2","code":"CC7.1","title":"Detection and monitoring","category":"monitoring","evidence_sources":["detections","agent_actions"],"check_key":"detection_active"},
    {"id":"soc2.CC7.2","framework":"soc2","code":"CC7.2","title":"Incident response","category":"response","evidence_sources":["crime_cases","commands"],"check_key":"ir_process"},
    {"id":"soc2.CC8.1","framework":"soc2","code":"CC8.1","title":"Change management","category":"governance","evidence_sources":["audit_log","commands"],"check_key":"audit_activity"},
    {"id":"soc2.CC9.1","framework":"soc2","code":"CC9.1","title":"Risk mitigation","category":"governance","evidence_sources":["recovery_vault_policies"],"check_key":"backup_active"},
    {"id":"soc2.A1.2","framework":"soc2","code":"A1.2","title":"Data backup and recovery","category":"availability","evidence_sources":["recovery_snapshots","recovery_restore_jobs"],"check_key":"backup_tested"},
    {"id":"iso.A.5.15","framework":"iso27001","code":"A.5.15","title":"Access control","category":"access","evidence_sources":["devices","audit_log"],"check_key":"endpoint_coverage"},
    {"id":"iso.A.8.7","framework":"iso27001","code":"A.8.7","title":"Protection against malware","category":"endpoint","evidence_sources":["devices","detections"],"check_key":"endpoint_coverage"},
    {"id":"iso.A.8.15","framework":"iso27001","code":"A.8.15","title":"Logging","category":"monitoring","evidence_sources":["audit_log"],"check_key":"audit_activity"},
    {"id":"iso.A.8.16","framework":"iso27001","code":"A.8.16","title":"Monitoring activities","category":"monitoring","evidence_sources":["detections","hunt_runs"],"check_key":"detection_active"},
    {"id":"iso.A.5.29","framework":"iso27001","code":"A.5.29","title":"Information security during disruption","category":"availability","evidence_sources":["recovery_vault_policies"],"check_key":"backup_active"},
    {"id":"gdpr.Art.5","framework":"gdpr","code":"Art.5","title":"Principles relating to processing","category":"governance","evidence_sources":["residency_audit","audit_log"],"check_key":"audit_activity"},
    {"id":"gdpr.Art.25","framework":"gdpr","code":"Art.25","title":"Data protection by design and by default","category":"privacy","evidence_sources":["data_trust"],"check_key":"data_trust_active"},
    {"id":"gdpr.Art.30","framework":"gdpr","code":"Art.30","title":"Records of processing","category":"governance","evidence_sources":["audit_log"],"check_key":"audit_activity"},
    {"id":"gdpr.Art.32","framework":"gdpr","code":"Art.32","title":"Security of processing","category":"security","evidence_sources":["data_trust","devices","detections"],"check_key":"data_trust_active"},
    {"id":"gdpr.Art.33","framework":"gdpr","code":"Art.33","title":"Notification of a personal data breach","category":"response","evidence_sources":["crime_cases","detections"],"check_key":"ir_process"},
    {"id":"hipaa.164.308","framework":"hipaa","code":"164.308","title":"Administrative safeguards","category":"governance","evidence_sources":["audit_log","crime_cases"],"check_key":"ir_process"},
    {"id":"hipaa.164.312","framework":"hipaa","code":"164.312","title":"Technical safeguards","category":"security","evidence_sources":["devices","data_trust"],"check_key":"data_trust_active"},
    {"id":"hipaa.164.308.a.7","framework":"hipaa","code":"164.308(a)(7)","title":"Contingency plan","category":"availability","evidence_sources":["recovery_vault_policies","recovery_restore_jobs"],"check_key":"backup_tested"},
    {"id":"pci.1","framework":"pci_dss","code":"Req 1","title":"Network security controls","category":"network","evidence_sources":["detections","data_trust"],"check_key":"detection_active"},
    {"id":"pci.5","framework":"pci_dss","code":"Req 5","title":"Malware protection","category":"endpoint","evidence_sources":["devices","detections"],"check_key":"endpoint_coverage"},
    {"id":"pci.10","framework":"pci_dss","code":"Req 10","title":"Log and monitor all access","category":"monitoring","evidence_sources":["audit_log","hunt_runs"],"check_key":"audit_activity"},
    {"id":"uae.16","framework":"uae_pdpl","code":"Art.16","title":"Data security","category":"security","evidence_sources":["data_trust","devices"],"check_key":"data_trust_active"},
    {"id":"uae.9","framework":"uae_pdpl","code":"Art.9","title":"Personal-data breach response","category":"response","evidence_sources":["crime_cases","detections"],"check_key":"ir_process"},
    {"id":"ng.39","framework":"ndpa_ng","code":"Art.39","title":"Security measures","category":"security","evidence_sources":["data_trust","devices"],"check_key":"data_trust_active"},
    {"id":"ng.40","framework":"ndpa_ng","code":"Art.40","title":"Personal-data breach response","category":"response","evidence_sources":["crime_cases","detections"],"check_key":"ir_process"},
]

FRAMEWORKS: Final[dict[str, dict[str, str]]] = {
    "soc2": {"name":"SOC 2 Type II", "version":"2017 TSC", "authority":"AICPA"},
    "iso27001": {"name":"ISO/IEC 27001", "version":"2022", "authority":"ISO"},
    "gdpr": {"name":"GDPR", "version":"2018", "authority":"EU"},
    "hipaa": {"name":"HIPAA Security Rule", "version":"2013", "authority":"HHS"},
    "pci_dss": {"name":"PCI DSS", "version":"4.0", "authority":"PCI SSC"},
    "uae_pdpl": {"name":"UAE PDPL", "version":"2021", "authority":"UAE"},
    "ndpa_ng": {"name":"NDPA Nigeria", "version":"2023", "authority":"NDPC"},
}


def controls_for(framework: str) -> list[dict[str, object]]:
    return [c for c in CONTROLS if c["framework"] == framework]
