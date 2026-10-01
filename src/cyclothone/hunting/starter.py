STARTER_HUNTS: list[dict] = [
    {"name": "Ransomware: encryption burst", "description": "Blocked detections with high-confidence signals.", "query": 'detections where verdict == "block" and score > 0.85 | limit 200', "tags": ["ransomware", "impact"]},
    {"name": "Lateral movement: SMB", "description": "Detections mapped to SMB/Windows Admin Shares.", "query": 'detections where mitre_technique == "T1021" and verdict != "allow" | limit 500', "tags": ["lateral_movement"]},
    {"name": "Canary triggers", "description": "Recent deception triggers for investigation.", "query": "canary_triggers | limit 200", "tags": ["deception", "confirmed"]},
    {"name": "Blocked AI tool calls", "description": "Agent actions blocked by policy or injection controls.", "query": "agent_actions where blocked == true | limit 500", "tags": ["ai_security"]},
    {"name": "High-score detections", "description": "Recent high-confidence detections for threat-intel review.", "query": "detections where score > 0.7 | limit 300", "tags": ["threat_intel"]},
    {"name": "Process telemetry", "description": "Recent process events for execution review.", "query": 'events where event_type == "process" | limit 500', "tags": ["execution", "process"]},
    {"name": "Failed response actions", "description": "Response actions that need reliability investigation.", "query": 'case_actions where status == "failed" | limit 200', "tags": ["response", "reliability"]},
    {"name": "Quarantine detections", "description": "Detections that resulted in quarantine.", "query": 'detections where verdict == "quarantine" | limit 500', "tags": ["response"]},
]
