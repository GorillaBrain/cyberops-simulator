# Detection Rules Reference

Detection rules are defined in `src/data/rules/detectionRules.js` and evaluated by `src/engine/detectionEngine.js`.

## Rule Structure

```json
{
  "id": "DET-002",
  "name": "Multi-Account Password Spraying From Single Source",
  "description": "Detects a single source IP failing authentication across 4 or more distinct user accounts within a 10-minute window.",
  "severity": "high",
  "type": "threshold",
  "supportedSources": ["iam_auth", "authentication"],
  "conditionQuery": "eventType = \"authentication\" AND result = \"failure\"",
  "aggregation": {
    "groupBy": "sourceIp",
    "windowSeconds": 600,
    "threshold": 4,
    "distinctField": "username",
    "distinctThreshold": 4
  },
  "attackMappings": [
    {
      "techniqueId": "T1110.003",
      "techniqueName": "Brute Force: Password Spraying",
      "tactic": "Credential Access",
      "version": "MITRE ATT&CK v15",
      "confidence": "supported",
      "rationale": "Low-volume authentication attempts distributed across many distinct accounts from a single IP."
    }
  ],
  "falsePositiveConsiderations": "Misconfigured internal service scanners or shared NAT gateways...",
  "remediationGuidance": "Block the offending external source IP and audit targeted accounts..."
}
```

## Included Rules (`DET-001` – `DET-012`)

1. `DET-001` — Repeated Failed Authentication Against Single Account (`T1110.001`)
2. `DET-002` — Multi-Account Password Spraying From Single Source (`T1110.003`)
3. `DET-003` — Successful Authentication Following Repeated Failures (`T1078`)
4. `DET-004` — Authentication From Anomalous External Network (`T1078`)
5. `DET-005` — Suspicious Office or Web Parent Spawning Scripting Interpreter (`T1059.001`)
6. `DET-006` — Encoded or Obfuscated Command-Line Execution (`T1027`, `T1059.001`) with `CcmExec.exe` exclusion
7. `DET-007` — Suspicious Persistence Mechanism Creation (`T1053.005`, `T1547.001`)
8. `DET-008` — Unexpected Privilege Escalation or Admin Group Modification (`T1098`)
9. `DET-009` — DNS Query to Suspicious or Uncategorized C2 Domain (`T1071.004`)
10. `DET-010` — Unusual Outbound Beaconing or High-Volume Transfer From Workstation (`T1071.001`, `T1041`)
11. `DET-011` — Bulk Access or Archiving of Sensitive Restricted Files (`T1005`)
12. `DET-012` — Suspicious Local or Backdoor Account Creation (`T1136.001`)
