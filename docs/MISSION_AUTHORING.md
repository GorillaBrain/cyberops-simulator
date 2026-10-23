# Mission Authoring Guide

You can author new missions in `src/data/missions/campaignMissions.js` or import custom scenarios directly in the UI under **Practice Lab & Triage ➔ Custom Scenario Import**.

## Scenario Schema

Each scenario JSON object must include:
- `id`: Alphanumeric slug (`3-64` characters, e.g. `"custom-usb-drop-scenario"`).
- `title`: Human-readable title.
- `subtitle`: Short learning focus subtitle.
- `difficulty`: `"Tutorial"`, `"Easy"`, `"Medium"`, `"Hard"`, `"Expert"`, or `"Custom"`.
- `organization`: Fictional organization name.
- `environment`: Network/system context.
- `minimumEvidenceRequired`: Minimum evidence count required before submitting a report.
- `briefing`: Object containing `summary`, `initialAlert`, `knownFacts`, `unknowns`, `telemetrySources`, `timeWindow`, and `consequencesOfPoorDecisions`.
- `objectives`: Array of objective definitions (`run_search`, `collect_evidence`, `run_detections`, `inspect_timeline`, `execute_response`, `complete_assessment`).
- `hints`: Progressive 3-level hints (`level: 1..3`).
- `events`: Array of canonical telemetry events (validated by `validateEventDataset`).
- `groundTruth`: Kept separate from player-visible briefing views; defines `classification`, `severity`, `affectedEntities`, `attackStages`, `expectedEvidenceIds`, `bonusEvidenceIds`, `expectedResponseActions`, and post-mission `explanation`.

## Safety Guidelines for Mission Authors

1. Always use reserved RFC 5737 documentation IPv4 ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 1918 private addresses (`10.x.x.x`).
2. Always use reserved example domains (`*.example.com`, `*.example.net`, `*.example.org`).
3. Include realistic benign telemetry alongside malicious events so analysts must correlate context rather than flagging every alert blindly.
