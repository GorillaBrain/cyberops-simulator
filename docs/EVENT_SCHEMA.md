# Canonical Event Schema

All synthetic security events in CyberOps Simulator follow a normalized schema validated by `validateEventRecord` and `validateEventDataset` in `src/utils/eventSchema.js`.

## Required Fields

- `eventId` (`string`): Unique identifier within the scenario (e.g., `"EVT-305"`).
- `timestamp` (`string`): Timezone-aware ISO 8601 UTC timestamp (e.g., `"2026-10-20T13:22:18Z"`).
- `source` (`string`): Telemetry collector name:
  - `iam_auth`
  - `edr_sensor`
  - `dns_resolver`
  - `perimeter_fw`
  - `secure_proxy`
  - `file_integrity`
  - `directory_svc`
  - `siem_alert`
- `eventType` (`string`): Normalized category:
  - `authentication`
  - `process_execution`
  - `dns_query`
  - `firewall_connection`
  - `web_proxy`
  - `file_activity`
  - `account_change`
  - `endpoint_detection`
- `severity` (`string`): `"low"`, `"medium"`, `"high"`, or `"critical"`.
- `message` (`string`): Human-readable description of the event.

## Optional Contextual Fields

- `host` (`string`): Endpoint or server hostname.
- `username` (`string`): Account username.
- `sourceIp` (`string`): Source IPv4 address.
- `destinationIp` (`string`): Destination IPv4 address.
- `domain` (`string`): Domain name involved in DNS or HTTP/S activity.
- `processName` (`string`): Executing process name.
- `parentProcess` (`string`): Parent process name.
- `commandLine` (`string`): Simulated command line string (never executed).
- `action` (`string`): Specific action taken (e.g. `"user_login"`, `"file_create"`).
- `result` (`string`): Outcome (`"success"`, `"failure"`, `"blocked"`).
- `tags` (`string[]`): Array of analytical tags.
- `metadata` (`object`): Additional key-value context and `relatedEventIds`.

When an optional field is absent on an event, the UI displays an explicit `Unavailable` indicator rather than inventing placeholder values.
