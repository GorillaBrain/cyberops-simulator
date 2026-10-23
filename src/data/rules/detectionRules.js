export const DETECTION_RULES = [
  {
    id: 'DET-001',
    name: 'Repeated Failed Authentication Against Single Account',
    description:
      'Detects three or more failed authentication attempts against the same user account within a 5-minute window.',
    severity: 'medium',
    type: 'threshold',
    supportedSources: ['iam_auth', 'authentication'],
    conditionQuery: 'eventType = "authentication" AND result = "failure"',
    conditionSummary: '>= 3 failed logins for same username within 300s',
    aggregation: {
      groupBy: 'username',
      windowSeconds: 300,
      threshold: 3
    },
    attackMappings: [
      {
        techniqueId: 'T1110.001',
        techniqueName: 'Brute Force: Password Guessing',
        tactic: 'Credential Access',
        version: 'MITRE ATT&CK v15',
        confidence: 'suspected',
        rationale:
          'Repeated authentication failures against a single identity may indicate automated password guessing or a user mistyping credentials.'
      }
    ],
    falsePositiveConsiderations:
      'Users frequently mistype passwords after a password rotation, keyboard layout change, or expired cached mobile/VPN credential. Check whether the source IP and workstation belong to the user and whether an IT password reset or MFA prompt succeeded.',
    remediationGuidance:
      'Verify source IP reputation and device ownership. If originating from an unrecognized external IP without MFA verification, reset credentials and block the offending IP.'
  },
  {
    id: 'DET-002',
    name: 'Multi-Account Password Spraying From Single Source',
    description:
      'Detects a single source IP failing authentication across 4 or more distinct user accounts within a 10-minute window.',
    severity: 'high',
    type: 'threshold',
    supportedSources: ['iam_auth', 'authentication'],
    conditionQuery: 'eventType = "authentication" AND result = "failure"',
    conditionSummary: '>= 4 failed logins across >= 4 distinct usernames from same sourceIp within 600s',
    aggregation: {
      groupBy: 'sourceIp',
      windowSeconds: 600,
      threshold: 4,
      distinctField: 'username',
      distinctThreshold: 4
    },
    attackMappings: [
      {
        techniqueId: 'T1110.003',
        techniqueName: 'Brute Force: Password Spraying',
        tactic: 'Credential Access',
        version: 'MITRE ATT&CK v15',
        confidence: 'supported',
        rationale:
          'Low-volume authentication attempts distributed across many distinct accounts from a single IP evade per-account lockout thresholds.'
      }
    ],
    falsePositiveConsiderations:
      'Misconfigured internal service scanners or shared NAT gateways can occasionally aggregate failed logins, though rarely with identical user-agent strings and uniform intervals.',
    remediationGuidance:
      'Block the offending external source IP at the perimeter firewall and audit whether any targeted account subsequently recorded a successful login from that IP.'
  },
  {
    id: 'DET-003',
    name: 'Successful Authentication Following Repeated Failures',
    description:
      'Detects a successful authentication event preceded by at least 2 failed attempts on the same account within 10 minutes.',
    severity: 'high',
    type: 'sequence',
    supportedSources: ['iam_auth', 'authentication'],
    conditionSummary: '>= 2 failed logins followed by a successful login for the same username within 600s',
    sequence: {
      step1Query: 'eventType = "authentication" AND result = "failure"',
      step1MinCount: 2,
      step2Query: 'eventType = "authentication" AND result = "success"',
      sharedField: 'username',
      windowSeconds: 600
    },
    attackMappings: [
      {
        techniqueId: 'T1078',
        techniqueName: 'Valid Accounts',
        tactic: 'Initial Access',
        version: 'MITRE ATT&CK v15',
        confidence: 'suspected',
        rationale:
          'A successful login immediately after multiple failures can signify either a user finally recalling their password or an adversary guessing a valid credential.'
      }
    ],
    falsePositiveConsiderations:
      'Very common when an employee mistypes their password twice before succeeding from their assigned corporate laptop. Compare the sourceIp, geo-location, MFA method, and post-login activity.',
    remediationGuidance:
      'Correlate the source IP of the failed attempts with the source IP of the successful login. If an external attacker IP succeeded, revoke active sessions and disable the account immediately.'
  },
  {
    id: 'DET-004',
    name: 'Authentication From Anomalous External Network',
    description:
      'Detects successful authentication originating from a non-corporate external documentation range flagged as anomalous geo/ASN context.',
    severity: 'medium',
    type: 'single',
    supportedSources: ['iam_auth', 'authentication'],
    conditionQuery:
      'eventType = "authentication" AND result = "success" AND tags CONTAINS "anomalous_geo"',
    conditionSummary: 'Successful authentication tagged with anomalous geo/ASN origin',
    attackMappings: [
      {
        techniqueId: 'T1078',
        techniqueName: 'Valid Accounts',
        tactic: 'Initial Access',
        version: 'MITRE ATT&CK v15',
        confidence: 'suspected',
        rationale:
          'Logins from unfamiliar external networks or hosting providers often indicate stolen credentials or session tokens.'
      }
    ],
    falsePositiveConsiderations:
      'Employees traveling on approved business trips or using authorized travel VPN gateways may trigger anomalous location alerts.',
    remediationGuidance:
      'Check HR travel logs or IT change tickets, and inspect endpoint/directory actions performed during the session.'
  },
  {
    id: 'DET-005',
    name: 'Suspicious Office or Web Parent Spawning Scripting Interpreter',
    description:
      'Detects productivity applications (winword.exe, excel.exe) or web services (w3wp.exe) spawning command shells or PowerShell.',
    severity: 'high',
    type: 'single',
    supportedSources: ['edr_sensor', 'process_execution'],
    conditionQuery:
      'eventType = "process_execution" AND parentProcess IN ("winword.exe", "excel.exe", "w3wp.exe", "outlook.exe") AND processName IN ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")',
    conditionSummary: 'Office or web server parent process spawning shell/scripting interpreter',
    attackMappings: [
      {
        techniqueId: 'T1059.001',
        techniqueName: 'Command and Scripting Interpreter: PowerShell',
        tactic: 'Execution',
        version: 'MITRE ATT&CK v15',
        confidence: 'supported',
        rationale:
          'Child shell execution from document editors or web workers is a classic indicator of macro/exploit payload execution.'
      }
    ],
    falsePositiveConsiderations:
      'Rare legacy finance macros or internal developer plugins may invoke scripts, but standard corporate policy prohibits Office applications from spawning shells.',
    remediationGuidance:
      'Inspect the command line, isolate the host if external C2 or payload staging occurs, and quarantine the parent document.'
  },
  {
    id: 'DET-006',
    name: 'Encoded or Obfuscated Command-Line Execution',
    description:
      'Detects PowerShell or command interpreter execution using Base64 encoded flags (-enc, -EncodedCommand, FromBase64String) or hidden window execution outside approved SCCM maintenance.',
    severity: 'critical',
    type: 'single',
    supportedSources: ['edr_sensor', 'process_execution'],
    conditionQuery:
      'eventType = "process_execution" AND (commandLine CONTAINS "-enc " OR commandLine CONTAINS "-EncodedCommand" OR commandLine CONTAINS "FromBase64String")',
    exclusionQuery: 'parentProcess = "CcmExec.exe" AND username = "SYSTEM"',
    conditionSummary: 'Encoded command-line execution not spawned by verified CcmExec.exe',
    attackMappings: [
      {
        techniqueId: 'T1027',
        techniqueName: 'Obfuscated Files or Information',
        tactic: 'Defense Evasion',
        version: 'MITRE ATT&CK v15',
        confidence: 'supported',
        rationale:
          'Adversaries encode command strings in Base64 to hide URLs, staging paths, and execution logic from simple string signatures.'
      },
      {
        techniqueId: 'T1059.001',
        techniqueName: 'Command and Scripting Interpreter: PowerShell',
        tactic: 'Execution',
        version: 'MITRE ATT&CK v15',
        confidence: 'supported',
        rationale:
          'PowerShell -EncodedCommand directly executes Base64-encoded UTF-16LE script blocks.'
      }
    ],
    falsePositiveConsiderations:
      'Endpoint management tools (like SCCM/CcmExec) sometimes run signed administrative scripts with encoded parameters. Always verify the parent process, digital signature context, and decoded payload.',
    remediationGuidance:
      'Inspect the decoded payload metadata, check for subsequent network connections or scheduled tasks, and isolate the endpoint if unauthorized.'
  },
  {
    id: 'DET-007',
    name: 'Suspicious Persistence Mechanism Creation',
    description:
      'Detects creation of scheduled tasks (schtasks /create) or Startup/Run registry modifications pointing to user-writable directories (AppData, Temp, ProgramData).',
    severity: 'high',
    type: 'single',
    supportedSources: ['edr_sensor', 'process_execution', 'file_integrity'],
    conditionQuery:
      '(eventType = "process_execution" AND processName = "schtasks.exe" AND commandLine CONTAINS "/create") OR (tags CONTAINS "persistence_change" AND NOT username = "svc_patch_mgmt")',
    conditionSummary: 'Scheduled task creation or unapproved registry Run key persistence',
    attackMappings: [
      {
        techniqueId: 'T1053.005',
        techniqueName: 'Scheduled Task/Job: Scheduled Task',
        tactic: 'Persistence',
        version: 'MITRE ATT&CK v15',
        confidence: 'supported',
        rationale:
          'Scheduled tasks allow adversaries to maintain execution across reboots or run payloads under specific intervals.'
      },
      {
        techniqueId: 'T1547.001',
        techniqueName: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder',
        tactic: 'Persistence',
        version: 'MITRE ATT&CK v15',
        confidence: 'supported',
        rationale:
          'Registry Run keys execute referenced binaries every time the user logs in.'
      }
    ],
    falsePositiveConsiderations:
      'Authorized IT patch management accounts (e.g., svc_patch_mgmt) may register maintenance tasks during scheduled change windows.',
    remediationGuidance:
      'Isolate the affected workstation, quarantine the referenced binary/script in AppData or ProgramData, and remove the persistence entry.'
  },
  {
    id: 'DET-008',
    name: 'Unexpected Privilege Escalation or Admin Group Modification',
    description:
      'Detects user accounts added to privileged directory groups (Domain Admins, Local Administrators, Cloud Infra Admins) without an approved change ticket.',
    severity: 'critical',
    type: 'single',
    supportedSources: ['directory_svc', 'account_change'],
    conditionQuery:
      'eventType = "account_change" AND (action = "group_membership_add" OR action = "privilege_escalation") AND tags CONTAINS "privileged_group"',
    conditionSummary: 'Addition of user to privileged security group',
    attackMappings: [
      {
        techniqueId: 'T1098',
        techniqueName: 'Account Manipulation',
        tactic: 'Privilege Escalation',
        version: 'MITRE ATT&CK v15',
        confidence: 'supported',
        rationale:
          'Adversaries modify group memberships to grant compromised accounts administrative privileges.'
      }
    ],
    falsePositiveConsiderations:
      'Legitimate IAM provisioning accompanied by a verified ServiceNow change request ID in event metadata.',
    remediationGuidance:
      'Disable the compromised account, revoke active sessions, revert the group membership modification, and audit all actions taken after privilege elevation.'
  },
  {
    id: 'DET-009',
    name: 'DNS Query to Suspicious or Uncategorized C2 Domain',
    description:
      'Detects DNS resolution requests to domains flagged with DGA-like entropy, newly observed C2 indicators, or tunneling patterns.',
    severity: 'high',
    type: 'single',
    supportedSources: ['dns_resolver', 'dns_query'],
    conditionQuery:
      'eventType = "dns_query" AND tags CONTAINS "suspicious_domain"',
    conditionSummary: 'DNS query matching suspicious/newly observed indicator domain',
    attackMappings: [
      {
        techniqueId: 'T1071.004',
        techniqueName: 'Application Layer Protocol: DNS',
        tactic: 'Command and Control',
        version: 'MITRE ATT&CK v15',
        confidence: 'suspected',
        rationale:
          'Malware resolves external C2 domains before establishing outbound command channels or encoding data in DNS queries.'
      }
    ],
    falsePositiveConsiderations:
      'Internal CDN test domains or newly registered vendor SaaS subdomains can occasionally trigger newly-observed-domain heuristics. Verify whether a browser or an unsigned background process initiated the request.',
    remediationGuidance:
      'Block the malicious domain at the DNS resolver and web proxy, and correlate with endpoint process execution on the source host.'
  },
  {
    id: 'DET-010',
    name: 'Unusual Outbound Beaconing or High-Volume Transfer From Workstation',
    description:
      'Detects outbound firewall or web proxy connections from standard user workstations to rare external IPs or unapproved storage endpoints.',
    severity: 'high',
    type: 'single',
    supportedSources: ['perimeter_fw', 'secure_proxy', 'firewall_connection', 'web_proxy'],
    conditionQuery:
      '(eventType = "firewall_connection" OR eventType = "web_proxy") AND (tags CONTAINS "c2_beacon" OR tags CONTAINS "anomalous_egress")',
    conditionSummary: 'Workstation outbound connection flagged for C2 beaconing or anomalous egress volume',
    attackMappings: [
      {
        techniqueId: 'T1071.001',
        techniqueName: 'Application Layer Protocol: Web Protocols',
        tactic: 'Command and Control',
        version: 'MITRE ATT&CK v15',
        confidence: 'suspected',
        rationale:
          'Periodic outbound HTTPS requests or large POST uploads to uncategorized external endpoints indicate C2 beaconing or data staging.'
      },
      {
        techniqueId: 'T1041',
        techniqueName: 'Exfiltration Over C2 Channel',
        tactic: 'Exfiltration',
        version: 'MITRE ATT&CK v15',
        confidence: 'suspected',
        rationale:
          'Large outbound payloads sent over the same external channel used for command and control suggest active data exfiltration.'
      }
    ],
    falsePositiveConsiderations:
      'Scheduled off-site disaster recovery backups or approved cloud sync tools can generate large outbound transfers. Check the initiating process, destination IP ownership, and file access history.',
    remediationGuidance:
      'Block the external destination IP/domain, preserve volatile evidence on the host, and isolate the endpoint if paired with unauthorized sensitive file staging.'
  },
  {
    id: 'DET-011',
    name: 'Bulk Access or Archiving of Sensitive Restricted Files',
    description:
      'Detects rapid read access or archive compression of confidential HR, financial, or cryptographic key material within a short window.',
    severity: 'high',
    type: 'threshold',
    supportedSources: ['file_integrity', 'file_activity'],
    conditionQuery:
      'eventType = "file_activity" AND tags CONTAINS "sensitive_asset"',
    conditionSummary: '>= 3 sensitive file access/archive events on the same host within 600s',
    aggregation: {
      groupBy: 'host',
      windowSeconds: 600,
      threshold: 3
    },
    attackMappings: [
      {
        techniqueId: 'T1005',
        techniqueName: 'Data from Local System',
        tactic: 'Collection',
        version: 'MITRE ATT&CK v15',
        confidence: 'supported',
        rationale:
          'Adversaries collect and compress high-value local files prior to exfiltrating them over an external channel.'
      }
    ],
    falsePositiveConsiderations:
      'Authorized backup agents (e.g., Veeam/BackupExec) or quarterly financial audit scripts running under service accounts.',
    remediationGuidance:
      'Correlate the file collection events with subsequent archive creation (7z, tar, zip) and outbound network transfers.'
  },
  {
    id: 'DET-012',
    name: 'Suspicious Local or Backdoor Account Creation',
    description:
      'Detects creation of a new local or directory user account outside standard HR onboarding workflows.',
    severity: 'high',
    type: 'single',
    supportedSources: ['directory_svc', 'edr_sensor', 'account_change'],
    conditionQuery:
      'eventType = "account_change" AND action = "user_created" AND tags CONTAINS "unapproved_account"',
    conditionSummary: 'Unapproved user account creation detected',
    attackMappings: [
      {
        techniqueId: 'T1136.001',
        techniqueName: 'Create Account: Local Account',
        tactic: 'Persistence',
        version: 'MITRE ATT&CK v15',
        confidence: 'supported',
        rationale:
          'Creating a secondary local or service account provides backup access if the primary compromised account is remediated.'
      }
    ],
    falsePositiveConsiderations:
      'Manual emergency account provisioning by an administrator during an outage; check for associated incident ticket IDs.',
    remediationGuidance:
      'Disable the newly created account, investigate the parent process or session that created it, and isolate the affected host.'
  }
];
