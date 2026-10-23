/**
 * TryHackMe-style step-by-step guided tasks, bite-sized lessons, and interactive check-in questions
 * for all 8 campaign missions (plus fallback generation for custom scenarios).
 */
export const GUIDED_WALKTHROUGHS = {
  'mission-1-noisy-login': {
    mentorName: 'Commander Vela (Senior SOC Lead)',
    mentorIntro:
      'Welcome to your first shift at Aegis BioLabs! Don’t worry—I will walk you through this first alert step by step. In a real SOC, 70% of alerts are actually harmless user mistakes ("False Positives"). Let’s find out if Elena Vance (`analyst.test`) is being hacked or just forgot her password!',
    steps: [
      {
        id: 'm1-step-1',
        stepNumber: 1,
        title: 'Task 1: Filter the Login Logs',
        targetTab: 'explorer',
        conceptTitle: 'What is Alert Triage?',
        conceptLesson:
          'When an alert fires for "Repeated Failed Logins", your first job is to isolate all events for that user and check WHERE the logins came from. If they came from the user’s own office laptop (`10.20.x.x`), it looks very different than an unknown foreign IP!',
        instructions: [
          'Look at the Log Explorer on the right side of your screen.',
          'Click the cyan quick-query pill `username = "analyst.test"` (or type it into the search bar and press Run Query).',
          'Click on event `EVT-102` in the list to inspect which computer (`host`) and IP (`sourceIp`) Elena used.'
        ],
        quickQuery: 'username = "analyst.test"',
        question: {
          prompt: 'Which internal workstation hostname did analyst.test log in from?',
          placeholder: 'e.g. WKSTN-HR-02',
          acceptedAnswers: ['wkstn-hr-02', '10.20.14.22'],
          explanation: 'Spot on! All login attempts came from WKSTN-HR-02 (10.20.14.22), which is Elena’s assigned HR laptop.'
        }
      },
      {
        id: 'm1-step-2',
        stepNumber: 2,
        title: 'Task 2: Find the Password Reset Clue & Collect Evidence',
        targetTab: 'explorer',
        conceptTitle: 'Why Do Benign Login Failures Happen?',
        conceptLesson:
          'Companies force employees to change their passwords every 90 days. Right after a password expires, employees often type their old password 2 or 3 times out of habit before updating it.',
        instructions: [
          'Clear your filter or inspect `EVT-101` (at 08:00:05 UTC) and `EVT-106` (at 08:14:22 UTC).',
          'Notice how `EVT-101` shows a scheduled 90-day password expiration, and `EVT-106` shows a successful login verified with a **FIDO2 YubiKey** hardware token!',
          'Click the **+ Evidence** button on at least **2 events** (such as `EVT-101`, `EVT-102`, `EVT-105`, or `EVT-106`) to save them to your Evidence Locker.'
        ],
        quickQuery: '',
        question: {
          prompt: 'What type of hardware Multi-Factor Authentication (MFA) verified Elena’s login in EVT-106?',
          placeholder: 'e.g. FIDO2 or YubiKey',
          acceptedAnswers: ['fido2', 'yubikey', 'fido2_yubikey', 'hardware'],
          explanation: 'Correct! Hardware FIDO2 YubiKey verification proves Elena physically touched her security key at her desk.'
        }
      },
      {
        id: 'm1-step-3',
        stepNumber: 3,
        title: 'Task 3: Run the Automated Threat Scanner',
        targetTab: 'detections',
        conceptTitle: 'Alerts vs. Confirmed Incidents',
        conceptLesson:
          'Detection rules look for patterns (like 3 failed logins followed by 1 success). A detection rule triggering is a **clue**, not proof of a crime. Good analysts always read the "False-Positive Considerations" on a rule.',
        instructions: [
          'The right panel is now on **3. Threat Scanner & ATT&CK**.',
          'Click **Execute All 12 Detection Rules**.',
          'Read the False-Positive Considerations on rule `DET-001` and `DET-003`.'
        ],
        question: {
          prompt: 'Which detection rule ID triggered for ">= 3 failed logins for same username"?',
          placeholder: 'e.g. DET-001',
          acceptedAnswers: ['det-001', 'det001'],
          explanation: 'Nice work! DET-001 and DET-003 fired, and both note that password rotation is a classic false positive.'
        }
      },
      {
        id: 'm1-step-4',
        stepNumber: 4,
        title: 'Task 4: Choose the Right Response Action',
        targetTab: 'response',
        conceptTitle: 'Do No Harm: Proportionate Response',
        conceptLesson:
          'If you lock Elena’s account or disconnect her laptop when she didn’t do anything wrong, HR payroll stops working! When evidence proves an alert is benign, the correct action is to **Close Alert as Benign**.',
        instructions: [
          'In the **4. Response & Containment** panel on the right, select **Close Alert as Benign / Authorized Activity** from the dropdown (or click its quick card).',
          'Optionally add a quick note ("Verified 90-day password reset with FIDO2 MFA") and click **Execute Simulated Action**.'
        ],
        question: {
          prompt: 'Is this alert a "malicious" incident or "benign" activity?',
          placeholder: 'Type: benign',
          acceptedAnswers: ['benign', 'benign_activity', 'false positive'],
          explanation: 'Exactly! It is 100% benign user activity.'
        }
      },
      {
        id: 'm1-step-5',
        stepNumber: 5,
        title: 'Task 5: Submit Your Case Verdict',
        targetTab: 'assessment',
        conceptTitle: 'Writing a Clear SOC Case Closure',
        conceptLesson:
          'Every alert ends with a brief report so the next analyst on shift knows why you closed or escalated it.',
        instructions: [
          'In **5. Case Verdict & Report** on the right:',
          '1. Set Classification to **False Positive — Benign / Authorized Activity**.',
          '2. Set Severity to **Low**.',
          '3. Enter Affected Entity: `analyst.test, WKSTN-HR-02` (or click the **Auto-Fill From Clues** helper button!).',
          '4. Write a short summary and click **Submit Final Report & View Debrief**!'
        ]
      }
    ]
  },

  'mission-2-password-spray': {
    mentorName: 'Commander Vela (Senior SOC Lead)',
    mentorIntro:
      'Great job on your first case! Now things get real. An external IP address is trying a "Password Spray" against our login portal. Instead of guessing 100 passwords on one user (which locks the account), they try ONE common password across MANY users.',
    steps: [
      {
        id: 'm2-step-1',
        stepNumber: 1,
        title: 'Task 1: Track the Attacker IP',
        targetTab: 'explorer',
        conceptTitle: 'What is Password Spraying (T1110.003)?',
        conceptLesson:
          'If an organization locks an account after 5 failed attempts, an attacker will try `Autumn2026!` once against 50 different usernames from the same IP address.',
        instructions: [
          'Click the quick button below to run `sourceIp = "198.51.100.24" AND eventType = "authentication"` in the Log Explorer.',
          'Look at the usernames targeted by `198.51.100.24` between 11:01 and 11:04 UTC.'
        ],
        quickQuery: 'sourceIp = "198.51.100.24" AND eventType = "authentication"',
        question: {
          prompt: 'Which user account actually SUCCEEDED (`result = "success"`) during the password spray?',
          placeholder: 'e.g. r.silva',
          acceptedAnswers: ['r.silva', 'evt-206'],
          explanation: 'Bingo! Legacy contractor account r.silva had no MFA enforced and the attacker guessed their password in EVT-206!'
        }
      },
      {
        id: 'm2-step-2',
        stepNumber: 2,
        title: 'Task 2: Check What the Attacker Stole & Collect Clues',
        targetTab: 'explorer',
        conceptTitle: 'Post-Compromise Reconnaissance',
        conceptLesson:
          'Once an attacker logs into an account, your next question is always: "What did they access before we caught them?"',
        instructions: [
          'Click the quick query `username = "r.silva"` to see everything `r.silva` did.',
          'Inspect `EVT-207` (web_proxy): the attacker immediately downloaded `/api/v2/users/export.csv` (the Global Address List)!',
          'Click **+ Evidence** on at least **3 key events** (e.g. `EVT-201`, `EVT-206`, and `EVT-207`).'
        ],
        quickQuery: 'username = "r.silva"',
        question: {
          prompt: 'What file path did r.silva download in EVT-207?',
          placeholder: 'e.g. export.csv',
          acceptedAnswers: ['export.csv', '/api/v2/users/export.csv', 'users/export.csv'],
          explanation: 'Correct! The attacker exported the company directory to find more targets.'
        }
      },
      {
        id: 'm2-step-3',
        stepNumber: 3,
        title: 'Task 3: Verify with the Threat Scanner',
        targetTab: 'detections',
        conceptTitle: 'Threshold Aggregation Detections',
        conceptLesson:
          'SIEM rules like `DET-002` group failed logins by `sourceIp` over a 10-minute sliding window and count how many distinct usernames were targeted.',
        instructions: [
          'Click **Execute All 12 Detection Rules** in the Threat Scanner panel.',
          'Confirm that `DET-002` (Multi-Account Password Spraying, MITRE `T1110.003`) triggered.'
        ],
        question: {
          prompt: 'What is the MITRE ATT&CK Technique ID for Password Spraying shown on DET-002?',
          placeholder: 'e.g. T1110.003',
          acceptedAnswers: ['t1110.003', 't1110'],
          explanation: 'Exact match! T1110.003 is Brute Force: Password Spraying.'
        }
      },
      {
        id: 'm2-step-4',
        stepNumber: 4,
        title: 'Task 4: Contain the Attacker IP & Compromised Account',
        targetTab: 'response',
        conceptTitle: 'Two-Part Identity Containment',
        conceptLesson:
          'When an external IP compromises a user account, you must stop BOTH the external IP at the firewall AND disable/revoke the compromised account so the attacker cannot switch IPs and keep using the session!',
        instructions: [
          'In **4. Response & Containment**, execute these actions:',
          '1. Select **Block External IP at Perimeter** with target `198.51.100.24` and click Execute.',
          '2. Select **Disable User Account** with target `r.silva` and click Execute.',
          '3. (Optional bonus) Select **Revoke Active Sessions** with target `r.silva`.'
        ]
      },
      {
        id: 'm2-step-5',
        stepNumber: 5,
        title: 'Task 5: File Your Incident Report',
        targetTab: 'assessment',
        conceptTitle: 'Documenting Credential Compromise',
        conceptLesson:
          'Include both the compromised username (`r.silva`) and the attacker IP (`198.51.100.24`) in your affected entities.',
        instructions: [
          'Set Classification to **True Positive — Malicious Incident** and Severity to **High**.',
          'Check MITRE techniques `T1110.003` and `T1078`.',
          'List Affected Entities: `r.silva, 198.51.100.24, SSO-GW-01` and submit your report!'
        ]
      }
    ]
  },

  'mission-3-suspicious-script': {
    mentorName: 'Commander Vela (Senior SOC Lead)',
    mentorIntro:
      'Two computers just ran encoded PowerShell commands at almost the same time: `WKSTN-IT-01` and `WKSTN-FIN-04`. One is normal IT maintenance, and the other is a malicious Microsoft Word macro attack! Let’s compare them.',
    steps: [
      {
        id: 'm3-step-1',
        stepNumber: 1,
        title: 'Task 1: Compare Parent Processes',
        targetTab: 'explorer',
        conceptTitle: 'Process Lineage (Parent ➔ Child)',
        conceptLesson:
          'Every program is started by a "Parent Process". When `CcmExec.exe` (Microsoft SCCM IT agent) starts `powershell.exe`, that’s routine IT management. When `winword.exe` (Microsoft Word) starts `powershell.exe`, a malicious document macro is attacking the PC!',
        instructions: [
          'Click the quick button to run `processName CONTAINS "powershell"` in the Log Explorer.',
          'Compare `EVT-301` (on `WKSTN-IT-01`) with `EVT-305` (on `WKSTN-FIN-04`).'
        ],
        quickQuery: 'processName CONTAINS "powershell"',
        question: {
          prompt: 'Which parentProcess spawned powershell.exe on WKSTN-FIN-04 in EVT-305?',
          placeholder: 'e.g. winword.exe',
          acceptedAnswers: ['winword.exe', 'winword'],
          explanation: 'Spot on! Microsoft Word (winword.exe) should never spawn hidden PowerShell commands.'
        }
      },
      {
        id: 'm3-step-2',
        stepNumber: 2,
        title: 'Task 2: Uncover the Dropped Payload & Collect Evidence',
        targetTab: 'explorer',
        conceptTitle: 'Decoded Payloads & Temp Staging',
        conceptLesson:
          'Attackers use `-EncodedCommand` (Base64) to hide their script. Inspecting the event metadata and file creation events reveals what file was written to disk.',
        instructions: [
          'Click the quick query `host = "WKSTN-FIN-04"` to see the full attack chain on `m.chen`’s workstation.',
          'Inspect `EVT-304` (Word doc opened), `EVT-305` (Encoded PowerShell), `EVT-306` (dropped `.ps1` file), and `EVT-307` (DNS lookup to `staging.example.net`).',
          'Click **+ Evidence** on `EVT-304`, `EVT-305`, `EVT-306`, and `EVT-307`.'
        ],
        quickQuery: 'host = "WKSTN-FIN-04"',
        question: {
          prompt: 'What is the filename of the malicious PowerShell script created in EVT-306?',
          placeholder: 'e.g. audit_helper.ps1',
          acceptedAnswers: ['audit_helper.ps1', 'c:\\users\\m.chen\\appdata\\local\\temp\\audit_helper.ps1'],
          explanation: 'Correct! PowerShell dropped audit_helper.ps1 into the user Temp folder.'
        }
      },
      {
        id: 'm3-step-3',
        stepNumber: 3,
        title: 'Task 3: Inspect the Timeline & Threat Scanner',
        targetTab: 'detections',
        conceptTitle: 'Smart Rule Exclusions',
        conceptLesson:
          'Notice how `DET-006` automatically ignored `WKSTN-IT-01` because its parent was `CcmExec.exe`, while flagging `WKSTN-FIN-04`!',
        instructions: [
          'Click **Execute All 12 Detection Rules** in the Threat Scanner.',
          'Review `DET-005` (`T1059.001`) and `DET-006` (`T1027`).'
        ]
      },
      {
        id: 'm3-step-4',
        stepNumber: 4,
        title: 'Task 4: Isolate the Infected Host & Quarantine the Script',
        targetTab: 'response',
        conceptTitle: 'Endpoint Containment',
        conceptLesson:
          'Do NOT touch `WKSTN-IT-01` (that’s benign IT maintenance!). Only contain the infected Finance workstation `WKSTN-FIN-04`.',
        instructions: [
          '1. Execute **Isolate Endpoint From Network** on target `WKSTN-FIN-04`.',
          '2. Execute **Quarantine Malicious File / Script** on target `audit_helper.ps1`.'
        ]
      },
      {
        id: 'm3-step-5',
        stepNumber: 5,
        title: 'Task 5: Submit Your Incident Report',
        targetTab: 'assessment',
        conceptTitle: 'Finalizing Macro Intrusion Cases',
        conceptLesson:
          'Document the host (`WKSTN-FIN-04`), user (`m.chen`), and payload (`audit_helper.ps1`), plus ATT&CK techniques `T1059.001` and `T1027`.',
        instructions: [
          'Select **True Positive — Malicious Incident** and Severity **High**.',
          'Check `T1059.001` and `T1027`, fill in the findings, and click **Submit Final Report**!'
        ]
      }
    ]
  },

  'mission-4-strange-domain': {
    mentorName: 'Commander Vela (Senior SOC Lead)',
    mentorIntro:
      'An engineering laptop (`WKSTN-ENG-07`) is making DNS lookups to a strange domain: `cdn-telemetry-sync.example.net`. Is the engineer just browsing a website, or is malware "beaconing" to a Command-and-Control (C2) server every 60 seconds?',
    steps: [
      {
        id: 'm4-step-1',
        stepNumber: 1,
        title: 'Task 1: Pivot on the Suspicious Domain',
        targetTab: 'explorer',
        conceptTitle: 'DNS & IP Pivoting',
        conceptLesson:
          'When you investigate a suspicious domain, check what IP address it resolves to and which program (`processName`) made the request. Browsers (`chrome.exe`) visit websites; unsigned `.exe` files in `AppData` are usually malware!',
        instructions: [
          'Run the quick query `domain = "cdn-telemetry-sync.example.net"` in the Log Explorer.',
          'Inspect `EVT-402` and `EVT-403` to see which binary started and what IP the domain resolved to.'
        ],
        quickQuery: 'domain = "cdn-telemetry-sync.example.net"',
        question: {
          prompt: 'What external IP address did cdn-telemetry-sync.example.net resolve to?',
          placeholder: 'e.g. 203.0.113.88',
          acceptedAnswers: ['203.0.113.88'],
          explanation: 'Bullseye! The domain resolves to 203.0.113.88.'
        }
      },
      {
        id: 'm4-step-2',
        stepNumber: 2,
        title: 'Task 2: Spot the 60-Second Heartbeat in the Timeline',
        targetTab: 'timeline',
        conceptTitle: 'What is C2 Beaconing?',
        conceptLesson:
          'Command-and-Control (C2) malware checks in with its controller on a robotic timer (for example, every 60 seconds) to ask for commands.',
        instructions: [
          'Look at **2. Timeline & Correlation** on the right.',
          'Notice how `netcheck.exe` (`EVT-402`) sends HTTPS POST requests to `/api/v1/pulse` at `15:02:01`, `15:03:01`, and `15:04:01`—exactly 60 seconds apart!',
          'Switch back to Log Explorer and collect `EVT-402`, `EVT-403`, `EVT-404`, and `EVT-407` into your Evidence Locker.'
        ],
        question: {
          prompt: 'Which unsigned executable (`processName`) is sending these 60-second beacons?',
          placeholder: 'e.g. netcheck.exe',
          acceptedAnswers: ['netcheck.exe', 'netcheck'],
          explanation: 'Correct! Unsigned netcheck.exe running from AppData\\Roaming is the C2 implant.'
        }
      },
      {
        id: 'm4-step-3',
        stepNumber: 3,
        title: 'Task 3: Block Domain, Block IP & Isolate Host',
        targetTab: 'response',
        conceptTitle: 'Defense-in-Depth C2 Containment',
        conceptLesson:
          'If you only block the domain name, malware often falls back to connecting directly to the hardcoded IP address (`203.0.113.88`). Always block the domain, block the IP, AND isolate the infected host!',
        instructions: [
          'In **4. Response & Containment**, execute:',
          '1. **Sinkhole / Block Domain** on `cdn-telemetry-sync.example.net`',
          '2. **Block External IP** on `203.0.113.88`',
          '3. **Isolate Endpoint** on `WKSTN-ENG-07`'
        ]
      },
      {
        id: 'm4-step-4',
        stepNumber: 4,
        title: 'Task 4: Submit Your C2 Incident Report',
        targetTab: 'assessment',
        conceptTitle: 'Reporting Network Indicators (IOCs)',
        conceptLesson:
          'Include the host, user, domain, and C2 IP in your report so threat intel teams can track the campaign.',
        instructions: [
          'Set Classification to **Malicious Incident**, Severity to **High**, and check `T1071.004` & `T1071.001`.',
          'Submit your final report!'
        ]
      }
    ]
  },

  'mission-5-persistence': {
    mentorName: 'Commander Vela (Senior SOC Lead)',
    mentorIntro:
      'Attackers hate losing access when a user reboots their computer. To survive reboots, they create "Persistence" using Scheduled Tasks (`schtasks.exe`) or Registry Run keys. We have two scheduled tasks in the logs—find the rogue one!',
    steps: [
      {
        id: 'm5-step-1',
        stepNumber: 1,
        title: 'Task 1: Separate Authorized Maintenance From Malware Persistence',
        targetTab: 'explorer',
        conceptTitle: 'Scheduled Tasks (T1053.005) & Registry Run Keys (T1547.001)',
        conceptLesson:
          'IT admins create scheduled tasks too, but they use service accounts (`svc_patch_mgmt`) and approved Change Tickets (`CHG-88412`). Attackers drop scripts in `C:\\ProgramData` or `AppData` and run them every few minutes.',
        instructions: [
          'Click the quick query `host = "WKSTN-OPS-11"` to inspect the suspicious workstation.',
          'Examine `EVT-502` (file drop), `EVT-503` (`schtasks.exe /create`), `EVT-504` (Registry Run key), and `EVT-505` (`taskeng.exe` running the task 15 minutes later).',
          'Collect `EVT-502`, `EVT-503`, `EVT-504`, and `EVT-505` as Evidence!'
        ],
        quickQuery: 'host = "WKSTN-OPS-11"',
        question: {
          prompt: 'What is the name of the persistent PowerShell script dropped in C:\\ProgramData\\Telemetry\\?',
          placeholder: 'e.g. beacon.ps1',
          acceptedAnswers: ['beacon.ps1', 'c:\\programdata\\telemetry\\beacon.ps1'],
          explanation: 'Spot on! updater_svc.exe dropped beacon.ps1 and registered both a Scheduled Task and a Registry Run key.'
        }
      },
      {
        id: 'm5-step-2',
        stepNumber: 2,
        title: 'Task 2: Verify the 15-Minute Trigger in Timeline',
        targetTab: 'timeline',
        conceptTitle: 'Verifying Persistence Execution',
        conceptLesson:
          'Seeing a task created at 16:15:00 and seeing `taskeng.exe` spawn `powershell.exe` at 16:30:00 (+15m) proves the persistence mechanism is actively firing.',
        instructions: [
          'Inspect **2. Timeline & Correlation** to see the exact +15m delta between `EVT-503` and `EVT-505`.',
          'Optionally run the Threat Scanner (`3. Threat Scanner`) to confirm `DET-007`.'
        ]
      },
      {
        id: 'm5-step-3',
        stepNumber: 3,
        title: 'Task 3: Contain WKSTN-OPS-11 & Quarantine beacon.ps1',
        targetTab: 'response',
        conceptTitle: 'Eradicating Persistence',
        conceptLesson:
          'Isolate the infected workstation `WKSTN-OPS-11` and quarantine `beacon.ps1` (do not isolate `SRV-APP-02`!).',
        instructions: [
          '1. Execute **Isolate Endpoint** on `WKSTN-OPS-11`.',
          '2. Execute **Quarantine Malicious File / Script** on `beacon.ps1`.'
        ]
      },
      {
        id: 'm5-step-4',
        stepNumber: 4,
        title: 'Task 4: Submit Your Persistence Report',
        targetTab: 'assessment',
        conceptTitle: 'Documenting Persistence Mechanisms',
        conceptLesson:
          'Cite `T1053.005`, `T1547.001`, and `T1059.001` so the remediation team removes both the scheduled task and the registry Run key.',
        instructions: [
          'Classify as **Malicious Incident** (Severity: **High**), fill in the report, and submit!'
        ]
      }
    ]
  },

  'mission-6-compromised-account': {
    mentorName: 'Commander Vela (Senior SOC Lead)',
    mentorIntro:
      'Critical alert! Systems engineer `j.kovacs` was just added to the `Cloud Infra Admins` group without a change ticket, and a brand-new user account was created on `WKSTN-ADM-03`. Trace the entire identity takeover!',
    steps: [
      {
        id: 'm6-step-1',
        stepNumber: 1,
        title: 'Task 1: Trace the Takeover & Rogue Backdoor Account',
        targetTab: 'explorer',
        conceptTitle: 'Privilege Escalation (T1098) & Rogue Accounts (T1136.001)',
        conceptLesson:
          'Smart attackers know you will eventually reset the password of the first account they stole (`j.kovacs`). So they immediately escalate privileges and create a second hidden account to keep access!',
        instructions: [
          'Click the quick query `username = "j.kovacs"` to trace every action performed by the compromised account.',
          'Collect `EVT-602` (login from `198.51.100.77`), `EVT-604` (RDP jump-host), `EVT-605` (`Cloud Infra Admins` group add), and `EVT-606` (new user created) as Evidence.'
        ],
        quickQuery: 'username = "j.kovacs"',
        question: {
          prompt: 'What is the username of the rogue backdoor account created in EVT-606?',
          placeholder: 'e.g. svc_diag_temp',
          acceptedAnswers: ['svc_diag_temp'],
          explanation: 'Critical catch! If we only disabled j.kovacs and missed svc_diag_temp, the attacker would still own our domain.'
        }
      },
      {
        id: 'm6-step-2',
        stepNumber: 2,
        title: 'Task 2: Lock Down Both Accounts & Block the Attacker IP',
        targetTab: 'response',
        conceptTitle: 'Complete Identity Eviction',
        conceptLesson:
          'To evict an attacker who created a backdoor account, you must disable BOTH accounts, revoke active tokens, and block the external IP.',
        instructions: [
          'In **4. Response & Containment**, execute:',
          '1. **Disable User Account** on `j.kovacs`',
          '2. **Disable User Account** on `svc_diag_temp`',
          '3. **Revoke Active Sessions** on `j.kovacs`',
          '4. **Block External IP** on `198.51.100.77`'
        ]
      },
      {
        id: 'm6-step-3',
        stepNumber: 3,
        title: 'Task 3: Submit Critical Incident Assessment',
        targetTab: 'assessment',
        conceptTitle: 'Scoping Multi-Identity Incidents',
        conceptLesson:
          'Make sure both `j.kovacs` and `svc_diag_temp` are listed in your Affected Entities.',
        instructions: [
          'Set Classification to **Malicious Incident** and Severity to **Critical**.',
          'Check `T1078`, `T1098`, and `T1136.001`, and submit your report!'
        ]
      }
    ]
  },

  'mission-7-data-exfiltration-puzzle': {
    mentorName: 'Commander Vela (Senior SOC Lead)',
    mentorIntro:
      'We have two large outbound file transfers tonight: 480 MB from `SRV-FIN-BACKUP` and 42 MB from `WKSTN-LEGAL-05`. Remember: size alone does not prove data theft! Let’s see which one is an authorized backup and which one is stealing restricted M&A files.',
    steps: [
      {
        id: 'm7-step-1',
        stepNumber: 1,
        title: 'Task 1: Investigate the Sensitive File Staging on WKSTN-LEGAL-05',
        targetTab: 'explorer',
        conceptTitle: 'Archive Staging (`7z.exe`) Before Exfiltration',
        conceptLesson:
          'Before stealing confidential documents, attackers usually compress and password-protect them into a `.7z` or `.zip` archive in a Temp folder, then upload them with `curl.exe` or a browser.',
        instructions: [
          'Notice that `EVT-701` and `EVT-702` on `SRV-FIN-BACKUP` are a legitimate nightly `VeeamAgent.exe` backup to `dr-vault.example.com`.',
          'Click the quick query `host = "WKSTN-LEGAL-05"` to inspect paralegal workstation `WKSTN-LEGAL-05`.',
          'Collect at least **4 events** (`EVT-703`, `EVT-706`, `EVT-707`, `EVT-708`) showing sensitive M&A file reads, `aurora_bundle.7z` creation, and `curl.exe` upload to `drop-storage-api.example.net` (`203.0.113.195`).'
        ],
        quickQuery: 'host = "WKSTN-LEGAL-05"',
        question: {
          prompt: 'What is the name of the password-protected .7z archive created in EVT-706?',
          placeholder: 'e.g. aurora_bundle.7z',
          acceptedAnswers: ['aurora_bundle.7z', 'c:\\users\\l.martinez\\appdata\\local\\temp\\aurora_bundle.7z'],
          explanation: 'Exactly! 7z.exe bundled the restricted Legal_Confidential files into aurora_bundle.7z.'
        }
      },
      {
        id: 'm7-step-2',
        stepNumber: 2,
        title: 'Task 2: Preserve Forensics & Contain the Exfiltration',
        targetTab: 'response',
        conceptTitle: 'Preserving Volatile Evidence in Legal Breaches',
        conceptLesson:
          'When intellectual property or legal M&A data is stolen, preserving volatile forensic evidence before isolating the host helps legal teams prove exactly what was taken.',
        instructions: [
          'First, check **2. Timeline & Correlation** so your timeline objective is checked off.',
          'Then in **4. Response & Containment**, execute:',
          '1. **Preserve Volatile Evidence** on `WKSTN-LEGAL-05`',
          '2. **Isolate Endpoint** on `WKSTN-LEGAL-05`',
          '3. **Block External IP** on `203.0.113.195`',
          '4. **Sinkhole / Block Domain** on `drop-storage-api.example.net`'
        ]
      },
      {
        id: 'm7-step-3',
        stepNumber: 3,
        title: 'Task 3: Submit Your Exfiltration Report',
        targetTab: 'assessment',
        conceptTitle: 'Distinguishing Backups From Exfiltration',
        conceptLesson:
          'Document `WKSTN-LEGAL-05`, `l.martinez`, `drop-storage-api.example.net`, and `203.0.113.195` as the true exfiltration scope.',
        instructions: [
          'Set Classification to **Malicious Incident** and Severity to **Critical**.',
          'Check `T1005` and `T1041`, and submit your report!'
        ]
      }
    ]
  },

  'mission-8-multi-stage-incident': {
    mentorName: 'Commander Vela (Senior SOC Lead)',
    mentorIntro:
      'This is your final Boss Mission! A full multi-stage cyberattack is unfolding across Aegis BioLabs, mixed in with two harmless decoy alerts (`h.wong` password typo and `SRV-PATCH-01` approved patching). Reconstruct the entire kill chain and stop the breach!',
    steps: [
      {
        id: 'm8-step-1',
        stepNumber: 1,
        title: 'Task 1: Filter Out the Decoys & Trace the Kill Chain',
        targetTab: 'explorer',
        conceptTitle: 'Full Intrusion Kill Chain Correlation',
        conceptLesson:
          'In a real enterprise breach, one stage leads to the next: Initial Access (`198.51.100.142` ➔ `d.thorne`) ➔ Execution (`w3wp.exe` ➔ `powershell.exe`) ➔ Dropper (`svc_host.ps1`) ➔ Persistence (`NetHealthMonitor` task) ➔ Privilege Escalation (`Domain Admins`) ➔ C2 Exfiltration (`core-telemetry-gw.example.net`).',
        instructions: [
          'Run `username = "d.thorne"` and then `host = "WKSTN-CORP-09"` in the Log Explorer (running 2 queries completes your search objective!).',
          'Collect at least **5 core evidence events**: `EVT-803`, `EVT-805`, `EVT-806`, `EVT-807`, `EVT-808`, `EVT-809`, and `EVT-810`.'
        ],
        quickQuery: 'username = "d.thorne"',
        question: {
          prompt: 'Which privileged group was d.thorne added to in EVT-808?',
          placeholder: 'e.g. Domain Admins',
          acceptedAnswers: ['domain admins', 'domain admin'],
          explanation: 'Spot on! The attacker escalated d.thorne to Domain Admins without a change ticket.'
        }
      },
      {
        id: 'm8-step-2',
        stepNumber: 2,
        title: 'Task 2: Run Threat Scanner & Inspect the Timeline',
        targetTab: 'detections',
        conceptTitle: 'Multi-Tactic ATT&CK Mapping',
        conceptLesson:
          'Correlating detections across Initial Access, Execution, Persistence, Privilege Escalation, and Command & Control gives you ironclad proof of a full intrusion.',
        instructions: [
          'Click **Execute All 12 Detection Rules** in the Threat Scanner.',
          'Also click the **2. Timeline & Correlation** tab to review the full chronological kill chain.'
        ]
      },
      {
        id: 'm8-step-3',
        stepNumber: 3,
        title: 'Task 3: Execute Full-Spectrum Containment',
        targetTab: 'response',
        conceptTitle: 'Coordinated Incident Eradication',
        conceptLesson:
          'When an adversary has Domain Admin privileges, a persistent scheduled task, and an active C2 channel, you must contain identity, endpoint, file, and network simultaneously.',
        instructions: [
          'In **4. Response & Containment**, execute:',
          '1. **Disable User Account** on `d.thorne`',
          '2. **Isolate Endpoint** on `WKSTN-CORP-09`',
          '3. **Quarantine Malicious File / Script** on `svc_host.ps1`',
          '4. **Sinkhole / Block Domain** on `core-telemetry-gw.example.net`',
          '5. **Block External IP** on `203.0.113.211`'
        ]
      },
      {
        id: 'm8-step-4',
        stepNumber: 4,
        title: 'Task 4: Submit Final Campaign Report',
        targetTab: 'assessment',
        conceptTitle: 'Executive Incident Reporting',
        conceptLesson:
          'Use the **Auto-Fill Scope From Collected Clues** button to populate all affected entities and ATT&CK stages cleanly.',
        instructions: [
          'Set Classification to **Malicious Incident** and Severity to **Critical**.',
          'Click **Submit Final Report & View Debrief** to complete the campaign!'
        ]
      }
    ]
  }
};

export function getWalkthroughForMission(mission) {
  if (!mission) return null;
  if (GUIDED_WALKTHROUGHS[mission.id]) {
    return GUIDED_WALKTHROUGHS[mission.id];
  }
  return {
    mentorName: 'Commander Vela (Senior SOC Lead)',
    mentorIntro: `Follow the steps below to investigate ${mission.title}, collect supporting evidence, and execute proportionate containment.`,
    steps: [
      {
        id: `${mission.id}-s1`,
        stepNumber: 1,
        title: 'Task 1: Inspect Telemetry & Collect Clues',
        targetTab: 'explorer',
        conceptTitle: 'Evidence-Based Triage',
        conceptLesson: 'Inspect the events in the Log Explorer and click + Evidence on the records that prove what happened.',
        instructions: [
          `Review the ${mission.events?.length || 0} telemetry events in the Log Explorer.`,
          `Collect at least ${mission.minimumEvidenceRequired || 2} relevant events into your Evidence Locker.`
        ],
        quickQuery: ''
      },
      {
        id: `${mission.id}-s2`,
        stepNumber: 2,
        title: 'Task 2: Run Threat Scanner & Timeline',
        targetTab: 'detections',
        conceptTitle: 'Automated Rule Evaluation',
        conceptLesson: 'Run the detection rules to see which MITRE ATT&CK techniques match the dataset.',
        instructions: ['Click Execute All 12 Detection Rules and inspect the Timeline tab.']
      },
      {
        id: `${mission.id}-s3`,
        stepNumber: 3,
        title: 'Task 3: Execute Containment & Submit Report',
        targetTab: 'response',
        conceptTitle: 'Proportionate Response',
        conceptLesson: 'Select the response action that matches your findings and submit the final report.',
        instructions: [
          'Execute your containment action in tab 4, then complete and submit the report in tab 5.'
        ]
      }
    ]
  };
}
