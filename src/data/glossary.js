export const SOC_GLOSSARY = [
  {
    term: 'SOC (Security Operations Center)',
    short: 'SOC',
    category: 'Operations',
    definition:
      'A centralized team and facility responsible for monitoring, detecting, investigating, and responding to cybersecurity threats across an organization’s telemetry.'
  },
  {
    term: 'SIEM (Security Information and Event Management)',
    short: 'SIEM',
    category: 'Platform',
    definition:
      'A platform that aggregates log data from identity providers, endpoints, firewalls, DNS, and proxies to support structured search, correlation, and detection alerting.'
  },
  {
    term: 'IOC (Indicator of Compromise)',
    short: 'IOC',
    category: 'Forensics',
    definition:
      'An observable artifact—such as a malicious IP address, C2 domain, file hash, or suspicious registry path—that suggests potential intrusion activity.'
  },
  {
    term: 'Alert Triage',
    short: 'Triage',
    category: 'Workflow',
    definition:
      'The initial assessment of a security alert to determine whether it represents a true threat, benign activity, or requires deeper escalation, along with its priority.'
  },
  {
    term: 'Event Correlation',
    short: 'Correlation',
    category: 'Analysis',
    definition:
      'Connecting related events across multiple distinct telemetry sources (e.g., linking an external VPN login to a subsequent PowerShell execution and outbound DNS query).'
  },
  {
    term: 'False Positive',
    short: 'False Positive',
    category: 'Analysis',
    definition:
      'A security alert triggered by benign user behavior or authorized administrative maintenance rather than actual malicious activity.'
  },
  {
    term: 'Containment',
    short: 'Containment',
    category: 'Response',
    definition:
      'Defensive actions—such as isolating a host, disabling a compromised account, or blocking an external IP—taken to stop an adversary from spreading or exfiltrating data.'
  },
  {
    term: 'Persistence',
    short: 'Persistence',
    category: 'Tactic',
    definition:
      'Techniques adversaries use to maintain access across system reboots or credential rotations, such as scheduled tasks, registry Run keys, or rogue local accounts.'
  },
  {
    term: 'Exfiltration',
    short: 'Exfiltration',
    category: 'Tactic',
    definition:
      'The unauthorized transfer of sensitive internal data to an external destination controlled by an adversary.'
  },
  {
    term: 'MITRE ATT&CK',
    short: 'MITRE ATT&CK',
    category: 'Framework',
    definition:
      'A globally accessible knowledge base of adversary tactics and techniques based on real-world cyber intrusion observations.'
  },
  {
    term: 'Severity vs. Confidence',
    short: 'Severity vs. Confidence',
    category: 'Assessment',
    definition:
      'Severity measures the potential business impact if the threat is real (Low to Critical), whereas Confidence measures how strongly the collected evidence proves the hypothesis.'
  }
];
