export const RESPONSE_CATALOG = [
  {
    actionType: 'preserve_evidence',
    label: 'Preserve Volatile Evidence',
    category: 'Forensics',
    intrusive: false,
    requiresTarget: true,
    targetPlaceholder: 'e.g. WKSTN-FIN-04 oriam_auth_logs',
    description:
      'Captures memory dump, process table, and immutable log snapshot before remediation alters host state.'
  },
  {
    actionType: 'disable_account',
    label: 'Disable User Account',
    category: 'Identity Containment',
    intrusive: true,
    requiresTarget: true,
    targetPlaceholder: 'e.g. m.chen or svc_backup',
    description:
      'Immediately suspends directory authentication for the specified identity. Disrupts legitimate work if applied to a benign user.'
  },
  {
    actionType: 'revoke_sessions',
    label: 'Revoke Active Sessions & Tokens',
    category: 'Identity Containment',
    intrusive: true,
    requiresTarget: true,
    targetPlaceholder: 'e.g. m.chen',
    description:
      'Invalidates active OAuth/SAML tokens and VPN sessions for the specified account.'
  },
  {
    actionType: 'isolate_host',
    label: 'Isolate Endpoint From Network',
    category: 'Endpoint Containment',
    intrusive: true,
    requiresTarget: true,
    targetPlaceholder: 'e.g. WKSTN-ENG-07',
    description:
      'Quarantines the workstation via EDR sensor so it can only communicate with the SOC management console.'
  },
  {
    actionType: 'block_ip',
    label: 'Block External IP at Perimeter',
    category: 'Network Containment',
    intrusive: true,
    requiresTarget: true,
    targetPlaceholder: 'e.g. 198.51.100.44',
    description:
      'Adds a deny rule on the perimeter firewall for traffic to/from the specified IP address.'
  },
  {
    actionType: 'block_domain',
    label: 'Sinkhole / Block Domain at DNS & Proxy',
    category: 'Network Containment',
    intrusive: true,
    requiresTarget: true,
    targetPlaceholder: 'e.g. telemetry-sync-cdn.example.net',
    description:
      'Blocks resolution and HTTP/S egress to the specified domain across corporate DNS and web proxy.'
  },
  {
    actionType: 'quarantine_file',
    label: 'Quarantine Malicious File / Script',
    category: 'Endpoint Containment',
    intrusive: true,
    requiresTarget: true,
    targetPlaceholder: 'e.g. C:\\ProgramData\\Updater\\sync.ps1',
    description:
      'Moves the specified file or script on the endpoint into an encrypted EDR quarantine vault.'
  },
  {
    actionType: 'escalate_incident',
    label: 'Escalate to Tier-3 Incident Response',
    category: 'Coordination',
    intrusive: false,
    requiresTarget: false,
    targetPlaceholder: 'Optional escalation focus',
    description:
      'Engages senior incident responders and legal/management stakeholders for confirmed high-severity incidents.'
  },
  {
    actionType: 'monitor_activity',
    label: 'Place Entity on Enhanced Monitoring',
    category: 'Watchlist',
    intrusive: false,
    requiresTarget: true,
    targetPlaceholder: 'e.g. WKSTN-DEV-02 or j.patel',
    description:
      'Increases telemetry verbosity and watches for follow-on activity without disrupting business operations.'
  },
  {
    actionType: 'dismiss_benign',
    label: 'Close Alert as Benign / Authorized Activity',
    category: 'Disposition',
    intrusive: false,
    requiresTarget: false,
    targetPlaceholder: 'Justification note required',
    description:
      'Documents that the alert was caused by verified benign user behavior or approved administrative maintenance.'
  }
];

export function createInitialIncidentState(mission) {
  const isMalicious = mission?.groundTruth?.classification === 'malicious_incident';
  return {
    threatStatus: isMalicious ? 'active_uncontained' : 'benign_operational',
    isolatedHosts: [],
    disabledAccounts: [],
    revokedAccounts: [],
    blockedIps: [],
    blockedDomains: [],
    quarantinedFiles: [],
    preservedTargets: [],
    monitoredTargets: [],
    escalated: false,
    dismissedAsBenign: false,
    prematureActionsCount: 0,
    unnecessaryActionsCount: 0,
    operationalImpactScore: 0,
    containmentProgress: 0,
    stateHistory: []
  };
}

/**
 * Evaluates a single simulated response action against the mission ground truth
 * and current evidence state, returning the action record and updated incidentState.
 */
export function executeSimulatedResponse(
  mission,
  currentIncidentState,
  currentEvidence = [],
  actionInput = {}
) {
  const { actionType, target = '', justification = '' } = actionInput;
  const catalogEntry = RESPONSE_CATALOG.find((c) => c.actionType === actionType);
  if (!catalogEntry) {
    throw new Error(`Unknown response action type: "${actionType}".`);
  }

  const normalizedTarget = String(target || '').trim();
  if (catalogEntry.requiresTarget && !normalizedTarget) {
    throw new Error(`Action "${catalogEntry.label}" requires a specific target (host, account, IP, domain, or file).`);
  }

  const gt = mission?.groundTruth || {};
  const expectedActions = Array.isArray(gt.expectedResponseActions) ? gt.expectedResponseActions : [];
  const relevantEvidenceCount = (currentEvidence || []).filter((ev) =>
    (gt.expectedEvidenceIds || []).includes(ev.targetId)
  ).length;

  // Check if intrusive action was taken before gathering sufficient evidence
  const isPremature =
    catalogEntry.intrusive && relevantEvidenceCount < Math.min(2, (gt.expectedEvidenceIds || []).length || 1);

  // Check whether this action + target matches an expected or acceptable response
  let evaluation = 'unnecessary';
  let consequenceText = '';

  const matchingExpected = expectedActions.find((exp) => {
    if (exp.actionType !== actionType) return false;
    if (!exp.target) return true;
    const targets = Array.isArray(exp.target) ? exp.target : [exp.target];
    return targets.some((t) => normalizedTarget.toLowerCase().includes(String(t).toLowerCase()));
  });

  if (matchingExpected) {
    evaluation = isPremature ? 'premature' : 'appropriate';
    consequenceText =
      matchingExpected.consequence ||
      `Successfully executed ${catalogEntry.label}${normalizedTarget ? ` on ${normalizedTarget}` : ''}.`;
    if (isPremature) {
      consequenceText +=
        ' Warning: You executed an intrusive containment action before collecting sufficient supporting evidence!';
    }
  } else if (actionType === 'preserve_evidence') {
    evaluation = 'appropriate';
    consequenceText = `Volatile forensic artifacts preserved for ${normalizedTarget || 'current scope'}.`;
  } else if (actionType === 'monitor_activity' && gt.classification !== 'malicious_incident') {
    evaluation = 'appropriate';
    consequenceText = `Enhanced telemetry watchlist enabled on ${normalizedTarget} without disrupting user productivity.`;
  } else {
    evaluation = 'unnecessary';
    if (gt.classification === 'benign_activity' && catalogEntry.intrusive) {
      consequenceText = `Operational Disruption: Executing "${catalogEntry.label}" on "${normalizedTarget}" interrupted legitimate business activity during a benign event.`;
    } else if (catalogEntry.intrusive) {
      consequenceText = `Target Mismatch / Over-containment: "${normalizedTarget}" is not an active threat vector in this scenario, causing avoidable operational friction.`;
    } else {
      consequenceText = `Disposition "${catalogEntry.label}" does not match the evidence profile for this incident.`;
    }
  }

  // Clone and update incident state
  const nextState = {
    ...currentIncidentState,
    isolatedHosts: [...(currentIncidentState.isolatedHosts || [])],
    disabledAccounts: [...(currentIncidentState.disabledAccounts || [])],
    revokedAccounts: [...(currentIncidentState.revokedAccounts || [])],
    blockedIps: [...(currentIncidentState.blockedIps || [])],
    blockedDomains: [...(currentIncidentState.blockedDomains || [])],
    quarantinedFiles: [...(currentIncidentState.quarantinedFiles || [])],
    preservedTargets: [...(currentIncidentState.preservedTargets || [])],
    monitoredTargets: [...(currentIncidentState.monitoredTargets || [])],
    stateHistory: [...(currentIncidentState.stateHistory || [])]
  };

  if (actionType === 'isolate_host' && !nextState.isolatedHosts.includes(normalizedTarget)) {
    nextState.isolatedHosts.push(normalizedTarget);
  }
  if (actionType === 'disable_account' && !nextState.disabledAccounts.includes(normalizedTarget)) {
    nextState.disabledAccounts.push(normalizedTarget);
  }
  if (actionType === 'revoke_sessions' && !nextState.revokedAccounts.includes(normalizedTarget)) {
    nextState.revokedAccounts.push(normalizedTarget);
  }
  if (actionType === 'block_ip' && !nextState.blockedIps.includes(normalizedTarget)) {
    nextState.blockedIps.push(normalizedTarget);
  }
  if (actionType === 'block_domain' && !nextState.blockedDomains.includes(normalizedTarget)) {
    nextState.blockedDomains.push(normalizedTarget);
  }
  if (actionType === 'quarantine_file' && !nextState.quarantinedFiles.includes(normalizedTarget)) {
    nextState.quarantinedFiles.push(normalizedTarget);
  }
  if (actionType === 'preserve_evidence' && !nextState.preservedTargets.includes(normalizedTarget)) {
    nextState.preservedTargets.push(normalizedTarget);
  }
  if (actionType === 'monitor_activity' && !nextState.monitoredTargets.includes(normalizedTarget)) {
    nextState.monitoredTargets.push(normalizedTarget);
  }
  if (actionType === 'escalate_incident') {
    nextState.escalated = true;
  }
  if (actionType === 'dismiss_benign') {
    nextState.dismissedAsBenign = true;
  }

  if (isPremature) {
    nextState.prematureActionsCount += 1;
  }
  if (evaluation === 'unnecessary') {
    nextState.unnecessaryActionsCount += 1;
    if (catalogEntry.intrusive) {
      nextState.operationalImpactScore += 25;
    }
  }

  const actionRecord = {
    actionId: `ACT-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    actionType,
    label: catalogEntry.label,
    target: normalizedTarget || 'Incident Scope',
    justification: String(justification || '').trim(),
    timestamp: new Date().toISOString(),
    evaluation,
    isPremature,
    consequenceText,
    evidenceCountAtExecution: currentEvidence.length
  };

  nextState.stateHistory.push(actionRecord);

  // Recalculate overall containment progress & threatStatus
  const requiredExpected = expectedActions.filter((e) => e.required !== false);
  if (requiredExpected.length > 0) {
    let matchedReqCount = 0;
    for (const req of requiredExpected) {
      const done = nextState.stateHistory.some((act) => {
        if (act.actionType !== req.actionType) return false;
        if (!req.target) return true;
        const targets = Array.isArray(req.target) ? req.target : [req.target];
        return targets.some((t) => act.target.toLowerCase().includes(String(t).toLowerCase()));
      });
      if (done) matchedReqCount++;
    }
    nextState.containmentProgress = Math.round((matchedReqCount / requiredExpected.length) * 100);

    if (gt.classification === 'malicious_incident') {
      if (nextState.containmentProgress >= 100) {
        nextState.threatStatus = 'threat_contained';
      } else if (nextState.containmentProgress > 0) {
        nextState.threatStatus = 'partially_contained';
      } else {
        nextState.threatStatus = 'active_uncontained';
      }
    } else {
      nextState.threatStatus =
        nextState.operationalImpactScore > 0
          ? 'production_disrupted_false_positive'
          : nextState.dismissedAsBenign
          ? 'closed_benign_verified'
          : 'benign_operational';
    }
  }

  return {
    actionRecord,
    incidentState: nextState
  };
}
