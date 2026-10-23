export const MISSION_STATES = {
  LOCKED: 'locked',
  AVAILABLE: 'available',
  BRIEFING: 'briefing',
  INVESTIGATING: 'investigating',
  READY_FOR_ASSESSMENT: 'ready_for_assessment',
  COMPLETED: 'completed',
  FAILED: 'failed',
  REPLAY: 'replay'
};

export const ALLOWED_TRANSITIONS = {
  [MISSION_STATES.LOCKED]: [MISSION_STATES.AVAILABLE],
  [MISSION_STATES.AVAILABLE]: [MISSION_STATES.BRIEFING, MISSION_STATES.INVESTIGATING],
  [MISSION_STATES.BRIEFING]: [MISSION_STATES.AVAILABLE, MISSION_STATES.INVESTIGATING],
  [MISSION_STATES.INVESTIGATING]: [
    MISSION_STATES.BRIEFING,
    MISSION_STATES.READY_FOR_ASSESSMENT,
    MISSION_STATES.COMPLETED,
    MISSION_STATES.FAILED,
    MISSION_STATES.REPLAY
  ],
  [MISSION_STATES.READY_FOR_ASSESSMENT]: [
    MISSION_STATES.INVESTIGATING,
    MISSION_STATES.COMPLETED,
    MISSION_STATES.FAILED,
    MISSION_STATES.REPLAY
  ],
  [MISSION_STATES.COMPLETED]: [MISSION_STATES.REPLAY, MISSION_STATES.BRIEFING, MISSION_STATES.INVESTIGATING],
  [MISSION_STATES.FAILED]: [MISSION_STATES.REPLAY, MISSION_STATES.BRIEFING, MISSION_STATES.INVESTIGATING],
  [MISSION_STATES.REPLAY]: [MISSION_STATES.BRIEFING, MISSION_STATES.INVESTIGATING]
};

/**
 * Checks if a state transition is structurally valid.
 */
export function canTransition(fromState, toState) {
  if (fromState === toState) return true;
  const allowed = ALLOWED_TRANSITIONS[fromState];
  if (!allowed) return false;
  return allowed.includes(toState);
}

/**
 * Evaluates a mission's objectives dynamically against the player's actual investigation state.
 */
export function evaluateMissionObjectives(mission, investigationState) {
  if (!mission || !Array.isArray(mission.objectives)) return [];

  const {
    executedQueries = [],
    evidence = [],
    ranDetections = false,
    inspectedTimeline = false,
    responseActions = [],
    assessment = {}
  } = investigationState || {};

  const evidenceTargetIds = new Set(evidence.map((e) => e.targetId));

  return mission.objectives.map((obj) => {
    let completed = false;

    switch (obj.type) {
      case 'run_search': {
        completed = executedQueries.length >= (obj.minCount || 1);
        break;
      }
      case 'collect_evidence': {
        const minCount = obj.minCount || 2;
        if (Array.isArray(obj.requiredAnyIds) && obj.requiredAnyIds.length > 0) {
          const matchedReq = obj.requiredAnyIds.filter((id) => evidenceTargetIds.has(id)).length;
          completed = evidence.length >= minCount && matchedReq >= (obj.minRequiredMatches || 1);
        } else {
          completed = evidence.length >= minCount;
        }
        break;
      }
      case 'run_detections': {
        completed = Boolean(ranDetections);
        break;
      }
      case 'inspect_timeline': {
        completed = Boolean(inspectedTimeline);
        break;
      }
      case 'execute_response': {
        completed = responseActions.length >= (obj.minCount || 1);
        break;
      }
      case 'complete_assessment': {
        completed = Boolean(
          assessment &&
            assessment.classification &&
            assessment.severity &&
            assessment.affectedEntity &&
            assessment.keyFindings &&
            assessment.keyFindings.trim().length >= 15
        );
        break;
      }
      default:
        completed = false;
    }

    return {
      ...obj,
      completed
    };
  });
}

/**
 * Validates whether the player has satisfied the mandatory investigation requirements
 * to submit their final incident report and complete the mission.
 */
export function validateMissionCompletionReadiness(mission, investigationState) {
  const missing = [];
  if (!investigationState) {
    return { ready: false, missing: ['Investigation state is not initialized.'] };
  }

  const evidenceCount = Array.isArray(investigationState.evidence)
    ? investigationState.evidence.length
    : 0;
  const minEvidence = mission?.minimumEvidenceRequired || 2;

  if (evidenceCount < minEvidence) {
    missing.push(`Collect at least ${minEvidence} pieces of supporting evidence (currently ${evidenceCount}).`);
  }

  const actionsCount = Array.isArray(investigationState.responseActions)
    ? investigationState.responseActions.length
    : 0;
  if (actionsCount < 1) {
    missing.push('Execute at least one simulated response or triage disposition action.');
  }

  const assessment = investigationState.assessment || {};
  if (!assessment.classification) {
    missing.push('Select an incident classification (Malicious Incident, Benign Activity, or Inconclusive).');
  }
  if (!assessment.severity) {
    missing.push('Assign an incident severity level.');
  }
  if (!assessment.affectedEntity || !assessment.affectedEntity.trim()) {
    missing.push('Identify the primary affected user, host, or indicator.');
  }
  if (!assessment.keyFindings || assessment.keyFindings.trim().length < 15) {
    missing.push('Write a substantive incident summary / key findings (at least 15 characters).');
  }

  return {
    ready: missing.length === 0,
    missing
  };
}

/**
 * Transitions mission state with strict validation.
 */
export function transitionMissionState(currentState, targetState, mission, investigationState) {
  if (!canTransition(currentState, targetState)) {
    return {
      ok: false,
      state: currentState,
      error: `Invalid state transition from "${currentState}" to "${targetState}".`
    };
  }

  if (targetState === MISSION_STATES.COMPLETED) {
    const check = validateMissionCompletionReadiness(mission, investigationState);
    if (!check.ready) {
      return {
        ok: false,
        state: currentState,
        error: `Cannot complete mission until mandatory criteria are met: ${check.missing.join(' ')}`,
        missingCriteria: check.missing
      };
    }
  }

  return {
    ok: true,
    state: targetState,
    error: null
  };
}
