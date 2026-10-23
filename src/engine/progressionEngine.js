export const ANALYST_RANKS = [
  { level: 1, title: 'Trainee', minXp: 0, badgeColor: '#94a3b8' },
  { level: 2, title: 'Junior Analyst', minXp: 250, badgeColor: '#38bdf8' },
  { level: 3, title: 'SOC Analyst', minXp: 600, badgeColor: '#22d3ee' },
  { level: 4, title: 'Senior Analyst', minXp: 1050, badgeColor: '#34d399' },
  { level: 5, title: 'Incident Responder', minXp: 1550, badgeColor: '#f59e0b' },
  { level: 6, title: 'Threat Hunter', minXp: 2100, badgeColor: '#a78bfa' },
  { level: 7, title: 'Lead Analyst', minXp: 2700, badgeColor: '#f43f5e' }
];

export const ACHIEVEMENTS = [
  {
    id: 'first_alert_triaged',
    title: 'First Alert Triaged',
    description: 'Complete your first SOC mission investigation and debrief.',
    xpBonus: 50
  },
  {
    id: 'evidence_collector',
    title: 'Evidence Collector',
    description: 'Collect 100% of expected core evidence on any mission without noise.',
    xpBonus: 75
  },
  {
    id: 'false_positive_found',
    title: 'False Positive Found',
    description: 'Correctly identify and close a benign activity scenario without disrupting operations.',
    xpBonus: 80
  },
  {
    id: 'clean_investigation',
    title: 'Clean Investigation',
    description: 'Achieve an S or A grade (85%+) with zero hints used.',
    xpBonus: 100
  },
  {
    id: 'multi_source_correlator',
    title: 'Multi-Source Correlator',
    description: 'Collect corroborating evidence across 3 or more distinct telemetry sources in a single mission.',
    xpBonus: 90
  },
  {
    id: 'no_unnecessary_containment',
    title: 'No Unnecessary Containment',
    description: 'Contain a malicious incident with 100% response appropriateness and zero premature/unnecessary actions.',
    xpBonus: 90
  },
  {
    id: 'threat_hunter',
    title: 'Threat Hunter',
    description: 'Execute 5 or more structured queries and trigger detection rules in an investigation.',
    xpBonus: 85
  },
  {
    id: 'perfect_report',
    title: 'Perfect Report',
    description: 'Earn 100% on the Incident Report Quality dimension with grounded evidence.',
    xpBonus: 75
  },
  {
    id: 'full_campaign_completion',
    title: 'Full Campaign Completion',
    description: 'Successfully complete all 8 core campaign missions.',
    xpBonus: 250
  }
];

/**
 * Determines current rank and progress toward next rank based on total XP.
 */
export function getRankForXp(xp = 0) {
  const safeXp = Math.max(0, Number(xp) || 0);
  let current = ANALYST_RANKS[0];
  let next = null;

  for (let i = 0; i < ANALYST_RANKS.length; i++) {
    if (safeXp >= ANALYST_RANKS[i].minXp) {
      current = ANALYST_RANKS[i];
      next = ANALYST_RANKS[i + 1] || null;
    } else {
      break;
    }
  }

  let progressPercent = 100;
  let xpToNext = 0;
  if (next) {
    const span = next.minXp - current.minXp;
    const gainedInTier = safeXp - current.minXp;
    progressPercent = Math.min(100, Math.max(0, Math.round((gainedInTier / span) * 100)));
    xpToNext = Math.max(0, next.minXp - safeXp);
  }

  return {
    ...current,
    xp: safeXp,
    nextRank: next,
    progressPercent,
    xpToNext
  };
}

/**
 * Evaluates which achievements are unlocked by the latest mission completion and overall profile.
 */
export function evaluateAchievements(
  profileState,
  mission,
  investigationState,
  debriefResult,
  allCampaignMissionIds = []
) {
  const existingUnlocked = new Set(profileState?.unlockedAchievements || []);
  const newlyUnlocked = [];

  function grant(id) {
    if (!existingUnlocked.has(id)) {
      const def = ACHIEVEMENTS.find((a) => a.id === id);
      if (def) {
        existingUnlocked.add(id);
        newlyUnlocked.push(def);
      }
    }
  }

  // 1. First Alert Triaged
  grant('first_alert_triaged');

  // 2. Evidence Collector
  if (
    debriefResult.missedEvidenceIds.length === 0 &&
    debriefResult.noiseEvidenceIds.length === 0 &&
    debriefResult.matchedCoreEvidence.length > 0
  ) {
    grant('evidence_collector');
  }

  // 3. False Positive Found
  if (
    mission?.groundTruth?.classification === 'benign_activity' &&
    investigationState?.assessment?.classification === 'benign_activity' &&
    debriefResult.unnecessaryActions.length === 0
  ) {
    grant('false_positive_found');
  }

  // 4. Clean Investigation
  if (debriefResult.overallScore >= 85 && (investigationState?.hintsUsed?.length || 0) === 0) {
    grant('clean_investigation');
  }

  // 5. Multi-Source Correlator
  const evSet = new Set((investigationState?.evidence || []).map((e) => e.targetId));
  const distinctSources = new Set(
    (mission?.events || []).filter((e) => evSet.has(e.eventId)).map((e) => e.source)
  );
  if (distinctSources.size >= 3) {
    grant('multi_source_correlator');
  }

  // 6. No Unnecessary Containment
  if (
    mission?.groundTruth?.classification === 'malicious_incident' &&
    debriefResult.dimensions.responseAppropriateness.score >= 95 &&
    debriefResult.unnecessaryActions.length === 0 &&
    debriefResult.prematureActions.length === 0
  ) {
    grant('no_unnecessary_containment');
  }

  // 7. Threat Hunter
  if (
    (investigationState?.executedQueries?.length || 0) >= 5 &&
    investigationState?.ranDetections
  ) {
    grant('threat_hunter');
  }

  // 8. Perfect Report
  if (
    debriefResult.dimensions.reportQuality.score === 100 &&
    debriefResult.matchedCoreEvidence.length > 0
  ) {
    grant('perfect_report');
  }

  // 9. Full Campaign Completion
  const completedMap = {
    ...(profileState?.completedMissions || {}),
    [mission.id]: true
  };
  if (
    allCampaignMissionIds.length >= 8 &&
    allCampaignMissionIds.every((mId) => Boolean(completedMap[mId]))
  ) {
    grant('full_campaign_completion');
  }

  return {
    unlockedAchievements: Array.from(existingUnlocked),
    newlyUnlocked
  };
}

/**
 * Updates player progression state after completing (or replaying) a mission.
 * Prevents duplicate XP farming on replays.
 */
export function applyMissionProgression(
  profileState,
  mission,
  investigationState,
  debriefResult,
  allCampaignMissionIds = []
) {
  const prevCompleted = profileState?.completedMissions || {};
  const prevBestRecord = prevCompleted[mission.id] || null;
  const previousBestXp = prevBestRecord ? prevBestRecord.bestXp || 0 : 0;
  const previousBestScore = prevBestRecord ? prevBestRecord.bestScore || 0 : 0;

  // Only award the positive delta over previous best XP on this mission
  const missionXpDelta = Math.max(0, debriefResult.earnedXp - previousBestXp);

  const achEval = evaluateAchievements(
    profileState,
    mission,
    investigationState,
    debriefResult,
    allCampaignMissionIds
  );

  const achievementBonusXp = achEval.newlyUnlocked.reduce((sum, a) => sum + (a.xpBonus || 0), 0);
  const netXpGained = missionXpDelta + achievementBonusXp;
  const newTotalXp = (profileState?.xp || 0) + netXpGained;

  const updatedMissionRecord = {
    missionId: mission.id,
    title: mission.title,
    bestScore: Math.max(previousBestScore, debriefResult.overallScore),
    lastScore: debriefResult.overallScore,
    bestGrade:
      debriefResult.overallScore >= previousBestScore
        ? debriefResult.grade
        : prevBestRecord?.bestGrade || debriefResult.grade,
    bestXp: Math.max(previousBestXp, debriefResult.earnedXp),
    playCount: (prevBestRecord?.playCount || 0) + 1,
    completedAt: new Date().toISOString()
  };

  const historyEntry = {
    id: `HIST-${Date.now()}`,
    missionId: mission.id,
    missionTitle: mission.title,
    score: debriefResult.overallScore,
    grade: debriefResult.grade,
    xpDelta: netXpGained,
    timestamp: new Date().toISOString()
  };

  const nextProfile = {
    ...profileState,
    xp: newTotalXp,
    completedMissions: {
      ...prevCompleted,
      [mission.id]: updatedMissionRecord
    },
    unlockedAchievements: achEval.unlockedAchievements,
    missionHistory: [historyEntry, ...(profileState?.missionHistory || [])].slice(0, 25)
  };

  return {
    profile: nextProfile,
    netXpGained,
    missionXpDelta,
    achievementBonusXp,
    newlyUnlockedAchievements: achEval.newlyUnlocked,
    newRank: getRankForXp(newTotalXp),
    isReplayImprovement: Boolean(prevBestRecord && missionXpDelta > 0),
    wasReplay: Boolean(prevBestRecord)
  };
}
