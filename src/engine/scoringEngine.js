import { evaluateMissionObjectives } from './missionStateMachine.js';

function clamp(val, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Math.round(val)));
}

/**
 * Evaluates a completed mission investigation and produces a comprehensive, deterministic debrief report.
 */
export function evaluateMissionPerformance(mission, investigationState) {
  const gt = mission?.groundTruth || {};
  const {
    evidence = [],
    responseActions = [],
    assessment = {},
    hintsUsed = [],
    executedQueries = []
  } = investigationState || {};

  const expectedEvidenceIds = Array.isArray(gt.expectedEvidenceIds) ? gt.expectedEvidenceIds : [];
  const bonusEvidenceIds = Array.isArray(gt.bonusEvidenceIds) ? gt.bonusEvidenceIds : [];
  const collectedIds = evidence.map((e) => e.targetId);

  const matchedCoreEvidence = expectedEvidenceIds.filter((id) => collectedIds.includes(id));
  const missedEvidenceIds = expectedEvidenceIds.filter((id) => !collectedIds.includes(id));
  const noiseEvidence = evidence.filter(
    (e) => !expectedEvidenceIds.includes(e.targetId) && !bonusEvidenceIds.includes(e.targetId)
  );

  // 1. Evidence Quality (20%)
  const coreCoverageRatio =
    expectedEvidenceIds.length > 0 ? matchedCoreEvidence.length / expectedEvidenceIds.length : 1;
  const noisePenalty = noiseEvidence.length * 8;
  const noteQualityBonus = evidence.some((e) => e.note && e.note.trim().length >= 10) ? 5 : 0;
  const evidenceScore = clamp(coreCoverageRatio * 95 + noteQualityBonus - noisePenalty);

  // 2. Detection Accuracy (25%)
  let rawDetectionScore = 0;
  const classificationCorrect = assessment.classification === gt.classification;
  const severityCorrect = assessment.severity === gt.severity;

  if (classificationCorrect) {
    rawDetectionScore += 65;
  } else if (
    assessment.classification === 'inconclusive' &&
    matchedCoreEvidence.length < expectedEvidenceIds.length
  ) {
    // Player honestly identified uncertainty when lacking complete evidence
    rawDetectionScore += 45;
  }

  if (severityCorrect) {
    rawDetectionScore += 20;
  } else {
    const sevOrder = { low: 1, medium: 2, high: 3, critical: 4 };
    const diff = Math.abs((sevOrder[assessment.severity] || 0) - (sevOrder[gt.severity] || 0));
    if (diff === 1) rawDetectionScore += 10;
  }

  // Attack stages / techniques identified
  const expectedStages = Array.isArray(gt.attackStages) ? gt.attackStages : [];
  const selectedStages = Array.isArray(assessment.attackStages) ? assessment.attackStages : [];
  const matchedStages = expectedStages.filter((st) => selectedStages.includes(st));
  if (expectedStages.length > 0) {
    rawDetectionScore += (matchedStages.length / expectedStages.length) * 15;
  } else {
    rawDetectionScore += 15;
  }

  // Anti-lucky-guess safeguard: cap detection score if player guessed without core evidence
  if (matchedCoreEvidence.length === 0 && expectedEvidenceIds.length > 0) {
    rawDetectionScore = Math.min(rawDetectionScore, 35);
  } else if (coreCoverageRatio < 0.4 && classificationCorrect) {
    rawDetectionScore = Math.min(rawDetectionScore, 60);
  }

  const detectionScore = clamp(rawDetectionScore);

  // 3. Investigation Completeness & Scope Accuracy (20%)
  const objectives = evaluateMissionObjectives(mission, investigationState);
  const completedObjCount = objectives.filter((o) => o.completed).length;
  const objRatio = objectives.length > 0 ? completedObjCount / objectives.length : 1;

  const expectedEntities = Array.isArray(gt.affectedEntities) ? gt.affectedEntities : [];
  const reportedEntityText = `${assessment.affectedEntity || ''} ${assessment.scopeSummary || ''}`.toLowerCase();
  const matchedEntities = expectedEntities.filter((ent) =>
    reportedEntityText.includes(String(ent).toLowerCase())
  );
  const scopeRatio =
    expectedEntities.length > 0 ? matchedEntities.length / expectedEntities.length : 1;

  const completenessScore = clamp(objRatio * 55 + scopeRatio * 45);

  // 4. Response Appropriateness (20%)
  const expectedResponses = Array.isArray(gt.expectedResponseActions)
    ? gt.expectedResponseActions.filter((r) => r.required !== false)
    : [];
  let matchedResponseCount = 0;
  for (const exp of expectedResponses) {
    const found = responseActions.some((act) => {
      if (act.actionType !== exp.actionType) return false;
      if (!exp.target) return true;
      const targets = Array.isArray(exp.target) ? exp.target : [exp.target];
      return targets.some((t) =>
        String(act.target || '').toLowerCase().includes(String(t).toLowerCase())
      );
    });
    if (found) matchedResponseCount++;
  }

  const responseCoverage =
    expectedResponses.length > 0 ? matchedResponseCount / expectedResponses.length : 1;
  const unnecessaryActions = responseActions.filter((a) => a.evaluation === 'unnecessary');
  const prematureActions = responseActions.filter((a) => a.isPremature);
  const preservedEvidenceBonus = responseActions.some((a) => a.actionType === 'preserve_evidence')
    ? 5
    : 0;

  const responseScore = clamp(
    responseCoverage * 95 +
      preservedEvidenceBonus -
      unnecessaryActions.length * 20 -
      prematureActions.length * 15
  );

  // 5. Incident Report Quality (10%)
  let reportScoreRaw = 0;
  if (assessment.keyFindings && assessment.keyFindings.trim().length >= 30) {
    reportScoreRaw += 35;
  } else if (assessment.keyFindings && assessment.keyFindings.trim().length >= 15) {
    reportScoreRaw += 20;
  }
  if (assessment.scopeSummary && assessment.scopeSummary.trim().length >= 15) {
    reportScoreRaw += 25;
  }
  if (assessment.remainingUncertainty && assessment.remainingUncertainty.trim().length >= 10) {
    reportScoreRaw += 20;
  }
  if (assessment.recommendedFollowUp && assessment.recommendedFollowUp.trim().length >= 15) {
    reportScoreRaw += 20;
  }
  const reportScore = clamp(reportScoreRaw);

  // 6. Efficiency & Hint Discipline (5%)
  const hintPenalty = hintsUsed.length * 15;
  const queryDisciplineBonus = executedQueries.length >= 1 ? 10 : 0;
  const efficiencyScore = clamp(90 + queryDisciplineBonus - hintPenalty);

  // Overall weighted score
  const weights = {
    detection: 0.25,
    evidence: 0.2,
    completeness: 0.2,
    response: 0.2,
    report: 0.1,
    efficiency: 0.05
  };

  const overallScore = clamp(
    detectionScore * weights.detection +
      evidenceScore * weights.evidence +
      completenessScore * weights.completeness +
      responseScore * weights.response +
      reportScore * weights.report +
      efficiencyScore * weights.efficiency
  );

  let grade = 'F';
  if (overallScore >= 93) grade = 'S';
  else if (overallScore >= 85) grade = 'A';
  else if (overallScore >= 75) grade = 'B';
  else if (overallScore >= 65) grade = 'C';
  else if (overallScore >= 50) grade = 'D';

  const baseXp = mission?.xpReward || 200;
  const earnedXp = Math.round((overallScore / 100) * baseXp);

  // Build constructive suggestions
  const improvements = [];
  if (missedEvidenceIds.length > 0) {
    improvements.push(
      `Review missed telemetry records (${missedEvidenceIds.join(', ')}) to strengthen your evidentiary chain.`
    );
  }
  if (noiseEvidence.length > 0) {
    improvements.push(
      `Remove ${noiseEvidence.length} unrelated noise event(s) from your evidence locker to keep the incident timeline focused.`
    );
  }
  if (!classificationCorrect) {
    improvements.push(
      `Expected classification was "${gt.classification.replace('_', ' ')}", whereas you selected "${(assessment.classification || 'none').replace('_', ' ')}".`
    );
  }
  if (unnecessaryActions.length > 0) {
    improvements.push(
      `Avoid unnecessary containment actions (${unnecessaryActions.map((a) => `${a.label} on ${a.target}`).join(', ')}) that disrupt normal operations.`
    );
  }
  if (prematureActions.length > 0) {
    improvements.push(
      'Collect at least 2 corroborating pieces of evidence before executing intrusive containment actions.'
    );
  }
  if ( matchedEntities.length < expectedEntities.length) {
    const missedEnts = expectedEntities.filter((e) => !matchedEntities.includes(e));
    improvements.push(
      `Ensure your scope assessment explicitly documents all affected entities: ${missedEnts.join(', ')}.`
    );
  }
  if (improvements.length === 0) {
    improvements.push(
      'Exemplary SOC investigation! Your hypothesis, evidentiary chain, scope assessment, and containment actions were proportionate and accurate.'
    );
  }

  return {
    overallScore,
    grade,
    earnedXp,
    dimensions: {
      detectionAccuracy: {
        score: detectionScore,
        weight: '25%',
        explanation: classificationCorrect
          ? matchedCoreEvidence.length > 0
            ? 'Correctly classified the activity and supported the hypothesis with real telemetry.'
            : 'Selected the right classification, but lacked supporting evidence (lucky-guess safeguard applied).'
          : `Classification mismatch: expected "${gt.classification}", received "${assessment.classification}".`
      },
      evidenceQuality: {
        score: evidenceScore,
        weight: '20%',
        explanation: `Collected ${matchedCoreEvidence.length}/${expectedEvidenceIds.length} core evidence records with ${noiseEvidence.length} noise item(s).`
      },
      investigationCompleteness: {
        score: completenessScore,
        weight: '20%',
        explanation: `Completed ${completedObjCount}/${objectives.length} mission objectives and identified ${matchedEntities.length}/${expectedEntities.length} scoped entities.`
      },
      responseAppropriateness: {
        score: responseScore,
        weight: '20%',
        explanation: `Executed ${matchedResponseCount}/${expectedResponses.length} expected containment/disposition actions (${unnecessaryActions.length} unnecessary, ${prematureActions.length} premature).`
      },
      reportQuality: {
        score: reportScore,
        weight: '10%',
        explanation:
          reportScore >= 85
            ? 'Comprehensive incident report covering findings, scope, uncertainty, and follow-up actions.'
            : 'Incident report could include deeper detail on remaining uncertainty and remediation follow-up.'
      },
      efficiency: {
        score: efficiencyScore,
        weight: '5%',
        explanation:
          hintsUsed.length === 0
            ? 'Completed investigation without relying on hints.'
            : `Used ${hintsUsed.length} hint(s) during the investigation.`
      }
    },
    matchedCoreEvidence,
    missedEvidenceIds,
    noiseEvidenceIds: noiseEvidence.map((e) => e.targetId),
    unnecessaryActions,
    prematureActions,
    matchedStages,
    expectedStages,
    objectives,
    intendedReasoning: gt.explanation || '',
    improvements,
    hintsUsedCount: hintsUsed.length
  };
}
