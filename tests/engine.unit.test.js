import { describe, it, expect, beforeEach } from 'vitest';
import {
  parseTimestamp,
  formatTimestamp,
  formatRelativeDelta,
  validateEventRecord,
  validateEventDataset,
  validateImportedScenario,
  validateImportedSave,
  sanitizeObject
} from '../src/utils/eventSchema.js';
import {
  tokenizeQuery,
  parseQuery,
  executeStructuredQuery,
  filterAndQueryEvents
} from '../src/engine/queryEngine.js';
import { evaluateDetectionRule, runAllDetections } from '../src/engine/detectionEngine.js';
import { DETECTION_RULES } from '../src/data/rules/detectionRules.js';
import {
  buildInvestigationTimeline,
  correlateEvents,
  buildEntityGraph
} from '../src/engine/correlationEngine.js';
import {
  MISSION_STATES,
  canTransition,
  transitionMissionState,
  validateMissionCompletionReadiness
} from '../src/engine/missionStateMachine.js';
import {
  createInitialIncidentState,
  executeSimulatedResponse
} from '../src/engine/responseEngine.js';
import { evaluateMissionPerformance } from '../src/engine/scoringEngine.js';
import {
  getRankForXp,
  applyMissionProgression
} from '../src/engine/progressionEngine.js';
import {
  exportSavePayload,
  importSavePayload,
  resetAllProgress
} from '../src/engine/storageEngine.js';
import { CAMPAIGN_MISSIONS } from '../src/data/missions/campaignMissions.js';
import { SAMPLE_CUSTOM_SCENARIO } from '../src/data/missions/extraModes.js';

describe('CyberOps Simulator — Core Game Engine Unit Tests', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  describe('1. Event Schema & Timestamp Validation', () => {
    it('validates all 8 campaign mission datasets cleanly', () => {
      expect(CAMPAIGN_MISSIONS.length).toBeGreaterThanOrEqual(8);
      for (const mission of CAMPAIGN_MISSIONS) {
        const res = validateEventDataset(mission.events);
        expect(res.valid).toBe(true);
        expect(res.errors).toEqual([]);
      }
    });

    it('rejects malformed events and non-timezone-aware timestamps', () => {
      expect(parseTimestamp('2026-10-20T08:14:22Z')).toBeTypeOf('number');
      expect(parseTimestamp('2026-10-20 08:14:22')).toBeNull();
      expect(parseTimestamp('not-a-timestamp')).toBeNull();

      const badEvent = {
        eventId: '',
        timestamp: '2026-10-20',
        source: 'iam_auth',
        eventType: 'unknown_type',
        severity: 'extreme',
        message: ''
      };
      const check = validateEventRecord(badEvent);
      expect(check.valid).toBe(false);
      expect(check.errors.length).toBeGreaterThanOrEqual(4);
    });

    it('formats timestamps and relative deltas accurately', () => {
      expect(formatTimestamp('2026-10-20T08:00:00Z')).toBe('2026-10-20 08:00:00 UTC');
      expect(formatRelativeDelta('2026-10-20T08:00:00Z', '2026-10-20T08:02:15Z')).toBe('+2m 15s');
    });
  });

  describe('2. Structured Query Language Tokenizer, Parser & Evaluator', () => {
    const m1Events = CAMPAIGN_MISSIONS[0].events;
    const m2Events = CAMPAIGN_MISSIONS[1].events;
    const m3Events = CAMPAIGN_MISSIONS[2].events;

    it('tokenizes and parses equality, inequality, IN, CONTAINS, AND, OR, NOT, and parentheses', () => {
      const tokens = tokenizeQuery('username = "analyst.test" AND (severity IN ("high", "critical") OR NOT result = "success")');
      expect(tokens.length).toBeGreaterThan(10);
      const ast = parseQuery('username = "analyst.test" AND result = "failure"');
      expect(ast.type).toBe('LogicalExpression');
      expect(ast.operator).toBe('AND');
    });

    it('evaluates all prompt example queries accurately against mission datasets', () => {
      const q1 = executeStructuredQuery(m1Events, 'eventType = "authentication"');
      expect(q1.error).toBeNull();
      expect(q1.results.length).toBe(4);

      const q2 = executeStructuredQuery(m1Events, 'username = "analyst.test" AND result = "failure"');
      expect(q2.error).toBeNull();
      expect(q2.results.length).toBe(3);

      const q3 = executeStructuredQuery(
        m2Events,
        'sourceIp = "198.51.100.24" AND eventType = "authentication"'
      );
      expect(q3.error).toBeNull();
      expect(q3.results.length).toBe(6);

      const q4 = executeStructuredQuery(m3Events, 'severity IN ("high", "critical")');
      expect(q4.error).toBeNull();
      expect(q4.results.every((e) => e.severity === 'high' || e.severity === 'critical')).toBe(true);

      const q5 = executeStructuredQuery(m3Events, 'processName CONTAINS "powershell"');
      expect(q5.error).toBeNull();
      expect(q5.results.length).toBe(5);
    });

    it('returns a helpful syntax error on invalid queries without crashing', () => {
      const bad1 = executeStructuredQuery(m1Events, 'username = "unterminated');
      expect(bad1.error).toMatch(/Unterminated string literal/i);
      expect(bad1.results).toEqual([]);

      const bad2 = executeStructuredQuery(m1Events, 'severity IN "high"');
      expect(bad2.error).toMatch(/Expected "\(" after IN/i);
    });

    it('combines structured queries, facet filters, and sorting together', () => {
      const combined = filterAndQueryEvents(m2Events, {
        structuredQuery: 'eventType = "authentication"',
        source: 'iam_auth',
        sortOrder: 'desc'
      });
      expect(combined.error).toBeNull();
      expect(combined.total).toBe(7);
      expect(combined.events[0].eventId).toBe('EVT-208');
    });
  });

  describe('3. Detection Engine & Threshold / Sequence / Exclusion Logic', () => {
    it('triggers password spray threshold rule DET-002 on Mission 2', () => {
      const det002 = DETECTION_RULES.find((r) => r.id === 'DET-002');
      const findings = evaluateDetectionRule(det002, CAMPAIGN_MISSIONS[1].events);
      expect(findings.length).toBe(1);
      expect(findings[0].entityKey).toContain('198.51.100.24');
      expect(findings[0].matchedEventIds.length).toBeGreaterThanOrEqual(4);
    });

    it('excludes benign signed CcmExec.exe PowerShell on Mission 3 while flagging winword.exe -> powershell.exe', () => {
      const det006 = DETECTION_RULES.find((r) => r.id === 'DET-006');
      const findings = evaluateDetectionRule(det006, CAMPAIGN_MISSIONS[2].events);
      expect(findings.length).toBe(1);
      expect(findings[0].matchedEventIds).toEqual(['EVT-305']);
      expect(findings[0].matchedEventIds).not.toContain('EVT-301');
    });

    it('deduplicates findings across repeated runs', () => {
      const f1 = runAllDetections(DETECTION_RULES, CAMPAIGN_MISSIONS[7].events);
      const f2 = runAllDetections(DETECTION_RULES, CAMPAIGN_MISSIONS[7].events);
      expect(f1.length).toBeGreaterThanOrEqual(5);
      expect(f1.map((f) => f.findingId)).toEqual(f2.map((f) => f.findingId));
    });
  });

  describe('4. Timeline & Correlation Engine', () => {
    it('builds chronological timeline with relative deltas and evidence markers', () => {
      const m4 = CAMPAIGN_MISSIONS[3];
      const evidence = [{ targetId: 'EVT-403', evidenceId: 'EVID-EVT-403' }];
      const timeline = buildInvestigationTimeline(m4.events, evidence);
      expect(timeline.length).toBe(m4.events.length);
      expect(timeline[0].deltaFromPrevious).toBe('Start');
      const ev403 = timeline.find((item) => item.eventId === 'EVT-403');
      expect(ev403.isEvidence).toBe(true);
    });

    it('correlates process lineage and cross-source IOCs with explicit confidence levels', () => {
      const m3Correlations = correlateEvents(CAMPAIGN_MISSIONS[2].events);
      expect(m3Correlations.length).toBeGreaterThan(0);
      const confirmed = m3Correlations.find(
        (c) => c.sourceEventId === 'EVT-304' && c.targetEventId === 'EVT-305'
      );
      expect(confirmed).toBeDefined();
      expect(confirmed.confidence).toBe('confirmed');

      const graph = buildEntityGraph(CAMPAIGN_MISSIONS[2].events);
      expect(graph.nodes.length).toBeGreaterThan(4);
      expect(graph.edges.length).toBeGreaterThan(3);
    });
  });

  describe('5. Mission State Machine & Response Consequences', () => {
    it('validates allowed state transitions and blocks completion when mandatory criteria are unmet', () => {
      expect(canTransition(MISSION_STATES.AVAILABLE, MISSION_STATES.BRIEFING)).toBe(true);
      expect(canTransition(MISSION_STATES.LOCKED, MISSION_STATES.COMPLETED)).toBe(false);

      const m1 = CAMPAIGN_MISSIONS[0];
      const emptyInvestigation = {
        evidence: [],
        responseActions: [],
        assessment: {}
      };
      const res = transitionMissionState(
        MISSION_STATES.INVESTIGATING,
        MISSION_STATES.COMPLETED,
        m1,
        emptyInvestigation
      );
      expect(res.ok).toBe(false);
      expect(res.missingCriteria.length).toBeGreaterThan(0);
    });

    it('penalizes premature intrusive containment and inappropriate disruption of benign assets', () => {
      const m1Benign = CAMPAIGN_MISSIONS[0];
      const initState = createInitialIncidentState(m1Benign);
      const badAction = executeSimulatedResponse(m1Benign, initState, [], {
        actionType: 'disable_account',
        target: 'analyst.test',
        justification: 'Quick containment without checking logs'
      });
      expect(badAction.actionRecord.evaluation).toBe('unnecessary');
      expect(badAction.incidentState.operationalImpactScore).toBeGreaterThan(0);
    });
  });

  describe('6. Scoring, Ranks, Achievements & Replay XP Safeguard', () => {
    it('caps detection accuracy score when a player guesses without collecting evidence', () => {
      const m2 = CAMPAIGN_MISSIONS[1];
      const luckyGuessState = {
        executedQueries: [],
        evidence: [],
        responseActions: [{ actionType: 'block_ip', target: '198.51.100.24', evaluation: 'premature' }],
        assessment: {
          classification: 'malicious_incident',
          severity: 'high',
          affectedEntity: 'r.silva',
          keyFindings: 'Guessed password spray without collecting any evidence.'
        },
        hintsUsed: []
      };
      const scoreRes = evaluateMissionPerformance(m2, luckyGuessState);
      expect(scoreRes.dimensions.detectionAccuracy.score).toBeLessThanOrEqual(35);
    });

    it('awards high score for thorough evidence-backed investigation and prevents duplicate XP on replay', () => {
      const m1 = CAMPAIGN_MISSIONS[0];
      const thoroughState = {
        executedQueries: ['username = "analyst.test"'],
        ranDetections: true,
        inspectedTimeline: true,
        evidence: [
          { targetId: 'EVT-101', note: 'Scheduled 90-day password expiration policy' },
          { targetId: 'EVT-102', note: 'Failed attempt from assigned internal workstation' },
          { targetId: 'EVT-105', note: 'Self-service password update with FIDO2 key' },
          { targetId: 'EVT-106', note: 'Successful FIDO2 login' }
        ],
        responseActions: [
          { actionType: 'dismiss_benign', target: 'Incident Scope', evaluation: 'appropriate', isPremature: false }
        ],
        assessment: {
          classification: 'benign_activity',
          severity: 'low',
          affectedEntity: 'analyst.test, WKSTN-HR-02',
          attackStages: [],
          keyFindings: 'User mistyped password after 90-day expiration on assigned laptop and verified via FIDO2.',
          scopeSummary: 'Isolated to analyst.test on WKSTN-HR-02 with zero malicious impact.',
          remainingUncertainty: 'None; hardware MFA and internal workstation ownership confirmed.',
          recommendedFollowUp: 'Close alert and retain standard monitoring.'
        },
        hintsUsed: []
      };

      const debrief = evaluateMissionPerformance(m1, thoroughState);
      expect(debrief.overallScore).toBeGreaterThanOrEqual(93);
      expect(debrief.grade).toBe('S');

      const initialProfile = resetAllProgress();
      const firstRun = applyMissionProgression(
        initialProfile,
        m1,
        thoroughState,
        debrief,
        CAMPAIGN_MISSIONS.map((m) => m.id)
      );
      expect(firstRun.netXpGained).toBeGreaterThan(200);
      expect(firstRun.newlyUnlockedAchievements.length).toBeGreaterThanOrEqual(3);

      // Replay the exact same mission with the same score -> net XP gained must be 0!
      const secondRun = applyMissionProgression(
        firstRun.profile,
        m1,
        thoroughState,
        debrief,
        CAMPAIGN_MISSIONS.map((m) => m.id)
      );
      expect(secondRun.netXpGained).toBe(0);
      expect(secondRun.profile.xp).toBe(firstRun.profile.xp);

      const rank = getRankForXp(secondRun.profile.xp);
      expect(rank.level).toBeGreaterThanOrEqual(2);
    });
  });

  describe('7. Save/Restore & Imported JSON Validation / Prototype Pollution Safety', () => {
    it('validates custom scenarios and blocks prototype pollution or malformed records', () => {
      const validCheck = validateImportedScenario(JSON.stringify(SAMPLE_CUSTOM_SCENARIO));
      expect(validCheck.valid).toBe(true);

      const pollutedJson = '{"__proto__": {"polluted": true}, "id": "bad"}';
      const pollutedCheck = validateImportedScenario(pollutedJson);
      expect(pollutedCheck.valid).toBe(false);
      expect({}.polluted).toBeUndefined();

      expect(() => sanitizeObject(JSON.parse('{"constructor": {"prototype": {}}}'))).toThrow();
    });

    it('exports and restores game save payload accurately', () => {
      const dummyProfile = {
        analystName: 'Defender-99',
        xp: 650,
        completedMissions: { 'mission-1-noisy-login': { bestScore: 98, bestGrade: 'S', bestXp: 196 } },
        unlockedAchievements: ['first_alert_triaged'],
        missionHistory: []
      };
      const exported = exportSavePayload(dummyProfile, { soundEnabled: false });
      const restored = importSavePayload(exported);
      expect(restored.ok).toBe(true);
      expect(restored.profile.analystName).toBe('Defender-99');
      expect(restored.profile.xp).toBe(650);
    });
  });
});
