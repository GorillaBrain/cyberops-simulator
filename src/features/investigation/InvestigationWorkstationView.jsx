import React, { useState, useMemo } from 'react';
import {
  AlertCircle,
  Bookmark,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Circle,
  Clock,
  Compass,
  Cpu,
  Database,
  Eye,
  FileCheck,
  Filter,
  Flag,
  GitBranch,
  HelpCircle,
  Lightbulb,
  Play,
  PlusCircle,
  RotateCcw,
  Search,
  Shield,
  Sparkles,
  Terminal,
  Trash2,
  Zap
} from 'lucide-react';
import {
  EXAMPLE_QUERIES,
  filterAndQueryEvents
} from '../../engine/queryEngine.js';
import { DETECTION_RULES } from '../../data/rules/detectionRules.js';
import { runAllDetections } from '../../engine/detectionEngine.js';
import {
  buildInvestigationTimeline,
  correlateEvents,
  buildEntityGraph
} from '../../engine/correlationEngine.js';
import {
  RESPONSE_CATALOG,
  executeSimulatedResponse
} from '../../engine/responseEngine.js';
import {
  evaluateMissionObjectives,
  validateMissionCompletionReadiness
} from '../../engine/missionStateMachine.js';
import { getWalkthroughForMission } from '../../data/missions/guidedWalkthroughs.js';
import { formatTimestamp } from '../../utils/eventSchema.js';
import { SeverityBadge } from '../../components/SeverityBadge.jsx';

const MITRE_TECHNIQUE_OPTIONS = [
  { id: 'T1110.001', label: 'T1110.001 - Brute Force: Password Guessing' },
  { id: 'T1110.003', label: 'T1110.003 - Brute Force: Password Spraying' },
  { id: 'T1078', label: 'T1078 - Valid Accounts' },
  { id: 'T1059.001', label: 'T1059.001 - Command & Scripting Interpreter: PowerShell' },
  { id: 'T1027', label: 'T1027 - Obfuscated Files or Information' },
  { id: 'T1053.005', label: 'T1053.005 - Scheduled Task/Job: Scheduled Task' },
  { id: 'T1547.001', label: 'T1547.001 - Boot or Logon Autostart: Registry Run Keys' },
  { id: 'T1098', label: 'T1098 - Account Manipulation / Privilege Escalation' },
  { id: 'T1136.001', label: 'T1136.001 - Create Account: Local/Directory Account' },
  { id: 'T1071.004', label: 'T1071.004 - Application Layer Protocol: DNS' },
  { id: 'T1071.001', label: 'T1071.001 - Application Layer Protocol: Web Protocols' },
  { id: 'T1005', label: 'T1005 - Data from Local System' },
  { id: 'T1041', label: 'T1041 - Exfiltration Over C2 Channel' }
];

export function InvestigationWorkstationView({
  mission,
  investigationState,
  savedQueries,
  onUpdateInvestigation,
  onSaveQuery,
  onCompleteMission,
  onRestartMission,
  onOpenBriefing,
  onNotify
}) {
  const walkthrough = useMemo(() => getWalkthroughForMission(mission), [mission]);
  const [activeStepIdx, setActiveStepIdx] = useState(0);
  const [activeTab, setActiveTab] = useState('explorer');
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);

  // Task flag inputs
  const [flagInputs, setFlagInputs] = useState({});
  const [flagFeedback, setFlagFeedback] = useState({});

  // Query & Filter local UI state
  const [queryInput, setQueryInput] = useState('');
  const [appliedQuery, setAppliedQuery] = useState('');
  const [freeText, setFreeText] = useState('');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [eventTypeFilter, setEventTypeFilter] = useState('all');
  const [hostFilter, setHostFilter] = useState('all');
  const [usernameFilter, setUsernameFilter] = useState('all');
  const [ipDomainFilter, setIpDomainFilter] = useState('');
  const [sortOrder, setSortOrder] = useState('asc');

  // Timeline filters
  const [timelineEntityFilter, setTimelineEntityFilter] = useState('');
  const [timelineOnlyEvidence, setTimelineOnlyEvidence] = useState(false);

  // Selected event & Evidence form state
  const [selectedEventId, setSelectedEventId] = useState(
    mission?.events?.[0]?.eventId || null
  );
  const [evidenceReason] = useState('Key indicator of suspicious or benign context');
  const [evidenceNote, setEvidenceNote] = useState('');
  const [evidenceAlignment, setEvidenceAlignment] = useState('supports');

  // Response console state
  const [selectedActionType, setSelectedActionType] = useState('preserve_evidence');
  const [responseTarget, setResponseTarget] = useState('');
  const [responseJustification, setResponseJustification] = useState('');

  // Submission validation message
  const [submitErrors, setSubmitErrors] = useState([]);

  const events = mission?.events || [];
  const evidence = investigationState?.evidence || [];
  const responseActions = investigationState?.responseActions || [];
  const incidentState = investigationState?.incidentState || {};
  const assessment = investigationState?.assessment || {};
  const hintsUsed = investigationState?.hintsUsed || [];
  const completedSteps = investigationState?.completedWalkthroughSteps || [];

  // Unique facet options from dataset
  const distinctSources = useMemo(
    () => Array.from(new Set(events.map((e) => e.source).filter(Boolean))),
    [events]
  );
  const distinctEventTypes = useMemo(
    () => Array.from(new Set(events.map((e) => e.eventType).filter(Boolean))),
    [events]
  );
  const distinctHosts = useMemo(
    () => Array.from(new Set(events.map((e) => e.host).filter(Boolean))),
    [events]
  );
  const distinctUsers = useMemo(
    () => Array.from(new Set(events.map((e) => e.username).filter(Boolean))),
    [events]
  );
  const allQuickEntities = useMemo(() => {
    const set = new Set();
    events.forEach((e) => {
      if (e.host) set.add(e.host);
      if (e.username) set.add(e.username);
      if (e.sourceIp && !e.sourceIp.startsWith('10.')) set.add(e.sourceIp);
      if (e.destinationIp && !e.destinationIp.startsWith('10.')) set.add(e.destinationIp);
      if (e.domain) set.add(e.domain);
    });
    return Array.from(set);
  }, [events]);

  // Filtered events
  const queryResult = useMemo(
    () =>
      filterAndQueryEvents(events, {
        structuredQuery: appliedQuery,
        freeText,
        source: sourceFilter,
        severity: severityFilter,
        eventType: eventTypeFilter,
        host: hostFilter,
        username: usernameFilter,
        ipOrDomain: ipDomainFilter,
        sortOrder
      }),
    [
      events,
      appliedQuery,
      freeText,
      sourceFilter,
      severityFilter,
      eventTypeFilter,
      hostFilter,
      usernameFilter,
      ipDomainFilter,
      sortOrder
    ]
  );

  const selectedEvent = useMemo(
    () => events.find((e) => e.eventId === selectedEventId) || events[0] || null,
    [events, selectedEventId]
  );

  // Timeline, Correlations & Entity Graph
  const timelineItems = useMemo(
    () =>
      buildInvestigationTimeline(events, evidence, {
        entity: timelineEntityFilter,
        onlyEvidence: timelineOnlyEvidence
      }),
    [events, evidence, timelineEntityFilter, timelineOnlyEvidence]
  );

  const correlations = useMemo(() => correlateEvents(events), [events]);
  const entityGraph = useMemo(() => buildEntityGraph(events, evidence), [events, evidence]);

  const objectives = useMemo(
    () => evaluateMissionObjectives(mission, investigationState),
    [mission, investigationState]
  );

  const readiness = useMemo(
    () => validateMissionCompletionReadiness(mission, investigationState),
    [mission, investigationState]
  );

  function markStepDone(stepId) {
    if (!stepId || completedSteps.includes(stepId)) return;
    onUpdateInvestigation({
      completedWalkthroughSteps: [...completedSteps, stepId]
    });
  }

  function handleSelectWalkthroughStep(idx) {
    setActiveStepIdx(idx);
    const step = walkthrough?.steps?.[idx];
    if (step?.targetTab) {
      setActiveTab(step.targetTab);
      if (step.targetTab === 'timeline') {
        onUpdateInvestigation({ inspectedTimeline: true });
      }
    }
  }

  function handleCheckStepQuestion(step, idx) {
    if (!step?.question) return;
    const rawAns = String(flagInputs[step.id] || '').trim().toLowerCase();
    const isMatch = step.question.acceptedAnswers.some((acc) =>
      rawAns.includes(String(acc).toLowerCase())
    );
    if (isMatch) {
      setFlagFeedback((prev) => ({
        ...prev,
        [step.id]: { ok: true, text: `✓ Correct! ${step.question.explanation}` }
      }));
      markStepDone(step.id);
      if (idx + 1 < (walkthrough?.steps?.length || 0)) {
        setTimeout(() => handleSelectWalkthroughStep(idx + 1), 650);
      }
    } else {
      setFlagFeedback((prev) => ({
        ...prev,
        [step.id]: {
          ok: false,
          text: `Not quite! Hint: Try "${step.question.acceptedAnswers[0]}" after inspecting the logs.`
        }
      }));
    }
  }

  function handleRunStructuredQuery(e) {
    if (e) e.preventDefault();
    const trimmed = queryInput.trim();
    setAppliedQuery(trimmed);
    const prevQueries = investigationState.executedQueries || [];
    const nextQueries = trimmed
      ? Array.from(new Set([...prevQueries, trimmed]))
      : [...prevQueries, '__filter_search__'];
    onUpdateInvestigation({ executedQueries: nextQueries });
  }

  function handleApplyExampleQuery(qStr) {
    setQueryInput(qStr);
    setAppliedQuery(qStr);
    setActiveTab('explorer');
    const prevQueries = investigationState.executedQueries || [];
    onUpdateInvestigation({
      executedQueries: Array.from(new Set([...prevQueries, qStr]))
    });
  }

  function handleClearAllFilters() {
    setQueryInput('');
    setAppliedQuery('');
    setFreeText('');
    setSourceFilter('all');
    setSeverityFilter('all');
    setEventTypeFilter('all');
    setHostFilter('all');
    setUsernameFilter('all');
    setIpDomainFilter('');
  }

  function handlePivotEntity(field, value) {
    if (!value) return;
    const q = `${field} = "${value}"`;
    setQueryInput(q);
    setAppliedQuery(q);
    setActiveTab('explorer');
    const prevQueries = investigationState.executedQueries || [];
    onUpdateInvestigation({
      executedQueries: Array.from(new Set([...prevQueries, q]))
    });
    if (onNotify) onNotify(`Filtered Log Explorer to ${q}`);
  }

  function handleAddEvidence(eventObj) {
    if (!eventObj) return;
    const existing = evidence.find((item) => item.targetId === eventObj.eventId);
    if (existing) {
      if (onNotify) onNotify(`Event ${eventObj.eventId} is already in your Evidence Locker.`);
      return;
    }
    const newItem = {
      evidenceId: `EVID-${eventObj.eventId}`,
      evidenceType: 'event',
      targetId: eventObj.eventId,
      summary: `${eventObj.eventType} on ${eventObj.host || eventObj.username || eventObj.source}`,
      reason: evidenceReason.trim() || 'Relevant security telemetry',
      note: evidenceNote.trim() || `Collected from ${eventObj.source} at ${eventObj.timestamp}`,
      alignment: evidenceAlignment,
      addedAt: new Date().toISOString()
    };
    onUpdateInvestigation({
      evidence: [...evidence, newItem]
    });
    setEvidenceNote('');
    if (onNotify) onNotify(`★ Clue Saved: Added ${eventObj.eventId} to Evidence Locker!`);
  }

  function handleRemoveEvidence(targetId) {
    onUpdateInvestigation({
      evidence: evidence.filter((e) => e.targetId !== targetId)
    });
  }

  function handleExecuteDetections() {
    const findings = runAllDetections(DETECTION_RULES, events);
    onUpdateInvestigation({
      ranDetections: true,
      detectionFindings: findings
    });
    if (onNotify) {
      onNotify(`Threat Scanner evaluated ${DETECTION_RULES.length} rules: ${findings.length} alert(s) matched.`);
    }
  }

  function handleExecuteResponseAction(e) {
    if (e) e.preventDefault();
    try {
      const res = executeSimulatedResponse(mission, incidentState, evidence, {
        actionType: selectedActionType,
        target: responseTarget,
        justification: responseJustification
      });
      onUpdateInvestigation({
        responseActions: [...responseActions, res.actionRecord],
        incidentState: res.incidentState
      });
      setResponseTarget('');
      setResponseJustification('');
      if (onNotify) {
        onNotify(res.actionRecord.consequenceText);
      }
    } catch (err) {
      if (onNotify) onNotify(err.message);
    }
  }

  function handleUpdateAssessmentField(field, value) {
    onUpdateInvestigation({
      assessment: {
        ...assessment,
        [field]: value
      }
    });
    setSubmitErrors([]);
  }

  function handleToggleAttackStage(techId) {
    const curr = Array.isArray(assessment.attackStages) ? assessment.attackStages : [];
    const next = curr.includes(techId)
      ? curr.filter((id) => id !== techId)
      : [...curr, techId];
    handleUpdateAssessmentField('attackStages', next);
  }

  function handleAutoFillFromClues() {
    const collectedEventObjs = events.filter((ev) =>
      evidence.some((item) => item.targetId === ev.eventId)
    );
    const entitiesSet = new Set();
    collectedEventObjs.forEach((ev) => {
      if (ev.username && ev.username !== 'SYSTEM') entitiesSet.add(ev.username);
      if (ev.host) entitiesSet.add(ev.host);
      if (ev.sourceIp && !ev.sourceIp.startsWith('10.')) entitiesSet.add(ev.sourceIp);
      if (ev.destinationIp && !ev.destinationIp.startsWith('10.')) entitiesSet.add(ev.destinationIp);
      if (ev.domain && !ev.domain.includes('internal')) entitiesSet.add(ev.domain);
    });
    const entityStr =
      entitiesSet.size > 0
        ? Array.from(entitiesSet).join(', ')
        : mission.briefing.initialAlert.entity;

    const detectedStages = Array.from(
      new Set(
        (investigationState.detectionFindings || []).flatMap((f) =>
          (f.attackMappings || []).map((m) => m.techniqueId)
        )
      )
    );

    const summaryDraft =
      collectedEventObjs.length > 0
        ? `Investigated ${collectedEventObjs.length} key telemetry events (${collectedEventObjs.map((e) => e.eventId).join(', ')}). Correlated activity across ${Array.from(new Set(collectedEventObjs.map((e) => e.source))).join(', ')} and executed ${responseActions.length} response action(s).`
        : 'Investigated scenario telemetry and executed response disposition.';

    onUpdateInvestigation({
      assessment: {
        ...assessment,
        affectedEntity: assessment.affectedEntity || entityStr,
        attackStages:
          assessment.attackStages && assessment.attackStages.length > 0
            ? assessment.attackStages
            : detectedStages,
        keyFindings: assessment.keyFindings || summaryDraft,
        scopeSummary:
          assessment.scopeSummary || `Scoped entities: ${entityStr}.`,
        remainingUncertainty:
          assessment.remainingUncertainty || 'Verified across available endpoint, network, and identity telemetry.',
        recommendedFollowUp:
          assessment.recommendedFollowUp || 'Continue monitoring affected subnet and review IAM/EDR controls.'
      }
    });
    if (onNotify) onNotify('Auto-filled report fields from your collected clues!');
  }

  function handleRevealNextHint() {
    const allHints = mission?.hints || [];
    if (hintsUsed.length >= allHints.length) return;
    const nextHint = allHints[hintsUsed.length];
    onUpdateInvestigation({
      hintsUsed: [...hintsUsed, nextHint]
    });
  }

  function handleSubmitReport(e) {
    e.preventDefault();
    const check = validateMissionCompletionReadiness(mission, investigationState);
    if (!check.ready) {
      setSubmitErrors(check.missing);
      return;
    }
    setSubmitErrors([]);
    onCompleteMission();
  }

  const detectionFindings = investigationState?.detectionFindings || [];
  const completedObjCount = objectives.filter((o) => o.completed).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Gamified Room Header Banner */}
      <section className="panel-elevated" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '4px' }}>
              <span className="sim-badge">{mission.difficulty.toUpperCase()} ROOM</span>
              <SeverityBadge severity={mission.briefing.initialAlert.severity} />
              <h1 style={{ margin: 0, fontSize: '19px', fontWeight: 800 }}>{mission.title}</h1>
            </div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
              {mission.subtitle} • Target: <strong className="mono" style={{ color: 'var(--accent-cyan)' }}>{mission.briefing.initialAlert.entity}</strong>
            </div>
          </div>

          {/* Clean Gamified Progress Pills */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <div className="player-hud-pill" style={{ padding: '5px 12px' }}>
              <Bookmark size={14} color="#34d399" />
              <span style={{ fontSize: '12.5px', fontWeight: 600 }}>
                Clues: {evidence.length}/{mission.minimumEvidenceRequired}
              </span>
            </div>

            <div className="player-hud-pill" style={{ padding: '5px 12px' }}>
              <CheckCircle2 size={14} color="var(--accent-cyan)" />
              <span style={{ fontSize: '12.5px', fontWeight: 600 }}>
                Goals: {completedObjCount}/{objectives.length}
              </span>
            </div>

            <button type="button" className="btn btn-sm" onClick={onOpenBriefing}>
              <HelpCircle size={13} />
              <span>Story Briefing</span>
            </button>

            <button
              type="button"
              className="btn btn-sm"
              onClick={handleRevealNextHint}
              disabled={hintsUsed.length >= (mission.hints || []).length}
            >
              <Lightbulb size={13} color="var(--sev-medium)" />
              <span>
                {hintsUsed.length >= (mission.hints || []).length
                  ? `Hints (${hintsUsed.length})`
                  : `Get Hint (${hintsUsed.length}/${(mission.hints || []).length})`}
              </span>
            </button>

            <button type="button" className="btn btn-sm" onClick={onRestartMission}>
              <RotateCcw size={13} />
              <span>Reset Room</span>
            </button>
          </div>
        </div>

        {/* Hints Drawer if any unlocked */}
        {hintsUsed.length > 0 && (
          <div
            style={{
              marginTop: '12px',
              padding: '10px 14px',
              backgroundColor: 'rgba(245, 158, 11, 0.12)',
              border: '1px solid rgba(245, 158, 11, 0.4)',
              borderRadius: 'var(--radius-sm)',
              display: 'flex',
              flexDirection: 'column',
              gap: '4px'
            }}
          >
            {hintsUsed.map((h) => (
              <div key={h.level} style={{ fontSize: '13px', color: '#fde047' }}>
                <strong>💡 Hint {h.level}:</strong> {h.text}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* TryHackMe-Style Split Screen: Left Guided Walkthrough + Right Interactive Lab */}
      <div className="thm-room-layout">
        {/* LEFT COLUMN: GUIDED STEP-BY-STEP COACH (TryHackMe Room Style) */}
        <aside style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {/* Mentor Welcome Bubble */}
          <div
            className="panel"
            style={{
              background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.12) 0%, rgba(19, 28, 46, 0.95) 100%)',
              borderColor: 'rgba(16, 185, 129, 0.4)',
              padding: '14px 16px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
              <div
                style={{
                  width: '30px',
                  height: '30px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--accent-green-dim)',
                  border: '1px solid var(--accent-green)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#34d399',
                  fontWeight: 800,
                  fontSize: '13px'
                }}
              >
                CV
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: '13px', color: '#34d399' }}>
                  {walkthrough.mentorName}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  Step-by-Step Guided Investigation
                </div>
              </div>
            </div>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              {walkthrough.mentorIntro}
            </p>
          </div>

          {/* Step-by-Step Tasks Accordion */}
          {walkthrough.steps.map((step, idx) => {
            const isOpen = activeStepIdx === idx;
            const isDone = completedSteps.includes(step.id);
            const fb = flagFeedback[step.id];

            return (
              <div
                key={step.id}
                className={`thm-task-card ${isOpen ? 'active' : ''} ${isDone ? 'completed' : ''}`}
              >
                <button
                  type="button"
                  className="thm-task-header"
                  onClick={() => handleSelectWalkthroughStep(idx)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {isDone ? (
                      <CheckCircle2 size={18} color="#34d399" />
                    ) : (
                      <span className="step-num-circle">{step.stepNumber}</span>
                    )}
                    <span style={{ fontWeight: 700, fontSize: '14px', color: isDone ? '#6ee7b7' : 'var(--text-primary)' }}>
                      {step.title}
                    </span>
                  </div>
                  {isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                </button>

                {isOpen && (
                  <div className="thm-task-body">
                    {/* Educational Concept Callout */}
                    <div className="concept-callout">
                      <div style={{ fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '3px' }}>
                        📘 {step.conceptTitle}
                      </div>
                      <div style={{ color: 'var(--text-secondary)' }}>{step.conceptLesson}</div>
                    </div>

                    {/* Numbered One-by-One Instructions */}
                    <div>
                      <div style={{ fontSize: '12px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '6px' }}>
                        What To Do Right Now:
                      </div>
                      <ol className="step-instruction-list">
                        {step.instructions.map((inst, i) => (
                          <li key={i} className="step-instruction-item">
                            <span className="step-num-circle">{i + 1}</span>
                            <span>{inst}</span>
                          </li>
                        ))}
                      </ol>
                    </div>

                    {/* One-Click Query Loader Button if applicable */}
                    {step.quickQuery && (
                      <button
                        type="button"
                        className="btn btn-sm btn-primary"
                        onClick={() => handleApplyExampleQuery(step.quickQuery)}
                      >
                        <Zap size={13} />
                        <span>Load Into Search: {step.quickQuery}</span>
                      </button>
                    )}

                    {/* TryHackMe-Style Interactive Question Check */}
                    {step.question ? (
                      <div className="flag-box">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 700, fontSize: '12.5px', color: '#34d399', marginBottom: '6px' }}>
                          <Flag size={13} />
                          <span>Task Check-In Question:</span>
                        </div>
                        <div style={{ fontSize: '13px', marginBottom: '8px' }}>
                          {step.question.prompt}
                        </div>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          <input
                            type="text"
                            aria-label={`Answer for ${step.title}`}
                            className="input mono"
                            style={{ padding: '6px 10px', fontSize: '12.5px' }}
                            placeholder={step.question.placeholder}
                            value={flagInputs[step.id] || ''}
                            onChange={(e) =>
                              setFlagInputs((prev) => ({ ...prev, [step.id]: e.target.value }))
                            }
                          />
                          <button
                            type="button"
                            className="btn btn-sm btn-primary"
                            onClick={() => handleCheckStepQuestion(step, idx)}
                          >
                            Submit Answer
                          </button>
                        </div>
                        {fb && (
                          <div
                            style={{
                              marginTop: '8px',
                              fontSize: '12.5px',
                              color: fb.ok ? '#6ee7b7' : '#fde047',
                              fontWeight: 600
                            }}
                          >
                            {fb.text}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '4px' }}>
                        <button
                          type="button"
                          className="btn btn-sm btn-success"
                          onClick={() => {
                            markStepDone(step.id);
                            if (idx + 1 < walkthrough.steps.length) {
                              handleSelectWalkthroughStep(idx + 1);
                            }
                          }}
                        >
                          <CheckCircle2 size={13} />
                          <span>
                            {idx + 1 < walkthrough.steps.length
                              ? 'Mark Done & Next Task ➔'
                              : 'Mark Final Task Done'}
                          </span>
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}

          {/* Compact Mission Objectives Progress Card */}
          <div className="panel" style={{ padding: '14px' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '8px' }}>
              Room Completion Checklist ({completedObjCount}/{objectives.length})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {objectives.map((obj) => (
                <div key={obj.id} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '12.5px' }}>
                  {obj.completed ? (
                    <CheckCircle2 size={15} color="#34d399" style={{ flexShrink: 0, marginTop: '2px' }} />
                  ) : (
                    <Circle size={15} color="var(--text-muted)" style={{ flexShrink: 0, marginTop: '2px' }} />
                  )}
                  <span style={{ color: obj.completed ? '#6ee7b7' : 'var(--text-secondary)' }}>
                    {obj.title}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </aside>

        {/* RIGHT COLUMN: STREAMLINED INTERACTIVE CYBER LAB */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', minWidth: 0 }}>
          {/* Clean Lab Tool Switcher Tabs */}
          <div className="workstation-tabs" role="tablist" aria-label="Investigation Workstation Views" style={{ marginBottom: 0 }}>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'explorer'}
              className={`tab-btn ${activeTab === 'explorer' ? 'active' : ''}`}
              onClick={() => setActiveTab('explorer')}
            >
              <Search size={14} />
              <span>1. Log Explorer ({queryResult.total})</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'timeline'}
              className={`tab-btn ${activeTab === 'timeline' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('timeline');
                onUpdateInvestigation({ inspectedTimeline: true });
              }}
            >
              <Clock size={14} />
              <span>2. Timeline &amp; Correlation ({correlations.length})</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'detections'}
              className={`tab-btn ${activeTab === 'detections' ? 'active' : ''}`}
              onClick={() => setActiveTab('detections')}
            >
              <Cpu size={14} />
              <span>3. Detection Rules &amp; ATT&amp;CK ({detectionFindings.length})</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'response'}
              className={`tab-btn ${activeTab === 'response' ? 'active' : ''}`}
              onClick={() => setActiveTab('response')}
            >
              <Shield size={14} />
              <span>4. Response &amp; Containment ({responseActions.length})</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'assessment'}
              className={`tab-btn ${activeTab === 'assessment' ? 'active' : ''}`}
              onClick={() => setActiveTab('assessment')}
            >
              <FileCheck size={14} />
              <span>5. Incident Assessment &amp; Debrief</span>
            </button>
          </div>

          {/* TAB 1: DECLUTTERED LOG EXPLORER */}
          {activeTab === 'explorer' && (
            <section className="panel">
              <div className="panel-header">
                <h2 className="panel-title">
                  <Terminal size={15} color="var(--accent-cyan)" />
                  <span>Interactive Security Log Explorer</span>
                </h2>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => setShowAdvancedFilters((s) => !s)}
                  >
                    <Filter size={12} />
                    <span>{showAdvancedFilters ? 'Hide Filters' : 'More Filters'}</span>
                  </button>
                  {(appliedQuery || freeText || sourceFilter !== 'all' || severityFilter !== 'all') && (
                    <button type="button" className="btn btn-sm" onClick={handleClearAllFilters}>
                      Show All ({events.length})
                    </button>
                  )}
                </div>
              </div>

              {/* Clean Search & Structured Query Bar */}
              <form onSubmit={handleRunStructuredQuery} style={{ marginBottom: '10px' }}>
                <label htmlFor="structured-query-input" className="label">
                  Structured Query Language (Click a quick pill below or type a query)
                </label>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <input
                    id="structured-query-input"
                    type="text"
                    className="input mono"
                    style={{ flex: 1, minWidth: '220px' }}
                    placeholder='e.g. username = "analyst.test" or processName CONTAINS "powershell"'
                    value={queryInput}
                    onChange={(e) => setQueryInput(e.target.value)}
                  />
                  <button type="submit" className="btn btn-primary">
                    <Play size={13} />
                    <span>Run Query</span>
                  </button>
                  <button
                    type="button"
                    className="btn"
                    onClick={() => {
                      if (queryInput.trim()) {
                        onSaveQuery(queryInput.trim());
                        if (onNotify) onNotify('Saved query to history.');
                      }
                    }}
                  >
                    <Bookmark size={13} />
                    <span>Save</span>
                  </button>
                </div>
              </form>

              {/* One-Click Quick Query Pills */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '12px', alignItems: 'center' }}>
                <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Quick Filter Pills:</span>
                {EXAMPLE_QUERIES.slice(0, 5).map((ex) => (
                  <button
                    key={ex.label}
                    type="button"
                    className="tag-chip"
                    style={{
                      cursor: 'pointer',
                      backgroundColor: appliedQuery === ex.query ? 'var(--accent-cyan-dim)' : 'var(--bg-input)',
                      borderColor: appliedQuery === ex.query ? 'var(--accent-cyan)' : 'var(--border-subtle)',
                      color: appliedQuery === ex.query ? 'var(--accent-cyan)' : 'var(--text-secondary)'
                    }}
                    onClick={() => handleApplyExampleQuery(ex.query)}
                    title={ex.query}
                  >
                    {ex.label}
                  </button>
                ))}
              </div>

              {/* Query Syntax Error Banner */}
              {queryResult.error && (
                <div
                  role="alert"
                  style={{
                    marginBottom: '12px',
                    padding: '10px 12px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'var(--sev-critical-bg)',
                    border: '1px solid var(--sev-critical)',
                    color: '#fda4af',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    fontSize: '13px'
                  }}
                >
                  <AlertCircle size={16} />
                  <div>
                    <strong>Query Syntax Error:</strong> {queryResult.error}
                  </div>
                </div>
              )}

              {/* Collapsible Advanced Filters Drawer (Hidden by default to prevent visual overload!) */}
              {showAdvancedFilters && (
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
                    gap: '8px',
                    marginBottom: '14px',
                    padding: '12px',
                    backgroundColor: 'var(--bg-input)',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border-subtle)'
                  }}
                >
                  <div>
                    <label htmlFor="free-text-filter" className="label">Keyword Search</label>
                    <input
                      id="free-text-filter"
                      type="search"
                      className="input"
                      placeholder="Keyword..."
                      value={freeText}
                      onChange={(e) => setFreeText(e.target.value)}
                    />
                  </div>
                  <div>
                    <label htmlFor="source-select" className="label">Source</label>
                    <select id="source-select" className="select" value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)}>
                      <option value="all">All Sources</option>
                      {distinctSources.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                  <div>
                    <label htmlFor="severity-select" className="label">Severity</label>
                    <select id="severity-select" className="select" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
                      <option value="all">All Severities</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                  <div>
                    <label htmlFor="eventtype-select" className="label">Event Type</label>
                    <select id="eventtype-select" className="select" value={eventTypeFilter} onChange={(e) => setEventTypeFilter(e.target.value)}>
                      <option value="all">All Types</option>
                      {distinctEventTypes.map((et) => <option key={et} value={et}>{et}</option>)}
                    </select>
                  </div>
                  <div>
                    <label htmlFor="host-select" className="label">Host</label>
                    <select id="host-select" className="select" value={hostFilter} onChange={(e) => setHostFilter(e.target.value)}>
                      <option value="all">All Hosts</option>
                      {distinctHosts.map((h) => <option key={h} value={h}>{h}</option>)}
                    </select>
                  </div>
                  <div>
                    <label htmlFor="user-select" className="label">Username</label>
                    <select id="user-select" className="select" value={usernameFilter} onChange={(e) => setUsernameFilter(e.target.value)}>
                      <option value="all">All Users</option>
                      {distinctUsers.map((u) => <option key={u} value={u}>{u}</option>)}
                    </select>
                  </div>
                  <div>
                    <label htmlFor="ip-domain-filter" className="label">IP / Domain</label>
                    <input id="ip-domain-filter" type="text" className="input mono" value={ipDomainFilter} onChange={(e) => setIpDomainFilter(e.target.value)} />
                  </div>
                  <div>
                    <label htmlFor="sort-select" className="label">Order</label>
                    <select id="sort-select" className="select" value={sortOrder} onChange={(e) => setSortOrder(e.target.value)}>
                      <option value="asc">Oldest First</option>
                      <option value="desc">Newest First</option>
                    </select>
                  </div>
                </div>
              )}

              {/* Streamlined Event Table */}
              {queryResult.events.length === 0 ? (
                <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                  No telemetry events matched your filter. Click <strong>Show All ({events.length})</strong> to reset.
                </div>
              ) : (
                <div className="table-container">
                  <table className="event-table" aria-label="Security Telemetry Events">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Time (UTC)</th>
                        <th>Severity</th>
                        <th>Host &amp; User</th>
                        <th>What Happened (Click any row to inspect details)</th>
                        <th>Save Clue</th>
                      </tr>
                    </thead>
                    <tbody>
                      {queryResult.events.map((ev) => {
                        const isSelected = selectedEvent?.eventId === ev.eventId;
                        const isEvid = evidence.some((item) => item.targetId === ev.eventId);

                        return (
                          <tr
                            key={ev.eventId}
                            className={`event-row ${isSelected ? 'selected' : ''} ${isEvid ? 'is-evidence' : ''}`}
                            onClick={() => setSelectedEventId(ev.eventId)}
                          >
                            <td className="mono" style={{ fontWeight: 700, color: isEvid ? '#34d399' : 'var(--accent-cyan)', whiteSpace: 'nowrap' }}>
                              {ev.eventId}
                              {isEvid && ' ★'}
                            </td>
                            <td className="mono" style={{ whiteSpace: 'nowrap', fontSize: '12px', color: 'var(--text-secondary)' }}>
                              {formatTimestamp(ev.timestamp, false)}
                            </td>
                            <td>
                              <SeverityBadge severity={ev.severity} />
                            </td>
                            <td className="mono" style={{ fontSize: '12px' }}>
                              <div>{ev.host || '—'}</div>
                              <div style={{ color: 'var(--text-muted)' }}>{ev.username || '—'}</div>
                            </td>
                            <td>
                              <div style={{ fontWeight: 500 }}>{ev.message}</div>
                              <div className="mono" style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
                                [{ev.source} • {ev.eventType}]
                                {ev.sourceIp ? ` src=${ev.sourceIp}` : ''}
                                {ev.destinationIp ? ` dst=${ev.destinationIp}` : ''}
                                {ev.processName ? ` proc=${ev.processName}` : ''}
                              </div>
                            </td>
                            <td onClick={(e) => e.stopPropagation()} style={{ whiteSpace: 'nowrap' }}>
                              <button
                                type="button"
                                className={`btn btn-sm ${isEvid ? 'btn-success' : 'btn-primary'}`}
                                onClick={() => handleAddEvidence(ev)}
                                disabled={isEvid}
                                aria-label={`Add ${ev.eventId} to Evidence`}
                              >
                                <PlusCircle size={12} />
                                <span>{isEvid ? 'Saved ★' : '+ Evidence'}</span>
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}

          {/* TAB 2: TIMELINE & CORRELATION */}
          {activeTab === 'timeline' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <section className="panel">
                <div className="panel-header">
                  <h2 className="panel-title">
                    <Clock size={15} color="var(--accent-cyan)" />
                    <span>Chronological Investigation Timeline</span>
                  </h2>
                  <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
                    <input
                      type="search"
                      className="input"
                      style={{ width: '190px', padding: '4px 8px' }}
                      placeholder="Filter entity..."
                      value={timelineEntityFilter}
                      onChange={(e) => setTimelineEntityFilter(e.target.value)}
                    />
                    <label style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '12px', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={timelineOnlyEvidence}
                        onChange={(e) => setTimelineOnlyEvidence(e.target.checked)}
                      />
                      <span>Saved Clues Only</span>
                    </label>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {timelineItems.map((item) => (
                    <div
                      key={item.eventId}
                      className="panel"
                      style={{
                        padding: '10px 14px',
                        backgroundColor: item.isEvidence ? 'var(--accent-green-dim)' : 'var(--bg-input)',
                        borderColor: item.isEvidence ? 'var(--accent-green)' : 'var(--border-subtle)',
                        cursor: 'pointer'
                      }}
                      onClick={() => setSelectedEventId(item.eventId)}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginBottom: '4px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span className="mono" style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>
                            Step #{item.timelineIndex} [{item.eventId}]
                          </span>
                          <span className="mono" style={{ fontSize: '12px' }}>
                            {formatTimestamp(item.timestamp)}
                          </span>
                          <span className="tag-chip">Δ prev: {item.deltaFromPrevious}</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          {item.isEvidence && <span className="sev-badge sev-safe">★ SAVED CLUE</span>}
                          <SeverityBadge severity={item.severity} />
                        </div>
                      </div>
                      <div style={{ fontSize: '13.5px' }}>{item.message}</div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="panel">
                <div className="panel-header">
                  <h2 className="panel-title">
                    <GitBranch size={15} color="var(--accent-cyan)" />
                    <span>Automated Cross-Source Correlations ({correlations.length})</span>
                  </h2>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {correlations.map((corr) => (
                    <div key={corr.id} className="panel" style={{ backgroundColor: 'var(--bg-input)', padding: '10px 14px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <span className="mono" style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>
                          {corr.sourceEventId} ➔ {corr.targetEventId} (Δ {corr.timeDeltaSeconds}s)
                        </span>
                        <SeverityBadge
                          severity={corr.confidence === 'confirmed' ? 'safe' : corr.confidence === 'probable' ? 'medium' : 'low'}
                          labelOverride={`LINK: ${corr.confidence.toUpperCase()}`}
                        />
                      </div>
                      <div style={{ fontSize: '13px' }}>{corr.rationale}</div>
                    </div>
                  ))}
                </div>
              </section>
            </div>
          )}

          {/* TAB 3: DETECTION ENGINE & ATT&CK */}
          {activeTab === 'detections' && (
            <section className="panel">
              <div className="panel-header">
                <h2 className="panel-title">
                  <Cpu size={15} color="var(--accent-cyan)" />
                  <span>Automated Threat Scanner &amp; MITRE ATT&amp;CK Mapper</span>
                </h2>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleExecuteDetections}
                >
                  <Play size={14} />
                  <span>Execute All {DETECTION_RULES.length} Detection Rules</span>
                </button>
              </div>

              {!investigationState.ranDetections ? (
                <div className="panel" style={{ backgroundColor: 'var(--bg-input)', textAlign: 'center', padding: '28px' }}>
                  <p style={{ margin: '0 0 14px 0', color: 'var(--text-secondary)' }}>
                    Run the automated Threat Scanner to check all 12 SIEM detection rules against this room’s logs.
                  </p>
                  <button type="button" className="btn btn-primary" onClick={handleExecuteDetections}>
                    Run Detection Rules Now
                  </button>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div style={{ fontWeight: 700, color: '#34d399' }}>
                    Triggered Detection Findings ({detectionFindings.length} Match{detectionFindings.length === 1 ? '' : 'es'})
                  </div>

                  {detectionFindings.map((finding) => (
                    <div key={finding.findingId} className="panel" style={{ backgroundColor: 'var(--bg-input)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginBottom: '6px' }}>
                        <div>
                          <span className="mono" style={{ color: 'var(--accent-cyan)', fontWeight: 700, marginRight: '8px' }}>
                            {finding.ruleId}
                          </span>
                          <strong>{finding.ruleName}</strong>
                        </div>
                        <SeverityBadge severity={finding.severity} />
                      </div>

                      <div style={{ fontSize: '13px', marginBottom: '8px' }}>
                        <strong>Why It Triggered:</strong> {finding.whyTriggered}
                      </div>

                      <div className="concept-callout" style={{ marginBottom: '8px' }}>
                        <strong>🤔 False-Positive Check:</strong> {finding.falsePositiveConsiderations}
                      </div>

                      {finding.attackMappings && finding.attackMappings.length > 0 && (
                        <div style={{ fontSize: '12.5px', marginBottom: '8px' }}>
                          {finding.attackMappings.map((m) => (
                            <span key={m.techniqueId} className="tag-chip" style={{ color: 'var(--accent-cyan)' }}>
                              MITRE {m.techniqueId}: {m.techniqueName} ({m.tactic})
                            </span>
                          ))}
                        </div>
                      )}

                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', alignItems: 'center' }}>
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Matched Events:</span>
                        {finding.matchedEventIds.map((evId) => (
                          <button
                            key={evId}
                            type="button"
                            className="btn btn-sm mono"
                            onClick={() => {
                              setSelectedEventId(evId);
                              setActiveTab('explorer');
                            }}
                          >
                            <Eye size={12} />
                            <span>Inspect {evId}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}

          {/* TAB 4: GAMIFIED RESPONSE & CONTAINMENT CONSOLE */}
          {activeTab === 'response' && (
            <section className="panel">
              <div className="panel-header">
                <h2 className="panel-title">
                  <Shield size={15} color="var(--accent-cyan)" />
                  <span>Tactical Response &amp; Containment Console</span>
                </h2>
                <span className="sim-badge">CONTAINMENT PROGRESS: {incidentState.containmentProgress || 0}%</span>
              </div>

              {/* Visual Tactical Action Cards */}
              <div style={{ marginBottom: '12px' }}>
                <div className="label">Step 1: Click a Tactical Action Card (or choose from the dropdown below)</div>
                <div className="tactical-cards-grid">
                  {RESPONSE_CATALOG.map((item) => {
                    const isSel = selectedActionType === item.actionType;
                    return (
                      <button
                        key={item.actionType}
                        type="button"
                        className={`tactical-card ${isSel ? 'selected' : ''}`}
                        onClick={() => setSelectedActionType(item.actionType)}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
                          <span className="tag-chip">{item.category}</span>
                          {item.intrusive && <span style={{ fontSize: '10px', color: '#fda4af' }}>Intrusive</span>}
                        </div>
                        <div style={{ fontWeight: 700, fontSize: '13.5px', color: isSel ? 'var(--accent-cyan)' : 'var(--text-primary)' }}>
                          {item.label}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              <form onSubmit={handleExecuteResponseAction} className="panel" style={{ backgroundColor: 'var(--bg-input)', marginBottom: '16px' }}>
                <div className="grid-2" style={{ marginBottom: '10px' }}>
                  <div>
                    <label htmlFor="response-action-select" className="label">Response / Disposition Action</label>
                    <select
                      id="response-action-select"
                      className="select"
                      value={selectedActionType}
                      onChange={(e) => setSelectedActionType(e.target.value)}
                    >
                      {RESPONSE_CATALOG.map((item) => (
                        <option key={item.actionType} value={item.actionType}>
                          [{item.category}] {item.label}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label htmlFor="response-target-input" className="label">Target Entity (Click a quick chip below to fill)</label>
                    <input
                      id="response-target-input"
                      type="text"
                      className="input mono"
                      placeholder={
                        RESPONSE_CATALOG.find((c) => c.actionType === selectedActionType)?.targetPlaceholder ||
                        'Target...'
                      }
                      value={responseTarget}
                      onChange={(e) => setResponseTarget(e.target.value)}
                    />
                  </div>
                </div>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '12px', alignItems: 'center' }}>
                  <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>1-Click Targets:</span>
                  {allQuickEntities.map((ent) => (
                    <button
                      key={ent}
                      type="button"
                      className="tag-chip"
                      style={{ cursor: 'pointer', color: 'var(--accent-cyan)' }}
                      onClick={() => setResponseTarget(ent)}
                    >
                      {ent}
                    </button>
                  ))}
                </div>

                <button type="submit" className="btn btn-primary">
                  <Shield size={14} />
                  <span>Execute Simulated Action</span>
                </button>
              </form>

              <h3 style={{ margin: '0 0 8px 0', fontSize: '13.5px' }}>
                Executed Response Log ({responseActions.length})
              </h3>
              {responseActions.map((act) => (
                <div key={act.actionId} className="panel" style={{ backgroundColor: 'var(--bg-input)', padding: '10px 12px', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <div>
                      <strong>{act.label}</strong> ➔ <span className="mono">{act.target}</span>
                    </div>
                    <SeverityBadge
                      severity={act.evaluation === 'appropriate' ? 'safe' : act.evaluation === 'premature' ? 'medium' : 'critical'}
                      labelOverride={act.evaluation.toUpperCase()}
                    />
                  </div>
                  <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>{act.consequenceText}</div>
                </div>
              ))}
            </section>
          )}

          {/* TAB 5: STREAMLINED INCIDENT ASSESSMENT & DEBRIEF */}
          {activeTab === 'assessment' && (
            <section className="panel">
              <div className="panel-header">
                <h2 className="panel-title">
                  <FileCheck size={15} color="var(--accent-cyan)" />
                  <span>Case Verdict &amp; Final Report</span>
                </h2>
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  onClick={handleAutoFillFromClues}
                >
                  <Sparkles size={13} />
                  <span>Auto-Fill Scope &amp; Summary From Collected Clues</span>
                </button>
              </div>

              {submitErrors.length > 0 && (
                <div
                  role="alert"
                  style={{
                    marginBottom: '14px',
                    padding: '12px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'var(--sev-critical-bg)',
                    border: '1px solid var(--sev-critical)',
                    color: '#fda4af'
                  }}
                >
                  <strong>Please complete the following mandatory criteria before submitting:</strong>
                  <ul style={{ margin: '6px 0 0 0', paddingLeft: '18px' }}>
                    {submitErrors.map((err, i) => (
                      <li key={i}>{err}</li>
                    ))}
                  </ul>
                </div>
              )}

              <form onSubmit={handleSubmitReport} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div className="grid-3">
                  <div>
                    <label htmlFor="assess-classification" className="label">1. Incident Classification *</label>
                    <select
                      id="assess-classification"
                      className="select"
                      value={assessment.classification || ''}
                      onChange={(e) => handleUpdateAssessmentField('classification', e.target.value)}
                    >
                      <option value="">Select classification...</option>
                      <option value="malicious_incident">True Positive — Malicious Incident</option>
                      <option value="benign_activity">False Positive — Benign / Authorized Activity</option>
                      <option value="inconclusive">Inconclusive — Insufficient Telemetry</option>
                    </select>
                  </div>

                  <div>
                    <label htmlFor="assess-severity" className="label">2. Incident Severity *</label>
                    <select
                      id="assess-severity"
                      className="select"
                      value={assessment.severity || ''}
                      onChange={(e) => handleUpdateAssessmentField('severity', e.target.value)}
                    >
                      <option value="">Select severity...</option>
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>

                  <div>
                    <label htmlFor="assess-confidence" className="label">3. Analyst Confidence Level</label>
                    <select
                      id="assess-confidence"
                      className="select"
                      value={assessment.confidence || 'high'}
                      onChange={(e) => handleUpdateAssessmentField('confidence', e.target.value)}
                    >
                      <option value="low">Low Confidence</option>
                      <option value="medium">Medium Confidence</option>
                      <option value="high">High Confidence</option>
                      <option value="confirmed">Confirmed by Multi-Source Evidence</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label htmlFor="assess-affected-entity" className="label">
                    4. Primary Affected User(s), Host(s), and Malicious Indicators *
                  </label>
                  <input
                    id="assess-affected-entity"
                    type="text"
                    className="input mono"
                    placeholder="e.g. analyst.test, WKSTN-HR-02"
                    value={assessment.affectedEntity || ''}
                    onChange={(e) => handleUpdateAssessmentField('affectedEntity', e.target.value)}
                  />
                </div>

                <div>
                  <span className="label">5. Observed MITRE ATT&amp;CK Techniques (leave unchecked if Benign)</span>
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))',
                      gap: '6px',
                      padding: '10px',
                      backgroundColor: 'var(--bg-input)',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-subtle)'
                    }}
                  >
                    {MITRE_TECHNIQUE_OPTIONS.map((tech) => {
                      const checked = (assessment.attackStages || []).includes(tech.id);
                      return (
                        <label
                          key={tech.id}
                          style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', cursor: 'pointer' }}
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => handleToggleAttackStage(tech.id)}
                          />
                          <span className="mono">{tech.label}</span>
                        </label>
                      );
                    })}
                  </div>
                </div>

                <div>
                  <label htmlFor="assess-findings" className="label">
                    6. Key Findings &amp; Root-Cause Attack Sequence (min 15 chars) *
                  </label>
                  <textarea
                    id="assess-findings"
                    rows={3}
                    className="textarea"
                    placeholder="Summarize what happened chronologically..."
                    value={assessment.keyFindings || ''}
                    onChange={(e) => handleUpdateAssessmentField('keyFindings', e.target.value)}
                  />
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <button type="submit" className="btn btn-primary" style={{ padding: '10px 22px', fontSize: '14px' }}>
                    <FileCheck size={16} />
                    <span>Submit Final Report &amp; View Debrief</span>
                  </button>
                </div>
              </form>
            </section>
          )}

          {/* BOTTOM 2-CARD DOCK: SELECTED EVENT DETAILS + SAVED EVIDENCE LOCKER */}
          <div className="grid-2">
            {/* Selected Event Inspector */}
            <section className="panel">
              <div className="panel-header">
                <h2 className="panel-title">
                  <Eye size={15} color="var(--accent-cyan)" />
                  <span>Selected Log Inspector ({selectedEvent?.eventId || 'None'})</span>
                </h2>
                {selectedEvent && <SeverityBadge severity={selectedEvent.severity} />}
              </div>

              {!selectedEvent ? (
                <div style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
                  Click any event row above to inspect its full fields.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px' }}>
                  <div className="mono" style={{ display: 'grid', gridTemplateColumns: '115px 1fr', gap: '4px' }}>
                    <span style={{ color: 'var(--text-muted)' }}>timestamp:</span>
                    <span>{formatTimestamp(selectedEvent.timestamp)}</span>

                    <span style={{ color: 'var(--text-muted)' }}>host:</span>
                    <span>
                      {selectedEvent.host ? (
                        <button
                          type="button"
                          className="tag-chip"
                          style={{ cursor: 'pointer', color: 'var(--accent-cyan)' }}
                          onClick={() => handlePivotEntity('host', selectedEvent.host)}
                        >
                          {selectedEvent.host} ⌕
                        </button>
                      ) : (
                        'Unavailable'
                      )}
                    </span>

                    <span style={{ color: 'var(--text-muted)' }}>username:</span>
                    <span>
                      {selectedEvent.username ? (
                        <button
                          type="button"
                          className="tag-chip"
                          style={{ cursor: 'pointer', color: 'var(--accent-cyan)' }}
                          onClick={() => handlePivotEntity('username', selectedEvent.username)}
                        >
                          {selectedEvent.username} ⌕
                        </button>
                      ) : (
                        'Unavailable'
                      )}
                    </span>

                    <span style={{ color: 'var(--text-muted)' }}>sourceIp:</span>
                    <span>{selectedEvent.sourceIp || 'Unavailable'}</span>

                    <span style={{ color: 'var(--text-muted)' }}>destinationIp:</span>
                    <span>{selectedEvent.destinationIp || 'Unavailable'}</span>

                    <span style={{ color: 'var(--text-muted)' }}>domain:</span>
                    <span>{selectedEvent.domain || 'Unavailable'}</span>

                    <span style={{ color: 'var(--text-muted)' }}>processName:</span>
                    <span>{selectedEvent.processName || 'Unavailable'}</span>

                    <span style={{ color: 'var(--text-muted)' }}>parentProcess:</span>
                    <span>{selectedEvent.parentProcess || 'Unavailable'}</span>
                  </div>

                  {selectedEvent.commandLine && (
                    <div className="mono" style={{ padding: '6px 8px', backgroundColor: 'var(--bg-input)', borderRadius: 'var(--radius-sm)', fontSize: '11.5px', wordBreak: 'break-all' }}>
                      cmd: {selectedEvent.commandLine}
                    </div>
                  )}

                  {selectedEvent.metadata && (
                    <pre className="mono" style={{ margin: 0, padding: '6px 8px', backgroundColor: 'var(--bg-input)', borderRadius: 'var(--radius-sm)', fontSize: '11px', overflowX: 'auto' }}>
                      {JSON.stringify(selectedEvent.metadata, null, 2)}
                    </pre>
                  )}
                </div>
              )}
            </section>

            {/* Collected Evidence Locker */}
            <section className="panel">
              <div className="panel-header">
                <h2 className="panel-title">
                  <Bookmark size={15} color="#34d399" />
                  <span>Evidence Locker ({evidence.length})</span>
                </h2>
                <span className="tag-chip">Need {mission.minimumEvidenceRequired}+ Clues</span>
              </div>

              {evidence.length === 0 ? (
                <div style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
                  No clues collected yet. Click <strong>+ Evidence</strong> on key events in the Log Explorer to build your case!
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {evidence.map((item) => (
                    <div
                      key={item.evidenceId}
                      className="panel"
                      style={{ padding: '8px 12px', backgroundColor: 'var(--bg-input)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                    >
                      <div>
                        <button
                          type="button"
                          className="mono"
                          style={{ background: 'none', border: 'none', padding: 0, color: '#34d399', fontWeight: 700, cursor: 'pointer' }}
                          onClick={() => setSelectedEventId(item.targetId)}
                        >
                          ★ {item.targetId}
                        </button>
                        <span style={{ fontSize: '12.5px', marginLeft: '8px' }}>{item.summary}</span>
                      </div>
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => handleRemoveEvidence(item.targetId)}
                        aria-label={`Remove ${item.targetId} from evidence`}
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>
        </div>
      </div>
    </div>
  );
}
