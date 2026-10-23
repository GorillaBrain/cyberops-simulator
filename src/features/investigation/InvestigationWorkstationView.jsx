import React, { useState, useMemo } from 'react';
import {
  AlertCircle,
  Bookmark,
  CheckCircle2,
  Circle,
  Clock,
  Cpu,
  Database,
  Eye,
  FileCheck,
  Filter,
  GitBranch,
  HelpCircle,
  Lightbulb,
  Play,
  PlusCircle,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  Terminal,
  Trash2
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
  const [activeTab, setActiveTab] = useState('explorer');

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
  const [evidenceReason, setEvidenceReason] = useState('Key indicator of suspicious or benign context');
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
    if (onNotify) onNotify(`Pivoted Event Explorer to ${q}`);
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
    if (onNotify) onNotify(`Added ${eventObj.eventId} to Evidence Locker.`);
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
      onNotify(`Detection Engine evaluated ${DETECTION_RULES.length} rules: ${findings.length} alert finding(s) triggered.`);
    }
  }

  function handleExecuteResponseAction(e) {
    e.preventDefault();
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Top Case Status Header */}
      <section className="panel" style={{ padding: '12px 16px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <SeverityBadge severity={mission.briefing.initialAlert.severity} />
              <h1 style={{ margin: 0, fontSize: '17px', fontWeight: 700 }}>{mission.title}</h1>
              <span className="mono" style={{ fontSize: '12px', color: 'var(--accent-cyan)' }}>
                [{mission.briefing.initialAlert.entity}]
              </span>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Incident Status:{' '}
              <strong className="mono" style={{ color: 'var(--accent-cyan)' }}>
                {(incidentState.threatStatus || 'active_uncontained').replace(/_/g, ' ').toUpperCase()}
              </strong>{' '}
              • Evidence Collected: <strong>{evidence.length}</strong> (Min {mission.minimumEvidenceRequired}) • Actions Taken:{' '}
              <strong>{responseActions.length}</strong>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <button type="button" className="btn btn-sm" onClick={onOpenBriefing}>
              <HelpCircle size={13} />
              <span>Briefing</span>
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
                  ? `All Hints Shown (${hintsUsed.length})`
                  : `Unlock Hint ${hintsUsed.length + 1}/${(mission.hints || []).length}`}
              </span>
            </button>
            <button type="button" className="btn btn-sm" onClick={onRestartMission}>
              <RotateCcw size={13} />
              <span>Reset Case</span>
            </button>
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={() => setActiveTab('assessment')}
            >
              <FileCheck size={13} />
              <span>Submit Incident Report</span>
            </button>
          </div>
        </div>

        {/* Hints Drawer if any unlocked */}
        {hintsUsed.length > 0 && (
          <div
            style={{
              marginTop: '10px',
              padding: '10px 12px',
              backgroundColor: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.35)',
              borderRadius: 'var(--radius-sm)',
              display: 'flex',
              flexDirection: 'column',
              gap: '4px'
            }}
          >
            {hintsUsed.map((h) => (
              <div key={h.level} style={{ fontSize: '12.5px', color: '#fde047' }}>
                <strong>Hint {h.level}:</strong> {h.text}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Workstation Navigation Tabs */}
      <div className="workstation-tabs" role="tablist" aria-label="Investigation Workstation Views">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'explorer'}
          className={`tab-btn ${activeTab === 'explorer' ? 'active' : ''}`}
          onClick={() => setActiveTab('explorer')}
        >
          <Search size={14} />
          <span>1. Event Explorer ({queryResult.total}/{events.length})</span>
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

      {/* Main 2-Column Workstation Layout */}
      <div className="workstation-layout">
        {/* Left Primary Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', minWidth: 0 }}>
          {/* TAB 1: EVENT EXPLORER */}
          {activeTab === 'explorer' && (
            <section className="panel">
              <div className="panel-header">
                <h2 className="panel-title">
                  <Terminal size={15} color="var(--accent-cyan)" />
                  <span>Structured Security Event Explorer</span>
                </h2>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span className="mono" style={{ fontSize: '12px', color: 'var(--accent-cyan)' }}>
                    Showing {queryResult.total} of {events.length} events
                  </span>
                  <button type="button" className="btn btn-sm" onClick={handleClearAllFilters}>
                    Clear Filters
                  </button>
                </div>
              </div>

              {/* Structured Query Input Bar */}
              <form onSubmit={handleRunStructuredQuery} style={{ marginBottom: '10px' }}>
                <label htmlFor="structured-query-input" className="label">
                  Structured Query Language (=, !=, &gt;, &lt;, CONTAINS, IN, AND, OR, NOT, parentheses)
                </label>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <input
                    id="structured-query-input"
                    type="text"
                    className="input mono"
                    style={{ flex: 1, minWidth: '240px' }}
                    placeholder='e.g. eventType = "authentication" AND result = "failure"'
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
                    <span>Save Query</span>
                  </button>
                </div>
              </form>

              {/* Example Query Quick Chips */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '12px', alignItems: 'center' }}>
                <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Quick Queries:</span>
                {EXAMPLE_QUERIES.map((ex) => (
                  <button
                    key={ex.label}
                    type="button"
                    className="tag-chip"
                    style={{ cursor: 'pointer', background: 'var(--bg-input)' }}
                    onClick={() => handleApplyExampleQuery(ex.query)}
                    title={ex.query}
                  >
                    {ex.label}
                  </button>
                ))}
                {savedQueries && savedQueries.length > 0 && (
                  <select
                    aria-label="Saved Queries"
                    className="select"
                    style={{ width: 'auto', padding: '2px 8px', fontSize: '11.5px' }}
                    value=""
                    onChange={(e) => {
                      if (e.target.value) handleApplyExampleQuery(e.target.value);
                    }}
                  >
                    <option value="">Saved Queries ({savedQueries.length})...</option>
                    {savedQueries.map((sq) => (
                      <option key={sq.id} value={sq.query}>
                        {sq.query}
                      </option>
                    ))}
                  </select>
                )}
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

              {/* Facet Filters Row */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(135px, 1fr))',
                  gap: '8px',
                  marginBottom: '14px',
                  padding: '10px',
                  backgroundColor: 'var(--bg-input)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)'
                }}
              >
                <div>
                  <label htmlFor="free-text-filter" className="label">Free-Text Search</label>
                  <input
                    id="free-text-filter"
                    type="search"
                    className="input"
                    placeholder="Keyword, hash, cmd..."
                    value={freeText}
                    onChange={(e) => {
                      setFreeText(e.target.value);
                      onUpdateInvestigation({
                        executedQueries: Array.from(
                          new Set([...(investigationState.executedQueries || []), `text:${e.target.value}`])
                        )
                      });
                    }}
                  />
                </div>

                <div>
                  <label htmlFor="source-select" className="label">Telemetry Source</label>
                  <select
                    id="source-select"
                    className="select"
                    value={sourceFilter}
                    onChange={(e) => setSourceFilter(e.target.value)}
                  >
                    <option value="all">All Sources</option>
                    {distinctSources.map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="severity-select" className="label">Severity</label>
                  <select
                    id="severity-select"
                    className="select"
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>

                <div>
                  <label htmlFor="eventtype-select" className="label">Event Type</label>
                  <select
                    id="eventtype-select"
                    className="select"
                    value={eventTypeFilter}
                    onChange={(e) => setEventTypeFilter(e.target.value)}
                  >
                    <option value="all">All Event Types</option>
                    {distinctEventTypes.map((et) => (
                      <option key={et} value={et}>{et}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="host-select" className="label">Host</label>
                  <select
                    id="host-select"
                    className="select"
                    value={hostFilter}
                    onChange={(e) => setHostFilter(e.target.value)}
                  >
                    <option value="all">All Hosts</option>
                    {distinctHosts.map((h) => (
                      <option key={h} value={h}>{h}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="user-select" className="label">Username</label>
                  <select
                    id="user-select"
                    className="select"
                    value={usernameFilter}
                    onChange={(e) => setUsernameFilter(e.target.value)}
                  >
                    <option value="all">All Users</option>
                    {distinctUsers.map((u) => (
                      <option key={u} value={u}>{u}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="ip-domain-filter" className="label">IP or Domain</label>
                  <input
                    id="ip-domain-filter"
                    type="text"
                    className="input mono"
                    placeholder="198.51.100... / .net"
                    value={ipDomainFilter}
                    onChange={(e) => setIpDomainFilter(e.target.value)}
                  />
                </div>

                <div>
                  <label htmlFor="sort-select" className="label">Sort Timestamp</label>
                  <select
                    id="sort-select"
                    className="select"
                    value={sortOrder}
                    onChange={(e) => setSortOrder(e.target.value)}
                  >
                    <option value="asc">Oldest First (Chronological)</option>
                    <option value="desc">Newest First</option>
                  </select>
                </div>
              </div>

              {/* Event Results Table */}
              {queryResult.events.length === 0 ? (
                <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                  No telemetry events matched the active query/filter criteria.
                </div>
              ) : (
                <div className="table-container">
                  <table className="event-table" aria-label="Security Telemetry Events">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Timestamp (UTC)</th>
                        <th>Source</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Host / User</th>
                        <th>Network / Process</th>
                        <th>Summary Message</th>
                        <th>Action</th>
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
                            <td className="mono" style={{ fontWeight: 600, color: isEvid ? 'var(--accent-cyan)' : 'inherit' }}>
                              {ev.eventId}
                              {isEvid && ' ★'}
                            </td>
                            <td className="mono" style={{ whiteSpace: 'nowrap' }}>
                              {formatTimestamp(ev.timestamp, false)}
                            </td>
                            <td className="mono">{ev.source}</td>
                            <td className="mono">{ev.eventType}</td>
                            <td>
                              <SeverityBadge severity={ev.severity} />
                            </td>
                            <td className="mono">
                              <div>{ev.host || '—'}</div>
                              <div style={{ color: 'var(--text-secondary)', fontSize: '11.5px' }}>
                                {ev.username || '—'}
                              </div>
                            </td>
                            <td className="mono" style={{ fontSize: '11.5px' }}>
                              {ev.processName && <div>proc: {ev.processName}</div>}
                              {ev.sourceIp && <div>src: {ev.sourceIp}</div>}
                              {ev.destinationIp && <div>dst: {ev.destinationIp}</div>}
                              {ev.domain && <div>dom: {ev.domain}</div>}
                            </td>
                            <td style={{ maxWidth: '320px' }}>{ev.message}</td>
                            <td onClick={(e) => e.stopPropagation()}>
                              <button
                                type="button"
                                className={`btn btn-sm ${isEvid ? 'btn-success' : ''}`}
                                onClick={() => handleAddEvidence(ev)}
                                disabled={isEvid}
                                aria-label={`Add ${ev.eventId} to Evidence`}
                              >
                                <PlusCircle size={12} />
                                <span>{isEvid ? 'Collected' : '+ Evidence'}</span>
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
                      placeholder="Filter entity in timeline..."
                      value={timelineEntityFilter}
                      onChange={(e) => setTimelineEntityFilter(e.target.value)}
                    />
                    <label style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '12px', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={timelineOnlyEvidence}
                        onChange={(e) => setTimelineOnlyEvidence(e.target.checked)}
                      />
                      <span>Evidence Only</span>
                    </label>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {timelineItems.map((item) => (
                    <div
                      key={item.eventId}
                      className="panel"
                      style={{
                        padding: '10px 12px',
                        backgroundColor: item.isEvidence ? 'var(--accent-cyan-dim)' : 'var(--bg-input)',
                        borderColor: item.isEvidence ? 'var(--accent-cyan)' : 'var(--border-subtle)',
                        cursor: 'pointer'
                      }}
                      onClick={() => setSelectedEventId(item.eventId)}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginBottom: '4px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span className="mono" style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>
                            #{item.timelineIndex} [{item.eventId}]
                          </span>
                          <span className="mono" style={{ fontSize: '12px' }}>
                            {formatTimestamp(item.timestamp)}
                          </span>
                          <span className="tag-chip">Δ prev: {item.deltaFromPrevious}</span>
                          <span className="tag-chip">Δ start: {item.deltaFromStart}</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          {item.isEvidence && <span className="sev-badge sev-safe">EVIDENCE COLLECTED</span>}
                          <SeverityBadge severity={item.severity} />
                        </div>
                      </div>
                      <div style={{ fontSize: '13px', marginBottom: '4px' }}>{item.message}</div>
                      <div className="mono" style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                        source={item.source} | type={item.eventType} | host={item.host || 'N/A'} | user={item.username || 'N/A'}
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              {/* Multi-Source Correlation Findings */}
              <section className="panel">
                <div className="panel-header">
                  <h2 className="panel-title">
                    <GitBranch size={15} color="var(--accent-cyan)" />
                    <span>Automated Cross-Source Correlation Analysis ({correlations.length})</span>
                  </h2>
                </div>
                <p style={{ margin: '0 0 12px 0', fontSize: '12.5px', color: 'var(--text-secondary)' }}>
                  Correlations are graded as <strong>CONFIRMED</strong> (explicit process lineage or telemetry link),{' '}
                  <strong>PROBABLE</strong> (shared external IOC or identity pivot across sources), or{' '}
                  <strong>WEAK</strong> (temporal proximity alone, which never proves causality on its own).
                </p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {correlations.map((corr) => (
                    <div key={corr.id} className="panel" style={{ backgroundColor: 'var(--bg-input)', padding: '10px 12px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <span className="mono" style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
                          {corr.sourceEventId} ➔ {corr.targetEventId} (Δ {corr.timeDeltaSeconds}s)
                        </span>
                        <SeverityBadge
                          severity={
                            corr.confidence === 'confirmed'
                              ? 'safe'
                              : corr.confidence === 'probable'
                              ? 'medium'
                              : 'low'
                          }
                          labelOverride={`CORRELATION: ${corr.confidence.toUpperCase()}`}
                        />
                      </div>
                      <div style={{ fontSize: '13px', color: 'var(--text-primary)' }}>{corr.rationale}</div>
                    </div>
                  ))}
                </div>
              </section>

              {/* Entity Relationship Explorer (SVG + Table) */}
              <section className="panel">
                <div className="panel-header">
                  <h2 className="panel-title">
                    <Database size={15} color="var(--accent-cyan)" />
                    <span>Entity Relationship Explorer ({entityGraph.nodes.length} Entities, {entityGraph.edges.length} Links)</span>
                  </h2>
                </div>

                {/* Lightweight SVG Relationship Map */}
                <div
                  style={{
                    backgroundColor: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '10px',
                    marginBottom: '12px',
                    overflowX: 'auto'
                  }}
                >
                  <svg width="680" height="220" viewBox="0 0 680 220" role="img" aria-label="Entity Relationship Graph">
                    {entityGraph.nodes.slice(0, 10).map((node, idx) => {
                      const col = idx % 5;
                      const row = Math.floor(idx / 5);
                      const cx = 75 + col * 130;
                      const cy = 55 + row * 110;
                      node._cx = cx;
                      node._cy = cy;
                      return null;
                    })}
                    {entityGraph.edges.map((edge) => {
                      const sNode = entityGraph.nodes.slice(0, 10).find((n) => n.id === edge.source);
                      const tNode = entityGraph.nodes.slice(0, 10).find((n) => n.id === edge.target);
                      if (!sNode || !tNode) return null;
                      return (
                        <line
                          key={edge.id}
                          x1={sNode._cx}
                          y1={sNode._cy}
                          x2={tNode._cx}
                          y2={tNode._cy}
                          stroke="rgba(34, 211, 238, 0.35)"
                          strokeWidth="1.5"
                        />
                      );
                    })}
                    {entityGraph.nodes.slice(0, 10).map((node) => (
                      <g key={node.id} transform={`translate(${node._cx}, ${node._cy})`}>
                        <circle
                          r="20"
                          fill={node.hasEvidence ? 'rgba(34, 211, 238, 0.25)' : '#162133'}
                          stroke={node.hasEvidence ? '#22d3ee' : '#475569'}
                          strokeWidth="2"
                        />
                        <text
                          y="-26"
                          textAnchor="middle"
                          fill="#94a3b8"
                          fontSize="9.5"
                          fontFamily="JetBrains Mono, monospace"
                        >
                          {node.type.toUpperCase()}
                        </text>
                        <text
                          y="4"
                          textAnchor="middle"
                          fill="#f1f5f9"
                          fontSize="10"
                          fontFamily="JetBrains Mono, monospace"
                        >
                          {node.label.length > 14 ? node.label.slice(0, 12) + '..' : node.label}
                        </text>
                      </g>
                    ))}
                  </svg>
                </div>

                <div className="table-container">
                  <table className="event-table">
                    <thead>
                      <tr>
                        <th>Source Entity</th>
                        <th>Relationship</th>
                        <th>Target Entity</th>
                        <th>Confidence</th>
                        <th>Supporting Events</th>
                      </tr>
                    </thead>
                    <tbody>
                      {entityGraph.edges.map((edge) => (
                        <tr key={edge.id}>
                          <td className="mono">{edge.source}</td>
                          <td className="mono" style={{ color: 'var(--accent-cyan)' }}>{edge.relation}</td>
                          <td className="mono">{edge.target}</td>
                          <td className="mono">{edge.confidence.toUpperCase()}</td>
                          <td className="mono">{edge.eventIds.join(', ')}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </div>
          )}

          {/* TAB 3: DETECTION ENGINE & MITRE ATT&CK */}
          {activeTab === 'detections' && (
            <section className="panel">
              <div className="panel-header">
                <h2 className="panel-title">
                  <Cpu size={15} color="var(--accent-cyan)" />
                  <span>SOC Detection Rule Engine &amp; ATT&amp;CK Attribution</span>
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

              <p style={{ margin: '0 0 14px 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
                Evaluating detection rules identifies candidate alerts across the dataset. Remember: a triggered rule is an{' '}
                <strong>alert hypothesis</strong>, not automatic proof of a breach. Always review the{' '}
                <em>False-Positive Considerations</em> before taking containment actions.
              </p>

              {!investigationState.ranDetections ? (
                <div className="panel" style={{ backgroundColor: 'var(--bg-input)', textAlign: 'center', padding: '24px' }}>
                  <p style={{ margin: '0 0 12px 0', color: 'var(--text-secondary)' }}>
                    Click <strong>Execute All {DETECTION_RULES.length} Detection Rules</strong> to evaluate threshold, sequence, and single-event detections against this scenario’s telemetry.
                  </p>
                  <button type="button" className="btn btn-primary" onClick={handleExecuteDetections}>
                    Run Detection Rules Now
                  </button>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
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
                        <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                          <span className="tag-chip">ALERT (UNCONFIRMED)</span>
                          <SeverityBadge severity={finding.severity} />
                        </div>
                      </div>

                      <div style={{ fontSize: '13px', marginBottom: '8px' }}>
                        <strong>Why Triggered:</strong> {finding.whyTriggered}
                      </div>

                      <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                        <strong>False-Positive Considerations:</strong> {finding.falsePositiveConsiderations}
                      </div>

                      <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginBottom: '10px' }}>
                        <strong>Remediation Guidance:</strong> {finding.remediationGuidance}
                      </div>

                      {/* MITRE ATT&CK Mappings */}
                      {finding.attackMappings && finding.attackMappings.length > 0 && (
                        <div style={{ marginBottom: '10px', padding: '8px 10px', backgroundColor: 'var(--bg-panel)', borderRadius: 'var(--radius-sm)' }}>
                          <div style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--accent-cyan)', marginBottom: '4px' }}>
                            MITRE ATT&amp;CK Mappings ({finding.attackMappings[0].version}):
                          </div>
                          {finding.attackMappings.map((m) => {
                            const hasSupportingEvidence = finding.matchedEventIds.some((id) =>
                              evidence.some((ev) => ev.targetId === id)
                            );
                            return (
                              <div key={m.techniqueId} style={{ fontSize: '12px', marginBottom: '4px' }}>
                                <span className="mono" style={{ fontWeight: 600 }}>{m.techniqueId}</span> — {m.techniqueName} ({m.tactic}) •{' '}
                                <span className="tag-chip">
                                  Status: {hasSupportingEvidence ? 'SUPPORTED BY COLLECTED EVIDENCE' : 'SUSPECTED FROM ALERT'}
                                </span>
                                <div style={{ color: 'var(--text-secondary)', marginTop: '2px' }}>{m.rationale}</div>
                              </div>
                            );
                          })}
                        </div>
                      )}

                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', alignItems: 'center' }}>
                        <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Matched Events:</span>
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

          {/* TAB 4: SIMULATED RESPONSE & CONTAINMENT CONSOLE */}
          {activeTab === 'response' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <section className="panel">
                <div className="panel-header">
                  <h2 className="panel-title">
                    <Shield size={15} color="var(--accent-cyan)" />
                    <span>Simulated Incident Containment &amp; Disposition Console</span>
                  </h2>
                  <span className="sim-badge">SIMULATION ONLY — NO REAL INFRASTRUCTURE ALTERED</span>
                </div>

                <p style={{ margin: '0 0 14px 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
                  Select proportionate defensive actions based on your collected evidence. Warning: executing intrusive containment
                  (isolating hosts, disabling accounts, blocking IPs) before collecting at least 2 supporting evidence records—or
                  targeting benign assets—will incur a Response Appropriateness penalty.
                </p>

                <form onSubmit={handleExecuteResponseAction} className="panel" style={{ backgroundColor: 'var(--bg-input)', marginBottom: '16px' }}>
                  <div className="grid-2" style={{ marginBottom: '12px' }}>
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
                            [{item.category}] {item.label} {item.intrusive ? '(Intrusive)' : '(Non-Intrusive)'}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <label htmlFor="response-target-input" className="label">Target Entity (Host, Account, IP, Domain, File)</label>
                      <input
                        id="response-target-input"
                        type="text"
                        className="input mono"
                        placeholder={
                          RESPONSE_CATALOG.find((c) => c.actionType === selectedActionType)?.targetPlaceholder ||
                          'Target entity...'
                        }
                        value={responseTarget}
                        onChange={(e) => setResponseTarget(e.target.value)}
                      />
                    </div>
                  </div>

                  {/* Quick-fill entity chips */}
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '12px', alignItems: 'center' }}>
                    <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Quick-fill Target from Scenario:</span>
                    {allQuickEntities.map((ent) => (
                      <button
                        key={ent}
                        type="button"
                        className="tag-chip"
                        style={{ cursor: 'pointer' }}
                        onClick={() => setResponseTarget(ent)}
                      >
                        {ent}
                      </button>
                    ))}
                  </div>

                  <div style={{ marginBottom: '12px' }}>
                    <label htmlFor="response-justification-input" className="label">Analyst Justification</label>
                    <input
                      id="response-justification-input"
                      type="text"
                      className="input"
                      placeholder="Explain why this containment or disposition action is justified by your collected evidence..."
                      value={responseJustification}
                      onChange={(e) => setResponseJustification(e.target.value)}
                    />
                  </div>

                  <button type="submit" className="btn btn-primary">
                    <Shield size={14} />
                    <span>Execute Simulated Action</span>
                  </button>
                </form>

                {/* Executed Response Action Log */}
                <h3 style={{ margin: '0 0 8px 0', fontSize: '13.5px', textTransform: 'uppercase' }}>
                  Executed Response Log ({responseActions.length})
                </h3>
                {responseActions.length === 0 ? (
                  <div style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
                    No response actions executed yet.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {responseActions.map((act) => (
                      <div key={act.actionId} className="panel" style={{ backgroundColor: 'var(--bg-input)', padding: '10px 12px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <div>
                            <strong>{act.label}</strong> ➔ <span className="mono">{act.target}</span>
                          </div>
                          <SeverityBadge
                            severity={
                              act.evaluation === 'appropriate'
                                ? 'safe'
                                : act.evaluation === 'premature'
                                ? 'medium'
                                : 'critical'
                            }
                            labelOverride={act.evaluation.toUpperCase()}
                          />
                        </div>
                        <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>{act.consequenceText}</div>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            </div>
          )}

          {/* TAB 5: INCIDENT ASSESSMENT & REPORT SUBMISSION */}
          {activeTab === 'assessment' && (
            <section className="panel">
              <div className="panel-header">
                <h2 className="panel-title">
                  <FileCheck size={15} color="var(--accent-cyan)" />
                  <span>Final Incident Assessment &amp; Report Submission</span>
                </h2>
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
                    placeholder="e.g. WKSTN-FIN-04, m.chen, 198.51.100.24, cdn-telemetry-sync.example.net"
                    value={assessment.affectedEntity || ''}
                    onChange={(e) => handleUpdateAssessmentField('affectedEntity', e.target.value)}
                  />
                </div>

                <div>
                  <span className="label">5. Observed MITRE ATT&amp;CK Techniques (leave unchecked if Benign)</span>
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))',
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
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px',
                            fontSize: '12px',
                            cursor: 'pointer'
                          }}
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
                    placeholder="Summarize what happened chronologically, referencing the evidence events you collected..."
                    value={assessment.keyFindings || ''}
                    onChange={(e) => handleUpdateAssessmentField('keyFindings', e.target.value)}
                  />
                </div>

                <div className="grid-3">
                  <div>
                    <label htmlFor="assess-scope" className="label">7. Scope &amp; Business Impact</label>
                    <textarea
                      id="assess-scope"
                      rows={2}
                      className="textarea"
                      placeholder="List all scoped hosts, accounts, and potential data impact..."
                      value={assessment.scopeSummary || ''}
                      onChange={(e) => handleUpdateAssessmentField('scopeSummary', e.target.value)}
                    />
                  </div>

                  <div>
                    <label htmlFor="assess-uncertainty" className="label">8. Remaining Uncertainty</label>
                    <textarea
                      id="assess-uncertainty"
                      rows={2}
                      className="textarea"
                      placeholder="Note any blind spots or unverified assumptions..."
                      value={assessment.remainingUncertainty || ''}
                      onChange={(e) => handleUpdateAssessmentField('remainingUncertainty', e.target.value)}
                    />
                  </div>

                  <div>
                    <label htmlFor="assess-followup" className="label">9. Recommended Follow-Up</label>
                    <textarea
                      id="assess-followup"
                      rows={2}
                      className="textarea"
                      placeholder="Long-term hardening, MFA enforcement, or forensic re-imaging..."
                      value={assessment.recommendedFollowUp || ''}
                      onChange={(e) => handleUpdateAssessmentField('recommendedFollowUp', e.target.value)}
                    />
                  </div>
                </div>

                <div
                  style={{
                    padding: '12px',
                    backgroundColor: 'var(--bg-input)',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: '12px'
                  }}
                >
                  <div style={{ fontSize: '12.5px', color: readiness.ready ? 'var(--status-safe)' : 'var(--text-secondary)' }}>
                    {readiness.ready
                      ? '✓ All mandatory evidence, response, and assessment requirements are met.'
                      : `Pending before submission: ${readiness.missing.join(' • ')}`}
                  </div>
                  <button type="submit" className="btn btn-primary" style={{ padding: '9px 18px' }}>
                    <FileCheck size={15} />
                    <span>Submit Final Report &amp; View Debrief</span>
                  </button>
                </div>
              </form>
            </section>
          )}
        </div>

        {/* Right Persistent Dock: Event Inspector, Evidence Locker & Objectives */}
        <aside style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {/* Selected Event Inspector */}
          <section className="panel">
            <div className="panel-header">
              <h2 className="panel-title">
                <Eye size={15} color="var(--accent-cyan)" />
                <span>Event &amp; Entity Inspector</span>
              </h2>
              {selectedEvent && <SeverityBadge severity={selectedEvent.severity} />}
            </div>

            {!selectedEvent ? (
              <div style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
                Select any event row to inspect its structured fields and pivot across entities.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span className="mono" style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>
                    {selectedEvent.eventId}
                  </span>
                  <span className="mono" style={{ color: 'var(--text-secondary)' }}>
                    {formatTimestamp(selectedEvent.timestamp)}
                  </span>
                </div>

                <div style={{ padding: '8px', backgroundColor: 'var(--bg-input)', borderRadius: 'var(--radius-sm)' }}>
                  {selectedEvent.message}
                </div>

                <div className="mono" style={{ display: 'grid', gridTemplateColumns: '110px 1fr', gap: '4px', fontSize: '12px' }}>
                  <span style={{ color: 'var(--text-muted)' }}>source:</span>
                  <span>{selectedEvent.source || 'Unavailable'}</span>

                  <span style={{ color: 'var(--text-muted)' }}>eventType:</span>
                  <span>{selectedEvent.eventType || 'Unavailable'}</span>

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
                  <span>
                    {selectedEvent.sourceIp ? (
                      <button
                        type="button"
                        className="tag-chip"
                        style={{ cursor: 'pointer', color: 'var(--accent-cyan)' }}
                        onClick={() => handlePivotEntity('sourceIp', selectedEvent.sourceIp)}
                      >
                        {selectedEvent.sourceIp} ⌕
                      </button>
                    ) : (
                      'Unavailable'
                    )}
                  </span>

                  <span style={{ color: 'var(--text-muted)' }}>destinationIp:</span>
                  <span>
                    {selectedEvent.destinationIp ? (
                      <button
                        type="button"
                        className="tag-chip"
                        style={{ cursor: 'pointer', color: 'var(--accent-cyan)' }}
                        onClick={() => handlePivotEntity('destinationIp', selectedEvent.destinationIp)}
                      >
                        {selectedEvent.destinationIp} ⌕
                      </button>
                    ) : (
                      'Unavailable'
                    )}
                  </span>

                  <span style={{ color: 'var(--text-muted)' }}>domain:</span>
                  <span>
                    {selectedEvent.domain ? (
                      <button
                        type="button"
                        className="tag-chip"
                        style={{ cursor: 'pointer', color: 'var(--accent-cyan)' }}
                        onClick={() => handlePivotEntity('domain', selectedEvent.domain)}
                      >
                        {selectedEvent.domain} ⌕
                      </button>
                    ) : (
                      'Unavailable'
                    )}
                  </span>

                  <span style={{ color: 'var(--text-muted)' }}>processName:</span>
                  <span>{selectedEvent.processName || 'Unavailable'}</span>

                  <span style={{ color: 'var(--text-muted)' }}>parentProcess:</span>
                  <span>{selectedEvent.parentProcess || 'Unavailable'}</span>

                  <span style={{ color: 'var(--text-muted)' }}>action / result:</span>
                  <span>
                    {selectedEvent.action || '—'} / {selectedEvent.result || '—'}
                  </span>
                </div>

                {selectedEvent.commandLine && (
                  <div>
                    <span className="label">Simulated Command Line (Safe Text Only)</span>
                    <div
                      className="mono"
                      style={{
                        padding: '6px 8px',
                        backgroundColor: 'var(--bg-input)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '11.5px',
                        wordBreak: 'break-all'
                      }}
                    >
                      {selectedEvent.commandLine}
                    </div>
                  </div>
                )}

                {selectedEvent.metadata && (
                  <div>
                    <span className="label">Structured Metadata</span>
                    <pre
                      className="mono"
                      style={{
                        margin: 0,
                        padding: '6px 8px',
                        backgroundColor: 'var(--bg-input)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '11px',
                        overflowX: 'auto'
                      }}
                    >
                      {JSON.stringify(selectedEvent.metadata, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Add to Evidence Subform */}
                <div style={{ paddingTop: '8px', borderTop: '1px solid var(--border-subtle)' }}>
                  <div style={{ display: 'flex', gap: '6px', marginBottom: '6px' }}>
                    <select
                      aria-label="Evidence Hypothesis Alignment"
                      className="select"
                      value={evidenceAlignment}
                      onChange={(e) => setEvidenceAlignment(e.target.value)}
                    >
                      <option value="supports">Supports Hypothesis</option>
                      <option value="contradicts">Contradicts / Rules Out Threat</option>
                    </select>
                  </div>
                  <input
                    type="text"
                    className="input"
                    style={{ marginBottom: '6px' }}
                    placeholder="Analyst note on why this event matters..."
                    value={evidenceNote}
                    onChange={(e) => setEvidenceNote(e.target.value)}
                  />
                  <button
                    type="button"
                    className="btn btn-primary"
                    style={{ width: '100%' }}
                    onClick={() => handleAddEvidence(selectedEvent)}
                    disabled={evidence.some((e) => e.targetId === selectedEvent.eventId)}
                  >
                    <PlusCircle size={14} />
                    <span>
                      {evidence.some((e) => e.targetId === selectedEvent.eventId)
                        ? `Already in Evidence Locker (${selectedEvent.eventId})`
                        : `Collect ${selectedEvent.eventId} as Evidence`}
                    </span>
                  </button>
                </div>
              </div>
            )}
          </section>

          {/* Collected Evidence Locker */}
          <section className="panel">
            <div className="panel-header">
              <h2 className="panel-title">
                <Bookmark size={15} color="var(--accent-cyan)" />
                <span>Evidence Locker ({evidence.length})</span>
              </h2>
            </div>

            {evidence.length === 0 ? (
              <div style={{ color: 'var(--text-secondary)', fontSize: '12.5px' }}>
                No evidence collected yet. Mark relevant events in the Event Explorer to support your investigation.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {evidence.map((item) => (
                  <div
                    key={item.evidenceId}
                    className="panel"
                    style={{ padding: '8px 10px', backgroundColor: 'var(--bg-input)' }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <button
                        type="button"
                        className="mono"
                        style={{
                          background: 'none',
                          border: 'none',
                          padding: 0,
                          color: 'var(--accent-cyan)',
                          fontWeight: 700,
                          cursor: 'pointer'
                        }}
                        onClick={() => setSelectedEventId(item.targetId)}
                      >
                        {item.targetId}
                      </button>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span className="tag-chip">{item.alignment}</span>
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => handleRemoveEvidence(item.targetId)}
                          aria-label={`Remove ${item.targetId} from evidence`}
                          title="Remove from evidence locker (does not delete underlying event)"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-primary)', marginTop: '2px' }}>
                      {item.summary}
                    </div>
                    <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>{item.note}</div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* Mission Objectives Checklist & Notes */}
          <section className="panel">
            <div className="panel-header">
              <h2 className="panel-title">
                <CheckCircle2 size={15} color="var(--accent-cyan)" />
                <span>Objectives &amp; Scratchpad</span>
              </h2>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '12px' }}>
              {objectives.map((obj) => (
                <div key={obj.id} style={{ display: 'flex', alignItems: 'flex-start', gap: '7px', fontSize: '12px' }}>
                  {obj.completed ? (
                    <CheckCircle2 size={14} color="var(--status-safe)" style={{ flexShrink: 0, marginTop: '2px' }} />
                  ) : (
                    <Circle size={14} color="var(--text-muted)" style={{ flexShrink: 0, marginTop: '2px' }} />
                  )}
                  <span style={{ color: obj.completed ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                    {obj.title}
                  </span>
                </div>
              ))}
            </div>

            <label htmlFor="analyst-scratchpad" className="label">Investigation Scratchpad Notes</label>
            <textarea
              id="analyst-scratchpad"
              rows={3}
              className="textarea"
              placeholder="Jot down IPs, timestamps, or hypotheses during your investigation..."
              value={investigationState.notes || ''}
              onChange={(e) => onUpdateInvestigation({ notes: e.target.value })}
            />
          </section>
        </aside>
      </div>
    </div>
  );
}
