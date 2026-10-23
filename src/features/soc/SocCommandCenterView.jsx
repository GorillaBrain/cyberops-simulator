import React from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Circle,
  Cpu,
  FileSearch,
  Play,
  Radio,
  ShieldAlert
} from 'lucide-react';
import { SeverityBadge } from '../../components/SeverityBadge.jsx';
import { evaluateMissionObjectives } from '../../engine/missionStateMachine.js';
import { formatTimestamp } from '../../utils/eventSchema.js';

export function SocCommandCenterView({
  missions,
  currentMission,
  investigationState,
  profile,
  onSelectMission,
  onOpenWorkstation,
  onOpenBriefing
}) {
  const events = currentMission?.events || [];
  const objectives = evaluateMissionObjectives(currentMission, investigationState);
  const completedObj = objectives.filter((o) => o.completed).length;

  const severityCounts = {
    critical: events.filter((e) => e.severity === 'critical').length,
    high: events.filter((e) => e.severity === 'high').length,
    medium: events.filter((e) => e.severity === 'medium').length,
    low: events.filter((e) => e.severity === 'low').length
  };

  const incState = investigationState?.incidentState || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
      {/* Top Operational Status Header */}
      <section className="panel-elevated">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <span className="sim-badge">SOC COMMAND CENTER — SIMULATION MODE</span>
              <span className="mono" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                Active Case: {currentMission.id}
              </span>
            </div>
            <h1 style={{ margin: '0 0 4px 0', fontSize: '20px' }}>{currentMission.title}</h1>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
              {currentMission.organization} • {currentMission.environment}
            </div>
          </div>

          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <button type="button" className="btn" onClick={onOpenBriefing}>
              <FileSearch size={15} />
              <span>Mission Briefing</span>
            </button>
            <button type="button" className="btn btn-primary" onClick={onOpenWorkstation}>
              <Play size={15} />
              <span>Open Investigation Workstation</span>
            </button>
          </div>
        </div>
      </section>

      {/* 4 Telemetry & Incident Status Cards */}
      <div className="grid-4">
        <div className="panel">
          <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            Simulated Incident State
          </div>
          <div className="mono" style={{ fontSize: '16px', fontWeight: 700, color: 'var(--accent-cyan)', margin: '6px 0' }}>
            {(incState.threatStatus || 'active_uncontained').replace(/_/g, ' ').toUpperCase()}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Containment Progress: {incState.containmentProgress || 0}%
          </div>
        </div>

        <div className="panel">
          <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            Mission Objectives
          </div>
          <div className="mono" style={{ fontSize: '18px', fontWeight: 700, margin: '6px 0' }}>
            {completedObj} / {objectives.length} Completed
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            {objectives.length - completedObj} remaining before final assessment
          </div>
        </div>

        <div className="panel">
          <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            Evidence Locker &amp; Queries
          </div>
          <div className="mono" style={{ fontSize: '18px', fontWeight: 700, margin: '6px 0' }}>
            {(investigationState?.evidence || []).length} Evidence Items
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            {(investigationState?.executedQueries || []).length} structured queries executed
          </div>
        </div>

        <div className="panel">
          <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            Current Case Telemetry
          </div>
          <div className="mono" style={{ fontSize: '18px', fontWeight: 700, margin: '6px 0' }}>
            {events.length} Structured Events
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            {currentMission.briefing.telemetrySources.length} active sensor feeds
          </div>
        </div>
      </div>

      {/* Main Grid: Active Incident Queue & Objectives + Severity Distribution */}
      <div className="grid-2">
        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <ShieldAlert size={15} color="var(--accent-cyan)" />
              <span>SOC Incident Alert Queue (Campaign Scenarios)</span>
            </h2>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {missions.map((m) => {
              const isCurrent = m.id === currentMission.id;
              const isDone = Boolean(profile.completedMissions?.[m.id]);
              return (
                <div
                  key={m.id}
                  className="panel"
                  style={{
                    padding: '10px 12px',
                    backgroundColor: isCurrent ? 'var(--accent-cyan-dim)' : 'var(--bg-input)',
                    borderColor: isCurrent ? 'var(--accent-cyan)' : 'var(--border-subtle)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: '10px'
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                      <span className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        {m.briefing.initialAlert.alertId}
                      </span>
                      <SeverityBadge severity={m.briefing.initialAlert.severity} />
                      {isDone && <span className="tag-chip">RESOLVED ({profile.completedMissions[m.id].bestGrade})</span>}
                    </div>
                    <div style={{ fontWeight: 600, fontSize: '13.5px' }}>{m.title}</div>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                      {m.briefing.initialAlert.title}
                    </div>
                  </div>
                  <button
                    type="button"
                    className={`btn btn-sm ${isCurrent ? 'btn-primary' : ''}`}
                    onClick={() => onSelectMission(m.id)}
                  >
                    {isCurrent ? 'Investigate' : 'Switch Case'}
                  </button>
                </div>
              );
            })}
          </div>
        </section>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Current Mission Objectives */}
          <section className="panel">
            <div className="panel-header">
              <h2 className="panel-title">
                <Activity size={15} color="var(--accent-cyan)" />
                <span>Active Case Objectives ({currentMission.title})</span>
              </h2>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {objectives.map((obj) => (
                <div
                  key={obj.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '9px',
                    padding: '8px 10px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)'
                  }}
                >
                  {obj.completed ? (
                    <CheckCircle2 size={16} color="var(--status-safe)" />
                  ) : (
                    <Circle size={16} color="var(--text-muted)" />
                  )}
                  <span
                    style={{
                      fontSize: '13px',
                      color: obj.completed ? 'var(--text-primary)' : 'var(--text-secondary)',
                      textDecoration: obj.completed ? 'line-through' : 'none'
                    }}
                  >
                    {obj.title}
                  </span>
                </div>
              ))}
            </div>
          </section>

          {/* Alert Severity Distribution & Simulated System Status */}
          <section className="panel">
            <div className="panel-header">
              <h2 className="panel-title">
                <Cpu size={15} color="var(--accent-cyan)" />
                <span>Case Telemetry Severity &amp; Sensor Health</span>
              </h2>
            </div>

            <div className="grid-4" style={{ marginBottom: '14px' }}>
              <div className="panel" style={{ backgroundColor: 'var(--bg-input)', padding: '10px' }}>
                <SeverityBadge severity="critical" />
                <div className="mono" style={{ fontSize: '18px', fontWeight: 700, marginTop: '6px' }}>
                  {severityCounts.critical}
                </div>
              </div>
              <div className="panel" style={{ backgroundColor: 'var(--bg-input)', padding: '10px' }}>
                <SeverityBadge severity="high" />
                <div className="mono" style={{ fontSize: '18px', fontWeight: 700, marginTop: '6px' }}>
                  {severityCounts.high}
                </div>
              </div>
              <div className="panel" style={{ backgroundColor: 'var(--bg-input)', padding: '10px' }}>
                <SeverityBadge severity="medium" />
                <div className="mono" style={{ fontSize: '18px', fontWeight: 700, marginTop: '6px' }}>
                  {severityCounts.medium}
                </div>
              </div>
              <div className="panel" style={{ backgroundColor: 'var(--bg-input)', padding: '10px' }}>
                <SeverityBadge severity="low" />
                <div className="mono" style={{ fontSize: '18px', fontWeight: 700, marginTop: '6px' }}>
                  {severityCounts.low}
                </div>
              </div>
            </div>

            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>
              Active Telemetry Collectors for {currentMission.title}:
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {currentMission.briefing.telemetrySources.map((src) => (
                <span key={src} className="sim-badge">
                  <Radio size={11} />
                  <span>{src}: ONLINE</span>
                </span>
              ))}
            </div>
          </section>
        </div>
      </div>

      {/* Recent Security Events Preview */}
      <section className="panel">
        <div className="panel-header">
          <h2 className="panel-title">
            <AlertTriangle size={15} color="var(--accent-cyan)" />
            <span>Recent Security Events in Current Scenario ({currentMission.title})</span>
          </h2>
          <button type="button" className="btn btn-sm btn-primary" onClick={onOpenWorkstation}>
            Inspect Full Telemetry in Workstation
          </button>
        </div>

        <div className="table-container">
          <table className="event-table">
            <thead>
              <tr>
                <th>Event ID</th>
                <th>Timestamp</th>
                <th>Source</th>
                <th>Severity</th>
                <th>Host / User</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {events.slice(0, 6).map((ev) => (
                <tr key={ev.eventId}>
                  <td className="mono">{ev.eventId}</td>
                  <td className="mono">{formatTimestamp(ev.timestamp, false)}</td>
                  <td className="mono">{ev.source}</td>
                  <td>
                    <SeverityBadge severity={ev.severity} />
                  </td>
                  <td className="mono">
                    {ev.host || '—'} / {ev.username || '—'}
                  </td>
                  <td>{ev.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
