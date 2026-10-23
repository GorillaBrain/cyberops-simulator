import React from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Clock,
  Database,
  HelpCircle,
  Play,
  ShieldAlert,
  Target
} from 'lucide-react';
import { SeverityBadge } from '../../components/SeverityBadge.jsx';

export function MissionBriefingView({
  mission,
  onStartInvestigation,
  onBackToMenu
}) {
  if (!mission) return null;
  const { briefing } = mission;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '18px', maxWidth: '1100px', margin: '0 auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
        <button type="button" className="btn btn-sm" onClick={onBackToMenu}>
          <ArrowLeft size={14} />
          <span>Back to Mission Catalogue</span>
        </button>
        <span className="sim-badge">OPERATIONAL MISSION BRIEFING</span>
      </div>

      {/* Header Card */}
      <section className="panel-elevated" style={{ padding: '22px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div className="mono" style={{ fontSize: '12px', color: 'var(--accent-cyan)', marginBottom: '4px' }}>
              {mission.difficulty.toUpperCase()} DIFFICULTY • EST. {mission.estimatedMinutes} MIN • REWARD: {mission.xpReward} XP
            </div>
            <h1 style={{ margin: '0 0 6px 0', fontSize: '24px' }}>{mission.title}</h1>
            <div style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '12px' }}>
              <strong>Organization:</strong> {mission.organization} | <strong>Environment:</strong> {mission.environment}
            </div>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.6, color: 'var(--text-primary)' }}>
              {briefing.summary}
            </p>
          </div>

          <button
            type="button"
            className="btn btn-primary"
            style={{ padding: '10px 18px', fontSize: '14px' }}
            onClick={onStartInvestigation}
          >
            <Play size={16} />
            <span>Begin Investigation</span>
          </button>
        </div>
      </section>

      {/* Initial Triggered Alert */}
      <section className="panel" style={{ borderLeft: '4px solid var(--accent-cyan)' }}>
        <div className="panel-header">
          <h2 className="panel-title">
            <ShieldAlert size={16} color="var(--accent-cyan)" />
            <span>Initial SIEM Alert Dispatch</span>
          </h2>
          <SeverityBadge severity={briefing.initialAlert.severity} />
        </div>
        <div className="grid-3">
          <div>
            <span className="label">Alert ID &amp; Rule</span>
            <div className="mono" style={{ fontWeight: 600 }}>
              {briefing.initialAlert.alertId} — {briefing.initialAlert.title}
            </div>
          </div>
          <div>
            <span className="label">Triggered Timestamp</span>
            <div className="mono">{briefing.initialAlert.triggeredAt}</div>
          </div>
          <div>
            <span className="label">Primary Flagged Entity</span>
            <div className="mono" style={{ color: 'var(--accent-cyan)' }}>{briefing.initialAlert.entity}</div>
          </div>
        </div>
      </section>

      {/* Known Facts & Unknowns */}
      <div className="grid-2">
        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <CheckCircle2 size={15} color="var(--status-safe)" />
              <span>Known Operational Facts</span>
            </h2>
          </div>
          <ul style={{ margin: 0, paddingLeft: '18px', display: 'flex', flexDirection: 'column', gap: '8px', color: 'var(--text-secondary)' }}>
            {briefing.knownFacts.map((fact, i) => (
              <li key={i}>{fact}</li>
            ))}
          </ul>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <HelpCircle size={15} color="var(--sev-medium)" />
              <span>Investigative Unknowns (Questions to Answer)</span>
            </h2>
          </div>
          <ul style={{ margin: 0, paddingLeft: '18px', display: 'flex', flexDirection: 'column', gap: '8px', color: 'var(--text-secondary)' }}>
            {briefing.unknowns.map((unk, i) => (
              <li key={i}>{unk}</li>
            ))}
          </ul>
        </section>
      </div>

      {/* Mission Objectives & Telemetry Sources */}
      <div className="grid-2">
        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <Target size={15} color="var(--accent-cyan)" />
              <span>Mission Objectives</span>
            </h2>
          </div>
          <ol style={{ margin: 0, paddingLeft: '18px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {mission.objectives.map((obj) => (
              <li key={obj.id} style={{ color: 'var(--text-primary)' }}>
                {obj.title}
              </li>
            ))}
          </ol>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <Database size={15} color="var(--accent-cyan)" />
              <span>Available Telemetry &amp; Operational Risk</span>
            </h2>
          </div>
          <div style={{ marginBottom: '12px' }}>
            <span className="label">Telemetry Feeds ({briefing.telemetrySources.length})</span>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '4px' }}>
              {briefing.telemetrySources.map((src) => (
                <span key={src} className="tag-chip">
                  {src}
                </span>
              ))}
            </div>
          </div>

          <div style={{ marginBottom: '12px' }}>
            <span className="label">Simulated Time Window</span>
            <div className="mono" style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12.5px' }}>
              <Clock size={13} />
              <span>{briefing.timeWindow}</span>
            </div>
          </div>

          <div
            style={{
              padding: '10px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.35)',
              fontSize: '12.5px',
              color: '#fde047'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, marginBottom: '3px' }}>
              <AlertTriangle size={14} />
              <span>Consequences of Poor Decisions</span>
            </div>
            <div>{briefing.consequencesOfPoorDecisions}</div>
          </div>
        </section>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
        <button type="button" className="btn" onClick={onBackToMenu}>
          Return to Mission List
        </button>
        <button type="button" className="btn btn-primary" onClick={onStartInvestigation}>
          <Play size={15} />
          <span>Launch Investigation Workstation</span>
        </button>
      </div>
    </div>
  );
}
