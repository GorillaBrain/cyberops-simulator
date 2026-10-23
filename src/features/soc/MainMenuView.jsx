import React from 'react';
import {
  Shield,
  Play,
  Award,
  CheckCircle2,
  Lock,
  Calendar,
  Compass,
  Clock,
  Terminal,
  BookOpen,
  Settings,
  RotateCcw
} from 'lucide-react';
import { getRankForXp, ACHIEVEMENTS } from '../../engine/progressionEngine.js';
import { getDailyChallengeInfo } from '../../data/missions/extraModes.js';
import { SeverityBadge } from '../../components/SeverityBadge.jsx';

export function MainMenuView({
  profile,
  missions,
  onSelectMission,
  onContinueMission,
  onNavigate,
  onOpenGlossary
}) {
  const rank = getRankForXp(profile.xp);
  const completedCount = Object.keys(profile.completedMissions || {}).length;
  const daily = getDailyChallengeInfo();

  const activeMission = missions.find((m) => m.id === profile.activeMissionId) || missions[0];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Hero Banner */}
      <section className="panel-elevated" style={{ padding: '24px' }}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            flexWrap: 'wrap',
            gap: '20px'
          }}
        >
          <div style={{ maxWidth: '680px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <span className="sim-badge">SIMULATED TRAINING ENVIRONMENT</span>
              <span className="tag-chip">v1.0.0</span>
            </div>
            <h1 style={{ margin: '0 0 8px 0', fontSize: '26px', fontWeight: 700, letterSpacing: '-0.01em' }}>
              CyberOps Simulator
            </h1>
            <p style={{ margin: '0 0 18px 0', fontSize: '15px', color: 'var(--accent-cyan)', fontWeight: 500 }}>
              Detect the signal. Investigate the evidence. Stop the threat.
            </p>
            <p style={{ margin: '0 0 20px 0', color: 'var(--text-secondary)', fontSize: '13.5px' }}>
              Step into the Security Operations Center at Aegis BioLabs. Triage incoming telemetry alerts,
              execute structured queries across authentication, endpoint, DNS, and proxy logs, build an
              evidentiary timeline, map adversary techniques to MITRE ATT&amp;CK, and execute proportionate
              containment.
            </p>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px' }}>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => onContinueMission(activeMission.id)}
              >
                <Play size={15} />
                <span>
                  {profile.activeMissionId
                    ? `Continue: ${activeMission.title}`
                    : completedCount === 0
                    ? 'Start Tutorial: Mission 1'
                    : `Launch ${activeMission.title}`}
                </span>
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => onNavigate('soc_center')}
              >
                <Compass size={15} />
                <span>Open SOC Command Center</span>
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => onNavigate('extra_modes')}
              >
                <Terminal size={15} />
                <span>Practice Lab &amp; Endless Triage</span>
              </button>
              <button
                type="button"
                className="btn"
                onClick={onOpenGlossary}
              >
                <BookOpen size={15} />
                <span>SOC Field Glossary</span>
              </button>
            </div>
          </div>

          {/* Analyst Rank Summary Card */}
          <div
            className="panel"
            style={{
              minWidth: '280px',
              flex: '0 1 320px',
              backgroundColor: 'var(--bg-input)'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                Analyst Dossier
              </span>
              <span className="mono" style={{ fontSize: '12px', color: rank.badgeColor, fontWeight: 600 }}>
                LVL {rank.level}
              </span>
            </div>
            <div style={{ fontSize: '19px', fontWeight: 700, color: rank.badgeColor, marginBottom: '4px' }}>
              {rank.title}
            </div>
            <div className="mono" style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '10px' }}>
              {rank.xp} XP Total • {completedCount}/{missions.length} Missions Completed
            </div>

            <div
              style={{
                width: '100%',
                height: '8px',
                backgroundColor: 'var(--bg-panel)',
                borderRadius: '4px',
                overflow: 'hidden',
                marginBottom: '6px',
                border: '1px solid var(--border-subtle)'
              }}
            >
              <div
                style={{
                  width: `${rank.progressPercent}%`,
                  height: '100%',
                  backgroundColor: 'var(--accent-cyan)'
                }}
              />
            </div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
              {rank.nextRank
                ? `${rank.xpToNext} XP needed for ${rank.nextRank.title}`
                : 'Maximum Analyst Rank Achieved'}
            </div>
          </div>
        </div>
      </section>

      {/* Daily Challenge & Quick Stats Row */}
      <div className="grid-2">
        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <Calendar size={15} color="var(--accent-cyan)" />
              <span>Daily Operational Challenge ({daily.date})</span>
            </h2>
            <span className="tag-chip">+{daily.bonusXp} Bonus XP</span>
          </div>
          <div style={{ marginBottom: '8px', fontWeight: 600, fontSize: '15px' }}>{daily.missionTitle}</div>
          <p style={{ margin: '0 0 12px 0', color: 'var(--text-secondary)', fontSize: '13px' }}>
            <strong>Operational Modifier:</strong> {daily.modifier}
          </p>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={() => onSelectMission(daily.missionId)}
          >
            <Play size={13} />
            <span>Deploy to Daily Scenario</span>
          </button>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <Award size={15} color="var(--accent-cyan)" />
              <span>Analyst Achievements ({(profile.unlockedAchievements || []).length}/{ACHIEVEMENTS.length})</span>
            </h2>
            <button type="button" className="btn btn-sm" onClick={() => onNavigate('settings')}>
              <Settings size={13} />
              <span>Manage Save</span>
            </button>
          </div>
          {(profile.unlockedAchievements || []).length === 0 ? (
            <div style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
              No achievements unlocked yet. Complete <strong>Mission 1: The Noisy Login</strong> to earn your first
              SOC commendation!
            </div>
          ) : (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {ACHIEVEMENTS.map((ach) => {
                const unlocked = (profile.unlockedAchievements || []).includes(ach.id);
                return (
                  <span
                    key={ach.id}
                    className="tag-chip"
                    title={ach.description}
                    style={{
                      borderColor: unlocked ? 'var(--accent-cyan)' : 'var(--border-subtle)',
                      color: unlocked ? 'var(--accent-cyan)' : 'var(--text-muted)',
                      backgroundColor: unlocked ? 'var(--accent-cyan-dim)' : 'transparent',
                      padding: '3px 8px'
                    }}
                  >
                    {unlocked ? '★ ' : '○ '}
                    {ach.title}
                  </span>
                );
              })}
            </div>
          )}
        </section>
      </div>

      {/* Mission Campaign Catalogue */}
      <section className="panel">
        <div className="panel-header">
          <h2 className="panel-title">
            <Shield size={16} color="var(--accent-cyan)" />
            <span>SOC Campaign Missions (8 Scenarios)</span>
          </h2>
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            All missions feature deterministic synthetic telemetry &amp; full replayability
          </span>
        </div>

        <div className="grid-2">
          {missions.map((m, idx) => {
            const completion = profile.completedMissions?.[m.id] || null;
            const prevCompleted = idx === 0 || Boolean(profile.completedMissions?.[missions[idx - 1].id]);
            const isUnlocked = idx <= 1 || prevCompleted || Boolean(completion);

            return (
              <div
                key={m.id}
                className="panel"
                style={{
                  backgroundColor: 'var(--bg-input)',
                  borderColor: completion
                    ? 'rgba(16, 185, 129, 0.4)'
                    : isUnlocked
                    ? 'var(--border-strong)'
                    : 'var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  gap: '12px'
                }}
              >
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                    <span className="mono" style={{ fontSize: '11.5px', color: 'var(--accent-cyan)' }}>
                      {m.difficulty.toUpperCase()} • ~{m.estimatedMinutes} MIN • {m.xpReward} XP
                    </span>
                    {completion ? (
                      <span className="sev-badge sev-safe">
                        <CheckCircle2 size={12} />
                        <span>GRADE {completion.bestGrade} ({completion.bestScore}%)</span>
                      </span>
                    ) : (
                      <SeverityBadge severity={m.briefing?.initialAlert?.severity || 'medium'} />
                    )}
                  </div>

                  <h3 style={{ margin: '0 0 4px 0', fontSize: '16px', fontWeight: 600 }}>{m.title}</h3>
                  <div style={{ fontSize: '12.5px', color: 'var(--accent-blue)', marginBottom: '8px' }}>
                    {m.subtitle}
                  </div>
                  <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)' }}>
                    {m.briefing.summary}
                  </p>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '8px', borderTop: '1px solid var(--border-subtle)' }}>
                  <div className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {m.events.length} Telemetry Events • {m.briefing.telemetrySources.length} Sources
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      type="button"
                      className={`btn btn-sm ${completion ? '' : 'btn-primary'}`}
                      onClick={() => onSelectMission(m.id)}
                    >
                      {completion ? <RotateCcw size={13} /> : isUnlocked ? <Play size={13} /> : <Lock size={13} />}
                      <span>{completion ? 'Replay Mission' : 'Open Briefing'}</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Recent Investigation History */}
      <section className="panel">
        <div className="panel-header">
          <h2 className="panel-title">
            <Clock size={15} color="var(--accent-cyan)" />
            <span>Recent Investigation Log</span>
          </h2>
        </div>
        {(!profile.missionHistory || profile.missionHistory.length === 0) ? (
          <div style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
            No completed investigations recorded yet. Your completed incident assessments, scores, and grades will appear here.
          </div>
        ) : (
          <div className="table-container">
            <table className="event-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Mission</th>
                  <th>Grade</th>
                  <th>Score</th>
                  <th>XP Awarded</th>
                </tr>
              </thead>
              <tbody>
                {profile.missionHistory.slice(0, 8).map((item) => (
                  <tr key={item.id}>
                    <td className="mono">{item.timestamp.slice(0, 19).replace('T', ' ')} UTC</td>
                    <td>{item.missionTitle}</td>
                    <td>
                      <span className="sev-badge sev-safe">{item.grade}</span>
                    </td>
                    <td className="mono">{item.score}%</td>
                    <td className="mono">+{item.xpDelta} XP</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
