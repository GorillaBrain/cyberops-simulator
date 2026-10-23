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
  RotateCcw,
  Sparkles,
  Flag
} from 'lucide-react';
import { getRankForXp, ACHIEVEMENTS } from '../../engine/progressionEngine.js';
import { getDailyChallengeInfo } from '../../data/missions/extraModes.js';
import { GUIDED_WALKTHROUGHS } from '../../data/missions/guidedWalkthroughs.js';
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      {/* Gamified Academy Hero Banner */}
      <section
        className="panel-elevated"
        style={{
          padding: '26px',
          background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.14) 0%, rgba(25, 37, 61, 0.96) 60%)'
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '24px'
          }}
        >
          <div style={{ maxWidth: '700px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
              <span className="sim-badge">INTERACTIVE SOC LEARNING PATH</span>
              <span className="tag-chip">Step-by-Step Guided Rooms</span>
            </div>
            <h1 style={{ margin: '0 0 6px 0', fontSize: '28px', fontWeight: 800, letterSpacing: '-0.01em' }}>
              CyberOps Simulator
            </h1>
            <p style={{ margin: '0 0 12px 0', fontSize: '15.5px', color: '#34d399', fontWeight: 600 }}>
              Detect the signal. Investigate the evidence. Stop the threat.
            </p>
            <p style={{ margin: '0 0 20px 0', color: 'var(--text-secondary)', fontSize: '14px' }}>
              Learn real-world Security Operations Center (SOC) investigation one guided task at a time.
              Commander Vela walks you through every room with bite-sized lessons, interactive check-in
              questions, 1-click query helpers, and realistic attack simulations.
            </p>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px' }}>
              <button
                type="button"
                className="btn btn-primary"
                style={{ padding: '10px 18px', fontSize: '14px' }}
                onClick={() => onContinueMission(activeMission.id)}
              >
                <Play size={16} />
                <span>
                  {profile.activeMissionId
                    ? `Continue Room: ${activeMission.title}`
                    : completedCount === 0
                    ? 'Start Tutorial: Mission 1'
                    : `Play ${activeMission.title}`}
                </span>
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => onNavigate('extra_modes')}
              >
                <Terminal size={15} />
                <span>Practice Lab &amp; Rapid Triage</span>
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

          {/* Gamified Player Level Card */}
          <div
            className="panel"
            style={{
              minWidth: '290px',
              flex: '0 1 330px',
              backgroundColor: 'var(--bg-input)',
              borderColor: 'var(--border-strong)'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                Analyst Rank Progress
              </span>
              <span className="xp-pill-badge">
                <Sparkles size={12} />
                <span>LVL {rank.level}</span>
              </span>
            </div>
            <div style={{ fontSize: '21px', fontWeight: 800, color: rank.badgeColor, marginBottom: '4px' }}>
              {rank.title}
            </div>
            <div className="mono" style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '10px' }}>
              {rank.xp} XP • {completedCount} / {missions.length} Rooms Cleared
            </div>

            <div
              style={{
                width: '100%',
                height: '10px',
                backgroundColor: 'var(--bg-panel)',
                borderRadius: '999px',
                overflow: 'hidden',
                marginBottom: '6px',
                border: '1px solid var(--border-subtle)'
              }}
            >
              <div
                style={{
                  width: `${rank.progressPercent}%`,
                  height: '100%',
                  background: 'linear-gradient(90deg, #10b981, #22d3ee)'
                }}
              />
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              {rank.nextRank
                ? `${rank.xpToNext} XP to promote to ${rank.nextRank.title}`
                : 'Maximum Analyst Rank Unlocked!'}
            </div>
          </div>
        </div>
      </section>

      {/* Guided Campaign Rooms Path */}
      <section className="panel">
        <div className="panel-header">
          <h2 className="panel-title">
            <Flag size={16} color="#34d399" />
            <span>Guided SOC Learning Path (8 Interactive Rooms)</span>
          </h2>
          <span style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>
            Each room includes step-by-step instructions, check-in questions &amp; live log investigation
          </span>
        </div>

        <div className="grid-2">
          {missions.map((m, idx) => {
            const completion = profile.completedMissions?.[m.id] || null;
            const prevCompleted = idx === 0 || Boolean(profile.completedMissions?.[missions[idx - 1].id]);
            const isUnlocked = idx <= 1 || prevCompleted || Boolean(completion);
            const wt = GUIDED_WALKTHROUGHS[m.id];
            const stepCount = wt ? wt.steps.length : 3;

            return (
              <div
                key={m.id}
                className="panel"
                style={{
                  backgroundColor: 'var(--bg-input)',
                  borderColor: completion
                    ? 'rgba(16, 185, 129, 0.5)'
                    : isUnlocked
                    ? 'var(--border-strong)'
                    : 'var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  gap: '14px'
                }}
              >
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span className="sim-badge">ROOM {idx + 1}</span>
                      <span className="tag-chip">{m.difficulty}</span>
                      <span className="tag-chip">{stepCount} Guided Tasks</span>
                    </div>
                    {completion ? (
                      <span className="sev-badge sev-safe">
                        <CheckCircle2 size={12} />
                        <span>RANK {completion.bestGrade} ({completion.bestScore}%)</span>
                      </span>
                    ) : (
                      <span className="xp-pill-badge">+{m.xpReward} XP</span>
                    )}
                  </div>

                  <h3 style={{ margin: '0 0 4px 0', fontSize: '17px', fontWeight: 700 }}>{m.title}</h3>
                  <div style={{ fontSize: '13px', color: 'var(--accent-cyan)', fontWeight: 600, marginBottom: '8px' }}>
                    Focus: {m.subtitle}
                  </div>
                  <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)' }}>
                    {m.briefing.summary}
                  </p>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)', flexWrap: 'wrap', gap: '8px' }}>
                  <SeverityBadge severity={m.briefing?.initialAlert?.severity || 'medium'} />
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => onSelectMission(m.id)}
                    >
                      {completion ? 'Replay Briefing' : 'Open Briefing'}
                    </button>
                    <button
                      type="button"
                      className="btn btn-sm btn-primary"
                      onClick={() => onContinueMission(m.id)}
                    >
                      {completion ? <RotateCcw size={13} /> : isUnlocked ? <Play size={13} /> : <Lock size={13} />}
                      <span>{completion ? 'Replay Guided Room' : 'Enter Guided Room'}</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Daily Challenge & Achievements Row */}
      <div className="grid-2">
        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <Calendar size={15} color="var(--accent-cyan)" />
              <span>Daily Challenge ({daily.date})</span>
            </h2>
            <span className="xp-pill-badge">+{daily.bonusXp} Bonus XP</span>
          </div>
          <div style={{ marginBottom: '6px', fontWeight: 700, fontSize: '15px' }}>{daily.missionTitle}</div>
          <p style={{ margin: '0 0 12px 0', color: 'var(--text-secondary)', fontSize: '13px' }}>
            <strong>Modifier:</strong> {daily.modifier}
          </p>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={() => onContinueMission(daily.missionId)}
          >
            <Play size={13} />
            <span>Launch Daily Challenge</span>
          </button>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <Award size={15} color="#fbbf24" />
              <span>Earned Badges ({(profile.unlockedAchievements || []).length}/{ACHIEVEMENTS.length})</span>
            </h2>
            <button type="button" className="btn btn-sm" onClick={() => onNavigate('settings')}>
              <Settings size={13} />
              <span>Save Data</span>
            </button>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
            {ACHIEVEMENTS.map((ach) => {
              const unlocked = (profile.unlockedAchievements || []).includes(ach.id);
              return (
                <span
                  key={ach.id}
                  className="tag-chip"
                  title={ach.description}
                  style={{
                    borderColor: unlocked ? '#10b981' : 'var(--border-subtle)',
                    color: unlocked ? '#6ee7b7' : 'var(--text-muted)',
                    backgroundColor: unlocked ? 'var(--accent-green-dim)' : 'transparent',
                    padding: '4px 10px'
                  }}
                >
                  {unlocked ? '🏆 ' : '🔒 '}
                  {ach.title}
                </span>
              );
            })}
          </div>
        </section>
      </div>
    </div>
  );
}
