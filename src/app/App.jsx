import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Activity,
  Award,
  BookOpen,
  Compass,
  Home,
  Settings,
  Shield,
  Sparkles,
  Terminal
} from 'lucide-react';
import { CAMPAIGN_MISSIONS } from '../data/missions/campaignMissions.js';
import { createInitialIncidentState } from '../engine/responseEngine.js';
import { evaluateMissionPerformance } from '../engine/scoringEngine.js';
import { applyMissionProgression, getRankForXp } from '../engine/progressionEngine.js';
import {
  MISSION_STATES,
  transitionMissionState
} from '../engine/missionStateMachine.js';
import {
  loadProfile,
  saveProfile,
  loadSettings,
  saveSettings,
  loadActiveWorkspace,
  saveActiveWorkspace,
  clearActiveWorkspace,
  loadSavedQueries,
  saveQueryToHistory,
  loadCustomScenarios,
  saveCustomScenario,
  resetAllProgress
} from '../engine/storageEngine.js';
import { soundManager } from '../utils/soundEffects.js';
import { MainMenuView } from '../features/soc/MainMenuView.jsx';
import { SocCommandCenterView } from '../features/soc/SocCommandCenterView.jsx';
import { MissionBriefingView } from '../features/briefing/MissionBriefingView.jsx';
import { InvestigationWorkstationView } from '../features/investigation/InvestigationWorkstationView.jsx';
import { MissionDebriefView } from '../features/reporting/MissionDebriefView.jsx';
import { ExtraModesView } from '../features/progression/ExtraModesView.jsx';
import { GlossaryModal } from '../components/GlossaryModal.jsx';

function createFreshInvestigationState(mission) {
  return {
    missionId: mission.id,
    lifecycleState: MISSION_STATES.INVESTIGATING,
    executedQueries: [],
    evidence: [],
    ranDetections: false,
    detectionFindings: [],
    inspectedTimeline: false,
    responseActions: [],
    incidentState: createInitialIncidentState(mission),
    completedWalkthroughSteps: [],
    answeredQuestions: {},
    assessment: {
      classification: '',
      severity: '',
      confidence: 'high',
      affectedEntity: '',
      attackStages: [],
      keyFindings: '',
      scopeSummary: '',
      remainingUncertainty: '',
      recommendedFollowUp: ''
    },
    hintsUsed: [],
    notes: ''
  };
}

function parseInitialRoute(missions) {
  if (typeof window === 'undefined') {
    return { view: 'main_menu', missionId: missions[0].id };
  }
  const path = window.location.pathname;
  if (path === '/soc') {
    return { view: 'soc_center', missionId: missions[0].id };
  }
  if (path === '/lab') {
    return { view: 'extra_modes', missionId: missions[0].id, section: 'practice' };
  }
  if (path === '/settings') {
    return { view: 'settings', missionId: missions[0].id, section: 'settings' };
  }
  const match = path.match(/^\/mission\/([^/]+)\/(briefing|investigate|debrief)$/);
  if (match) {
    const [, mId, sub] = match;
    const exists = missions.some((m) => m.id === mId);
    const validId = exists ? mId : missions[0].id;
    const viewMap = {
      briefing: 'briefing',
      investigate: 'workstation',
      debrief: 'debrief'
    };
    return { view: viewMap[sub] || 'briefing', missionId: validId };
  }
  return { view: 'main_menu', missionId: missions[0].id };
}

export function App() {
  const [customScenarios, setCustomScenarios] = useState(() => loadCustomScenarios());
  const allMissions = useMemo(
    () => [...CAMPAIGN_MISSIONS, ...customScenarios],
    [customScenarios]
  );

  const initialRoute = useMemo(() => parseInitialRoute(allMissions), [allMissions]);

  const [profile, setProfile] = useState(() => loadProfile());
  const [settings, setSettings] = useState(() => loadSettings());
  const [savedQueries, setSavedQueries] = useState(() => loadSavedQueries());

  const [currentView, setCurrentView] = useState(initialRoute.view);
  const [currentMissionId, setCurrentMissionId] = useState(
    profile.activeMissionId || initialRoute.missionId || CAMPAIGN_MISSIONS[0].id
  );

  const currentMission = useMemo(
    () => allMissions.find((m) => m.id === currentMissionId) || CAMPAIGN_MISSIONS[0],
    [allMissions, currentMissionId]
  );

  const [investigationState, setInvestigationState] = useState(() => {
    const saved = loadActiveWorkspace(currentMission.id);
    return saved || createFreshInvestigationState(currentMission);
  });

  const [lastDebriefResult, setLastDebriefResult] = useState(null);
  const [lastProgressionOutcome, setLastProgressionOutcome] = useState(null);
  const [glossaryOpen, setGlossaryOpen] = useState(false);
  const [toastMessage, setToastMessage] = useState('');

  useEffect(() => {
    soundManager.setEnabled(settings.soundEnabled);
  }, [settings.soundEnabled]);

  const showNotification = useCallback((msg) => {
    setToastMessage(msg);
  }, []);

  useEffect(() => {
    if (!toastMessage) return undefined;
    const timer = setTimeout(() => setToastMessage(''), 4000);
    return () => clearTimeout(timer);
  }, [toastMessage]);

  const syncUrl = useCallback((view, mId) => {
    if (typeof window === 'undefined' || !window.history?.pushState) return;
    let targetPath = '/';
    if (view === 'soc_center') targetPath = '/soc';
    else if (view === 'extra_modes') targetPath = '/lab';
    else if (view === 'settings') targetPath = '/settings';
    else if (view === 'briefing') targetPath = `/mission/${mId}/briefing`;
    else if (view === 'workstation') targetPath = `/mission/${mId}/investigate`;
    else if (view === 'debrief') targetPath = `/mission/${mId}/debrief`;
    if (window.location.pathname !== targetPath) {
      window.history.pushState({}, '', targetPath);
    }
  }, []);

  function navigateTo(view, mId = currentMission.id) {
    setCurrentView(view);
    syncUrl(view, mId);
  }

  function handleSelectMission(missionId, targetView = 'briefing') {
    const targetMission = allMissions.find((m) => m.id === missionId) || CAMPAIGN_MISSIONS[0];
    setCurrentMissionId(targetMission.id);
    const savedWorkspace = loadActiveWorkspace(targetMission.id);
    const nextWs = savedWorkspace || createFreshInvestigationState(targetMission);
    setInvestigationState(nextWs);
    saveActiveWorkspace(targetMission.id, nextWs);

    const updatedProfile = { ...profile, activeMissionId: targetMission.id };
    setProfile(updatedProfile);
    saveProfile(updatedProfile);

    navigateTo(targetView, targetMission.id);
  }

  function handleStartInvestigation() {
    const nextWs = {
      ...investigationState,
      lifecycleState: MISSION_STATES.INVESTIGATING
    };
    setInvestigationState(nextWs);
    saveActiveWorkspace(currentMission.id, nextWs);
    navigateTo('workstation', currentMission.id);
  }

  function handleUpdateInvestigation(patch) {
    setInvestigationState((prev) => {
      const updated = { ...prev, ...patch };
      saveActiveWorkspace(currentMission.id, updated);
      return updated;
    });
  }

  function handleRestartMission() {
    clearActiveWorkspace(currentMission.id);
    const fresh = createFreshInvestigationState(currentMission);
    setInvestigationState(fresh);
    saveActiveWorkspace(currentMission.id, fresh);
    setLastDebriefResult(null);
    setLastProgressionOutcome(null);
    navigateTo('workstation', currentMission.id);
    showNotification(`Reset mission room for ${currentMission.title}.`);
  }

  function handleCompleteMission() {
    const transition = transitionMissionState(
      investigationState.lifecycleState || MISSION_STATES.INVESTIGATING,
      MISSION_STATES.COMPLETED,
      currentMission,
      investigationState
    );

    if (!transition.ok) {
      showNotification(transition.error);
      return;
    }

    const debrief = evaluateMissionPerformance(currentMission, investigationState);
    const campaignIds = CAMPAIGN_MISSIONS.map((m) => m.id);
    const outcome = applyMissionProgression(
      profile,
      currentMission,
      investigationState,
      debrief,
      campaignIds
    );

    const completedWs = {
      ...investigationState,
      lifecycleState: MISSION_STATES.COMPLETED
    };
    setInvestigationState(completedWs);
    saveActiveWorkspace(currentMission.id, completedWs);

    setProfile(outcome.profile);
    saveProfile(outcome.profile);

    setLastDebriefResult(debrief);
    setLastProgressionOutcome(outcome);
    soundManager.playMissionCompleted();
    navigateTo('debrief', currentMission.id);
  }

  function handleUpdateSettings(nextSettings) {
    setSettings(nextSettings);
    saveSettings(nextSettings);
  }

  function handleUpdateProfile(nextProfile) {
    setProfile(nextProfile);
    saveProfile(nextProfile);
  }

  function handleResetAll() {
    const freshProfile = resetAllProgress();
    setProfile(freshProfile);
    const freshWs = createFreshInvestigationState(CAMPAIGN_MISSIONS[0]);
    setCurrentMissionId(CAMPAIGN_MISSIONS[0].id);
    setInvestigationState(freshWs);
    navigateTo('main_menu', CAMPAIGN_MISSIONS[0].id);
    showNotification('All campaign progress and workspaces have been reset.');
  }

  const rank = getRankForXp(profile.xp);
  const currentIdx = allMissions.findIndex((m) => m.id === currentMission.id);
  const nextMission = currentIdx >= 0 && currentIdx + 1 < allMissions.length ? allMissions[currentIdx + 1] : null;

  return (
    <div className={`app-shell ${settings.reducedMotion ? 'reduced-motion' : ''}`}>
      {/* Clean Gamified Top Navbar */}
      <header className="game-top-navbar" aria-label="Primary Navigation">
        <div
          className="brand-cluster"
          style={{ cursor: 'pointer' }}
          onClick={() => navigateTo('main_menu')}
        >
          <div className="brand-icon">
            <Shield size={20} />
          </div>
          <div>
            <div className="brand-title">CYBEROPS ACADEMY</div>
            <div className="brand-subtitle">Interactive SOC Game</div>
          </div>
        </div>

        <nav className="top-nav-pills">
          <button
            type="button"
            className={`nav-btn ${currentView === 'main_menu' ? 'active' : ''}`}
            onClick={() => navigateTo('main_menu')}
          >
            <Home size={15} />
            <span>Campaign Map</span>
          </button>

          <button
            type="button"
            className={`nav-btn ${currentView === 'workstation' || currentView === 'briefing' ? 'active' : ''}`}
            onClick={() => navigateTo('workstation')}
          >
            <Activity size={15} />
            <span>Active Room: {currentMission.title.split(':')[0]}</span>
          </button>

          <button
            type="button"
            className={`nav-btn ${currentView === 'soc_center' ? 'active' : ''}`}
            onClick={() => navigateTo('soc_center')}
          >
            <Compass size={15} />
            <span>SOC Queue</span>
          </button>

          <button
            type="button"
            className={`nav-btn ${currentView === 'extra_modes' ? 'active' : ''}`}
            onClick={() => navigateTo('extra_modes')}
          >
            <Terminal size={15} />
            <span>Practice Lab &amp; Triage</span>
          </button>

          <button
            type="button"
            className="nav-btn"
            onClick={() => setGlossaryOpen(true)}
          >
            <BookOpen size={15} />
            <span>Glossary</span>
          </button>

          <button
            type="button"
            className={`nav-btn ${currentView === 'settings' ? 'active' : ''}`}
            onClick={() => navigateTo('settings')}
            aria-label="Settings"
          >
            <Settings size={15} />
          </button>
        </nav>

        <div className="player-hud-pill">
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Award size={16} color={rank.badgeColor} />
            <span style={{ fontWeight: 700, fontSize: '13px', color: rank.badgeColor }}>
              Lvl {rank.level} {rank.title}
            </span>
          </div>
          <span className="xp-pill-badge">
            <Sparkles size={12} />
            <span>{profile.xp} XP</span>
          </span>
        </div>
      </header>

      {/* Main Content Area */}
      <div className="main-viewport">
        <main className="page-content">
          {currentView === 'main_menu' && (
            <MainMenuView
              profile={profile}
              missions={allMissions}
              onSelectMission={(id) => handleSelectMission(id, 'briefing')}
              onContinueMission={(id) => handleSelectMission(id, 'workstation')}
              onNavigate={(v) => navigateTo(v)}
              onOpenGlossary={() => setGlossaryOpen(true)}
            />
          )}

          {currentView === 'soc_center' && (
            <SocCommandCenterView
              missions={allMissions}
              currentMission={currentMission}
              investigationState={investigationState}
              profile={profile}
              onSelectMission={(id) => handleSelectMission(id, 'briefing')}
              onOpenWorkstation={() => navigateTo('workstation')}
              onOpenBriefing={() => navigateTo('briefing')}
            />
          )}

          {currentView === 'briefing' && (
            <MissionBriefingView
              mission={currentMission}
              onStartInvestigation={handleStartInvestigation}
              onBackToMenu={() => navigateTo('main_menu')}
            />
          )}

          {currentView === 'workstation' && (
            <InvestigationWorkstationView
              mission={currentMission}
              investigationState={investigationState}
              savedQueries={savedQueries}
              onUpdateInvestigation={handleUpdateInvestigation}
              onSaveQuery={(q) => setSavedQueries(saveQueryToHistory(q, q))}
              onCompleteMission={handleCompleteMission}
              onRestartMission={handleRestartMission}
              onOpenBriefing={() => navigateTo('briefing')}
              onNotify={showNotification}
            />
          )}

          {currentView === 'debrief' && (
            <MissionDebriefView
              mission={currentMission}
              investigationState={investigationState}
              debriefResult={
                lastDebriefResult || evaluateMissionPerformance(currentMission, investigationState)
              }
              progressionOutcome={lastProgressionOutcome}
              onReplayMission={handleRestartMission}
              onNextMission={
                nextMission ? () => handleSelectMission(nextMission.id, 'briefing') : null
              }
              onBackToMenu={() => navigateTo('main_menu')}
            />
          )}

          {(currentView === 'extra_modes' || currentView === 'settings') && (
            <ExtraModesView
              key={currentView}
              initialSection={currentView === 'settings' ? 'settings' : 'practice'}
              missions={allMissions}
              profile={profile}
              settings={settings}
              onUpdateSettings={handleUpdateSettings}
              onUpdateProfile={handleUpdateProfile}
              onResetProgress={handleResetAll}
              onImportCustomScenario={(scen) => {
                const updated = saveCustomScenario(scen);
                setCustomScenarios(updated);
                showNotification(`Imported custom scenario: ${scen.title}`);
              }}
              onLaunchMission={(id) => handleSelectMission(id, 'briefing')}
              onNotify={showNotification}
            />
          )}
        </main>
      </div>

      {/* Glossary Modal */}
      <GlossaryModal isOpen={glossaryOpen} onClose={() => setGlossaryOpen(false)} />

      {/* Accessible Toast Banner */}
      {toastMessage && (
        <div className="toast-banner" role="status" aria-live="polite">
          <span>{toastMessage}</span>
        </div>
      )}
    </div>
  );
}
