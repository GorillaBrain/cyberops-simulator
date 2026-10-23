import React, { useState, useMemo } from 'react';
import {
  CheckCircle2,
  Cpu,
  Download,
  FileUp,
  Play,
  RotateCcw,
  Settings,
  Terminal,
  Trash2,
  Zap
} from 'lucide-react';
import {
  getEndlessTriageSequence,
  SAMPLE_CUSTOM_SCENARIO
} from '../../data/missions/extraModes.js';
import { executeStructuredQuery } from '../../engine/queryEngine.js';
import { DETECTION_RULES } from '../../data/rules/detectionRules.js';
import { runAllDetections } from '../../engine/detectionEngine.js';
import { validateImportedScenario } from '../../utils/eventSchema.js';
import { exportSavePayload, importSavePayload } from '../../engine/storageEngine.js';
import { SeverityBadge } from '../../components/SeverityBadge.jsx';

export function ExtraModesView({
  initialSection = 'practice',
  missions,
  profile,
  settings,
  onUpdateSettings,
  onUpdateProfile,
  onResetProgress,
  onImportCustomScenario,
  onLaunchMission,
  onNotify
}) {
  const [section, setSection] = useState(initialSection);

  // Practice Lab state
  const [labQuery, setLabQuery] = useState('severity IN ("high", "critical")');
  const allCombinedEvents = useMemo(
    () => missions.flatMap((m) => m.events.map((ev) => ({ ...ev, _missionId: m.id }))),
    [missions]
  );
  const labQueryRes = useMemo(
    () => executeStructuredQuery(allCombinedEvents, labQuery),
    [allCombinedEvents, labQuery]
  );
  const labDetections = useMemo(
    () => runAllDetections(DETECTION_RULES, allCombinedEvents),
    [allCombinedEvents]
  );

  // Endless Triage state
  const [triageSeed, setTriageSeed] = useState(42);
  const [triageIndex, setTriageIndex] = useState(0);
  const [triageAnswers, setTriageAnswers] = useState({});
  const triageCards = useMemo(() => getEndlessTriageSequence(triageSeed), [triageSeed]);
  const currentCard = triageCards[triageIndex] || triageCards[0];

  // Custom Scenario Import state
  const [customJsonText, setCustomJsonText] = useState(
    JSON.stringify(SAMPLE_CUSTOM_SCENARIO, null, 2)
  );
  const [customErrors, setCustomErrors] = useState([]);

  // Save Import state
  const [saveImportText, setSaveImportText] = useState('');
  const [saveImportError, setSaveImportError] = useState('');
  const [confirmReset, setConfirmReset] = useState(false);

  function handleAnswerTriage(choice) {
    setTriageAnswers((prev) => ({
      ...prev,
      [currentCard.id]: {
        choice,
        correct: choice === currentCard.expectedClassification
      }
    }));
  }

  function handleValidateAndLaunchCustom() {
    const res = validateImportedScenario(customJsonText);
    if (!res.valid) {
      setCustomErrors(res.errors);
      return;
    }
    setCustomErrors([]);
    onImportCustomScenario(res.scenario);
    onLaunchMission(res.scenario.id);
  }

  function handleExportSaveFile() {
    const json = exportSavePayload(profile, settings);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cyberops-simulator-save.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleImportSaveSubmit(e) {
    e.preventDefault();
    const res = importSavePayload(saveImportText);
    if (!res.ok) {
      setSaveImportError(res.errors.join(' '));
      return;
    }
    setSaveImportError('');
    if (res.isReport) {
      if (onNotify) {
        onNotify(`Verified exported Incident Report for "${res.report.missionTitle}" (Score: ${res.report.overallScore}%).`);
      }
    } else if (res.profile) {
      onUpdateProfile(res.profile);
      if (onNotify) onNotify('Successfully restored analyst profile and progression.');
    }
  }

  const triageCorrectCount = Object.values(triageAnswers).filter((a) => a.correct).length;
  const triageTotalAnswered = Object.keys(triageAnswers).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Sub-navigation */}
      <div className="workstation-tabs">
        <button
          type="button"
          className={`tab-btn ${section === 'practice' ? 'active' : ''}`}
          onClick={() => setSection('practice')}
        >
          <Terminal size={14} />
          <span>Practice Lab (Free Query &amp; Rule Sandbox)</span>
        </button>
        <button
          type="button"
          className={`tab-btn ${section === 'triage' ? 'active' : ''}`}
          onClick={() => setSection('triage')}
        >
          <Zap size={14} />
          <span>Endless Alert Triage</span>
        </button>
        <button
          type="button"
          className={`tab-btn ${section === 'custom' ? 'active' : ''}`}
          onClick={() => setSection('custom')}
        >
          <FileUp size={14} />
          <span>Custom Scenario Import</span>
        </button>
        <button
          type="button"
          className={`tab-btn ${section === 'settings' ? 'active' : ''}`}
          onClick={() => setSection('settings')}
        >
          <Settings size={14} />
          <span>Settings &amp; Save Management</span>
        </button>
      </div>

      {/* SECTION 1: PRACTICE LAB */}
      {section === 'practice' && (
        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <Terminal size={15} color="var(--accent-cyan)" />
              <span>SOC Telemetry Practice Lab ({allCombinedEvents.length} Combined Events)</span>
            </h2>
            <span className="tag-chip">{labDetections.length} Total Rule Matches Across Corpus</span>
          </div>
          <p style={{ margin: '0 0 12px 0', color: 'var(--text-secondary)', fontSize: '13px' }}>
            Experiment with the structured query language and detection rules across the entire synthetic corpus without timers or scoring penalties.
          </p>

          <div style={{ marginBottom: '12px' }}>
            <label htmlFor="practice-query-input" className="label">Test Structured Query Expression</label>
            <input
              id="practice-query-input"
              type="text"
              className="input mono"
              value={labQuery}
              onChange={(e) => setLabQuery(e.target.value)}
            />
          </div>

          {labQueryRes.error ? (
            <div style={{ color: '#fda4af', marginBottom: '12px', fontSize: '13px' }}>
              Syntax Error: {labQueryRes.error}
            </div>
          ) : (
            <div className="mono" style={{ fontSize: '12px', color: 'var(--accent-cyan)', marginBottom: '10px' }}>
              Matched {labQueryRes.results.length} of {allCombinedEvents.length} events
            </div>
          )}

          <div className="table-container">
            <table className="event-table">
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Scenario</th>
                  <th>Source</th>
                  <th>Type</th>
                  <th>Severity</th>
                  <th>Host / User</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {labQueryRes.results.slice(0, 25).map((ev) => (
                  <tr key={ev.eventId}>
                    <td className="mono">{ev.eventId}</td>
                    <td className="mono">{ev._missionId}</td>
                    <td className="mono">{ev.source}</td>
                    <td className="mono">{ev.eventType}</td>
                    <td><SeverityBadge severity={ev.severity} /></td>
                    <td className="mono">{ev.host || '—'} / {ev.username || '—'}</td>
                    <td>{ev.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* SECTION 2: ENDLESS TRIAGE */}
      {section === 'triage' && (
        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <Zap size={15} color="var(--accent-cyan)" />
              <span>Rapid Alert Triage Drill (Seed #{triageSeed})</span>
            </h2>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className="mono" style={{ color: 'var(--accent-cyan)' }}>
                Accuracy: {triageCorrectCount}/{triageTotalAnswered}
              </span>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => {
                  setTriageSeed((s) => s + 7);
                  setTriageIndex(0);
                  setTriageAnswers({});
                }}
              >
                <RotateCcw size={13} />
                <span>New Seeded Queue</span>
              </button>
            </div>
          </div>

          <div className="panel" style={{ backgroundColor: 'var(--bg-input)', marginBottom: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span className="mono" style={{ color: 'var(--accent-cyan)' }}>
                ALERT {triageIndex + 1} OF {triageCards.length} ({currentCard.id})
              </span>
              <SeverityBadge severity={currentCard.severity} />
            </div>

            <h3 style={{ margin: '0 0 8px 0', fontSize: '17px' }}>{currentCard.title}</h3>
            <p style={{ margin: '0 0 12px 0', color: 'var(--text-primary)' }}>{currentCard.summary}</p>

            <div className="mono" style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '14px', display: 'grid', gap: '4px' }}>
              <div>source={currentCard.source} | host={currentCard.host} | username={currentCard.username} | srcIp={currentCard.sourceIp}</div>
              {currentCard.commandLine && <div>commandLine: {currentCard.commandLine}</div>}
            </div>

            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="btn btn-danger"
                onClick={() => handleAnswerTriage('malicious_incident')}
              >
                Classify: Malicious Incident
              </button>
              <button
                type="button"
                className="btn btn-success"
                onClick={() => handleAnswerTriage('benign_activity')}
              >
                Classify: Benign Activity
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => handleAnswerTriage('inconclusive')}
              >
                Classify: Inconclusive Noise
              </button>
            </div>

            {triageAnswers[currentCard.id] && (
              <div
                style={{
                  marginTop: '14px',
                  padding: '12px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: triageAnswers[currentCard.id].correct
                    ? 'var(--status-safe-bg)'
                    : 'var(--sev-critical-bg)',
                  border: '1px solid var(--border-strong)'
                }}
              >
                <strong>
                  {triageAnswers[currentCard.id].correct
                    ? '✓ Correct Classification!'
                    : `✗ Expected: ${currentCard.expectedClassification.replace('_', ' ')}`}
                </strong>
                <p style={{ margin: '4px 0 8px 0', fontSize: '13px' }}>{currentCard.explanation}</p>
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  onClick={() => setTriageIndex((i) => (i + 1) % triageCards.length)}
                >
                  Next Alert in Queue ➔
                </button>
              </div>
            )}
          </div>
        </section>
      )}

      {/* SECTION 3: CUSTOM SCENARIO IMPORT */}
      {section === 'custom' && (
        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <FileUp size={15} color="var(--accent-cyan)" />
              <span>Custom Scenario JSON Validator &amp; Importer</span>
            </h2>
          </div>
          <p style={{ margin: '0 0 12px 0', color: 'var(--text-secondary)', fontSize: '13px' }}>
            Import a bounded JSON scenario definition. All records are strictly validated against the canonical event schema and sanitized against prototype pollution. No code execution is permitted.
          </p>

          {customErrors.length > 0 && (
            <div
              role="alert"
              style={{
                marginBottom: '12px',
                padding: '10px',
                backgroundColor: 'var(--sev-critical-bg)',
                border: '1px solid var(--sev-critical)',
                color: '#fda4af',
                borderRadius: 'var(--radius-sm)'
              }}
            >
              <strong>Scenario Validation Failed:</strong>
              <ul style={{ margin: '4px 0 0 0', paddingLeft: '18px' }}>
                {customErrors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            </div>
          )}

          <textarea
            aria-label="Custom Scenario JSON"
            rows={14}
            className="textarea mono"
            style={{ fontSize: '12px', marginBottom: '12px' }}
            value={customJsonText}
            onChange={(e) => setCustomJsonText(e.target.value)}
          />

          <div style={{ display: 'flex', gap: '10px' }}>
            <button type="button" className="btn btn-primary" onClick={handleValidateAndLaunchCustom}>
              <Play size={14} />
              <span>Validate &amp; Launch Custom Scenario</span>
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => {
                setCustomJsonText(JSON.stringify(SAMPLE_CUSTOM_SCENARIO, null, 2));
                setCustomErrors([]);
              }}
            >
              Restore Sample Scenario Template
            </button>
          </div>
        </section>
      )}

      {/* SECTION 4: SETTINGS & SAVE MANAGEMENT */}
      {section === 'settings' && (
        <div className="grid-2">
          <section className="panel">
            <div className="panel-header">
              <h2 className="panel-title">
                <Settings size={15} color="var(--accent-cyan)" />
                <span>Workstation Preferences &amp; Accessibility</span>
              </h2>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label htmlFor="analyst-callsign-input" className="label">Analyst Callsign</label>
                <input
                  id="analyst-callsign-input"
                  type="text"
                  className="input mono"
                  value={profile.analystName || 'Operator-01'}
                  onChange={(e) => onUpdateProfile({ ...profile, analystName: e.target.value })}
                />
              </div>

              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={Boolean(settings.soundEnabled)}
                  onChange={(e) => onUpdateSettings({ ...settings, soundEnabled: e.target.checked })}
                />
                <span>Enable Tactical Audio Cues (Conservative Web Audio Synthesizer)</span>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={Boolean(settings.reducedMotion)}
                  onChange={(e) => onUpdateSettings({ ...settings, reducedMotion: e.target.checked })}
                />
                <span>Enforce Reduced Motion</span>
              </label>

              <div style={{ paddingTop: '12px', borderTop: '1px solid var(--border-subtle)' }}>
                {!confirmReset ? (
                  <button
                    type="button"
                    className="btn btn-danger"
                    onClick={() => setConfirmReset(true)}
                  >
                    <Trash2 size={14} />
                    <span>Reset All Campaign Progress</span>
                  </button>
                ) : (
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <span style={{ fontSize: '12.5px', color: '#fda4af' }}>Confirm permanent progress reset?</span>
                    <button
                      type="button"
                      className="btn btn-sm btn-danger"
                      onClick={() => {
                        onResetProgress();
                        setConfirmReset(false);
                      }}
                    >
                      Yes, Wipe Progress
                    </button>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => setConfirmReset(false)}
                    >
                      Cancel
                    </button>
                  </div>
                )}
              </div>
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <h2 className="panel-title">
                <Download size={15} color="var(--accent-cyan)" />
                <span>Export / Import Save &amp; Report JSON</span>
              </h2>
            </div>

            <div style={{ marginBottom: '14px' }}>
              <button type="button" className="btn btn-primary" onClick={handleExportSaveFile}>
                <Download size={14} />
                <span>Export Current Game Save (.json)</span>
              </button>
            </div>

            <form onSubmit={handleImportSaveSubmit}>
              <label htmlFor="save-import-textarea" className="label">
                Paste Exported Save or Incident Report JSON to Validate &amp; Restore
              </label>
              <textarea
                id="save-import-textarea"
                rows={6}
                className="textarea mono"
                style={{ fontSize: '11.5px', marginBottom: '8px' }}
                placeholder='{"exportType": "cyberops_save_v1", ...}'
                value={saveImportText}
                onChange={(e) => setSaveImportText(e.target.value)}
              />
              {saveImportError && (
                <div style={{ color: '#fda4af', fontSize: '12.5px', marginBottom: '8px' }}>
                  {saveImportError}
                </div>
              )}
              <button type="submit" className="btn">
                <CheckCircle2 size={14} />
                <span>Validate &amp; Import JSON</span>
              </button>
            </form>
          </section>
        </div>
      )}
    </div>
  );
}
