import { sanitizeObject, validateImportedSave } from '../utils/eventSchema.js';

const STORAGE_KEYS = {
  PROFILE: 'cyberops_profile_v1',
  SETTINGS: 'cyberops_settings_v1',
  ACTIVE_WORKSPACE: 'cyberops_active_workspace_v1',
  SAVED_QUERIES: 'cyberops_saved_queries_v1',
  CUSTOM_SCENARIOS: 'cyberops_custom_scenarios_v1'
};

const IDB_NAME = 'CyberOpsSimulatorDB';
const IDB_VERSION = 1;
const IDB_STORE = 'kv_store';

export const DEFAULT_PROFILE = {
  analystName: 'Operator-01',
  xp: 0,
  completedMissions: {},
  unlockedAchievements: [],
  missionHistory: [],
  activeMissionId: null,
  activeMissionState: null
};

export const DEFAULT_SETTINGS = {
  soundEnabled: false,
  reducedMotion: false,
  compactTables: false,
  showTutorialHints: true
};

function openIdb() {
  return new Promise((resolve) => {
    if (typeof window === 'undefined' || !window.indexedDB) {
      resolve(null);
      return;
    }
    try {
      const req = window.indexedDB.open(IDB_NAME, IDB_VERSION);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains(IDB_STORE)) {
          db.createObjectStore(IDB_STORE);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

export async function idbSet(key, value) {
  const db = await openIdb();
  if (!db) return false;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      const store = tx.objectStore(IDB_STORE);
      store.put(value, key);
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => resolve(false);
    } catch {
      resolve(false);
    }
  });
}

export async function idbGet(key) {
  const db = await openIdb();
  if (!db) return null;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction(IDB_STORE, 'readonly');
      const store = tx.objectStore(IDB_STORE);
      const req = store.get(key);
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

export function loadProfile() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.PROFILE);
    if (!raw) return { ...DEFAULT_PROFILE };
    const parsed = sanitizeObject(JSON.parse(raw));
    return {
      ...DEFAULT_PROFILE,
      ...parsed,
      completedMissions: parsed.completedMissions || {},
      unlockedAchievements: Array.isArray(parsed.unlockedAchievements)
        ? parsed.unlockedAchievements
        : [],
      missionHistory: Array.isArray(parsed.missionHistory) ? parsed.missionHistory : []
    };
  } catch {
    return { ...DEFAULT_PROFILE };
  }
}

export function saveProfile(profile) {
  try {
    const clean = sanitizeObject(profile);
    localStorage.setItem(STORAGE_KEYS.PROFILE, JSON.stringify(clean));
    idbSet(STORAGE_KEYS.PROFILE, clean);
    return true;
  } catch {
    return false;
  }
}

export function loadSettings() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.SETTINGS);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const parsed = sanitizeObject(JSON.parse(raw));
    return { ...DEFAULT_SETTINGS, ...parsed };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export function saveSettings(settings) {
  try {
    const clean = sanitizeObject(settings);
    localStorage.setItem(STORAGE_KEYS.SETTINGS, JSON.stringify(clean));
    return true;
  } catch {
    return false;
  }
}

export function loadActiveWorkspace(missionId) {
  try {
    const raw = localStorage.getItem(`${STORAGE_KEYS.ACTIVE_WORKSPACE}_${missionId}`);
    if (!raw) return null;
    return sanitizeObject(JSON.parse(raw));
  } catch {
    return null;
  }
}

export function saveActiveWorkspace(missionId, workspaceState) {
  if (!missionId) return false;
  try {
    const clean = sanitizeObject(workspaceState);
    localStorage.setItem(`${STORAGE_KEYS.ACTIVE_WORKSPACE}_${missionId}`, JSON.stringify(clean));
    idbSet(`${STORAGE_KEYS.ACTIVE_WORKSPACE}_${missionId}`, clean);
    return true;
  } catch {
    return false;
  }
}

export function clearActiveWorkspace(missionId) {
  if (!missionId) return;
  try {
    localStorage.removeItem(`${STORAGE_KEYS.ACTIVE_WORKSPACE}_${missionId}`);
    idbSet(`${STORAGE_KEYS.ACTIVE_WORKSPACE}_${missionId}`, null);
  } catch {
    // ignore
  }
}

export function loadSavedQueries() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.SAVED_QUERIES);
    if (!raw) return [];
    const parsed = sanitizeObject(JSON.parse(raw));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveQueryToHistory(label, query) {
  if (!query || !query.trim()) return loadSavedQueries();
  const existing = loadSavedQueries();
  const entry = {
    id: `Q-${Date.now()}`,
    label: label || query.trim().slice(0, 36),
    query: query.trim(),
    savedAt: new Date().toISOString()
  };
  const deduped = [entry, ...existing.filter((q) => q.query !== entry.query)].slice(0, 15);
  try {
    localStorage.setItem(STORAGE_KEYS.SAVED_QUERIES, JSON.stringify(deduped));
  } catch {
    // ignore
  }
  return deduped;
}

export function loadCustomScenarios() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.CUSTOM_SCENARIOS);
    if (!raw) return [];
    const parsed = sanitizeObject(JSON.parse(raw));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveCustomScenario(scenario) {
  const list = loadCustomScenarios().filter((s) => s.id !== scenario.id);
  const updated = [scenario, ...list].slice(0, 10);
  try {
    localStorage.setItem(STORAGE_KEYS.CUSTOM_SCENARIOS, JSON.stringify(updated));
    idbSet(STORAGE_KEYS.CUSTOM_SCENARIOS, updated);
  } catch {
    // ignore
  }
  return updated;
}

export function resetAllProgress() {
  try {
    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith('cyberops_')) {
        keysToRemove.push(k);
      }
    }
    keysToRemove.forEach((k) => localStorage.removeItem(k));
    return { ...DEFAULT_PROFILE };
  } catch {
    return { ...DEFAULT_PROFILE };
  }
}

export function exportSavePayload(profile, settings) {
  return JSON.stringify(
    {
      exportType: 'cyberops_save_v1',
      exportedAt: new Date().toISOString(),
      version: '1.0.0',
      analystName: profile.analystName,
      xp: profile.xp,
      completedMissions: profile.completedMissions,
      unlockedAchievements: profile.unlockedAchievements,
      missionHistory: profile.missionHistory,
      settings
    },
    null,
    2
  );
}

export function importSavePayload(rawJsonString) {
  const check = validateImportedSave(rawJsonString);
  if (!check.valid) {
    return { ok: false, errors: check.errors, profile: null };
  }
  const data = check.data;
  if (data.exportType === 'cyberops_report_v1') {
    return {
      ok: true,
      isReport: true,
      report: data,
      errors: []
    };
  }
  const mergedProfile = {
    ...DEFAULT_PROFILE,
    analystName: String(data.analystName || 'Operator-01').slice(0, 40),
    xp: Math.max(0, Number(data.xp) || 0),
    completedMissions: data.completedMissions || {},
    unlockedAchievements: Array.isArray(data.unlockedAchievements) ? data.unlockedAchievements : [],
    missionHistory: Array.isArray(data.missionHistory) ? data.missionHistory : []
  };
  saveProfile(mergedProfile);
  if (data.settings && typeof data.settings === 'object') {
    saveSettings({ ...DEFAULT_SETTINGS, ...data.settings });
  }
  return {
    ok: true,
    isReport: false,
    profile: mergedProfile,
    errors: []
  };
}
