export const VALID_EVENT_TYPES = [
  'authentication',
  'process_execution',
  'dns_query',
  'firewall_connection',
  'web_proxy',
  'file_activity',
  'account_change',
  'endpoint_detection'
];

export const VALID_SEVERITIES = ['low', 'medium', 'high', 'critical'];

export const SEVERITY_RANK = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export const VALID_SOURCES = [
  'iam_auth',
  'edr_sensor',
  'dns_resolver',
  'perimeter_fw',
  'secure_proxy',
  'file_integrity',
  'directory_svc',
  'siem_alert'
];

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Recursively strips prototype-pollution keys and returns a clean plain object/value.
 */
export function sanitizeObject(input, depth = 0) {
  if (depth > 12) {
    throw new Error('Object nesting exceeds maximum safe depth of 12.');
  }
  if (input === null || typeof input !== 'object') {
    return input;
  }
  if (Array.isArray(input)) {
    return input.map((item) => sanitizeObject(item, depth + 1));
  }
  const clean = Object.create(null);
  for (const [key, value] of Object.entries(input)) {
    if (DANGEROUS_KEYS.has(key)) {
      throw new Error(`Forbidden property key detected: ${key}`);
    }
    clean[key] = sanitizeObject(value, depth + 1);
  }
  return Object.assign({}, clean);
}

/**
 * Parses an ISO 8601 timestamp string and returns epoch milliseconds or null if invalid.
 */
export function parseTimestamp(ts) {
  if (typeof ts !== 'string' || !ts.trim()) return null;
  // Require ISO-8601 date-time structure with timezone (Z or +/-HH:MM)
  const isoRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$/;
  if (!isoRegex.test(ts.trim())) return null;
  const ms = Date.parse(ts.trim());
  return Number.isNaN(ms) ? null : ms;
}

/**
 * Formats an ISO timestamp for readable display in UTC.
 */
export function formatTimestamp(ts, includeDate = true) {
  const ms = parseTimestamp(ts);
  if (ms === null) return 'Unavailable';
  const d = new Date(ms);
  const iso = d.toISOString();
  if (!includeDate) {
    return iso.slice(11, 19) + ' UTC';
  }
  return iso.slice(0, 10) + ' ' + iso.slice(11, 19) + ' UTC';
}

/**
 * Formats relative time delta between two ISO timestamps.
 */
export function formatRelativeDelta(baseTs, currentTs) {
  const baseMs = parseTimestamp(baseTs);
  const currMs = parseTimestamp(currentTs);
  if (baseMs === null || currMs === null) return 'N/A';
  const diffSec = Math.round((currMs - baseMs) / 1000);
  if (diffSec === 0) return '0s';
  const sign = diffSec > 0 ? '+' : '-';
  const abs = Math.abs(diffSec);
  if (abs < 60) return `${sign}${abs}s`;
  if (abs < 3600) {
    const m = Math.floor(abs / 60);
    const s = abs % 60;
    return s > 0 ? `${sign}${m}m ${s}s` : `${sign}${m}m`;
  }
  const h = Math.floor(abs / 3600);
  const m = Math.floor((abs % 3600) / 60);
  return m > 0 ? `${sign}${h}h ${m}m` : `${sign}${h}h`;
}

/**
 * Validates a canonical security event record.
 */
export function validateEventRecord(event) {
  const errors = [];
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    return { valid: false, errors: ['Event must be a non-null object.'] };
  }
  if (typeof event.eventId !== 'string' || !event.eventId.trim()) {
    errors.push('Missing or invalid eventId.');
  }
  if (parseTimestamp(event.timestamp) === null) {
    errors.push(`Invalid or non-timezone-aware ISO 8601 timestamp: "${event.timestamp}".`);
  }
  if (typeof event.source !== 'string' || !event.source.trim()) {
    errors.push('Missing or invalid telemetry source.');
  }
  if (!VALID_EVENT_TYPES.includes(event.eventType)) {
    errors.push(`Invalid eventType "${event.eventType}". Expected one of: ${VALID_EVENT_TYPES.join(', ')}.`);
  }
  if (!VALID_SEVERITIES.includes(event.severity)) {
    errors.push(`Invalid severity "${event.severity}". Expected one of: ${VALID_SEVERITIES.join(', ')}.`);
  }
  if (typeof event.message !== 'string' || !event.message.trim()) {
    errors.push('Missing or empty message.');
  }
  if (event.tags !== undefined && (!Array.isArray(event.tags) || event.tags.some((t) => typeof t !== 'string'))) {
    errors.push('tags must be an array of strings when provided.');
  }
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Validates an entire dataset of events, checking uniqueness of eventIds.
 */
export function validateEventDataset(events, maxEvents = 2500) {
  if (!Array.isArray(events)) {
    return { valid: false, errors: ['Dataset must be an array of events.'] };
  }
  if (events.length === 0) {
    return { valid: false, errors: ['Dataset must contain at least one event.'] };
  }
  if (events.length > maxEvents) {
    return { valid: false, errors: [`Dataset exceeds maximum allowed event count (${maxEvents}).`] };
  }
  const seenIds = new Set();
  const errors = [];
  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    const res = validateEventRecord(ev);
    if (!res.valid) {
      errors.push(`Event [${i}]: ${res.errors.join(' ')}`);
    } else if (seenIds.has(ev.eventId)) {
      errors.push(`Duplicate eventId detected: "${ev.eventId}".`);
    } else {
      seenIds.add(ev.eventId);
    }
    if (errors.length >= 10) break;
  }
  return { valid: errors.length === 0, errors };
}

/**
 * Validates an imported custom scenario JSON payload safely.
 */
export function validateImportedScenario(rawJsonString, maxBytes = 1024 * 512) {
  if (typeof rawJsonString !== 'string') {
    return { valid: false, errors: ['Import payload must be a JSON string.'] };
  }
  if (rawJsonString.length > maxBytes) {
    return { valid: false, errors: [`Import file exceeds maximum size limit of ${Math.round(maxBytes / 1024)} KB.`] };
  }
  let parsed;
  try {
    parsed = sanitizeObject(JSON.parse(rawJsonString));
  } catch (err) {
    return { valid: false, errors: [`Invalid JSON or unsafe payload: ${err.message}`] };
  }

  const errors = [];
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { valid: false, errors: ['Scenario root must be a JSON object.'] };
  }
  if (typeof parsed.id !== 'string' || !/^[a-zA-Z0-9_-]{3,64}$/.test(parsed.id)) {
    errors.push('Scenario id must be an alphanumeric slug (3-64 chars).');
  }
  if (typeof parsed.title !== 'string' || parsed.title.trim().length < 3) {
    errors.push('Scenario title is required (minimum 3 characters).');
  }
  if (typeof parsed.organization !== 'string' || !parsed.organization.trim()) {
    errors.push('Scenario organization is required.');
  }
  if (!parsed.briefing || typeof parsed.briefing.summary !== 'string') {
    errors.push('Scenario briefing.summary is required.');
  }
  if (!Array.isArray(parsed.events)) {
    errors.push('Scenario events array is required.');
  } else {
    const dsValidation = validateEventDataset(parsed.events, 1000);
    if (!dsValidation.valid) {
      errors.push(...dsValidation.errors);
    }
  }
  if (!parsed.groundTruth || typeof parsed.groundTruth !== 'object') {
    errors.push('Scenario groundTruth object is required.');
  } else {
    const validClassifications = ['malicious_incident', 'benign_activity', 'inconclusive'];
    if (!validClassifications.includes(parsed.groundTruth.classification)) {
      errors.push(`groundTruth.classification must be one of: ${validClassifications.join(', ')}.`);
    }
    if (!VALID_SEVERITIES.includes(parsed.groundTruth.severity)) {
      errors.push(`groundTruth.severity must be one of: ${VALID_SEVERITIES.join(', ')}.`);
    }
    if (!Array.isArray(parsed.groundTruth.expectedEvidenceIds)) {
      errors.push('groundTruth.expectedEvidenceIds must be an array of eventIds.');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    scenario: errors.length === 0 ? parsed : null
  };
}

/**
 * Validates an imported game save or incident report JSON file.
 */
export function validateImportedSave(rawJsonString, maxBytes = 1024 * 1024) {
  if (typeof rawJsonString !== 'string') {
    return { valid: false, errors: ['Import payload must be a string.'] };
  }
  if (rawJsonString.length > maxBytes) {
    return { valid: false, errors: ['Save file exceeds maximum allowed size (1 MB).'] };
  }
  let parsed;
  try {
    parsed = sanitizeObject(JSON.parse(rawJsonString));
  } catch (err) {
    return { valid: false, errors: [`Malformed JSON: ${err.message}`] };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { valid: false, errors: ['Root save payload must be a JSON object.'] };
  }
  if (parsed.exportType !== 'cyberops_save_v1' && parsed.exportType !== 'cyberops_report_v1') {
    return { valid: false, errors: ['Unrecognized exportType. Expected "cyberops_save_v1" or "cyberops_report_v1".'] };
  }
  if (parsed.exportType === 'cyberops_save_v1') {
    if (typeof parsed.xp !== 'number' || parsed.xp < 0 || !Number.isFinite(parsed.xp)) {
      return { valid: false, errors: ['Invalid xp value in save file.'] };
    }
    if (!parsed.completedMissions || typeof parsed.completedMissions !== 'object') {
      return { valid: false, errors: ['Missing completedMissions map in save file.'] };
    }
  }
  return { valid: true, errors: [], data: parsed };
}
