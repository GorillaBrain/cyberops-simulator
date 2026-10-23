import { parseQuery, evaluateQueryAst, resolveEventField } from './queryEngine.js';
import { parseTimestamp } from '../utils/eventSchema.js';

/**
 * Evaluates a single detection rule against a dataset of events.
 * Supports:
 * - "single": conditionQuery match with contextual evaluation
 * - "threshold": sliding time-window aggregation with optional distinctField count
 * - "sequence": two-stage event correlation within a time window sharing an entity key
 */
export function evaluateDetectionRule(rule, events) {
  if (!rule || !Array.isArray(events) || events.length === 0) {
    return [];
  }

  // Filter to supported sources if specified
  const sourceFiltered = Array.isArray(rule.supportedSources) && rule.supportedSources.length > 0
    ? events.filter((ev) => rule.supportedSources.includes(ev.source) || rule.supportedSources.includes(ev.eventType))
    : events;

  const sortedEvents = [...sourceFiltered].sort(
    (a, b) => (parseTimestamp(a.timestamp) ?? 0) - (parseTimestamp(b.timestamp) ?? 0)
  );

  const findings = [];
  const seenFindingKeys = new Set();

  if (rule.type === 'threshold' && rule.aggregation) {
    const ast = parseQuery(rule.conditionQuery);
    const matching = sortedEvents.filter((ev) => evaluateQueryAst(ast, ev));
    const {
      groupBy = 'username',
      windowSeconds = 300,
      threshold = 3,
      distinctField = null,
      distinctThreshold = 1
    } = rule.aggregation;

    // Group matching events by groupBy key
    const groups = new Map();
    for (const ev of matching) {
      const keyVal = resolveEventField(ev, groupBy);
      if (!keyVal) continue;
      const key = String(keyVal);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(ev);
    }

    for (const [groupKey, groupEvents] of groups.entries()) {
      // Sliding window evaluation
      for (let i = 0; i < groupEvents.length; i++) {
        const startMs = parseTimestamp(groupEvents[i].timestamp);
        if (startMs === null) continue;
        const endLimitMs = startMs + windowSeconds * 1000;
        const windowEvents = [];
        for (let j = i; j < groupEvents.length; j++) {
          const currMs = parseTimestamp(groupEvents[j].timestamp);
          if (currMs !== null && currMs <= endLimitMs) {
            windowEvents.push(groupEvents[j]);
          } else {
            break;
          }
        }

        if (windowEvents.length >= threshold) {
          let distinctCount = 1;
          let distinctValues = [];
          if (distinctField) {
            const set = new Set(
              windowEvents.map((e) => resolveEventField(e, distinctField)).filter(Boolean)
            );
            distinctCount = set.size;
            distinctValues = Array.from(set);
          }

          if (!distinctField || distinctCount >= distinctThreshold) {
            const eventIds = windowEvents.map((e) => e.eventId);
            const dedupKey = `${rule.id}::${groupKey}`;
            if (!seenFindingKeys.has(dedupKey)) {
              seenFindingKeys.add(dedupKey);
              findings.push({
                findingId: `${rule.id}-${groupKey.replace(/[^a-zA-Z0-9_-]/g, '_')}`,
                ruleId: rule.id,
                ruleName: rule.name,
                severity: rule.severity,
                status: 'alert_triggered',
                triggeredAt: windowEvents[windowEvents.length - 1].timestamp,
                entityKey: `${groupBy}: ${groupKey}`,
                matchedEventIds: eventIds,
                matchedEvents: windowEvents,
                whyTriggered: distinctField
                  ? `Observed ${windowEvents.length} matching events from ${groupBy}="${groupKey}" targeting ${distinctCount} distinct ${distinctField}s (${distinctValues.slice(0, 5).join(', ')}) within ${windowSeconds}s (threshold: >=${threshold} events, >=${distinctThreshold} distinct ${distinctField}).`
                  : `Observed ${windowEvents.length} matching events for ${groupBy}="${groupKey}" within a ${windowSeconds}s window (threshold: >=${threshold}).`,
                attackMappings: rule.attackMappings || [],
                falsePositiveConsiderations: rule.falsePositiveConsiderations,
                remediationGuidance: rule.remediationGuidance
              });
            }
          }
        }
      }
    }
    return findings;
  }

  if (rule.type === 'sequence' && rule.sequence) {
    const {
      step1Query,
      step1MinCount = 1,
      step2Query,
      sharedField = 'username',
      windowSeconds = 600
    } = rule.sequence;

    const ast1 = parseQuery(step1Query);
    const ast2 = parseQuery(step2Query);
    const step1Events = sortedEvents.filter((ev) => evaluateQueryAst(ast1, ev));
    const step2Events = sortedEvents.filter((ev) => evaluateQueryAst(ast2, ev));

    for (const ev2 of step2Events) {
      const entityVal = resolveEventField(ev2, sharedField);
      if (!entityVal) continue;
      const t2 = parseTimestamp(ev2.timestamp);
      if (t2 === null) continue;

      const priorStep1 = step1Events.filter((ev1) => {
        if (ev1.eventId === ev2.eventId) return false;
        const val1 = resolveEventField(ev1, sharedField);
        if (String(val1) !== String(entityVal)) return false;
        const t1 = parseTimestamp(ev1.timestamp);
        return t1 !== null && t1 <= t2 && t2 - t1 <= windowSeconds * 1000;
      });

      if (priorStep1.length >= step1MinCount) {
        const dedupKey = `${rule.id}::${entityVal}::${ev2.eventId}`;
        if (!seenFindingKeys.has(dedupKey)) {
          seenFindingKeys.add(dedupKey);
          const combined = [...priorStep1, ev2];
          findings.push({
            findingId: `${rule.id}-${String(entityVal).replace(/[^a-zA-Z0-9_-]/g, '_')}-${ev2.eventId}`,
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            status: 'alert_triggered',
            triggeredAt: ev2.timestamp,
            entityKey: `${sharedField}: ${entityVal}`,
            matchedEventIds: combined.map((e) => e.eventId),
            matchedEvents: combined,
            whyTriggered: `Sequence matched on ${sharedField}="${entityVal}": ${priorStep1.length} prior prerequisite event(s) followed by "${ev2.eventType}" (${ev2.eventId}) within ${windowSeconds}s.`,
            attackMappings: rule.attackMappings || [],
            falsePositiveConsiderations: rule.falsePositiveConsiderations,
            remediationGuidance: rule.remediationGuidance
          });
        }
      }
    }
    return findings;
  }

  // Default: single-event condition evaluation with optional exclusion query
  const ast = parseQuery(rule.conditionQuery);
  const excludeAst = rule.exclusionQuery ? parseQuery(rule.exclusionQuery) : null;

  for (const ev of sortedEvents) {
    if (evaluateQueryAst(ast, ev)) {
      if (excludeAst && evaluateQueryAst(excludeAst, ev)) {
        continue;
      }
      const dedupKey = `${rule.id}::${ev.eventId}`;
      if (!seenFindingKeys.has(dedupKey)) {
        seenFindingKeys.add(dedupKey);
        const primaryEntity = ev.host || ev.username || ev.sourceIp || ev.domain || ev.eventId;
        findings.push({
          findingId: `${rule.id}-${ev.eventId}`,
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          status: 'alert_triggered',
          triggeredAt: ev.timestamp,
          entityKey: primaryEntity,
          matchedEventIds: [ev.eventId],
          matchedEvents: [ev],
          whyTriggered: `Event ${ev.eventId} on ${primaryEntity} matched detection condition: ${rule.conditionSummary || rule.conditionQuery}.`,
          attackMappings: rule.attackMappings || [],
          falsePositiveConsiderations: rule.falsePositiveConsiderations,
          remediationGuidance: rule.remediationGuidance
        });
      }
    }
  }

  return findings;
}

/**
 * Evaluates a set of detection rules against the current mission dataset.
 * Deduplicates findings across repeated runs.
 */
export function runAllDetections(rules, events) {
  if (!Array.isArray(rules) || !Array.isArray(events)) {
    return [];
  }
  const allFindings = [];
  const seenIds = new Set();

  for (const rule of rules) {
    const ruleFindings = evaluateDetectionRule(rule, events);
    for (const f of ruleFindings) {
      if (!seenIds.has(f.findingId)) {
        seenIds.add(f.findingId);
        allFindings.push(f);
      }
    }
  }

  return allFindings.sort(
    (a, b) => (parseTimestamp(a.triggeredAt) ?? 0) - (parseTimestamp(b.triggeredAt) ?? 0)
  );
}
