import { parseTimestamp, formatRelativeDelta } from '../utils/eventSchema.js';

/**
 * Generates a chronological investigation timeline from event timestamps.
 */
export function buildInvestigationTimeline(events, evidenceItems = [], filters = {}) {
  if (!Array.isArray(events)) return [];

  const {
    entity = '',
    source = 'all',
    severity = 'all',
    eventType = 'all',
    onlyEvidence = false
  } = filters;

  const evidenceMap = new Map();
  if (Array.isArray(evidenceItems)) {
    for (const item of evidenceItems) {
      if (item.targetId) {
        evidenceMap.set(item.targetId, item);
      }
    }
  }

  let list = events.filter((ev) => {
    if (onlyEvidence && !evidenceMap.has(ev.eventId)) return false;
    if (source !== 'all' && ev.source !== source) return false;
    if (severity !== 'all' && ev.severity !== severity) return false;
    if (eventType !== 'all' && ev.eventType !== eventType) return false;
    if (entity && entity.trim()) {
      const q = entity.trim().toLowerCase();
      const match = [
        ev.host,
        ev.username,
        ev.sourceIp,
        ev.destinationIp,
        ev.domain,
        ev.processName
      ]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(q));
      if (!match) return false;
    }
    return true;
  });

  list.sort((a, b) => (parseTimestamp(a.timestamp) ?? 0) - (parseTimestamp(b.timestamp) ?? 0));

  const firstTs = list.length > 0 ? list[0].timestamp : null;

  return list.map((ev, index) => {
    const prevTs = index > 0 ? list[index - 1].timestamp : ev.timestamp;
    const evItem = evidenceMap.get(ev.eventId) || null;
    const isImportant =
      Boolean(evItem) ||
      ev.severity === 'critical' ||
      ev.severity === 'high' ||
      (Array.isArray(ev.tags) &&
        ev.tags.some((t) =>
          ['c2_beacon', 'persistence_change', 'privileged_group', 'sensitive_asset', 'suspicious_domain', 'encoded_cmd'].includes(t)
        ));

    return {
      ...ev,
      timelineIndex: index + 1,
      deltaFromStart: firstTs ? formatRelativeDelta(firstTs, ev.timestamp) : '0s',
      deltaFromPrevious: index === 0 ? 'Start' : formatRelativeDelta(prevTs, ev.timestamp),
      isEvidence: Boolean(evItem),
      evidenceRecord: evItem,
      isImportant
    };
  });
}

/**
 * Correlates events and classifies each correlation as 'confirmed', 'probable', or 'weak'
 * with an explicit rationale. Never implies causality from time proximity alone.
 */
export function correlateEvents(events) {
  if (!Array.isArray(events) || events.length < 2) return [];

  const sorted = [...events].sort(
    (a, b) => (parseTimestamp(a.timestamp) ?? 0) - (parseTimestamp(b.timestamp) ?? 0)
  );

  const correlations = [];
  const seenPairs = new Set();

  for (let i = 0; i < sorted.length; i++) {
    const evA = sorted[i];
    const tA = parseTimestamp(evA.timestamp) ?? 0;

    for (let j = i + 1; j < sorted.length; j++) {
      const evB = sorted[j];
      const tB = parseTimestamp(evB.timestamp) ?? 0;
      const diffSec = Math.round(Math.abs(tB - tA) / 1000);

      // Only correlate within 2 hours unless explicitly linked
      const explicitLink =
        (Array.isArray(evA.metadata?.relatedEventIds) &&
          evA.metadata.relatedEventIds.includes(evB.eventId)) ||
        (Array.isArray(evB.metadata?.relatedEventIds) &&
          evB.metadata.relatedEventIds.includes(evA.eventId));

      if (diffSec > 7200 && !explicitLink) continue;

      const pairKey = `${evA.eventId}<->${evB.eventId}`;
      if (seenPairs.has(pairKey)) continue;

      const reasons = [];
      let confidence = null;

      // 1. Explicit dataset correlation or parent-child process execution on same host
      if (explicitLink) {
        confidence = 'confirmed';
        reasons.push(
          `Explicit telemetry linkage between ${evA.eventId} (${evA.source}) and ${evB.eventId} (${evB.source}).`
        );
      }

      if (
        evA.host &&
        evA.host === evB.host &&
        evA.processName &&
        evB.parentProcess &&
        evA.processName.toLowerCase() === evB.parentProcess.toLowerCase() &&
        diffSec <= 900
      ) {
        confidence = 'confirmed';
        reasons.push(
          `Process lineage on host ${evA.host}: process "${evA.processName}" spawned child "${evB.processName || evB.eventType}" (+${diffSec}s).`
        );
      }

      // 2. Cross-source shared network indicator (IP or domain)
      const sharedIp =
        (evA.sourceIp && (evA.sourceIp === evB.sourceIp || evA.sourceIp === evB.destinationIp) && evA.sourceIp) ||
        (evA.destinationIp &&
          (evA.destinationIp === evB.sourceIp || evA.destinationIp === evB.destinationIp) &&
          evA.destinationIp);

      if (sharedIp && evA.source !== evB.source && diffSec <= 1800) {
        if (!confidence) confidence = 'probable';
        reasons.push(
          `Cross-source IP pivot (${sharedIp}) shared between ${evA.source} and ${evB.source} within ${diffSec}s.`
        );
      }

      if (evA.domain && evB.domain && evA.domain === evB.domain && diffSec <= 1800) {
        if (!confidence) confidence = 'probable';
        reasons.push(`Shared domain indicator "${evA.domain}" across ${evA.eventType} and ${evB.eventType}.`);
      }

      // 3. Shared user identity and host across different telemetry types
      if (
        evA.username &&
        evA.username === evB.username &&
        evA.eventType !== evB.eventType &&
        diffSec <= 900
      ) {
        if (!confidence) confidence = 'probable';
        reasons.push(
          `User "${evA.username}" performed "${evA.eventType}" followed by "${evB.eventType}" within ${diffSec}s.`
        );
      }

      // 4. Weak time-proximity correlation on same host without direct indicator link
      if (
        !confidence &&
        evA.host &&
        evA.host === evB.host &&
        diffSec <= 120 &&
        (evA.severity === 'high' || evA.severity === 'critical') &&
        (evB.severity === 'high' || evB.severity === 'critical')
      ) {
        confidence = 'weak';
        reasons.push(
          `Temporal proximity (${diffSec}s apart) on host ${evA.host}. Note: Time proximity alone does not confirm causality; verify process or user lineage.`
        );
      }

      if (confidence && reasons.length > 0) {
        seenPairs.add(pairKey);
        correlations.push({
          id: `CORR-${evA.eventId}-${evB.eventId}`,
          sourceEventId: evA.eventId,
          targetEventId: evB.eventId,
          sourceEvent: evA,
          targetEvent: evB,
          timeDeltaSeconds: diffSec,
          confidence,
          rationale: reasons.join(' ')
        });
      }
    }
  }

  const rankOrder = { confirmed: 3, probable: 2, weak: 1 };
  correlations.sort((a, b) => {
    const rDiff = (rankOrder[b.confidence] || 0) - (rankOrder[a.confidence] || 0);
    if (rDiff !== 0) return rDiff;
    return a.timeDeltaSeconds - b.timeDeltaSeconds;
  });

  return correlations;
}

/**
 * Extracts entities and relationships for the Relationship Explorer (graph + table).
 */
export function buildEntityGraph(events, evidenceItems = []) {
  if (!Array.isArray(events)) {
    return { nodes: [], edges: [] };
  }

  const evidenceSet = new Set(
    (evidenceItems || []).map((item) => item.targetId)
  );

  const nodeMap = new Map();
  const edgeMap = new Map();

  function upsertNode(type, value, event) {
    if (!value || typeof value !== 'string') return null;
    const id = `${type}:${value}`;
    if (!nodeMap.has(id)) {
      nodeMap.set(id, {
        id,
        type,
        label: value,
        eventIds: new Set(),
        maxSeverity: event.severity || 'low',
        hasEvidence: false
      });
    }
    const node = nodeMap.get(id);
    node.eventIds.add(event.eventId);
    if (evidenceSet.has(event.eventId) || evidenceSet.has(value)) {
      node.hasEvidence = true;
    }
    const sevOrder = { low: 1, medium: 2, high: 3, critical: 4 };
    if ((sevOrder[event.severity] || 1) > (sevOrder[node.maxSeverity] || 1)) {
      node.maxSeverity = event.severity;
    }
    return id;
  }

  function upsertEdge(fromId, toId, relation, eventId, confidence = 'probable') {
    if (!fromId || !toId || fromId === toId) return;
    const key = [fromId, toId].sort().join('--') + `::${relation}`;
    if (!edgeMap.has(key)) {
      edgeMap.set(key, {
        id: key,
        source: fromId,
        target: toId,
        relation,
        confidence,
        eventIds: new Set()
      });
    }
    edgeMap.get(key).eventIds.add(eventId);
  }

  for (const ev of events) {
    const hostId = upsertNode('host', ev.host, ev);
    const userId = upsertNode('user', ev.username, ev);
    const srcIpId = upsertNode('ip', ev.sourceIp, ev);
    const dstIpId = upsertNode('ip', ev.destinationIp, ev);
    const domainId = upsertNode('domain', ev.domain, ev);
    const procId = upsertNode('process', ev.processName, ev);

    if (userId && hostId) upsertEdge(userId, hostId, 'authenticated_on', ev.eventId, 'confirmed');
    if (srcIpId && userId) upsertEdge(srcIpId, userId, 'source_ip_for', ev.eventId, 'confirmed');
    if (srcIpId && hostId) upsertEdge(srcIpId, hostId, 'connected_to', ev.eventId, 'probable');
    if (hostId && procId) upsertEdge(hostId, procId, 'executed_process', ev.eventId, 'confirmed');
    if (hostId && domainId) upsertEdge(hostId, domainId, 'queried_domain', ev.eventId, 'confirmed');
    if (domainId && dstIpId) upsertEdge(domainId, dstIpId, 'resolved_to', ev.eventId, 'confirmed');
    if (hostId && dstIpId) upsertEdge(hostId, dstIpId, 'egress_to', ev.eventId, 'probable');
  }

  const nodes = Array.from(nodeMap.values()).map((n) => ({
    ...n,
    eventCount: n.eventIds.size,
    eventIds: Array.from(n.eventIds)
  }));

  const edges = Array.from(edgeMap.values()).map((e) => ({
    ...e,
    weight: e.eventIds.size,
    eventIds: Array.from(e.eventIds)
  }));

  return { nodes, edges };
}
