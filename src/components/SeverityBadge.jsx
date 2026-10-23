import React from 'react';
import { AlertOctagon, AlertTriangle, Info, ShieldAlert, CheckCircle2 } from 'lucide-react';

export function SeverityBadge({ severity = 'low', labelOverride = null }) {
  const norm = String(severity || 'low').toLowerCase();

  let cls = 'sev-low';
  let Icon = Info;
  let text = labelOverride || norm.toUpperCase();

  if (norm === 'critical') {
    cls = 'sev-critical';
    Icon = AlertOctagon;
  } else if (norm === 'high') {
    cls = 'sev-high';
    Icon = ShieldAlert;
  } else if (norm === 'medium') {
    cls = 'sev-medium';
    Icon = AlertTriangle;
  } else if (norm === 'safe' || norm === 'benign' || norm === 'appropriate') {
    cls = 'sev-safe';
    Icon = CheckCircle2;
  }

  return (
    <span className={`sev-badge ${cls}`} title={`Severity: ${text}`}>
      <Icon size={12} aria-hidden="true" />
      <span>{text}</span>
    </span>
  );
}
