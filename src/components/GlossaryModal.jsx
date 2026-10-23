import React, { useState } from 'react';
import { BookOpen, X, Search, Terminal } from 'lucide-react';
import { SOC_GLOSSARY } from '../data/glossary.js';

export function GlossaryModal({ isOpen, onClose }) {
  const [filter, setFilter] = useState('');

  if (!isOpen) return null;

  const filtered = SOC_GLOSSARY.filter(
    (item) =>
      item.term.toLowerCase().includes(filter.toLowerCase()) ||
      item.definition.toLowerCase().includes(filter.toLowerCase()) ||
      item.category.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="glossary-dialog-title"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(9, 14, 23, 0.82)',
        zIndex: 900,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px'
      }}
    >
      <div
        className="panel-elevated"
        style={{
          maxWidth: '760px',
          width: '100%',
          maxHeight: '85vh',
          display: 'flex',
          flexDirection: 'column'
        }}
      >
        <div className="panel-header">
          <h2 id="glossary-dialog-title" className="panel-title">
            <BookOpen size={16} />
            <span>SOC Analyst Field Glossary & Query Reference</span>
          </h2>
          <button type="button" className="btn btn-sm" onClick={onClose} aria-label="Close Glossary">
            <X size={14} />
            <span>Close</span>
          </button>
        </div>

        <div style={{ marginBottom: '12px', position: 'relative' }}>
          <input
            type="search"
            className="input"
            placeholder="Filter terms (e.g. IOC, SIEM, Containment, ATT&CK, False Positive)..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            aria-label="Filter glossary terms"
          />
        </div>

        <div style={{ overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '10px', paddingRight: '4px' }}>
          <div className="panel" style={{ backgroundColor: 'var(--bg-input)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--accent-cyan)', fontWeight: 600, marginBottom: '6px' }}>
              <Terminal size={14} />
              <span>Structured Query Language Quick Syntax</span>
            </div>
            <div className="mono" style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'grid', gap: '4px' }}>
              <div>• Equality / Inequality: <code>eventType = &quot;authentication&quot;</code>, <code>result != &quot;success&quot;</code></div>
              <div>• Substring Match: <code>processName CONTAINS &quot;powershell&quot;</code>, <code>commandLine CONTAINS &quot;-enc&quot;</code></div>
              <div>• List Membership: <code>severity IN (&quot;high&quot;, &quot;critical&quot;)</code></div>
              <div>• Boolean &amp; Grouping: <code>(username = &quot;r.silva&quot; OR sourceIp = &quot;198.51.100.24&quot;) AND NOT result = &quot;failure&quot;</code></div>
            </div>
          </div>

          {filtered.map((item) => (
            <div key={item.term} className="panel" style={{ padding: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <strong style={{ color: 'var(--accent-cyan)', fontSize: '14px' }}>{item.term}</strong>
                <span className="tag-chip">{item.category}</span>
              </div>
              <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '13px' }}>{item.definition}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
