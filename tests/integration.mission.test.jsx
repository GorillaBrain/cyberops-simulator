import React from 'react';
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { App } from '../src/app/App.jsx';

describe('CyberOps Simulator — End-to-End Integration & Regression Tests', () => {
  beforeEach(() => {
    localStorage.clear();
    window.history.pushState({}, '', '/');
  });

  it('completes a benign false-positive investigation end-to-end (Mission 1: The Noisy Login)', () => {
    render(<App />);

    // 1. Verify Main Menu loads with empty new-player state
    expect(screen.getByText(/Detect the signal\. Investigate the evidence\. Stop the threat\./i)).toBeInTheDocument();

    // 2. Launch Mission 1 into Workstation
    const startBtn = screen.getByRole('button', { name: /Start Tutorial: Mission 1/i });
    fireEvent.click(startBtn);

    // 3. Search the event data using the Structured Query input
    const queryInput = screen.getByLabelText(/Structured Query Language/i);
    fireEvent.change(queryInput, { target: { value: 'username = "analyst.test"' } });
    fireEvent.click(screen.getByRole('button', { name: /Run Query/i }));

    // 4. Collect at least 2 core evidence items (EVT-101, EVT-106)
    const addEvt101Btn = screen.getByRole('button', { name: /Add EVT-101 to Evidence/i });
    fireEvent.click(addEvt101Btn);
    const addEvt106Btn = screen.getByRole('button', { name: /Add EVT-106 to Evidence/i });
    fireEvent.click(addEvt106Btn);

    // Verify Evidence Locker updated
    expect(screen.getByText(/Evidence Locker \(2\)/i)).toBeInTheDocument();

    // 5. Inspect the Timeline tab
    fireEvent.click(screen.getByRole('tab', { name: /2\. Timeline & Correlation/i }));
    expect(screen.getByText(/Chronological Investigation Timeline/i)).toBeInTheDocument();

    // 6. Execute Detection Rules
    fireEvent.click(screen.getByRole('tab', { name: /3\. Detection Rules & ATT&CK/i }));
    fireEvent.click(screen.getByRole('button', { name: /Execute All 12 Detection Rules/i }));
    expect(screen.getByText(/Triggered Detection Findings/i)).toBeInTheDocument();

    // 7. Execute a proportionate simulated disposition action (Close Alert as Benign)
    fireEvent.click(screen.getByRole('tab', { name: /4\. Response & Containment/i }));
    const actionSelect = screen.getByLabelText(/Response \/ Disposition Action/i);
    fireEvent.change(actionSelect, { target: { value: 'dismiss_benign' } });
    fireEvent.click(screen.getByRole('button', { name: /Execute Simulated Action/i }));
    expect(screen.getByText(/Executed Response Log \(1\)/i)).toBeInTheDocument();

    // 8. Complete and submit the Incident Assessment Report
    fireEvent.click(screen.getByRole('tab', { name: /5\. Incident Assessment & Debrief/i }));
    fireEvent.change(screen.getByLabelText(/1\. Incident Classification/i), {
      target: { value: 'benign_activity' }
    });
    fireEvent.change(screen.getByLabelText(/2\. Incident Severity/i), {
      target: { value: 'low' }
    });
    fireEvent.change(screen.getByLabelText(/4\. Primary Affected User/i), {
      target: { value: 'analyst.test, WKSTN-HR-02' }
    });
    fireEvent.change(screen.getByLabelText(/6\. Key Findings/i), {
      target: {
        value: 'Scheduled 90-day password expiration caused user typos from assigned laptop before FIDO2 MFA reset.'
      }
    });

    fireEvent.click(screen.getByRole('button', { name: /Submit Final Report & View Debrief/i }));

    // 9. Verify Debrief & Progression screen renders with high score and XP
    expect(screen.getByText(/POST-INCIDENT DEBRIEF & EVALUATION/i)).toBeInTheDocument();
    expect(screen.getByText(/Multi-Dimensional Performance Breakdown/i)).toBeInTheDocument();
  });

  it('completes a malicious incident investigation end-to-end (Mission 2: Password Spray)', () => {
    render(<App />);

    // Open Mission 2 Briefing from Main Menu
    const m2Card = screen.getByText(/Mission 2: Password Spray/i).closest('.panel');
    const openBriefingBtn = within(m2Card).getByRole('button', { name: /Open Briefing/i });
    fireEvent.click(openBriefingBtn);

    // Begin Investigation
    fireEvent.click(screen.getByRole('button', { name: /Begin Investigation/i }));

    // Collect 3 core evidence items: EVT-201, EVT-206, EVT-207
    fireEvent.click(screen.getByRole('button', { name: /Add EVT-201 to Evidence/i }));
    fireEvent.click(screen.getByRole('button', { name: /Add EVT-206 to Evidence/i }));
    fireEvent.click(screen.getByRole('button', { name: /Add EVT-207 to Evidence/i }));

    // Execute Response actions: Block IP 198.51.100.24 & Disable Account r.silva
    fireEvent.click(screen.getByRole('tab', { name: /4\. Response & Containment/i }));
    const actionSelect = screen.getByLabelText(/Response \/ Disposition Action/i);
    const targetInput = screen.getByLabelText(/Target Entity/i);

    fireEvent.change(actionSelect, { target: { value: 'block_ip' } });
    fireEvent.change(targetInput, { target: { value: '198.51.100.24' } });
    fireEvent.click(screen.getByRole('button', { name: /Execute Simulated Action/i }));

    fireEvent.change(actionSelect, { target: { value: 'disable_account' } });
    fireEvent.change(targetInput, { target: { value: 'r.silva' } });
    fireEvent.click(screen.getByRole('button', { name: /Execute Simulated Action/i }));

    // Submit Incident Report
    fireEvent.click(screen.getByRole('tab', { name: /5\. Incident Assessment & Debrief/i }));
    fireEvent.change(screen.getByLabelText(/1\. Incident Classification/i), {
      target: { value: 'malicious_incident' }
    });
    fireEvent.change(screen.getByLabelText(/2\. Incident Severity/i), {
      target: { value: 'high' }
    });
    fireEvent.change(screen.getByLabelText(/4\. Primary Affected User/i), {
      target: { value: 'r.silva, 198.51.100.24, SSO-GW-01' }
    });
    fireEvent.change(screen.getByLabelText(/6\. Key Findings/i), {
      target: {
        value: 'Password spray from 198.51.100.24 compromised legacy account r.silva and exported GAL.'
      }
    });

    fireEvent.click(screen.getByRole('button', { name: /Submit Final Report & View Debrief/i }));
    expect(screen.getByText(/Mission 2: Password Spray — Debrief/i)).toBeInTheDocument();
  });

  it('handles invalid queries gracefully and blocks submission when mandatory fields are missing', () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: /Start Tutorial: Mission 1/i }));

    // Enter invalid query syntax
    const queryInput = screen.getByLabelText(/Structured Query Language/i);
    fireEvent.change(queryInput, { target: { value: 'eventType = ' } });
    fireEvent.click(screen.getByRole('button', { name: /Run Query/i }));

    expect(screen.getByRole('alert')).toHaveTextContent(/Query Syntax Error/i);

    // Attempt to submit report with zero evidence and empty fields
    fireEvent.click(screen.getByRole('tab', { name: /5\. Incident Assessment & Debrief/i }));
    fireEvent.click(screen.getByRole('button', { name: /Submit Final Report & View Debrief/i }));

    expect(screen.getByRole('alert')).toHaveTextContent(/Please complete the following mandatory criteria/i);
  });

  it('renders Unavailable for missing optional event fields and opens the SOC Field Glossary', () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: /Start Tutorial: Mission 1/i }));

    // EVT-101 is an account_change event without a domain or processName
    expect(screen.getAllByText('Unavailable').length).toBeGreaterThan(0);

    // Open Glossary modal
    const glossaryBtns = screen.getAllByRole('button', { name: /Glossary/i });
    fireEvent.click(glossaryBtns[0]);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText(/SOC Analyst Field Glossary/i)).toBeInTheDocument();
  });

  it('supports Practice Lab, Endless Alert Triage, and Custom Scenario Import', () => {
    render(<App />);
    fireEvent.click(screen.getAllByRole('button', { name: /Practice Lab & Triage/i })[0]);

    expect(screen.getByText(/SOC Telemetry Practice Lab/i)).toBeInTheDocument();

    // Switch to Endless Alert Triage
    fireEvent.click(screen.getByRole('button', { name: /Endless Alert Triage/i }));
    expect(screen.getByText(/Rapid Alert Triage Drill/i)).toBeInTheDocument();

    // Switch to Custom Scenario Import and launch sample custom scenario
    fireEvent.click(screen.getByRole('button', { name: /Custom Scenario Import/i }));
    fireEvent.click(screen.getByRole('button', { name: /Validate & Launch Custom Scenario/i }));

    expect(screen.getByText(/Custom Scenario: The Conference USB Drop/i)).toBeInTheDocument();
  });

  it('supports TryHackMe-style step-by-step guided tasks and interactive Check-In Flag verification', () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: /Start Tutorial: Mission 1/i }));

    // Verify Commander Vela mentor banner and Task 1 accordion are visible
    expect(screen.getByText(/Commander Vela \(Senior SOC Lead\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Task 1: Filter the Login Logs/i)).toBeInTheDocument();

    // Load suggested query with 1 click
    fireEvent.click(screen.getByRole('button', { name: /Load Into Search: username = "analyst.test"/i }));

    // Submit the Check-In Question answer for Task 1 (WKSTN-HR-02)
    const checkInput = screen.getByLabelText(/Answer for Task 1: Filter the Login Logs/i);
    fireEvent.change(checkInput, { target: { value: 'WKSTN-HR-02' } });
    fireEvent.click(screen.getByRole('button', { name: /Submit Answer/i }));

    // Verify Task 1 is solved and explanation is displayed
    expect(screen.getByText(/Spot on! All login attempts came from WKSTN-HR-02/i)).toBeInTheDocument();
  });
});
