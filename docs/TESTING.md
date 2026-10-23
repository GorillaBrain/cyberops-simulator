# Testing Guide

CyberOps Simulator includes unit, integration, and regression tests powered by **Vitest**, **React Testing Library**, and **jsdom**.

## Running Tests

```bash
# Run all tests once
npm test

# Run tests in interactive watch mode
npm run test:watch
```

## Test Suite Structure

### 1. Unit Tests (`tests/engine.unit.test.js`)
Tests the standalone game engine (`src/engine/*` and `src/utils/*`) without rendering React:
- Canonical event schema validation across all 8 campaign datasets.
- ISO 8601 timestamp parsing and relative time formatting.
- Structured query tokenizer, recursive-descent parser, and AST evaluator across all required operators (`=`, `!=`, `>`, `<`, `CONTAINS`, `IN`, `AND`, `OR`, `NOT`, parentheses).
- Detection rule evaluation (`DET-001` through `DET-012`), sliding time-window threshold logic, sequence matching, benign `CcmExec.exe` exclusions, and finding deduplication.
- Timeline generation, multi-source correlation grading (`confirmed`, `probable`, `weak`), and entity relationship graph extraction.
- Mission state machine transitions and mandatory completion readiness checks.
- Response consequence simulation, premature containment detection, and operational disruption penalties.
- Multi-dimensional scoring, anti-lucky-guess caps, rank progression, achievement unlocking, and replay XP deduplication.
- Save/restore serialization and prototype-pollution blocking.

### 2. Integration & Regression Tests (`tests/integration.mission.test.jsx`)
Tests complete user flows through the rendered React application:
- Full end-to-end benign false-positive investigation (*Mission 1: The Noisy Login*).
- Full end-to-end malicious incident investigation (*Mission 2: Password Spray*).
- Graceful handling of invalid query syntax and incomplete incident report submissions.
- Rendering `Unavailable` for absent optional event fields and opening the SOC Field Glossary modal.
- Navigating and interacting with the Practice Lab, Endless Alert Triage mode, and Custom Scenario importer.
