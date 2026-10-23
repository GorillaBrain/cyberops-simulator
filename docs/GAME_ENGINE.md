# Game Engine Design

## Core Modules

### 1. Mission Lifecycle State Machine (`src/engine/missionStateMachine.js`)
Manages valid state transitions across:
- `locked`
- `available`
- `briefing`
- `investigating`
- `ready_for_assessment`
- `completed`
- `failed`
- `replay`

Transitioning to `completed` invokes `validateMissionCompletionReadiness(mission, investigationState)`, which verifies that the analyst has collected the minimum required evidence, executed at least one response/disposition action, and completed all mandatory assessment fields.

### 2. Structured Query Engine (`src/engine/queryEngine.js`)
Implements a three-stage pipeline:
1. **Tokenizer (`tokenizeQuery`)**: Scans operators (`=`, `!=`, `>=`, `<=`, `>`, `<`, `CONTAINS`, `IN`), logical keywords (`AND`, `OR`, `NOT`), parentheses, numbers, identifiers, and quoted strings.
2. **Recursive-Descent Parser (`parseQuery`)**: Builds an explicit Abstract Syntax Tree (`LogicalExpression`, `UnaryExpression`, `ComparisonExpression`).
3. **Safe Evaluator (`evaluateQueryAst`)**: Evaluates each event against the AST with type-aware comparisons for ISO 8601 timestamps, severity ranks, numbers, strings, and tag arrays.

### 3. Detection Rule Engine (`src/engine/detectionEngine.js`)
Evaluates declarative rules (`single`, `threshold`, and `sequence`) against mission datasets, deduplicating findings by deterministic keys (`ruleId + entityKey`).

### 4. Correlation & Timeline Engine (`src/engine/correlationEngine.js`)
- Generates chronological timelines with relative time deltas (`deltaFromPrevious`, `deltaFromStart`).
- Grades multi-event correlations as `confirmed` (process lineage or explicit link), `probable` (shared cross-source indicator or identity), or `weak` (temporal proximity on same host).
- Extracts entity nodes and relationship edges for the interactive SVG graph and relationship table.

### 5. Response Simulation Engine (`src/engine/responseEngine.js`)
Simulates 10 containment and disposition actions, tracking whether intrusive actions were taken prematurely (before collecting at least 2 supporting evidence items) or against benign production assets.

### 6. Scoring & Progression Engine (`src/engine/scoringEngine.js`, `src/engine/progressionEngine.js`)
Computes bounded 0–100 scores across 6 weighted dimensions, prevents lucky guesses without evidence from earning full credit, manages the 7 Analyst Ranks, evaluates 9 Achievements, and prevents duplicate XP farming when replaying completed missions.
