# Security and Privacy Model

CyberOps Simulator is designed with defensive security best practices throughout its architecture:

## 1. Synthetic Telemetry & Reserved Indicators Only
- All scenarios use fictional organizations (**Aegis BioLabs**) and synthetic log data.
- External IP indicators strictly use IANA/RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- External domains strictly use RFC 2606 reserved domains (`*.example.com`, `*.example.net`, `*.example.org`).
- Users are never asked or permitted to upload real corporate security logs to any external service.

## 2. Safe Query Parsing (Zero Dynamic Code Execution)
- The structured query engine (`src/engine/queryEngine.js`) uses a custom character tokenizer, recursive-descent parser, and explicit AST traversal.
- It **never** uses `eval()`, `new Function()`, or dynamic script injection.

## 3. Inert Command Lines & Simulated Containment
- Suspicious command lines in mission telemetry (such as Base64-encoded PowerShell or `schtasks` strings) are inert text strings rendered safely by React.
- Response and containment actions modify only the in-memory/localStorage simulation state and never interact with host operating systems, accounts, or networks.

## 4. Import Validation & Prototype Pollution Protection
- All JSON imports (custom scenarios, game saves, and reports) are size-limited (`<= 512 KB` for scenarios, `<= 1 MB` for saves).
- `sanitizeObject()` recursively strips `__proto__`, `constructor`, and `prototype` keys and enforces a maximum nesting depth of 12 before schema validation.
