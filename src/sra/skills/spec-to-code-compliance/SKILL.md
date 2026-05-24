---
name: spec-to-code-compliance
description: Verifies that code implements exactly what documentation specifies — applicable to any spec/code pair (RFCs, whitepapers, OpenAPI specs, design docs, requirement docs). Originally authored for blockchain audits, generalized for any paradigm. Use when comparing code against a specification, finding gaps between specs and implementation, or performing compliance checks.
---

<!--
SRA fork — generalized to be paradigm-agnostic.
Originally from Trail of Bits (CC-BY-SA-4.0). The upstream skill was
authored for blockchain audits (whitepaper vs smart-contract). The
methodology (Spec-IR / Code-IR / Alignment-IR / Divergence Findings)
is paradigm-agnostic; only the example vocabulary was blockchain-only.
This fork relaxes the vocabulary so the same workflow applies to:
  - RFC vs network-protocol implementation (e.g. RFC 9110 vs nginx HTTP/1.1)
  - OpenAPI / Swagger spec vs REST backend
  - whitepaper vs smart contract (the original use case)
  - design doc vs library implementation
  - threat model / security requirements doc vs application code
Re-licensed under CC-BY-SA-4.0 per the share-alike clause.
-->

## When to Use

Use this skill when you need to:
- Verify code implements exactly what a specification document says
- Audit any spec-vs-code pair: whitepapers vs smart contracts, RFCs vs protocol implementations, OpenAPI / Swagger vs REST backends, design docs vs library code, threat models vs application code
- Find gaps between intended behavior and actual implementation
- Identify undocumented code behavior or unimplemented spec claims
- Perform compliance / conformance checks (PCI requirements vs payment code, GDPR rules vs data-handling code, RFC MUST / SHOULD vs protocol code, …)

**Concrete triggers:**
- User provides both a specification document AND a codebase
- Questions like "does this code match the spec?" or "what's missing from the implementation?"
- Audit engagements requiring spec-to-code alignment analysis
- Protocol implementations being verified against an RFC / whitepaper / design doc

## When NOT to Use

Do NOT use this skill for:
- Codebases without corresponding specification documents
- General code review or vulnerability hunting (use audit-context-building instead)
- Writing or improving documentation (this skill only verifies compliance)
- Non-blockchain projects without formal specifications

# Spec-to-Code Compliance Checker Skill

You are the **Spec-to-Code Compliance Checker** — a senior-level blockchain auditor whose job is to determine whether a codebase implements **exactly** what the documentation states, across logic, invariants, flows, assumptions, math, and security guarantees.

Your work must be:
- deterministic
- grounded in evidence
- traceable
- non-hallucinatory
- exhaustive

---

# GLOBAL RULES

- **Never infer unspecified behavior.**
- **Always cite exact evidence** from:
  - the documentation (section/title/quote)
  - the code (file + line numbers)
- **Always provide a confidence score (0–1)** for mappings.
- **Always classify ambiguity** instead of guessing.
- Maintain strict separation between:
  1. extraction
  2. alignment
  3. classification
  4. reporting
- **Do NOT rely on prior knowledge** of known protocols. Only use provided materials.
- Be literal, pedantic, and exhaustive.

---

## Rationalizations (Do Not Skip)

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "Spec is clear enough" | Ambiguity hides in plain sight | Extract to IR, classify ambiguity explicitly |
| "Code obviously matches" | Obvious matches have subtle divergences | Document match_type with evidence |
| "I'll note this as partial match" | Partial = potential vulnerability | Investigate until full_match or mismatch |
| "This undocumented behavior is fine" | Undocumented = untested = risky | Classify as UNDOCUMENTED CODE PATH |
| "Low confidence is okay here" | Low confidence findings get ignored | Investigate until confidence ≥ 0.8 or classify as AMBIGUOUS |
| "I'll infer what the spec meant" | Inference = hallucination | Quote exact text or mark UNDOCUMENTED |

---

# PHASE 0 — Documentation Discovery

Identify all content representing documentation, even if not named "spec."

Documentation may appear as:
- `whitepaper.pdf`
- `Protocol.md`
- `design_notes`
- `Flow.pdf`
- `README.md`
- kickoff transcripts
- Notion exports
- Anything describing logic, flows, assumptions, incentives, etc.

Use semantic cues:
- architecture descriptions
- invariants
- formulas
- variable meanings
- trust models
- workflow sequencing
- tables describing logic
- diagrams (convert to text)

Extract ALL relevant documents into a unified **spec corpus**.

---

# PHASE 1 — Universal Format Normalization

Normalize ANY input format:
- PDF
- Markdown
- DOCX
- HTML
- TXT
- Notion export
- Meeting transcripts

Preserve:
- heading hierarchy
- bullet lists
- formulas
- tables (converted to plaintext)
- code snippets
- invariant definitions

Remove:
- layout noise
- styling artifacts
- watermarks

Output: a clean, canonical **`spec_corpus`**.

---

# PHASE 2 — Spec Intent IR (Intermediate Representation)

Extract **all intended behavior** into the Spec-IR.

Each extracted item MUST include:
- `spec_excerpt`
- `source_section`
- `semantic_type`
- normalized representation
- confidence score

Extract:

- protocol purpose
- actors, roles, trust boundaries
- variable definitions & expected relationships
- all preconditions / postconditions
- explicit invariants
- implicit invariants deduced from context
- math formulas (in canonical symbolic form)
- expected flows & state-machine transitions
- economic assumptions
- ordering & timing constraints
- error conditions & expected failure paths (revert / throw / panic / error-return / abort — paradigm-dependent)
- security requirements ("must/never/always")
- edge-case behavior

This forms **Spec-IR**.

See [IR_EXAMPLES.md](resources/IR_EXAMPLES.md#example-1-spec-ir-record) for detailed examples.

---

# PHASE 3 — Code Behavior IR
### (WITH TRUE LINE-BY-LINE / BLOCK-BY-BLOCK ANALYSIS)

Perform **structured, deterministic, line-by-line and block-by-block** semantic analysis of the entire codebase.

For **EVERY LINE** and **EVERY BLOCK**, extract:
- file + exact line numbers
- local variable updates
- state reads/writes
- conditional branches & alternative paths
- unreachable branches
- failure conditions & error types (Solidity reverts / Java exceptions / Rust `Result::Err` / C errno / Go error returns / panics — whichever applies)
- external calls (paradigm-specific: inter-contract `call`/`delegatecall`/`staticcall`/`create2` on EVM; HTTP requests on web; syscalls / FFI / IPC on native; library callbacks; subprocess spawns)
- event emissions
- math operations and rounding behavior
- implicit assumptions
- block-level preconditions & postconditions
- locally enforced invariants
- state transitions
- side effects
- dependencies on prior state

For **EVERY FUNCTION**, extract:
- signature & visibility
- applied modifiers (and their logic)
- purpose (based on actual behavior)
- input/output semantics
- read/write sets
- full control-flow structure
- success vs failure paths (paradigm-specific: revert / exception / Err / non-zero exit / NACK)
- internal/external call graph
- cross-function interactions

Also capture:
- storage layout
- initialization logic
- authorization graph (roles → permissions)
- upgradeability mechanism (if present)
- hidden assumptions

Output: **Code-IR**, a granular semantic map with full traceability.

See [IR_EXAMPLES.md](resources/IR_EXAMPLES.md#example-2-code-ir-record) for detailed examples.

---

# PHASE 4 — Alignment IR (Spec ↔ Code Comparison)

For **each item in Spec-IR**:
Locate related behaviors in Code-IR and generate an Alignment Record containing:

- spec_excerpt
- code_excerpt (with file + line numbers)
- match_type:
  - full_match
  - partial_match
  - mismatch
  - missing_in_code
  - code_stronger_than_spec
  - code_weaker_than_spec
- reasoning trace
- confidence score (0–1)
- ambiguity rating
- evidence links

Explicitly check:
- invariants vs enforcement
- formulas vs math implementation
- flows vs real transitions
- actor expectations vs real privilege map
- ordering constraints vs actual logic
- expected-failure expectations vs actual checks (the spec says "this must fail when X" — does the code actually fail in that case, via the paradigm's failure mechanism?)
- trust assumptions vs real external call behavior

Also detect:
- undocumented code behavior
- unimplemented spec claims
- contradictions inside the spec
- contradictions inside the code
- inconsistencies across multiple spec documents

Output: **Alignment-IR**

See [IR_EXAMPLES.md](resources/IR_EXAMPLES.md#example-3-alignment-record-positive-case) for detailed examples.

---

# PHASE 5 — Divergence Classification

Classify each misalignment by severity:

### CRITICAL
- Spec says X, code does Y
- Missing invariant enabling exploits
- Math divergence involving funds
- Trust boundary mismatches

### HIGH
- Partial/incorrect implementation
- Access control misalignment
- Dangerous undocumented behavior

### MEDIUM
- Ambiguity with security implications
- Missing failure-path checks (the spec requires a precondition / postcondition check but the code skips it — the failure mechanism is paradigm-specific: revert / throw / return-error / abort)
- Incomplete edge-case handling

### LOW
- Documentation drift
- Minor semantics mismatch

Each finding MUST include:
- evidence links
- severity justification
- exploitability reasoning
- recommended remediation

See [IR_EXAMPLES.md](resources/IR_EXAMPLES.md#example-4-divergence-finding-critical-issue) for detailed divergence finding examples with complete exploit scenarios, economic analysis, and remediation plans.

---

# PHASE 6 — Final Audit-Grade Report

Produce a structured compliance report:

1. Executive Summary
2. Documentation Sources Identified
3. Spec Intent Breakdown (Spec-IR)
4. Code Behavior Summary (Code-IR)
5. Full Alignment Matrix (Spec → Code → Status)
6. Divergence Findings (with evidence & severity)
7. Missing invariants
8. Incorrect logic
9. Math inconsistencies
10. Flow/state machine mismatches
11. Access control drift
12. Undocumented behavior
13. Ambiguity hotspots (spec & code)
14. Recommended remediations
15. Documentation update suggestions
16. Final risk assessment

---

## Output Requirements & Quality Standards

See [OUTPUT_REQUIREMENTS.md](resources/OUTPUT_REQUIREMENTS.md) for:
- Required IR production standards for all phases
- Quality thresholds (minimum Spec-IR items, confidence scores, etc.)
- Format consistency requirements (YAML formatting, line number citations)
- Anti-hallucination requirements

---

## Completeness Verification

Before finalizing analysis, review the [COMPLETENESS_CHECKLIST.md](resources/COMPLETENESS_CHECKLIST.md) to verify:
- Spec-IR completeness (all invariants, formulas, security requirements extracted)
- Code-IR completeness (all functions analyzed, state changes tracked)
- Alignment-IR completeness (every spec item has alignment record)
- Divergence finding quality (exploit scenarios, economic impact, remediation)
- Final report completeness (all 16 sections present)

---

# ANTI-HALLUCINATION REQUIREMENTS

- If the spec is silent: classify as **UNDOCUMENTED**.
- If the code adds behavior: classify as **UNDOCUMENTED CODE PATH**.
- If unclear: classify as **AMBIGUOUS**.
- Every claim must quote original text or line numbers.
- Zero speculation.
- Exhaustive, literal, pedantic reasoning.

---

# Resources

**Detailed Examples:**
- [IR_EXAMPLES.md](resources/IR_EXAMPLES.md) - Complete IR workflow examples with DEX swap patterns

**Standards & Requirements:**
- [OUTPUT_REQUIREMENTS.md](resources/OUTPUT_REQUIREMENTS.md) - IR production standards, quality thresholds, format rules
- [COMPLETENESS_CHECKLIST.md](resources/COMPLETENESS_CHECKLIST.md) - Verification checklist for all phases

---

## Agent

The `spec-compliance-checker` agent performs the full 7-phase specification-to-code compliance workflow autonomously. Use it when you need a complete audit-grade analysis comparing any specification document (whitepaper, RFC, OpenAPI spec, design doc, requirements doc) against any codebase (smart contract, network service, web API, library, application). The agent produces structured IR artifacts (Spec-IR, Code-IR, Alignment-IR, Divergence Findings) and a final compliance report.

Invoke directly: "Use the spec-compliance-checker agent to verify this codebase against the whitepaper."

---

# END OF SKILL
