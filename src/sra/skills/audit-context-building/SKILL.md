---
name: audit-context-building
description: Enables ultra-granular, line-by-line code analysis to build deep architectural context before vulnerability or bug finding. Works across paradigms — web apps, native services, CLI tools, mobile apps, embedded firmware, data pipelines, libraries, and smart contracts.
---

<!--
SRA fork — generalized to be paradigm-agnostic.
Originally from Trail of Bits (https://github.com/trailofbits/skills,
plugin: audit-context-building, CC-BY-SA-4.0).

Changes from upstream:
  - Added Phase 0 "Paradigm Identification" so the analyst adapts the
    actor/storage/external-call vocabulary to the codebase's paradigm
    (web / native / CLI / mobile / embedded / data-pipeline / library /
    smart-contract) instead of defaulting to smart-contract terms.
  - Genericized Phase 1 actor and storage examples beyond
    owners/oracles/relayers/contracts and cells/state-structs.
  - Genericized the "External Calls — Two Cases" framework so it
    applies to syscalls, HTTP requests, IPC, FFI, and library calls
    in addition to inter-contract calls. "Reentrancy" demoted from a
    universal concern to a paradigm-specific one.
  - Genericized Phase 3 workflow examples beyond deposit/withdraw/
    upgrades.
  - The FUNCTION_MICRO_ANALYSIS_EXAMPLE.md example is still a DeFi
    swap — kept because the *structure* is exemplary; on other
    paradigms map the sections to your domain's equivalents.

This fork remains under CC-BY-SA-4.0, per the upstream share-alike
clause.
-->

# Deep Context Builder Skill (Ultra-Granular Pure Context Mode)

## 1. Purpose

This skill governs **how Claude thinks** during the context-building phase of an audit.

When active, Claude will:
- Perform **line-by-line / block-by-block** code analysis by default.
- Apply **First Principles**, **5 Whys**, and **5 Hows** at micro scale.
- Continuously link insights → functions → modules → entire system.
- Maintain a stable, explicit mental model that evolves with new evidence.
- Identify invariants, assumptions, flows, and reasoning hazards.

This skill defines a structured analysis format (see Example: Function Micro-Analysis below) and runs **before** the vulnerability-hunting phase.

---

## 2. When to Use This Skill

Use when:
- Deep comprehension is needed before bug or vulnerability discovery.
- You want bottom-up understanding instead of high-level guessing.
- Reducing hallucinations, contradictions, and context loss is critical.
- Preparing for security auditing, architecture review, or threat modeling.

Do **not** use for:
- Vulnerability findings
- Fix recommendations
- Exploit reasoning
- Severity/impact rating

---

## 3. How This Skill Behaves

When active, Claude will:
- Default to **ultra-granular analysis** of each block and line.
- Apply micro-level First Principles, 5 Whys, and 5 Hows.
- Build and refine a persistent global mental model.
- Update earlier assumptions when contradicted ("Earlier I thought X; now Y.").
- Periodically anchor summaries to maintain stable context.
- Avoid speculation; express uncertainty explicitly when needed.

Goal: **deep, accurate understanding**, not conclusions.

---

## Rationalizations (Do Not Skip)

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "I get the gist" | Gist-level understanding misses edge cases | Line-by-line analysis required |
| "This function is simple" | Simple functions compose into complex bugs | Apply 5 Whys anyway |
| "I'll remember this invariant" | You won't. Context degrades. | Write it down explicitly |
| "External call is probably fine" | External = adversarial until proven otherwise | Jump into code or model as hostile |
| "I can skip this helper" | Helpers contain assumptions that propagate | Trace the full call chain |
| "This is taking too long" | Rushed context = hallucinated vulnerabilities later | Slow is fast |

---

## 4. Phase 0 — Paradigm Identification (Mandatory First Step)

Before anything else, identify which **paradigm(s)** this codebase belongs to. The vocabulary you use for "actors", "storage", "external calls", "trust boundaries", and "flows" depends entirely on this. Skipping this step produces analysis that mis-applies one paradigm's mental model to another (e.g. searching for "reentrancy" in a CLI tool, or for "syscalls" in a smart contract).

Pick **one primary paradigm** and zero or more secondary ones:

| Paradigm | Marker signals (file/dir/dep hints) |
|---|---|
| **Web application / API** | `routes/`, `controllers/`, web framework deps (Express / Django / Flask / Rails / Spring / Laravel / Symfony / FastAPI / ASP.NET), HTTP middleware, ORM, session store |
| **Web framework / library** | published package implementing the above primitives rather than consuming them; route-handler infra, middleware base classes |
| **Native service / daemon** | C/C++/Rust binary, `main()` with event loop, syscall use, IPC, sockets, signal handling, systemd unit |
| **CLI tool** | `argparse`/`clap`/`cobra` flag parsing, terminal I/O, exit codes, no long-running server loop, single-shot invocation |
| **Mobile app** | iOS (Swift/ObjC + Xcode project) or Android (Kotlin/Java + Gradle), UI framework (SwiftUI / UIKit / Jetpack Compose), platform APIs (Keychain, Intents, SharedPreferences) |
| **Embedded / firmware** | bare-metal or RTOS code, register access, interrupt handlers, no OS, hardware-specific headers |
| **Data pipeline / ML** | DataFrame ops, Spark / Beam / Airflow DAGs, batch jobs, schedulers, model artifacts |
| **Library / SDK** | public API surface for consumers, package manifest with `exports`, no own entrypoint |
| **Smart contract / on-chain** | Solidity / Vyper / Rust-Solana / Move / Cairo / CosmWasm sources, `pragma`, `contract`, `module` keywords, gas semantics |
| **Browser extension** | `manifest.json`, content scripts, message-passing, host permissions |
| **OS kernel / driver** | kernel headers, `EXPORT_SYMBOL`, syscall implementation, lock primitives |

Then map the paradigm-specific vocabulary you will use throughout Phases 1–3:

| Concept | Web app | Native daemon | CLI tool | Mobile | Smart contract | Library |
|---|---|---|---|---|---|---|
| **Actors** | anon user, authenticated user, admin, API client, internal service, scheduled job, plugin/extension | OS user, sibling processes, kernel, parent / child, unix socket peer | invoking shell user, scripts piping stdin, env-var supplier | end user, OS, platform service, intent sender, push provider | EOA caller, owner / admin, oracle, relayer, other contract | downstream consumer code, plugin, host application |
| **Storage** | DB tables, session store, cache (Redis/memcached), filesystem, env vars, ORM entities, config files | heap, stack, mmap, IPC shm, sockets, file descriptors, sysfs/procfs | in-memory state during run, files written, env-var output | UserDefaults / SharedPreferences, Keychain / Keystore, sqlite, file sandbox | storage slots / state vars / cells, transient memory | in-process state, caller-supplied buffers |
| **External calls** | HTTP API, DB query, shell exec, child process, message queue, FFI / native lib | syscalls, libc, third-party shared libs, FFI, IPC, network sockets | subprocess (exec/system), pipes, network if applicable | platform API (CoreLocation / Camera / Network), IPC (intents / XPC), HTTP | inter-contract call, low-level call/delegatecall/staticcall, oracle read | callbacks into caller, user-provided closures |
| **Trust boundaries** | network perimeter, browser↔server, role levels, plugin sandbox, tenant isolation | privilege levels (root/user), SUID, capabilities, namespaces, syscall filters | OS process boundary, env-var trust | app sandbox, OS permissions, signed code, attestation | contract↔caller, on-chain↔off-chain, owner↔EOA | API consumer↔library |
| **Typical flows** | HTTP request lifecycle, auth flow, ORM unit-of-work, background job, plugin/hook | init → event loop → signal handling → graceful shutdown, fork/exec, accept loop | parse args → validate → execute → emit output → exit | activity/scene lifecycle, background task, OS event handling | tx entry → state read → checks → effects → external interactions | API call → validation → core logic → return |

**Output of Phase 0:** state the primary paradigm and the secondary ones in one or two sentences. Example: *"Primary paradigm: web framework (PHP, Symfony component). Secondary: library (published on Packagist). Actor / storage / external-call vocabulary for the rest of this analysis follows the web-framework column."* From here on, every reference to "actors", "storage", "external calls", etc. uses the column from the table above that matches the primary paradigm.

If the codebase is genuinely multi-paradigm (e.g. a mobile app with a heavy C++ native layer), analyze each component using its own paradigm column rather than forcing a single one.

---

## 5. Phase 1 — Initial Orientation (Bottom-Up Scan)

Before deep analysis, Claude performs a minimal mapping (using the paradigm vocabulary identified in Phase 0):

1. Identify major modules / files / packages / contracts / source units (the unit name depends on paradigm).
2. Note obvious public / external entrypoints (HTTP routes, CLI subcommands, exported library functions, contract external functions, exported syscalls, mobile activities/scenes, message handlers, …).
3. Identify likely **actors** (use the row from the Phase 0 table).
4. Identify important **storage** (use the row from the Phase 0 table).
5. Build a preliminary structure without assuming behavior.

This establishes anchors for detailed analysis.

---

## 5. Phase 2 — Ultra-Granular Function Analysis (Default Mode)

Every non-trivial function receives full micro analysis.

### 5.1 Per-Function Microstructure Checklist

For each function:

1. **Purpose**
   - Why the function exists and its role in the system.

2. **Inputs & Assumptions**
   - Parameters and implicit inputs (state, sender, env).
   - Preconditions and constraints.

3. **Outputs & Effects**
   - Return values.
   - State/storage writes.
   - Events/messages.
   - External interactions.

4. **Block-by-Block / Line-by-Line Analysis**
   For each logical block:
   - What it does.
   - Why it appears here (ordering logic).
   - What assumptions it relies on.
   - What invariants it establishes or maintains.
   - What later logic depends on it.

   Apply per-block:
   - **First Principles**
   - **5 Whys**
   - **5 Hows**

---

### 5.2 Cross-Function & External Flow Analysis
*(Full Integration of Jump-Into-External-Code Rule)*

When encountering calls, **continue the same micro-first analysis across boundaries.**

#### Internal Calls
- Jump into the callee immediately.
- Perform block-by-block analysis of relevant code.
- Track flow of data, assumptions, and invariants:
  caller → callee → return → caller.
- Note if callee logic behaves differently in this specific call context.

#### External Calls — Two Cases

"External call" here means any call that crosses an *analytical boundary* — the exact mechanism depends on paradigm (inter-contract call, HTTP request, syscall, FFI / native lib invocation, IPC / message-passing, subprocess spawn, callback into caller-supplied code, oracle read, …). Use whichever mechanism applies to your Phase 0 paradigm.

**Case A — External Call Whose Target Code Exists in the Codebase**
Examples: a controller calling a service in the same repo; a contract calling another contract in the same codebase; a CLI subcommand dispatching to an internal handler; a syscall implemented in the same OS kernel tree.

Treat as an internal call:
- Jump into the target function / module / contract.
- Continue block-by-block micro-analysis.
- Propagate invariants and assumptions seamlessly.
- Consider edge cases based on the *actual* code, not a black-box guess.

**Case B — External Call Without Available Code (True External / Black Box)**
Examples: HTTP to a third-party API; a `libcurl` call; a syscall whose kernel implementation is out of scope; an arbitrary ERC20 token call; a plugin / extension loaded at runtime; a child process invoking an arbitrary binary; an oracle read; a callback closure provided by an unknown caller.

Analyze as adversarial:
- Describe what is sent (payload, arguments, environment, file descriptors, gas / value, …).
- Identify assumptions about the target (does it return on success? can it block? can it return malformed data? can it call back into us?).
- Consider all outcomes — pick the subset relevant to the paradigm:
  - **Error/failure**: exception, error code, panic, revert, signal, timeout, partial result.
  - **Unexpected return data**: malformed, oversized, encoding mismatch, truncated.
  - **Unexpected side effects**: state changes in shared resources (DB rows, files, registers, on-chain state), log emissions, network traffic.
  - **Re-entry into our code** (a.k.a. reentrancy in smart contracts, callback re-entry in event-driven systems, signal handlers running mid-update, async tasks racing): does the external target call back into us before we finish?
  - **Resource exhaustion**: CPU, memory, file descriptors, connections, gas, stack.
  - **Time-of-check vs time-of-use**: did the external state move between our check and our action?
  - **Misbehavior / adversarial**: malicious peer, malicious dependency, attacker-controlled response.

#### Continuity Rule
Treat the entire call chain as **one continuous execution flow**.
Never reset context.
All invariants, assumptions, and data dependencies must propagate across calls.

---

### 5.3 Complete Analysis Example

See [FUNCTION_MICRO_ANALYSIS_EXAMPLE.md](resources/FUNCTION_MICRO_ANALYSIS_EXAMPLE.md) for a complete walkthrough demonstrating:
- Full micro-analysis of a function (the example targets a DeFi DEX swap, but the **structure** is the contract — apply the same section ordering and depth to any paradigm)
- Application of First Principles, 5 Whys, and 5 Hows
- Block-by-block analysis with invariants and assumptions
- Cross-function dependency mapping
- Risk analysis for external interactions

**Paradigm mapping for the example:** even though the example uses Solidity / DeFi terminology, the structure (Purpose → Inputs & Assumptions → Outputs & Effects → Block-by-block → Cross-function deps) is paradigm-agnostic. When auditing other paradigms, mentally substitute:

- *"`msg.sender` is the EOA caller"* → *"the authenticated user identified by session token"* (web), *"the OS user the process runs as"* (native), *"the caller of the exported API"* (library), …
- *"reverts on failure"* → *"throws exception"* (Java/PHP/Python), *"returns errno"* (C), *"panics"* (Rust), *"returns Result::Err"* (Rust idiomatic), *"sends NACK"* (protocol)
- *"reentrancy via `tokenIn.transferFrom`"* → *"signal handler re-entering during update"* (native), *"async task racing with sync handler"* (event-driven), *"callback closure invoked by external library"* (library)
- *"gas exhaustion"* → *"memory exhaustion / OOM"*, *"file-descriptor exhaustion"*, *"connection-pool exhaustion"*
- *"state writes to `reserves[pair]`"* → *"UPDATE statement on `users` table"* (web/ORM), *"write to `*p`"* (C), *"setValue on Keychain item"* (mobile)

This example demonstrates the level of depth and structure required for all analyzed functions, **regardless of paradigm**.

---

### 5.4 Output Requirements

When performing ultra-granular analysis, Claude MUST structure output following the format defined in [OUTPUT_REQUIREMENTS.md](resources/OUTPUT_REQUIREMENTS.md).

Key requirements:
- **Purpose** (2-3 sentences minimum)
- **Inputs & Assumptions** (all parameters, preconditions, trust assumptions)
- **Outputs & Effects** (returns, state writes, external calls, events, postconditions)
- **Block-by-Block Analysis** (What, Why here, Assumptions, First Principles/5 Whys/5 Hows)
- **Cross-Function Dependencies** (internal calls, external calls with risk analysis, shared state)

Quality thresholds:
- Minimum 3 invariants per function
- Minimum 5 assumptions documented
- Minimum 3 risk considerations for external interactions
- At least 1 First Principles application
- At least 3 combined 5 Whys/5 Hows applications

---

### 5.5 Completeness Checklist

Before concluding micro-analysis of a function, verify against the [COMPLETENESS_CHECKLIST.md](resources/COMPLETENESS_CHECKLIST.md):

- **Structural Completeness**: All required sections present (Purpose, Inputs, Outputs, Block-by-Block, Dependencies)
- **Content Depth**: Minimum thresholds met (invariants, assumptions, risk analysis, First Principles)
- **Continuity & Integration**: Cross-references, propagated assumptions, invariant couplings
- **Anti-Hallucination**: Line number citations, no vague statements, evidence-based claims

Analysis is complete when all checklist items are satisfied and no unresolved "unclear" items remain.

---

## 6. Phase 3 — Global System Understanding

After sufficient micro-analysis:

1. **State & Invariant Reconstruction**
   - Map reads/writes of each state variable.
   - Derive multi-function and multi-module invariants.

2. **Workflow Reconstruction**
   - Identify end-to-end flows. **Examples per paradigm:**
     - Web: HTTP request lifecycle, sign-up / sign-in / password-reset, checkout / payment, file upload / download, background job, plugin / hook chain.
     - Native daemon: init → bind socket → accept loop → per-connection handler → shutdown; signal handler ↔ main loop; fork / exec sequences.
     - CLI: parse args → validate → execute → emit → exit; pipeline composition (stdin / stdout chains).
     - Mobile: activity / scene / view lifecycle; background fetch; intent / URL-scheme handling; deep link.
     - Smart contract: deposit, withdraw, swap, lifecycle, upgrades, claim, vote.
     - Library: public API call → validation → core logic → return / callback.
     - Data pipeline: ingest → transform → publish; backfill / replay; checkpointing.
     - Embedded: boot → init → main loop → interrupt-handler dispatch → shutdown.
   - Track how state transforms across these flows.
   - Record assumptions that persist across steps.

3. **Trust Boundary Mapping**
   - Actor → entrypoint → behavior (use the paradigm-specific actor list from Phase 0).
   - Identify untrusted input paths (HTTP body / query / header, CLI arg / env / stdin, syscall arg from user-space, IPC message, file content, on-chain caller, …).
   - Privilege changes and implicit role expectations (admin vs regular user, root vs non-root, signed vs unsigned code, on-chain owner vs caller, …).

4. **Complexity & Fragility Clustering**
   - Functions with many assumptions.
   - High branching logic.
   - Multi-step dependencies.
   - Coupled state changes across modules.

These clusters help guide the vulnerability-hunting phase.

---

## 7. Stability & Consistency Rules
*(Anti-Hallucination, Anti-Contradiction)*

Claude must:

- **Never reshape evidence to fit earlier assumptions.**
  When contradicted:
  - Update the model.
  - State the correction explicitly.

- **Periodically anchor key facts**
  Summarize core:
  - invariants
  - state relationships
  - actor roles
  - workflows

- **Avoid vague guesses**
  Use:
  - "Unclear; need to inspect X."
  instead of:
  - "It probably…"

- **Cross-reference constantly**
  Connect new insights to previous state, flows, and invariants to maintain global coherence.

---

## 8. Subagent Usage

Claude may spawn subagents for:
- Dense or complex functions.
- Long data-flow or control-flow chains.
- Cryptographic / mathematical logic.
- Complex state machines.
- Multi-module workflow reconstruction.

Use the **`function-analyzer`** agent for per-function deep analysis.
It follows the full microstructure checklist, cross-function flow
rules, and quality thresholds defined in this skill, and enforces
the pure-context-building constraint.

Subagents must:
- Follow the same micro-first rules.
- Return summaries that Claude integrates into its global model.

---

## 9. Relationship to Other Phases

This skill runs **before**:
- Vulnerability discovery
- Classification / triage
- Report writing
- Impact modeling
- Exploit reasoning

It exists solely to build:
- Deep understanding
- Stable context
- System-level clarity

---

## 10. Non-Goals

While active, Claude should NOT:
- Identify vulnerabilities
- Propose fixes
- Generate proofs-of-concept
- Model exploits
- Assign severity or impact

This is **pure context building** only.
