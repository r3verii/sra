# Skill — audit/parser-state-machine (v0)

This file defines the contract for the Claude skill that investigates
a `PACKET-NNN.md` under `.audit/04-packets-sensors/audit-parser-state-machine/`.

The skill is invoked **once per packet** and stays inside the
packet's cluster.

## Inputs

- The single packet given in the prompt.
- The target repository, reachable from the current working directory.

## Tools allowed

- `Read`, `Grep`, `Glob` only.

## Tools FORBIDDEN

- `Write`, `Edit`, `NotebookEdit`, `Bash`, any network tool.

## What the skill does

Parser / state-machine audit asks four core questions:

1. **State coverage**: is every defined state explicitly handled in every
   dispatcher (no fall-through, no silent defaults)?
2. **Transition discipline**: do all transitions go through the same
   dispatcher, or are there ad-hoc `state = X` assignments scattered
   across error paths?
3. **Partial-state safety**: can the parser return data while in an
   intermediate state? Can a short read or early EOF leave a
   half-constructed object visible to callers?
4. **Frame / chunk boundary**: when handling delimited input (HTTP
   chunked, length-prefixed frames, etc.), is the boundary verified
   against state invariants?

Hits categorised by `expected_role`:

- `state_definition` — enum / type defining the states
- `state_dispatcher` — `switch (state)` or `match state`
- `state_transition` — case labels in the dispatcher
- `parser_entry` — known parser entry points (http-parser callbacks,
  Go's `http.ReadRequest`, Node streams, etc.)
- `framing_marker` — Transfer-Encoding / Content-Length / frame markers
- `partial_read` — short-read / EOF checks on the underlying syscall

For each packet:

1. **Map the state machine**.
   - Find every `state_definition` hit. Read it. Enumerate the states.
   - Find every `state_dispatcher` hit. Verify it handles every state.
   - Look for `default:` / `_` branches; do they fail-closed or
     fall-through?

2. **Find every place `state = X` is assigned**.
   - Use Grep: `\bstate\s*=` in the cluster's files.
   - Note assignments that happen OUTSIDE the dispatcher (error paths,
     reset functions). These are the high-risk transitions.
   - For each: what's the trigger? Is the post-state consistent with
     the pre-state semantics?

3. **For each `partial_read` hit**:
   - What state was the parser in BEFORE the read?
   - On short read (return value < expected), what state does it go to?
   - On read==0 (EOF) mid-parse, does it produce a valid partial object?
   - **Findings to look for**: parser returns success on partial data;
     state remains "in-progress" after disconnect, leaving connection
     unreusable; state advances despite no bytes consumed.

4. **For each `framing_marker` hit**:
   - Trace how the length / boundary is parsed.
   - Is it bounded against the actual bytes read?
   - For HTTP: does Content-Length AND Transfer-Encoding handling
     prioritize one or reject both (RFC compliance)?
   - **Findings to look for**: ambiguous Content-Length /
     Transfer-Encoding precedence (request smuggling territory),
     chunked-encoding state confusion, missing chunk-extension parsing
     that allows comment-injection.

5. **Cross-state invariants**:
   - Is there code that assumes state X means "all headers parsed"?
   - Can state X be reached without parsing all headers (error paths)?
   - **Findings to look for**: invariant violations across error
     paths, missing zero-init of state fields on reuse.

6. **Lifecycle hooks** (Node streams, RAII handlers):
   - `_destroy`, `_final`, `close`, etc. called in the wrong order?
   - Can the parser receive input after close / destroy?

7. **Cross-check with tests**:
   - Look for differential / fuzzing test files (`fuzz_*.c`,
     `*_fuzzer.c`, `boofuzz`, etc.) — their presence is positive
     evidence the team is aware.
   - Read at least one to see what behaviour they pin.

8. **For each potential issue**:
   - Cite the `file:line` you verified.
   - Describe the state confusion or boundary violation concretely.
   - State the smallest change that would close it.

9. **For each dismissed hit**:
   - Note the reason in one sentence.

10. **For unknowns**:
    - Cross-translation-unit state assignments
    - Runtime behaviour outside static reach
    - Fuzzing coverage you cannot verify

## What the skill MUST NOT do

- Do not flag every `switch (state)`. The job is to find STATE
  CONFUSION, not state machines.
- Do not invent risks from a single `case` without tracing back to the
  full state space.
- Do not extrapolate to other audit families (no input-validation,
  no memory-safety findings even if visible).
- **Acknowledge when fuzzing is the right tool.** Many real findings in
  this family require differential / fuzzing test runs that this skill
  cannot perform. Note this as a limitation rather than over-claiming.

## Output

Print to STDOUT, Markdown only. No file writes.

Output structure:

    # PACKET-NNN — investigation report

    ## Summary
    <2-4 sentences>

    ## Confirmed issues (N)
    <For each: severity, file:line, state-confusion / boundary chain,
    smallest fix>

    ## Dismissed sensor hits (M)
    <Bulleted list with one-sentence reason each>

    ## Limitations / what I could not determine (K)
    <Bulleted list; explicitly note when fuzzing / runtime testing
    would be the right tool>

    ## Files read during investigation
    <Ranges + Grep / Glob queries>

## Failure modes the skill should report explicitly

- "The state machine in this cluster has N states; every state is
  handled in the dispatcher with explicit error returns. No
  unhandled transitions found."
- "Content-Length and Transfer-Encoding are both parsed at lines X
  and Y; the code rejects requests where both are present
  (RFC 7230 § 3.3.3 case 3). Confirmed safe."
- "I could not statically verify whether state X is reachable
  without going through state Y; this would require runtime
  tracing or symbolic execution."
- "Fuzzing harness `fuzz/fuzz_parser.c` exists and exercises this
  parser; full coverage of state-transition pairs would require
  inspecting the harness corpus, which is outside this skill's scope."

## Why this contract exists

State-machine bugs are the highest-value class of finding in
protocol implementations and parsers — request smuggling,
HTTP/2 RST flood mitigation gaps, TLS state confusion, etc. They
are also the hardest class to find via SAST. The skill's job is to
**map the state space, find the gaps, and be explicit about what
static analysis cannot prove**.
