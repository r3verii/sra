# Skill — audit/input-validation (v0)

This file defines the contract for the Claude skill that consumes a single
`PACKET-NNN.md` under `.audit/04-packets-sensors/audit-input-validation/`
and produces a structured investigation report.

The skill is invoked **once per packet**. It is not aware of other packets,
it does not aggregate across them, and it does not propose findings outside
the packet's cluster.

## Inputs

- **The single packet you are given** in this invocation. Its content is
  pasted into the prompt. **Do not search for, list, open, or investigate
  any other packet.** Other packets are handled by other invocations of
  this skill. If you see other packet files in the directory while
  reading the target repo, ignore them.
- **The target repository** is reachable from the current working
  directory. The skill may read files, search, and list — but only
  inside the repo.

## Tools allowed

- `Read` — open any file in the target repository.
- `Grep` — search for symbols, imports, callers.
- `Glob` — locate files by pattern (tests, sibling validators, etc.).

## Tools FORBIDDEN

- `Write`, `Edit`, `NotebookEdit` — the skill never modifies the target.
- `Bash`, `PowerShell` — no shell execution.
- Any network tool (`WebFetch`, `WebSearch`).
- Any other tool not listed above.

If a needed action is outside this list, the skill records it as a
**limitation** in the report and stops.

## What the skill does

1. **Read the packet**. Identify the cluster's directory, role, files,
   and the four kinds of sensor hits: framework markers, input sources,
   parsers / middleware, validators.

2. **For each cluster file with input-source hits**, open the file and
   read the surrounding function (typically the route handler or
   controller method).

3. **Trace forward from each input access**:
   - Where does the input value go?
   - Is it passed to a validator (joi, zod, pydantic, JSR-303, etc.)
     before being used?
   - Or is it consumed directly by a sink (DB query, shell, response
     body, file path, redirect)?
   - Does an upstream middleware (e.g. `express.json` + a schema)
     enforce shape?

4. **Trace backward from each validator hit** in the packet:
   - Which routes does this validator protect?
   - Is the protection wired into the same routes the input-source hits
     came from, or different ones?

5. **Cross-check with tests**: glob `test*/**`, `**/__tests__/**`,
   `**/*spec*` in or near the cluster. If a test exercises the boundary,
   read it to learn the intended contract.

6. **For each potential issue**:
   - Decide whether the sensor hit represents a real, reachable problem.
   - Cite the **file:line** you verified (not the sensor hit you started
     from).
   - Record what would need to change for the issue to be exploitable
     (e.g. "this only fires if the caller skips middleware X").

7. **For each sensor hit you dismiss**:
   - Record why in one short sentence.

8. **For anything you could not determine** (cross-module dataflow,
   runtime registration of routes, dynamic dispatch, generated code),
   record it as a **limitation**, not a finding.

## What the skill MUST NOT do

- Do not report a finding based on the sensor hit alone. The hit is a
  seed. Every reported finding must cite code you read.
- Do not invent risks that are not anchored in the packet's cluster.
  Other packets cover other clusters.
- Do not propose fixes unless asked. The output is an audit, not a PR.
- Do not extrapolate to vulnerability classes outside
  `audit/input-validation`. SQL injection, XSS, file-boundary, supply
  chain, etc. live in other packets and other skills.

## Output

**Print the report to STDOUT**, in Markdown. Do not write any file. Do
not use the Write, Edit, or NotebookEdit tools. The caller captures
stdout via shell redirection and decides where the report lives on
disk.

Output structure (no preamble, no "I will now investigate" text — just
the report):

    # PACKET-NNN — investigation report

    ## Summary
    <2-4 sentences: what was reviewed, what was confirmed, what remained
    open. No hype, no marketing language.>

    ## Confirmed issues (N)
    <For each: a section with severity hint (info/low/med/high), the
    file:line you verified, the input → sink chain you traced, and the
    smallest change that would close it. If N = 0, omit the section.>

    ## Dismissed sensor hits (M)
    <Bulleted list. Each: the file:line of the sensor hit + one short
    sentence on why it is not a real issue here.>

    ## Limitations / what I could not determine (K)
    <Bulleted list. Each: a concrete sentence on what the static read
    could not answer (cross-module dataflow, runtime-registered handlers,
    test coverage you could not find, etc.).>

    ## Files read during investigation
    <List of file:line ranges you opened with Read, plus any Grep / Glob
    queries you ran. Reproducibility hook.>

Severity hints are non-authoritative; an aggregator will assign final
severity once all skills have run.

## Failure modes the skill should report explicitly

- "The packet's cluster directory is empty or has only generated code."
- "Every input-source hit in this cluster is protected by a validator
  this skill verified."
- "The cluster appears to be test or example code only; no production
  risk is implied."
- "I could not trace the input chain past a dynamic dispatch. The
  question 'is this validated downstream?' remains open."

## Why this contract exists

The packet's job is to **bound the skill's input** so the skill has a
small enough surface to investigate carefully. The skill's job is to
**produce evidence**, not to chase scope. If the skill starts wandering
the whole repo, the packet abstraction has failed and the packet
builder needs adjustment — not the skill.
