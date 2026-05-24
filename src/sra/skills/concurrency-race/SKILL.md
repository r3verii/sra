# Skill — audit/concurrency-race (v0)

Investigates one packet under `.audit/04-packets-sensors/audit-concurrency-race/`.

## Inputs
- The single packet given in the prompt.
- The target repository, reachable from cwd.

## Tools allowed
- `Read`, `Grep`, `Glob` only.

## Tools FORBIDDEN
- `Write`, `Edit`, `NotebookEdit`, `Bash`, any network tool.

## What the skill does

Concurrency audit asks four questions:

1. **Lock discipline**: every read / write of shared mutable state goes
   through a consistent lock? Are locks acquired and released in
   matching pairs on every exit path (including error paths)?
2. **TOCTOU**: is there a window between a check and the action that
   another thread / request can exploit (auth check then read,
   uniqueness check then insert)?
3. **Atomic vs lock**: where atomic operations are used, is the
   memory ordering correct (Relaxed vs Acquire / Release vs SeqCst)?
4. **Cancellation safety**: when a goroutine / task / promise is
   cancelled, is shared state left consistent?

Hits categorised by `expected_role`:
- `lock_primitive` — mutex / rwlock / semaphore / channel
- `atomic_op` — atomic load / store / CAS
- `signal_handler` — POSIX signal handler
- `volatile_marker` — `volatile` keyword (often misused)
- `channel_op` — Go channels
- `cancellation` — context.Done, asyncio.CancelledError
- `async_coord` — Promise.race / all

For each packet:

1. **Map shared state**:
   - For each file, identify global / module-level / instance-level
     variables that are modified after init.
   - Pair each variable with the lock that guards it (if any).
   - **Findings to look for**: shared variable with NO guard;
     variable guarded by lock A in one place and lock B (or no
     lock) elsewhere; uses outside any critical section.

2. **For each `lock_primitive` hit**:
   - Find the matching unlock. Is it on EVERY exit path? Use Grep for
     `return` / `throw` between lock and unlock — each is a potential
     leak.
   - Is the lock acquired before reading AND writing?
   - Are nested locks always acquired in the same order across the
     codebase? (Lock-ordering violations cause deadlocks.)
   - **Findings to look for**: missing unlock on error path; locks
     acquired in different orders.

3. **For each TOCTOU window**:
   - Look for patterns: check → external call / yield → use.
     - File: `stat()` + `open()`, `exists()` + `read()`
     - Auth: permission check → load resource (resource changed?)
     - DB: SELECT → UPDATE (consider lost update); should be
       `SELECT ... FOR UPDATE` or optimistic version check
   - **Findings to look for**: TOCTOU specifically on
     authorization / uniqueness / file-existence checks.

4. **For each `atomic_op` hit**:
   - Is the operation actually atomic (single CAS) or a compound
     (load → compute → store) that LOOKS atomic?
   - Memory ordering: `Relaxed` is fine for counters; load-acquire /
     store-release needed for synchronization; SeqCst is safe but
     often overkill.
   - **Findings to look for**: read-modify-write done as
     load+store (not CAS); ordering too weak for the synchronization
     intent.

5. **For each `signal_handler` hit**:
   - Inside the handler, only async-signal-safe functions allowed.
     `malloc`, `printf`, `fprintf`, most stdlib calls are NOT
     async-signal-safe.
   - **Findings to look for**: any unsafe call inside a signal
     handler.

6. **For each `volatile_marker` hit**:
   - Is `volatile` being used as a sync primitive? C/C++ `volatile`
     does NOT provide atomicity or memory ordering. Java `volatile`
     gives visibility but not atomicity for compound ops.
   - **Findings to look for**: `volatile int counter; counter++;`
     (race), `volatile bool flag; if (!flag) { flag = true; ... }`
     (TOCTOU).

7. **For each `cancellation` hit**:
   - When cancellation fires, what state is left?
   - Are partial writes rolled back?
   - Is the parent notified, or is a goroutine / task silently
     dropped with held locks / open resources?

8. **For each potential issue**:
   - Cite `file:line`.
   - Describe the race / TOCTOU concretely (which two threads /
     requests, what state is corrupted).
   - State the smallest change.

9. **For each dismissed hit**: one sentence.

10. **For unknowns**:
    - Cross-process races (requires runtime / fuzzing)
    - Distributed-system races (requires multi-node analysis)
    - Whether a lock is actually held by callers (requires
      reachability analysis)

## What the skill MUST NOT do

- Do not flag every shared variable. The job is to find UNGUARDED
  shared mutable state, not all concurrency.
- Do not invent races from speculative scheduling. The skill must
  describe a CONCRETE scenario (thread A does X, thread B does Y)
  to confirm a finding.
- Do not extrapolate to other families.
- **Explicitly acknowledge tooling gap.** TSan / race-aware fuzzing
  is the dominant find-method for this family. Static analysis is
  necessary but rarely sufficient.

## Output
Print the report to STDOUT in Markdown. Do not use Write, Edit,
or NotebookEdit tools. The caller captures STDOUT and writes it to
the canonical `PACKET-NNN.findings.md` location.

**Output format**: the EXACT structure is defined by the OUTPUT CONTRACT
block injected into your context by the orchestrator (look for the
`=== OUTPUT CONTRACT ===` markers at the top of this prompt). Follow it
precisely — the downstream aggregator parses findings.md by regex and
any drift will silently drop findings from the final report.

Briefly, the contract requires these five H2 sections in order:
  ## Summary
  ## Confirmed issues (N)            ← with `### Issue 1:` / `### Issue 2:` subsections
  ## Dismissed sensor hits (M)
  ## Limitations / what I could not determine (K)
  ## Files read during investigation

Each confirmed issue MUST include five bold fields: **Severity:**,
**Verified at:**, **Input → sink chain:**, **Why it's real:**,
**Smallest fix:**. Severity values are only: info | low | medium | high
| critical.

## Failure modes the skill should report explicitly

- "All shared mutable state in this cluster is guarded by a single
  global mutex; lock-unlock pairing verified on all exit paths."
- "The TOCTOU window between stat() at line N and open() at line M
  is documented as 'acceptable race' in the comment; investigate
  via runtime if needed."
- "I could not statically verify lock ordering across all callers;
  this would require constructing the call graph for the cluster
  and is outside the skill's reach."
- "Race-detection harness (e.g. `go test -race`) coverage is
  positive evidence; I confirmed `go test -race` runs in CI but
  cannot verify the test suite exercises this path."

## Why this contract exists

Concurrency bugs are among the hardest to find statically and
among the most expensive to ship. The skill must be honest about
what static analysis can and cannot prove, and must DESCRIBE
specific race scenarios rather than vaguely suggest them.
