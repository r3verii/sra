# Skill — audit/business-logic (v0)

Investigates one packet under `.audit/04-packets-sensors/audit-business-logic/`.

## Inputs
- The single packet given in the prompt.
- The target repository, reachable from cwd.

## Tools allowed
- `Read`, `Grep`, `Glob` only.

## Tools FORBIDDEN
- `Write`, `Edit`, `NotebookEdit`, `Bash`, any network tool.

## What the skill does

Business-logic audit is the family with the LEAST help from
static analysis. Most bugs require understanding the business
rules — which only the team owning the code knows. The skill's job
here is narrower:

1. **Idempotency**: side-effectful endpoints (charge, refund,
   transfer, send-email, send-sms) should be idempotent. Missing
   idempotency on POST-only endpoints is a finding.
2. **State transitions**: workflows that go pending → approved →
   shipped → delivered should not allow `pending → shipped`
   directly. Look for unguarded `status = X` assignments.
3. **Race-prone patterns**: balance reads followed by writes without
   locking; check-then-act flows.
4. **Compensating actions**: when step N of a multi-step workflow
   fails, are steps 1..N-1 rolled back / compensated?

Hits categorised by `expected_role`:
- `payment_marker` — payment/billing keywords
- `idempotency_marker` — Idempotency-Key handling (positive sign)
- `state_transition` — `status = '...'` assignments
- `transaction_marker` — DB transactions / savepoints
- `concurrency_guard` — SELECT FOR UPDATE / version columns
- `state_machine_marker` — formal state-machine libraries

For each packet:

1. **Identify side-effectful endpoints**:
   - Search for HTTP handlers that mutate persistent state
     (database write, external API call, email/SMS send).
   - For each: is there an Idempotency-Key check?
   - **Findings to look for**: POST /charge / /refund / /transfer
     without idempotency.

2. **Map state transitions**:
   - For each `state_transition` hit, find the BEFORE state
     check. Does the code verify the previous state is the one
     expected, or does it just set the new state?
   - Pattern A (good): `if (order.status === 'pending') { order.status = 'paid' }`
   - Pattern B (bad): `order.status = 'paid'` (no precondition)
   - **Findings to look for**: state transitions without
     precondition check.

3. **Look for race-prone patterns**:
   - Balance check followed by debit:
     - `balance = user.balance; if (balance >= amount) user.balance -= amount` →
       race; two parallel debits both pass the check.
     - Should be: atomic update `UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?`
   - Uniqueness check followed by insert: should be `INSERT ... ON CONFLICT` or
     unique index + handle the conflict.
   - **Findings to look for**: read-then-write without locking on
     financial / quota / uniqueness paths.

4. **Compensating-action review**:
   - For multi-step workflows (e.g., charge card → create order →
     send confirmation), what happens if step 2 fails after step 1?
   - Is there a rollback / refund / cleanup?
   - **Findings to look for**: side-effects without inverse on
     failure.

5. **For each potential issue**:
   - Cite `file:line`.
   - Describe the business scenario that the issue enables (e.g.,
     "user submits the same POST twice; the system charges twice").
   - State the smallest fix.

6. **For each dismissed hit**: one sentence.

7. **For unknowns**:
   - Whether the business rule actually requires what the code
     enforces (the skill can't know the spec)
   - Idempotency provided at infrastructure layer (API gateway)
     not visible in code
   - Whether external system (Stripe, Paypal) handles idempotency
     for us

## What the skill MUST NOT do

- Do not flag every `status = X`. Verify the precondition.
- Do not invent business rules.
- Do not extrapolate to other families.
- **Acknowledge the spec gap.** Many findings here require
  knowing what the workflow SHOULD do; the skill can only flag
  structural anomalies.

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

- "All side-effectful endpoints in this cluster require an
  Idempotency-Key header (verified at file:line)."
- "State transitions are wrapped in transactions; on rollback
  the state assignment is undone."
- "Balance debits use atomic UPDATE with `balance >= ?` predicate;
  no read-then-write race visible."
- "I could not determine whether the workflow's intermediate
  steps are required to occur in order (e.g., whether `shipped`
  must come after `paid`); this requires the business spec."
- "Compensating actions for partial failure are not visible in
  this cluster; the workflow may be designed for eventual
  consistency."

## Why this contract exists

Business-logic flaws are simultaneously high-value and low-recall
for any automated tool. The skill must focus on PATTERNS that
have a structural answer (idempotency present? transaction
wrapped?) and explicitly defer to humans on rules that need
spec knowledge.
