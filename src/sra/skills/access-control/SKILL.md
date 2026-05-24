# Skill — audit/access-control (v0)

Investigates one packet under `.audit/04-packets-sensors/audit-access-control/`.

## Inputs
- The single packet given in the prompt.
- The target repository, reachable from cwd.

## Tools allowed
- `Read`, `Grep`, `Glob` only.

## Tools FORBIDDEN
- `Write`, `Edit`, `NotebookEdit`, `Bash`, any network tool.

## What the skill does

Access-control audit asks three questions:

1. **Authentication**: every protected route requires authentication?
   Are there debug / health / admin routes that bypass auth?
2. **Authorization (BOLA)**: when a route loads a resource by user-
   supplied ID, does it verify the current user OWNS the resource
   (or has explicit permission to it)?
3. **Privilege escalation**: are role / permission checks placed
   BEFORE the action they protect, on every code path?

Hits categorised by `expected_role`:
- `auth_check` — middleware / decorator / annotation enforcing auth
- `identity_source` — `req.user` / `request.user` / context.UserID
- `resource_load_by_id` — ORM lookup with user-supplied ID
- `role_check` — `hasRole` / `is_admin` / `PreAuthorize` etc.

For each packet:

1. **Enumerate routes in the cluster**.
   - Each handler / controller method = one route.
   - For each route: what's the URL pattern, what's the HTTP method?

2. **Per route, verify authentication**:
   - Is there a `@login_required` / `requireAuth` / middleware /
     `@PreAuthorize` / `Auth::middleware` etc. that gates this route?
   - If middleware is registered at app/router level, verify the
     route is under that scope.
   - **Findings to look for**: routes with no auth check; routes
     under a router that explicitly bypasses auth; admin routes
     accessible without a role check.

3. **Per route, trace the BOLA pattern**:
   - Does the route take an ID from the URL / query / body?
   - Does it load a resource by that ID?
   - Between load and response, is there a check that
     `resource.owner_id == request.user.id` (or equivalent)?
   - **Findings to look for**: route loads
     `Resource.find(req.params.id)` and returns it without verifying
     the resource belongs to the current user. This IS the BOLA
     pattern. Confirm by reading the handler.

4. **Per `role_check` hit**:
   - Is the check BEFORE the privileged action, or after (effectively
     no protection)?
   - Is the check on every code path leading to the action, or only
     the happy path?
   - Are there shortcuts via "internal" methods that bypass the check?
   - **Findings to look for**: role check in one method, action in
     another method called from elsewhere without check; check after
     a side effect.

5. **Look for bypass paths**:
   - Debug routes: `/debug/...`, `/admin/...`, `/health` (often
     bypass auth)
   - Internal API endpoints: marked "internal" but exposed
   - Batch / cron / job endpoints: triggered via HTTP, may skip
     standard middleware
   - **Findings to look for**: any of these accessible without auth.

6. **Identity source consistency**:
   - The user identity should come from: session, verified JWT,
     authenticated header — NOT from request body / query.
   - **Findings to look for**: `user_id = req.body.user_id` (user-
     controlled, not authenticated).

7. **For each potential issue**:
   - Cite `file:line`.
   - Describe the missing check and the attack scenario (user A
     requests `/users/B/orders/123`, system returns B's data).
   - State the smallest change (add ownership filter, add role
     check, etc.).

8. **For each dismissed hit**: one sentence.

9. **For unknowns**:
   - Middleware applied at the framework configuration level (not in
     the cluster code)
   - Tenant isolation enforced at the DB layer (row-level security)
     not visible in handler code
   - Business rules that say "managers can see their reports' data"
     — context-dependent

## What the skill MUST NOT do

- Do not flag every `Model.find(id)`. Verify whether ownership is
  checked.
- Do not flag every route. Verify whether the route is meant to be
  public.
- Do not extrapolate to other families (not input-validation, not
  crypto).
- **Distinguish authentication from authorization.** "Logged in"
  ≠ "allowed to see this object".

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

- "All routes in this cluster are guarded by
  `@PreAuthorize('hasRole(...)')`; no bypass paths visible."
- "The `OrderController.show(id)` handler at file:line loads the
  order by ID but the next line filters `where order.user_id ==
  current_user.id`. BOLA risk mitigated."
- "I could not determine whether the middleware applied at the
  router-level (router file outside this cluster) actually gates
  every route here. Confirm by reading the router config."
- "The `is_admin` check at file:line happens AFTER the
  side-effect-causing call at file:line. The action runs even when
  the check would fail."
- "Tenant isolation appears to rely on row-level security in the
  DB (not visible in this cluster's handler code). Verify the DB
  policy."

## Why this contract exists

BOLA / IDOR is the #1 OWASP API risk and the most under-detected
class. SAST tools miss it because they require business-context
understanding ("user A's order vs user B's order — are they
distinguished?"). The skill's job is to bring that context-aware
reading to bear, route by route.
