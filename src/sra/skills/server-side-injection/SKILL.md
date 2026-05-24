# Skill — audit/server-side-injection (v0)

Investigates one packet under `.audit/04-packets-sensors/audit-server-side-injection/`.

## Inputs
- The single packet given in the prompt.
- The target repository, reachable from cwd.

## Tools allowed
- `Read`, `Grep`, `Glob` only.

## Tools FORBIDDEN
- `Write`, `Edit`, `NotebookEdit`, `Bash`, any network tool.

## What the skill does

Server-side injection audit asks one core question per sink:

> Does external input flow into a context that interprets that input
> as code / query / command / template?

Sub-classes:
1. **SQL injection** — input concatenated into a query string
2. **Command injection** — input passed to a shell-spawning API
3. **Template injection (SSTI)** — input interpreted as template
   markup
4. **Eval injection** — input passed to dynamic-evaluation APIs
5. **Expression-language injection** — JavaEL, OGNL, Spring SpEL, etc.

Hits categorised by `expected_role`:
- `sql_sink` — raw SQL APIs / interpolated SQL
- `command_sink` — shell-spawning functions
- `eval_sink` — dynamic-code-execution APIs / dynamic imports
- `ssti_sink` — template render with possibly user-controlled template

For each packet:

1. **Per `sql_sink` hit**:
   - Read the call site. What's the query argument?
   - If it's a constant string → safe.
   - If it's a parameterised string with placeholders (`?`, `$1`,
     `:name`) and the user data goes through the placeholder args →
     safe.
   - If it's a string concatenation / f-string / template literal
     with user data embedded → **finding** (SQL injection).
   - Trace where the embedded value comes from. Is it from
     request body / query / path?
   - **Findings to look for**: SQL query strings that interpolate
     user data via `${...}`, `#{...}`, `%s`, f-strings, or `+`.

2. **Per `command_sink` hit**:
   - What's the command argument? Constant → safe.
   - Variable → trace where it comes from.
   - If a shell is invoked (`shell=True`, command-line interpreted
     by `/bin/sh`, backticks) → command injection via
     metacharacters even if "validated".
   - **Findings to look for**: any shell-exec call with a
     non-constant argument that's not whitelisted.

3. **Per `eval_sink` hit**:
   - Dynamic-code APIs with non-constant arguments that include
     user input → almost always a finding.
   - Parsing JSON via the eval-family API → use a real JSON parser
     instead.
   - Restricted expression parser (calculator-style with a strict
     grammar) → may be OK; otherwise finding.

4. **Per `ssti_sink` hit**:
   - Is the template string constant, or is the user-provided
     value the template itself?
   - User-data IN a constant template = safe.
   - User-controlled template string = SSTI.
   - **Findings to look for**: render-from-string with user input
     as the template argument.

5. **For each potential issue**:
   - Cite `file:line`.
   - Show the trace: request field → variable → sink.
   - State the smallest fix (parameterise the query, use array-style
     args without a shell, switch to a safe alternative).

6. **For each dismissed hit**: one sentence on why.

7. **For unknowns**:
   - Validation in middleware not visible from the sink
   - Whitelisting applied via a config not in the cluster
   - Whether ORM layer's `where` accepts strings or only objects

## What the skill MUST NOT do

- Do not flag every `query()` call. Verify the argument.
- Do not flag ORM lookups with object-style `where`. Only string-
  style filters are vulnerable.
- Do not extrapolate to other families.
- **Be specific about the injection vector.** "Maybe injectable"
  is not a finding; "user-controlled value reaches sink at file:line"
  is.

## Output
Print to STDOUT. Standard schema.

## Failure modes the skill should report explicitly

- "All SQL in this cluster uses parameterised queries via
  ORM-managed query builder. No string concatenation visible."
- "The shell-exec call at file:line invokes a constant command
  with no user-controlled arguments."
- "The dynamic-evaluation call at file:line evaluates a constant
  whitelist expression; user input only selects among predefined
  branches."
- "I could not determine whether the `where` filter passed to
  `Model.find` is treated as a string or an object; this depends
  on the ORM version (some accept both)."

## Why this contract exists

Injection is the most well-documented class of vulnerability
and SAST does it best — but the false-positive rate is high.
The skill must be ruthless about distinguishing PARAMETERISED
queries (safe) from CONCATENATED ones (vulnerable), and about
following the actual data flow rather than flagging by sink
keyword alone.
