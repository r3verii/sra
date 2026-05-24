# Skill — audit/client-side (v0)

Investigates one packet under `.audit/04-packets-sensors/audit-client-side/`.

## Inputs
- The single packet given in the prompt.
- The target repository, reachable from cwd.

## Tools allowed
- `Read`, `Grep`, `Glob` only.

## Tools FORBIDDEN
- `Write`, `Edit`, `NotebookEdit`, `Bash`, any network tool.

## What the skill does

Client-side audit asks four questions:

1. **XSS sinks**: when user data flows into a DOM sink (innerHTML,
   the React HTML-injection prop, v-html, bypass-security APIs), is
   the data sanitised first?
2. **URL schemes**: when user data flows into `href` / `src` /
   `action`, is the scheme verified against a whitelist (no
   `javascript:`, `data:`, `vbscript:`)?
3. **postMessage**: do message listeners verify `event.origin`
   against an expected origin, and do senders specify a non-* target
   origin?
4. **Markdown / rich-text**: is the rendered output passed through a
   sanitiser before injection into the DOM?

Hits categorised by `expected_role`:
- `html_sink` — innerHTML / React-bypass / v-html / triple-mustache
- `url_sink` — href / src / navigation
- `postmessage` — message receive / send
- `markdown_render` — marked / markdown-it / showdown
- `sanitiser` — DOMPurify / sanitize-html (positive evidence)

For each packet:

1. **Per `html_sink` hit**:
   - What value is assigned?
   - Constant string → safe.
   - Variable → trace it. Does it come through a sanitiser
     (DOMPurify.sanitize, sanitize-html)?
   - Does it come from server response (still risky if server
     reflects user data)?
   - **Findings to look for**: any HTML sink where user data
     reaches without going through a sanitiser.

2. **Per `url_sink` hit**:
   - When user data becomes part of an href / src / action:
     - Is the scheme verified (`url.startsWith('https://')` or
       URL-object parsing)?
     - Is `javascript:` / `data:text/html` / `vbscript:` rejected?
   - **Findings to look for**: user-supplied URL used in
     navigation without scheme validation.

3. **Per `postmessage` hit**:
   - For receivers: is `event.origin` checked against a known
     whitelist BEFORE acting on `event.data`?
   - For senders: is the target origin a specific URL, not `*`?
   - **Findings to look for**: receivers without origin check;
     senders using `'*'` as target with sensitive data.

4. **Per `markdown_render` hit**:
   - Is the renderer configured with safe defaults (no raw HTML
     pass-through)?
   - Is the output passed through DOMPurify or sanitize-html
     before DOM injection?
   - **Findings to look for**: markdown rendered to HTML then
     directly assigned to innerHTML / the React-bypass prop
     without sanitisation.

5. **Cross-cluster context**:
   - The page may have a CSP that mitigates XSS. Note its
     presence as a defense-in-depth observation.
   - The framework may auto-escape; the question is what escape
     hatches are used and why.

6. **For each potential issue**:
   - Cite `file:line`.
   - Show the trace: source (URL param? server response? user
     input?) → variable → sink.
   - Smallest fix: route through DOMPurify, validate scheme, check
     origin.

7. **For each dismissed hit**: one sentence.

8. **For unknowns**:
   - CSP enforced at server / proxy level (not visible in client
     code)
   - Trusted-Types policy applied at runtime
   - Whether a markdown library was configured at startup outside
     this cluster

## What the skill MUST NOT do

- Do not flag every `innerHTML`. Verify what's assigned.
- Do not flag every `href`. Verify the source of the URL.
- Do not flag every `postMessage`. Receivers without input usage
  may be safe; senders to known origins are fine.
- Do not extrapolate to other families.
- **Be specific about the XSS vector** — "user data reaches sink at
  file:line without sanitisation".

## Output
Print to STDOUT. Standard schema.

## Failure modes the skill should report explicitly

- "All HTML-sink assignments in this cluster use DOMPurify.sanitize
  on the value before assignment."
- "The URL in the navigation call is constructed from a
  whitelist of known endpoints; user input only selects the index."
- "The postMessage receiver at file:line checks `event.origin ===
  'https://...known-origin...'` before processing."
- "I could not determine whether the server's CSP allows
  'unsafe-inline' — verify the CSP header at the server config."
- "The markdown library is configured at app init outside this
  cluster; verify `sanitize: true` in that config."

## Why this contract exists

XSS is the bread-and-butter web vulnerability. The skill must
distinguish between sinks that handle user data (vulnerable) and
sinks that handle constants / framework-internal data (safe). The
contract demands TRACING, not pattern-flagging.
