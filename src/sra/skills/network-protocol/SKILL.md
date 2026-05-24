# Skill — audit/network-protocol (v0)

Investigates one packet under
`.audit/04-packets-sensors/audit-network-protocol/`.

## Inputs

- The single packet given in the prompt.
- The target repository, reachable from cwd.

## Tools allowed

- `Read`, `Grep`, `Glob` only.

## Tools FORBIDDEN

- `Write`, `Edit`, `NotebookEdit`, `Bash`, any network tool.

## What the skill does

Network-protocol audit asks four questions, in priority order:

1. **Request smuggling**: when Content-Length and Transfer-Encoding
   both appear, what does the implementation do? RFC 7230 § 3.3.3
   requires either case 3 (reject) or case 4 (use TE, drop CL). Many
   real-world bugs come from one layer using one rule and another
   layer using the opposite.

2. **Header normalization**: at which layer does header
   case-folding / whitespace-trimming happen? Do all consumers see
   the same normalized form, or does an early consumer see raw bytes
   while a later one sees normalized?

3. **Connection reuse**: when keep-alive is on, is request state
   (headers, body buffer, chunked decoder state) cleaned between
   requests? Reuse bugs are connection-poisoning vectors.

4. **Cross-version translation**: when HTTP/1 ↔ HTTP/2 ↔ HTTP/3
   translation happens (any proxy, gateway, or rewriter), is request
   framing preserved? HTTP/2 doesn't have CL; H2-to-H1 downgrade
   adds it. The translation point is high-value.

Hits categorised by `expected_role`:

- `framing_header` — TE / CL / chunked markers
- `header_parser` — header parse entry points
- `header_normalize` — case-folding / canonicalization paths
- `connection_reuse` — keep-alive / connection-state markers
- `http2_marker` — HTTP/2 frame / library usage
- `tls_marker` — TLS API usage

For each packet:

1. **Find every TE / CL parser**.
   - Use Grep + Read to locate where `Transfer-Encoding` is parsed
     and where `Content-Length` is parsed.
   - When both are present, which wins?
   - Is the implementation RFC 7230 § 3.3.3 compliant?
   - **Findings to look for**: silent prefer-one-over-other (often
     CL), no rejection of conflicting headers, accepting
     `Transfer-Encoding: chunked\r\nTransfer-Encoding: identity`,
     accepting `Transfer-Encoding: chunked, identity`, accepting
     non-canonical case (`Transfer-encoding:`).

2. **Trace each `header_normalize` hit**.
   - When does normalization happen — at parse time, at access time,
     never?
   - Are downstream consumers normalization-aware?
   - **Findings to look for**: header set at parse time before
     normalization; downstream code matches on canonical form but
     the proxy passed raw.

3. **Verify connection reuse cleanup**.
   - On request completion, is the parser state reset?
   - Are body-buffer / chunked-decoder buffers freed or cleared?
   - On error mid-request, is the connection closed (not reused)?
   - **Findings to look for**: state leaks between requests on the
     same connection; chunked-decoder retains state on error.

4. **For each HTTP/2 ↔ HTTP/1 translation point**:
   - When converting H2 to H1, what is Content-Length set to?
   - When converting H1 to H2, is `Transfer-Encoding: chunked`
     stripped?
   - Is the body length translation lossless?
   - **Findings to look for**: smuggling via the translation gap.

5. **TLS configuration**:
   - What protocol versions are accepted?
   - Is there a downgrade defense (e.g. TLS_FALLBACK_SCSV check)?
   - Renegotiation: is it allowed, and is the post-handshake state
     re-validated?
   - **Findings to look for**: TLS 1.0/1.1 accepted, renegotiation
     accepted from client without authentication change.

6. **For each potential issue**:
   - Cite the exact `file:line`.
   - Describe the smuggling / normalization gap concretely with a
     payload example if possible (do NOT execute anything — just
     describe what would trigger the issue).
   - State the smallest change that would close it.

7. **For each dismissed hit**:
   - One sentence on why.

8. **For unknowns**:
   - Behaviour you cannot determine without a differential test
     against another implementation.
   - Behaviour that depends on runtime configuration (e.g. nginx
     `proxy_http_version`, HAProxy `option http-server-close`).

## What the skill MUST NOT do

- Do not flag every header access. The job is framing-level
  semantics, not application validation.
- Do not extrapolate to other families.
- **Acknowledge when differential testing is the right tool.** The
  most common real findings here come from comparing two
  implementations side-by-side (e.g. the frontend says CL is
  authoritative, the backend says TE is). Static analysis can flag
  the divergence point but cannot prove exploitability.

## Output

Print to STDOUT. Same schema as other family skills:

    # PACKET-NNN — investigation report
    ## Summary
    ## Confirmed issues (N)
    ## Dismissed sensor hits (M)
    ## Limitations / what I could not determine (K)
    ## Files read during investigation

## Failure modes the skill should report explicitly

- "TE and CL are both parsed; the code at file:line rejects
  requests where both are present. RFC 7230 § 3.3.3 case 3
  compliant. No smuggling vector visible at this layer."
- "Header normalization happens at parse time in `parse_headers`
  (file:line); downstream access via `get_header(name)` performs
  case-insensitive lookup. Consistent."
- "I could not verify cross-implementation behaviour
  (smuggling-class bugs require differential testing against the
  upstream / downstream HTTP implementations)."
- "Renegotiation is not visible in this cluster's code; the TLS
  library defaults apply, and the deployment configures the
  library at runtime — out of scope for static review."

## Why this contract exists

Request-smuggling is among the highest-impact and lowest-detectable
bug classes in web infrastructure. SAST tools rarely find it;
human review with explicit attention to RFC 7230 / 9112 nuance
finds most cases. The skill's job is to bring that human-style
attention to bear in a bounded, traceable way.
