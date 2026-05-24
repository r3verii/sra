# Skill — audit/memory-safety (v0)

This file defines the contract for the Claude skill that consumes a
single `PACKET-NNN.md` under
`.audit/04-packets-sensors/audit-memory-safety/` and produces a
structured investigation report.

The skill is invoked **once per packet**. It does not aggregate across
packets and does not propose findings outside the packet's cluster.

## Inputs

- **The single packet you are given** in this invocation. Its content
  is pasted into the prompt. **Do not search for, list, open, or
  investigate any other packet.** Other packets are handled by other
  invocations of this skill.
- **The target repository** is reachable from the current working
  directory. The skill may read files, search, and list — but only
  inside the repo.

## Tools allowed

- `Read` — open any file in the target repository.
- `Grep` — search for symbols, callers, allocations, frees, sizes.
- `Glob` — locate files by pattern.

## Tools FORBIDDEN

- `Write`, `Edit`, `NotebookEdit` — the skill never modifies the target.
- `Bash`, `PowerShell` — no shell execution.
- Any network tool (`WebFetch`, `WebSearch`).
- Any other tool not listed above.

If a needed action is outside this list, record it as a **limitation**
in the report and stop.

## What the skill does

This family is **fundamentally different** from input-validation.
Sensor hits identify *allocations*, *frees*, *unsafe string operations*,
*raw memory copies*, *unsafe Rust blocks*, and *FFI boundaries* — not
input boundaries. The investigation must reason about lifecycle, size
arithmetic, and trust boundaries rather than validation chains.

For each packet:

1. **Read the packet**. Identify the cluster's directory, role, files,
   and the hits by `expected_role`:
   - `allocator` / `allocator_stack` / `allocator_cpp`
   - `deallocator`
   - `unsafe_sink` (gets, strcpy, sprintf, etc.)
   - `bounded_sink` (strncpy, snprintf)
   - `raw_copy_sink` (memcpy, memmove)
   - `format_sink` (printf-family with variable format)
   - `size_arith_sink` (multiplication into malloc)
   - `type_pun_sink` (reinterpret_cast, transmute, char* casts)
   - `trust_boundary` (unsafe blocks, unsafe fn)
   - `ownership_transfer` (from_raw / into_raw)
   - `uninit_sink` (set_len)
   - `ffi_boundary` (cgo C.malloc / C.GoBytes)

2. **For each `unsafe_sink` hit**, open the file and read the
   surrounding function. Ask:
   - Where does the source buffer / string come from?
   - Is its length bounded by a check the function relies on?
   - Is the destination buffer large enough in the worst case?
   - Is the destination sized using a constant, or a runtime
     expression?

3. **For each `bounded_sink` hit** (strncpy, snprintf):
   - Is the bound the *destination size* or some other quantity?
   - Is NUL-termination explicit, or is the bound `sizeof(dest)`
     leaving a non-NUL-terminated buffer?
   - Is the return value (truncation indicator) checked?

4. **For each `raw_copy_sink` hit** (memcpy, memmove):
   - Where does the size argument come from?
   - If it's input-derived, is there a `<= sizeof(dest)` check before
     the call?
   - Is integer overflow possible on the size computation
     (multiplication, addition)?

5. **For each `size_arith_sink` hit** (`malloc(n * size)`):
   - Could `n * size` overflow on this platform's `size_t`?
   - Is there a prior check like `n <= SIZE_MAX / size`?
   - Could this be replaced safely with `calloc(n, size)`?

6. **For each `allocator` / `deallocator` cluster**, ask:
   - Is every allocation paired with a free on every exit path?
   - Are there error paths that return without freeing?
   - Can the same pointer be freed twice across error paths?
   - Is the pointer set to NULL after free, or could a later free()
     hit a stale pointer?

7. **For each `trust_boundary` hit** (Rust `unsafe`, Go `unsafe`):
   - What is the invariant the unsafe block depends on?
   - Is the invariant comments-documented and enforced upstream?
   - Is the unsafe scope minimal, or does it span more code than
     necessary?

8. **For each `ffi_boundary` hit** (Go cgo, Rust FFI):
   - Who owns the memory across the boundary?
   - On what side is it freed?
   - Does the lifetime match the C-side expectations?

9. **For each `type_pun_sink` hit** (reinterpret_cast, transmute,
   `(char *)` casts):
   - What is the source type, what is the destination type?
   - Do the alignment and size rules permit the punning?
   - Is the source coming from input or from another typed allocation?

10. **Cross-check tests when present.** Look for fuzzing harnesses
    (libFuzzer, AFL), sanitizer test runs (ASan, MSan, UBSan), and unit
    tests that exercise the boundary. Their presence is positive
    evidence that the team is aware of the surface.

11. **For each potential issue**:
    - Decide whether the sensor hit represents a real, reachable
      problem in this code.
    - Cite the **file:line** you verified.
    - Record the smallest change that would eliminate the issue.

12. **For each sensor hit you dismiss**:
    - Record why in one short sentence.

13. **For anything you could not determine** (callers of the function,
    runtime configuration, fuzzing coverage you couldn't enumerate),
    record it as a **limitation**.

## What the skill MUST NOT do

- Do not report a finding based on the sensor hit alone. Memory-safety
  hits in particular are noisy — every memcpy in a parser fires, most
  are safe. Verify by reading.
- Do not invent risks outside the packet's cluster. Other packets
  cover other clusters.
- Do not propose patches unless asked.
- Do not extrapolate to other families (no input-validation, no crypto,
  no concurrency) even when adjacent code triggers them.
- **Do not assume modern compilers / OS protections fix the issue.**
  Stack canaries, ASLR, fortify-source, etc. are mitigations, not
  fixes. Report the underlying defect.

## Output

**Print the report to STDOUT**, in Markdown. Do not write any file. Do
not use the Write, Edit, or NotebookEdit tools.

Output structure (no preamble, no "I will now investigate" text — just
the report):

    # PACKET-NNN — investigation report

    ## Summary
    <2-4 sentences: what was reviewed, what was confirmed, what
    remained open.>

    ## Confirmed issues (N)
    <For each: a section with severity hint (info/low/med/high/critical),
    the file:line you verified, the lifecycle / size derivation /
    trust-boundary chain you traced, and the smallest change that would
    close it.>

    ## Dismissed sensor hits (M)
    <Bulleted list. Each: file:line of the sensor hit + one short
    sentence on why it is not a real issue here.>

    ## Limitations / what I could not determine (K)
    <Bulleted list. Each: concrete sentence on what static read could
    not answer (whole-program reachability, dynamic dispatch,
    sanitizer/fuzzer coverage you could not verify, etc.).>

    ## Files read during investigation
    <List of file:line ranges + any Grep / Glob queries.>

## Failure modes the skill should report explicitly

- "Every sensor hit in this cluster is inside a function that is
  unreachable from external input (verified by Grep)."
- "All allocations are paired with free on every exit path examined."
- "Sensor hits cluster in `*_test.c` / `fuzz_*.c` — this is the test
  harness, not production code."
- "I could not determine the bound of `n` in `malloc(n * size)`
  because `n` is set in a different translation unit."
- "Sanitizer build evidence is present (`ASAN_OPTIONS`, `-fsanitize`
  flags in build files) but I could not verify the actual fuzzer
  coverage; check `oss-fuzz` or `OSS-Fuzz-style` infrastructure."

## Why this contract exists

Memory-safety findings are the highest-stakes class of bug in C/C++
codebases — and the noisiest class of sensor hit. Every memcpy fires;
almost none are vulnerabilities. The skill's job is to **convert
noisy seeds into bounded, evidence-cited verdicts**. A finding here
must include the actual trace from input to corrupted state, not just
a sensor hit.

For Rust / Go, the analogous role is converting `unsafe` / `cgo`
markers into "is the invariant documented and upheld?" answers.
