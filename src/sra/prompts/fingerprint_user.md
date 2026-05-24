# Repository fingerprinting — user prompt

Below is the `raw-summary.md` produced by `sra collect` for a target
repository.

Read it carefully and emit the JSON fingerprint described in the system
prompt.

Reminders:

- Use only evidence visible in the summary below.
- Prefer `unknowns` over guessing.
- Mark per-label confidence honestly. `"low"` whenever evidence is
  indirect, ambiguous, or derived from a single weak signal.
- `suggested_modes` items must be one of `"packet"`, `"research_trail"`,
  or `"both"`.
- `suggested_packs` items must be shaped `"<category>/<identifier>"`
  (categories: `language`, `domain`, `protocol`, `vuln`).
- Respond with one strict JSON object — no markdown fences, no prose
  around it.

---

{{raw_summary_md}}
