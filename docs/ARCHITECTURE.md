# SRA architecture

Long-form architectural overview of the SRA audit pipeline. The
[project README](../README.md) is the user-facing entry point; this
document is for someone who needs to understand *how* the pipeline is
wired before extending it.

## Identity

SRA is an **orchestrator for audit skills** — primarily
[Trail of Bits' skills](https://github.com/trailofbits/skills),
supplemented by our own family skills where ToB has no equivalent.
We compose; we do not duplicate.

|  | We provide | Trail of Bits provides |
|---|---|---|
| **Sensor catalogs** | ripgrep / semgrep / ast-grep patterns per family (~778 patterns) | — |
| **Packet builder** | cross-sensor dedup, clustering, micro-fold, adaptive cap | — |
| **Orchestrator** | `sra audit`: stages + per-packet skill invocations + parallelism | — |
| **Aggregator** | cross-packet dedup, top-files panel, Coverage Map, per-repo report | — |
| **Family skills** | 12 SKILL.md under `src/sra/skills/<family>/` | 74 vendored SKILL.md (also under `src/sra/skills/`) |

## Pipeline stages

```
00 collect                       — no LLM
01 fingerprint                   — 1 LLM call
02 route-packs                   — no LLM
04a context-building   (ToB)     — 1 LLM call          [optional]
04b entry-points       (ToB)     — 1 LLM call          [optional, contracts-only]
   ┌─── per family ───┐
   │ 03 sensors        — no LLM  (rg + semgrep + ast-grep)
   │ 04 packet build   — no LLM  (cross-sensor dedup → cluster → micro-fold → cap)
   │ 05 skill phase    — N LLM calls (one per production packet, parallelisable)
   └──────────────────┘
06a variant-analysis (ToB)       — 1 LLM call per confirmed finding   [optional]
06b fp-check         (ToB)       — 1 LLM call per repo                [optional]
05 build-report                  — no LLM (deterministic roll-up + Coverage Map)
07 synthesis                     — 1 LLM call (executive report + attack chains)
```

| Stage | What it does | LLM | Source | On-disk path |
|---|---|:---:|---|---|
| 00 collect | Walk repo, write neutral structural signals | — | ours | `.audit/00-fingerprint/raw-signals.json` |
| 01 fingerprint | Classify languages, frameworks, audit families | ✓ | ours | `.audit/00-fingerprint/fingerprint.json` |
| 02 route-packs | Normalise `suggested_packs` → `audit_families` + backstop rules | — | ours | `.audit/01-pack-router/selected-packs.json` |
| 02 plan | Expand each family into a per-family workflow plan | — | ours | `.audit/02-plan/audit-plan.json` |
| 04a context-building | Architectural understanding before hunting | ✓ | ToB `audit-context-building` | `.audit/04-context/context-building.md` |
| 04b entry-points | Map state-changing entry points (smart-contract repos only) | ✓ | ToB `entry-point-analyzer` | `.audit/04-context/entry-points.md` |
| 03 sensors | Per-family rg / sg / ast-grep scan | — | ours | `.audit/03-evidence/<family>/sensors/<sensor>/` |
| 04 packet build | Dedup + cluster + micro-fold + cap sensor hits into packets | — | ours | `.audit/04-packets-sensors/<family>/PACKET-NNN.md` |
| 05 skill phase | One LLM call per production packet | ✓ | ours OR ToB drop-in | `…PACKET-NNN.findings.md` |
| 06a variant-analysis | One call per confirmed finding | ✓ | ToB `variant-analysis` | `.audit/06-variants/<PACKET>-<n>.md` |
| 06b fp-check | Audit-of-audits across every findings file | ✓ | ToB `fp-check` | `.audit/06-fp-check/audit-of-audits.md` |
| 05 build-report | Deterministic structural roll-up + Coverage Map | — | ours | `.audit/05-report/repo-report.{md,json}` |
| 07 synthesis | Re-read all artifacts, chain attacks, executive report | ✓ | ours `audit-synthesis` | `.audit/07-synthesis/security-audit-report.md` |

Note: the *on-disk* numbering (`03-evidence`, `04-packets-sensors`,
`05-report`, `06-variants`, `06-fp-check`, `07-synthesis`) preserves
the original layout. The *logical* order in `cmd_audit` is what the
column ordering above describes.

### Resumability

Every stage in `cmd_audit` checks for its output file and skips unless
`--force` is set globally (or its specific `--force-<stage>` flag
overrides only that stage). The `--no-<stage>` flags suppress
individual LLM stages; `--no-skills` suppresses every LLM stage at
once. Sensor stages are also resume-safe: a re-run with existing
`index.json` skips the scan unless `--force` is passed.

Ctrl+C cleanly stops the pipeline:
- In-flight `claude` subprocesses get SIGTERM.
- The per-packet parallel pool drains in-flight work and skips the
  rest.
- A partial report is still produced from whatever findings landed.

## The packet-builder pipeline

Sensor hits go through five passes before becoming review packets:

1. **`_load_sensor_hits`** — read every `sensors/<sensor>/*.json` and
   flatten into one list of hit dicts.
2. **`_merge_cross_sensor_hits`** — fold duplicates by `(path, line)`.
   When rg + sg + ast-grep all flag the same line, the result is one
   hit with `sensors_matched=["ripgrep", "semgrep", "ast-grep"]` and
   `consensus_count=3`. The LLM sees a `[3 sensors]` badge in the
   packet and prioritises high-consensus locations.
3. **`_cluster_sensor_hits`** — group by `(parent_dir, role)`, sort by
   role priority and consensus density.
4. **`_fold_micro_clusters`** — clusters with fewer than
   `--micro-fold-threshold` hits (default 10) get merged into their
   nearest sibling (same role, ≥2 common path components). Empirically
   trims ~25% of packet count on Java/Spring layouts with zero data
   loss. Disable with `--no-micro-fold`.
5. **`_resolve_packet_cap`** — three-tier cap on packet count:
   - `--family` flag set ⇒ **no cap** (user-intent to focus = give
     full depth).
   - No `--family` ⇒ **adaptive cap**:
     `min(30 + (file_count // 1000) * 5, 80)`. Caps at 80; scales
     up to that ceiling based on `total_file_count` from
     `raw-signals.json`.
   - Explicit numeric cap (reserved for a future `--max-packets N`).

Output: `PACKET-NNN.md` for each cluster + `packet-index.json` with
attribution metadata (`folded_in`, `multi_consensus_hits`,
`raw_hit_count`, etc.).

## The language filter (`--only-lang` / `--exclude-lang`)

Implemented as a `LanguageFilter` helper in `cli.py`. Canonical
language tokens map to (a) file extensions, (b) ripgrep
`lang_group` keys, (c) ast-grep `--lang` values. Applied in three
stages:

1. **Sensor stage**: skip ripgrep / ast-grep patterns whose language
   doesn't match. Manifest / IaC / CI groups always run (they're
   language-agnostic).
2. **Semgrep post-filter**: semgrep runs repo-wide and can't be
   filtered upfront, so we drop findings whose path is outside scope.
3. **Packet-builder safety net**: even on a resumed audit reusing old
   sensor output, hits outside scope get dropped before clustering.

Config / manifest / IaC files (Dockerfile, `package.json`,
`.github/workflows/*.yml`, …) always pass — the filter scopes source
code only.

## Cross-packet aggregation (`build-report`)

`src/sra/report.py::_aggregate_findings` is the deterministic
aggregator. It de-duplicates findings across packets using a 4-tier
strategy:

1. **Exact**: same title + same file + same line.
2. **Fuzzy title**: normalized-title equality across the same file
   (handles "SQLi in users.go:42" vs "SQL injection at users.go:42").
3. **Same file, different titles**: kept separate but cross-linked.
4. **Cross-file with shared root cause**: detected via title overlap +
   severity match; flagged as related but kept distinct.

The report also renders a **Coverage Map** with five statuses per
family:
- *Investigated* — sensor ran, packets built, skill phase produced
  findings.
- *Elected clean* — fingerprint elected it, skill ran, zero findings.
- *Elected pending* — elected but skill stage hasn't completed.
- *CLI override* — user passed `--family X`, others were skipped.
- *Not in scope* — fingerprint didn't elect.

Coverage Map gives the reader explicit visibility into "what wasn't
audited and why" rather than silent omissions.

## Skill registry

[`src/sra/skill_registry.py`](../src/sra/skill_registry.py) is the
single source of truth for **every** audit skill — ours or ToB.
Each entry is a frozen `SkillSpec`:

```python
@dataclass(frozen=True)
class SkillSpec:
    name: str
    stage: Stage          # pre-audit | family | post-confirmed |
                          # post-audit | alt-mode | dev-tool
    trigger: Trigger      # per-repo | per-packet | per-confirmed |
                          # per-mode | manual
    source: Source        # "ours" | "tob"
    path: str             # SKILLS_DIR-relative path to SKILL.md
    references_dir: str | None = None
    allowed_tools: tuple[str, ...] = ("Read", "Grep", "Glob")
    family: str | None = None
    dependencies: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    description: str = ""
```

`SKILLS_DIR = Path(__file__).parent / "skills"` — package-relative so
it resolves identically under `pip install -e .` and `pipx install`.

Verify the whole registry resolves to existing files:

```bash
python -m sra.skill_registry --verify
```

Registry size: **46 entries** across six categories (pre-audit,
family-overlap drop-ins, family slots, post-confirmed, post-audit,
alt-mode, dev-tool). 86 skill directories under `src/sra/skills/` —
some plugins ship multiple sub-skills not all of which have registry
entries (we register what the orchestrator actually invokes).

## Skill loader

[`src/sra/skill_loader.py`](../src/sra/skill_loader.py) consumes a
`SkillSpec` and produces the markdown blob that gets piped into
`claude -p`:

```python
def load_skill_prompt(
    skill_name: str,
    *,
    target_language: str | None = None,
    extra_context: list[str] | None = None,
) -> str: ...
```

What the loader does:
- **`{baseDir}` templating** — every literal `{baseDir}` in the
  SKILL.md (and any references file) is replaced with the absolute
  path to the SKILL.md's parent directory.
- **Dependencies** — `spec.dependencies` walked depth-first
  post-order with a seen-set to break cycles. Unknown deps are
  silently skipped (the registry `--verify` is responsible for
  catching those).
- **Language references** — if `references_dir` is set and
  `target_language` is provided, append the matching
  `references/<lang>.md` (with a small alias map: `rust` → `solana`,
  `cpp` → `c++`, etc).
- **Extra context** — used by the orchestrator to forward 04a / 04b
  output to family skills, and to compose `constant-time-analysis` /
  `zeroize-audit` / `dimensional-analysis` into the relevant family
  packets.

CLI for one-off testing:

```bash
python -m sra.skill_loader audit-context-building
python -m sra.skill_loader entry-point-analyzer --language solidity
python -m sra.skill_loader sharp-edges --language python
```

## Family-skill orchestration

For each `PACKET-NNN.md`, `cmd_audit`:

1. Looks up the family `SkillSpec` via
   `_family_skill_spec("audit/<family>")`.
2. Builds the `extra_context` block:
   - 04a + 04b output is prepended when available.
   - For `audit/crypto-auth`, scans packet text for
     compare/equal/hmac/signature/timing → adds
     `constant-time-analysis`; for key/secret/zero/secure_erase/mlock
     → adds `zeroize-audit`.
   - For `audit/business-logic`, scans for
     unit/precision/decimal/currency → adds `dimensional-analysis`.
3. Calls `load_skill_prompt(spec.name,
   target_language=fingerprint.languages[0], extra_context=...)`.
4. Pipes the assembled markdown + packet content into `claude -p`.
   Stdout is captured to `PACKET-NNN.findings.md`.
5. If `spec.source == "tob"`, prefixes the output with a CC-BY-SA-4.0
   attribution comment naming the upstream skill and linking to its
   `trailofbits/skills` plugin path.

Parallelism: `--parallel N` runs N packets concurrently via a thread
pool. Each thread is its own `claude -p` subprocess. Pre-audit
stages (04a/04b), variant-analysis (06a), and fp-check (06b) stay
sequential regardless.

## Alternative audit modes

`sra audit --mode <X>` bypasses sensors and packets entirely. Each
alt mode loads one ToB skill and feeds it a mode-specific extra
context block:

| `--mode` | ToB skill | Extra context | Output |
|---|---|---|---|
| `differential` | `differential-review` | Per-side file lists, added/removed buckets, byte deltas, optional `git diff --stat` | `differential-vs-<repo_b_name>.md` |
| `spec-to-code` | `spec-to-code-compliance` | Spec content (50 KB cap) | `spec-compliance.md` |
| `mutation-testing` | `mutation-testing` | Test-layout summary (test dirs, counts, sample excerpts) | `mutation-testing.md` |
| `property-based-testing` | `property-based-testing` | Same test-layout summary | `property-based-testing.md` |

Implementation: [`src/sra/audit_modes.py`](../src/sra/audit_modes.py).

## Developer tools — `sra dev`

`sra dev <subcommand>` wraps four ToB meta-skills as one-shot
authoring helpers. These do NOT run the audit pipeline.

| `sra dev` subcommand | Wraps ToB | Required flags |
|---|---|---|
| `create-semgrep-rule` | `semgrep-rule-creator` | `--pattern`, `--lang` |
| `create-variant` | `semgrep-rule-variant-creator` | `--rule` |
| `improve-skill` | `skill-improver` | `--skill` |
| `design-workflow` | `designing-workflow-skills` | `--description` |

All four accept `--out <path>` (else stdout) and `--model <name>`
(else default). Implementation:
[`src/sra/dev_tools.py`](../src/sra/dev_tools.py). The dev-tool flow
bundles SKILL.md + sibling `references/` + `workflows/` files
(since `claude -p` has no progressive-disclosure loader) and pipes
the bundle + user input into `claude -p`.

## Attribution and licensing

SRA project: **MIT-licensed**.
Vendored ToB skills under `src/sra/skills/`: **CC-BY-SA-4.0**.

When a family `SkillSpec` has `source="tob"`, the orchestrator
prefixes the per-packet findings file with a CC-BY-SA-4.0 attribution
header naming the upstream skill and linking to its `trailofbits/
skills` plugin path. The user-facing report at `.audit/05-report/`
carries the same attribution by virtue of including those findings
files.

See [`LICENSE_THIRD_PARTY.md`](../LICENSE_THIRD_PARTY.md) for the
pinned upstream commit, the full skill list, and update instructions.

## Module map

| Module | Lines | Responsibility |
|---|---|---|
| `src/sra/cli.py` | ~7000 | argparse, every `cmd_*` stage, `sra audit` orchestrator, sensor invocation, packet builder, language filter |
| `src/sra/report.py` | ~2100 | `cmd_build_report` — aggregator, 4-tier dedup, Coverage Map |
| `src/sra/audit_modes.py` | ~740 | Four `cmd_audit_mode_*` functions for alt modes |
| `src/sra/skill_registry.py` | ~620 | `SkillSpec` + `SKILL_REGISTRY` + `--verify` |
| `src/sra/dev_tools.py` | ~400 | Four `cmd_dev_*` functions wrapping ToB meta-skills |
| `src/sra/skill_loader.py` | ~240 | `load_skill_prompt` + dependency walk + `{baseDir}` expansion + language refs |
| `src/sra/sensors/ripgrep/*.json` | — | 15 per-family ripgrep catalogs |
| `src/sra/sensors/ast-grep/*.json` | — | 13 per-family ast-grep catalogs |
| `src/sra/skills/<X>/SKILL.md` | — | 86 skill specs (12 ours + 74 ToB) |
| `src/sra/prompts/fingerprint_*.md` | — | Stage 01 fingerprint prompt halves |

## Where to look first when extending

- **Adding a new audit family.** Touch points:
  `src/sra/sensors/ripgrep/audit-<family>.json` (catalog),
  `src/sra/sensors/ast-grep/audit-<family>.json` (optional),
  `src/sra/skills/<family>/SKILL.md` (spec),
  `SENSOR_SUPPORTED_FAMILIES` + `_CODE_GLOBS_BY_LANG_GROUP` in
  `cli.py`, and a new entry in `SKILL_REGISTRY`.
- **Adding a new sensor (e.g. CodeQL).** Wire it the same way
  semgrep is wired in `cli.py`: a per-family catalog under
  `src/sra/sensors/codeql/`, a `_run_codeql` runner, and a branch
  in `cmd_run_sensor`. The ToB `codeql` skill (registered as a
  dev-tool) is the best-practice guide upstream.
- **Adding a language to the filter.** Extend `_LANG_ALIASES`,
  `_LANG_EXTENSIONS`, `_LANG_RG_GROUPS`, `_LANG_ASTGREP` in
  `cli.py`. The `LanguageFilter` predicates use those tables
  directly.
- **Bumping vendored ToB skills.** Clone the upstream ToB
  [skills repo](https://github.com/trailofbits/skills) at the new
  commit; for each `plugins/*/skills/<X>/` directory copy the
  whole subtree into `src/sra/skills/<X>/`, overwriting. Update the
  pinned commit in `LICENSE_THIRD_PARTY.md`. Always run
  `python -m sra.skill_registry --verify` after a bump.
- **Tuning a family skill.** Edit
  `src/sra/skills/<family>/SKILL.md`. Use
  `sra dev improve-skill --skill <family>` to get a second opinion
  from ToB's `skill-improver` before committing.
