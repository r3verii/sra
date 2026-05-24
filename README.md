# SRA — Security audit pipeline for source code

> ## ⚠️ Alpha · Experimental · Use at your own risk
>
> **This is pre-beta software.** SRA has been smoke-tested on a handful
> of repositories during development, but **no systematic benchmark
> exists** to claim it reliably surfaces real vulnerabilities, nor that
> its false-positive rate is bounded at scale. Findings are
> **suggestions for human review** — never treat the output as a
> security guarantee, a compliance attestation, or a substitute for a
> professional audit.
>
> Expect: missed bugs, spurious findings, occasional crashes, and
> breaking changes between commits. Please open issues with reproducers.

> ## 🤖 Built with Claude
>
> SRA was **designed, written, and tested in collaboration with
> Anthropic's Claude**, and uses the `claude` CLI as the reasoning
> engine for every LLM stage of the pipeline (fingerprint, per-packet
> investigation, variant analysis, false-positive triage, synthesis).
> Without Claude this project would not exist, and at runtime it
> cannot function without a working `claude` CLI on PATH.

---

> One command. Three SAST sensors. Claude as the reasoning engine.
> A complete, resumable audit of any repo — with attack chains,
> false-positive triage, and an executive report.

```bash
sra audit /path/to/repo --parallel 4
```

That's it. SRA fingerprints the repo, elects the relevant audit
families, runs ripgrep + semgrep + ast-grep, clusters the hits into
review packets, asks Claude to investigate each one with a dedicated
skill, hunts for variants of every confirmed finding, double-checks
for false positives, and writes you an executive report with attack
chains.

---

## Install — 60 seconds

### 1. Install the three sensors + `pipx`

**Linux / macOS**

```bash
# ripgrep + ast-grep via your package manager
brew install ripgrep ast-grep     # macOS
sudo apt install ripgrep          # Debian/Ubuntu  (then: cargo install ast-grep)
sudo dnf install ripgrep          # Fedora         (then: cargo install ast-grep)

# semgrep + pipx via pip
python3 -m pip install --user pipx semgrep
python3 -m pipx ensurepath
```

**Windows (PowerShell)**

```powershell
# All three sensors in one shot via scoop (recommended)
scoop install ripgrep ast-grep
python -m pip install --user pipx semgrep
python -m pipx ensurepath

# Or via winget:
# winget install BurntSushi.ripgrep.MSVC
# winget install ast-grep.ast-grep
```

### 2. Install the `claude` CLI

Follow https://docs.claude.com/claude-code (one-liner install, then
`claude login`). **Required** — the LLM stages of the pipeline shell
out to `claude -p` and cannot run without it.

### 3. Install SRA

```bash
# From this checkout
pipx install --editable .

# Verify
sra --help
```

Requires Python ≥ 3.11.

---

## Quickstart

```bash
# Full audit, 4 packets in parallel — sane default
sra audit /path/to/repo --parallel 4

# Focus on one family (e.g. injection bugs only) — bypasses the packet cap
sra audit /path/to/repo --family audit/server-side-injection --parallel 4

# Polyglot repo: audit only the PHP backend, skip the JS frontend
sra audit /path/to/repo --only-lang php --parallel 4

# Deterministic-only (no LLM cost) — just sensors + clustering + structural report
sra audit /path/to/repo --no-skills

# Re-aggregate findings into the structural report (zero LLM, ~5s)
sra build-report /path/to/repo
```

### Outputs

After a full run, look in `<repo>/.audit/`:

- **`07-synthesis/security-audit-report.md`** — executive report with
  attack chains. **Start here.**
- **`05-report/repo-report.md`** — structural roll-up + Coverage Map
  (what was audited, what was skipped, why).
- **`04-packets-sensors/<family>/PACKET-NNN.findings.md`** — per-packet
  raw findings from the skill phase.

---

## What it does — pipeline stages

| # | Stage | LLM calls |
|---|---|:---:|
| 00 | **collect** — walk repo, emit raw signals | — |
| 01 | **fingerprint** — classify languages, frameworks, domains | 1 |
| 02 | **route-packs** — deterministic family election | — |
| 03 | **sensors** — ripgrep + semgrep + ast-grep, cross-sensor dedup | — |
| 04 | **packets** — cluster hits into review packets, micro-fold | — |
| 05 | **skill phase** — Claude investigates each packet (parallel) | many |
| 06a | **variants** — for every confirmed bug, find its siblings | per finding |
| 06b | **fp-check** — audit-of-audits, flag likely false positives | 1 |
| 07 | **synthesis** — chain attacks, write executive report | 1 |
| — | **build-report** — structural roll-up + Coverage Map | — |

Resume-safe: every stage skips its work if the output exists. Ctrl+C
mid-run produces a partial report.

---

## Common flags

| Flag | Effect |
|---|---|
| `--family audit/<X>` | Focus on one family. Bypasses the per-family packet cap. |
| `--only-lang LANG` | Audit only this language. Repeatable / comma-sep. |
| `--exclude-lang LANG` | Skip this language. Repeatable / comma-sep. |
| `--parallel N` | Run N skill invocations in parallel (default 1; 2–4 recommended). |
| `--semgrep-profile security` | Use the deeper rule set (~3000 rules). Recommended for serious audits. |
| `--no-variants` | Skip variant analysis (the slowest LLM stage). |
| `--no-fp-check` / `--no-synthesis` | Skip those final stages. |
| `--no-skills` | Skip every LLM stage. Deterministic-only mode. |
| `--no-micro-fold` | Disable the micro-cluster fold pass. |
| `--model {sonnet,opus,haiku}` | Override the `claude` CLI default model. |
| `--force` | Re-run every stage even if output exists. |

**Language tokens** (for `--only-lang` / `--exclude-lang`):
`php` · `js`/`ts` · `python` · `go` · `java` · `kotlin` · `ruby` ·
`rust` · `c`/`cpp` · `csharp` · `swift` · `solidity`.

Config / manifest / IaC files (Dockerfile, `package.json`, `.github/
workflows`, …) always pass — the language filter only scopes source code.

---

## Architecture & internals

- **`docs/ARCHITECTURE.md`** — stage-by-stage data flow, cross-sensor
  dedup design, adaptive packet cap, micro-cluster fold, Coverage Map.
- **`src/sra/sensors/`** — ripgrep + ast-grep + semgrep catalogs
  (~778 patterns across 11 languages). Per-family JSON files.
- **`src/sra/skills/`** — Claude skills the pipeline composes:
  - Our 12 family skills (one per audit family)
  - 74 vendored Trail of Bits skills (CC-BY-SA-4.0, see
    [`LICENSE_THIRD_PARTY.md`](LICENSE_THIRD_PARTY.md))

Inspect what a skill expands to (free, no LLM call):

```bash
python -m sra.skill_loader audit-context-building
```

---

## License

First-party SRA code: MIT (see top-level `LICENSE` if present).
Vendored Trail of Bits skills under `src/sra/skills/`: CC-BY-SA-4.0
(see [`LICENSE_THIRD_PARTY.md`](LICENSE_THIRD_PARTY.md)).
