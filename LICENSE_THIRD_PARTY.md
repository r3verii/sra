# Third-party content

## Trail of Bits skills

This project vendors the **Trail of Bits skills** (74 skill specifications
+ their references / agents / scripts) into `src/sra/skills/`. Each
vendored skill is in its own subdirectory there:

```
src/sra/skills/
├── audit-context-building/        # ToB
├── entry-point-analyzer/          # ToB
├── fp-check/                      # ToB
├── variant-analysis/              # ToB
├── insecure-defaults/             # ToB
├── supply-chain-risk-auditor/     # ToB
├── constant-time-analysis/        # ToB
├── zeroize-audit/                 # ToB
├── agentic-actions-auditor/       # ToB
├── dimensional-analysis/          # ToB
├── sharp-edges/                   # ToB
├── building-secure-contracts/     # ToB (one of many sub-skills)
├── algorand-vulnerability-scanner/   # ToB sub-skill
├── cairo-vulnerability-scanner/      # ToB sub-skill
├── cosmos-vulnerability-scanner/     # ToB sub-skill
├── solana-vulnerability-scanner/     # ToB sub-skill
├── substrate-vulnerability-scanner/  # ToB sub-skill
├── ton-vulnerability-scanner/        # ToB sub-skill
├── token-integration-analyzer/       # ToB sub-skill
├── secure-workflow-guide/            # ToB sub-skill
├── audit-prep-assistant/             # ToB sub-skill
├── code-maturity-assessor/           # ToB sub-skill
├── guidelines-advisor/               # ToB sub-skill
├── second-opinion/                # ToB
├── spec-to-code-compliance/       # ToB
├── differential-review/           # ToB
├── skill-improver/                # ToB
├── designing-workflow-skills/     # ToB (workflow-skill-design)
├── c-review/                      # ToB
├── modern-python/                 # ToB
├── dwarf-expert/                  # ToB
├── semgrep/                       # ToB (sub-skill of static-analysis)
├── codeql/                        # ToB (sub-skill of static-analysis)
├── sarif-parsing/                 # ToB (sub-skill of static-analysis)
├── semgrep-rule-creator/          # ToB
├── semgrep-rule-variant-creator/  # ToB
├── yara-rule-authoring/           # ToB (yara-authoring)
├── burpsuite-project-parser/      # ToB
├── mutation-testing/              # ToB
├── property-based-testing/        # ToB
├── testing-handbook-generator/    # ToB (testing-handbook-skills)
├── address-sanitizer/             # ToB testing sub-skill
├── aflpp/                         # ToB testing sub-skill
├── atheris/                       # ToB testing sub-skill
├── cargo-fuzz/                    # ToB testing sub-skill
├── constant-time-testing/         # ToB testing sub-skill
├── coverage-analysis/             # ToB testing sub-skill
├── fuzzing-dictionary/            # ToB testing sub-skill
├── fuzzing-obstacles/             # ToB testing sub-skill
├── harness-writing/               # ToB testing sub-skill
├── libafl/                        # ToB testing sub-skill
├── libfuzzer/                     # ToB testing sub-skill
├── ossfuzz/                       # ToB testing sub-skill
├── ruzzy/                         # ToB testing sub-skill
├── wycheproof/                    # ToB testing sub-skill
├── trailmark/                     # ToB
├── trailmark-structural/          # ToB sub-skill
├── trailmark-summary/             # ToB sub-skill
├── audit-augmentation/            # ToB trailmark sub-skill
├── crypto-protocol-diagram/       # ToB trailmark sub-skill
├── diagramming-code/              # ToB trailmark sub-skill
├── genotoxic/                     # ToB trailmark sub-skill
├── graph-evolution/               # ToB trailmark sub-skill
├── mermaid-to-proverif/           # ToB trailmark sub-skill
├── vector-forge/                  # ToB trailmark sub-skill
├── firebase-apk-scanner/          # ToB
├── ask-questions-if-underspecified/   # ToB
├── claude-in-chrome-troubleshooting/  # ToB
├── debug-buttercup/               # ToB
├── devcontainer-setup/            # ToB
├── git-cleanup/                   # ToB
├── interpreting-culture-index/    # ToB (culture-index)
├── let-fate-decide/               # ToB
├── seatbelt-sandboxer/            # ToB
└── gh-cli/                        # ToB (from .codex/skills/)
```

- **Source:** https://github.com/trailofbits/skills
- **License:** Creative Commons Attribution-ShareAlike 4.0 International
  (CC-BY-SA-4.0)
- **Vendored from commit:** `a56045e9ae00b3506cacefea0f672aab0a1a6e3c`

### Attribution and use

Any skill specification file under `src/sra/skills/<dir>/` that is
derived from, copies, or significantly adapts content from the
Trail of Bits skills repository is governed by the CC-BY-SA-4.0
license. Derivative works of those specs must:

1. Retain the upstream copyright notice (preserved in each SKILL.md).
2. Be released under CC-BY-SA-4.0 per the share-alike clause.

The rest of the SRA project (Python source under `src/sra/`, the
13 family skills under `src/sra/skills/{access-control,audit-synthesis,
business-logic,client-side,concurrency-race,crypto-auth,file-boundary,
input-validation,memory-safety,network-protocol,parser-state-machine,
server-side-injection}/`, sensor catalogs under `src/sra/sensors/`,
scripts, documentation) is **not** derived from Trail of Bits content
and retains the project's own license (see top-level LICENSE if present).

### Updating vendored ToB skills

The skills were vendored at the pinned commit above. To update:

1. Clone the upstream repo at a newer commit into a temporary location.
2. Re-run `scripts/_migrate_layout.py` (or manually copy each
   `plugins/*/skills/<X>/` subdirectory into `src/sra/skills/<X>/`,
   overwriting existing).
3. Update the **Vendored from commit** line above.
4. Run `pytest tests/test_skill_registry.py` to verify every
   registered SkillSpec still resolves.
