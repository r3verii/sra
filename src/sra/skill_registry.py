"""Skill registry — source of truth for audit skill specs.

Each entry in :data:`SKILL_REGISTRY` describes a single skill: where its
markdown lives on disk, which pipeline stage and trigger it belongs to,
whether it comes from us or Trail of Bits, and which other skills must be
loaded as context first.

The registry is consumed by the pipeline orchestrator (Phase 2) and the
skill loader (Phase 3). It is also self-validating via the CLI:

    python -m sra.skill_registry --verify
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

# Package-local data dirs. Both skills/ and sensors/ now live INSIDE
# the `sra` Python package so they're shipped as `package-data` and
# resolve correctly under `pipx install` (where the package lives in
# an isolated venv with no sibling `external/`, `sensors/`, `prompts/`
# directories at the repo root).
_PKG_DIR: Path = Path(__file__).resolve().parent
SKILLS_DIR: Path = _PKG_DIR / "skills"
SENSORS_DIR: Path = _PKG_DIR / "sensors"
PROMPTS_DIR: Path = _PKG_DIR / "prompts"


Stage = Literal[
    "pre-audit",       # runs once per repo, before sensors / packets
    "family",          # runs per packet, one invocation per (family, packet)
    "post-confirmed",  # runs per confirmed finding
    "post-audit",      # runs once per repo, after all family skills
    "alt-mode",        # invoked only when a specific audit mode is selected
    "dev-tool",        # invoked manually, not part of `sra audit`
]

Trigger = Literal[
    "per-repo",
    "per-packet",
    "per-confirmed",
    "per-mode",
    "manual",
]

Source = Literal["ours", "tob"]


@dataclass(frozen=True)
class SkillSpec:
    """A single audit-skill entry.

    Attributes mirror the plan's "Architecture: skill registry" section.
    """

    name: str
    stage: Stage
    trigger: Trigger
    source: Source
    path: str
    references_dir: str | None = None
    allowed_tools: tuple[str, ...] = ("Read", "Grep", "Glob")
    family: str | None = None
    dependencies: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    description: str = ""

    def resolved_path(self) -> Path:
        """Return the absolute path to this skill's SKILL.md.

        ``path`` is relative to :data:`SKILLS_DIR` (the canonical layout
        is ``src/sra/skills/<skill-dirname>/SKILL.md``).
        """
        return (SKILLS_DIR / self.path).resolve()

    def resolved_references_dir(self) -> Path | None:
        """Return the absolute path to this skill's references_dir, if any.

        ``references_dir`` is relative to :data:`SKILLS_DIR`.
        """
        if self.references_dir is None:
            return None
        return (SKILLS_DIR / self.references_dir).resolve()


# Standard family dependencies for every audit/<family> skill.
#
# Only `audit-context-building` is universal: it's a language-agnostic
# guidance skill that improves any audit.
#
# `entry-point-analyzer` is intentionally NOT here. Its SKILL.md is
# explicit that it is smart-contracts-only (Solidity, Vyper, Move, TON,
# Solana, CosmWasm). Wiring it as a universal dependency caused every
# family-skill prompt to carry ~7 KB of smart-contracts content as
# preamble, polluting reasoning on Node.js / Python / Go / Java repos.
# It now appears only in the `building-secure-contracts` entry (the
# smart-contracts family) where it belongs.
_FAMILY_DEPS: tuple[str, ...] = ("audit-context-building",)
# ToB drop-in family skills only depend on context-building (per plan).
_DROPIN_DEPS: tuple[str, ...] = ("audit-context-building",)


SKILL_REGISTRY: dict[str, SkillSpec] = {
    # =====================================================================
    # Category A — Meta-skills (10): pipeline stages
    # =====================================================================
    "audit-context-building": SkillSpec(
        name="audit-context-building",
        stage="pre-audit", trigger="per-repo",
        source="tob",
        path="audit-context-building/SKILL.md",
        description="Deep architectural understanding before vulnerability hunting.",
    ),
    "entry-point-analyzer": SkillSpec(
        name="entry-point-analyzer",
        stage="pre-audit", trigger="per-repo",
        source="tob",
        path="entry-point-analyzer/SKILL.md",
        references_dir="entry-point-analyzer/references",
        description="Map state-changing entry points.",
    ),
    "ask-questions-if-underspecified": SkillSpec(
        name="ask-questions-if-underspecified",
        stage="pre-audit", trigger="per-repo",
        source="tob",
        path="ask-questions-if-underspecified/SKILL.md",
        description="Clarify ambiguous audit prompts before launching skills.",
    ),
    "variant-analysis": SkillSpec(
        name="variant-analysis",
        stage="post-confirmed", trigger="per-confirmed",
        source="tob",
        path="variant-analysis/SKILL.md",
        description="Find sibling vulnerabilities of a confirmed finding.",
    ),
    "second-opinion": SkillSpec(
        name="second-opinion",
        stage="post-confirmed", trigger="per-confirmed",
        source="tob",
        path="second-opinion/SKILL.md",
        references_dir="second-opinion/references",
        description="Optional sanity check on a confirmed finding.",
    ),
    "fp-check": SkillSpec(
        name="fp-check",
        stage="post-audit", trigger="per-repo",
        source="tob",
        path="fp-check/SKILL.md",
        references_dir="fp-check/references",
        description="Audit-of-audits: flag likely false positives across the report.",
    ),
    "audit-synthesis": SkillSpec(
        name="audit-synthesis",
        # Final synthesis stage (07): re-reads every artifact produced
        # by stages 00-06, chains related findings into attack
        # scenarios, drops false positives that fp-check overruled,
        # ranks by severity, and emits a strict-template
        # `security-audit-report.md`. Runs once per repo at the end.
        stage="post-audit", trigger="per-repo",
        source="ours",
        path="audit-synthesis/SKILL.md",
        description=(
            "Read all audit artifacts, chain related findings into "
            "attack scenarios, produce executive security-audit-"
            "report.md."
        ),
    ),
    "spec-to-code-compliance": SkillSpec(
        name="spec-to-code-compliance",
        stage="alt-mode", trigger="per-mode",
        source="tob",
        path="spec-to-code-compliance/SKILL.md",
        description="Compare code against an external specification document.",
    ),
    "differential-review": SkillSpec(
        name="differential-review",
        stage="alt-mode", trigger="per-mode",
        source="tob",
        path="differential-review/SKILL.md",
        description="Diff-focused review between two repo snapshots.",
    ),
    "skill-improver": SkillSpec(
        name="skill-improver",
        stage="dev-tool", trigger="manual",
        source="tob",
        path="skill-improver/SKILL.md",
        description="Iteratively improve an existing skill spec.",
    ),
    # NOTE: plugin dir is `workflow-skill-design` but the skill inside is
    # named `designing-workflow-skills` (unusual sub-skill name).
    "workflow-skill-design": SkillSpec(
        name="workflow-skill-design",
        stage="dev-tool", trigger="manual",
        source="tob",
        path="designing-workflow-skills/SKILL.md",
        references_dir="designing-workflow-skills/references",
        description="Design a new workflow-style skill from scratch.",
    ),

    # =====================================================================
    # Category B — Family-skill overlaps (4)
    # Two replace existing families; two compose with audit/crypto-auth.
    # =====================================================================
    "insecure-defaults": SkillSpec(
        name="insecure-defaults",
        stage="family", trigger="per-packet",
        source="tob",
        path="insecure-defaults/SKILL.md",
        references_dir="insecure-defaults/references",
        family="audit/config-deployment",
        dependencies=_DROPIN_DEPS,
        description="Drop-in replacement for our config-deployment family skill.",
    ),
    "supply-chain-risk-auditor": SkillSpec(
        name="supply-chain-risk-auditor",
        stage="family", trigger="per-packet",
        source="tob",
        path="supply-chain-risk-auditor/SKILL.md",
        family="audit/supply-chain",
        dependencies=_DROPIN_DEPS,
        description="Drop-in replacement for our supply-chain family skill.",
    ),
    "constant-time-analysis": SkillSpec(
        name="constant-time-analysis",
        stage="family", trigger="per-packet",
        source="tob",
        path="constant-time-analysis/SKILL.md",
        references_dir="constant-time-analysis/references",
        family="audit/crypto-auth",
        dependencies=_DROPIN_DEPS,
        description="Composes with crypto-auth packets that compare secret material.",
    ),
    "zeroize-audit": SkillSpec(
        name="zeroize-audit",
        stage="family", trigger="per-packet",
        source="tob",
        path="zeroize-audit/SKILL.md",
        references_dir="zeroize-audit/references",
        family="audit/crypto-auth",
        # SKILL.md is explicit: only C/C++/Rust have manual memory
        # management where zeroize semantics matter. On managed-memory
        # languages (Python/JS/Go/Java/...) the GC owns the memory and
        # the skill cannot help — composing it there is pure noise.
        languages=("c", "cpp", "c++", "rust"),
        dependencies=_DROPIN_DEPS,
        description="Composes with crypto-auth packets that handle key material in C/C++/Rust.",
    ),

    # =====================================================================
    # Category C — New family categories (5)
    # =====================================================================
    "agentic-actions-auditor": SkillSpec(
        name="agentic-actions-auditor",
        stage="family", trigger="per-packet",
        source="tob",
        path="agentic-actions-auditor/SKILL.md",
        references_dir="agentic-actions-auditor/references",
        family="audit/agentic-ai",
        dependencies=_DROPIN_DEPS,
        description="Audit autonomous-agent / tool-use action surfaces.",
    ),
    "firebase-apk-scanner": SkillSpec(
        name="firebase-apk-scanner",
        # SKILL.md frontmatter has `disable-model-invocation: true` — the
        # author explicitly does not want this auto-loaded as a family
        # skill. It is a binary scanner that runs `Bash {baseDir}/scanner.sh`
        # against an APK file, not a per-packet source-review skill.
        # Park it under stage="dev-tool" so manual `sra dev ...` callers
        # can still reach it; the per-packet path no longer picks it up.
        stage="dev-tool", trigger="manual",
        source="tob",
        path="firebase-apk-scanner/SKILL.md",
        references_dir="firebase-apk-scanner/references",
        family=None,
        dependencies=(),
        description="Manual-only: Firebase + Android APK misconfigurations (binary scanner).",
    ),
    "dimensional-analysis": SkillSpec(
        name="dimensional-analysis",
        stage="family", trigger="per-packet",
        source="tob",
        path="dimensional-analysis/SKILL.md",
        references_dir="dimensional-analysis/references",
        family="audit/business-logic",
        # SKILL.md scope is "DeFi protocols, financial code, scientific
        # computations" with on-chain D18{tok}-style annotations as the
        # main mode of operation. On a generic Node.js / Python web app
        # this composition adds boilerplate noise; only fire it when
        # the repo actually has Solidity / Vyper / Rust contract code.
        # The cli.py business-logic chooser already does a content
        # probe before composing — this language list also lets manual
        # `sra audit --skill dimensional-analysis` callers see the
        # constraint.
        languages=("solidity", "vyper", "rust"),
        dependencies=_DROPIN_DEPS,
        description="Composes with business-logic packets to flag unit/dimension mistakes (DeFi / contract).",
    ),
    "sharp-edges": SkillSpec(
        name="sharp-edges",
        stage="family", trigger="per-packet",
        source="tob",
        path="sharp-edges/SKILL.md",
        references_dir="sharp-edges/references",
        family=None,  # cross-family helper, loaded for any language-footgun review
        dependencies=_DROPIN_DEPS,
        description="Cross-family helper: language / API footguns.",
    ),
    # NOTE: plugin contains 10+ chain-specific sub-skills. We point the
    # umbrella entry at `secure-workflow-guide` (the most general one);
    # chain-specific sub-skills can be added in Phase 5 if needed.
    "building-secure-contracts": SkillSpec(
        name="building-secure-contracts",
        stage="family", trigger="per-packet",
        source="tob",
        path="secure-workflow-guide/SKILL.md",
        family="audit/smart-contracts",
        dependencies=("audit-context-building", "entry-point-analyzer"),
        description="Smart-contract secure-development workflow (umbrella entry).",
    ),

    # =====================================================================
    # Category D — Language-specific (3): composability layer
    # =====================================================================
    "c-review": SkillSpec(
        name="c-review",
        stage="family", trigger="per-packet",
        source="tob",
        path="c-review/SKILL.md",
        languages=("c", "cpp", "c++"),
        description="Load alongside any family skill when target language is C/C++.",
    ),
    "modern-python": SkillSpec(
        name="modern-python",
        # SKILL.md scope: "Configures Python projects with modern tooling
        # (uv, ruff, ty). Use when creating projects... migrating from
        # pip/Poetry." This is project setup / dev-tooling, NOT a
        # security-audit skill. Wiring it as a per-packet family
        # composition just added 5+ KB of uv/ruff guidance to every
        # Python family-skill prompt as noise. Moved to dev-tool /
        # manual so it stays in the registry for `sra dev ...` callers
        # but doesn't leak into audit prompts.
        stage="dev-tool", trigger="manual",
        source="tob",
        path="modern-python/SKILL.md",
        references_dir="modern-python/references",
        languages=("python",),
        description="Dev-tool: configure Python projects with uv/ruff/ty (not security).",
    ),
    "dwarf-expert": SkillSpec(
        name="dwarf-expert",
        stage="family", trigger="per-packet",
        source="tob",
        path="dwarf-expert/SKILL.md",
        languages=("binary",),
        description="Binary-input audits only — out of v1 scope but registered.",
    ),

    # =====================================================================
    # Category E — Tool / SAST integration (7): dev tools
    # NOTE: static-analysis is one plugin with three sub-skills, so we
    # register each sub-skill as its own entry.
    # =====================================================================
    "static-analysis/semgrep": SkillSpec(
        name="static-analysis/semgrep",
        stage="dev-tool", trigger="manual",
        source="tob",
        path="semgrep/SKILL.md",
        references_dir="semgrep/references",
        description="Best-practice guide for authoring semgrep rules.",
    ),
    "static-analysis/codeql": SkillSpec(
        name="static-analysis/codeql",
        stage="dev-tool", trigger="manual",
        source="tob",
        path="codeql/SKILL.md",
        references_dir="codeql/references",
        description="Used when wiring CodeQL as a 4th sensor.",
    ),
    "static-analysis/sarif-parsing": SkillSpec(
        name="static-analysis/sarif-parsing",
        stage="dev-tool", trigger="manual",
        source="tob",
        path="sarif-parsing/SKILL.md",
        description="SARIF parsing helper.",
    ),
    "semgrep-rule-creator": SkillSpec(
        name="semgrep-rule-creator",
        stage="dev-tool", trigger="manual",
        source="tob",
        path="semgrep-rule-creator/SKILL.md",
        references_dir="semgrep-rule-creator/references",
        description="Author new semgrep rules from scratch.",
    ),
    "semgrep-rule-variant-creator": SkillSpec(
        name="semgrep-rule-variant-creator",
        stage="dev-tool", trigger="manual",
        source="tob",
        path="semgrep-rule-variant-creator/SKILL.md",
        references_dir="semgrep-rule-variant-creator/references",
        description="Generate variant semgrep rules from an existing one.",
    ),
    # NOTE: plugin dir is `yara-authoring` but the sub-skill is named
    # `yara-rule-authoring` (unusual sub-skill name).
    "yara-authoring": SkillSpec(
        name="yara-authoring",
        stage="dev-tool", trigger="manual",
        source="tob",
        path="yara-rule-authoring/SKILL.md",
        references_dir="yara-rule-authoring/references",
        description="Author YARA rules (if YARA sensor is added).",
    ),
    "burpsuite-project-parser": SkillSpec(
        name="burpsuite-project-parser",
        stage="dev-tool", trigger="manual",
        source="tob",
        path="burpsuite-project-parser/SKILL.md",
        description="DAST integration helper (Burp Suite project parsing).",
    ),

    # =====================================================================
    # Category F — Testing / QA (3)
    # =====================================================================
    "mutation-testing": SkillSpec(
        name="mutation-testing",
        stage="alt-mode", trigger="per-mode",
        source="tob",
        path="mutation-testing/SKILL.md",
        references_dir="mutation-testing/references",
        description="Audit mode: mutation-testing analysis.",
    ),
    "property-based-testing": SkillSpec(
        name="property-based-testing",
        stage="alt-mode", trigger="per-mode",
        source="tob",
        path="property-based-testing/SKILL.md",
        references_dir="property-based-testing/references",
        description="Audit mode: property-based testing analysis.",
    ),
    # NOTE: plugin contains 14 testing sub-skills (afl++, libfuzzer, etc.).
    # We point the umbrella entry at `testing-handbook-generator`; individual
    # tool sub-skills can be added if/when they become first-class.
    "testing-handbook-skills": SkillSpec(
        name="testing-handbook-skills",
        stage="dev-tool", trigger="manual",
        source="tob",
        path="testing-handbook-generator/SKILL.md",
        # This is actually a META skill that generates *new* skills from
        # appsec.guide content — it is not a reference doc for audits.
        # Keep stage=dev-tool / manual so it stays callable via `sra dev`
        # but doesn't show up in audit-time invocations.
        description="Dev-tool: meta-generator for new testing-quality skills from appsec.guide.",
    ),

    # =====================================================================
    # Family skills (13): our 11 originals + 2 ToB drop-ins for the
    # retiring config-deployment / supply-chain families.
    # =====================================================================
    "audit/input-validation": SkillSpec(
        name="audit/input-validation",
        stage="family", trigger="per-packet",
        source="ours",
        path="input-validation/SKILL.md",
        family="audit/input-validation",
        dependencies=_FAMILY_DEPS,
    ),
    "audit/memory-safety": SkillSpec(
        name="audit/memory-safety",
        stage="family", trigger="per-packet",
        source="ours",
        path="memory-safety/SKILL.md",
        family="audit/memory-safety",
        dependencies=_FAMILY_DEPS,
    ),
    "audit/supply-chain": SkillSpec(
        name="audit/supply-chain",
        stage="family", trigger="per-packet",
        source="tob",  # retiring family — point at ToB drop-in
        path="supply-chain-risk-auditor/SKILL.md",
        family="audit/supply-chain",
        dependencies=_DROPIN_DEPS,
    ),
    "audit/file-boundary": SkillSpec(
        name="audit/file-boundary",
        stage="family", trigger="per-packet",
        source="ours",
        path="file-boundary/SKILL.md",
        family="audit/file-boundary",
        dependencies=_FAMILY_DEPS,
    ),
    "audit/parser-state-machine": SkillSpec(
        name="audit/parser-state-machine",
        stage="family", trigger="per-packet",
        source="ours",
        path="parser-state-machine/SKILL.md",
        family="audit/parser-state-machine",
        dependencies=_FAMILY_DEPS,
    ),
    "audit/network-protocol": SkillSpec(
        name="audit/network-protocol",
        stage="family", trigger="per-packet",
        source="ours",
        path="network-protocol/SKILL.md",
        family="audit/network-protocol",
        dependencies=_FAMILY_DEPS,
    ),
    "audit/crypto-auth": SkillSpec(
        name="audit/crypto-auth",
        stage="family", trigger="per-packet",
        source="ours",
        path="crypto-auth/SKILL.md",
        family="audit/crypto-auth",
        dependencies=_FAMILY_DEPS,
    ),
    "audit/config-deployment": SkillSpec(
        name="audit/config-deployment",
        stage="family", trigger="per-packet",
        source="tob",  # retiring family — point at ToB drop-in
        path="insecure-defaults/SKILL.md",
        family="audit/config-deployment",
        dependencies=_DROPIN_DEPS,
    ),
    "audit/concurrency-race": SkillSpec(
        name="audit/concurrency-race",
        stage="family", trigger="per-packet",
        source="ours",
        path="concurrency-race/SKILL.md",
        family="audit/concurrency-race",
        dependencies=_FAMILY_DEPS,
    ),
    "audit/access-control": SkillSpec(
        name="audit/access-control",
        stage="family", trigger="per-packet",
        source="ours",
        path="access-control/SKILL.md",
        family="audit/access-control",
        dependencies=_FAMILY_DEPS,
    ),
    "audit/server-side-injection": SkillSpec(
        name="audit/server-side-injection",
        stage="family", trigger="per-packet",
        source="ours",
        path="server-side-injection/SKILL.md",
        family="audit/server-side-injection",
        dependencies=_FAMILY_DEPS,
    ),
    "audit/client-side": SkillSpec(
        name="audit/client-side",
        stage="family", trigger="per-packet",
        source="ours",
        path="client-side/SKILL.md",
        family="audit/client-side",
        dependencies=_FAMILY_DEPS,
    ),
    "audit/business-logic": SkillSpec(
        name="audit/business-logic",
        stage="family", trigger="per-packet",
        source="ours",
        path="business-logic/SKILL.md",
        family="audit/business-logic",
        dependencies=_FAMILY_DEPS,
    ),
}


# =========================================================================
# CLI: `python -m sra.skill_registry --verify`
# =========================================================================

def _verify(registry: dict[str, SkillSpec] = SKILL_REGISTRY) -> int:
    """Walk every entry, open its file, print OK/MISSING. Returns exit code."""
    ok = 0
    missing: list[tuple[str, Path]] = []
    for name, spec in registry.items():
        path = spec.resolved_path()
        try:
            with path.open("rb") as fh:
                fh.read(1)
        except OSError:
            missing.append((name, path))
            print(f"MISSING {name} -> {path}")
            continue
        print(f"OK {name} -> {path}")
        ok += 1
        if spec.references_dir is not None:
            refs = spec.resolved_references_dir()
            if refs is None or not refs.is_dir():
                missing.append((name + " [references_dir]", refs or Path("<unset>")))
                print(f"MISSING {name} [references_dir] -> {refs}")
    print()
    print(f"{ok}/{len(registry)} entries resolved.")
    if missing:
        print(f"{len(missing)} missing path(s).")
        return 1
    return 0


def _main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m sra.skill_registry",
        description="Inspect or verify the SRA skill registry.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Walk every entry, open its file, exit non-zero if any are missing.",
    )
    args = parser.parse_args(argv)
    if args.verify:
        return _verify()
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via CLI
    raise SystemExit(_main())
