"""sra dev — developer tools that wrap Trail of Bits "meta" skills.

These commands invoke ToB skills directly via `claude -p`, without going
through the audit pipeline. They take a user-supplied input (pattern,
rule path, skill name, or description), pipe the relevant ToB SKILL.md
(plus any `references/` and `workflows/` files) into claude alongside
that input, and capture stdout.

The four wired skills are:

- `create-semgrep-rule`  -> ToB `semgrep-rule-creator`
- `create-variant`       -> ToB `semgrep-rule-variant-creator`
- `improve-skill`        -> ToB `skill-improver`
- `design-workflow`      -> ToB `workflow-skill-design`
                            (SKILL.md is under
                            skills/designing-workflow-skills/)

This module deliberately uses *direct paths* to the vendored ToB
SKILL.md files. A future refactor (Phase 1) will replace these with
lookups against `sra.skill_registry`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


# Repo-root-relative paths to the four ToB dev-tool SKILL.md files.
# Note: the workflow-skill-design plugin's SKILL.md is under
# `skills/designing-workflow-skills/`, NOT `skills/workflow-skill-design/`
# (verified by inspection of the vendored submodule).
_TOB_SKILL_PATHS: dict[str, str] = {
    "create-semgrep-rule":
        "external/trailofbits-skills/plugins/semgrep-rule-creator/"
        "skills/semgrep-rule-creator/SKILL.md",
    "create-variant":
        "external/trailofbits-skills/plugins/semgrep-rule-variant-creator/"
        "skills/semgrep-rule-variant-creator/SKILL.md",
    "improve-skill":
        "external/trailofbits-skills/plugins/skill-improver/"
        "skills/skill-improver/SKILL.md",
    "design-workflow":
        "external/trailofbits-skills/plugins/workflow-skill-design/"
        "skills/designing-workflow-skills/SKILL.md",
}


def _find_repo_root() -> Path:
    """Walk up from this file looking for the repository root.

    Heuristic: a parent directory that contains both `pyproject.toml`
    and `external/trailofbits-skills/`. Falls back to the cwd if neither
    matches (the caller will then surface a clean FileNotFoundError on
    the skill path).
    """
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        if (parent / "pyproject.toml").is_file() \
                and (parent / "external" / "trailofbits-skills").is_dir():
            return parent
    return Path.cwd().resolve()


def _resolve_skill_path(slug: str) -> Path:
    """Return the absolute path to the ToB SKILL.md for `slug`."""
    rel = _TOB_SKILL_PATHS.get(slug)
    if rel is None:
        raise ValueError(f"unknown dev skill slug: {slug!r}")
    root = _find_repo_root()
    path = (root / rel).resolve()
    if not path.is_file():
        raise FileNotFoundError(
            f"ToB SKILL.md not found: {path}\n"
            f"(expected under repo root {root}). Is the submodule at "
            f"external/trailofbits-skills initialized? "
            f"Run: git submodule update --init --recursive"
        )
    return path


def _load_skill_bundle(skill_path: Path) -> str:
    """Concatenate SKILL.md plus any sibling `references/*.md` and
    `workflows/*.md` files into one big prompt.

    ToB skills practice "progressive disclosure" — SKILL.md is the
    entry point and references/workflows contain the deeper detail.
    Since we're piping the whole bundle into `claude -p` in one shot
    (no progressive loading available in headless mode), we include
    everything up front so claude has the full skill content.
    """
    parts: list[str] = []
    try:
        parts.append(f"=== SKILL.md ({skill_path.name}) ===\n\n"
                     + skill_path.read_text(encoding="utf-8"))
    except OSError as e:
        raise FileNotFoundError(f"cannot read {skill_path}: {e}") from e

    skill_dir = skill_path.parent
    for sub in ("references", "workflows"):
        sub_dir = skill_dir / sub
        if not sub_dir.is_dir():
            continue
        for child in sorted(sub_dir.glob("*.md")):
            try:
                parts.append(
                    f"\n\n=== {sub}/{child.name} ===\n\n"
                    + child.read_text(encoding="utf-8")
                )
            except OSError:
                continue
    return "\n".join(parts)


def _invoke_dev_skill(
    skill_slug: str,
    user_block: str,
    *,
    out_path: Path | None,
    model: str | None,
    cwd: Path | None = None,
) -> int:
    """Pipe (skill bundle + user block) into `claude -p`, capture
    stdout, and either print it or write it to `out_path`.

    `user_block` is appended to the prompt verbatim under a labelled
    section. The caller is responsible for shaping it (e.g. "the
    pseudo-pattern is X, the language is Y").

    Returns the process exit code (0 on success, non-zero on error).
    """
    claude = shutil.which("claude")
    if not claude:
        print("error: `claude` CLI not found on PATH", file=sys.stderr)
        return 127

    try:
        skill_path = _resolve_skill_path(skill_slug)
    except (FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    try:
        skill_bundle = _load_skill_bundle(skill_path)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    prompt = (
        "You are running the skill defined below as a one-shot dev "
        "tool. Produce your deliverable as markdown on stdout. Do NOT "
        "use the Write, Edit, or NotebookEdit tools — your output is "
        "captured directly from your assistant message text.\n"
        "\n=== SKILL BUNDLE ===\n\n"
        f"{skill_bundle}\n"
        "\n=== USER INPUT ===\n\n"
        f"{user_block}\n"
        "\n=== END ===\n"
        "\nReturn the deliverable. Be concise; no preamble."
    )

    env = os.environ.copy()
    # Match the nested-session guard in _invoke_claude_skill().
    env.pop("CLAUDECODE", None)
    env.pop("CLAUDE_CODE_ENTRYPOINT", None)

    cmd = [claude, "-p"]
    if model:
        cmd.extend(["--model", model])

    # Route via cli._run_claude_with_heartbeat so the live child is
    # registered in _LIVE_PROCS and a Ctrl+C from the user terminates
    # it cleanly. Imported here (not at module top) to avoid a circular
    # import between cli.py and dev_tools.py.
    from sra.cli import _run_claude_with_heartbeat
    try:
        proc = _run_claude_with_heartbeat(
            cmd, input_text=prompt, timeout=600,
            cwd=str(cwd) if cwd else os.getcwd(),
            env=env, label=f"dev:{skill_slug}",
        )
    except subprocess.TimeoutExpired:
        print("error: `claude -p` timed out after 10 minutes",
              file=sys.stderr)
        return 124
    except KeyboardInterrupt:
        print("[dev] interrupted by user", file=sys.stderr)
        return 130

    output = proc.stdout or ""
    if proc.stderr:
        # Surface stderr but don't bury stdout; route to our stderr so
        # piping `sra dev ... > out.yaml` stays clean.
        print(proc.stderr, end="", file=sys.stderr)

    # Only persist a non-zero-rc output to a `.partial` sibling so the
    # user can inspect it but can't accidentally feed it back as a
    # real artifact. Atomic write on the happy path so a Ctrl+C between
    # the .tmp dump and rename leaves the prior file (if any) intact.
    if out_path is not None:
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if proc.returncode != 0:
                partial = out_path.with_suffix(out_path.suffix + ".partial")
                partial.write_text(output, encoding="utf-8")
                print(
                    f"[dev] claude -p returned {proc.returncode}; wrote "
                    f"{partial} (partial)",
                    file=sys.stderr,
                )
            else:
                tmp = out_path.with_suffix(out_path.suffix + ".tmp")
                tmp.write_text(output, encoding="utf-8")
                os.replace(tmp, out_path)
                print(f"[dev] wrote {out_path} ({len(output)} chars)",
                      file=sys.stderr)
        except OSError as e:
            print(f"error: cannot write {out_path}: {e}", file=sys.stderr)
            return 1
    else:
        sys.stdout.write(output)
        if not output.endswith("\n"):
            sys.stdout.write("\n")

    if proc.returncode != 0:
        print(f"[dev] claude -p returned {proc.returncode}",
              file=sys.stderr)
    return proc.returncode


# ---- command entry points -------------------------------------------------

def cmd_dev_create_semgrep_rule(
    pattern: str,
    lang: str,
    out: str | None,
    model: str | None,
) -> int:
    """`sra dev create-semgrep-rule`.

    The user supplies a pseudo-code `pattern` (e.g. `eval(user_input)`)
    and a target `lang` (e.g. `javascript`). The ToB
    `semgrep-rule-creator` skill produces a draft Semgrep YAML rule on
    stdout (or to `out` if provided).
    """
    user_block = (
        f"Create a Semgrep rule for the following pseudo-code pattern.\n\n"
        f"- **Pattern (pseudo-code)**: `{pattern}`\n"
        f"- **Target language**: `{lang}`\n\n"
        "Produce a single complete Semgrep YAML rule. Include a sensible "
        "rule id, message, severity, languages list, and a `pattern` "
        "(or `patterns:`/`pattern-either:`) block that captures the "
        "pseudo-code intent. After the YAML, briefly note any "
        "limitations or false-positive risks. Output the YAML inside a "
        "```yaml fenced block."
    )
    out_path = Path(out).expanduser().resolve() if out else None
    return _invoke_dev_skill(
        "create-semgrep-rule", user_block,
        out_path=out_path, model=model,
    )


def cmd_dev_create_variant(
    rule_path_str: str,
    out: str | None,
    model: str | None,
) -> int:
    """`sra dev create-variant`.

    Reads the YAML rule at `rule_path_str` and asks ToB
    `semgrep-rule-variant-creator` to produce language variants.
    """
    rule_path = Path(rule_path_str).expanduser().resolve()
    if not rule_path.is_file():
        print(f"error: rule file not found: {rule_path}", file=sys.stderr)
        return 2
    try:
        rule_text = rule_path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"error: cannot read {rule_path}: {e}", file=sys.stderr)
        return 2

    user_block = (
        f"Produce variants of the following Semgrep rule for additional "
        f"target languages. Use the skill's applicability analysis to "
        f"decide which languages are sensible variants. For each "
        f"applicable language, output a complete independent YAML rule "
        f"in its own ```yaml fenced block, preceded by a short "
        f"justification.\n\n"
        f"=== ORIGINAL RULE ({rule_path.name}) ===\n\n"
        f"```yaml\n{rule_text}\n```\n"
    )
    out_path = Path(out).expanduser().resolve() if out else None
    return _invoke_dev_skill(
        "create-variant", user_block,
        out_path=out_path, model=model,
    )


def cmd_dev_improve_skill(
    skill_name: str,
    out: str | None,
    model: str | None,
) -> int:
    """`sra dev improve-skill --skill <name>`.

    `<name>` resolves in this order:
      1. An existing file path (absolute or relative to cwd).
      2. `prompts/skill_<name>.md` (with `-` converted to `_`).

    The skill content is passed to ToB `skill-improver`, which returns
    suggested improvements as markdown on stdout.
    """
    skill_path = _resolve_our_skill(skill_name)
    if skill_path is None:
        print(
            f"error: could not resolve our skill {skill_name!r}. Tried as "
            f"file path and as prompts/skill_<name>.md.",
            file=sys.stderr,
        )
        return 2
    try:
        skill_text = skill_path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"error: cannot read {skill_path}: {e}", file=sys.stderr)
        return 2

    user_block = (
        f"Review the following skill spec and return concrete, actionable "
        f"improvement suggestions as a markdown report. Categorise issues "
        f"by severity (critical / major / minor). For each issue, quote "
        f"the offending excerpt and propose a specific replacement. Do "
        f"not output a rewritten SKILL.md — only the review.\n\n"
        f"=== SKILL UNDER REVIEW ({skill_path.name}) ===\n\n"
        f"{skill_text}\n"
    )
    out_path = Path(out).expanduser().resolve() if out else None
    return _invoke_dev_skill(
        "improve-skill", user_block,
        out_path=out_path, model=model,
    )


def cmd_dev_design_workflow(
    description: str,
    out: str | None,
    model: str | None,
) -> int:
    """`sra dev design-workflow --description '<text>'`.

    Passes the natural-language workflow description to ToB
    `workflow-skill-design` (SKILL.md is under
    `skills/designing-workflow-skills/`). The skill returns a draft
    workflow-skill spec as markdown.
    """
    user_block = (
        f"Design a workflow-based skill that accomplishes the following "
        f"goal. Apply the skill's principles (numbered phases, entry / "
        f"exit criteria, progressive disclosure, decision trees, "
        f"subagent delegation where appropriate). Output a complete "
        f"draft SKILL.md including YAML frontmatter, plus a short "
        f"explanation of which patterns you applied and why.\n\n"
        f"=== WORKFLOW GOAL ===\n\n"
        f"{description}\n"
    )
    out_path = Path(out).expanduser().resolve() if out else None
    return _invoke_dev_skill(
        "design-workflow", user_block,
        out_path=out_path, model=model,
    )


def _resolve_our_skill(name: str) -> Path | None:
    """Resolve `name` to one of our `prompts/skill_<X>.md` files.

    Accepts either a file path or a short name like `input-validation`
    / `input_validation`. Returns None if nothing matches.
    """
    # 1. literal file path
    cand = Path(name).expanduser()
    if cand.is_file():
        return cand.resolve()

    # 2. prompts/skill_<name>.md, walking up from this module
    here = Path(__file__).resolve()
    underscored = name.replace("-", "_")
    candidates = (
        f"skill_{underscored}.md",
        f"skill_{name}.md",
        underscored if underscored.endswith(".md") else f"{underscored}.md",
    )
    for parent in [here.parent, *here.parents]:
        prompts = parent / "prompts"
        if not prompts.is_dir():
            continue
        for fname in candidates:
            p = prompts / fname
            if p.is_file():
                return p.resolve()
    return None
