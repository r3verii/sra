"""Skill loader — assemble the markdown blob fed to ``claude -p`` for a skill.

The loader takes a skill name registered in :mod:`sra.skill_registry`, reads
its ``SKILL.md`` from disk, expands the ``{baseDir}`` templating used by
Trail of Bits skills, optionally appends a language-specific references
file, prepends any dependency skills' content, and tacks on extra context
blocks. The result is the full markdown the pipeline pipes into
``claude -p`` via stdin.

Public API:

    load_skill_prompt(name, *, target_language=None, extra_context=None) -> str

CLI:

    python -m sra.skill_loader <skill_name> [--language <lang>]
"""

from __future__ import annotations

from pathlib import Path

from sra.skill_registry import SKILL_REGISTRY, SkillSpec


# Trail of Bits SKILL.md files use the literal string ``{baseDir}`` as a
# placeholder for the absolute path to the skill's directory (the one
# containing the SKILL.md). It appears in both inline markdown links
# (``[refs/foo.md]({baseDir}/refs/foo.md)``) and in shell snippets
# (``uv run {baseDir}/scripts/foo.py``).
_BASE_DIR_TOKEN = "{baseDir}"


# Aliases mapping a caller-supplied ``target_language`` to one or more
# reference-file slugs to search for under ``references_dir``. The first
# alias found wins. Direct matches (``<target_language>.md`` exactly) are
# tried first, before the alias list.
#
# These cover the slugs ToB skills actually use in their ``references/``
# folders (e.g. entry-point-analyzer has solana.md / move-sui.md / etc).
_LANGUAGE_ALIASES: dict[str, tuple[str, ...]] = {
    "rust": ("rust", "solana"),   # rust commonly maps to solana in ToB skills
    "c++": ("cpp", "c++"),
    "cpp": ("cpp", "c++"),
    "javascript": ("javascript", "js"),
    "typescript": ("typescript", "ts"),
    "move": ("move", "move-sui", "move-aptos"),
}


def _expand_basedir(text: str, base_dir: Path) -> str:
    """Replace every ``{baseDir}`` occurrence with ``base_dir``.

    Forces forward-slash form via ``Path.as_posix()``. On Windows,
    ``str(Path("D:/foo"))`` returns ``D:\\foo``; ToB skill bodies
    contain shell snippets like ``uv run {baseDir}/scripts/foo.py``,
    so substituting a backslash path produces mixed separators
    (``uv run D:\\foo\\scripts/foo.py``) that confuse sh-style commands
    and look ugly in the prompt.
    """
    return text.replace(_BASE_DIR_TOKEN, base_dir.as_posix())


def _read_skill_md(spec: SkillSpec) -> str:
    """Read a spec's SKILL.md and expand ``{baseDir}`` relative to its parent."""
    path = spec.resolved_path()
    text = path.read_text(encoding="utf-8")
    return _expand_basedir(text, path.parent)


def _find_reference_file(refs_dir: Path, target_language: str) -> Path | None:
    """Return the references markdown file matching ``target_language``, if any.

    Looks for ``<target_language>.md`` first; falls back to known aliases
    (see :data:`_LANGUAGE_ALIASES`). Returns ``None`` if nothing matches —
    callers treat that as "no language refs, proceed silently".
    """
    if not refs_dir.is_dir():
        return None
    slug = target_language.lower()
    candidates: list[str] = [slug]
    for alias in _LANGUAGE_ALIASES.get(slug, ()):
        if alias not in candidates:
            candidates.append(alias)
    for cand in candidates:
        candidate = refs_dir / f"{cand}.md"
        if candidate.is_file():
            return candidate
    return None


def _read_reference(ref_path: Path, skill_base_dir: Path) -> str:
    """Read a references file and expand ``{baseDir}`` relative to the SKILL.md's dir."""
    text = ref_path.read_text(encoding="utf-8")
    return _expand_basedir(text, skill_base_dir)


def _walk_dependencies(name: str, seen: set[str], order: list[str]) -> None:
    """Depth-first post-order walk of the dependency graph.

    Appends each visited skill name to ``order`` *after* its own
    dependencies. The result is that ``order[0]`` is the deepest
    dependency and ``order[-1]`` is ``name`` itself. Cycles are broken
    by the ``seen`` set: a name encountered twice is skipped on the
    second visit.

    Dependencies that aren't registered (unknown names) are silently
    skipped — they're treated like missing optional helpers rather than
    a hard error, so a single typo in a spec doesn't break every loader
    call that transitively touches it. (The registry's own ``--verify``
    command is the place where missing-dep errors should surface.)
    """
    if name in seen:
        return
    seen.add(name)
    if name not in SKILL_REGISTRY:
        return
    spec = SKILL_REGISTRY[name]
    for dep in spec.dependencies:
        _walk_dependencies(dep, seen, order)
    order.append(name)


def load_skill_prompt(
    skill_name: str,
    *,
    target_language: str | None = None,
    extra_context: list[str] | None = None,
) -> str:
    """Return the full markdown to feed ``claude -p`` for this skill.

    Resolves:

    * SKILL.md content (with ``{baseDir}`` templating expanded to the
      absolute filesystem path of the skill's directory)
    * references/<lang>.md if ``target_language`` matches a file in
      ``references_dir`` (only when ``references_dir`` is set on the spec)
    * dependencies' SKILL.md prepended as context (recursive — but
      cycles broken with a seen-set)
    * ``extra_context`` blocks appended verbatim at the end

    Raises:
        KeyError: if ``skill_name`` is not registered in
            :data:`sra.skill_registry.SKILL_REGISTRY`.
        FileNotFoundError: if any required file is missing.
    """
    if skill_name not in SKILL_REGISTRY:
        raise KeyError(skill_name)
    primary = SKILL_REGISTRY[skill_name]

    # Resolve dependencies in post-order (deepest first). The last entry
    # is always ``skill_name`` itself; we drop it because the primary
    # content gets its own dedicated section below.
    order: list[str] = []
    _walk_dependencies(skill_name, seen=set(), order=order)
    dep_names = order[:-1]

    sections: list[str] = []
    sections.append(f"=== Loaded skill: {skill_name} (source={primary.source}) ===")

    for dep_name in dep_names:
        dep_spec = SKILL_REGISTRY[dep_name]
        dep_content = _read_skill_md(dep_spec)
        sections.append(f"=== Dependency skill: {dep_name} ===\n\n{dep_content}")

    sections.append(f"=== Primary skill content ===\n\n{_read_skill_md(primary)}")

    if target_language and primary.references_dir is not None:
        refs_dir = primary.resolved_references_dir()
        if refs_dir is not None:
            ref_path = _find_reference_file(refs_dir, target_language)
            if ref_path is not None:
                skill_base_dir = primary.resolved_path().parent
                ref_content = _read_reference(ref_path, skill_base_dir)
                sections.append(
                    f"=== References (target_language={target_language}) ===\n\n"
                    f"{ref_content}"
                )

    if extra_context:
        blocks = "\n\n".join(extra_context)
        sections.append(f"=== Additional context ===\n\n{blocks}")

    return "\n\n".join(sections) + "\n"


# =========================================================================
# CLI: ``python -m sra.skill_loader <skill_name> [--language <lang>]``
# =========================================================================

def _main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="python -m sra.skill_loader",
        description=(
            "Resolve a registered skill to the full markdown prompt that "
            "would be piped into ``claude -p``. Useful for inspecting what "
            "a skill expands to (dependencies, references, {baseDir} "
            "templating) without spending a real Claude call."
        ),
    )
    parser.add_argument("skill_name", help="A key from sra.skill_registry.SKILL_REGISTRY.")
    parser.add_argument(
        "--language",
        default=None,
        help=(
            "Optional target_language. When set, and the skill's spec has "
            "a references_dir, the matching <lang>.md is appended."
        ),
    )
    args = parser.parse_args(argv)

    try:
        out = load_skill_prompt(args.skill_name, target_language=args.language)
    except KeyError:
        parser.error(
            f"unknown skill: {args.skill_name!r}. "
            "Run `python -m sra.skill_registry --verify` to see the registry."
        )
        return 2  # parser.error exits; this is just for type checkers
    except FileNotFoundError as exc:
        parser.error(f"skill file missing on disk: {exc}")
        return 2

    # Skill content frequently contains non-ASCII (em dashes, smart quotes,
    # arrows). On Windows, sys.stdout defaults to cp1252 and chokes; write
    # bytes directly so the encoding is forced to UTF-8 regardless of
    # platform / console code page.
    sys.stdout.buffer.write(out.encode("utf-8"))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via CLI
    raise SystemExit(_main())
