"""sra CLI — multi-stage source-code security audit pipeline.

End-to-end orchestrator: `sra audit <repo>` runs every stage below.
Each stage writes its output to `.audit/<stage>/` and is resumable
(re-running picks up where the previous run left off).

Stage 00 — `sra collect`
    Walks the repository and writes neutral raw structural signals
    (`00-fingerprint/raw-signals.json` + human-readable
    `raw-summary.md`): file counts, extensions, directory shape,
    manifest filenames, parsed package metadata (package.json,
    pyproject.toml, go.mod, etc.). Records observable facts only —
    no risk scoring, no security keywords, no LLM call.

Stage 01 — `sra fingerprint`
    Pipes `raw-summary.md` into `claude -p` with the fingerprint
    prompts. Claude classifies the repo (languages, frameworks,
    domains, protocols), names security-relevant areas, suggests an
    initial audit pack list (4-7 audit/* families) and a workflow
    mode hint. Output: `00-fingerprint/fingerprint.{json,md}`.

Stage 02 — `sra route-packs`
    Deterministic normalisation of `fingerprint.json`. Dedupes
    `suggested_packs`, splits by prefix, caps `audit/` at
    MAX_AUDIT_PACKS, applies the audit-family backstop (adds
    crypto-auth / input-validation / server-side-injection /
    business-logic / supply-chain / config-deployment when raw-
    signals evidence warrants it but the LLM fingerprint missed
    them). Output: `01-pack-router/selected-packs.json` +
    human-readable `next-steps.md`. No LLM.

Stage 03 — `sra plan`
    Per-family informational summary: which sensors WOULD be
    relevant, what first-review questions an auditor should ask.
    Output: `02-plan/audit-plan.{json,md}`. Informational only —
    cmd_audit doesn't read these back; the actual sensor list
    comes from the `--sensor` CLI flag (default: all three).
    No LLM.

Stage 04 — sensors + packets per family
    For each elected family: run ripgrep + semgrep + ast-grep against
    the repo using the family's catalogues under `sensors/`. Cluster
    sensor hits into review packets at
    `04-packets-sensors/<family>/PACKET-NNN.md`. Optional 04a
    `audit-context-building` and 04b `entry-point-analyzer` (smart-
    contracts-only) write `04-context/{context-building,entry-points}.md`.
    These are the WHOLE-REPO claude calls that produce the repo
    summary used as preamble for every per-packet skill below.

Stage 05 — per-packet skill investigation
    For each PACKET-NNN.md, invoke the family-specific claude skill
    (via `_invoke_claude_skill`). Skills produce
    `PACKET-NNN.findings.md` with confirmed findings + dismissed
    sensor hits + limitations. Parallelisable via `--parallel N`.

Stage 06 — variant-analysis + fp-check
    06a: for every confirmed finding, invoke the ToB
    variant-analysis skill to look for similar bugs elsewhere
    (`06-variants/<family-slug>/<PACKET>-<idx>.md`).
    06b: invoke ToB fp-check skill over EVERY family's findings
    to produce an audit-of-audits report at
    `06-fp-check/audit-of-audits.md`.

Stage 05 final — `sra build-report`
    Deterministic aggregation of every per-packet findings.md +
    variants + fp-check into a single `05-report/repo-report.{md,json}`.
    No LLM, no new investigation; just structural roll-up grouped
    by family with severity within family.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from sra.output import get_reporter
from sra.report import cmd_build_report, _parse_findings_md, _parse_fp_check
from sra.skill_registry import SKILL_REGISTRY, SkillSpec
from sra.skill_loader import load_skill_prompt
from sra.dev_tools import (
    cmd_dev_create_semgrep_rule,
    cmd_dev_create_variant,
    cmd_dev_improve_skill,
    cmd_dev_design_workflow,
)
from sra.audit_modes import (
    cmd_audit_mode_differential,
    cmd_audit_mode_mutation_testing,
    cmd_audit_mode_property_based_testing,
    cmd_audit_mode_spec_to_code,
)

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


# --- Static reference data --------------------------------------------------

# Broad generic list of manifest, build, and config filenames.
# Matched by exact filename (case-sensitive, per their canonical spelling).
MANIFEST_FILENAMES: set[str] = {
    # Python
    "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
    "Pipfile", "Pipfile.lock", "poetry.lock", "tox.ini", "environment.yml",
    "MANIFEST.in",
    # JavaScript / TypeScript / Node
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lockb", "deno.json", "deno.jsonc",
    "tsconfig.json", "jsconfig.json",
    # Ruby
    "Gemfile", "Gemfile.lock", "Rakefile",
    # PHP
    "composer.json", "composer.lock",
    # Go
    "go.mod", "go.sum", "go.work", "go.work.sum",
    # Rust
    "Cargo.toml", "Cargo.lock",
    # JVM
    "pom.xml", "build.gradle", "build.gradle.kts",
    "settings.gradle", "settings.gradle.kts",
    "build.sbt", "ivy.xml",
    # .NET
    "packages.config", "project.json", "paket.dependencies",
    # Swift / iOS
    "Package.swift", "Podfile", "Podfile.lock",
    "Cartfile", "Cartfile.resolved",
    # C / C++
    "CMakeLists.txt", "Makefile", "GNUmakefile",
    "configure.ac", "configure.in", "meson.build",
    "conanfile.txt", "conanfile.py", "vcpkg.json",
    # Bazel / Buck
    "BUILD", "BUILD.bazel", "WORKSPACE", "WORKSPACE.bazel",
    # Elixir / Erlang
    "mix.exs", "mix.lock", "rebar.config",
    # Haskell
    "cabal.project", "stack.yaml",
    # OCaml
    "dune-project",
    # Dart
    "pubspec.yaml", "pubspec.lock",
    # Crystal
    "shard.yml", "shard.lock",
    # Containers
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerignore", "Procfile",
    # CI
    ".gitlab-ci.yml", ".travis.yml", "azure-pipelines.yml",
    "bitbucket-pipelines.yml", "Jenkinsfile", "appveyor.yml",
    # Repo metadata
    ".editorconfig", ".gitignore", ".gitattributes",
    ".npmrc", ".yarnrc", ".pnpmrc",
    ".nvmrc", ".python-version", ".ruby-version", ".tool-versions",
}


# Directory role groups based on generic naming conventions only.
# Match is case-insensitive, exact basename.
DIRECTORY_ROLE_NAMES: dict[str, set[str]] = {
    "docs":     {"docs", "doc", "documentation"},
    "tests":    {"tests", "test", "spec", "specs", "regression"},
    "examples": {"examples", "example", "samples", "sample", "demo", "demos"},
    "source":   {"src", "source", "sources", "lib", "libs", "include", "includes"},
    "config":   {"config", "configs", "configuration", "settings"},
    "scripts":  {"scripts", "script", "tools", "tooling", "dev"},
}


# Directories the walker never descends into.
SKIP_DIRECTORIES: set[str] = {
    ".git", ".hg", ".svn",
    "node_modules", "bower_components", "vendor",
    "__pycache__", ".venv", "venv", "env",
    ".tox", ".nox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", "target", "out",
    ".idea", ".vscode", ".vs",
    ".gradle", ".next", ".nuxt", ".svelte-kit",
    ".audit",
}


# Limits to keep output well-bounded.
MAX_READ_BYTES = 256 * 1024
MAX_README_LINES = 40
MAX_README_LINE_LENGTH = 2000
MAX_README_FILES = 25
MAX_README_FILES_IN_SUMMARY = 3
MAX_ROLE_DIRS_PER_ROLE = 50
TOP_FILENAME_STEMS = 50
TOP_DIRECTORY_NAMES = 50
TOP_DIRECTORIES_BY_FILE_COUNT = 20


# --- Helpers ----------------------------------------------------------------

def posix(path: Path | str) -> str:
    return str(path).replace(os.sep, "/")


def _family_slug(family: str) -> str:
    """Convert an `audit/<family>` identifier to its on-disk slug.

    Example: ``audit/access-control`` -> ``audit-access-control``. Used for
    naming sensor catalogs, evidence directories, and packet directories.
    """
    return family.replace("/", "-")


def read_text_safely(path: Path, max_bytes: int = MAX_READ_BYTES) -> str | None:
    try:
        with open(path, "rb") as f:
            raw = f.read(max_bytes)
    except OSError:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def is_readme_filename(filename: str) -> bool:
    f = filename.lower()
    return f == "readme" or f.startswith("readme.")


def match_directory_role(directory_name: str) -> str | None:
    name = directory_name.lower()
    for role, names in DIRECTORY_ROLE_NAMES.items():
        if name in names:
            return role
    return None


def extract_readme_first_lines(path: Path) -> list[str]:
    content = read_text_safely(path)
    if content is None:
        return []
    result: list[str] = []
    for line in content.splitlines():
        if not line.strip():
            continue
        if len(line) > MAX_README_LINE_LENGTH:
            line = line[:MAX_README_LINE_LENGTH] + "..."
        result.append(line)
        if len(result) >= MAX_README_LINES:
            break
    return result


# --- TOML helpers ------------------------------------------------------------

def _toml_load(content: str) -> dict | None:
    """Try to parse TOML with the stdlib parser. Returns None on failure."""
    if tomllib is None:
        return None
    try:
        return tomllib.loads(content)
    except Exception:
        return None


def _extract_toml_table_name(content: str, table: str) -> str | None:
    """Regex fallback: read `name = "..."` from a top-level [table] block.

    Used when tomllib is unavailable (Python < 3.11) or the file fails to
    parse strictly. Only handles the simple case of a top-level table with
    a single-line `name = "value"` entry.
    """
    pattern_table = re.compile(
        r'^\s*\[\s*' + re.escape(table) + r'\s*\]\s*$',
        re.MULTILINE,
    )
    match = pattern_table.search(content)
    if not match:
        return None
    rest = content[match.end():]
    next_header = re.search(r'^\s*\[[^\[\]]+\]\s*$', rest, re.MULTILINE)
    block = rest[: next_header.start()] if next_header else rest
    name_match = re.search(
        r'^\s*name\s*=\s*(?:"([^"]*)"|\'([^\']*)\')',
        block,
        re.MULTILINE,
    )
    if not name_match:
        return None
    return name_match.group(1) or name_match.group(2)


# --- Manifest parsers --------------------------------------------------------

def parse_package_json(path: Path) -> dict | None:
    content = read_text_safely(path)
    if content is None:
        return None
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    deps: list[str] = []
    for key in ("dependencies", "devDependencies",
                "peerDependencies", "optionalDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            deps.extend(k for k in section.keys() if isinstance(k, str))
    name = data.get("name")
    desc = data.get("description")
    return {
        "name": name if isinstance(name, str) else None,
        "description": desc if isinstance(desc, str) else None,
        "dependencies": deps,
    }


def parse_composer_json(path: Path) -> dict | None:
    content = read_text_safely(path)
    if content is None:
        return None
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    deps: list[str] = []
    for key in ("require", "require-dev"):
        section = data.get(key)
        if isinstance(section, dict):
            deps.extend(k for k in section.keys() if isinstance(k, str))
    name = data.get("name")
    desc = data.get("description")
    return {
        "name": name if isinstance(name, str) else None,
        "description": desc if isinstance(desc, str) else None,
        "dependencies": deps,
    }


def parse_pyproject_toml(path: Path) -> dict | None:
    content = read_text_safely(path)
    if content is None:
        return None
    name: str | None = None
    data = _toml_load(content)
    if isinstance(data, dict):
        project = data.get("project")
        if isinstance(project, dict):
            n = project.get("name")
            if isinstance(n, str):
                name = n
    if name is None:
        name = _extract_toml_table_name(content, "project")
    if name is None:
        return None
    return {"name": name}


def parse_cargo_toml(path: Path) -> dict | None:
    content = read_text_safely(path)
    if content is None:
        return None
    name: str | None = None
    data = _toml_load(content)
    if isinstance(data, dict):
        package = data.get("package")
        if isinstance(package, dict):
            n = package.get("name")
            if isinstance(n, str):
                name = n
    if name is None:
        name = _extract_toml_table_name(content, "package")
    if name is None:
        return None
    return {"name": name}


_GO_MOD_MODULE_RE = re.compile(r'^\s*module\s+(\S+)\s*$', re.MULTILINE)
# Matches dependency lines inside `require (...)` blocks AND single-
# line `require <path> <version>` forms. The path itself may include
# `/v<N>` major-version suffixes (go-chi/chi/v5) and arbitrary
# domain.tld/owner/repo shapes. Stops at the first whitespace before
# the version token.
_GO_MOD_REQUIRE_BLOCK_RE = re.compile(
    r'^\s*require\s*\(\s*$(?P<block>.*?)^\s*\)\s*$',
    re.MULTILINE | re.DOTALL,
)
_GO_MOD_REQUIRE_LINE_RE = re.compile(
    r'^\s*(?P<path>[A-Za-z0-9._/\-]+)\s+(?P<version>v[^\s]+)',
    re.MULTILINE,
)
_GO_MOD_REQUIRE_SINGLE_RE = re.compile(
    r'^\s*require\s+(?P<path>[A-Za-z0-9._/\-]+)\s+(?P<version>v[^\s]+)',
    re.MULTILINE,
)


def parse_go_mod(path: Path) -> dict | None:
    """Parse a `go.mod` file into ``{"module": ..., "dependencies": {...}}``.

    Both forms are supported:

        require github.com/go-chi/chi/v5 v5.2.2       # single-line
        require (
            github.com/go-chi/chi/v5 v5.2.2           # block form
            github.com/swaggo/http-swagger/v2 v2.0.2
        )

    The dependencies dict mirrors the shape produced by `parse_package_json`
    so the backstop and other downstream consumers can iterate the same
    way across language ecosystems.
    """
    content = read_text_safely(path)
    if content is None:
        return None
    match = _GO_MOD_MODULE_RE.search(content)
    if not match:
        return None

    deps: dict[str, str] = {}
    # require (...) blocks — may have multiple, e.g. one for regular
    # deps and one for indirect deps.
    for block in _GO_MOD_REQUIRE_BLOCK_RE.finditer(content):
        for ln in _GO_MOD_REQUIRE_LINE_RE.finditer(block.group("block")):
            deps[ln.group("path")] = ln.group("version")
    # Single-line `require path version` statements outside blocks.
    for ln in _GO_MOD_REQUIRE_SINGLE_RE.finditer(content):
        deps[ln.group("path")] = ln.group("version")

    return {"module": match.group(1), "dependencies": deps}


# --- Main collection ---------------------------------------------------------

def collect_signals(repo_path: Path) -> dict:
    repo_path = repo_path.resolve()

    total_files = 0
    files_without_extension = 0
    extension_counts: Counter[str] = Counter()
    dir_file_counts: Counter[str] = Counter()
    filename_stem_counts: Counter[str] = Counter()
    directory_name_counts: Counter[str] = Counter()

    manifest_files: list[str] = []
    readme_files: list[dict] = []
    directory_roles: dict[str, list[str]] = {role: [] for role in DIRECTORY_ROLE_NAMES}

    package_metadata: dict[str, list[dict]] = {
        "package_json": [],
        "composer_json": [],
        "pyproject_toml": [],
        "go_mod": [],
        "cargo_toml": [],
    }

    # Top-level directories (filtered through SKIP_DIRECTORIES).
    top_level_directories: list[str] = []
    try:
        for entry in sorted(os.listdir(repo_path)):
            full = repo_path / entry
            if full.is_dir() and entry not in SKIP_DIRECTORIES:
                top_level_directories.append(entry)
    except OSError:
        pass

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]

        root_path = Path(root)
        rel_root = root_path.relative_to(repo_path)
        rel_root_str = posix(rel_root) if str(rel_root) != "." else "."

        for d in dirs:
            directory_name_counts[d] += 1
            role = match_directory_role(d)
            if role is not None and len(directory_roles[role]) < MAX_ROLE_DIRS_PER_ROLE:
                directory_roles[role].append(posix(rel_root / d))

        if files:
            dir_file_counts[rel_root_str] += len(files)

        for fname in files:
            total_files += 1

            stem = Path(fname).stem
            if stem:
                filename_stem_counts[stem] += 1

            ext = Path(fname).suffix.lower()
            if ext:
                extension_counts[ext] += 1
            else:
                files_without_extension += 1

            if fname in MANIFEST_FILENAMES:
                manifest_files.append(posix(rel_root / fname))

            if is_readme_filename(fname) and len(readme_files) < MAX_README_FILES:
                readme_files.append({
                    "path": posix(rel_root / fname),
                    "first_lines": extract_readme_first_lines(root_path / fname),
                })

            full_path = root_path / fname
            rel_path = posix(rel_root / fname)

            if fname == "package.json":
                meta = parse_package_json(full_path)
                if meta is not None:
                    package_metadata["package_json"].append({"path": rel_path, **meta})
            elif fname == "composer.json":
                meta = parse_composer_json(full_path)
                if meta is not None:
                    package_metadata["composer_json"].append({"path": rel_path, **meta})
            elif fname == "pyproject.toml":
                meta = parse_pyproject_toml(full_path)
                if meta is not None:
                    package_metadata["pyproject_toml"].append({"path": rel_path, **meta})
            elif fname == "go.mod":
                meta = parse_go_mod(full_path)
                if meta is not None:
                    package_metadata["go_mod"].append({"path": rel_path, **meta})
            elif fname == "Cargo.toml":
                meta = parse_cargo_toml(full_path)
                if meta is not None:
                    package_metadata["cargo_toml"].append({"path": rel_path, **meta})

    manifest_files.sort()
    # Sort shallow paths first so root README appears before nested ones.
    readme_files.sort(key=lambda d: (d["path"].count("/"), d["path"]))
    for role in directory_roles:
        directory_roles[role].sort()

    largest_directories = [
        {"path": p, "file_count": c}
        for p, c in dir_file_counts.most_common(TOP_DIRECTORIES_BY_FILE_COUNT)
    ]
    top_filename_stems = dict(filename_stem_counts.most_common(TOP_FILENAME_STEMS))
    top_directory_names = dict(directory_name_counts.most_common(TOP_DIRECTORY_NAMES))

    return {
        "schema_version": 2,
        "repo_path": posix(repo_path),
        "total_file_count": total_files,
        "files_without_extension": files_without_extension,
        "file_extension_counts": dict(extension_counts.most_common()),
        "top_level_directories": top_level_directories,
        "largest_directories_by_file_count": largest_directories,
        "manifest_files": manifest_files,
        "readme_files": readme_files,
        "package_metadata": package_metadata,
        "directory_role_signals": directory_roles,
        "top_filename_stems": top_filename_stems,
        "top_directory_names": top_directory_names,
    }


# --- Output -----------------------------------------------------------------

def write_json(signals: dict, path: Path) -> None:
    path.write_text(
        json.dumps(signals, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _format_counter_dict(d: dict, limit: int) -> list[str]:
    items = list(d.items())[:limit]
    return [f"- `{k}`: {v}" for k, v in items]


def _safe_backtick_fence(content_lines: list[str]) -> str:
    """Return a backtick fence longer than any backtick run in the content.

    This guarantees that no line inside the rendered code block can close
    the fence prematurely, even if the source text contains its own
    ``` markers.
    """
    max_run = 0
    for line in content_lines:
        for match in re.finditer(r"`+", line):
            run = len(match.group())
            if run > max_run:
                max_run = run
    return "`" * max(3, max_run + 1)


def _render_metadata_entry(entry: dict, out) -> None:
    out(f"- `{entry['path']}`")
    if entry.get("name"):
        out(f"  - name: `{entry['name']}`")
    if entry.get("module"):
        out(f"  - module: `{entry['module']}`")
    desc = entry.get("description")
    if isinstance(desc, str) and desc:
        if len(desc) > 200:
            desc = desc[:200] + "..."
        out(f"  - description: {desc}")
    deps = entry.get("dependencies")
    if isinstance(deps, list) and deps:
        shown = deps[:30]
        listed = ", ".join(f"`{d}`" for d in shown)
        suffix = ", showing first 30" if len(deps) > 30 else ""
        out(f"  - dependencies ({len(deps)}{suffix}): {listed}")


def write_summary(signals: dict, path: Path) -> None:
    lines: list[str] = []
    out = lines.append

    out("# Raw repository signals")
    out("")
    out(f"- Repository: `{signals['repo_path']}`")
    out(f"- Total files: {signals['total_file_count']}")
    out(f"- Files without extension: {signals['files_without_extension']}")
    out(f"- Top-level directories: {len(signals['top_level_directories'])}")
    out(f"- Manifest / build / config files: {len(signals['manifest_files'])}")
    out(f"- README-like files: {len(signals['readme_files'])}")

    out("")
    out("## Top-level directories")
    out("")
    if signals["top_level_directories"]:
        for d in signals["top_level_directories"]:
            out(f"- `{d}/`")
    else:
        out("_(none)_")

    out("")
    out("## Largest directories (by direct file count)")
    out("")
    if signals["largest_directories_by_file_count"]:
        for entry in signals["largest_directories_by_file_count"]:
            out(f"- `{entry['path']}` — {entry['file_count']} files")
    else:
        out("_(none)_")

    out("")
    out("## Directory role signals")
    out("")
    for role, paths in signals["directory_role_signals"].items():
        out(f"### `{role}` ({len(paths)})")
        out("")
        if paths:
            for p in paths:
                out(f"- `{p}/`")
        else:
            out("_(none)_")
        out("")

    out("## Top file extensions")
    out("")
    rows = _format_counter_dict(signals["file_extension_counts"], 25)
    if rows:
        lines.extend(rows)
    else:
        out("_(none)_")

    out("")
    out(f"## Top filename stems (max {TOP_FILENAME_STEMS}, showing 25)")
    out("")
    rows = _format_counter_dict(signals["top_filename_stems"], 25)
    if rows:
        lines.extend(rows)
    else:
        out("_(none)_")

    out("")
    out(f"## Top directory names (max {TOP_DIRECTORY_NAMES}, showing 25)")
    out("")
    rows = _format_counter_dict(signals["top_directory_names"], 25)
    if rows:
        lines.extend(rows)
    else:
        out("_(none)_")

    out("")
    out("## Manifest / build / config files")
    out("")
    if signals["manifest_files"]:
        for f in signals["manifest_files"]:
            out(f"- `{f}`")
    else:
        out("_(none)_")

    out("")
    out("## Manifest / package metadata")
    out("")
    pm = signals["package_metadata"]
    metadata_sections = [
        ("package.json",   "package_json"),
        ("composer.json",  "composer_json"),
        ("pyproject.toml", "pyproject_toml"),
        ("go.mod",         "go_mod"),
        ("Cargo.toml",     "cargo_toml"),
    ]
    parsed_paths: set[str] = set()
    for label, key in metadata_sections:
        entries = pm.get(key, [])
        out(f"### `{label}` ({len(entries)})")
        out("")
        if entries:
            for entry in entries:
                parsed_paths.add(entry["path"])
                _render_metadata_entry(entry, out)
        else:
            out("_(none)_")
        out("")

    other_manifests = [m for m in signals["manifest_files"] if m not in parsed_paths]
    out(f"### Other manifest / build / config files ({len(other_manifests)})")
    out("")
    if other_manifests:
        for m in other_manifests:
            out(f"- `{m}`")
    else:
        out("_(none)_")
    out("")

    out("## README previews")
    out("")
    readmes = signals["readme_files"]
    if readmes:
        shown = readmes[:MAX_README_FILES_IN_SUMMARY]
        if len(readmes) > MAX_README_FILES_IN_SUMMARY:
            out(
                f"_Showing first {len(shown)} of {len(readmes)} "
                f"README-like files._"
            )
            out("")
        for entry in shown:
            out(f"### `{entry['path']}`")
            out("")
            first_lines = entry["first_lines"]
            if first_lines:
                fence = _safe_backtick_fence(first_lines)
                out(fence)
                for ln in first_lines:
                    out(ln)
                out(fence)
            else:
                out("_(empty or unreadable)_")
            out("")
    else:
        out("_(none)_")
        out("")

    path.write_text("\n".join(lines), encoding="utf-8")


# --- Commands ---------------------------------------------------------------

def cmd_collect(repo_path_str: str) -> int:
    repo_path = Path(repo_path_str).expanduser()
    if not repo_path.exists():
        print(f"error: path does not exist: {repo_path}", file=sys.stderr)
        return 2
    if not repo_path.is_dir():
        print(f"error: not a directory: {repo_path}", file=sys.stderr)
        return 2

    output_dir = repo_path.resolve() / ".audit" / "00-fingerprint"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"sra: collecting raw signals from {repo_path.resolve()}", file=sys.stderr)
    signals = collect_signals(repo_path)

    json_path = output_dir / "raw-signals.json"
    md_path = output_dir / "raw-summary.md"

    write_json(signals, json_path)
    write_summary(signals, md_path)

    print(f"sra: wrote {posix(json_path)}", file=sys.stderr)
    print(f"sra: wrote {posix(md_path)}", file=sys.stderr)
    return 0


# --- Fingerprint command ----------------------------------------------------

FINGERPRINT_PLACEHOLDER = "{{raw_summary_md}}"
CLAUDE_TIMEOUT_SECONDS = 600

FINGERPRINT_SUMMARY_SECTIONS: list[tuple[str, str]] = [
    ("Languages",               "languages"),
    ("Repository types",        "repo_types"),
    ("Primary domains",         "primary_domains"),
    ("Secondary domains",       "secondary_domains"),
    ("Protocols",               "protocols"),
    ("Frameworks",              "frameworks"),
    ("Build systems",           "build_systems"),
    ("Package managers",        "package_managers"),
    ("Security-relevant areas", "security_relevant_areas"),
    ("Suggested modes",         "suggested_modes"),
    ("Suggested packs",         "suggested_packs"),
]


def _find_prompts_dir() -> Path:
    """Locate the sra prompts directory.

    Resolution order:
      1. ``SRA_PROMPTS_DIR`` environment variable (if set, must contain
         ``fingerprint_system.md``).
      2. The packaged location: ``<sra-package>/prompts/`` next to this
         module — works for both editable install (``pip install -e .``)
         and the wheel/pipx case (``site-packages/sra/prompts/``).
    """
    env_dir = os.environ.get("SRA_PROMPTS_DIR")
    if env_dir:
        candidate = Path(env_dir).expanduser().resolve()
        if (candidate / "fingerprint_system.md").is_file():
            return candidate
        raise FileNotFoundError(
            f"SRA_PROMPTS_DIR='{env_dir}' does not contain "
            f"fingerprint_system.md"
        )

    packaged = Path(__file__).resolve().parent / "prompts"
    if (packaged / "fingerprint_system.md").is_file():
        return packaged

    raise FileNotFoundError(
        f"could not locate fingerprint_system.md (looked in {packaged}). "
        f"Set SRA_PROMPTS_DIR to override."
    )


def _build_fingerprint_prompt(prompts_dir: Path, raw_summary: str) -> str:
    system_path = prompts_dir / "fingerprint_system.md"
    user_path = prompts_dir / "fingerprint_user.md"
    if not system_path.is_file():
        raise FileNotFoundError(f"missing prompt file: {system_path}")
    if not user_path.is_file():
        raise FileNotFoundError(f"missing prompt file: {user_path}")

    system_text = system_path.read_text(encoding="utf-8")
    user_text = user_path.read_text(encoding="utf-8")

    if FINGERPRINT_PLACEHOLDER not in user_text:
        raise ValueError(
            f"user prompt {user_path.name} does not contain placeholder "
            f"{FINGERPRINT_PLACEHOLDER!r}"
        )
    user_substituted = user_text.replace(FINGERPRINT_PLACEHOLDER, raw_summary)

    return f"{system_text}\n\n---\n\n{user_substituted}"


def _extract_fingerprint_json(text: str) -> dict | None:
    """Try several strategies to extract a JSON object from claude's output."""
    candidates: list[str] = []

    stripped = text.strip()
    candidates.append(stripped)

    if stripped.startswith("```"):
        first_nl = stripped.find("\n")
        if first_nl != -1:
            body = stripped[first_nl + 1:]
            close = body.rfind("```")
            if close != -1:
                body = body[:close]
            candidates.append(body.strip())

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        candidates.append(text[start:end + 1])

    for cand in candidates:
        if not cand:
            continue
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj

    return None


def _render_fingerprint_summary(fingerprint: dict) -> str:
    lines: list[str] = []
    out = lines.append

    out("# Repository fingerprint")
    out("")

    confidence = fingerprint.get("confidence") or {}
    if not isinstance(confidence, dict):
        confidence = {}

    def conf_for(field: str, value: object) -> str:
        if isinstance(value, str):
            key = f"{field}.{value}"
            v = confidence.get(key)
            if isinstance(v, str):
                return v
        v = confidence.get(field)
        if isinstance(v, str):
            return v
        return ""

    for title, key in FINGERPRINT_SUMMARY_SECTIONS:
        out(f"## {title}")
        out("")
        items = fingerprint.get(key) or []
        if not isinstance(items, list):
            items = []
        if items:
            for item in items:
                if not isinstance(item, str):
                    continue
                c = conf_for(key, item)
                if c:
                    out(f"- `{item}` _(confidence: {c})_")
                else:
                    out(f"- `{item}`")
        else:
            out("_(none)_")
        out("")

    out("## Confidence")
    out("")
    if confidence:
        for k in sorted(confidence.keys()):
            v = confidence[k]
            if isinstance(v, str):
                out(f"- `{k}`: {v}")
    else:
        out("_(none)_")
    out("")

    out("## Unknowns")
    out("")
    unknowns = fingerprint.get("unknowns") or []
    if not isinstance(unknowns, list):
        unknowns = []
    written = 0
    for u in unknowns:
        if isinstance(u, str) and u.strip():
            out(f"- {u}")
            written += 1
    if written == 0:
        out("_(none)_")
    out("")

    out("## Reasoning")
    out("")
    reasoning = fingerprint.get("reasoning")
    if isinstance(reasoning, str) and reasoning.strip():
        out(reasoning.strip())
    else:
        out("_(none)_")
    out("")

    return "\n".join(lines)


def cmd_fingerprint(repo_path_str: str) -> int:
    repo_path = Path(repo_path_str).expanduser()
    if not repo_path.exists():
        print(f"error: path does not exist: {repo_path}", file=sys.stderr)
        return 2
    if not repo_path.is_dir():
        print(f"error: not a directory: {repo_path}", file=sys.stderr)
        return 2

    fingerprint_dir = repo_path.resolve() / ".audit" / "00-fingerprint"
    raw_summary_path = fingerprint_dir / "raw-summary.md"

    if not raw_summary_path.is_file():
        print(
            f"error: required input is missing: {raw_summary_path}\n"
            f"       run 'sra collect' first.",
            file=sys.stderr,
        )
        return 2

    if shutil.which("claude") is None:
        print(
            "error: the 'claude' CLI was not found on PATH.\n"
            "       install Claude Code from https://docs.claude.com/claude-code "
            "and ensure 'claude' is callable.",
            file=sys.stderr,
        )
        return 3

    try:
        prompts_dir = _find_prompts_dir()
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 4

    raw_summary = raw_summary_path.read_text(encoding="utf-8")

    try:
        prompt_text = _build_fingerprint_prompt(prompts_dir, raw_summary)
    except (FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 4

    print(
        f"sra: sending {len(prompt_text)} chars to 'claude -p' via stdin...",
        file=sys.stderr,
    )

    # Strip the nested-session env vars so `claude -p` doesn't refuse to
    # run when the orchestrator was itself launched from inside Claude
    # Code (CLAUDECODE / CLAUDE_CODE_ENTRYPOINT are set in that case).
    env = os.environ.copy()
    env.pop("CLAUDECODE",           None)
    env.pop("CLAUDE_CODE_ENTRYPOINT", None)

    try:
        result = subprocess.run(
            ["claude", "-p"],
            input=prompt_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=CLAUDE_TIMEOUT_SECONDS,
            env=env,
        )
    except subprocess.TimeoutExpired:
        print(
            f"error: 'claude' timed out after {CLAUDE_TIMEOUT_SECONDS}s",
            file=sys.stderr,
        )
        return 5
    except FileNotFoundError:
        print(
            "error: failed to invoke 'claude' (no longer on PATH?)",
            file=sys.stderr,
        )
        return 3

    if result.returncode != 0:
        print(
            f"error: 'claude' exited with code {result.returncode}",
            file=sys.stderr,
        )
        if result.stderr:
            print("--- claude stderr ---", file=sys.stderr)
            print(result.stderr.rstrip(), file=sys.stderr)
        return 5

    stdout = result.stdout or ""
    if not stdout.strip():
        print("error: 'claude' produced no output on stdout", file=sys.stderr)
        return 5

    fingerprint = _extract_fingerprint_json(stdout)
    if fingerprint is None:
        raw_response_path = fingerprint_dir / "fingerprint.raw.txt"
        try:
            raw_response_path.write_text(stdout, encoding="utf-8")
        except OSError:
            pass
        print(
            "error: 'claude' response was not valid JSON.\n"
            f"       raw response saved to {posix(raw_response_path)}",
            file=sys.stderr,
        )
        return 6

    json_path = fingerprint_dir / "fingerprint.json"
    md_path = fingerprint_dir / "fingerprint.md"

    json_path.write_text(
        json.dumps(fingerprint, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    md_path.write_text(
        _render_fingerprint_summary(fingerprint),
        encoding="utf-8",
    )

    # Clean up a stale raw response from a previous failure, if present.
    stale_raw = fingerprint_dir / "fingerprint.raw.txt"
    if stale_raw.is_file():
        try:
            stale_raw.unlink()
        except OSError:
            pass

    print(f"sra: wrote {posix(json_path)}", file=sys.stderr)
    print(f"sra: wrote {posix(md_path)}", file=sys.stderr)
    return 0


# --- Route-packs command ----------------------------------------------------

PACK_PREFIXES = ("language/", "domain/", "protocol/", "audit/")
# Raised from 6 to 8: the fingerprint Claude call tends to elect 3-4
# obvious audit families, but the deterministic backstop below adds up
# to 4 more (crypto-auth, input-validation, supply-chain, config-
# deployment) when strong evidence is present. 8 leaves headroom.
MAX_AUDIT_PACKS = 8

MODE_DISPLAY_NAMES = {
    "packet": "Packet Mode",
    "research_trail": "Research Trail Mode",
    "both": "Packet Mode and Research Trail Mode",
}


# --- Audit-family backstop rules --------------------------------------------
#
# Why this exists. The fingerprint Claude call is intentionally
# conservative ("Do not include every plausible audit family" — see
# `prompts/fingerprint_system.md`). On real-world repos like outline it
# routinely elects 3-4 families even when strong evidence justifies
# more. The backstop layer ADDS families when raw signals (deps, files,
# directories) unambiguously prove the family applies. Rules are
# deterministic so the result is reproducible and reviewable.
#
# Each rule names:
#   - the audit pack it backs ("audit/<family>")
#   - a function `(raw_signals: dict, fingerprint: dict) -> str | None`
#     that returns a reason string if the rule fires, None otherwise.
#
# Reasons are surfaced in selected-packs.json under `backstop_additions`
# and in next-steps.md so the user can see WHY each backstop pack was
# added.

_CRYPTO_AUTH_DEP_MARKERS: tuple[str, ...] = (
    "passport",                # generic passport.js auth lib + strategies
    "oauth2-server", "oauth2", "openid",
    "jsonwebtoken", "jose", "jws", "jwt-",
    "bcrypt", "argon2", "scrypt",
    "node-forge", "tweetnacl",
    "csurf", "express-session", "koa-session",
    "saml",
    # Python
    "authlib", "python-jose", "pyjwt", "passlib", "cryptography",
    "django-allauth", "flask-login",
    # Go
    "golang.org/x/crypto", "go-oauth2",
    # Rust
    "jsonwebtoken", "argon2", "ring", "rustls",
)

_HTTP_FRAMEWORK_DEP_MARKERS: tuple[str, ...] = (
    # Node
    "express", "koa", "fastify", "hapi", "@nestjs/core", "@hapi/hapi",
    "restify", "polka",
    # Python
    "django", "flask", "fastapi", "starlette", "tornado", "bottle",
    "aiohttp", "sanic", "pyramid",
    # Go HTTP routers (visible in go.mod path)
    "gin-gonic/gin", "labstack/echo", "go-chi/chi", "gorilla/mux",
    # Ruby
    "rails", "sinatra",
    # PHP
    "symfony", "laravel/framework", "slim/slim",
    # Java
    "spring-boot", "spring-web",
)

_DEPLOYMENT_FILE_MARKERS: tuple[str, ...] = (
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "kustomization.yaml", "kustomization.yml",
    "Chart.yaml", "values.yaml",
    "main.tf", "terragrunt.hcl",
    "Procfile",
)


def _classify_pack(pack: str) -> str:
    for prefix in PACK_PREFIXES:
        if pack.startswith(prefix):
            return prefix.rstrip("/")
    return "other"


def _all_dependency_names(raw_signals: dict) -> set[str]:
    """Flat lowercase set of dependency names from every manifest type
    in raw-signals.json (package_json, pyproject_toml, go_mod, cargo_toml,
    composer_json). Used by backstop rules to probe for marker libs."""
    out: set[str] = set()
    pm = raw_signals.get("package_metadata") or {}
    # The walker emits each manifest as a list of {path, dependencies, ...}
    for manifest_list in pm.values():
        if not isinstance(manifest_list, list):
            continue
        for entry in manifest_list:
            if not isinstance(entry, dict):
                continue
            deps = entry.get("dependencies") or {}
            if isinstance(deps, dict):
                for k in deps:
                    if isinstance(k, str):
                        out.add(k.lower())
            elif isinstance(deps, list):
                for k in deps:
                    if isinstance(k, str):
                        out.add(k.lower())
    return out


def _has_marker_dep(deps: set[str], markers: tuple[str, ...]) -> str | None:
    """Return the first marker substring that appears in any dep name.

    Substring match (not equality) because Node ecosystem prefixes
    packages with scopes (``@node-oauth/oauth2-server`` matches
    "oauth2-server") and Go module paths embed the lib name.

    Two filtering rules to avoid noisy reason strings:

    1. Prefer non-``@types/*`` packages. The TypeScript types ecosystem
       mirrors every runtime package as ``@types/<name>``, so a runtime
       dep on ``koa`` plus a devDep on ``@types/express-useragent`` would
       arbitrarily surface the types package first depending on set
       iteration order. We prefer the runtime dep when both match.

    2. Substring matching iterates markers IN ORDER, and within each
       marker iterates deps deterministically (sorted). So whichever
       marker appears first in the markers tuple gets priority.
    """
    runtime_match: str | None = None
    types_match: str | None = None
    for marker in markers:
        m = marker.lower()
        for d in sorted(deps):
            if m not in d:
                continue
            if d.startswith("@types/"):
                if types_match is None:
                    types_match = d
            else:
                runtime_match = d
                return runtime_match
    return runtime_match or types_match


def _backstop_crypto_auth(
    raw_signals: dict, fingerprint: dict,
) -> str | None:
    """Fire when the repo contains OAuth/JWT/password/crypto auth deps."""
    deps = _all_dependency_names(raw_signals)
    hit = _has_marker_dep(deps, _CRYPTO_AUTH_DEP_MARKERS)
    if hit:
        return f"deps include {hit!r} (auth/crypto library)"
    # Fingerprint Claude often spots auth surfaces even when we don't.
    sra = fingerprint.get("security_relevant_areas") or []
    if isinstance(sra, list) and any(
        isinstance(s, str) and "authentic" in s.lower() for s in sra
    ):
        return "fingerprint marked 'authentication surfaces' as security-relevant"
    return None


def _backstop_input_validation(
    raw_signals: dict, fingerprint: dict,
) -> str | None:
    """Fire on a webapp with HTTP-framework deps AND visible api/routes dirs.

    Almost any production HTTP service handles structured external input
    at boundaries — the canonical input-validation surface. Keep it
    conditional on real evidence so library-style repos don't trigger.
    """
    deps = _all_dependency_names(raw_signals)
    fw_hit = _has_marker_dep(deps, _HTTP_FRAMEWORK_DEP_MARKERS)
    if not fw_hit:
        return None
    # Need at least one visible HTTP surface directory. Includes both
    # plural (Node/Python convention: "handlers", "routes") and
    # singular (Go convention: "handler", "route") forms, plus the
    # Go-standard `cmd` (binary entry-points) and `internal/api`
    # equivalents.
    dir_names = raw_signals.get("top_directory_names") or {}
    if isinstance(dir_names, dict):
        keys = set(dir_names.keys())
    elif isinstance(dir_names, list):
        keys = set(dir_names)
    else:
        keys = set()
    api_surface = {
        "api", "apis", "routes", "route",
        "controllers", "controller",
        "handlers", "handler",  # Go convention is the singular form
        "endpoints", "endpoint",
        "rest", "rpc",
        # Go-specific entry-point conventions: `cmd/<binary>/main.go`
        # for each service binary; `app` is the common app-init
        # package name in chi / gin projects.
        "cmd", "app",
        # JVM-ish:
        "resources",
        # Django:
        "views", "viewsets",
    }
    matched_surface = api_surface & keys
    if not matched_surface:
        return None
    surface = ", ".join(sorted(matched_surface))
    return f"HTTP framework dep {fw_hit!r} + surface dirs ({surface})"


def _backstop_server_side_injection(
    raw_signals: dict, fingerprint: dict,
) -> str | None:
    """Fire when the repo handles SQL / shell / template execution.

    A Go/Python/Node app with database access + raw query helpers,
    shell-exec helpers, or template-render helpers has a real
    server-side injection surface that's worth a focused review even
    when no specific semgrep rule has fired yet. The skill is the
    one looking for actually-vulnerable usage, not the backstop.
    """
    deps = _all_dependency_names(raw_signals)
    # Database deps. Each marker is chosen long enough to avoid
    # substring collisions (e.g. plain "pg" would also match
    # `pgpassfile`, `pgproto3`, etc.; we use `jackc/pgx` /
    # `node-pg` instead).
    db_markers = (
        # Node — use full canonical package names
        "mysql2", "sqlite3", "mongodb", "mongoose",
        "sequelize", "typeorm", "prisma", "mikro-orm", "knex",
        "node-postgres", "/pg ", "==pg",   # `pg` is Node's Postgres pkg; we check the name pattern in `_has_marker_dep`
        # Python
        "psycopg2", "psycopg", "sqlalchemy", "asyncpg", "aiomysql",
        "pymongo", "peewee", "django.db",
        # Go — use scoped paths to avoid pg/pgx-* substring noise
        "database/sql", "lib/pq", "go-sql-driver/mysql",
        "jackc/pgx", "go-mongo-driver", "gorm.io/gorm",
        "jmoiron/sqlx", "uptrace/bun",
        # Ruby/Rails
        "activerecord",
        # JVM
        "jdbi", "hibernate-core", "spring-jdbc",
    )
    db_hit = _has_marker_dep(deps, db_markers)
    if db_hit:
        return f"database dep {db_hit!r} present (raw-SQL injection surface)"
    # Template engines (server-side template injection).
    tpl_markers = (
        "jinja2", "django-template", "twig", "handlebars",
        "pug", "ejs", "nunjucks", "mustache", "html/template",
        "text/template", "erubis", "haml",
    )
    tpl_hit = _has_marker_dep(deps, tpl_markers)
    if tpl_hit:
        return f"template engine dep {tpl_hit!r} (SSTI surface)"
    return None


def _backstop_business_logic(
    raw_signals: dict, fingerprint: dict,
) -> str | None:
    """Fire when the repo has the markers of a multi-step app with
    state transitions, queues, or workflows.

    The audit family that looks at idempotency, TOCTOU races on shared
    state, missing dedup, and compensating-action gaps. The salazar
    audit missed this family for a Go microservice platform that very
    much has these properties — fingerprint Claude does not always
    elect business-logic even when the evidence is plain.
    """
    dir_names = raw_signals.get("top_directory_names") or {}
    if isinstance(dir_names, dict):
        keys = set(dir_names.keys())
    elif isinstance(dir_names, list):
        keys = set(dir_names)
    else:
        keys = set()
    # Queues / async workers / scheduled tasks are the canonical
    # business-logic surface (state transitions outside the request
    # lifecycle).
    workflow_dirs = {
        "tasks", "task", "queues", "queue", "workers", "worker",
        "jobs", "job", "processors", "processor", "scheduler",
        "commands", "command",       # CQRS-style command handlers
        "events", "event", "domain", # event-sourcing / DDD layouts
        "service", "services",
        "workflows", "workflow",
    }
    matched = workflow_dirs & keys
    if not matched:
        return None
    # We also want HTTP surface or auth surface present — pure-cron
    # batch tools without an HTTP surface aren't business-logic
    # candidates (no actors, no state transitions over user input).
    deps = _all_dependency_names(raw_signals)
    fw_hit = _has_marker_dep(deps, _HTTP_FRAMEWORK_DEP_MARKERS)
    auth_hit = _has_marker_dep(deps, _CRYPTO_AUTH_DEP_MARKERS)
    if not (fw_hit or auth_hit):
        return None
    surface = ", ".join(sorted(matched))
    return (
        f"workflow surface dirs ({surface}) + "
        f"{'http=' + repr(fw_hit) if fw_hit else 'auth=' + repr(auth_hit)}"
    )


def _backstop_supply_chain(
    raw_signals: dict, fingerprint: dict,
) -> str | None:
    """Fire when the repo ships an installable artefact.

    Triggers:
    - a non-private package.json (Node packages users can install)
    - any manifest with > 50 declared deps (large dependency surface
      worth a focused review even for non-library apps)
    - presence of `.github/workflows/release*` or `publish*` (not yet
      visible in raw-signals; deferred)
    """
    pm = raw_signals.get("package_metadata") or {}
    for manifest_list in pm.values():
        if not isinstance(manifest_list, list):
            continue
        for entry in manifest_list:
            if not isinstance(entry, dict):
                continue
            if entry.get("private") is False:
                return "package manifest is not marked private (publishable)"
            deps = entry.get("dependencies") or {}
            n = len(deps) if isinstance(deps, (dict, list)) else 0
            if n > 50:
                path = entry.get("path") or "manifest"
                return f"{path} has {n} dependencies (large supply-chain surface)"
    return None


def _backstop_config_deployment(
    raw_signals: dict, fingerprint: dict,
) -> str | None:
    """Fire when the repo ships deployment artefacts."""
    manifests = raw_signals.get("manifest_files") or []
    found = [m for m in manifests if isinstance(m, str) and any(
        m.endswith(marker) or m == marker
        for marker in _DEPLOYMENT_FILE_MARKERS
    )]
    if found:
        return f"deployment artefacts present: {', '.join(found[:3])}"
    return None


_BACKSTOP_RULES: tuple[tuple[str, callable], ...] = (
    ("audit/crypto-auth",            _backstop_crypto_auth),
    ("audit/input-validation",       _backstop_input_validation),
    ("audit/server-side-injection",  _backstop_server_side_injection),
    ("audit/business-logic",         _backstop_business_logic),
    ("audit/supply-chain",           _backstop_supply_chain),
    ("audit/config-deployment",      _backstop_config_deployment),
)


def _apply_audit_backstop(
    packs: list[str],
    raw_signals: dict,
    fingerprint: dict,
) -> tuple[list[str], list[tuple[str, str]]]:
    """Return ``(augmented_packs, added_with_reasons)``.

    The original order of ``packs`` is preserved; backstop additions are
    appended at the end so the fingerprint's own picks stay at the
    head of the cap window.
    """
    existing = set(packs)
    additions: list[tuple[str, str]] = []
    out = list(packs)
    for pack, rule in _BACKSTOP_RULES:
        if pack in existing:
            continue
        try:
            reason = rule(raw_signals, fingerprint)
        except Exception:  # noqa: BLE001 — backstop must never crash
            continue
        if reason:
            out.append(pack)
            existing.add(pack)
            additions.append((pack, reason))
    return out, additions


def _route_packs(fingerprint: dict, raw_signals: dict | None = None) -> dict:
    """Pure transform: fingerprint dict → routing dict. Deterministic.

    When ``raw_signals`` is provided, the deterministic backstop runs
    before deduplication and capping. Older callers that pass only the
    fingerprint still work — the backstop is silently skipped.
    """
    raw_packs = fingerprint.get("suggested_packs")
    if not isinstance(raw_packs, list):
        raw_packs = []
    # Apply backstop FIRST so backstop additions count toward dedup +
    # cap arithmetic. Reasons are returned in the routing dict so the
    # cmd_route_packs writer can render them.
    backstop_additions: list[tuple[str, str]] = []
    if raw_signals is not None:
        raw_packs, backstop_additions = _apply_audit_backstop(
            [p for p in raw_packs if isinstance(p, str)],
            raw_signals,
            fingerprint,
        )
    raw_modes = fingerprint.get("suggested_modes")
    if not isinstance(raw_modes, list):
        raw_modes = []

    # Deduplicate preserving order; drop non-strings defensively.
    seen: set[str] = set()
    deduped: list[str] = []
    dropped_duplicates = 0
    for p in raw_packs:
        if not isinstance(p, str):
            continue
        if p in seen:
            dropped_duplicates += 1
            continue
        seen.add(p)
        deduped.append(p)

    # Split by prefix; preserve order within each bucket.
    by_category: dict[str, list[str]] = {
        "language": [],
        "domain":   [],
        "protocol": [],
        "audit":    [],
        "other":    [],
    }
    for p in deduped:
        by_category[_classify_pack(p)].append(p)

    # Cap audit/ at MAX_AUDIT_PACKS, preserving order from the head.
    dropped_audit = 0
    if len(by_category["audit"]) > MAX_AUDIT_PACKS:
        dropped_audit = len(by_category["audit"]) - MAX_AUDIT_PACKS
        by_category["audit"] = by_category["audit"][:MAX_AUDIT_PACKS]

    # Copy modes verbatim; keep only string entries.
    recommended_modes = [m for m in raw_modes if isinstance(m, str)]

    # Cap can have removed some backstop additions; only surface the
    # backstop entries that survived the cut.
    surviving_audit = set(by_category["audit"])
    surviving_backstop = [
        {"pack": pack, "reason": reason}
        for (pack, reason) in backstop_additions
        if pack in surviving_audit
    ]

    return {
        "selected_packs":      by_category,
        "recommended_modes":   recommended_modes,
        "dropped_duplicates":  dropped_duplicates,
        "dropped_audit":       dropped_audit,
        "total_unique_packs":  len(deduped),
        "backstop_additions":  surviving_backstop,
    }


def _render_next_steps_md(repo_name: str, selected: dict) -> str:
    lines: list[str] = []
    out = lines.append

    packs = selected["selected_packs"]
    modes = selected["recommended_modes"]

    out(f"# Audit next steps — {repo_name}")
    out("")
    out("## Recommended mode")
    out("")
    if modes:
        for m in modes:
            display = MODE_DISPLAY_NAMES.get(m, m)
            out(f"- `{m}` ({display})")
    else:
        out("_(none specified by the fingerprint)_")
    if "both" in modes:
        out("")
        out("Both Packet Mode and Research Trail Mode may apply.")

    sections = [
        ("Language",       "language"),
        ("Domain",         "domain"),
        ("Protocol",       "protocol"),
        ("Audit families", "audit"),
    ]
    backstop = selected.get("backstop_additions") or []
    backstop_lookup = {b["pack"]: b["reason"] for b in backstop}
    for title, key in sections:
        items = packs.get(key, [])
        out("")
        out(f"## {title}")
        out("")
        if items:
            for it in items:
                if it in backstop_lookup:
                    out(f"- `{it}` *(backstop: {backstop_lookup[it]})*")
                else:
                    out(f"- `{it}`")
        else:
            out("_(none)_")

    other = packs.get("other", [])
    if other:
        out("")
        out("## Other")
        out("")
        for it in other:
            out(f"- `{it}`")

    out("")
    out("## Notes")
    out("")
    out("No scanning or audit has been run yet.")
    if backstop:
        out("")
        out(
            f"The deterministic backstop added {len(backstop)} audit "
            f"families the fingerprint missed (see asterisked items above)."
        )

    return "\n".join(lines) + "\n"


def cmd_route_packs(repo_path_str: str) -> int:
    repo_path = Path(repo_path_str).expanduser()
    if not repo_path.exists():
        print(f"error: path does not exist: {repo_path}", file=sys.stderr)
        return 2
    if not repo_path.is_dir():
        print(f"error: not a directory: {repo_path}", file=sys.stderr)
        return 2

    fingerprint_path = (
        repo_path.resolve() / ".audit" / "00-fingerprint" / "fingerprint.json"
    )
    if not fingerprint_path.is_file():
        print(
            f"error: required input is missing: {fingerprint_path}\n"
            f"       run 'sra fingerprint' first.",
            file=sys.stderr,
        )
        return 2

    try:
        raw_text = fingerprint_path.read_text(encoding="utf-8")
    except OSError as e:
        print(
            f"error: could not read {fingerprint_path}: {e}",
            file=sys.stderr,
        )
        return 2

    try:
        fingerprint = json.loads(raw_text)
    except json.JSONDecodeError as e:
        print(
            f"error: {fingerprint_path} is not valid JSON: {e}",
            file=sys.stderr,
        )
        return 6

    if not isinstance(fingerprint, dict):
        print(
            f"error: {fingerprint_path} top-level value is not a JSON object",
            file=sys.stderr,
        )
        return 6

    # Best-effort load of raw-signals.json so the deterministic backstop
    # has access to dep lists / manifests / dir signals. We don't fail
    # the command if raw-signals.json is missing — older audit runs
    # predate the backstop; they just won't get its additions.
    raw_signals: dict | None = None
    raw_signals_path = (
        repo_path.resolve() / ".audit" / "00-fingerprint" / "raw-signals.json"
    )
    if raw_signals_path.is_file():
        try:
            rs = json.loads(raw_signals_path.read_text(encoding="utf-8"))
            if isinstance(rs, dict):
                raw_signals = rs
        except (OSError, json.JSONDecodeError):
            pass

    routed = _route_packs(fingerprint, raw_signals=raw_signals)

    output_dir = repo_path.resolve() / ".audit" / "01-pack-router"
    output_dir.mkdir(parents=True, exist_ok=True)

    notes: list[str] = []
    if routed["dropped_duplicates"]:
        notes.append(
            f"Deduplicated {routed['dropped_duplicates']} repeated pack "
            f"entries."
        )
    if routed["dropped_audit"]:
        notes.append(
            f"Capped audit/ packs to {MAX_AUDIT_PACKS}; dropped "
            f"{routed['dropped_audit']} entries from the tail."
        )
    backstop = routed.get("backstop_additions") or []
    if backstop:
        notes.append(
            f"Deterministic backstop added {len(backstop)} audit "
            f"family/families that the fingerprint missed."
        )
    notes.append(
        f"Carried {routed['total_unique_packs']} unique packs from "
        f"fingerprint."
    )
    notes.append("No scanning or audit has been run yet.")

    selected = {
        "schema_version":          1,
        "repo_path":               posix(repo_path.resolve()),
        "source_fingerprint_path": posix(fingerprint_path),
        "recommended_modes":       routed["recommended_modes"],
        "selected_packs":          routed["selected_packs"],
        "backstop_additions":      backstop,
        "notes":                   notes,
    }

    json_path = output_dir / "selected-packs.json"
    md_path   = output_dir / "next-steps.md"

    json_path.write_text(
        json.dumps(selected, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    md_path.write_text(
        _render_next_steps_md(repo_path.resolve().name, selected),
        encoding="utf-8",
    )

    print(f"sra: wrote {posix(json_path)}", file=sys.stderr)
    print(f"sra: wrote {posix(md_path)}", file=sys.stderr)
    return 0


# --- Plan command -----------------------------------------------------------

# Family → workflow mode mapping. Matches docs/pack-router-v0.md and
# docs/family-workflow-map-v0.md.
FAMILY_TO_MODE: dict[str, str] = {
    "audit/access-control":        "packet",
    "audit/input-validation":      "packet",
    "audit/client-side":           "packet",
    "audit/server-side-injection": "packet",
    "audit/file-boundary":         "packet",
    "audit/supply-chain":          "packet",
    "audit/business-logic":        "packet",
    "audit/config-deployment":     "packet",
    "audit/network-protocol":      "research_trail",
    "audit/parser-state-machine":  "research_trail",
    "audit/memory-safety":         "research_trail",
    "audit/crypto-auth":           "research_trail",
    "audit/concurrency-race":      "research_trail",
}

# Allowed sensor / tool identifiers. The plan must use only these.
ALLOWED_SENSORS: frozenset[str] = frozenset({
    "semgrep", "codeql", "joern", "ast-grep", "ripgrep", "manual-review",
})

# Per-family sensor recommendations and first review questions. Mirrors
# docs/family-workflow-map-v0.md.
FAMILY_PLAN: dict[str, dict] = {
    "audit/access-control": {
        "suggested_sensors": ["semgrep", "codeql", "ast-grep", "manual-review"],
        "first_questions": [
            "Does every route that touches a per-user or per-tenant resource verify ownership before reading or writing it?",
            "Are there admin-only or privileged routes that lack a role or scope check?",
            "Where is the user identity read from — the session, a verified token, or the request body?",
            "Are there bypass paths (debug routes, internal APIs, batch endpoints) that skip the standard auth middleware?",
        ],
    },
    "audit/input-validation": {
        "suggested_sensors": ["semgrep", "codeql", "ast-grep", "manual-review"],
        "first_questions": [
            "What schema or type validation is applied at each public boundary?",
            "Are there code paths that consume request fields without going through the validator?",
            "Are validators applied consistently across HTTP, WebSocket, background-job, and CLI entry points?",
            "How are optional and unknown fields handled?",
        ],
    },
    "audit/client-side": {
        "suggested_sensors": ["semgrep", "codeql", "ast-grep", "ripgrep", "manual-review"],
        "first_questions": [
            "Where does user-supplied content flow into an HTML or DOM sink?",
            "What sanitiser / escaping library is in use, and is it applied at every render path?",
            "Are there bypass APIs (`v-html`, `innerHTML`, framework escape hatches) used in production code, and what flows into them?",
            "Are URLs used in `href` / `src` validated against `javascript:` and other dangerous schemes?",
        ],
    },
    "audit/server-side-injection": {
        "suggested_sensors": ["semgrep", "codeql", "ast-grep", "ripgrep", "manual-review"],
        "first_questions": [
            "Is server-side template rendering ever invoked with user-supplied template strings (as opposed to user-supplied data in a fixed template)?",
            "Where are shell commands constructed, and what input flows into them?",
            "Are there raw query APIs in use alongside the project's ORM?",
            "Is there dynamic code execution (eval, dynamic require / import, expression evaluation) reachable from request input?",
        ],
    },
    "audit/file-boundary": {
        "suggested_sensors": ["semgrep", "codeql", "ast-grep", "manual-review"],
        "first_questions": [
            "How are user-supplied filenames sanitised before being used as paths? Is a rooted-path / containment check applied?",
            "What file types are accepted on upload, and how is the accepted set enforced (extension, content-type, magic bytes)?",
            "Are archive extractions guarded against symlinks, absolute paths, and `..` traversal (zip-slip)?",
            "What size and rate limits apply to uploads and to archive expansion?",
        ],
    },
    "audit/network-protocol": {
        "suggested_sensors": ["codeql", "joern", "ripgrep", "manual-review"],
        "first_questions": [
            "How is the boundary of a request determined — by `Content-Length`, `Transfer-Encoding`, or both — and what happens when they disagree?",
            "At which layer is header normalisation done, and do all consumers see the same normalised view?",
            "How are upstream and downstream connections reused, and is request state cleaned between reuses?",
            "Are there cross-version translation paths (HTTP / 1 ↔ HTTP / 2 ↔ HTTP / 3)? How is request framing preserved?",
        ],
    },
    "audit/parser-state-machine": {
        "suggested_sensors": ["codeql", "joern", "ast-grep", "manual-review"],
        "first_questions": [
            "What are the defined states and transitions, and is every transition explicitly handled or rejected?",
            "Are there places where the parser can return data while in a partial / intermediate state?",
            "How are errors propagated mid-transition — does the state revert, advance, or remain ambiguous?",
            "What happens on early disconnect or short-read at each state?",
        ],
    },
    "audit/memory-safety": {
        "suggested_sensors": ["codeql", "joern", "semgrep", "manual-review"],
        "first_questions": [
            "Where are buffer sizes derived from external input, and is the arithmetic overflow-checked?",
            "Are there ownership / lifetime patterns where a use-after-free is possible across object close / reuse?",
            "At FFI boundaries, who owns the memory, and on what side is it freed?",
            "Are there `unsafe` blocks (Rust) or unchecked casts (C / C++) on data flowing in from the network?",
        ],
    },
    "audit/crypto-auth": {
        "suggested_sensors": ["semgrep", "codeql", "ripgrep", "manual-review"],
        "first_questions": [
            "What cipher suites, KDFs, and signature algorithms are configured, and how were the defaults chosen?",
            "Where is signature verification performed, and are there early-return / fail-open paths?",
            "Is there an RNG in use that should be cryptographically secure (key generation, nonces, session IDs)? How is it seeded?",
            "Are sensitive comparisons (HMAC, token equality) done in constant time?",
        ],
    },
    "audit/supply-chain": {
        "suggested_sensors": ["ripgrep", "semgrep", "manual-review"],
        "first_questions": [
            "What does each install or post-install hook actually do?",
            "Is the dependency set pinned (lockfile present and committed) or floating?",
            "Do release workflows verify artefact integrity (checksums, signatures, attestations)?",
            "Are any secrets used by release workflows scoped to a single workflow / branch?",
        ],
    },
    "audit/business-logic": {
        "suggested_sensors": ["ast-grep", "semgrep", "manual-review"],
        "first_questions": [
            "What state transitions are guarded, and what are the preconditions for each?",
            "Where is double-submit and concurrent-request protection (idempotency keys, optimistic locks)?",
            "What invariants must hold across a multi-step flow, and what enforces them on partial completion?",
            "Are there compensating actions (refund, rollback) on workflow failure, and are they idempotent?",
        ],
    },
    "audit/concurrency-race": {
        "suggested_sensors": ["codeql", "joern", "semgrep", "manual-review"],
        "first_questions": [
            "What shared mutable state exists, and what guards it on read and on write?",
            "Are there time-of-check / time-of-use windows in authorisation or ownership checks?",
            "Where can two requests, two threads, or two processes race on the same record (double-spend, double-publish, etc.)?",
            "Are signal handlers or async cancellation paths safe against partially-applied work?",
        ],
    },
    "audit/config-deployment": {
        "suggested_sensors": ["semgrep", "ripgrep", "manual-review"],
        "first_questions": [
            "What user, capabilities, and exposed ports are set for each container? Is the default user non-root?",
            "Are debug, test, or development settings shipped in the production defaults (debug flags, permissive CORS, open admin endpoints)?",
            "Are secrets committed in defaults, sample configs, or environment-file templates?",
            "How is the metadata service (cloud / k8s) reachable from application containers, and is it intended?",
        ],
    },
}


def _build_audit_plan(selected: dict) -> dict:
    """Pure transform from selected-packs dict to plan dict. Deterministic.

    Note on consumption: the resulting `audit-plan.json` is **informational
    only** — downstream stages do NOT read its `workflow_mode`,
    `suggested_sensors`, or `first_questions` fields. The actual audit
    pipeline (cmd_audit) always runs in packet mode and uses whichever
    sensors the caller passes via `--sensor` (default: all three).
    The plan file exists as a human-readable summary of what WOULD be
    suggested, plus a resumability checkpoint marker. See `next-steps.md`
    for the practical CLI users care about.
    """
    selected_packs = selected.get("selected_packs")
    if not isinstance(selected_packs, dict):
        selected_packs = {}

    audit_in = selected_packs.get("audit")
    if not isinstance(audit_in, list):
        audit_in = []

    items: list[dict] = []
    skipped_unknown: list[str] = []
    seen: set[str] = set()

    for fam in audit_in:
        if not isinstance(fam, str):
            continue
        if fam in seen:
            continue
        seen.add(fam)
        if fam not in FAMILY_TO_MODE or fam not in FAMILY_PLAN:
            skipped_unknown.append(fam)
            continue
        plan_entry = FAMILY_PLAN[fam]
        # Defensively filter sensors to the allow-list.
        sensors = [
            s for s in plan_entry["suggested_sensors"] if s in ALLOWED_SENSORS
        ]
        items.append({
            "family":            fam,
            "workflow_mode":     FAMILY_TO_MODE[fam],
            "suggested_sensors": sensors,
            "first_questions":   list(plan_entry["first_questions"]),
        })

    return {
        "audit_plan":               items,
        "skipped_unknown_families": skipped_unknown,
    }


def _render_audit_plan_md(
    repo_name: str,
    recommended_modes: list[str],
    plan: dict,
) -> str:
    lines: list[str] = []
    out = lines.append

    items   = plan["audit_plan"]
    unknown = plan["skipped_unknown_families"]

    out(f"# Audit plan — {repo_name}")
    out("")

    out("## Recommended workflow modes")
    out("")
    if recommended_modes:
        for m in recommended_modes:
            display = MODE_DISPLAY_NAMES.get(m, m)
            out(f"- `{m}` ({display})")
    else:
        out("_(none carried from selected-packs.json)_")

    out("")
    out("## Audit families")
    out("")
    if not items:
        out(
            "_(no audit families to plan; selected-packs.json had none "
            "mapped to v0 families)_"
        )
    else:
        for it in items:
            mode_display = MODE_DISPLAY_NAMES.get(
                it["workflow_mode"], it["workflow_mode"]
            )
            out(
                f"### `{it['family']}` — {mode_display} "
                f"(`{it['workflow_mode']}`)"
            )
            out("")
            out("**Suggested sensors / tools:**")
            out("")
            for s in it["suggested_sensors"]:
                out(f"- `{s}`")
            out("")
            out("**First review questions:**")
            out("")
            for q in it["first_questions"]:
                out(f"- {q}")
            out("")

    if unknown:
        out("## Skipped (no v0 mapping)")
        out("")
        for u in unknown:
            out(f"- `{u}`")
        out("")

    out("## Notes")
    out("")
    out(
        "- This plan was generated deterministically from "
        "selected-packs.json. No scanner has been run, and no specific "
        "vulnerability class has been investigated."
    )
    out(
        "- Suggested sensors are guidance, not a contract. The next-phase "
        "workflow is free to pick a subset based on local availability and "
        "language coverage."
    )
    out(
        "- `manual-review` appears under every family because no static-tool "
        "combination currently substitutes for a human reading the code."
    )

    return "\n".join(lines) + "\n"


def cmd_plan(repo_path_str: str) -> int:
    repo_path = Path(repo_path_str).expanduser()
    if not repo_path.exists():
        print(f"error: path does not exist: {repo_path}", file=sys.stderr)
        return 2
    if not repo_path.is_dir():
        print(f"error: not a directory: {repo_path}", file=sys.stderr)
        return 2

    selected_path = (
        repo_path.resolve() / ".audit" / "01-pack-router" / "selected-packs.json"
    )
    if not selected_path.is_file():
        print(
            f"error: required input is missing: {selected_path}\n"
            f"       run 'sra route-packs' first.",
            file=sys.stderr,
        )
        return 2

    try:
        raw_text = selected_path.read_text(encoding="utf-8")
    except OSError as e:
        print(
            f"error: could not read {selected_path}: {e}",
            file=sys.stderr,
        )
        return 2

    try:
        selected = json.loads(raw_text)
    except json.JSONDecodeError as e:
        print(
            f"error: {selected_path} is not valid JSON: {e}",
            file=sys.stderr,
        )
        return 6

    if not isinstance(selected, dict):
        print(
            f"error: {selected_path} top-level value is not a JSON object",
            file=sys.stderr,
        )
        return 6

    # Recommended modes pass through verbatim, filtered to strings.
    recommended_modes_raw = selected.get("recommended_modes")
    if not isinstance(recommended_modes_raw, list):
        recommended_modes_raw = []
    recommended_modes = [m for m in recommended_modes_raw if isinstance(m, str)]

    plan = _build_audit_plan(selected)

    output_dir = repo_path.resolve() / ".audit" / "02-plan"
    output_dir.mkdir(parents=True, exist_ok=True)

    notes: list[str] = []
    if plan["skipped_unknown_families"]:
        notes.append(
            f"Skipped {len(plan['skipped_unknown_families'])} unknown audit "
            f"families (no v0 mapping)."
        )
    notes.append(
        f"Planned {len(plan['audit_plan'])} audit families from "
        f"selected-packs.json."
    )
    notes.append(
        "No scanner has been run; no specific vulnerability class has been "
        "investigated."
    )

    output_doc = {
        "schema_version":             1,
        "repo_path":                  posix(repo_path.resolve()),
        "source_selected_packs_path": posix(selected_path),
        "recommended_modes":          recommended_modes,
        "audit_plan":                 plan["audit_plan"],
        "skipped_unknown_families":   plan["skipped_unknown_families"],
        "notes":                      notes,
    }

    json_path = output_dir / "audit-plan.json"
    md_path   = output_dir / "audit-plan.md"

    json_path.write_text(
        json.dumps(output_doc, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    md_path.write_text(
        _render_audit_plan_md(
            repo_path.resolve().name,
            recommended_modes,
            plan,
        ),
        encoding="utf-8",
    )

    print(f"sra: wrote {posix(json_path)}", file=sys.stderr)
    print(f"sra: wrote {posix(md_path)}", file=sys.stderr)
    return 0


# --- Collect-evidence: audit/input-validation -------------------------------

EVIDENCE_FAMILY_INPUT_VALIDATION = "audit/input-validation"
EVIDENCE_SUPPORTED_FAMILIES = frozenset({EVIDENCE_FAMILY_INPUT_VALIDATION})

# Output budget — keeps the JSON / Markdown manageable to read.
MAX_CANDIDATES_PER_CATEGORY  = 50
MAX_HITS_PER_PATTERN_PER_FILE = 5
MAX_EVIDENCE_FILE_BYTES      = 256 * 1024
MAX_EVIDENCE_CONTEXT_CHARS   = 200

# Path-role classification. Each candidate gets a `role` derived from
# tokens in its path. Roles are mutually exclusive — when multiple
# tokens match, role priority below resolves the tie.
ROLE_TOKEN_SETS: dict[str, frozenset[str]] = {
    "test":                frozenset({
        "test", "tests", "spec", "specs", "fixtures", "fixture",
    }),
    "example":             frozenset({
        "example", "examples", "demo", "demos", "sample", "samples",
    }),
    "docs":                frozenset({
        "docs", "doc", "documentation",
    }),
    "generated_or_vendor": frozenset({
        "node_modules", "vendor", "vendored",
        "dist", "build", "target", "out",
        "coverage", "generated", "gen",
    }),
}

# When a path matches more than one role, the first match in this
# tuple wins. Vendor / generated comes first so a "tests" directory
# inside `node_modules/` is still classed as generated. Test wins
# over example because tests-of-an-example and examples-in-tests
# are both more honestly "tests".
ROLE_PRIORITY: tuple[str, ...] = (
    "generated_or_vendor", "test", "example", "docs",
)

# Order in which roles are rendered as subsections in evidence.md.
# Production first, then example, then test, then the rest.
ROLE_RENDER_ORDER: tuple[str, ...] = (
    "production", "example", "test", "docs", "generated_or_vendor",
)

# Static guidance recorded in evidence.json telling a downstream packet
# assembler which roles to prefer / demote when composing a packet for
# this family. The evidence stage itself does NOT build packets — this
# field is only a hint for the next stage.
PACKET_GENERATION_HINTS: dict = {
    "preferred_roles":     ["production"],
    "secondary_roles":     ["example"],
    "deprioritized_roles": ["test", "docs", "generated_or_vendor"],
    "notes": [
        "Use production evidence first when building packets.",
        "Use examples as behavioral context.",
        "Use tests mainly to understand intended behavior, not as "
        "primary audit targets.",
    ],
}

_ROLE_TOKEN_SPLIT_RE = re.compile(r"[._\-]+")


def _classify_path_role(path: str) -> str:
    """Classify a posix-style path into one of the five role labels.

    Splits on '/' and on token separators (`.`, `-`, `_`) so a path
    like `__tests__/foo.test.js` produces tokens that match `tests`
    and `test`, while `latest.js` does NOT match either.
    """
    if not path or path == ".":
        return "production"
    norm = path.replace("\\", "/").lower()
    tokens: set[str] = set()
    for seg in norm.split("/"):
        if not seg:
            continue
        tokens.add(seg)
        for t in _ROLE_TOKEN_SPLIT_RE.split(seg):
            if t:
                tokens.add(t)
    for role in ROLE_PRIORITY:
        if tokens & ROLE_TOKEN_SETS[role]:
            return role
    return "production"

# === Sensor layer (vertical-slice scaffolding) ===============================
#
# The heuristic evidence collector (`cmd_collect_evidence`) and the heuristic
# packet builder (`cmd_build_packets`) above are intentionally kept; they
# remain useful as a deterministic baseline and as a comparison artefact.
#
# `cmd_run_sensor` and `cmd_build_packets_from_sensors` below implement the
# sensor-first path the project pivoted to in project-state.md §9: instead of
# generating packets from filename/token heuristics, run a real sensor
# (ripgrep first, semgrep next) against the target repo, then cluster the
# sensor hits into packets that a Claude skill will investigate.

SENSOR_SUPPORTED_FAMILIES: frozenset[str] = frozenset({
    "audit/input-validation",
    "audit/memory-safety",
    "audit/supply-chain",
    "audit/file-boundary",
    "audit/parser-state-machine",
    "audit/network-protocol",
    "audit/crypto-auth",
    "audit/config-deployment",
    "audit/concurrency-race",
    "audit/access-control",
    "audit/server-side-injection",
    "audit/client-side",
    "audit/business-logic",
    # Phase 5: new family categories. `audit/firebase-mobile` stays opt-in
    # only (registered in the skill registry but NOT in the supported set,
    # so the fingerprint never auto-elects it).
    "audit/agentic-ai",
    "audit/smart-contracts",
})

SENSOR_SUPPORTED_SENSORS: frozenset[str] = frozenset({
    "ripgrep",
    "semgrep",
    "ast-grep",
})

# Per-cluster sensor-packet caps. Kept smaller than the heuristic builder's
# caps because sensor hits are denser per file.
MAX_SENSOR_HITS_PER_SECTION = 40
MAX_SENSOR_FILES_PER_CLUSTER = 20
# Packet cap is **adaptive** by repo size (see `_adaptive_packet_cap`).
# These constants define the linear schedule:
#
#     cap = min(BASE + (file_count // STEP) * STEP_INCREMENT, CEILING)
#
# Tuning rationale based on h2o empirical demo (250K LOC, 7422 files):
# - 30 (BASE) on small repos preserves the long-standing default for
#   tiny webapp / library / CLI codebases (~ < 1000 files).
# - +5 per 1000 files climbs gently — on salazar (803 files) cap stays
#   at 30; on h2o (7422 files) cap rises to ~65, recovering ~24 of the
#   89 clusters the static cap of 30 was dropping; on a Linux-kernel-
#   sized repo (~50K files) cap saturates at 80.
# - 80 (CEILING) is a hard upper bound on per-family LLM cost. Even on
#   mega-codebases we refuse to spawn more than 80 packets per family
#   per audit run; the alternative is unbounded LLM spend.
#
# `MAX_SENSOR_PACKETS_PER_REPO` is preserved as the BASE for backward
# compatibility — callers that read the constant directly continue to
# get the small-repo default.
MAX_SENSOR_PACKETS_PER_REPO = 30                      # BASE
MAX_SENSOR_PACKETS_CEILING:        int = 80           # absolute upper bound
MAX_SENSOR_PACKETS_FILES_PER_STEP: int = 1000         # files per scaling step
MAX_SENSOR_PACKETS_STEP_INCREMENT: int = 5            # packets added per step


def _fold_micro_clusters(
    clusters: list[dict],
    *,
    min_hits: int = 10,
) -> list[dict]:
    """Merge micro clusters into their nearest sibling.

    The packet builder's primary clustering step is ``(parent_dir, role)``.
    On deep package layouts (Java enterprise, Spring/Tomcat) this
    over-fragments: every ``java/org/apache/tomcat/util/X/Y/Z`` becomes
    a separate cluster, frequently with only 1-3 sensor hits. Each
    micro-cluster then triggers a full claude-skill invocation,
    wasting LLM cost for trivially small evidence.

    Empirical (98 packet-indexes across repo_a1 + tomcat + h2o +
    salazar + outline corpus, ``scripts/simulate_cluster_fold_corpus.py``):
    folding micros at ``min_hits=10`` reduces packet count by ~25%
    globally, zero data loss (hit sum preserved), zero pathological
    inflations of the host cluster's hit_count (worst case +38 on
    tomcat concurrency-race).

    Algorithm:

    1. Split clusters into ``big`` (``hit_count >= min_hits``) and
       ``micro`` (``hit_count < min_hits``).
    2. For each micro: find the big cluster with the **longest
       common ancestor directory path** AND the same ``primary_role``.
    3. If the common ancestor has at least 2 path components,
       MERGE the micro into the big: combine ``hits`` lists,
       deduplicate ``files``, sum ``hit_count`` / ``raw_hit_count`` /
       ``total_consensus``, and record the merge in the host's
       ``folded_in`` list (for attribution).
    4. If no sibling exists (no big cluster shares ≥2 path components
       AND the same role), the micro stays as an **orphan** — it
       continues to its own packet. No data is ever dropped.

    Preserves all existing cluster fields. Adds ``folded_in`` to any
    big cluster that absorbed at least one micro. Orphans get
    ``folded_in = []`` for schema consistency.
    """
    if min_hits <= 0:
        # Defensive: disabled
        return [{**c, "folded_in": []} for c in clusters]

    big   = [c for c in clusters if c["hit_count"] >= min_hits]
    micro = [c for c in clusters if c["hit_count"] <  min_hits]

    # Index big clusters by role for fast sibling lookup.
    big_by_role: dict[str, list[dict]] = {}
    for b in big:
        big_by_role.setdefault(b["role"], []).append(b)

    # Working copies so we don't mutate caller's clusters.
    merged: dict[int, dict] = {}  # id(b) -> shallow copy of b with folded_in
    for b in big:
        merged[id(b)] = {
            **b,
            "hits":          list(b["hits"]),
            "files":         list(b["files"]),
            "folded_in":     [],
        }

    def _common_ancestor_components(a: str, b: str) -> int:
        pa = a.split("/")
        pb = b.split("/")
        n = 0
        for x, y in zip(pa, pb):
            if x == y:
                n += 1
            else:
                break
        return n

    orphans: list[dict] = []
    for m in micro:
        candidates = big_by_role.get(m["role"], [])
        if not candidates:
            orphans.append({**m, "folded_in": []})
            continue
        # Find the candidate with the longest common ancestor path.
        best, best_depth = None, 0
        for b in candidates:
            depth = _common_ancestor_components(m["directory"], b["directory"])
            if depth > best_depth:
                best_depth = depth
                best = b
        # Require >=2 common path components so we don't fold
        # cross-area micros (e.g. `lib/foo` into `tests/bar`).
        if best is None or best_depth < 2:
            orphans.append({**m, "folded_in": []})
            continue

        host = merged[id(best)]
        # Merge: extend hits, dedupe files, sum counts.
        host["hits"].extend(m["hits"])
        existing_files = set(host["files"])
        for f in m["files"]:
            if f not in existing_files:
                host["files"].append(f)
                existing_files.add(f)
        host["hit_count"]       += m["hit_count"]
        host["file_count"]      = len(host["files"])
        host["raw_hit_count"]   = host.get("raw_hit_count", host["hit_count"]) \
                                  + m.get("raw_hit_count", m["hit_count"])
        host["total_consensus"] = host.get("total_consensus", 0) \
                                  + m.get("total_consensus", 0)
        host["folded_in"].append({
            "directory":       m["directory"],
            "hit_count":       m["hit_count"],
            "file_count":      m["file_count"],
            "files":           list(m["files"]),
            "common_ancestor": "/".join(m["directory"].split("/")[:best_depth]),
        })

    return list(merged.values()) + orphans


def _resolve_packet_cap(
    repo_path: Path,
    cap_override: int | None,
) -> tuple[int, bool]:
    """Resolve which packet cap (if any) applies for this build.

    Returns ``(effective_cap, applies)`` where ``applies`` is False
    only for the explicit "no cap" mode. Decoupled from
    :func:`cmd_build_packets_from_sensors` so the policy is unit-testable
    without setting up a full audit fixture.

    Three modes:

    - ``cap_override is None`` → full-audit semantic: returns
      ``(_adaptive_packet_cap(repo), True)``. The adaptive value
      depends on the repo's file count; same value for every family
      so total LLM cost is predictable.
    - ``cap_override == 0`` → focused/bypass semantic: returns
      ``(0, False)``. Caller skips truncation entirely.
    - ``cap_override > 0`` → explicit numeric cap: returns
      ``(cap_override, True)``. Reserved for a future
      ``--max-packets N`` flag.

    Negative ``cap_override`` is treated as 0 (bypass) — defensive
    rather than crashing on a CLI typo.
    """
    if cap_override is None:
        return _adaptive_packet_cap(repo_path), True
    if cap_override <= 0:
        return 0, False
    return int(cap_override), True


def _adaptive_packet_cap(repo_path: Path) -> int:
    """Return the per-family packet cap for this repo.

    Reads ``total_file_count`` from
    ``<repo>/.audit/00-fingerprint/raw-signals.json`` and scales the
    cap linearly. On small repos (file_count < STEP) and on repos where
    raw-signals.json is missing / malformed, the cap stays at the
    BASE (= ``MAX_SENSOR_PACKETS_PER_REPO``) so behaviour is unchanged
    from before the adaptive scaling landed.

    Why scale by ``total_file_count`` and not LOC: LOC is not in
    raw-signals.json (the collector counts files but does not run wc).
    File count is a good enough proxy for cluster volume: more files
    means more parent directories means more natural clusters means
    more risk of hitting the BASE cap.
    """
    raw_signals_path = repo_path / ".audit" / "00-fingerprint" / "raw-signals.json"
    try:
        with raw_signals_path.open(encoding="utf-8") as f:
            data = json.load(f)
        total_files = int(data.get("total_file_count", 0))
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return MAX_SENSOR_PACKETS_PER_REPO
    if total_files <= 0:
        return MAX_SENSOR_PACKETS_PER_REPO
    extra_steps = total_files // MAX_SENSOR_PACKETS_FILES_PER_STEP
    cap = MAX_SENSOR_PACKETS_PER_REPO + extra_steps * MAX_SENSOR_PACKETS_STEP_INCREMENT
    return min(cap, MAX_SENSOR_PACKETS_CEILING)


def _find_sensors_dir() -> Path:
    """Locate the sensors/ catalog directory.

    Resolution order:
      1. ``SRA_SENSORS_DIR`` environment variable (if it is a directory).
      2. The packaged location: ``<sra-package>/sensors/`` next to this
         module — works for both editable install and wheel/pipx.
    """
    env = os.environ.get("SRA_SENSORS_DIR")
    if env:
        p = Path(env).expanduser()
        if p.is_dir():
            return p
    packaged = Path(__file__).resolve().parent / "sensors"
    if packaged.is_dir():
        return packaged
    raise FileNotFoundError(
        f"sensors/ directory not found (looked in {packaged}). "
        f"Set SRA_SENSORS_DIR to override."
    )


def _load_ripgrep_catalog(sensors_dir: Path, family: str) -> dict:
    family_slug = _family_slug(family)
    path = sensors_dir / "ripgrep" / f"{family_slug}.json"
    if not path.is_file():
        raise FileNotFoundError(
            f"no ripgrep catalog at {path} for family {family}"
        )
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"catalog {path} is not valid JSON: {e}") from e


# File-extension globs to scope each ripgrep pattern by the catalog's
# language group. Patterns in the "generic" group run against the union
# of all code extensions (no language-specific filter, but still excludes
# docs, manifests, lockfiles, binaries).
_CODE_GLOBS_BY_LANG_GROUP: dict[str, list[str]] = {
    "javascript_typescript": [
        "*.js", "*.mjs", "*.cjs", "*.jsx", "*.ts", "*.tsx",
    ],
    "python":                 ["*.py", "*.pyi"],
    "go":                     ["*.go"],
    "php":                    ["*.php", "*.phtml"],
    "java":                   ["*.java", "*.kt", "*.kts", "*.scala"],
    "ruby":                   ["*.rb", "*.rake"],
    "rust":                   ["*.rs"],
    "c_cpp": [
        "*.c", "*.cc", "*.cpp", "*.cxx", "*.c++",
        "*.h", "*.hh", "*.hpp", "*.hxx", "*.h++",
        "*.inc",
    ],
    # Solidity / EVM smart contracts (Phase 5: audit/smart-contracts).
    "solidity":               ["*.sol"],
    # Supply-chain-specific groups: scan manifests, lockfiles, CI configs,
    # release tooling — not source code. Each group's glob list targets
    # ecosystem-specific artefacts.
    "manifest_node": [
        "package.json", "package-lock.json",
        "yarn.lock", "pnpm-lock.yaml",
        ".npmrc", ".yarnrc", ".pnpmrc", ".nvmrc",
    ],
    "manifest_python": [
        "pyproject.toml", "setup.py", "setup.cfg",
        "requirements*.txt", "constraints*.txt",
        "Pipfile", "Pipfile.lock", "poetry.lock",
        "tox.ini", "MANIFEST.in",
    ],
    "manifest_php": [
        "composer.json", "composer.lock",
    ],
    "manifest_go": [
        "go.mod", "go.sum", "go.work", "go.work.sum",
    ],
    "manifest_rust": [
        "Cargo.toml", "Cargo.lock", "build.rs",
    ],
    "manifest_java": [
        "pom.xml",
        "build.gradle", "build.gradle.kts",
        "settings.gradle", "settings.gradle.kts",
        "gradle.properties",
    ],
    "ci_workflow": [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        ".gitlab-ci.yml",
        ".circleci/config.yml",
        "azure-pipelines.yml",
        "Jenkinsfile",
        ".buildkite/*.yml",
        "appveyor.yml",
    ],
    "release_config": [
        "release.config.js", "release.config.mjs", "release.config.cjs",
        ".releaserc", ".releaserc.json",
        ".releaserc.yml", ".releaserc.yaml",
        ".releaserc.js",
        ".goreleaser.yml", ".goreleaser.yaml",
        ".changeset/config.json",
    ],
    # Config-deployment groups: container / IaC / env config artefacts.
    "dockerfile": [
        "Dockerfile",
        "Dockerfile.*",
        "*.dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "docker-compose.*.yml",
        "docker-compose.*.yaml",
        ".dockerignore",
    ],
    "k8s_manifests": [
        "*.yaml", "*.yml",  # k8s manifests live in many directories
        "values.yaml", "values.*.yaml",
        "Chart.yaml",
    ],
    "terraform": [
        "*.tf", "*.tf.json", "*.tfvars",
    ],
    "env_config": [
        ".env", ".env.*",
        "settings.py", "settings.*.py",
        "config.py", "config.*.py",
        "config.js", "config.*.js", "config.ts",
        "config.json", "config.*.json",
        "*.cfg", "*.ini", "*.conf",
    ],
    "generic": [
        "*.js", "*.mjs", "*.cjs", "*.jsx", "*.ts", "*.tsx",
        "*.py", "*.pyi",
        "*.go", "*.php", "*.phtml",
        "*.java", "*.kt", "*.kts", "*.scala",
        "*.rb", "*.rake", "*.rs",
        "*.cs", "*.fs",
        "*.c", "*.cc", "*.cpp", "*.h", "*.hpp",
    ],
}

# Paths excluded from every ripgrep pattern regardless of lang_group.
# ripgrep already respects .gitignore, which usually covers
# node_modules / dist / target / .venv etc. These extra excludes cover
# (a) the .audit/ output directory of this same tool — never feed on
# our own output, (b) common doc and manifest noise that shows up at
# repo roots and is not interesting for code-level audit.
_GLOBAL_RG_EXCLUDES: list[str] = [
    "!.audit/**",
    "!**/*.md", "!**/*.markdown", "!**/*.mdx",
    "!**/*.rst", "!**/*.txt",
    "!**/CHANGELOG*", "!**/HISTORY*", "!**/History.md",
    "!**/*.lock", "!**/*.lockb",
    "!**/package-lock.json", "!**/yarn.lock", "!**/pnpm-lock.yaml",
    "!**/composer.lock", "!**/Gemfile.lock",
    "!**/poetry.lock", "!**/Cargo.lock",
    "!**/*.min.js", "!**/*.min.css",
]


# --- Language filter (--only-lang / --exclude-lang) -------------------
#
# Canonical user-facing language tokens. Each token maps to:
#   - File extensions (used to filter sensor hits by `path`)
#   - ripgrep `lang_group` values from `_CODE_GLOBS_BY_LANG_GROUP`
#   - ast-grep `lang` values from each pattern's `lang` field
#
# Aliases: `js`/`ts`/`javascript`/`typescript` all map to the same
# logical "javascript_typescript" bucket so users can write whatever
# is natural for their repo. `cpp`/`c++` collapse with `c` into `c_cpp`.
_LANG_ALIASES: dict[str, str] = {
    "js":         "javascript",
    "ts":         "javascript",   # rg group is the same bucket
    "typescript": "javascript",
    "javascript": "javascript",
    "py":         "python",
    "python":     "python",
    "go":         "go",
    "golang":     "go",
    "php":        "php",
    "java":       "java",
    "kotlin":     "kotlin",
    "kt":         "kotlin",
    "scala":      "scala",
    "ruby":       "ruby",
    "rb":         "ruby",
    "rust":       "rust",
    "rs":         "rust",
    "c":          "c_cpp",
    "cpp":        "c_cpp",
    "c++":        "c_cpp",
    "cxx":        "c_cpp",
    "csharp":     "csharp",
    "cs":         "csharp",
    "c#":         "csharp",
    "swift":      "swift",
    "solidity":   "solidity",
    "sol":        "solidity",
}

# Canonical token -> file extensions (lower-case, with leading dot).
_LANG_EXTENSIONS: dict[str, set[str]] = {
    "javascript": {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"},
    "python":     {".py", ".pyi"},
    "go":         {".go"},
    "php":        {".php", ".phtml"},
    "java":       {".java"},
    "kotlin":     {".kt", ".kts"},
    "scala":      {".scala"},
    "ruby":       {".rb", ".rake"},
    "rust":       {".rs"},
    "c_cpp":      {
        ".c", ".cc", ".cpp", ".cxx", ".c++",
        ".h", ".hh", ".hpp", ".hxx", ".h++", ".inc",
    },
    "csharp":     {".cs", ".fs"},
    "swift":      {".swift"},
    "solidity":   {".sol"},
}

# Canonical token -> ripgrep `lang_group` keys from
# `_CODE_GLOBS_BY_LANG_GROUP`. Java+Kotlin+Scala share the "java" group
# (rg only scopes by extension, and "java" group already includes
# *.kt/*.scala). Note: we DON'T scope manifest_* / ci_workflow / env_*
# groups here — those are language-agnostic and run unconditionally.
_LANG_RG_GROUPS: dict[str, set[str]] = {
    "javascript": {"javascript_typescript"},
    "python":     {"python"},
    "go":         {"go"},
    "php":        {"php"},
    "java":       {"java"},
    "kotlin":     {"java"},   # rg "java" group already includes *.kt
    "scala":      {"java"},
    "ruby":       {"ruby"},
    "rust":       {"rust"},
    "c_cpp":      {"c_cpp"},
    "csharp":     set(),      # no dedicated rg group today
    "swift":      set(),      # no dedicated rg group today
    "solidity":   {"solidity"},
}

# Canonical token -> ast-grep `--lang` values that count as that language.
# ast-grep uses tree-sitter parser names.
_LANG_ASTGREP: dict[str, set[str]] = {
    "javascript": {"javascript", "typescript", "tsx", "jsx"},
    "python":     {"python"},
    "go":         {"go"},
    "php":        {"php"},
    "java":       {"java"},
    "kotlin":     {"kotlin"},
    "scala":      {"scala"},
    "ruby":       {"ruby"},
    "rust":       {"rust"},
    "c_cpp":      {"c", "cpp", "c++"},
    "csharp":     {"csharp", "c_sharp"},
    "swift":      {"swift"},
    "solidity":   {"solidity"},
}


def _canonicalise_lang_token(token: str) -> str | None:
    """Normalise a user-typed language token (e.g. ``Js``, ``c++``)
    to its canonical form. Returns ``None`` for unknown tokens."""
    if not isinstance(token, str):
        return None
    return _LANG_ALIASES.get(token.strip().lower())


def canonical_language_tokens() -> list[str]:
    """Sorted list of canonical tokens (for CLI help / error messages)."""
    return sorted(set(_LANG_ALIASES.values()))


class LanguageFilter:
    """Yes/no predicate over file paths + sensor pattern metadata.

    Built from ``--only-lang`` (whitelist) and ``--exclude-lang``
    (blacklist) flags. ``only`` overrides: a path passes iff its
    extension belongs to at least one ``only`` language. When ``only``
    is empty, the filter passes everything except the extensions in
    ``exclude``.

    Files with unknown extensions (.md, .yaml, Dockerfile, …) always
    pass — the language filter applies to *source code*, not to config
    or manifest hits, which the sensor catalogs sometimes legitimately
    target across all repos regardless of primary language.
    """

    __slots__ = ("_only", "_exclude", "_only_exts", "_exclude_exts")

    def __init__(
        self,
        only: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> None:
        # Canonicalise tokens defensively. Callers that already
        # canonicalised pay no penalty; callers that didn't (tests,
        # programmatic uses) get the same behaviour as via the CLI.
        # Unknown tokens are silently dropped here — input validation
        # belongs in `_build_lang_filter_from_args`.
        def _canon(items: list[str] | None) -> list[str]:
            out: list[str] = []
            seen: set[str] = set()
            for it in items or []:
                c = _canonicalise_lang_token(it) if isinstance(it, str) else None
                if c is None:
                    continue
                if c not in seen:
                    seen.add(c)
                    out.append(c)
            return sorted(out)

        self._only = _canon(only)
        self._exclude = _canon(exclude)
        self._only_exts: set[str] = set()
        for tok in self._only:
            self._only_exts |= _LANG_EXTENSIONS.get(tok, set())
        self._exclude_exts: set[str] = set()
        for tok in self._exclude:
            self._exclude_exts |= _LANG_EXTENSIONS.get(tok, set())

    @property
    def is_active(self) -> bool:
        return bool(self._only or self._exclude)

    @property
    def only(self) -> list[str]:
        return list(self._only)

    @property
    def exclude(self) -> list[str]:
        return list(self._exclude)

    def describe(self) -> str:
        bits = []
        if self._only:
            bits.append("only=" + ",".join(self._only))
        if self._exclude:
            bits.append("exclude=" + ",".join(self._exclude))
        return "; ".join(bits) or "(no filter)"

    @staticmethod
    def _ext_of(path: str) -> str:
        if not isinstance(path, str) or not path:
            return ""
        # Use only the last suffix; Path("foo.tar.gz").suffix == ".gz".
        # That's what we want here — language extensions are single.
        return Path(path).suffix.lower()

    def allows_path(self, path: str) -> bool:
        """Returns True iff a sensor hit at this path should be kept."""
        ext = self._ext_of(path)
        # Unknown extensions (config files, manifests, IaC, etc.) are
        # always allowed: the language filter is about *code*, not about
        # everything else the catalogs scan.
        all_code_exts: set[str] = set()
        for exts in _LANG_EXTENSIONS.values():
            all_code_exts |= exts
        if ext not in all_code_exts:
            return True
        if self._only_exts and ext not in self._only_exts:
            return False
        if ext in self._exclude_exts:
            return False
        return True

    def allows_rg_lang_group(self, lang_group: str) -> bool:
        """Returns True iff a ripgrep pattern in this lang_group should run.

        Language-agnostic groups (generic, manifest_*, ci_workflow,
        release_config, dockerfile, k8s_manifests, terraform, env_config)
        always run — their hits are post-filtered by `allows_path`.
        """
        # Only language-specific groups are gated here; everything else
        # is treated as language-agnostic infrastructure scanning.
        lang_specific = set()
        for groups in _LANG_RG_GROUPS.values():
            lang_specific |= groups
        if lang_group not in lang_specific:
            return True
        if self._only:
            allowed: set[str] = set()
            for tok in self._only:
                allowed |= _LANG_RG_GROUPS.get(tok, set())
            if lang_group not in allowed:
                return False
        if self._exclude:
            blocked: set[str] = set()
            for tok in self._exclude:
                # Only block if the group is EXCLUSIVELY this language.
                # `java` group covers java+kotlin+scala; excluding
                # `kotlin` alone shouldn't kill all Java patterns.
                blocked_token_exts = _LANG_EXTENSIONS.get(tok, set())
                # Compute which other canonical tokens also map here.
                co_tokens = {
                    other for other, grps in _LANG_RG_GROUPS.items()
                    if lang_group in grps
                }
                # If every co-token is excluded, block the group.
                if co_tokens and all(
                    ct in self._exclude or _LANG_EXTENSIONS.get(ct, set()) <= blocked_token_exts
                    for ct in co_tokens
                ):
                    blocked.add(lang_group)
            if lang_group in blocked:
                return False
        return True

    def allows_astgrep_lang(self, lang: str) -> bool:
        """Returns True iff an ast-grep pattern with this --lang should run."""
        if not isinstance(lang, str):
            return True
        norm = lang.strip().lower()
        # Find the canonical token this ast-grep lang belongs to.
        canon: str | None = None
        for tok, vals in _LANG_ASTGREP.items():
            if norm in vals:
                canon = tok
                break
        if canon is None:
            # Unknown ast-grep lang — let it through (catalog authors
            # may add new languages we haven't catalogued).
            return True
        if self._only and canon not in self._only:
            return False
        if canon in self._exclude:
            return False
        return True

    def filter_hits(self, hits: list[dict]) -> tuple[list[dict], int]:
        """Drop hits whose path is excluded by the filter.

        Returns (kept_hits, dropped_count).
        """
        if not self.is_active:
            return list(hits), 0
        kept: list[dict] = []
        dropped = 0
        for h in hits:
            if self.allows_path(h.get("path", "")):
                kept.append(h)
            else:
                dropped += 1
        return kept, dropped


def parse_language_tokens(
    raw: list[str] | None, flag_name: str,
) -> tuple[list[str], list[str]]:
    """Normalise raw user input to canonical tokens.

    `raw` may contain comma-separated values (``--only-lang php,js``)
    in addition to repeated flags (``--only-lang php --only-lang js``).
    Returns (canonical_tokens, unknown_tokens). Caller decides whether
    to error on unknowns.
    """
    canon: list[str] = []
    unknown: list[str] = []
    seen: set[str] = set()
    for item in raw or []:
        if not isinstance(item, str):
            continue
        for piece in item.split(","):
            piece = piece.strip()
            if not piece:
                continue
            c = _canonicalise_lang_token(piece)
            if c is None:
                unknown.append(piece)
            elif c not in seen:
                seen.add(c)
                canon.append(c)
    return canon, unknown


def _build_lang_filter_from_args(args) -> "LanguageFilter | None":
    """Build a LanguageFilter from argparse Namespace.

    Returns None on a fatal input error (already printed). Otherwise
    returns a (possibly inactive) LanguageFilter.
    """
    only_raw = getattr(args, "only_lang", None)
    excl_raw = getattr(args, "exclude_lang", None)
    only, only_unknown = parse_language_tokens(only_raw, "--only-lang")
    excl, excl_unknown = parse_language_tokens(excl_raw, "--exclude-lang")

    if only_unknown or excl_unknown:
        valid = ", ".join(canonical_language_tokens())
        if only_unknown:
            print(
                f"error: --only-lang: unknown language token(s): "
                f"{', '.join(only_unknown)}. Valid: {valid}.",
                file=sys.stderr,
            )
        if excl_unknown:
            print(
                f"error: --exclude-lang: unknown language token(s): "
                f"{', '.join(excl_unknown)}. Valid: {valid}.",
                file=sys.stderr,
            )
        return None

    conflict = sorted(set(only) & set(excl))
    if conflict:
        print(
            f"error: language(s) listed in BOTH --only-lang and "
            f"--exclude-lang: {', '.join(conflict)}. Drop one.",
            file=sys.stderr,
        )
        return None

    return LanguageFilter(only=only, exclude=excl)


def _ripgrep_version() -> str:
    try:
        v = subprocess.run(
            ["rg", "--version"],
            capture_output=True, text=True, timeout=5,
            encoding="utf-8", errors="replace",
        )
        first = (v.stdout or "").splitlines()[:1]
        return first[0] if first else "unknown"
    except (FileNotFoundError, subprocess.SubprocessError):
        return "unknown"


def _run_one_ripgrep_pattern(
    pattern: str, target: Path, lang_group: str = "generic",
) -> tuple[list[dict], str | None]:
    """Run rg --json for a single regex, scoped to lang_group's file
    extensions and with global doc / lockfile excludes applied.

    Returns (matches, error_msg).
    """
    cmd = [
        "rg", "--json", "--no-heading", "--line-number",
        # --hidden is needed to scan .github/ (workflows live there). rg
        # still excludes .git/ even with --hidden, so it's safe.
        "--hidden",
    ]
    for inc in _CODE_GLOBS_BY_LANG_GROUP.get(lang_group) or []:
        cmd.extend(["--glob", inc])
    for exc in _GLOBAL_RG_EXCLUDES:
        cmd.extend(["--glob", exc])
    # ripgrep interprets path-prefix `--glob` patterns
    # (e.g. `.github/workflows/*.yml`) relative to the process's current
    # working directory, NOT to the target argument. Running with a
    # different cwd silently produces zero matches even though the files
    # exist under the target. Fix by chdir-ing into the target and
    # searching ".".
    cmd.extend(["-e", pattern, "."])
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=120,
            cwd=str(target),
        )
    except FileNotFoundError:
        return [], "ripgrep ('rg') is not installed or not on PATH"
    except subprocess.TimeoutExpired:
        return [], f"ripgrep timed out on pattern {pattern!r}"
    # rg returncode: 0 = matches found, 1 = no matches, 2 = error
    if proc.returncode not in (0, 1):
        return [], f"ripgrep failed (rc={proc.returncode}): {proc.stderr.strip()}"

    matches: list[dict] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") != "match":
            continue
        data = obj.get("data") or {}
        path_obj = (data.get("path") or {}).get("text", "")
        lines_obj = (data.get("lines") or {}).get("text", "")
        # With cwd=target and target ".", rg emits paths like
        # `./.github/workflows/foo.yml` or `src/main.py`. Normalise
        # to posix without the leading `./`.
        norm = path_obj.replace("\\", "/")
        if norm.startswith("./"):
            norm = norm[2:]
        matches.append({
            "path": norm,
            "line": data.get("line_number", 0),
            "text": (lines_obj or "").rstrip("\r\n"),
        })
    return matches, None


def _semgrep_executable() -> str | None:
    """Return the path to a callable `semgrep` executable, or None.

    Checks system PATH first, then the venv that hosts this Python
    (so the user only has to `pip install semgrep` into the project's
    venv without also adjusting PATH).
    """
    found = shutil.which("semgrep")
    if found:
        return found
    venv_scripts = Path(sys.executable).parent
    for candidate in (
        venv_scripts / "semgrep.exe",
        venv_scripts / "semgrep",
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def _semgrep_version() -> str:
    exe = _semgrep_executable()
    if not exe:
        return "unknown"
    try:
        v = subprocess.run(
            [exe, "--version"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        first = (v.stdout or "").splitlines()[:1]
        return first[0].strip() if first else "unknown"
    except (FileNotFoundError, subprocess.SubprocessError):
        return "unknown"


# Semgrep config strategy.
#
# We point semgrep at the FULL public registry via the URL config
# `https://semgrep.dev/r`. That URL serves the aggregate YAML of every
# public rule (~3000 rules across all languages); semgrep itself
# decides which rules apply to which files based on detected
# language. So one invocation, one config, semgrep handles language-
# routing internally.
#
# We then apply `_SEMGREP_NOISE_CATEGORIES` as a post-filter to drop
# check_ids that are clearly non-security (portability, style, etc.).
# Without this filter the full registry returns ~5000 hits on an
# average repo, most of which are correctness/style issues — real
# bugs but not what an audit is looking for. The filter is empirical:
# every entry was identified from a full-registry scan of a real
# codebase where it dominated the noise floor.
#
# No per-family configs, no per-profile knobs. The previous design
# had three profiles (default / security / comprehensive) and a CLI
# flag to pick between them — that flag is gone. If you genuinely
# need a different config (custom pack, registry mirror, offline
# YAML), set the env var ``SRA_SEMGREP_CONFIG`` to a comma-separated
# list of configs; it overrides the default.
#
# Note: the URL endpoint negotiates by Accept header. A browser hit
# returns HTML (the registry website); semgrep's HTTP client sends
# `Accept: application/x-yaml` and gets back the aggregated rules
# file. Verified with `curl -H "Accept: application/x-yaml"
# https://semgrep.dev/r` — first line is `rules:`.
SEMGREP_DEFAULT_CONFIGS: list[str] = ["https://semgrep.dev/r"]


def _semgrep_configs() -> list[str]:
    """The configs to hand to ``semgrep --config``.

    Default is :data:`SEMGREP_DEFAULT_CONFIGS` (the full public
    registry). Override via the ``SRA_SEMGREP_CONFIG`` env var, set to
    a comma-separated list (e.g. ``p/default,p/trailofbits`` to
    restore the old curated profile, or ``./my-rules.yml`` to point at
    a local rule file). Unrecognised entries are still passed to
    semgrep verbatim so any value semgrep accepts works.
    """
    override = os.environ.get("SRA_SEMGREP_CONFIG", "").strip()
    if override:
        parts = [p.strip() for p in override.split(",") if p.strip()]
        if parts:
            return parts
    return list(SEMGREP_DEFAULT_CONFIGS)


# check_id substrings that mark a rule as NON-security. Hits whose
# check_id contains any of these (case-insensitive, substring match)
# are dropped from the final result set. Each entry was identified
# empirically from full-registry scans where it dominated the noise
# floor. Order doesn't matter (we check ALL substrings).
#
# Conservative-by-default: only drop categories that are clearly
# non-security. When in doubt, keep the hit and let the Claude
# per-packet skill dismiss it.
_SEMGREP_NOISE_CATEGORIES: tuple[str, ...] = (
    ".portability.",       # i18n, framework-portability
    ".best-practice.",     # style guidance like react-props-spreading
    ".correctness.",       # bug-detection that's not security
    ".style.",             # pure style
    ".performance.",       # perf antipatterns
    ".maintainability.",   # code quality
    # `ai.generic.detect-generic-ai-*` rules fire on any string that
    # looks like an Anthropic / OpenAI / etc property name — they
    # produce ~13 FPs on plain WordPress / SEO plugins that name a
    # CSS class or JSON field with one of those tokens. Not useful
    # for source code audits; drop.
    "ai.generic.",
)


def _is_semgrep_noise(check_id: str) -> bool:
    """True if ``check_id`` belongs to a category we drop."""
    cid = check_id.lower()
    return any(marker in cid for marker in _SEMGREP_NOISE_CATEGORIES)


# Backward-compatible alias — older callers that imported
# ``SEMGREP_CONFIG`` directly continue to get the default config list.
SEMGREP_CONFIG: list[str] = SEMGREP_DEFAULT_CONFIGS


# Mapping `check_id` substring -> audit family. First match wins, so
# put the most specific rules first. Anything unmatched falls through
# to the catch-all in `_assign_semgrep_hit_family`.
#
# Why we own this mapping: Semgrep's `check_id` is shaped like
# `<lang>.<framework>.<category>.<bucket>.<rule-name>` and there is no
# stable "this rule belongs to audit family X" field in the output.
# Keyword matching against the check_id is the most reliable signal —
# rule authors are consistent about including the vuln class name
# (`xss`, `sql-injection`, `jwt`, `path-traversal`, ...) somewhere in
# the path.
_SEMGREP_FAMILY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    # Ordered most-specific-keyword-first. Earlier families win when a
    # check_id matches multiple. The general principle: families with
    # rare, unambiguous tokens (e.g. `subresource-integrity`,
    # `dockerfile`) come before families with broader category tokens
    # (e.g. `html.security`, `react.security`).
    ("audit/config-deployment", (
        "dockerfile", "kubernetes", "yaml.k8s", "terraform", "ansible",
        "helm",
        # CI/CD configuration: GitHub Actions hardcoded-secret rules
        # (aws-secret-key, gcp-credentials, vault-token, pypi-publish-
        # password, ...) live here rather than under crypto-auth because
        # the audit family that reviews them is the one looking at the
        # CI surface, not the one looking at app-level auth flows.
        "github-actions", "docker-compose", "nomad",
    )),
    # supply-chain BEFORE client-side: rules like
    # `html.security.audit.missing-integrity.missing-integrity` would
    # otherwise be eaten by `html.security` (client-side) even though
    # subresource-integrity is a supply-chain concern (verifying CDN-
    # hosted scripts haven't been tampered with). Specific token wins.
    ("audit/supply-chain", (
        "missing-integrity", "subresource-integrity", "outdated",
        "vulnerable-dep", "lockfile",
    )),
    ("audit/server-side-injection", (
        "sql-injection", "command-injection", "code-injection",
        "child-process", "detect-eval", "deserialization",
        "ssrf", "server-side-request-forgery", "ldap-injection",
        "xpath-injection", "nosql-injection",
        # Deserialization variants from ToB Python ML pack: pickles-in-
        # pytorch, pickles-in-tensorflow, marshal-load, etc. Unsafe
        # deserialization is the canonical "load attacker-controlled
        # bytes -> RCE" pattern.
        "pickle", "marshal-load", "yaml-unsafe-load",
        # ToB Go rule: DLL hijacking via unsafe loader paths is RCE.
        "dll-loading", "dll-hijack",
    )),
    ("audit/crypto-auth", (
        # Specific tokens first (uncommon in non-crypto rule names).
        "jwt", "insecure-transport", "md5", "sha1",
        "csrf", "saml", "oauth", "session-fixation",
        "hardcoded-secret", "hardcoded-token", "hardcoded-credential",
        "constant-time", "timing-attack",
        # ToB transport-layer rules: redis/mongo/postgres/mysql/amqp
        # unencrypted-transport, wget-unencrypted-url, curl-insecure,
        # node-disable-certificate-validation, etc. The shared shape
        # is "unencrypted-..." or "...-disable-certificate-..." —
        # both go to crypto-auth as transport-security issues.
        "unencrypted", "skip-tls-verify", "skip-verification",
        "disable-certificate", "disable-host-key-checking",
        "insecure-flags",
        # Broader substrings — short and might appear in unrelated
        # rule paths, but in practice semgrep rule namespacing puts
        # them in security contexts. Examples covered:
        # - `bypass-tls-verification`, `sequelize-enforce-tls` -> "tls"
        # - `weak-ssl`, `ssl-verification-disabled` -> "ssl"
        # - `weak-cipher`, `ecb-mode-cipher` -> "cipher"
        # - `weak-hash`, `md5-hash`, `sha1-hash` -> "hash"
        # - `weak-crypto`, `insecure-crypto` -> "crypto"
        # - `password-storage`, `weak-password` -> "password"
        "tls", "ssl", "cipher", "crypto", "password",
        # `hash` is too short / risky in general (matches `hashmap`,
        # `hash-table`) so we don't include it bare.
    )),
    ("audit/file-boundary", (
        "path-traversal", "directory-traversal", "zip-slip",
        "file-permission", "static-file", "send-file",
        "tarslip", "arbitrary-file-write",
    )),
    ("audit/memory-safety", (
        "use-after-free", "double-free", "buffer-overflow",
        "stack-overflow", "uninitialized", "memory-leak",
        "null-deref",
    )),
    ("audit/concurrency-race", (
        "race-condition", "deadlock", "data-race", "atomic",
        # ToB Go concurrency rules: racy-append-to-slice, racy-write-
        # to-map, hanging-goroutine, missing-runlock-on-rwmutex,
        # waitgroup-wait-inside-loop, sync-mutex-value-copied, ...
        "racy", "goroutine", "rwmutex", "mutex", "waitgroup",
    )),
    ("audit/client-side", (
        "xss", "dangerouslysetinnerhtml", "innerhtml",
        "postmessage", "open-redirect", "browser.security",
        "html.security", "react.security", "vue.security",
        "missing-noopener", "missing-noreferrer", "dom-xss",
        "clickjacking",
        # CORS / cross-origin misconfig (Apollo GraphQL, Express,
        # generic v3-cors). Strictly browser-enforced origin-policy
        # bypass — fits client-side better than access-control.
        "cors", "cross-origin",
    )),
    # input-validation is intentionally LAST among the specific buckets
    # because its keywords overlap with everyone else's (regex / format
    # / sanitization show up in xss + injection contexts too). It must
    # fall through after the higher-priority families.
    ("audit/input-validation", (
        "regexp", "regex", "format-string", "unsafe-format",
        "prototype-pollution", "incomplete-sanitization",
        "validation", "input-validation", "tainted",
    )),
)
# Families that semgrep can't meaningfully cover. Hits never assigned here.
# Not used by the dispatcher (it just doesn't match), kept for documentation.
_SEMGREP_UNCOVERED_FAMILIES: frozenset[str] = frozenset({
    "audit/agentic-ai",        # no semgrep rules for tool-use / LLM patterns
    "audit/smart-contracts",   # ToB skills + slither, not semgrep
    "audit/parser-state-machine",   # state-machine bugs are not pattern-grep
    "audit/network-protocol",       # wire-level bugs not pattern-grep
    "audit/business-logic",         # by definition not pattern-detectable
    "audit/access-control",         # AuthZ logic is contextual, not regex
})


def _assign_semgrep_hit_family(check_id: str) -> str:
    """Return the audit family this semgrep `check_id` belongs to.

    Walks `_SEMGREP_FAMILY_RULES` in order (most-specific first) and
    matches by substring. Falls back to `audit/input-validation` —
    chosen as catch-all because (a) it is the broadest family by
    definition (any external input boundary qualifies) and (b) the
    semgrep packs we run are dominated by input-side rules.
    """
    cid = check_id.lower()
    for family, keywords in _SEMGREP_FAMILY_RULES:
        if any(kw in cid for kw in keywords):
            return family
    return "audit/input-validation"


# Per-process cache: a single semgrep invocation produces results for
# every audit family, so we want to run it once even when the
# orchestrator hits `sra run-sensor --sensor semgrep` from N family
# loops in a row. Cache key is `(target.resolve(), frozenset(configs))`.
_SEMGREP_RESULT_CACHE: dict[tuple[Path, frozenset[str]], dict] = {}
# Guards `_SEMGREP_RESULT_CACHE` reads/writes. Current callers only hit
# the cache from cmd_audit's per-family sensor loop (sequential), so
# there's no race today. The lock is in place defensively for when
# the sensor phase eventually gets parallelised (TODO in the future
# refactor that consolidates `_invoke_claude_*` helpers).
_SEMGREP_CACHE_LOCK = threading.Lock()


def _run_one_semgrep_config(
    exe: str, target: Path, config: str,
) -> tuple[dict, str | None]:
    """Run semgrep with ONE config. Returns (raw_json, error)."""
    cmd = [exe, "--json", "--metrics=off", "--quiet",
           "--config", config, str(target)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=900,
        )
    except FileNotFoundError:
        return {}, "semgrep is not installed"
    except subprocess.TimeoutExpired:
        return {}, f"semgrep timed out on config {config}"
    # semgrep returncode: 0 / 1 are normal (findings or none); >1 = error.
    # rc=7 is "Internal error" — observed when a pack errors on a language
    # mismatch in the target. We swallow it as an error per-pack but
    # continue with other packs.
    if proc.returncode > 1:
        err_short = (proc.stderr or "").strip()[:300]
        return {}, f"semgrep config {config} failed (rc={proc.returncode}): {err_short}"
    try:
        return json.loads(proc.stdout or "{}"), None
    except json.JSONDecodeError as e:
        return {}, f"semgrep output for {config} is not valid JSON: {e}"


def _run_semgrep(target: Path, configs: list[str]) -> tuple[dict, str | None]:
    """Run semgrep over `target` with each config separately, then merge.

    Per-pack failures are recorded as errors but do not abort the whole
    run — partial results are preferred over none. Returns the merged
    raw_json (`results` is the union of all per-pack results, with a
    `_per_config_errors` key listing pack failures).
    """
    exe = _semgrep_executable()
    if not exe:
        return {}, "semgrep is not installed. Try: pip install semgrep"
    if not configs:
        return {}, "no semgrep configs registered for this family"

    merged_results: list[dict] = []
    seen_keys: set[tuple] = set()
    per_config_errors: list[str] = []
    semgrep_version_seen = None

    for cfg in configs:
        raw, err = _run_one_semgrep_config(exe, target, cfg)
        if err:
            per_config_errors.append(err)
            continue
        if semgrep_version_seen is None:
            semgrep_version_seen = raw.get("version")
        # Dedup findings across configs by (check_id, path, start_line).
        for r in raw.get("results") or []:
            if not isinstance(r, dict):
                continue
            check_id = r.get("check_id", "")
            path = r.get("path", "")
            line = (r.get("start") or {}).get("line", 0)
            key = (check_id, path, line)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            merged_results.append(r)

    merged = {
        "version":             semgrep_version_seen,
        "results":             merged_results,
        "_per_config_errors":  per_config_errors,
    }
    # If every config errored, surface that as a hard error.
    if not merged_results and per_config_errors and len(per_config_errors) == len(configs):
        return merged, f"all {len(configs)} semgrep configs failed: " + "; ".join(per_config_errors[:3])
    return merged, None


def _get_or_run_semgrep(
    target: Path, configs: list[str],
) -> tuple[dict, str | None]:
    """Run `_run_semgrep` once per `(target, configs)` combo.

    The audit orchestrator may call `sra run-sensor --sensor semgrep`
    for every family in sequence (or in parallel later). With a single
    universal config (`p/default`) they would all run identical scans
    and produce identical raw output — wasting ~10-15 s × N families.
    This cache makes the second+ calls free.

    Returns the same shape as `_run_semgrep`: (raw_json, error_msg).
    Errors are NOT cached (so a retry after a transient failure still
    actually retries).
    """
    key = (target.resolve(), frozenset(configs))
    with _SEMGREP_CACHE_LOCK:
        cached = _SEMGREP_RESULT_CACHE.get(key)
    if cached is not None:
        return cached, None
    raw, err = _run_semgrep(target, configs)
    if err is None:
        with _SEMGREP_CACHE_LOCK:
            _SEMGREP_RESULT_CACHE[key] = raw
    return raw, err


# === ast-grep sensor ========================================================

def _ast_grep_executable() -> str | None:
    """Find ast-grep on PATH (installed via scoop / cargo / brew)."""
    for name in ("ast-grep", "sg"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _ast_grep_version() -> str:
    exe = _ast_grep_executable()
    if not exe:
        return "unknown"
    try:
        v = subprocess.run(
            [exe, "--version"],
            capture_output=True, text=True, timeout=5,
            encoding="utf-8", errors="replace",
        )
        first = (v.stdout or "").splitlines()[:1]
        return first[0].strip() if first else "unknown"
    except (FileNotFoundError, subprocess.SubprocessError):
        return "unknown"


def _load_ast_grep_catalog(sensors_dir: Path, family: str) -> dict:
    """Load `sensors/ast-grep/audit-<family>.json`.

    Schema:
      {
        "schema_version": 1,
        "sensor": "ast-grep",
        "family": "audit/<family>",
        "patterns": [
          {
            "id": str,
            "pattern": str,        // ast-grep pattern with $METAVARS
            "lang": str,           // ast-grep lang flag (javascript, python, ...)
            "description": str,
            "expected_role": str,
            "false_positive_notes": str
          }, ...
        ]
      }
    """
    family_slug = _family_slug(family)
    path = sensors_dir / "ast-grep" / f"{family_slug}.json"
    if not path.is_file():
        raise FileNotFoundError(
            f"no ast-grep catalog at {path} for family {family}"
        )
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"catalog {path} is not valid JSON: {e}") from e


def _run_one_ast_grep_pattern(
    pattern: str, lang: str, target: Path,
) -> tuple[list[dict], str | None]:
    """Run `ast-grep run --pattern X --lang Y --json target`.

    Returns (matches, error_msg). Each match: {path, line, text}.
    """
    exe = _ast_grep_executable()
    if not exe:
        return [], "ast-grep is not installed. Install via: scoop install ast-grep"
    cmd = [
        exe, "run",
        "--pattern", pattern,
        "--lang", lang,
        "--json=compact",
        "."
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=120,
            cwd=str(target),
        )
    except FileNotFoundError:
        return [], "ast-grep is not callable"
    except subprocess.TimeoutExpired:
        return [], f"ast-grep timed out on pattern {pattern!r}"
    # ast-grep exit codes (same convention as grep):
    #   0 = matches found
    #   1 = no matches
    #   2+ = error
    if proc.returncode not in (0, 1):
        return [], f"ast-grep failed (rc={proc.returncode}): {proc.stderr.strip()[:300]}"

    try:
        arr = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as e:
        return [], f"ast-grep output is not valid JSON: {e}"

    matches: list[dict] = []
    for m in arr if isinstance(arr, list) else []:
        if not isinstance(m, dict):
            continue
        file_path = m.get("file", "")
        rng = m.get("range") or {}
        start = (rng.get("start") or {})
        line = start.get("line", 0)
        # ast-grep uses 0-indexed lines; convert to 1-indexed.
        if isinstance(line, int):
            line = line + 1
        text = (m.get("text") or "").splitlines()[:1]
        text = text[0] if text else ""
        # Normalise path to posix and strip leading ./
        norm = file_path.replace("\\", "/")
        if norm.startswith("./"):
            norm = norm[2:]
        matches.append({
            "path": norm,
            "line": line,
            "text": text.strip(),
        })
    return matches, None


def _run_ast_grep(
    target: Path, family: str, out_dir: Path, ran_at: str,
    *,
    lang_filter: "LanguageFilter | None" = None,
) -> int:
    """Top-level ast-grep runner. Loads catalog, runs each pattern,
    writes per-pattern .json + index.json."""
    if _ast_grep_executable() is None:
        print(
            "error: ast-grep is not on PATH.\n"
            "       install with: scoop install ast-grep",
            file=sys.stderr,
        )
        return 5

    try:
        sensors_dir = _find_sensors_dir()
        catalog = _load_ast_grep_catalog(sensors_dir, family)
    except (FileNotFoundError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 6

    patterns = catalog.get("patterns") or []
    outputs: list[dict] = []
    errors: list[str] = []
    total_hits = 0
    skipped_by_lang_filter = 0

    for p in patterns:
        if _INTERRUPTED.is_set():
            errors.append("interrupted by user; remaining patterns skipped")
            break
        if not isinstance(p, dict):
            continue
        pid  = p.get("id")
        pat  = p.get("pattern")
        lang = p.get("lang")
        if not (isinstance(pid, str) and isinstance(pat, str) and isinstance(lang, str)):
            continue
        if lang_filter is not None and not lang_filter.allows_astgrep_lang(lang):
            skipped_by_lang_filter += 1
            continue
        matches, err = _run_one_ast_grep_pattern(pat, lang, target)
        if err:
            errors.append(f"[{pid}] {err}")
        # Path-level filter is a safety net (ast-grep --lang scopes
        # parsing, but extension filtering catches edge cases like
        # .ts files with --lang=javascript).
        if lang_filter is not None and matches:
            matches = [m for m in matches if lang_filter.allows_path(m.get("path", ""))]
        output_doc = {
            "schema_version": 1,
            "pattern_id":     pid,
            "pattern":        pat,
            "description":    p.get("description", ""),
            "expected_role":  p.get("expected_role", "input_source"),
            "lang_group":     lang,
            "match_count":    len(matches),
            "matches":        matches,
        }
        (out_dir / f"{pid}.json").write_text(
            json.dumps(output_doc, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        outputs.append({
            "name":         pid,
            "output_file":  f"{pid}.json",
            "result_count": len(matches),
        })
        total_hits += len(matches)

    family_slug = _family_slug(family)
    index_doc = {
        "schema_version":       1,
        "sensor":               "ast-grep",
        "sensor_version":       _ast_grep_version(),
        "audit_family":         family,
        "ran_at":               ran_at,
        "inputs": {
            "catalog_path":  posix(
                sensors_dir / "ast-grep" / f"{family_slug}.json"
            ),
            "target_path":   posix(target),
            "pattern_count": len(patterns),
        },
        "outputs":              outputs,
        "executed_target_code": False,
        "errors":               errors,
        "notes": [
            f"Ran {len(patterns)} ast-grep patterns.",
            f"Total hits: {total_hits}.",
            "ast-grep is AST-aware; hits are higher-precision than ripgrep.",
        ],
    }
    (out_dir / "index.json").write_text(
        json.dumps(index_doc, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    lang_note = ""
    if lang_filter is not None and lang_filter.is_active:
        lang_note = f" [lang-filter: {lang_filter.describe()}; {skipped_by_lang_filter} patterns skipped]"
    print(
        f"sra: ast-grep ran {len(patterns) - skipped_by_lang_filter} "
        f"of {len(patterns)} patterns on {target}; "
        f"{total_hits} hits.{lang_note}",
        file=sys.stderr,
    )
    return 0


def cmd_run_sensor(
    repo_path_str: str, family: str, sensor: str,
    *,
    force: bool = False,
    lang_filter: "LanguageFilter | None" = None,
) -> int:
    if family not in SENSOR_SUPPORTED_FAMILIES:
        supported = ", ".join(sorted(SENSOR_SUPPORTED_FAMILIES))
        print(
            f"error: --family {family!r} is not supported by run-sensor.\n"
            f"       supported: {supported}",
            file=sys.stderr,
        )
        return 4
    if sensor not in SENSOR_SUPPORTED_SENSORS:
        supported = ", ".join(sorted(SENSOR_SUPPORTED_SENSORS))
        print(
            f"error: --sensor {sensor!r} is not supported.\n"
            f"       supported: {supported}",
            file=sys.stderr,
        )
        return 4

    repo_path = Path(repo_path_str).expanduser()
    if not repo_path.exists():
        print(f"error: path does not exist: {repo_path}", file=sys.stderr)
        return 2
    if not repo_path.is_dir():
        print(f"error: not a directory: {repo_path}", file=sys.stderr)
        return 2

    target = repo_path.resolve()
    family_slug = _family_slug(family)
    out_dir = (
        target / ".audit" / "03-evidence" / family_slug
        / "sensors" / sensor
    )

    # Resume guard: if `index.json` already exists from a previous run
    # AND the caller didn't request force, skip the scan. Previously
    # cmd_run_sensor wiped the dir on every invocation, so a long
    # audit that got interrupted mid-family would re-scan every
    # already-done sensor on resume — minutes of waste with semgrep
    # on a large repo. The skill phase already has per-packet resume;
    # the sensor phase should be no different.
    index_path = out_dir / "index.json"
    if index_path.is_file() and not force:
        print(
            f"sra: {sensor} on {family} — skipped (index.json exists; "
            f"pass --force to re-scan)",
            file=sys.stderr,
        )
        return 0

    # Clean prior run's output so the directory reflects only this run.
    if out_dir.exists():
        for f in out_dir.iterdir():
            if f.is_file():
                try:
                    f.unlink()
                except OSError:
                    pass
    out_dir.mkdir(parents=True, exist_ok=True)

    ran_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if sensor == "ripgrep":
        if shutil.which("rg") is None:
            print(
                "error: ripgrep ('rg') is not on PATH.\n"
                "       install with:  winget install BurntSushi.ripgrep.MSVC\n"
                "                  or: scoop install ripgrep",
                file=sys.stderr,
            )
            return 5

        try:
            sensors_dir = _find_sensors_dir()
            catalog = _load_ripgrep_catalog(sensors_dir, family)
        except (FileNotFoundError, RuntimeError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 6

        all_patterns: list[dict] = []
        for lang, entries in (catalog.get("groups") or {}).items():
            for e in entries or []:
                if not isinstance(e, dict):
                    continue
                e2 = dict(e)
                e2["_lang_group"] = lang
                all_patterns.append(e2)

        outputs: list[dict] = []
        errors: list[str] = []
        total_hits = 0
        skipped_by_lang_filter = 0

        for p in all_patterns:
            if _INTERRUPTED.is_set():
                errors.append("interrupted by user; remaining patterns skipped")
                break
            pat = p.get("pattern")
            pid = p.get("id")
            if not isinstance(pat, str) or not isinstance(pid, str):
                continue
            lang_group = p.get("_lang_group", "generic")
            if lang_filter is not None and not lang_filter.allows_rg_lang_group(lang_group):
                skipped_by_lang_filter += 1
                continue
            matches, err = _run_one_ripgrep_pattern(
                pat, target, lang_group,
            )
            if err:
                errors.append(f"[{pid}] {err}")
            # Apply language filter at the path level too — catches hits
            # from "generic"/manifest groups whose paths happen to be in
            # an excluded language.
            if lang_filter is not None and matches:
                matches = [m for m in matches if lang_filter.allows_path(m.get("path", ""))]
            for m in matches:
                ap = Path(m.get("path", ""))
                try:
                    rel = ap.relative_to(target)
                    m["path"] = posix(rel)
                except ValueError:
                    m["path"] = posix(ap)
            output_doc = {
                "schema_version": 1,
                "pattern_id":     pid,
                "pattern":        pat,
                "description":    p.get("description", ""),
                "expected_role":  p.get("expected_role", "input_source"),
                "lang_group":     p.get("_lang_group", "generic"),
                "match_count":    len(matches),
                "matches":        matches,
            }
            (out_dir / f"{pid}.json").write_text(
                json.dumps(output_doc, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            outputs.append({
                "name":         pid,
                "output_file":  f"{pid}.json",
                "result_count": len(matches),
            })
            total_hits += len(matches)

        index_doc = {
            "schema_version":       1,
            "sensor":               "ripgrep",
            "sensor_version":       _ripgrep_version(),
            "audit_family":         family,
            "ran_at":               ran_at,
            "inputs": {
                "catalog_path":  posix(
                    sensors_dir / "ripgrep" / f"{family_slug}.json"
                ),
                "target_path":   posix(target),
                "pattern_count": len(all_patterns),
            },
            "outputs":              outputs,
            "executed_target_code": False,
            "errors":               errors,
            "notes": [
                f"Ran {len(all_patterns)} ripgrep patterns from the catalog.",
                f"Total hits across all patterns: {total_hits}.",
                "Output is evidence-seeds, not findings.",
            ],
        }
        (out_dir / "index.json").write_text(
            json.dumps(index_doc, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        lang_note = ""
        if lang_filter is not None and lang_filter.is_active:
            lang_note = f" [lang-filter: {lang_filter.describe()}; {skipped_by_lang_filter} patterns skipped]"
        print(
            f"sra: ripgrep ran {len(all_patterns) - skipped_by_lang_filter} "
            f"of {len(all_patterns)} patterns on {target}; "
            f"{total_hits} hits across {len(outputs)} pattern files."
            f"{lang_note}",
            file=sys.stderr,
        )
        return 0

    if sensor == "ast-grep":
        return _run_ast_grep(
            target, family, out_dir, ran_at,
            lang_filter=lang_filter,
        )

    # sensor == "semgrep"
    if _semgrep_executable() is None:
        print(
            "error: semgrep is not on PATH and not in the venv that hosts "
            "this Python.\n"
            "       install with:  pip install semgrep",
            file=sys.stderr,
        )
        return 5

    # Flow:
    # 1. Resolve the semgrep configs (default: full public registry).
    # 2. Run semgrep ONCE per repo with that config (cached in-process
    #    so subsequent family runs are free).
    # 3. Apply the noise filter: drop check_ids in `portability.*`,
    #    `style.*`, `correctness.*`, `best-practice.*`, `performance.*`,
    #    `maintainability.*`, `ai.generic.*` — clearly non-security.
    # 4. Dispatch each surviving hit to ONE family based on `check_id`
    #    keyword matching; unmatched hits land in audit/input-validation
    #    (broadest catch-all).
    configs = _semgrep_configs()
    raw, err = _get_or_run_semgrep(target, configs)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 7

    raw_findings = raw.get("results") or []
    all_findings = [
        r for r in raw_findings
        if not _is_semgrep_noise(r.get("check_id", ""))
    ]
    dropped_as_noise = len(raw_findings) - len(all_findings)
    # Filter to hits assigned to THIS family.
    findings = [
        r for r in all_findings
        if _assign_semgrep_hit_family(r.get("check_id", "")) == family
    ]
    # Apply --only-lang / --exclude-lang at the path level. We can't
    # gate semgrep rule selection (it's a single repo-wide invocation),
    # so the filter is purely a post-pass.
    if lang_filter is not None and lang_filter.is_active and findings:
        before = len(findings)
        findings = [
            r for r in findings
            if lang_filter.allows_path(r.get("path", ""))
        ]
        dropped_by_lang = before - len(findings)
        if dropped_by_lang:
            print(
                f"sra: semgrep ({family}): lang-filter dropped "
                f"{dropped_by_lang} of {before} hits "
                f"({lang_filter.describe()}).",
                file=sys.stderr,
            )

    # Write the (full repo-wide) raw output to every family dir for
    # debug-trace symmetry with the old behaviour. Small price; lets a
    # user grep the raw output without re-running semgrep.
    (out_dir / "results.json").write_text(
        json.dumps(raw, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # Normalise findings into the same per-pattern shape used by ripgrep so
    # the packet builder can read both uniformly. Group by rule id.
    by_rule: dict[str, list[dict]] = {}
    for r in findings:
        rule_id = r.get("check_id", "unknown")
        path = r.get("path", "")
        try:
            rel = posix(Path(path).resolve().relative_to(target))
        except (ValueError, OSError):
            rel = posix(Path(path))
        start = (r.get("start") or {}).get("line", 0)
        message = (r.get("extra") or {}).get("message", "")
        by_rule.setdefault(rule_id, []).append({
            "path": rel,
            "line": start,
            "text": message[:200],
        })

    outputs = []
    for rule_id, hits in sorted(by_rule.items()):
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", rule_id)[:120] or "rule"
        fname = f"{safe}.json"
        (out_dir / fname).write_text(
            json.dumps({
                "schema_version": 1,
                "pattern_id":     rule_id,
                "pattern":        rule_id,
                "description":    "semgrep rule hit",
                "expected_role":  "input_source",
                "lang_group":     "semgrep",
                "match_count":    len(hits),
                "matches":        hits,
            }, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        outputs.append({
            "name":         rule_id,
            "output_file":  fname,
            "result_count": len(hits),
        })

    index_doc = {
        "schema_version":       1,
        "sensor":               "semgrep",
        "sensor_version":       _semgrep_version(),
        "audit_family":         family,
        "ran_at":               ran_at,
        "inputs": {
            "configs":              configs,
            "target_path":          posix(target),
            "rule_count":           len(by_rule),
            "raw_repo_hits":        len(raw_findings),
            "dropped_as_noise":     dropped_as_noise,
            "total_repo_hits":      len(all_findings),
            "assigned_to_family":   len(findings),
        },
        "outputs":              outputs,
        "executed_target_code": False,
        "errors":               [],
        "notes": [
            f"Ran semgrep configs={configs}.",
            f"Raw repo-wide hits: {len(raw_findings)}; dropped as "
            f"non-security noise: {dropped_as_noise}; remaining: "
            f"{len(all_findings)}; dispatched to {family}: "
            f"{len(findings)} across {len(by_rule)} rules.",
            "Hit assignment uses `check_id` keyword matching against "
            "`_SEMGREP_FAMILY_RULES`; the same hit is NEVER counted under "
            "two families.",
            "Raw repo-wide output preserved as results.json for cross-"
            "family debugging.",
        ],
    }
    (out_dir / "index.json").write_text(
        json.dumps(index_doc, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(
        f"sra: semgrep produced {len(findings)} findings across "
        f"{len(by_rule)} rules.",
        file=sys.stderr,
    )
    return 0


def _load_sensor_hits(sensors_root: Path) -> list[dict]:
    """Load all per-pattern hits from every sensor under sensors_root.

    Reads `sensors/<sensor>/*.json` (excluding index.json) and yields a
    flat list of hit records carrying the sensor name, pattern id, and
    expected role.
    """
    hits: list[dict] = []
    if not sensors_root.is_dir():
        return hits
    for sensor_dir in sorted(sensors_root.iterdir()):
        if not sensor_dir.is_dir():
            continue
        sensor_name = sensor_dir.name
        for f in sorted(sensor_dir.glob("*.json")):
            if f.name == "index.json":
                continue
            try:
                doc = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for m in doc.get("matches", []) or []:
                if not isinstance(m, dict):
                    continue
                path = m.get("path", "")
                if not isinstance(path, str) or not path:
                    continue
                hits.append({
                    "sensor":        sensor_name,
                    "pattern_id":    doc.get("pattern_id", ""),
                    "expected_role": doc.get("expected_role", "input_source"),
                    "lang_group":    doc.get("lang_group", "generic"),
                    "path":          path,
                    "line":          m.get("line", 0),
                    "text":          (m.get("text") or "").strip(),
                })
    return hits


# Priority for resolving conflicting `expected_role` values when the
# same (path, line) is matched by multiple sensors. Lower number = wins.
# Rationale: security-relevant input boundaries trump generic framework
# markers, so when ripgrep flags a file as `framework_marker` and
# semgrep flags the same line as `input_source`, we keep
# `input_source` (the more actionable label for the LLM).
_EXPECTED_ROLE_PRIORITY: dict[str, int] = {
    "input_source":      0,
    "parser_middleware": 1,
    "validator":         2,
    "framework_marker":  3,
}


def _merge_cross_sensor_hits(hits: list[dict]) -> list[dict]:
    """Fuse hits with the same (path, line) from multiple sensors.

    The four sensors (ripgrep / semgrep / ast-grep / future codeql)
    frequently flag the *same* file:line because their pattern corpora
    overlap. Without merging, the LLM that reads the resulting packet
    sees the same code location N times with N different pattern
    descriptions — wasting tokens and inflating apparent hit counts.

    The merge preserves attribution:

    - ``sensors_matched``: ordered list of unique sensors that hit this
      location (e.g. ``["ripgrep", "semgrep", "ast-grep"]``).
    - ``patterns_matched``: list of ``{sensor, pattern_id}`` dicts so
      no provenance is lost. Useful when one specific pattern of one
      sensor is the smoking gun and the others are circumstantial.
    - ``consensus_count``: ``len(sensors_matched)`` — surfaced to the
      LLM as a "[N sensors]" badge so it can prioritise high-consensus
      hits.

    Conflict resolution rules:

    - ``text``: pick the longest among candidates (more context for
      the LLM), capped at 200 chars to avoid blobs.
    - ``expected_role``: priority order via
      :data:`_EXPECTED_ROLE_PRIORITY`. Unknown roles sort last.
    - ``lang_group``: first non-``"generic"`` value wins; fallback to
      ``"generic"`` if every contributor was generic.

    Input shape: list of dicts produced by :func:`_load_sensor_hits`.
    Output shape: same field names plus the three new attribution
    fields; one entry per unique ``(path, line)``.
    """
    by_key: dict[tuple[str, int], dict] = {}

    def _role_priority(r: str) -> int:
        return _EXPECTED_ROLE_PRIORITY.get(r, 99)

    for h in hits:
        path = h.get("path", "")
        line = h.get("line", 0)
        if not isinstance(path, str) or not path:
            continue
        try:
            line_int = int(line)
        except (TypeError, ValueError):
            line_int = 0
        key = (path, line_int)

        sensor_name = h.get("sensor", "?")
        pattern_id  = h.get("pattern_id", "")
        text        = (h.get("text") or "").strip()
        if len(text) > 200:
            text = text[:197] + "..."
        role        = h.get("expected_role", "input_source")
        lang        = h.get("lang_group", "generic")

        if key not in by_key:
            by_key[key] = {
                "path":               path,
                "line":               line_int,
                "text":               text,
                "expected_role":      role,
                "lang_group":         lang,
                "sensors_matched":    [sensor_name],
                "patterns_matched":   [
                    {"sensor": sensor_name, "pattern_id": pattern_id}
                ],
                "consensus_count":    1,
            }
            continue

        existing = by_key[key]
        # Text: keep the longer one (more context for the LLM).
        if len(text) > len(existing["text"]):
            existing["text"] = text
        # expected_role: priority order.
        if _role_priority(role) < _role_priority(existing["expected_role"]):
            existing["expected_role"] = role
        # lang_group: first non-generic wins.
        if existing["lang_group"] == "generic" and lang != "generic":
            existing["lang_group"] = lang
        # sensors_matched: dedupe by sensor name (one sensor may have
        # fired multiple patterns for the same line; we count it once
        # in sensors_matched but record every pattern).
        if sensor_name not in existing["sensors_matched"]:
            existing["sensors_matched"].append(sensor_name)
            existing["consensus_count"] = len(existing["sensors_matched"])
        # patterns_matched: dedupe by (sensor, pattern_id).
        new_pattern = {"sensor": sensor_name, "pattern_id": pattern_id}
        if new_pattern not in existing["patterns_matched"]:
            existing["patterns_matched"].append(new_pattern)

    return list(by_key.values())


def _cluster_sensor_hits(hits: list[dict]) -> list[dict]:
    """Group hits by (parent-directory, role). Returns clusters ordered by
    role priority (production > example > test > docs > vendor), then by
    descending total consensus (high-consensus clusters first within the
    same role), then by directory path.

    Expects ``hits`` to already be merged across sensors via
    :func:`_merge_cross_sensor_hits` — each hit has ``consensus_count``,
    ``sensors_matched``, ``patterns_matched``. The cluster's
    ``total_consensus`` is the sum of its hits' ``consensus_count`` and
    drives the secondary sort: clusters where multiple sensors concur on
    many lines should investigate first.

    The cluster also tracks ``raw_hit_count`` (sum of consensus_count =
    total pre-dedup hit volume the cluster represents) alongside
    ``hit_count`` (unique-by-line count after dedup) so the packet
    builder can surface both numbers in the index.
    """
    by_key: dict[tuple[str, str], list[dict]] = {}
    for h in hits:
        role = _classify_path_role(h["path"])
        h["role"] = role
        parent = posix(Path(h["path"]).parent)
        if parent in ("", "."):
            parent = "(root)"
        by_key.setdefault((parent, role), []).append(h)

    role_order = {
        "production":         0,
        "example":            1,
        "test":               2,
        "docs":               3,
        "generated_or_vendor": 4,
    }
    clusters: list[dict] = []
    for (parent, role), items in by_key.items():
        files = sorted({h["path"] for h in items})
        total_consensus = sum(
            int(h.get("consensus_count", 1)) for h in items
        )
        clusters.append({
            "directory":       parent,
            "role":            role,
            "files":           files,
            "hits":            items,
            "hit_count":       len(items),
            "raw_hit_count":   total_consensus,
            "total_consensus": total_consensus,
            "file_count":      len(files),
        })
    # Sort: role priority first, then high-consensus first within role,
    # then directory alphabetically for determinism.
    clusters.sort(key=lambda c: (
        role_order.get(c["role"], 9),
        -c["total_consensus"],
        c["directory"],
    ))
    return clusters


_SENSOR_ROLE_TITLES = {
    "input_source":      "Input source hits",
    "parser_middleware": "Parser / middleware hits",
    "validator":         "Validator / schema hits",
    "framework_marker":  "Framework markers",
}
_SENSOR_ROLE_ORDER = (
    "framework_marker",
    "input_source",
    "parser_middleware",
    "validator",
)


def _fold_hits_by_function(
    hits: list[dict], repo_root: Path | None,
) -> tuple[list[dict], list[dict]]:
    """Group hits by `(file, enclosing function name)`. Returns
    `(folded_groups, ungrouped_hits)`.

    `folded_groups`: list of dicts `{file, function, hits: [...]}` for
    files where at least 2 hits share the same enclosing function.

    `ungrouped_hits`: hits whose function couldn't be detected OR which
    were the only hit in their function (no point folding a group of 1).

    When `repo_root` is None, returns `([], hits)` — fold is opt-in to
    contexts where we know the absolute paths to read the source files.
    """
    if not repo_root or not hits:
        return [], list(hits)
    # Group by (file, function) where function is detected
    by_func: dict[tuple[str, str], list[dict]] = {}
    no_func: list[dict] = []
    for h in hits:
        path = h.get("path", "")
        line = h.get("line", 0)
        if not path or not isinstance(line, int):
            no_func.append(h)
            continue
        fn = _function_for_hit(repo_root, path, line)
        if not fn:
            no_func.append(h)
            continue
        by_func.setdefault((path, fn), []).append(h)
    folded: list[dict] = []
    for (path, fn), group in by_func.items():
        if len(group) >= 2:
            folded.append({"file": path, "function": fn, "hits": group})
        else:
            # Solo hit in this function — render as singleton
            no_func.extend(group)
    return folded, no_func


def _render_sensor_packet_md(
    packet_id: str,
    family: str,
    repo_name: str,
    cluster: dict,
    family_questions: list[str],
    repo_root_for_render: Path | None = None,
) -> str:
    lines: list[str] = []
    out = lines.append

    out(f"# {packet_id} — {family} — {repo_name}")
    out("")
    out("> Generated from sensor output under "
        "`.audit/03-evidence/<family>/sensors/`.")
    out("> Each item below is a **sensor hit** — a low-precision textual or "
        "syntactic match. Sensor hits are **investigation seeds, not "
        "findings**. No LLM has reviewed this code yet.")
    out("")

    out("## Cluster")
    out("")
    out(f"- Primary directory: `{cluster['directory']}`")
    out(f"- Primary role: `{cluster['role']}`")
    out(f"- Files in cluster: {cluster['file_count']}")
    out(f"- Unique sensor hits (after cross-sensor dedup): {cluster['hit_count']}")
    raw = cluster.get("raw_hit_count", cluster["hit_count"])
    if raw != cluster["hit_count"]:
        out(f"- Raw sensor hits (pre-dedup, sum of consensus): {raw}")
    # Surface the multi-sensor agreement signal explicitly: how many
    # of this cluster's lines were flagged by 2+ sensors. The LLM
    # uses this to prioritise — high-consensus lines are far more
    # likely to be real than singleton hits.
    multi = sum(1 for h in cluster["hits"] if int(h.get("consensus_count", 1)) >= 2)
    if multi > 0:
        out(f"- Lines with multi-sensor consensus (≥2 sensors agreed): {multi}")
    # Surface micro-cluster fold attribution: if this packet absorbed
    # micros from nearby directories, the LLM should know to read
    # those too — not just the primary directory.
    folded = cluster.get("folded_in") or []
    if folded:
        out(f"- Micro-clusters folded in: {len(folded)} (see list below)")
    out("")
    if folded:
        out("### Folded-in micro-clusters")
        out("")
        out("These directories had too few sensor hits to warrant their "
            "own packet, but share a common ancestor with this cluster. "
            "Their hits are included in the cluster above. Investigate "
            "them as part of the same review:")
        out("")
        for f in folded[:20]:
            d = f.get("directory", "(unknown)")
            hc = f.get("hit_count", 0)
            fc = f.get("file_count", 0)
            anc = f.get("common_ancestor", "")
            out(f"- `{d}` — {hc} hits, {fc} file(s)"
                + (f" (common ancestor: `{anc}`)" if anc else ""))
        if len(folded) > 20:
            out(f"- _({len(folded) - 20} more folded micros omitted; full list in packet-index.json)_")
        out("")

    by_role: dict[str, list[dict]] = {}
    for h in cluster["hits"]:
        by_role.setdefault(h["expected_role"], []).append(h)

    # Short sensor name aliases for the consensus badge — keeps the
    # `[3 sensors: rg+sg+ag]` form compact even with codeql in the mix.
    sensor_abbrev = {
        "ripgrep":  "rg",
        "semgrep":  "sg",
        "ast-grep": "ag",
        "codeql":   "cq",
    }

    def _hit_attribution(h: dict) -> str:
        """Render the sensor/pattern attribution for one hit line.

        Two modes:
        - 1 sensor (most common today): keep the legacy single-pattern
          form `sensor:pattern_id` for backward compatibility with
          existing report parsers + readers.
        - 2+ sensors (the cross-sensor consensus case): show a compact
          badge `[N sensors: rg+sg+ag]` so the LLM sees the agreement
          at a glance. Pattern ids are still in `patterns_matched`
          inside the source JSON but kept out of the markdown to avoid
          a verbose dump.
        """
        # Prefer merged-hit fields, fall back to legacy single-sensor.
        sensors = h.get("sensors_matched") or [h.get("sensor", "?")]
        if len(sensors) == 1:
            patterns = h.get("patterns_matched")
            if patterns:
                pid = patterns[0].get("pattern_id", "")
                sensor = patterns[0].get("sensor", sensors[0])
            else:
                pid = h.get("pattern_id", "")
                sensor = sensors[0]
            return f"`{sensor}:{pid}`"
        # Consensus case: 2+ sensors agreed on this line.
        abbrev = [sensor_abbrev.get(s, s) for s in sensors]
        return f"`[{len(sensors)} sensors: {'+'.join(abbrev)}]`"

    for role_key in _SENSOR_ROLE_ORDER:
        if role_key not in by_role:
            continue
        items = by_role[role_key]
        title = _SENSOR_ROLE_TITLES.get(role_key, role_key)
        # Function-level fold: group hits by (file, enclosing function).
        # Hits within the same function rarely need separate investigation
        # — same context, same data flow, same root cause. We collapse
        # them into one "interest point" with multiple line refs.
        # Hits whose function can't be detected fall back to per-line
        # rendering (legacy behaviour).
        folded_groups, ungrouped = _fold_hits_by_function(items, repo_root_for_render)
        total_shown_units = len(folded_groups) + len(ungrouped)
        fold_saved = len(items) - total_shown_units
        head = f"## {title} ({len(items)})"
        if fold_saved > 0:
            head += f" — {len(folded_groups)} function group(s) + {len(ungrouped)} singleton(s) [function-fold saved {fold_saved} repeat entries]"
        out(head)
        out("")
        # Sort within the section: high-consensus hits first so the
        # LLM reads the strong-signal ones before the singletons.
        # For folded groups, use the highest-consensus hit as the
        # sort key; for ungrouped, use the hit directly.
        def _group_sort_key(group_or_hit):
            if isinstance(group_or_hit, dict) and "hits" in group_or_hit:
                hits = group_or_hit["hits"]
                max_consensus = max((int(h.get("consensus_count", 1)) for h in hits), default=1)
                first = hits[0]
                return (-max_consensus, first.get("path", ""), min(h.get("line", 0) for h in hits))
            h = group_or_hit
            return (-int(h.get("consensus_count", 1)), h.get("path", ""), h.get("line", 0))

        all_units = sorted(folded_groups + ungrouped, key=_group_sort_key)
        shown = all_units[:MAX_SENSOR_HITS_PER_SECTION]
        for unit in shown:
            if isinstance(unit, dict) and "hits" in unit:
                # Folded group: 1 line summarizing N hits in same function
                hits = unit["hits"]
                func_name = unit.get("function", "?")
                file_path = unit.get("file", hits[0].get("path", ""))
                line_refs = sorted({h.get("line", 0) for h in hits})
                # First-line preview text (the most-consensus hit's text)
                hits_sorted_for_text = sorted(hits, key=lambda h: -int(h.get("consensus_count", 1)))
                text = hits_sorted_for_text[0].get("text", "")
                if len(text) > 140:
                    text = text[:137] + "..."
                # Aggregate attribution: union of sensors across the group
                all_sensors: set[str] = set()
                for h in hits:
                    all_sensors.update(h.get("sensors_matched") or [h.get("sensor", "?")])
                if len(all_sensors) > 1:
                    abbrev = sorted(sensor_abbrev.get(s, s) for s in all_sensors)
                    attrib = f"`[{len(all_sensors)} sensors: {'+'.join(abbrev)}]`"
                else:
                    attrib = _hit_attribution(hits_sorted_for_text[0])
                lines_str = ",".join(str(ln) for ln in line_refs[:8])
                if len(line_refs) > 8:
                    lines_str += f",…(+{len(line_refs) - 8})"
                out(
                    f"- `{file_path}` function `{func_name}()` lines {lines_str} "
                    f"— {len(hits)} hits — {attrib} — `{text}`"
                )
            else:
                # Singleton hit (function not detected)
                h = unit
                text = h["text"]
                if len(text) > 140:
                    text = text[:137] + "..."
                attrib = _hit_attribution(h)
                out(
                    f"- `{h['path']}:{h['line']}` — {attrib} — `{text}`"
                )
        if len(all_units) > len(shown):
            out(
                f"- _({len(all_units) - len(shown)} more groups/hits "
                f"omitted; raw sensor output has them all.)_"
            )
        out("")

    # Hits whose expected_role is not one of the four known ones
    other_roles = [r for r in by_role if r not in _SENSOR_ROLE_ORDER]
    for role_key in sorted(other_roles):
        items = by_role[role_key]
        # Same function-level fold as above (legacy behaviour for
        # uncategorised roles: keep the rendering simple but still
        # benefit from the grouping when functions are detectable).
        folded_groups, ungrouped = _fold_hits_by_function(items, repo_root_for_render)
        head = f"## Other hits ({role_key}) ({len(items)})"
        if (len(items) - len(folded_groups) - len(ungrouped)) > 0:
            head += f" — folded into {len(folded_groups)} group(s) + {len(ungrouped)} singleton(s)"
        out(head)
        out("")
        all_units = sorted(
            folded_groups + ungrouped,
            key=lambda g: (
                -(max((int(h.get("consensus_count", 1)) for h in g["hits"]), default=1) if isinstance(g, dict) and "hits" in g else int(g.get("consensus_count", 1))),
            ),
        )
        for unit in all_units[:MAX_SENSOR_HITS_PER_SECTION]:
            if isinstance(unit, dict) and "hits" in unit:
                hits = unit["hits"]
                fp = unit.get("file", hits[0].get("path", ""))
                fn = unit.get("function", "?")
                line_refs = sorted({h.get("line", 0) for h in hits})
                text = hits[0].get("text", "")
                if len(text) > 140:
                    text = text[:137] + "..."
                lines_str = ",".join(str(ln) for ln in line_refs[:8])
                if len(line_refs) > 8:
                    lines_str += f",…(+{len(line_refs) - 8})"
                out(
                    f"- `{fp}` function `{fn}()` lines {lines_str} "
                    f"— {len(hits)} hits — `{text}`"
                )
            else:
                h = unit
                text = h["text"]
                if len(text) > 140:
                    text = text[:137] + "..."
                attrib = _hit_attribution(h)
                out(
                    f"- `{h['path']}:{h['line']}` — {attrib} — `{text}`"
                )
        out("")

    out(f"## Files in cluster ({cluster['file_count']})")
    out("")
    shown_files = cluster["files"][:MAX_SENSOR_FILES_PER_CLUSTER]
    for f in shown_files:
        out(f"- `{f}`")
    if len(cluster["files"]) > len(shown_files):
        out(f"- _({len(cluster['files']) - len(shown_files)} more files "
            f"in this cluster.)_")
    out("")

    out("## Questions for the Claude skill")
    out("")
    if family_questions:
        for q in family_questions:
            out(f"- {q}")
    else:
        out("_(no first_questions registered for this family)_")
    out("")

    out("## Investigation guidance (for the skill)")
    out("")
    out("- This packet is a **seed for investigation**, not a list of "
        "findings. Each sensor hit may or may not represent a real risk.")
    out("- Use `Read` to open the files listed and inspect the surrounding "
        "code, not just the matched lines.")
    out("- Use `Grep` and `Glob` to follow imports, locate the validators "
        "called from these files, find related routes, and confirm whether "
        "any claimed protection actually applies.")
    out("- Consult tests (under `test/`, `tests/`, `__tests__/`, `spec/`) "
        "to understand the intended validation contract at this boundary.")
    out("- Do NOT report a finding unless you have read enough code to be "
        "confident the issue is real. Cite the `file:line` you verified, "
        "not the sensor hit you started from.")
    out("- Be explicit about what you could **not** determine. A sensor hit "
        "on `req.body` in a route handler is a place to look, not a "
        "vulnerability.")
    out("")

    return "\n".join(lines) + "\n"


# Per-language regex to locate a function/method definition. We use a
# simple "walk backward from hit.line until we find a function-header
# line" heuristic to attach each hit to its enclosing function. This is
# imperfect (won't handle anonymous closures, nested functions, etc) but
# good enough for the redundancy-reduction goal: hits that share an
# obvious enclosing function don't need separate investigation effort.
_FUNCTION_DECL_RE: dict[str, list[str]] = {
    # PHP — functions, methods, anonymous/arrow functions don't capture.
    ".php":   [r"\bfunction\s+(\w+)\s*\(", r"(?:public|private|protected|static)\s+(?:static\s+)?function\s+(\w+)\s*\("],
    # JS/TS
    ".js":    [r"\bfunction\s+(\w+)\s*\(", r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\()", r"(\w+)\s*:\s*(?:async\s+)?function", r"(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{"],
    ".jsx":   [r"\bfunction\s+(\w+)\s*\(", r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\()"],
    ".ts":    [r"\bfunction\s+(\w+)\s*\(", r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\()", r"(?:public|private|protected|static|async)\s+(\w+)\s*\("],
    ".tsx":   [r"\bfunction\s+(\w+)\s*\(", r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\()"],
    ".mjs":   [r"\bfunction\s+(\w+)\s*\(", r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\()"],
    ".cjs":   [r"\bfunction\s+(\w+)\s*\(", r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\()"],
    # Python
    ".py":    [r"\bdef\s+(\w+)\s*\(", r"\basync\s+def\s+(\w+)\s*\("],
    # Go
    ".go":    [r"\bfunc\s+(?:\([^)]+\)\s+)?(\w+)\s*\("],
    # Java / Kotlin / Scala / C#
    ".java":  [r"(?:public|private|protected|static|final|synchronized|abstract|\s)+\s+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws[^{]+)?\{"],
    ".kt":    [r"\bfun\s+(?:[\w<>]+\.)?(\w+)\s*\("],
    ".kts":   [r"\bfun\s+(?:[\w<>]+\.)?(\w+)\s*\("],
    ".scala": [r"\bdef\s+(\w+)\s*[\[(]"],
    ".cs":    [r"(?:public|private|protected|internal|static|virtual|override|async|\s)+\s+[\w<>\[\]]+\s+(\w+)\s*\("],
    # Ruby
    ".rb":    [r"\bdef\s+(?:self\.)?(\w+)"],
    # Rust
    ".rs":    [r"\bfn\s+(\w+)\s*[\(<]"],
    # C / C++
    ".c":     [r"^\s*(?:static\s+|inline\s+)*[\w\s\*]+\s+(\w+)\s*\([^)]*\)\s*\{?\s*$"],
    ".cpp":   [r"^\s*(?:static\s+|inline\s+|virtual\s+)*[\w:\s\*<>]+\s+(?:\w+::)?(\w+)\s*\([^)]*\)\s*(?:const)?\s*\{?\s*$"],
    ".cc":    [r"^\s*(?:static\s+|inline\s+|virtual\s+)*[\w:\s\*<>]+\s+(?:\w+::)?(\w+)\s*\([^)]*\)\s*(?:const)?\s*\{?\s*$"],
    ".h":     [r"^\s*(?:static\s+|inline\s+)*[\w\s\*]+\s+(\w+)\s*\([^)]*\)\s*\{?\s*$"],
    ".hpp":   [r"^\s*(?:static\s+|inline\s+|virtual\s+)*[\w:\s\*<>]+\s+(?:\w+::)?(\w+)\s*\([^)]*\)\s*(?:const)?\s*\{?\s*$"],
    # Swift
    ".swift": [r"\bfunc\s+(\w+)\s*[\(<]"],
}

# Cache: (file_abs_path) → list of (function_name, line). Read-once
# per file; many hits on the same file share the function map.
_FUNCTION_MAP_CACHE: dict[str, list[tuple[str, int]]] = {}


def _function_for_hit(repo_root: Path, rel_path: str, line: int) -> str | None:
    """Best-effort: return the name of the function that contains
    `rel_path:line`, or None if we can't tell.

    Walks the file once (cached), collects every line that looks like a
    function declaration, and returns the most recent function whose
    declaration line is at or before `line`. False positives (e.g. a
    nested closure picking the outer function) are tolerable for the
    redundancy-reduction goal: the worst case is over-grouping.
    """
    if not rel_path or not isinstance(line, int) or line <= 0:
        return None
    suffix = Path(rel_path).suffix.lower()
    patterns = _FUNCTION_DECL_RE.get(suffix)
    if not patterns:
        return None
    abs_path = str((repo_root / rel_path).resolve())
    if abs_path not in _FUNCTION_MAP_CACHE:
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            _FUNCTION_MAP_CACHE[abs_path] = []
            return None
        decls: list[tuple[str, int]] = []
        compiled = [re.compile(p) for p in patterns]
        for ln_idx, ln_text in enumerate(content.splitlines(), start=1):
            for pat in compiled:
                m = pat.search(ln_text)
                if m:
                    name = m.group(1)
                    if name and not name.startswith("_test_"):
                        decls.append((name, ln_idx))
                        break
        _FUNCTION_MAP_CACHE[abs_path] = decls
    decls = _FUNCTION_MAP_CACHE[abs_path]
    if not decls:
        return None
    # Find the function whose decl line is the LARGEST <= `line`.
    candidate = None
    for name, decl_line in decls:
        if decl_line <= line:
            candidate = name
        else:
            break
    return candidate


def _annotate_cross_family_overlap(target: Path, families: list[str]) -> None:
    """Annotate every PACKET-NNN.md with cross-family file/pattern overlap.

    Post-pass after ALL families have built packets. For each packet,
    appends a `## Cross-family overlap` section listing files and
    pattern_ids that ALSO appear in other family packets. The LLM
    investigating a packet sees the cross-references and can use the
    Read tool to skim the other family's findings.md (when ready) to
    avoid duplicating investigation effort.

    Strictly additive — does NOT drop, merge, or modify the actual
    hits or the packet's family assignment. Worst case (overlap data
    has noise): the LLM ignores the annotation.
    """
    # Build per-(file → [(family, packet_id)]) and per-(pattern_id →
    # [(family, packet_id)]) maps across ALL families.
    file_to_packets: dict[str, list[tuple[str, str]]] = {}
    pattern_to_packets: dict[str, list[tuple[str, str]]] = {}

    family_indexes: dict[str, dict] = {}
    for fam in families:
        slug = _family_slug(fam)
        idx_path = target / ".audit" / "04-packets-sensors" / slug / "packet-index.json"
        if not idx_path.is_file():
            continue
        try:
            family_indexes[fam] = json.loads(idx_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for p in family_indexes[fam].get("packets", []):
            pid = p.get("id", "")
            if not pid:
                continue
            for f in p.get("files", []) or []:
                file_to_packets.setdefault(f, []).append((fam, pid))

    # Pattern overlap requires reading the per-pattern JSON under
    # 03-evidence; cheap because we only enumerate index.json metadata.
    for fam in families:
        slug = _family_slug(fam)
        sensors_root = target / ".audit" / "03-evidence" / slug / "sensors"
        if not sensors_root.is_dir():
            continue
        idx = family_indexes.get(fam)
        if not idx:
            continue
        # Map packets to their pattern_ids: load sensors/<sensor>/<pid>.json
        # files and aggregate. Skip if mapping is too expensive.
        for sensor_dir in sensors_root.iterdir():
            if not sensor_dir.is_dir():
                continue
            for pat_file in sensor_dir.glob("*.json"):
                if pat_file.name == "index.json":
                    continue
                try:
                    pat_doc = json.loads(pat_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                pid = pat_doc.get("pattern_id", "")
                if not pid:
                    continue
                # Which packets cover the matched files of this pattern?
                matched_files = {m.get("path", "") for m in (pat_doc.get("matches") or []) if isinstance(m, dict)}
                packets_seen: set[str] = set()
                for f in matched_files:
                    for fam2, pid2 in file_to_packets.get(f, []):
                        if fam2 == fam:
                            packets_seen.add(pid2)
                for ppid in packets_seen:
                    pattern_to_packets.setdefault(pid, []).append((fam, ppid))

    # Now re-write each packet markdown with the annotation appended.
    annotated_count = 0
    for fam in families:
        slug = _family_slug(fam)
        idx = family_indexes.get(fam)
        if not idx:
            continue
        packets_dir = target / ".audit" / "04-packets-sensors" / slug
        for p in idx.get("packets", []):
            pid = p.get("id", "")
            md_path = packets_dir / f"{pid}.md"
            if not md_path.is_file():
                continue
            this_files = set(p.get("files", []) or [])
            # Compute cross-family files (files in this packet that
            # ALSO appear in a DIFFERENT family's packet)
            cross_file_refs: dict[str, list[str]] = {}  # file -> list of "family/PID"
            for f in this_files:
                others = [
                    f"{f2}/{pid2}" for (f2, pid2) in file_to_packets.get(f, [])
                    if f2 != fam
                ]
                if others:
                    cross_file_refs[f] = sorted(set(others))[:5]
            if not cross_file_refs:
                continue  # nothing to annotate for this packet
            try:
                existing = md_path.read_text(encoding="utf-8")
            except OSError:
                continue
            # Strip any previous annotation (idempotency on re-run)
            sentinel = "\n## Cross-family overlap (advisory)\n"
            cut_at = existing.find(sentinel)
            if cut_at != -1:
                existing = existing[:cut_at].rstrip() + "\n"
            # Compose the annotation
            lines = ["", "## Cross-family overlap (advisory)", ""]
            lines.append(
                "> The files listed below are ALSO investigated by other "
                "family packets in this audit. To avoid duplicating "
                "investigation effort, you MAY read the corresponding "
                "`<family>/PACKET-<id>.findings.md` (once produced) to see "
                "what those skills concluded — your job is to add this "
                "family's angle, not re-derive theirs."
            )
            lines.append("")
            for f, refs in sorted(cross_file_refs.items()):
                lines.append(f"- `{f}` — also in: " + ", ".join(f"`{r}`" for r in refs))
            lines.append("")
            new_content = existing.rstrip() + "\n" + "\n".join(lines) + "\n"
            try:
                md_path.write_text(new_content, encoding="utf-8")
                annotated_count += 1
            except OSError:
                pass
    if annotated_count:
        print(
            f"sra: cross-family overlap: annotated {annotated_count} packet(s) "
            f"with file-overlap advisory.",
            file=sys.stderr,
        )


# Prompt template for the LLM packet-dedup stage. Sent to claude -p
# once per family. The instructions are deliberately strict +
# conservative: when in doubt, do NOT merge. Output is JSON-only so
# parsing is deterministic.
_LLM_PACKET_DEDUP_PROMPT_TEMPLATE = """You are a packet redundancy detector. Your job is to identify packets in a single audit family that cover the SAME ROOT CAUSE in semantically-equivalent code, so a downstream LLM can investigate them as ONE unit instead of N.

Family: {family}
Repository: {repo_name}
Total packets to analyze: {n_packets}

Each packet below was produced by deterministic clustering of sensor hits (ripgrep / semgrep / ast-grep matches). They live in `{family_slug}/`. For each packet you see:

- ID (`PACKET-NNN`)
- Cluster directory + role + hit count + file count
- Up to 5 files
- Up to 5 representative hits (file:line + matched line text)

================================================================
PACKETS:

{packet_summaries}

================================================================

YOUR TASK: produce a JSON object (and NOTHING else) with this exact schema:

```json
{{
  "merge_groups": [
    {{
      "primary": "PACKET-XXX",
      "merge_into_primary": ["PACKET-YYY", "PACKET-ZZZ"],
      "reason": "one short sentence: why these cover the same root cause"
    }}
  ]
}}
```

If NO merges are warranted, return `{{"merge_groups": []}}`. That's the safe default.

STRICT RULES:

1. **CONSERVATIVE BY DEFAULT.** When uncertain, KEEP packets separate. Merging is irreversible from the LLM-skill-investigation perspective. False negatives (over-merging) cost MORE than false positives (under-merging).

2. A merge is justified ONLY when ALL of these hold:
   a. Packets share the same logical code area (overlapping files OR same module/sub-package OR contiguous parent directories).
   b. Packets target the same security CONCERN type (e.g. all about capability checks, OR all about SQL sinks in DB layer, OR all about input deserialization). Same family is NOT enough — same concern within the family.
   c. A merged investigation would NATURALLY cover every bug a separate investigation would find. No angle gets lost.

3. NEVER merge across unrelated code areas. Example: `admin/Menus/` capability checks + `frontend/Renderer/` capability checks → KEEP SEPARATE. Different attack surfaces.

4. NEVER merge a production cluster with a test/fixtures cluster.

5. The `primary` of each merge group MUST be the packet with the HIGHEST hit count among the group. If tied, the one with the most files. The merged packets' hits will be appended to the primary's findings investigation.

6. A packet appears in AT MOST ONE merge group. No transitive chains (A→B and B→C means just {{primary:A, merge:[B,C]}}).

7. Do NOT propose mergers for packets that look superficially similar but are in entirely different code paths. Same `bug class` is not enough — the code itself must overlap meaningfully.

EXAMPLES OF LEGITIMATE MERGES:

- PACKET-001 (`includes/Admin/Menus`, capability checks across 5 admin pages) + PACKET-005 (`includes/Admin/Menus/Submenu`, capability checks across 3 more pages of the same submenu) → same module, same concern, MERGE with PACKET-001 primary.

- PACKET-010 (`includes/Database/Migrations.php:50` raw SQL) + PACKET-011 (`includes/Database/Migrations.php:80` raw SQL) → same file, same sink class, MERGE.

- PACKET-003 + PACKET-007 + PACKET-009, all in `includes/Auth/` and all about token validation flow → MERGE with the largest as primary.

EXAMPLES OF NON-MERGES (KEEP SEPARATE):

- PACKET-001 (admin auth) + PACKET-002 (REST API auth) — same family, same concern type, but DIFFERENT attack surfaces. Each needs its own investigation.

- PACKET-005 (Forms.php SQL sink) + PACKET-007 (Forms.php XSS sink) — same file, but DIFFERENT bug classes. Different skill mental models needed.

- PACKET-012 (capability checks in admin/) + PACKET-019 (capability checks in lib/) — same family, same concern, but unrelated modules with different threat models.

- Anything where you'd need to manually verify the merge is safe → do NOT merge.

OUTPUT FORMAT: emit only the JSON object, fenced with ```json ... ```. No prose before or after. No "Here is..." preamble.
"""


def _build_packet_summary_for_dedup(
    packets_dir: Path, packet_meta: dict, max_files: int = 5, max_hits: int = 5,
) -> str:
    """One-packet compact summary for the LLM dedup prompt.

    Reads PACKET-NNN.md to extract the top hits but only the lines we
    need (file:line + matched text), so the prompt stays small even on
    repos with 50+ packets per family. Aim: < 800 chars per packet.
    """
    pid = packet_meta.get("id", "?")
    cluster_dir = packet_meta.get("cluster_directory", "?")
    role = packet_meta.get("primary_role", "?")
    hits = packet_meta.get("hit_count", 0)
    files = packet_meta.get("files", []) or []
    file_list = ", ".join(f"`{f}`" for f in files[:max_files])
    if len(files) > max_files:
        file_list += f" (+{len(files) - max_files} more)"

    # Extract top sensor hits from the packet markdown (cheap regex)
    hits_lines: list[str] = []
    md_path = packets_dir / f"{pid}.md"
    if md_path.is_file():
        try:
            md = md_path.read_text(encoding="utf-8")
            # Extract bullet lines that look like "- `path:line` — ... — `text`"
            hit_re = re.compile(
                r"^-\s+`(?P<path>[^`]+:\d+)`\s+—\s+(?P<rest>.+)$",
                re.MULTILINE,
            )
            for m in hit_re.finditer(md):
                if len(hits_lines) >= max_hits:
                    break
                # Truncate rest to avoid bloating the prompt
                rest = m.group("rest")
                if len(rest) > 120:
                    rest = rest[:117] + "..."
                hits_lines.append(f"  - `{m.group('path')}` — {rest}")
        except OSError:
            pass

    parts = [
        f"### {pid}",
        f"- directory: `{cluster_dir}` | role: `{role}` | hits: {hits} | files: {len(files)}",
        f"- top files: {file_list}",
    ]
    if hits_lines:
        parts.append("- top hits:")
        parts.extend(hits_lines)
    return "\n".join(parts)


def _llm_packet_dedup_for_family(
    target: Path,
    family: str,
    *,
    model: str | None = None,
    timeout: int = 240,
) -> list[dict]:
    """One claude -p call to identify semantically-duplicate packets
    within a single family. Returns a list of merge_groups:
    `[{"primary": "PACKET-001", "merge_into_primary": ["PACKET-005"], "reason": "..."}]`.

    Returns `[]` (no merge) on ANY error path: missing packet-index,
    claude unavailable, malformed JSON response, response references
    non-existent packets, etc. Conservative-by-default: when in doubt
    we don't change anything.
    """
    slug = _family_slug(family)
    packets_dir = target / ".audit" / "04-packets-sensors" / slug
    idx_path = packets_dir / "packet-index.json"
    if not idx_path.is_file():
        return []
    try:
        idx = json.loads(idx_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    # Only consider PRODUCTION packets — test/fixtures packets are
    # already skipped by the skill phase, no point asking the LLM to
    # dedup them.
    packets = [
        p for p in (idx.get("packets") or [])
        if p.get("primary_role") == "production"
    ]
    if len(packets) < 2:
        return []

    claude = shutil.which("claude")
    if not claude:
        return []

    summaries = "\n\n".join(
        _build_packet_summary_for_dedup(packets_dir, p) for p in packets
    )

    repo_name = target.name
    prompt = _LLM_PACKET_DEDUP_PROMPT_TEMPLATE.format(
        family=family,
        repo_name=repo_name,
        family_slug=slug,
        n_packets=len(packets),
        packet_summaries=summaries,
    )

    cmd = [claude, "-p"]
    if model:
        cmd.extend(["--model", model])

    env = os.environ.copy()
    env.pop("CLAUDECODE", None)
    env.pop("CLAUDE_CODE_ENTRYPOINT", None)

    try:
        proc = _run_claude_with_heartbeat(
            cmd, input_text=prompt, timeout=timeout,
            cwd=str(target), env=env,
            label=f"packet-dedup({slug}, {len(packets)} packets)",
            capture_mode="final",
        )
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        print(
            f"sra: packet-dedup({slug}): timeout or interrupt — skipping dedup",
            file=sys.stderr,
        )
        return []
    if proc.returncode != 0:
        print(
            f"sra: packet-dedup({slug}): claude returned {proc.returncode} — skipping",
            file=sys.stderr,
        )
        return []

    # Extract JSON from the response. The prompt asks for fenced JSON;
    # tolerate plain-JSON responses too.
    out = proc.stdout or ""
    json_text = None
    fence_re = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL)
    fm = fence_re.search(out)
    if fm:
        json_text = fm.group(1).strip()
    else:
        # Heuristic: find first '{' to last '}' and try to parse.
        first = out.find("{")
        last = out.rfind("}")
        if 0 <= first < last:
            json_text = out[first:last + 1]
    if not json_text:
        return []

    try:
        parsed = json.loads(json_text)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, dict):
        return []
    groups = parsed.get("merge_groups") or []
    if not isinstance(groups, list):
        return []

    # Validate every referenced PACKET-ID exists in this family.
    valid_ids = {p["id"] for p in packets}
    cleaned: list[dict] = []
    seen_pids: set[str] = set()
    for g in groups:
        if not isinstance(g, dict):
            continue
        primary = g.get("primary")
        merges = g.get("merge_into_primary") or []
        reason = g.get("reason") or ""
        if not isinstance(primary, str) or primary not in valid_ids:
            continue
        if not isinstance(merges, list) or not merges:
            continue
        # No primary in merges, no overlap with previous groups
        clean_merges: list[str] = []
        for m in merges:
            if not isinstance(m, str): continue
            if m == primary: continue
            if m not in valid_ids: continue
            if m in seen_pids: continue
            clean_merges.append(m)
        if not clean_merges:
            continue
        if primary in seen_pids:
            continue
        cleaned.append({
            "primary": primary,
            "merge_into_primary": clean_merges,
            "reason": str(reason)[:300],
        })
        seen_pids.add(primary)
        seen_pids.update(clean_merges)
    return cleaned


def _apply_packet_merges(
    target: Path, family: str, merge_groups: list[dict],
) -> int:
    """Apply LLM-decided merges to a family's packet directory.

    For each group, the `primary` packet keeps its position. The merged
    packets are marked with `_merged_into: "PACKET-XXX"` in
    `packet-index.json` so the skill phase skips them. Their on-disk
    `.md` files get a short redirect header but stay readable for human
    inspection. The primary packet's `.md` gets a new section listing
    absorbed packets.

    Returns the number of packets marked-as-merged. Idempotent: re-runs
    with the same merge_groups produce no further changes.
    """
    if not merge_groups:
        return 0
    slug = _family_slug(family)
    packets_dir = target / ".audit" / "04-packets-sensors" / slug
    idx_path = packets_dir / "packet-index.json"
    if not idx_path.is_file():
        return 0
    try:
        idx = json.loads(idx_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    packets = idx.get("packets") or []
    by_id = {p["id"]: p for p in packets if "id" in p}

    merged_count = 0
    for g in merge_groups:
        primary_id = g["primary"]
        merge_ids = g["merge_into_primary"]
        reason = g.get("reason", "")
        primary = by_id.get(primary_id)
        if not primary:
            continue
        absorbed = []
        for mid in merge_ids:
            m_meta = by_id.get(mid)
            if not m_meta:
                continue
            if m_meta.get("_merged_into"):
                continue  # already merged from prior run
            # Mark in index
            m_meta["_merged_into"] = primary_id
            m_meta["_merge_reason"] = reason
            absorbed.append(mid)
            # Rewrite the merged packet's .md with a redirect header
            mpath = packets_dir / f"{mid}.md"
            if mpath.is_file():
                try:
                    body = mpath.read_text(encoding="utf-8")
                except OSError:
                    body = ""
                redirect = (
                    f"> ⚠️  **This packet was merged into [{primary_id}]({primary_id}.md)** by "
                    f"the LLM packet-dedup stage. The skill phase will NOT investigate it "
                    f"separately — its hits are considered absorbed by the primary packet.\n"
                    f">\n"
                    f"> **Reason:** {reason}\n"
                    f">\n"
                    f"> The original packet content is preserved below for traceability.\n"
                    f"\n"
                    f"---\n\n"
                )
                if not body.startswith("> ⚠️"):
                    try:
                        mpath.write_text(redirect + body, encoding="utf-8")
                    except OSError:
                        pass
            merged_count += 1
        if absorbed:
            # Annotate primary packet with absorbed list
            primary["_absorbed"] = (primary.get("_absorbed") or []) + absorbed
            ppath = packets_dir / f"{primary_id}.md"
            if ppath.is_file():
                try:
                    body = ppath.read_text(encoding="utf-8")
                except OSError:
                    body = ""
                marker = "\n## Packets absorbed by LLM dedup\n"
                # Idempotency: strip prior marker block
                cut = body.find(marker)
                if cut != -1:
                    body = body[:cut].rstrip() + "\n"
                lines = ["", marker.lstrip("\n").rstrip("\n"), ""]
                lines.append(
                    "> An intermediate LLM dedup stage determined that the following "
                    "packets cover the same root cause as this one. They have been "
                    "marked merged-into-this; you should investigate ALL of their "
                    "files and hits together as a single review unit."
                )
                lines.append("")
                lines.append(f"**Merge reason:** {reason}")
                lines.append("")
                lines.append("**Absorbed packets:**")
                for ab in absorbed:
                    ab_meta = by_id.get(ab, {})
                    ab_dir = ab_meta.get("cluster_directory", "?")
                    ab_files = ab_meta.get("file_count", 0)
                    ab_hits = ab_meta.get("hit_count", 0)
                    lines.append(
                        f"- `{ab}.md` — directory `{ab_dir}` "
                        f"({ab_files} file(s), {ab_hits} hits)"
                    )
                lines.append("")
                try:
                    ppath.write_text(body.rstrip() + "\n" + "\n".join(lines) + "\n", encoding="utf-8")
                except OSError:
                    pass

    # Write updated index
    try:
        idx_path.write_text(
            json.dumps(idx, indent=2, ensure_ascii=False), encoding="utf-8",
        )
    except OSError:
        pass
    return merged_count


def cmd_build_packets_from_sensors(
    repo_path_str: str,
    family: str,
    *,
    cap_override: int | None = None,
    micro_fold_threshold: int | None = 10,
    lang_filter: "LanguageFilter | None" = None,
) -> int:
    """Cluster sensor hits into review packets for one family.

    Two post-clustering passes shape the final packet list:

    1. **Micro-cluster fold** (``micro_fold_threshold``): clusters with
       fewer than ``micro_fold_threshold`` hits get merged into their
       nearest sibling (same role, longest common ancestor directory).
       Reduces over-fragmentation on deep Java/Spring package layouts.
       Set to ``None`` or ``0`` to disable. Default: 10 (empirically
       safe — see ``scripts/simulate_cluster_fold_corpus.py``).

    2. **Packet count cap** (``cap_override``): bounds total LLM cost.
       Three-tiered:

       - ``cap_override=None`` (default): adaptive cap from
         :func:`_adaptive_packet_cap` based on the repo's file count.
       - ``cap_override=0``: **no cap**. Used when ``sra audit
         --family X`` signals user-intent to focus.
       - ``cap_override=N > 0``: explicit numeric cap. Reserved for
         a future ``--max-packets N`` flag.
    """
    if family not in SENSOR_SUPPORTED_FAMILIES:
        supported = ", ".join(sorted(SENSOR_SUPPORTED_FAMILIES))
        print(
            f"error: --family {family!r} is not supported.\n"
            f"       supported: {supported}",
            file=sys.stderr,
        )
        return 4

    repo_path = Path(repo_path_str).expanduser()
    if not repo_path.is_dir():
        print(f"error: not a directory: {repo_path}", file=sys.stderr)
        return 2

    target = repo_path.resolve()
    family_slug = _family_slug(family)
    sensors_root = (
        target / ".audit" / "03-evidence" / family_slug / "sensors"
    )
    if not sensors_root.is_dir():
        print(
            f"error: no sensor output at {sensors_root}\n"
            f"       run 'sra run-sensor --family {family} "
            f"--sensor ripgrep' first.",
            file=sys.stderr,
        )
        return 2

    raw_hits = _load_sensor_hits(sensors_root)
    # Safety-net language filter: even if the sensor stage was run
    # without --only-lang/--exclude-lang (e.g. a resumed audit reusing
    # old sensor output), drop hits whose file extension is outside
    # the requested language scope before clustering.
    if lang_filter is not None and lang_filter.is_active:
        filtered, dropped = lang_filter.filter_hits(raw_hits)
        if dropped:
            print(
                f"sra: packet-builder ({family}): lang-filter dropped "
                f"{dropped} of {len(raw_hits)} sensor hits "
                f"({lang_filter.describe()}).",
                file=sys.stderr,
            )
        raw_hits = filtered
    # Fold cross-sensor duplicates BEFORE clustering. Without this, the
    # same file:line flagged by ripgrep + semgrep + ast-grep (and soon
    # codeql) appears three or four times in the packet markdown,
    # wasting LLM tokens and obscuring the consensus signal.
    hits = _merge_cross_sensor_hits(raw_hits)
    clusters = _cluster_sensor_hits(hits)

    # Micro-cluster fold: merge clusters with very few hits into their
    # nearest sibling (same role, longest common ancestor directory).
    # On deep Java/Spring layouts the (parent_dir, role) clustering
    # over-fragments — a single sensor hit in a deep package becomes
    # its own LLM call. The fold consolidates these into one investigation
    # while preserving every hit + attribution.
    folded_count = 0
    if micro_fold_threshold and micro_fold_threshold > 0:
        before_count = len(clusters)
        clusters = _fold_micro_clusters(
            clusters, min_hits=micro_fold_threshold,
        )
        folded_count = before_count - len(clusters)
        if folded_count > 0:
            print(
                f"sra: micro-fold (threshold={micro_fold_threshold}): "
                f"{before_count} clusters -> {len(clusters)} "
                f"({folded_count} micros merged into nearest siblings).",
                file=sys.stderr,
            )

    cap, applies = _resolve_packet_cap(target, cap_override)
    truncation_note: str | None = None
    if applies and len(clusters) > cap:
        truncation_note = (
            f"Capped at {cap} packets "
            f"(adaptive: base={MAX_SENSOR_PACKETS_PER_REPO}, "
            f"ceiling={MAX_SENSOR_PACKETS_CEILING}, "
            f"would have produced {len(clusters)}). "
            f"Dropped by (role priority, -total_consensus, directory) — "
            f"i.e. high-consensus production clusters kept first."
        )
        clusters = clusters[:cap]
    elif not applies:
        # No-cap mode. Surface what the user opted into so they're
        # not surprised by the LLM-call count later.
        print(
            f"sra: cap bypassed (--family focused mode); "
            f"{len(clusters)} clusters all become packets.",
            file=sys.stderr,
        )

    # Output goes to a separate directory so the heuristic packets under
    # 04-packets/ remain available as a baseline for comparison.
    out_dir = target / ".audit" / "04-packets-sensors" / family_slug
    if out_dir.exists():
        # Only clean files we own: PACKET-NNN.md and packet-index.json.
        # PACKET-NNN.findings.md are skill outputs and must survive a
        # packet rebuild — otherwise re-running this stage destroys
        # downstream work.
        for f in out_dir.iterdir():
            if not f.is_file():
                continue
            name = f.name
            if name == "packet-index.json" or (
                name.startswith("PACKET-") and name.endswith(".md")
                and not name.endswith(".findings.md")
            ):
                try:
                    f.unlink()
                except OSError:
                    pass
    out_dir.mkdir(parents=True, exist_ok=True)

    family_questions = FAMILY_PLAN.get(family, {}).get(
        "first_questions", []
    )
    repo_name = target.name

    index_entries: list[dict] = []
    new_pids: set[str] = set()
    for n, cluster in enumerate(clusters, 1):
        pid = f"PACKET-{n:03d}"
        new_pids.add(pid)
        md = _render_sensor_packet_md(
            pid, family, repo_name, cluster, family_questions,
            repo_root_for_render=target,
        )
        md_path = out_dir / f"{pid}.md"
        md_path.write_text(md, encoding="utf-8")
        # Multi-sensor consensus metric: count of hits where ≥2 sensors
        # concur. Useful for prioritising packets in dashboards and the
        # Coverage Map's future "high-consensus packets" sub-view.
        multi_consensus = sum(
            1 for h in cluster["hits"]
            if int(h.get("consensus_count", 1)) >= 2
        )
        index_entries.append({
            "id":                  pid,
            "primary_role":        cluster["role"],
            "cluster_directory":   cluster["directory"],
            "files":               cluster["files"][:MAX_SENSOR_FILES_PER_CLUSTER],
            "file_count":          cluster["file_count"],
            "hit_count":           cluster["hit_count"],
            "raw_hit_count":       cluster.get("raw_hit_count", cluster["hit_count"]),
            "multi_consensus_hits": multi_consensus,
            "folded_in":           cluster.get("folded_in", []),
            "markdown_path":       f".audit/04-packets-sensors/{family_slug}/{pid}.md",
            "byte_count":          len(md.encode("utf-8")),
        })

    # Clean up orphan `.findings.md` files: when a re-run produces a
    # SMALLER number of packets (e.g. sensors found less, or a
    # different clustering), the previous run's findings.md files for
    # higher PIDs would still be on disk. Downstream (report.py,
    # 06a, 06b) reads ALL findings.md files in the dir — including
    # those orphans, which reference packets that no longer exist.
    # Drop any `.findings.md` whose pid is not in `new_pids`.
    for f in out_dir.glob("PACKET-*.findings.md"):
        # `PACKET-001.findings.md` -> stem `PACKET-001.findings`
        stem_no_findings = f.stem[:-len(".findings")] \
            if f.stem.endswith(".findings") else f.stem
        if stem_no_findings not in new_pids:
            try:
                f.unlink()
            except OSError:
                pass
    # Same cleanup for `.findings.md.partial` siblings (failed runs).
    for f in out_dir.glob("PACKET-*.findings.md.partial"):
        stem = f.stem
        if stem.endswith(".findings.md"):
            stem = stem[:-len(".findings.md")]
        elif stem.endswith(".findings"):
            stem = stem[:-len(".findings")]
        if stem not in new_pids:
            try:
                f.unlink()
            except OSError:
                pass

    notes = [
        f"Built {len(index_entries)} packets from sensor output.",
        f"Sensor hits considered: {len(raw_hits)} raw → "
        f"{len(hits)} unique (after cross-sensor dedup on path+line).",
        "Packets are seeds for Claude-skill investigation, not findings.",
        "No LLM was invoked at this stage.",
    ]
    if folded_count > 0:
        notes.append(
            f"Micro-cluster fold (min_hits={micro_fold_threshold}): "
            f"{folded_count} micros merged into siblings; "
            f"see `folded_in` field per packet."
        )
    if truncation_note:
        notes.append(truncation_note)

    index_doc = {
        "schema_version":     1,
        "repo_path":          posix(target),
        "family":             family,
        "source_sensor_root": posix(sensors_root),
        "packets":            index_entries,
        "notes":              notes,
    }
    (out_dir / "packet-index.json").write_text(
        json.dumps(index_doc, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        f"sra: built {len(index_entries)} sensor-based packets under "
        f"{out_dir}",
        file=sys.stderr,
    )
    return 0


# Stage 05 (per-repo aggregator) lives in sra.report — imported above.


# === Stage-orchestrator: `sra audit` ========================================
#
# Single-command run of the whole pipeline on a repository. Stages that
# already have output are skipped (resumable). Per-stage errors surface
# but do not abort subsequent stages where reasonable.

def _family_skill_spec(family: str) -> SkillSpec | None:
    """Return the registered family-stage SkillSpec for ``family``, or None.

    Replaces the old hardcoded ``_FAMILY_TO_SKILL_FILE`` dict — the registry
    in :mod:`sra.skill_registry` is the single source of truth for which
    skill (ours or a ToB drop-in) implements each audit family.
    """
    spec = SKILL_REGISTRY.get(family)
    if spec is None or spec.stage != "family" or spec.family != family:
        return None
    return spec


# Keyword triggers for composing ToB crypto sub-skills on top of our
# audit/crypto-auth packet. Keys are skill names registered in
# :data:`sra.skill_registry.SKILL_REGISTRY`; values are the substrings we
# look for in the packet markdown (case-insensitive). A hit on any one of
# the keywords loads the corresponding sub-skill as additional context.
_CRYPTO_SUBSKILL_TRIGGERS: dict[str, tuple[str, ...]] = {
    "constant-time-analysis": (
        "compare", "equal", "hmac", "signature", "timing",
    ),
    "zeroize-audit": (
        "key", "secret", "zero", "secure_erase", "mlock", "free",
    ),
}


def _choose_crypto_subskills(
    packet_text: str,
    target_language: str | list[str] | None = None,
) -> list[str]:
    """Pick which ToB crypto sub-skills to load alongside audit/crypto-auth.

    Inspects ``packet_text`` for keywords from
    :data:`_CRYPTO_SUBSKILL_TRIGGERS` (case-insensitive substring match).
    Returns a list of skill names — empty if no keywords matched, one or
    both of ``constant-time-analysis`` / ``zeroize-audit`` otherwise. The
    order matches the trigger dict insertion order so behaviour is
    deterministic across runs.

    If ``target_language`` is supplied AND the chosen skill declares a
    ``languages`` constraint in its registry entry, the skill is
    dropped when none of the target languages matches. Accepts a single
    string or a list (for polyglot repos). Example: ``zeroize-audit``
    is declared C/C++/Rust-only because managed-memory languages can't
    benefit from manual zeroize semantics — composing it on a pure
    Python/Go crypto packet was just noise.
    """
    lowered = packet_text.lower()
    chosen: list[str] = []
    for skill_name, keywords in _CRYPTO_SUBSKILL_TRIGGERS.items():
        if not any(kw in lowered for kw in keywords):
            continue
        if not _skill_supports_language(skill_name, target_language):
            continue
        chosen.append(skill_name)
    return chosen


def _skill_supports_language(
    skill_name: str,
    target_language: str | list[str] | None,
) -> bool:
    """True iff `skill_name`'s registry entry has no `languages`
    constraint OR ANY of the target languages matches that constraint
    (case- and alias-insensitive).

    `target_language` accepts:
      - None: unknown language → don't filter (returns True).
      - str: single language string (back-compat with old callers).
      - list[str]: ALL languages observed in the repo. Polyglot repos
        (e.g. salazar's Go + TypeScript + Vue) need this — passing
        only the PRIMARY language would exclude skills that legit
        cover one of the secondary ones. ANY match keeps the skill.
    """
    spec = SKILL_REGISTRY.get(skill_name)
    if spec is None or not spec.languages:
        return True
    if not target_language:
        return True

    # Normalise into a set of canonical lowercase names.
    if isinstance(target_language, str):
        targets_raw = [target_language]
    else:
        targets_raw = list(target_language)
    declared = {lang.lower() for lang in spec.languages}

    # Two-way alias resolution. Key: any name we might see (lowercased);
    # value: the canonical set this name maps to. Must include both
    # `js -> javascript` and `javascript -> javascript` shapes so the
    # lookup succeeds whichever side originates from the fingerprint.
    aliases = {
        "javascript":  {"javascript", "js"},
        "js":          {"javascript", "js"},
        "typescript":  {"typescript", "ts"},
        "ts":          {"typescript", "ts"},
        "c++":         {"c++", "cpp"},
        "cpp":         {"c++", "cpp"},
    }

    for raw in targets_raw:
        if not isinstance(raw, str):
            continue
        t = raw.strip().lower()
        if not t:
            continue
        synonym_set = aliases.get(t, {t})
        if declared & synonym_set:
            return True
    return False


# Phase 5: keyword triggers for composing ToB ``dimensional-analysis`` on
# top of audit/business-logic packets. Same shape as
# :data:`_CRYPTO_SUBSKILL_TRIGGERS` for symmetry, even though there is
# only one sub-skill today — business-logic packets that mention numeric
# units / money / time / on-chain denominations are the cases where
# unit-mismatch and decimal-precision findings live.
_BUSINESS_LOGIC_SUBSKILL_TRIGGERS: dict[str, tuple[str, ...]] = {
    "dimensional-analysis": (
        "unit", "precision", "decimal", "bigdecimal",
        "currency", "wei", "gwei", "ether",
        "seconds", "milliseconds", "bigint",
    ),
}


def _choose_business_logic_subskills(
    packet_text: str,
    target_language: str | list[str] | None = None,
) -> list[str]:
    """Pick which ToB sub-skills to load alongside audit/business-logic.

    Mirrors :func:`_choose_crypto_subskills`, including the
    ``languages`` gate: ``dimensional-analysis`` declares
    ``languages=("solidity","vyper","rust")`` since the unit-mismatch
    findings it looks for are DeFi/contract-specific. On a Node.js or
    Python web app the skill would add noise, so it's dropped when
    the repo's primary language isn't on the list.
    """
    lowered = packet_text.lower()
    chosen: list[str] = []
    for skill_name, keywords in _BUSINESS_LOGIC_SUBSKILL_TRIGGERS.items():
        if not any(kw in lowered for kw in keywords):
            continue
        if not _skill_supports_language(skill_name, target_language):
            continue
        chosen.append(skill_name)
    return chosen



# Attribution header prepended to findings.md when the underlying family
# skill comes from Trail of Bits. The skill name is interpolated into both
# the prose and the upstream URL.
_TOB_ATTRIBUTION_TEMPLATE = (
    "<!-- This skill investigation was performed using Trail of Bits' "
    "{name} skill (CC-BY-SA-4.0). See "
    "https://github.com/trailofbits/skills/tree/main/plugins/{name}. -->\n"
)


# Canonical output contract for family-skill packet investigations.
#
# Injected as the first `extra_context_block` for every per-packet skill
# invocation (see cmd_audit skill phase). Gives Claude an authoritative
# template that the downstream aggregator in report.py knows how to
# parse deterministically.
#
# Why this lives in the orchestrator and not in each SKILL.md:
#   - DRY: one source of truth instead of 11 duplicated copies
#   - Parser-coupled: when the parser grows new section types, the
#     contract updates here without touching skill files
#   - Backward compatible: existing SKILL.md "Output" sections still
#     work — this just supersedes any conflicting instruction
#
# The structure mirrors the canonical schema that already worked for
# input-validation / parser-state-machine (## Confirmed issues (N) +
# ### Issue N subsections), now elevated to the strict standard for
# all family skills.
_FINDING_OUTPUT_CONTRACT = """=== OUTPUT CONTRACT (authoritative — supersedes any conflicting instruction in the skill) ===

Your investigation MUST emit a Markdown report to STDOUT with EXACTLY
the structure below. Do NOT use Write/Edit/NotebookEdit — the caller
captures STDOUT. Do NOT include preamble text ("I will now..." /
"Now I have enough...") before the first heading.

```
# {PACKET_ID} — investigation report

## Summary
<2–4 sentences: what was reviewed, what was confirmed, what remained
open. No marketing language, no hype.>

## Confirmed issues (N)
<Replace N with the actual count. If N=0, write "## Confirmed issues (0)"
on its own line followed by "_None._" and SKIP the per-issue subsections.>

### Issue 1: <Short imperative title>
**Severity:** info | low | medium | high | critical
**Verified at:** `path/to/file.ext:LINE` (one or more `file:line` refs)
**Input → sink chain:** <one sentence tracing untrusted input to the sink>
**Why it's real:** <2–4 sentences of evidence — what the code does that
makes this exploitable, citing line numbers>
**Smallest fix:** <one sentence on the minimal change that closes it>

### Issue 2: <...>
<repeat the same five **bold** fields>

## Dismissed sensor hits (M)
<Bulleted list. Each: `path/to/file.ext:LINE` plus ONE sentence on why
it's not a real issue here. M is the count.>

## Limitations / what I could not determine (K)
<Bulleted list. Each: ONE concrete sentence on what static reading could
not answer — cross-module dataflow, runtime-registered handlers, missing
test coverage, third-party trust assumptions, etc.>

## Files read during investigation
<List of file paths and any Grep / Glob queries you ran. Reproducibility
hook for a human reviewer.>
```

STRICT REQUIREMENTS — non-negotiable:

1. The H2 headings MUST be EXACTLY these strings (case-sensitive,
   parenthesized count format):
     `## Summary`
     `## Confirmed issues (N)`        ← N is a digit
     `## Dismissed sensor hits (M)`   ← M is a digit
     `## Limitations / what I could not determine (K)`  ← K is a digit
     `## Files read during investigation`

2. Each confirmed issue MUST be an H3 with the EXACT prefix
   `### Issue <N>:` followed by a short title.
   Do NOT use `### FIND-001`, `### F-1`, `### S-1`, `### Hit N`,
   `### FINDING N`, `### Vulnerability N`, `### 1. Title`, or any
   other variant. Sequential numbering starts at 1.

3. Each confirmed issue MUST include all FIVE bold fields in this
   order: Severity, Verified at, Input → sink chain, Why it's real,
   Smallest fix.

4. Severity uses ONLY the literal tokens `info`, `low`, `medium`,
   `high`, `critical` (lower-case, no synonyms like "med" / "moderate"
   / "sev2" / numeric scales).

5. If your investigation found nothing exploitable, output
   `## Confirmed issues (0)` followed by `_None._` on its own line.
   Do NOT skip the section entirely.

6. Do NOT add additional H2 sections beyond the five above. If you
   need to surface extra context (e.g. an architectural observation
   that's not a confirmed finding), put it as a bullet under
   `## Limitations / what I could not determine`.

Why this contract exists: a downstream aggregator parses every
PACKET-NNN.findings.md deterministically by regex. Any drift from
this structure means findings get DROPPED from the final report — a
real bug we already had to fix once.

=== END OUTPUT CONTRACT ===
"""


def _output_contract_for_packet(packet_id: str) -> str:
    """Materialize the canonical output contract for one packet, with
    `{PACKET_ID}` replaced by the actual id."""
    return _FINDING_OUTPUT_CONTRACT.replace("{PACKET_ID}", packet_id)


def _elected_families(repo_path: Path) -> list[str]:
    """Return the audit/<family> entries that should run for this repo.

    Reads from ``selected-packs.json`` (post route-packs, post deterministic
    backstop) when it exists — that file is the authoritative selection
    after all our deterministic layers have run. Falls back to
    ``fingerprint.json`` when route-packs hasn't run yet (e.g. someone
    invoked the audit family loop before the routing stage, or on an
    older audit dir created before the backstop existed).

    Intersected with ``SENSOR_SUPPORTED_FAMILIES`` so the loop never
    elects a family the sensor layer can't actually catalogue.

    The selection order matters: ``selected-packs.json`` preserves
    fingerprint picks first, then backstop additions appended. The cap
    has already been applied so what we read is exactly what should run.
    """
    sp = repo_path / ".audit" / "01-pack-router" / "selected-packs.json"
    if sp.is_file():
        try:
            d = json.loads(sp.read_text(encoding="utf-8"))
            audit_packs = (d.get("selected_packs") or {}).get("audit") or []
            return [
                p for p in audit_packs
                if isinstance(p, str)
                and p in SENSOR_SUPPORTED_FAMILIES
            ]
        except (OSError, json.JSONDecodeError):
            pass  # fall through to fingerprint
    # Pre-backstop fallback: read directly from the LLM fingerprint.
    fp = repo_path / ".audit" / "00-fingerprint" / "fingerprint.json"
    if not fp.is_file():
        return []
    try:
        d = json.loads(fp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    suggested = d.get("suggested_packs") or []
    return [
        p for p in suggested
        if isinstance(p, str)
        and p.startswith("audit/")
        and p in SENSOR_SUPPORTED_FAMILIES
    ]


def _capped_block(text: str, max_bytes: int = 200_000) -> str:
    """Return `text` capped at `max_bytes` with a truncation marker.

    Used by stage 07 audit-synthesis when packaging artifacts as
    extra_context: a pathological multi-MB findings.md could push
    past the model's context window otherwise. The marker tells
    the synthesizer it was truncated and to use the Read tool for
    the rest of the file.
    """
    if len(text) <= max_bytes:
        return text
    return (
        text[:max_bytes]
        + f"\n\n[... truncated at {max_bytes} bytes; "
        + "open the file via Read for the rest ...]\n"
    )


# Test-only alias so test_latent_fixes can import without going
# through cmd_audit's closure.
_capped_for_test = _capped_block


def _atomic_write_text(path: Path, content: str) -> None:
    """Write `content` to `path` atomically (temp file + os.replace).

    Used for skill outputs: if the process is interrupted mid-write, the
    on-disk file is either the old version or the new one — never a
    partial mix. The skip-if-exists guard then correctly distinguishes
    completed work from in-progress work on resume.

    Side-effect: if a leftover `<path>.partial` exists from a prior
    failed run, it is removed after the successful atomic rename.
    The successful canonical file makes the partial misleading.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)
    # Cleanup stale partial for THIS path (not for unrelated files).
    partial = path.with_suffix(path.suffix + ".partial")
    try:
        partial.unlink()
    except (FileNotFoundError, OSError):
        pass


# --- Interrupt handling -----------------------------------------------------
#
# Long audit runs can take 30+ minutes and the user must be able to abort
# them cleanly with Ctrl+C. The orchestration is multi-layered (asyncio-free
# but threaded for parallel claude calls), so we need a few coordinated
# pieces:
#
#   1. `_INTERRUPTED` — a module-global threading.Event set by SIGINT.
#      Hot loops (family iteration, packet iteration, ThreadPoolExecutor
#      drainage) check it and bail out early.
#
#   2. `_LIVE_PROCS` — registry of currently-running subprocess.Popen objects
#      keyed by id. When SIGINT fires we walk the registry and terminate
#      every live child so the user doesn't have to wait for claude to
#      finish.
#
#   3. `_install_sigint_handler()` — wired at the top of `main()`. The
#      handler is intentionally minimal: set the event, signal live procs.
#      Doing more inside a signal handler is dangerous on Windows where
#      the handler runs on a separate console-control thread.
#
# On a second Ctrl+C we restore the default handler so the user can force
# kill if the orchestrator is stuck somewhere we don't poll the flag.

_INTERRUPTED: threading.Event = threading.Event()
_LIVE_PROCS: dict[int, subprocess.Popen] = {}
_LIVE_PROCS_LOCK: threading.Lock = threading.Lock()


def _sigint_handler(signum, frame) -> None:  # noqa: ARG001
    """Set the interrupt flag and terminate every live child process.

    Idempotent: a second Ctrl+C re-enters and just terminates again.
    After the first interrupt we restore the default SIGINT handler so
    a third Ctrl+C will kill the orchestrator outright.
    """
    if not _INTERRUPTED.is_set():
        print(
            "\n[interrupt] Ctrl+C received — stopping after current step. "
            "Press Ctrl+C again to force-kill.",
            file=sys.stderr, flush=True,
        )
    _INTERRUPTED.set()
    with _LIVE_PROCS_LOCK:
        procs = list(_LIVE_PROCS.values())
    for p in procs:
        try:
            p.terminate()
        except (OSError, ValueError):
            pass
    # After first interrupt, hand control back to the default handler so
    # a second Ctrl+C produces an immediate KeyboardInterrupt traceback.
    try:
        signal.signal(signal.SIGINT, signal.default_int_handler)
    except (ValueError, OSError):
        pass


def _install_sigint_handler() -> None:
    """Register the SIGINT handler. Safe to call multiple times."""
    try:
        signal.signal(signal.SIGINT, _sigint_handler)
    except (ValueError, OSError):
        # Some embedded scenarios disallow signal handlers; ignore.
        pass


def _register_proc(proc: subprocess.Popen) -> None:
    with _LIVE_PROCS_LOCK:
        _LIVE_PROCS[id(proc)] = proc


def _unregister_proc(proc: subprocess.Popen) -> None:
    with _LIVE_PROCS_LOCK:
        _LIVE_PROCS.pop(id(proc), None)


def _extract_assistant_text_from_stream_json(stream: str) -> str:
    """Walk a `claude -p --output-format stream-json` NDJSON capture and
    concatenate every text block emitted by an ``assistant`` message.

    Why this exists: with the default ``--output-format text``, only the
    final assistant message ends up in stdout. Skills like ToB's
    `audit-context-building` produce their analysis incrementally
    across many assistant messages interleaved with tool calls; the
    "final" message ends up being a one-line summary like "The analysis
    above covers ..." while the substantive content is lost.

    The stream-json format emits one JSON object per line; we want every
    ``{"type":"assistant","message":{"content":[{"type":"text",
    "text":"..."}]}}`` block. Any non-text content (tool_use, thinking,
    etc.) is intentionally skipped — we want the prose, not the
    structured tool invocations.

    Falls back to the `result` field of the final ``result`` event if
    parsing yields no assistant text (defensive — should never happen
    on a successful run, but keeps the output non-empty when the stream
    is malformed).
    """
    chunks: list[str] = []
    final_result = ""
    for line in stream.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        otype = obj.get("type")
        if otype == "assistant":
            content = (obj.get("message") or {}).get("content") or []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text") or ""
                    if text.strip():
                        chunks.append(text)
        elif otype == "result":
            result = obj.get("result") or ""
            if isinstance(result, str):
                final_result = result
    # Strip leading conversational intro chunks. With agentic loops
    # claude often emits short planning utterances like "Let me verify
    # the most critical findings by reading the actual source code."
    # before producing the actual report. They pollute the top of the
    # output file. Pattern: short chunk (<300 chars) starting with a
    # first-person planning verb, found ONLY at the leading edge of
    # the stream.
    #
    # Tightening rules vs. an earlier looser version:
    # - "Now I have" alone was too broad ("Now I have a complete
    #   picture..." legitimately opens many context-building reports).
    #   Tightened to specific completion-style phrasings.
    # - The strip is CAPPED at 3 leading chunks. Without a cap, a
    #   skill whose entire output is conversational (e.g. an
    #   audit-context-building report that opens "Let me share the
    #   architecture..." and continues in first-person) would have
    #   every chunk stripped and we'd fall to the result fallback.
    # - A chunk containing structural markdown (`# heading`, `|`
    #   table row, `` ``` `` fence) is NEVER stripped — that signals
    #   the real report has begun.
    _conv_prefixes = (
        "i'll ", "i will ", "let me ", "now let me ",
        "now i have completed", "now i have enough",
        "now i have all the", "now i have sufficient",
        "i now have completed", "i now have enough",
        "here is the ", "here's the ",
        "based on my ", "after analyzing ", "after reviewing ",
    )

    def _is_conv_intro(c: str) -> bool:
        s = c.strip()
        if len(s) > 300:
            return False
        # If the chunk contains a real markdown structure marker, it's
        # the start of the report — don't strip it.
        if any(marker in s for marker in ("# ", "## ", "|", "```")):
            return False
        sl = s.lower()
        return any(sl.startswith(p) for p in _conv_prefixes)

    # Cap at 3 stripped chunks so we don't accidentally eat a real
    # first-person opening of an entire conversational skill output.
    stripped = 0
    while chunks and stripped < 3 and _is_conv_intro(chunks[0]):
        chunks.pop(0)
        stripped += 1

    if chunks:
        return "\n\n".join(chunks)

    # Fallback path: empty chunk list (e.g. malformed stream). Also
    # strip leading conversational lines from the result text so the
    # caller doesn't get an "I now have enough..." prefix.
    if final_result:
        lines = final_result.splitlines()
        i = 0
        while i < min(3, len(lines)):
            ln = lines[i].strip()
            if not ln:
                i += 1
                continue
            if _is_conv_intro(ln):
                i += 1
                continue
            break
        return "\n".join(lines[i:])
    return final_result


def _run_claude_with_heartbeat(
    cmd: list[str],
    *,
    input_text: str,
    timeout: int,
    cwd: str,
    env: dict,
    label: str,
    heartbeat_interval: int = 30,
    capture_mode: str = "final",
) -> subprocess.CompletedProcess:
    """Run `claude -p` (or any subprocess) with a periodic stderr heartbeat
    so long-running invocations don't look hung.

    The heartbeat thread prints `[<label>] still running (<N>s elapsed)`
    every `heartbeat_interval` seconds until the subprocess returns. On
    completion (success or failure) it prints a final line with elapsed
    time and stdout size.

    Uses ``Popen`` rather than ``run`` so that ``_sigint_handler`` can
    register the live child and terminate it cleanly on Ctrl+C. Raises
    ``subprocess.TimeoutExpired`` to preserve the previous contract on
    timeout. On user interrupt, raises ``KeyboardInterrupt``.

    ``capture_mode`` controls how the subprocess output is post-processed:

    - ``"final"`` (default): pass-through. The caller has built the
      cmd line normally (e.g. ``[claude, "-p"]``) so claude emits the
      final assistant message as plain text on stdout, and we capture
      it verbatim. Suitable for skills that produce a single final
      report (the vast majority).

    - ``"all"``: the caller MUST have built the cmd to include
      ``--output-format stream-json --verbose`` (this function asserts
      it). claude then emits NDJSON with every assistant message as a
      separate event; we parse the stream and concatenate every text
      block. Suitable for skills that emit analysis incrementally
      across many tool-use rounds (notably ToB's
      ``audit-context-building``, which would otherwise lose
      everything except the final summary line).
    """
    if capture_mode not in ("final", "all"):
        raise ValueError(f"capture_mode must be 'final' or 'all', got {capture_mode!r}")
    if capture_mode == "all" and "stream-json" not in cmd:
        raise ValueError(
            "capture_mode='all' requires '--output-format stream-json --verbose' in cmd"
        )
    start = time.time()
    stop_event = threading.Event()
    # The reporter owns ALL start/heartbeat/done emission so the live
    # dashboard footer stays consistent. In plain mode this collapses
    # to "[label] still running (Ns)" lines as before; in live mode the
    # dashboard's in-flight section shows the worker dynamically and
    # this thread stays silent.
    reporter = get_reporter()

    def _beat() -> None:
        while not stop_event.wait(heartbeat_interval):
            elapsed = int(time.time() - start)
            reporter.worker_heartbeat(label, elapsed)

    hb = threading.Thread(target=_beat, daemon=True)
    hb.start()

    proc = subprocess.Popen(  # noqa: S603 — cmd is built from shutil.which
        cmd,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
        cwd=cwd, env=env,
    )
    _register_proc(proc)
    try:
        try:
            stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            stop_event.set()
            raise
        except KeyboardInterrupt:
            # The SIGINT handler already called terminate(); finish drain
            # then re-raise so callers can unwind cleanly.
            try:
                stdout, stderr = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = "", ""
            stop_event.set()
            raise
    finally:
        _unregister_proc(proc)
        stop_event.set()

    # If the signal handler killed the child while we were communicating
    # but didn't surface KeyboardInterrupt (rare, but possible on Windows
    # since signal delivery may be deferred), turn the abnormal exit into
    # a KeyboardInterrupt so callers see a consistent abort path.
    if _INTERRUPTED.is_set():
        raise KeyboardInterrupt

    elapsed = int(time.time() - start)
    rc = proc.returncode
    raw_stdout = stdout or ""

    # In stream-json mode the raw stdout is NDJSON, not the final report.
    # Reduce it to the concatenated assistant prose here so callers don't
    # have to know about the capture mode.
    final_stdout = raw_stdout
    if capture_mode == "all":
        final_stdout = _extract_assistant_text_from_stream_json(raw_stdout)

    out_size = len(final_stdout)
    # We DON'T emit a per-subprocess "[label] ok/fail in Xs" line here
    # any more — the caller (cmd_audit's packet_done / phase plumbing)
    # owns the final reporting. Suppressing it avoids double-logging
    # and keeps the live dashboard footer from being pushed up by
    # stray subprocess-level summaries.
    _ = out_size  # kept for potential future reporter.note hook

    return subprocess.CompletedProcess(
        args=cmd, returncode=rc, stdout=final_stdout, stderr=stderr or "",
    )


def _invoke_claude_skill(
    spec: SkillSpec, packet_path: Path, output_path: Path,
    repo_path: Path, packet_id: str, model: str | None = None,
    extra_subskills: list[str] | None = None,
    extra_context_blocks: list[str] | None = None,
) -> tuple[int, str]:
    """Pipe (skill + packet) into `claude -p` and capture stdout to
    `output_path`. Returns (returncode, error_msg).

    The skill prompt is assembled by :func:`sra.skill_loader.load_skill_prompt`
    which expands dependencies, ``{baseDir}`` templating, and any
    ``extra_subskills`` passed as additional context (see
    :func:`_choose_crypto_subskills` for the crypto composition use case).
    ``extra_context_blocks`` adds caller-supplied free-form markdown blocks
    (e.g. the 04a / 04b pre-audit outputs) to the same ``extra_context``
    list, after the sub-skill blocks.

    When ``spec.source == "tob"`` the findings file is prefixed with a
    CC-BY-SA-4.0 attribution header pointing at the upstream skill.

    If `model` is provided, passes `--model <model>` to the claude CLI.
    Otherwise the user's default claude model is used.

    Honours the nested-session guard by clearing CLAUDECODE in the env."""
    claude = shutil.which("claude")
    if not claude:
        return -1, "claude CLI not found on PATH"

    try:
        packet_text = packet_path.read_text(encoding="utf-8")
    except OSError as e:
        return -1, f"cannot read packet: {e}"

    extra_context: list[str] = []
    if extra_subskills:
        for sub_name in extra_subskills:
            try:
                sub_prompt = load_skill_prompt(sub_name)
            except (KeyError, FileNotFoundError) as e:
                return -1, f"cannot load sub-skill {sub_name!r}: {e}"
            extra_context.append(
                f"--- Sub-skill: {sub_name} ---\n\n{sub_prompt}"
            )
    if extra_context_blocks:
        extra_context.extend(extra_context_blocks)

    try:
        skill_text = load_skill_prompt(
            spec.name, extra_context=extra_context or None,
        )
    except (KeyError, FileNotFoundError) as e:
        return -1, f"cannot load skill {spec.name!r}: {e}"

    prompt = (
        f"You are running the skill defined below. Investigate EXACTLY ONE "
        f"packet: {packet_id}. Do not search for, list, or investigate any "
        f"other packet under .audit/. Output your report to stdout in "
        f"Markdown form. Do not use the Write, Edit, or NotebookEdit tools.\n"
        f"\n=== SKILL SPEC ===\n\n{skill_text}\n"
        f"\n=== THE PACKET TO INVESTIGATE ({packet_id}) ===\n\n{packet_text}\n"
    )

    env = os.environ.copy()
    env.pop("CLAUDECODE",           None)
    env.pop("CLAUDE_CODE_ENTRYPOINT", None)

    cmd = [claude, "-p"]
    if model:
        cmd.extend(["--model", model])
    # Per-packet family skills emit substantial analysis across many
    # tool-use rounds (Read/Grep cycles). With --output-format text
    # only the FINAL assistant message reaches stdout — intermediate
    # findings get lost. Use stream-json capture (same mechanism as
    # 04a context-building) so every assistant text block makes it
    # into the findings file. Real-world impact on salazar's
    # crypto-auth: 3 TLS-bypass findings were emitted across tool
    # rounds and partially preserved only because the skill happened
    # to also summarise them in the final message.
    cmd.extend(["--output-format", "stream-json", "--verbose"])

    label = f"{spec.name} / {packet_id}" + (f" [{model}]" if model else "")
    try:
        proc = _run_claude_with_heartbeat(
            cmd, input_text=prompt, timeout=600,
            cwd=str(repo_path), env=env, label=label,
            capture_mode="all",
        )
    except subprocess.TimeoutExpired:
        return -1, f"claude -p timed out after 10 minutes on {packet_id}"

    # Write whatever Claude produced — even on non-zero, the partial may
    # be informative. ToB skills require an attribution header (CC-BY-SA-4.0).
    body = (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr)
                                   if proc.stderr else "")
    if spec.source == "tob":
        body = _TOB_ATTRIBUTION_TEMPLATE.format(name=spec.name) + body
    # On non-zero rc, write to a `.partial` sibling instead of the
    # canonical path. The skip-if-exists guard in cmd_audit keys off
    # the canonical `<pid>.findings.md` — writing partials there made
    # resume treat failed runs as completed, silently dropping the
    # work. The partial is kept for human inspection.
    try:
        if proc.returncode == 0:
            _atomic_write_text(output_path, body)
        else:
            partial = output_path.with_suffix(output_path.suffix + ".partial")
            _atomic_write_text(partial, body)
    except OSError as e:
        return -1, f"cannot write findings: {e}"

    if proc.returncode != 0:
        return proc.returncode, f"claude -p returned {proc.returncode}"
    return 0, ""


def _invoke_loaded_skill(
    skill_name: str,
    output_path: Path,
    repo_path: Path,
    *,
    extra_context: list[str] | None = None,
    target_language: str | None = None,
    model: str | None = None,
    preamble: str | None = None,
    timeout: int = 600,
    capture_mode: str = "final",
) -> tuple[int, str]:
    """Resolve a registered skill via :func:`load_skill_prompt`, pipe the
    full prompt into ``claude -p``, and capture stdout to ``output_path``.

    Generic helper for orchestrator stages that don't carry the per-packet
    investigation contract — the 04a context-building, 04b entry-points,
    06a variant-analysis, and 06b fp-check stages all flow through here.
    The per-family flow stays on :func:`_invoke_claude_skill` because it
    additionally needs the packet attachment and the ToB attribution
    comment.

    ``preamble`` (when provided) is prepended verbatim before the
    skill-loader output, separated by a blank line. ``target_language``
    is forwarded to the loader so a skill with a ``references/`` dir can
    pull in the right language-specific reference markdown.

    Returns (returncode, error_msg). Honours the nested-session guard by
    clearing CLAUDECODE in the env."""
    claude = shutil.which("claude")
    if not claude:
        return -1, "claude CLI not found on PATH"

    try:
        prompt_body = load_skill_prompt(
            skill_name,
            target_language=target_language,
            extra_context=extra_context,
        )
    except KeyError:
        return -1, f"skill not in registry: {skill_name}"
    except FileNotFoundError as e:
        return -1, f"skill file missing: {e}"

    prompt = f"{preamble.strip()}\n\n{prompt_body}" if preamble else prompt_body

    env = os.environ.copy()
    env.pop("CLAUDECODE",           None)
    env.pop("CLAUDE_CODE_ENTRYPOINT", None)

    cmd = [claude, "-p"]
    if model:
        cmd.extend(["--model", model])
    # When the caller asks for `capture_mode="all"`, we MUST emit
    # stream-json so every intermediate assistant message is preserved.
    # `--verbose` is a hard requirement of stream-json mode.
    if capture_mode == "all":
        cmd.extend(["--output-format", "stream-json", "--verbose"])

    label = f"{skill_name}" + (f" [{model}]" if model else "")
    try:
        proc = _run_claude_with_heartbeat(
            cmd, input_text=prompt, timeout=timeout,
            cwd=str(repo_path), env=env, label=label,
            capture_mode=capture_mode,
        )
    except subprocess.TimeoutExpired:
        return -1, f"claude -p timed out after {timeout} s on {skill_name}"

    combined = (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr)
                                       if proc.stderr else "")
    # Same partial-on-failure policy as _invoke_claude_skill — see that
    # function's comment. The canonical path is only written on rc=0
    # so the skip-if-exists guard correctly treats failed runs as
    # "not yet done" on resume.
    try:
        if proc.returncode == 0:
            _atomic_write_text(output_path, combined)
        else:
            partial = output_path.with_suffix(output_path.suffix + ".partial")
            _atomic_write_text(partial, combined)
    except OSError as e:
        return -1, f"cannot write output: {e}"

    if proc.returncode != 0:
        return proc.returncode, f"claude -p returned {proc.returncode}"
    return 0, ""


def _has_smart_contracts(repo_path: Path) -> bool:
    """Quick filesystem probe for smart-contract source files.

    Trail of Bits' ``entry-point-analyzer`` skill is explicitly
    smart-contracts-only (Solidity, Vyper, Move, TON FunC/Tact, Solana,
    CosmWasm). Invoking it on a Node.js / Python / Go web app produces
    a useless "this is not a smart-contract codebase" report that still
    gets prepended to every family-skill prompt as noise. This gate
    short-circuits 04b when there is clearly no contract code to read.

    Uses ``os.walk`` with ``SKIP_DIRECTORIES`` pruning so we don't false-
    positive on a vendored ``.sol`` file under ``node_modules`` and don't
    spend minutes walking giant trees on monorepos.
    """
    sc_exts = {".sol", ".vy", ".move", ".fc", ".func", ".tact"}
    seen = 0
    max_files = 20000  # generous cap; pruning makes this rarely hit
    for dirpath, dirnames, filenames in os.walk(repo_path):
        # Prune skip-dirs in place so os.walk doesn't descend into them.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRECTORIES]
        for fn in filenames:
            seen += 1
            if seen > max_files:
                return False
            # Cheap extension match against the basename.
            dot = fn.rfind(".")
            if dot >= 0 and fn[dot:].lower() in sc_exts:
                return True
            # Rust contract signal: check Cargo.toml manifests inline so
            # we don't have to re-walk afterwards.
            if fn == "Cargo.toml":
                try:
                    text = Path(dirpath, fn).read_text(
                        encoding="utf-8", errors="replace",
                    )
                except OSError:
                    continue
                if "solana-program" in text or "cosmwasm-std" in text:
                    return True
    return False


def _primary_language(repo_path: Path) -> str | None:
    """Return the first entry in fingerprint.json's ``languages`` list,
    or ``None`` if absent / malformed. Used by Phase-2 pre-audit stages
    (04a / 04b) to forward ``target_language`` to the skill loader so
    references/<lang>.md gets picked up when the skill provides one."""
    langs = _all_languages(repo_path)
    return langs[0] if langs else None


def _all_languages(repo_path: Path) -> list[str]:
    """Return EVERY non-empty string from fingerprint.json's
    ``languages`` list, in fingerprint order. Used by the skill-
    composition language gate to handle polyglot repos correctly:
    a Go+TS repo's primary is "Go" but a TS-only ToB skill should
    still compose. Empty list when fingerprint is missing or has
    no string entries."""
    fp = repo_path / ".audit" / "00-fingerprint" / "fingerprint.json"
    if not fp.is_file():
        return []
    try:
        d = json.loads(fp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    langs = d.get("languages")
    if not isinstance(langs, list):
        return []
    return [
        entry.strip() for entry in langs
        if isinstance(entry, str) and entry.strip()
    ]


# Regexes for the section parser in :func:`_parse_confirmed_findings`.
_FINDINGS_SECTION_RE = re.compile(r"^##\s+(.+?)\s*$")
_FINDINGS_SUBSEC_RE  = re.compile(r"^###\s+(.+?)\s*$")
# Patterns the parser treats as an empty-confirmed-issues section: a
# short body that just says "none" / "0 confirmed" / "_None._".
_NONE_MARKERS = ("none", "0 confirmed", "no confirmed")


def _parse_confirmed_findings(text: str) -> list[str]:
    """Extract the per-finding markdown blocks under ``## Confirmed issues``.

    Returns an empty list when:
      - the file has no ``## Confirmed issues`` heading,
      - the heading is ``## Confirmed issues (0)``,
      - the section body is blank, or
      - the section body is short and just says "None" / "0 confirmed".

    When the section has ``###``-subsectioned findings, each subsection
    becomes one block (the ``### `` heading line is preserved at the top
    of the block). When the section has content but no ``###`` headings,
    the whole section body is returned as a single block.
    """
    in_confirmed = False
    body_lines: list[str] = []
    for line in text.splitlines():
        h = _FINDINGS_SECTION_RE.match(line)
        if h:
            if in_confirmed:
                # New `## ` heading closes the confirmed section.
                break
            title = h.group(1).strip()
            if title.lower().startswith("confirmed issues"):
                m_count = re.search(r"\((\d+)\)", title)
                if m_count and int(m_count.group(1)) == 0:
                    return []
                in_confirmed = True
            continue
        if in_confirmed:
            body_lines.append(line)

    if not body_lines:
        return []

    body_text = "\n".join(body_lines).strip()
    if not body_text:
        return []
    # Short "this section is intentionally empty" bodies. Length guard
    # keeps a real finding that incidentally mentions "none" from being
    # discarded.
    body_lower = body_text.lower()
    if len(body_text) < 200 and any(m in body_lower for m in _NONE_MARKERS):
        return []

    findings: list[str] = []
    cur: list[str] = []
    saw_subsec = False
    for line in body_lines:
        if _FINDINGS_SUBSEC_RE.match(line):
            saw_subsec = True
            if cur:
                block = "\n".join(cur).strip()
                if block:
                    findings.append(block)
            cur = [line]
            continue
        cur.append(line)
    if cur:
        block = "\n".join(cur).strip()
        if block:
            findings.append(block)

    if not saw_subsec:
        # One unstructured block — treat the whole section as one finding.
        return [body_text]
    return findings


def cmd_audit(
    repo_path_str: str,
    sensors: list[str],
    families_arg: list[str] | None,
    with_skills: bool,
    force: bool,
    model: str | None = None,
    *,
    no_context: bool = False,
    no_entry_points: bool = False,
    no_variants: bool = False,
    no_fp_check: bool = False,
    no_synthesis: bool = False,
    force_context: bool = False,
    force_entry_points: bool = False,
    force_variants: bool = False,
    force_fp_check: bool = False,
    force_synthesis: bool = False,
    parallel: int = 1,
    micro_fold_threshold: int | None = 10,
    lang_filter: "LanguageFilter | None" = None,
    no_llm_packet_dedup: bool = False,
    llm_packet_dedup_threshold: int = 15,
) -> int:
    repo_path = Path(repo_path_str).expanduser()
    if not repo_path.is_dir():
        print(f"error: not a directory: {repo_path}", file=sys.stderr)
        return 2
    target = repo_path.resolve()

    def have(*parts: str) -> bool:
        return (target / ".audit" / Path(*parts)).is_file()

    # Centralised reporter — see sra.output. The closure stays as a
    # thin wrapper so the ~80 legacy ``announce(msg)`` call sites work
    # unchanged; structured events (phase boundaries, per-packet
    # progress, final banner) call the reporter directly.
    reporter = get_reporter()

    def announce(msg: str) -> None:
        reporter.info(msg)

    def _count_confirmed_findings(findings_md_path: Path,
                                  fam: str, pid: str) -> int:
        """Parse a freshly-produced PACKET-NNN.findings.md and return
        the count of confirmed findings. Best-effort: any parse error
        returns 0 so a malformed file doesn't crash the orchestrator."""
        try:
            text = findings_md_path.read_text(encoding="utf-8")
        except OSError:
            return 0
        try:
            parsed = _parse_findings_md(text, family=fam, packet_id=pid)
        except Exception:  # noqa: BLE001 — parser is lenient but defensive
            return 0
        return len(parsed.get("confirmed", []))

    if lang_filter is not None and lang_filter.is_active:
        announce(f"language filter active: {lang_filter.describe()}")

    # 00 collect
    if force or not have("00-fingerprint", "raw-signals.json"):
        announce("00 collect — walking repo for raw signals")
        rc = cmd_collect(str(target))
        if rc != 0:
            return rc
    else:
        announce("00 collect — skipped (raw-signals.json exists)")

    # 00 fingerprint (LLM call #1)
    if force or not have("00-fingerprint", "fingerprint.json"):
        announce("00 fingerprint — invoking claude on raw-summary.md")
        rc = cmd_fingerprint(str(target))
        if rc != 0:
            return rc
    else:
        announce("00 fingerprint — skipped (fingerprint.json exists)")

    # 01 route-packs
    if force or not have("01-pack-router", "selected-packs.json"):
        announce("01 route-packs")
        rc = cmd_route_packs(str(target))
        if rc != 0:
            return rc
    else:
        announce("01 route-packs — skipped")

    # 02 plan
    if force or not have("02-plan", "audit-plan.json"):
        announce("02 plan")
        rc = cmd_plan(str(target))
        if rc != 0:
            return rc
    else:
        announce("02 plan — skipped")

    # 04a context-building (Trail of Bits audit-context-building skill).
    # Grouped under `with_skills` so --no-skills suppresses every LLM
    # cost including pre-audit ones.
    if with_skills and not no_context:
        out_path = target / ".audit" / "04-context" / "context-building.md"
        if out_path.is_file() and not (force or force_context):
            reporter.info("phase 04a context-building — skipped (output exists)")
        else:
            lang = _primary_language(target)
            reporter.phase_start(
                "04a", "context-building",
                total=1,
                note=(f"lang={lang}" if lang else "")
                     + (f" model={model}" if model else ""),
            )
            ctx_label = "audit-context-building"
            reporter.packet_start(ctx_label)
            rc, err = _invoke_loaded_skill(
                "audit-context-building",
                out_path, target,
                extra_context=None,
                target_language=lang,
                model=model,
                preamble=(
                    "You are running the skill defined below against the "
                    "repository in the current working directory. Output "
                    "your report to stdout in Markdown form. Do not use "
                    "the Write, Edit, or NotebookEdit tools."
                ),
                # 04a does a full repo-wide line-by-line analysis; on large
                # codebases with Opus it routinely exceeds the default 600 s.
                timeout=2400,
                # audit-context-building emits its analysis incrementally
                # across many tool-use rounds; with the default capture
                # mode only the final summary line ("the report above
                # covers ...") reaches stdout. Force stream-json capture
                # so every assistant text block makes it into the file.
                capture_mode="all",
            )
            reporter.packet_done(
                ctx_label, ok=(rc == 0),
                error=("" if rc == 0 else (err or f"rc={rc}")),
                index=(1, 1),
            )
            reporter.phase_end()
    elif no_context:
        reporter.info("phase 04a context-building — skipped (--no-context)")
    else:
        reporter.info("phase 04a context-building — skipped (--no-skills)")

    # 04b entry-points (Trail of Bits entry-point-analyzer skill).
    # ToB's entry-point-analyzer is explicitly smart-contracts-only; on
    # non-contract repos it just emits "this isn't a smart-contract
    # codebase" which then leaks into every family-skill prompt as noise.
    # Gate on a cheap filesystem probe instead of invoking unconditionally.
    if with_skills and not no_entry_points:
        out_path = target / ".audit" / "04-context" / "entry-points.md"
        if out_path.is_file() and not (force or force_entry_points):
            reporter.info("phase 04b entry-points — skipped (output exists)")
        elif not _has_smart_contracts(target):
            reporter.info(
                "phase 04b entry-points — skipped (no smart-contract source files; "
                "entry-point-analyzer is contracts-only)"
            )
        else:
            lang = _primary_language(target)
            reporter.phase_start(
                "04b", "entry points",
                total=1,
                note=(f"lang={lang}" if lang else "")
                     + (f" model={model}" if model else ""),
            )
            ep_label = "entry-point-analyzer"
            reporter.packet_start(ep_label)
            rc, err = _invoke_loaded_skill(
                "entry-point-analyzer",
                out_path, target,
                extra_context=None,
                target_language=lang,
                model=model,
                preamble=(
                    "You are running the skill defined below against the "
                    "repository in the current working directory. Output "
                    "your report to stdout in Markdown form. Do not use "
                    "the Write, Edit, or NotebookEdit tools."
                ),
                # Same stream-json capture rationale as 04a / 06b / 07:
                # entry-point-analyzer walks every contract file via
                # Read/Grep tools and emits its analysis incrementally.
                capture_mode="all",
                timeout=1800,
            )
            reporter.packet_done(
                ep_label, ok=(rc == 0),
                error=("" if rc == 0 else (err or f"rc={rc}")),
                index=(1, 1),
            )
            reporter.phase_end()
    elif no_entry_points:
        reporter.info("phase 04b entry-points — skipped (--no-entry-points)")
    else:
        reporter.info("phase 04b entry-points — skipped (--no-skills)")

    # Discover which families to run.
    elected = _elected_families(target)
    if families_arg:
        # User can override; intersect with supported.
        wanted = [
            f for f in families_arg
            if f in SENSOR_SUPPORTED_FAMILIES
        ]
        announce(f"family override: {', '.join(wanted) or '(none)'}")
        families = wanted
    else:
        families = elected
        announce(
            "elected by fingerprint (intersected with sensor support): "
            + (", ".join(families) if families else "(none)")
        )

    # Default-off filter. These families produced more noise than signal
    # in practice on real audits:
    #
    #   - audit/supply-chain: typically duplicates what Dependabot /
    #     GHSA / Snyk surface from CI; semgrep / Claude per-packet
    #     reasoning rarely adds value over those tools. Worth running
    #     deliberately when you don't already have a dependency-CVE
    #     workflow, but as a default it eats packet budget that's
    #     better spent on input/auth/parser families.
    #
    #   - audit/config-deployment: the fingerprint elects it whenever
    #     it sees an `install/` or `deploy/` dir, but on classic PHP/
    #     Python apps without Dockerfile/k8s manifests, the family
    #     produces near-zero confirmed findings and consumes meaningful
    #     LLM cost on container/IaC patterns that aren't there.
    #
    # The drop applies ONLY to the fingerprint-elected list. If the
    # user explicitly passes `--family audit/supply-chain`, they get
    # it — opt-in respects user intent.
    _DEFAULT_OFF_FAMILIES = {"audit/supply-chain", "audit/config-deployment"}
    if not families_arg:
        dropped = [f for f in families if f in _DEFAULT_OFF_FAMILIES]
        if dropped:
            families = [f for f in families if f not in _DEFAULT_OFF_FAMILIES]
            announce(
                "default-off (pass --family to opt in): "
                + ", ".join(dropped)
            )

    # Domain gate: audit/smart-contracts is only meaningful on a repo
    # that actually contains contract source files. Without this the
    # fingerprint can occasionally elect it on web apps, and the
    # downstream building-secure-contracts skill emits "this isn't a
    # smart-contract codebase" for every packet — same wasted-LLM
    # class of bug as the 04b entry-point-analyzer regression.
    if "audit/smart-contracts" in families and not _has_smart_contracts(target):
        families = [f for f in families if f != "audit/smart-contracts"]
        announce(
            "audit/smart-contracts — skipped (no smart-contract source files)"
        )

    if not families:
        announce("no supported families to run; stopping after stage 02")
        return 0

    # 03 sensors + 04 packets per family
    for fam in families:
        if _INTERRUPTED.is_set():
            announce("interrupted; skipping remaining families")
            break
        announce(f"--- family: {fam} ---")
        for sensor in sensors:
            if _INTERRUPTED.is_set():
                break
            announce(f"03 run-sensor {sensor}")
            rc = cmd_run_sensor(
                str(target), fam, sensor,
                force=force,
                lang_filter=lang_filter,
            )
            if rc != 0:
                reporter.warn(f"{sensor} returned {rc}; continuing")
        if _INTERRUPTED.is_set():
            break
        # When the user explicitly focused the audit on one or more
        # families via `--family X`, treat that as "I want depth on
        # what I picked" and bypass the per-family cap. In a default
        # full audit (no --family flag), keep the adaptive cap to bound
        # total LLM cost across all elected families.
        cap_override_for_family = 0 if families_arg else None
        announce(
            "04 build-packets-from-sensors"
            + (" (no cap, --family focused)" if families_arg else "")
            + (f" [micro-fold @ {micro_fold_threshold}]" if micro_fold_threshold else " [micro-fold disabled]")
        )
        rc = cmd_build_packets_from_sensors(
            str(target), fam,
            cap_override=cap_override_for_family,
            micro_fold_threshold=micro_fold_threshold,
            lang_filter=lang_filter,
        )
        if rc != 0:
            reporter.warn(f"packet builder returned {rc}; continuing")

    # Cross-family overlap annotation: post-pass that appends a
    # "## Cross-family overlap (advisory)" section to each packet that
    # shares files with packets in other families. Strictly additive —
    # no packet is dropped or modified semantically; just gives the LLM
    # awareness of where related investigation is happening so it can
    # avoid redoing analysis from another family's angle.
    if len(families) >= 2:
        announce(f"04+ cross-family overlap annotation ({len(families)} families)")
        try:
            _annotate_cross_family_overlap(target, families)
        except Exception as e:  # noqa: BLE001 — annotation must never crash
            reporter.warn(f"cross-family annotation failed: {e}")

    # 04.5 LLM packet dedup: one claude -p call per family to identify
    # semantically-duplicate packets (same root cause + same code area)
    # and merge them. Conservative-by-default: any failure path
    # (malformed JSON, claude unavailable, timeout) just skips the
    # dedup for that family — no packets are touched.
    if with_skills and not no_llm_packet_dedup:
        eligible = []
        for fam in families:
            slug = _family_slug(fam)
            idx_path = target / ".audit" / "04-packets-sensors" / slug / "packet-index.json"
            if not idx_path.is_file():
                continue
            try:
                idx_data = json.loads(idx_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            prod_packets = sum(
                1 for p in (idx_data.get("packets") or [])
                if p.get("primary_role") == "production"
                and not p.get("_merged_into")  # idempotency
            )
            if prod_packets >= llm_packet_dedup_threshold:
                eligible.append((fam, prod_packets))
        if eligible:
            announce(
                f"04.5 LLM packet dedup — {len(eligible)} families above "
                f"threshold={llm_packet_dedup_threshold}: "
                + ", ".join(f"{fam}({n})" for fam, n in eligible)
            )
            for fam, n in eligible:
                if _INTERRUPTED.is_set():
                    break
                announce(f"  dedup {fam} ({n} packets) — invoking claude")
                try:
                    groups = _llm_packet_dedup_for_family(
                        target, fam, model=model,
                    )
                except Exception as e:  # noqa: BLE001
                    reporter.warn(f"dedup call failed: {e}")
                    continue
                if not groups:
                    announce(f"    -> no merges proposed")
                    continue
                merged = _apply_packet_merges(target, fam, groups)
                announce(
                    f"    -> {len(groups)} merge group(s), "
                    f"{merged} packet(s) absorbed into primary"
                )
        else:
            announce(
                f"04.5 LLM packet dedup — no family above "
                f"threshold={llm_packet_dedup_threshold} packets"
            )
    elif with_skills:
        announce("04.5 LLM packet dedup — skipped (--no-llm-packet-dedup)")

    # 04b skill invocations (per production packet, per family)
    if with_skills:
        # Phase header + structured progress emitted by the reporter; the
        # legacy "--- skill phase ---" divider line is gone. The job-
        # builder below collects skip counts and emits a single summary
        # line at phase_start() — no more 263 "skip ..." lines.

        # Read the 04a / 04b pre-audit outputs once; they get appended as
        # extra_context to every family-skill invocation. Either may be
        # absent (--no-context / --no-entry-points / a failed earlier
        # stage); in that case the corresponding block is just omitted.
        ctx_dir = target / ".audit" / "04-context"
        ctx_md_path = ctx_dir / "context-building.md"
        ep_md_path  = ctx_dir / "entry-points.md"
        pre_audit_blocks: list[str] = []
        if ctx_md_path.is_file():
            try:
                pre_audit_blocks.append(
                    "=== Repo context (from 04a context-building) ===\n\n"
                    + ctx_md_path.read_text(encoding="utf-8")
                )
            except OSError as e:
                reporter.warn(f"cannot read 04a output: {e}")
        if ep_md_path.is_file():
            try:
                pre_audit_blocks.append(
                    "=== Repo entry points (from 04b entry-point-analyzer) ===\n\n"
                    + ep_md_path.read_text(encoding="utf-8")
                )
            except OSError as e:
                reporter.warn(f"cannot read 04b output: {e}")

        # Build job list across all families, then optionally fan out.
        #
        # Skip accounting: legacy code emitted ``announce(f"  skip {fam}/
        # {pid} (already has findings.md)")`` once per cached packet,
        # producing 263 noise lines on a typical resumed run. We now
        # tally cached / structural-skip counts here and surface them
        # once in the phase_start summary.
        jobs: list[tuple[str, SkillSpec, Path, Path, str]] = []
        total_skipped = 0     # cached (findings.md already on disk)
        family_skipped: dict[str, int] = {}  # cached count per family
        structural_skipped = 0  # missing index / spec — reported as warnings
        for fam in families:
            slug = _family_slug(fam)
            packets_dir = target / ".audit" / "04-packets-sensors" / slug
            index_path  = packets_dir / "packet-index.json"
            if not index_path.is_file():
                reporter.warn(f"{fam}: no packet-index.json; skipping skill")
                structural_skipped += 1
                continue
            try:
                idx = json.loads(index_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue

            spec = _family_skill_spec(fam)
            if spec is None:
                reporter.warn(f"{fam}: no skill spec registered")
                structural_skipped += 1
                continue
            if not spec.resolved_path().is_file():
                reporter.warn(
                    f"{fam}: skill spec not found: {spec.resolved_path()}"
                )
                structural_skipped += 1
                continue

            for p in idx.get("packets", []):
                if p.get("primary_role") != "production":
                    continue
                if p.get("_merged_into"):
                    # Absorbed by primary packet via LLM dedup (04.5)
                    # — primary will investigate all hits together.
                    continue
                pid = p.get("id", "")
                if not pid:
                    continue
                packet_md   = packets_dir / f"{pid}.md"
                findings_md = packets_dir / f"{pid}.findings.md"
                if not packet_md.is_file():
                    continue
                if findings_md.is_file() and not force:
                    total_skipped += 1
                    family_skipped[fam] = family_skipped.get(fam, 0) + 1
                    continue
                jobs.append((fam, spec, packet_md, findings_md, pid))

        # Resolve repo's languages ONCE so each per-packet job
        # doesn't re-read fingerprint.json. Use the FULL list (not
        # just primary) for the language-gate in _choose_*_subskills
        # so polyglot repos don't lose skills that cover only the
        # secondary language.
        all_langs = _all_languages(target)

        def _run_one_packet(job: tuple[str, SkillSpec, Path, Path, str]) -> tuple[str, str, int, str]:
            fam, spec, packet_md, findings_md, pid = job
            extra_subskills: list[str] | None = None
            sub_note = ""
            if fam == "audit/crypto-auth":
                try:
                    packet_text = packet_md.read_text(encoding="utf-8")
                except OSError:
                    packet_text = ""
                chosen = _choose_crypto_subskills(packet_text, all_langs)
                if chosen:
                    extra_subskills = chosen
                    sub_note = "+" + ",".join(chosen)
            elif fam == "audit/business-logic":
                try:
                    packet_text = packet_md.read_text(encoding="utf-8")
                except OSError:
                    packet_text = ""
                chosen = _choose_business_logic_subskills(packet_text, all_langs)
                if chosen:
                    extra_subskills = chosen
                    sub_note = "+" + ",".join(chosen)

            # Always prepend the canonical output contract — the
            # downstream aggregator parses .findings.md by regex and
            # any drift from the contract drops findings on the floor.
            # See `_FINDING_OUTPUT_CONTRACT` for rationale.
            packet_blocks = [_output_contract_for_packet(pid)]
            if pre_audit_blocks:
                packet_blocks.extend(pre_audit_blocks)

            # Call packet_start from INSIDE the worker so the dashboard
            # in-flight set reflects what's actually running right now,
            # not what's been submitted to the pool's queue.
            short = fam.split("/", 1)[-1] if "/" in fam else fam
            reporter.packet_start(f"{short}/{pid}", extra=sub_note)

            rc, err = _invoke_claude_skill(
                spec, packet_md, findings_md, target, pid,
                model=model,
                extra_subskills=extra_subskills,
                extra_context_blocks=packet_blocks,
            )
            return (fam, pid, rc, err)

        total_ran = total_failed = 0
        n_jobs = len(jobs)
        reporter.phase_start(
            "04", "skill audit",
            total=n_jobs, cached=total_skipped, parallel=parallel,
            note=f"model={model}" if model else "",
        )

        def _label(fam_: str, pid_: str) -> str:
            # Compact family label for the worker line: "audit/crypto-auth"
            # -> "crypto-auth". The family prefix is implicit in this phase.
            short = fam_.split("/", 1)[-1] if "/" in fam_ else fam_
            return f"{short}/{pid_}"

        def _finalise_packet(fam_: str, pid_: str, rc_: int, err_: str,
                             findings_md_: Path,
                             index_: tuple[int, int]) -> None:
            """Common post-processing for both serial and parallel paths:
            parse findings.md on success, then drive reporter.packet_done."""
            label = _label(fam_, pid_)
            if rc_ == 0:
                n_found = _count_confirmed_findings(findings_md_, fam_, pid_)
                reporter.packet_done(
                    label, ok=True, findings=n_found, index=index_,
                )
            else:
                reporter.packet_done(
                    label, ok=False, error=err_ or f"rc={rc_}",
                    index=index_,
                )

        # The worker function (_run_one_packet) is the single owner of
        # packet_start — it runs inside the worker thread right before
        # invoking claude, so the reporter's in-flight dashboard
        # reflects what's *actually* executing, not what's queued. The
        # main thread below only calls packet_done after collecting the
        # future result; that pops the worker out of _workers and emits
        # the result line.
        if parallel <= 1 or n_jobs <= 1:
            for i, job in enumerate(jobs, 1):
                if _INTERRUPTED.is_set():
                    reporter.warn(
                        f"interrupted; skipping remaining "
                        f"{n_jobs - i + 1} packet(s)"
                    )
                    break
                fam, _spec, _packet_md, findings_md_p, pid = job
                try:
                    _, _, rc, err = _run_one_packet(job)
                except KeyboardInterrupt:
                    reporter.packet_done(
                        _label(fam, pid), ok=False, error="interrupted",
                        index=(i, n_jobs),
                    )
                    reporter.warn("interrupted during packet")
                    total_failed += 1
                    break
                _finalise_packet(
                    fam, pid, rc, err, findings_md_p, (i, n_jobs),
                )
                if rc == 0:
                    total_ran += 1
                else:
                    total_failed += 1
        else:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=parallel) as ex:
                future_to_job = {ex.submit(_run_one_packet, job): job for job in jobs}
                completed = 0
                try:
                    for fut in as_completed(future_to_job):
                        completed += 1
                        job = future_to_job[fut]
                        fam, _spec, _packet_md, findings_md_p, pid = job
                        try:
                            _, _, rc, err = fut.result()
                        except KeyboardInterrupt:
                            rc, err = -1, "interrupted"
                        except Exception as e:  # noqa: BLE001
                            rc, err = -1, str(e)
                        _finalise_packet(
                            fam, pid, rc, err, findings_md_p,
                            (completed, n_jobs),
                        )
                        if rc == 0:
                            total_ran += 1
                        else:
                            total_failed += 1
                        if _INTERRUPTED.is_set():
                            cancelled = 0
                            for f in future_to_job:
                                if f.cancel():
                                    cancelled += 1
                            if cancelled:
                                reporter.warn(
                                    f"interrupted; cancelled {cancelled} "
                                    f"pending packet(s)"
                                )
                            break
                except KeyboardInterrupt:
                    reporter.warn(
                        "interrupted; waiting for in-flight workers to drain"
                    )
                    for f in future_to_job:
                        f.cancel()

        reporter.phase_end()
    else:
        reporter.info("phase 04 skill audit — skipped (--no-skills)")

    # 06a variant-analysis (per confirmed finding).
    # Walks every PACKET-NNN.findings.md, extracts each confirmed-issue
    # block, and invokes the ToB variant-analysis skill once per block.
    # Output: <repo>/.audit/06-variants/<family-slug>/<PACKET-ID>-<finding-index>.md
    # The family-slug subdir is required because two families may both
    # produce PACKET-001 + finding #1 (e.g. access-control and
    # crypto-auth on the same repo) — without the prefix the second
    # write would silently overwrite the first and the skip-if-exists
    # guard would drop the second invocation.
    if with_skills and not no_variants and not _INTERRUPTED.is_set():
        variants_dir = target / ".audit" / "06-variants"
        v_lang = _primary_language(target)

        # Two-pass: first enumerate every (family, packet-id, finding-
        # index, finding-block, out-path) tuple so phase_start gets an
        # accurate total. Cached items (out_path already exists) are
        # tallied separately and reported in the phase header.
        variant_jobs: list[tuple[str, str, int, str, Path]] = []
        v_cached = 0
        for fam in families:
            if _INTERRUPTED.is_set():
                break
            slug = _family_slug(fam)
            packets_dir = target / ".audit" / "04-packets-sensors" / slug
            if not packets_dir.is_dir():
                continue
            for findings_md in sorted(packets_dir.glob("PACKET-*.findings.md")):
                try:
                    fcontent = findings_md.read_text(encoding="utf-8")
                except OSError as e:
                    reporter.warn(f"cannot read {findings_md.name}: {e}")
                    continue
                blocks = _parse_confirmed_findings(fcontent)
                if not blocks:
                    continue
                pid_v = findings_md.stem[:-len(".findings")] \
                    if findings_md.stem.endswith(".findings") \
                    else findings_md.stem
                for idx_f, finding_block in enumerate(blocks, start=1):
                    out_path = variants_dir / slug / f"{pid_v}-{idx_f}.md"
                    if out_path.is_file() and not (force or force_variants):
                        v_cached += 1
                        continue
                    variant_jobs.append(
                        (fam, pid_v, idx_f, finding_block, out_path)
                    )

        n_v = len(variant_jobs)
        reporter.phase_start(
            "06a", "variant analysis",
            total=n_v, cached=v_cached,
            note=f"model={model}" if model else "",
        )

        total_v_ran = total_v_failed = 0
        interrupted_v = False
        for i_v, (fam, pid_v, idx_f, finding_block, out_path) in enumerate(
            variant_jobs, start=1,
        ):
            if _INTERRUPTED.is_set():
                interrupted_v = True
                break
            slug = _family_slug(fam)
            short = fam.split("/", 1)[-1] if "/" in fam else fam
            v_label = f"{short}/{pid_v}-{idx_f}"
            reporter.packet_start(v_label)
            try:
                rc, err = _invoke_loaded_skill(
                    "variant-analysis",
                    out_path, target,
                    extra_context=[
                        f"=== Confirmed finding (from {fam} {pid_v}, finding #{idx_f}) ===\n\n"
                        + finding_block
                    ],
                    target_language=v_lang,
                    model=model,
                    preamble=(
                        "You are running the skill defined below to find "
                        "variants of ONE specific confirmed finding "
                        "(provided as 'Additional context'). Output your "
                        "variant analysis to stdout in Markdown form. Do "
                        "not use the Write, Edit, or NotebookEdit tools."
                    ),
                    # Same stream-json capture as the other
                    # whole-repo skills: variant-analysis Greps the
                    # whole tree for similar bug shapes and emits
                    # per-variant findings spread across many tool-
                    # use rounds.
                    capture_mode="all",
                    timeout=1200,
                )
            except KeyboardInterrupt:
                reporter.packet_done(
                    v_label, ok=False, error="interrupted",
                    index=(i_v, n_v),
                )
                interrupted_v = True
                break
            if rc == 0:
                total_v_ran += 1
                reporter.packet_done(v_label, ok=True, index=(i_v, n_v))
            else:
                total_v_failed += 1
                reporter.packet_done(
                    v_label, ok=False, error=err or f"rc={rc}",
                    index=(i_v, n_v),
                )

        if interrupted_v:
            reporter.warn("interrupted; remaining variants skipped")
        reporter.phase_end()
    elif no_variants:
        reporter.info("phase 06a variant-analysis — skipped (--no-variants)")
    else:
        reporter.info("phase 06a variant-analysis — skipped (--no-skills)")

    # 06b fp-check (audit-of-audits over every PACKET-NNN.findings.md).
    if with_skills and not no_fp_check and not _INTERRUPTED.is_set():
        out_path = target / ".audit" / "06-fp-check" / "audit-of-audits.md"
        if out_path.is_file() and not (force or force_fp_check):
            reporter.info("phase 06b fp-check — skipped (output exists)")
        else:
            # Walk EVERY family directory on disk, not just `families`
            # (the current invocation's elected list). When the user
            # re-runs with `--family X`, fp-check used to silently drop
            # all other families from the audit-of-audits aggregation,
            # producing a misleading "all" report. Now we always read
            # the full repo's findings.
            findings_blocks: list[str] = []
            packets_root = target / ".audit" / "04-packets-sensors"
            for fam_dir in sorted(packets_root.iterdir()) if packets_root.is_dir() else []:
                if not fam_dir.is_dir() or not fam_dir.name.startswith("audit-"):
                    continue
                fam_name = "audit/" + fam_dir.name[len("audit-"):]
                for findings_md in sorted(fam_dir.glob("PACKET-*.findings.md")):
                    try:
                        fcontent = findings_md.read_text(encoding="utf-8")
                    except OSError as e:
                        reporter.warn(f"cannot read {findings_md.name}: {e}")
                        continue
                    pid = findings_md.stem[:-len(".findings")] \
                        if findings_md.stem.endswith(".findings") \
                        else findings_md.stem
                    findings_blocks.append(
                        f"=== {fam_name} {pid} ===\n\n{fcontent}"
                    )
            if not findings_blocks:
                reporter.info("phase 06b fp-check — no findings to check; skipping")
            else:
                reporter.phase_start(
                    "06b", "fp-check",
                    total=1,
                    note=(f"model={model}" if model else "")
                         + f" {len(findings_blocks)} findings files",
                )
                fp_label = "fp-check"
                reporter.packet_start(fp_label)
                rc, err = _invoke_loaded_skill(
                    "fp-check",
                    out_path, target,
                    extra_context=findings_blocks,
                    target_language=_primary_language(target),
                    model=model,
                    preamble=(
                        "You are running the skill defined below over the "
                        "audit findings provided as additional context. "
                        "Produce a single audit-of-audits report flagging "
                        "likely false positives. Output to stdout in "
                        "Markdown form. Do not use the Write, Edit, or "
                        "NotebookEdit tools."
                    ),
                    # fp-check aggregates every PACKET-NNN.findings.md
                    # across every family — on a real repo this is many
                    # tens of kB of input and 600 s is not enough for Opus.
                    timeout=2400,
                    # Same stream-json capture as 04a / 07: fp-check
                    # iterates over findings, opens many files, then
                    # writes a structured verdicts table. Without
                    # capture_mode="all" only the final summary
                    # ("Zero FPs identified among N findings.") makes
                    # it to disk — the per-finding verdicts table is
                    # lost in intermediate messages. Real-world impact
                    # on salazar: audit-of-audits.md was a single 355-
                    # byte summary line; the report aggregator then
                    # had no per-finding evidence to flag.
                    capture_mode="all",
                )
                if rc == 0:
                    # Count flagged FPs from the produced report so the
                    # final banner shows ``fp-check flagged: N``. The
                    # report parser owns that count — call it here so
                    # the totals stay in sync with the report builder.
                    try:
                        fp_text = out_path.read_text(encoding="utf-8")
                        fp_data = _parse_fp_check(fp_text)
                        n_flagged = len(fp_data.get("flagged", []))
                        reporter.add_fp_flagged(n_flagged)
                    except Exception:  # noqa: BLE001
                        n_flagged = 0
                    reporter.packet_done(
                        fp_label, ok=True, index=(1, 1),
                    )
                    if n_flagged:
                        reporter.note(f"fp-check flagged {n_flagged} finding(s)")
                else:
                    reporter.packet_done(
                        fp_label, ok=False, error=err or f"rc={rc}",
                        index=(1, 1),
                    )
                reporter.phase_end()
    elif no_fp_check:
        reporter.info("phase 06b fp-check — skipped (--no-fp-check)")
    else:
        reporter.info("phase 06b fp-check — skipped (--no-skills)")

    # 07 audit-synthesis (executive-quality report with attack chains).
    # Reads every artifact produced so far (context, findings, variants,
    # fp-check) and asks a fresh claude pass to:
    #   - re-verify each finding against the source code (Read tool)
    #   - drop fp-check-overruled false positives
    #   - chain related findings into attack scenarios
    #   - emit a strict-template security-audit-report.md
    # Runs once per repo. Skipped when --no-skills, --no-synthesis,
    # or interrupted.
    if with_skills and not no_synthesis and not _INTERRUPTED.is_set():
        synth_out = target / ".audit" / "07-synthesis" / "security-audit-report.md"
        if synth_out.is_file() and not (force or force_synthesis):
            reporter.info("phase 07 audit-synthesis — skipped (output exists)")
        else:
            # Per-block size cap is now provided by module-level
            # `_capped_block` so it can be unit-tested in isolation.
            _capped = _capped_block

            # Build the input context: every finding + variants
            # + fp-check + context-building + entry-points.
            synth_blocks: list[str] = []
            ctx_md = target / ".audit" / "04-context" / "context-building.md"
            if ctx_md.is_file():
                try:
                    synth_blocks.append(
                        "=== Repo context (04a context-building) ===\n\n"
                        + _capped(ctx_md.read_text(encoding="utf-8"))
                    )
                except OSError:
                    pass
            # 04b entry-points: only meaningful on smart-contract repos.
            # On non-contract repos the skill is auto-skipped — but a
            # leftover file from a prior contract-style run could still
            # be on disk. Gate the inclusion the same way cmd_audit
            # gates the producer, so synthesis doesn't get fed smart-
            # contract entry-point notes when reviewing a Go repo.
            ep_md = target / ".audit" / "04-context" / "entry-points.md"
            if ep_md.is_file() and _has_smart_contracts(target):
                try:
                    synth_blocks.append(
                        "=== Entry points (04b) ===\n\n"
                        + _capped(ep_md.read_text(encoding="utf-8"))
                    )
                except OSError:
                    pass
            packets_root = target / ".audit" / "04-packets-sensors"
            if packets_root.is_dir():
                for fam_dir in sorted(packets_root.iterdir()):
                    if not fam_dir.is_dir() or not fam_dir.name.startswith("audit-"):
                        continue
                    fam_name = "audit/" + fam_dir.name[len("audit-"):]
                    for findings_md in sorted(fam_dir.glob("PACKET-*.findings.md")):
                        try:
                            fcontent = findings_md.read_text(encoding="utf-8")
                        except OSError:
                            continue
                        pid = findings_md.stem[:-len(".findings")] \
                            if findings_md.stem.endswith(".findings") \
                            else findings_md.stem
                        synth_blocks.append(
                            f"=== Findings: {fam_name} {pid} ===\n\n"
                            + _capped(fcontent)
                        )
            # fp-check verdicts BEFORE variants so the synthesizer
            # sees fp-check's overruled-false-positive list before
            # the variants — otherwise it might inflate findings
            # whose original was already dismissed by fp-check.
            fp_md = target / ".audit" / "06-fp-check" / "audit-of-audits.md"
            if fp_md.is_file():
                try:
                    synth_blocks.append(
                        "=== fp-check audit-of-audits (06b) ===\n\n"
                        + _capped(fp_md.read_text(encoding="utf-8"))
                    )
                except OSError:
                    pass
            # Then variants. Family-disambiguating header so two
            # families that both produced `PACKET-001-1.md` don't
            # collide in the prompt (the rglob walk flattens family
            # subdirs).
            variants_root = target / ".audit" / "06-variants"
            if variants_root.is_dir():
                for v_md in sorted(variants_root.rglob("*.md")):
                    try:
                        if v_md.stat().st_size == 0:
                            continue
                        parent = v_md.parent.name
                        fam_tag = (
                            f"{parent}/"
                            if parent.startswith("audit-")
                            else ""
                        )
                        synth_blocks.append(
                            f"=== Variant: {fam_tag}{v_md.name} ===\n\n"
                            + _capped(v_md.read_text(encoding="utf-8"))
                        )
                    except OSError:
                        continue

            # Count findings blocks during construction (was: brittle
            # substring check `"Findings:" in b` which would silently
            # disable synthesis if the header text ever changes).
            n_finding_blocks = sum(
                1 for b in synth_blocks if b.startswith("=== Findings:")
            )
            if n_finding_blocks == 0:
                reporter.info(
                    "phase 07 audit-synthesis — no findings to synthesise; skipping"
                )
            else:
                reporter.phase_start(
                    "07", "audit synthesis",
                    total=1,
                    note=(f"model={model}" if model else "")
                         + f" {len(synth_blocks)} artefact blocks",
                )
                synth_label = "audit-synthesis"
                reporter.packet_start(synth_label)
                synth_lang = _primary_language(target)
                rc, err = _invoke_loaded_skill(
                    "audit-synthesis",
                    synth_out, target,
                    extra_context=synth_blocks,
                    target_language=synth_lang,
                    model=model,
                    preamble=(
                        "You are running the audit-synthesis skill over "
                        "every artifact produced by the prior stages. "
                        "Read the cited code via the Read / Grep tools "
                        "to verify findings before including them. Emit "
                        "EXACTLY the markdown template described in the "
                        "skill spec — no preamble, no chat. Do not use "
                        "the Write, Edit, or NotebookEdit tools."
                    ),
                    # Synthesis is whole-repo, heavyweight: needs the
                    # generous timeout (same as fp-check) and stream-json
                    # capture so analysis emitted across tool-use rounds
                    # is preserved.
                    timeout=2400,
                    capture_mode="all",
                )
                if rc == 0:
                    reporter.packet_done(synth_label, ok=True, index=(1, 1))
                else:
                    reporter.packet_done(
                        synth_label, ok=False, error=err or f"rc={rc}",
                        index=(1, 1),
                    )
                reporter.phase_end()
    elif no_synthesis:
        reporter.info("phase 07 audit-synthesis — skipped (--no-synthesis)")
    else:
        reporter.info("phase 07 audit-synthesis — skipped (--no-skills)")

    # 05 aggregate.
    # Build a partial report even on interrupt: whatever findings landed
    # on disk are still worth surfacing. The conventional 130 exit code
    # is reserved for the actual interrupt case so callers can detect it.
    report_md = target / ".audit" / "05-report" / "repo-report.md"
    report_json = target / ".audit" / "05-report" / "repo-report.json"
    report_path_str = str(report_md) if report_md.is_file() else ""

    def _repo_totals() -> dict:
        """Read repo-wide totals from the finalised JSON. Falls back to
        an empty dict on any parse error so the banner just uses
        in-run counters."""
        if not report_json.is_file():
            return {}
        try:
            data = json.loads(report_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        confirmed_list = data.get("confirmed", []) or []
        # The canonical "fp-flagged" count is the number of confirmed
        # findings that fp-check tagged for re-review (the same metric
        # report.py emits on its stdout summary line). flagged_refs /
        # flagged_packets are coarser groupings.
        fp_flagged = sum(1 for c in confirmed_list if c.get("fp_flagged"))
        return {
            "repo_total_findings": len(confirmed_list),
            "repo_total_variants": len(data.get("variants", []) or []),
            "repo_total_packets": data.get("packet_total") or 0,
            "fp_flagged": fp_flagged,
        }

    if _INTERRUPTED.is_set():
        reporter.section("phase 05 build-report (partial — pipeline interrupted)")
        try:
            cmd_build_report(str(target))
            if report_md.is_file():
                report_path_str = str(report_md)
        except Exception as e:  # noqa: BLE001
            reporter.warn(f"partial report build failed: {e}")
        reporter.final_summary(
            report_path=report_path_str, interrupted=True,
            **_repo_totals(),
        )
        try:
            reporter.shutdown()
        except Exception:  # noqa: BLE001
            pass
        return 130

    reporter.section("phase 05 build-report")
    rc = cmd_build_report(str(target))
    if rc != 0:
        reporter.warn(f"report builder returned {rc}")
    if report_md.is_file():
        report_path_str = str(report_md)

    reporter.final_summary(report_path=report_path_str, **_repo_totals())
    try:
        reporter.shutdown()
    except Exception:  # noqa: BLE001
        pass
    return 0


def main(argv: list[str] | None = None) -> int:
    # Install SIGINT handler so the user can stop a long audit run with
    # Ctrl+C: live claude subprocesses get SIGTERM'd, the parallel-skill
    # loop drains in-flight work and skips remaining packets, and the
    # process exits with the conventional 130 (128 + SIGINT).
    _install_sigint_handler()
    parser = argparse.ArgumentParser(
        prog="sra",
        description="Repository fingerprinting in six stages: collect raw "
                    "structural signals, ask the 'claude' CLI to interpret "
                    "them, deterministically route packs, expand each audit "
                    "family into a per-family workflow plan, collect "
                    "per-family evidence, then assemble small review packets "
                    "from that evidence.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_collect = subparsers.add_parser(
        "collect",
        help="Walk a repository and write raw fingerprint signals.",
    )
    p_collect.add_argument("repo_path", help="Path to the repository.")

    p_fingerprint = subparsers.add_parser(
        "fingerprint",
        help="Send raw-summary.md to 'claude -p' (via stdin) and write "
             "fingerprint.json / fingerprint.md.",
    )
    p_fingerprint.add_argument("repo_path", help="Path to the repository.")

    p_route_packs = subparsers.add_parser(
        "route-packs",
        help="Deterministically normalise fingerprint.json into "
             "selected-packs.json / next-steps.md. No LLM call.",
    )
    p_route_packs.add_argument("repo_path", help="Path to the repository.")

    p_plan = subparsers.add_parser(
        "plan",
        help="Deterministically expand selected-packs.json audit families "
             "into a per-family workflow plan (audit-plan.json / .md). "
             "No LLM call.",
    )
    p_plan.add_argument("repo_path", help="Path to the repository.")

    p_run_sensor = subparsers.add_parser(
        "run-sensor",
        help="Run a real sensor (ripgrep or semgrep) against the repo for "
             "one audit family and write structured output under "
             ".audit/03-evidence/<family>/sensors/<sensor>/. This replaces "
             "the heuristic collect-evidence path for the sensor-first "
             "vertical slice.",
    )
    p_run_sensor.add_argument("repo_path", help="Path to the repository.")
    p_run_sensor.add_argument(
        "--family",
        required=True,
        help="Audit family. v0 supports only: audit/input-validation.",
    )
    p_run_sensor.add_argument(
        "--sensor",
        required=True,
        choices=sorted(SENSOR_SUPPORTED_SENSORS),
        help="Which sensor to run. ripgrep uses the catalog under "
             "sensors/ripgrep/. semgrep runs the full public registry "
             "(`https://semgrep.dev/r`) and post-filters non-security "
             "categories — override with env var SRA_SEMGREP_CONFIG.",
    )
    p_run_sensor.add_argument(
        "--force",
        action="store_true",
        help="Re-scan even if .audit/03-evidence/<family>/sensors/"
             "<sensor>/index.json already exists. Without --force, an "
             "existing index.json causes the sensor to be skipped (so "
             "long audits resume cheaply).",
    )
    p_run_sensor.add_argument(
        "--only-lang",
        action="append",
        default=None,
        metavar="LANG",
        help="Restrict scan to these languages (repeatable / comma-sep). "
             "See `sra audit --help` for token list.",
    )
    p_run_sensor.add_argument(
        "--exclude-lang",
        action="append",
        default=None,
        metavar="LANG",
        help="Skip these languages (repeatable / comma-sep). "
             "See `sra audit --help` for token list.",
    )

    p_packets_sensors = subparsers.add_parser(
        "build-packets-from-sensors",
        help="Cluster sensor hits under .audit/03-evidence/<family>/sensors/ "
             "into per-cluster review packets at "
             ".audit/04-packets-sensors/<family>/. Source-agnostic across "
             "ripgrep and semgrep output.",
    )
    p_packets_sensors.add_argument(
        "repo_path", help="Path to the repository.",
    )
    p_packets_sensors.add_argument(
        "--family",
        required=True,
        help="Audit family.",
    )
    p_packets_sensors.add_argument(
        "--only-lang",
        action="append",
        default=None,
        metavar="LANG",
        help="Restrict packets to these languages (repeatable / comma-sep). "
             "See `sra audit --help` for token list.",
    )
    p_packets_sensors.add_argument(
        "--exclude-lang",
        action="append",
        default=None,
        metavar="LANG",
        help="Skip these languages (repeatable / comma-sep). "
             "See `sra audit --help` for token list.",
    )

    p_report = subparsers.add_parser(
        "build-report",
        help="Aggregate every PACKET-NNN.findings.md under "
             ".audit/04-packets-sensors/<family>/ into a single per-repo "
             "report at .audit/05-report/repo-report.{md,json}. No LLM call.",
    )
    p_report.add_argument("repo_path", help="Path to the repository.")

    p_audit = subparsers.add_parser(
        "audit",
        help="Single-command end-to-end audit (default mode), or one of "
             "four whole-repo alternative modes via --mode. Default: "
             "collect -> fingerprint -> route-packs -> plan -> 04a context-"
             "building -> 04b entry-points -> run-sensor (per family) -> "
             "build-packets-from-sensors -> claude family skill (per "
             "packet, with 04a / 04b as extra context) -> 06a "
             "variant-analysis (per confirmed finding) -> 06b fp-check -> "
             "build-report. Resumable: stages with existing output are "
             "skipped unless --force or the stage-specific "
             "--force-<stage> flag is set. --no-<stage> flags skip "
             "individual LLM stages (04a / 04b / variants / fp-check); "
             "--no-skills skips all LLM stages at once. Use --mode "
             "{differential,spec-to-code,mutation-testing,"
             "property-based-testing} to invoke a single ToB skill on "
             "the repo as a whole — alt modes bypass sensors / packets "
             "and write one report under <repo>/.audit/05-report/.",
    )
    p_audit.add_argument("repo_path", help="Path to the repository.")
    p_audit.add_argument(
        "--mode",
        default="audit",
        choices=[
            "audit",
            "differential",
            "spec-to-code",
            "mutation-testing",
            "property-based-testing",
        ],
        help=(
            "Audit flow to run. 'audit' (default) is the full deterministic-"
            "first pipeline. The other four are whole-repo single-invocation "
            "alt modes that bypass sensors / packets and run one ToB skill: "
            "'differential' requires --repo-b (and runs the "
            "differential-review skill on the file-level diff); "
            "'spec-to-code' requires --spec <path> (and runs "
            "spec-to-code-compliance against that document); "
            "'mutation-testing' and 'property-based-testing' take only "
            "the repo path. Output for alt modes lands under "
            "<repo>/.audit/05-report/."
        ),
    )
    p_audit.add_argument(
        "--repo-b",
        default=None,
        help="Second repo path for --mode differential. Diffed against "
             "the primary repo_path positional. Required for differential "
             "mode, ignored otherwise.",
    )
    p_audit.add_argument(
        "--spec",
        default=None,
        help="Path to a specification document (Markdown or plain text) "
             "for --mode spec-to-code. Read whole-file, capped at 50 KB. "
             "Required for spec-to-code mode, ignored otherwise.",
    )
    p_audit.add_argument(
        "--diff-tool",
        default=None,
        choices=["git"],
        help="Optional helper for --mode differential. With 'git', also "
             "invoke `git diff --stat` inside repo_a if both repos appear "
             "to be git worktrees (useful when they're different commits "
             "of the same repo).",
    )
    p_audit.add_argument(
        "--sensor",
        action="append",
        default=None,
        help="(Default mode only.) Sensor to run for each family. May be "
             "passed multiple times (e.g. --sensor ripgrep --sensor "
             "semgrep). Defaults to ripgrep only. Ignored by alt modes.",
    )
    p_audit.add_argument(
        "--family",
        action="append",
        default=None,
        help="Family override. May be passed multiple times. Defaults to "
             "every audit/<family> the fingerprint elected (intersected "
             "with sensor-supported families).",
    )
    p_audit.add_argument(
        "--no-skills",
        action="store_true",
        help="Skip every claude-skill LLM stage: pre-audit context-building "
             "and entry-points (04a / 04b), all per-family family skills, "
             "and post-skill variant-analysis / fp-check (06a / 06b). "
             "Useful when you only want the deterministic stages or when "
             "LLM cost is a concern.",
    )
    p_audit.add_argument(
        "--no-context",
        action="store_true",
        help="Skip the 04a context-building stage (Trail of Bits "
             "audit-context-building skill, runs once per repo).",
    )
    p_audit.add_argument(
        "--no-entry-points",
        action="store_true",
        help="Skip the 04b entry-points stage (Trail of Bits "
             "entry-point-analyzer skill, runs once per repo).",
    )
    p_audit.add_argument(
        "--no-variants",
        action="store_true",
        help="Skip the 06a variant-analysis stage (Trail of Bits "
             "variant-analysis skill, runs once per confirmed finding).",
    )
    p_audit.add_argument(
        "--no-fp-check",
        action="store_true",
        help="Skip the 06b fp-check stage (Trail of Bits fp-check skill, "
             "audit-of-audits across all findings, runs once per repo).",
    )
    p_audit.add_argument(
        "--no-synthesis",
        action="store_true",
        help="Skip the 07 audit-synthesis stage (executive report with "
             "attack chains, runs once per repo at the very end). "
             "When skipped, only the deterministic 05 build-report "
             "structural roll-up is produced.",
    )
    p_audit.add_argument(
        "--force",
        action="store_true",
        help="Re-run every stage even if its output already exists. "
             "Subsumes --force-context / --force-entry-points / "
             "--force-variants / --force-fp-check / --force-synthesis.",
    )
    p_audit.add_argument(
        "--force-context",
        action="store_true",
        help="Re-run the 04a context-building stage even if its output "
             "already exists.",
    )
    p_audit.add_argument(
        "--force-entry-points",
        action="store_true",
        help="Re-run the 04b entry-points stage even if its output exists.",
    )
    p_audit.add_argument(
        "--force-variants",
        action="store_true",
        help="Re-run every 06a variant-analysis output that already exists.",
    )
    p_audit.add_argument(
        "--force-fp-check",
        action="store_true",
        help="Re-run the 06b fp-check stage even if its output exists.",
    )
    p_audit.add_argument(
        "--force-synthesis",
        action="store_true",
        help="Re-run the 07 audit-synthesis stage even if its output exists.",
    )
    p_audit.add_argument(
        "--parallel",
        type=int, default=1, metavar="N",
        help="Run N family-skill invocations concurrently (uses a thread "
             "pool; each thread is a separate `claude -p` subprocess). "
             "Default 1 (sequential). Recommended 2-4 for Sonnet, 3-6 for "
             "Haiku. Higher values risk Anthropic rate limits. The "
             "pre-audit stages (04a/04b), variant-analysis (06a), and "
             "fp-check (06b) stay sequential regardless.",
    )
    p_audit.add_argument(
        "--model",
        default=None,
        help="Model to pass to `claude -p` for the skill phase "
             "(e.g. sonnet, opus, haiku, or a full id like "
             "claude-sonnet-4-6). When omitted, the user's default "
             "claude CLI model is used.",
    )
    p_audit.add_argument(
        "--no-micro-fold",
        action="store_true",
        default=False,
        help="Disable the micro-cluster fold pass. By default, "
             "clusters with hit_count < --micro-fold-threshold are "
             "merged into their nearest sibling (same role, longest "
             "common ancestor directory). Empirically reduces packet "
             "count by ~25%% across the repo_a1 corpus with zero data "
             "loss. Use this flag to inspect raw per-directory "
             "clusters instead.",
    )
    p_audit.add_argument(
        "--micro-fold-threshold",
        type=int,
        default=10,
        help="Threshold below which a cluster is considered 'micro' "
             "and merged into its nearest sibling. Default: 10. "
             "Set to 5 for more conservative folding (only fold "
             "very small clusters), or 20 for more aggressive. "
             "Ignored when --no-micro-fold is set.",
    )
    p_audit.add_argument(
        "--no-llm-packet-dedup",
        action="store_true",
        default=False,
        help="Disable the 04.5 LLM packet-dedup stage. By default, "
             "for any family with >= --llm-packet-dedup-threshold "
             "production packets, ONE claude -p call is made to "
             "identify semantically-duplicate packets (same root cause "
             "+ same code area) and merge them. Merging is conservative "
             "(default = no merge when uncertain) and absorbed packets "
             "stay on disk with a redirect header. Disable to skip the "
             "dedup call entirely (saves a few cents per family but "
             "produces more redundant skill investigations).",
    )
    p_audit.add_argument(
        "--llm-packet-dedup-threshold",
        type=int,
        default=15,
        help="Minimum production-packet count for a family to be "
             "considered for LLM packet dedup. Default: 15. Lower "
             "(e.g. 5) for aggressive dedup on small repos; higher "
             "(e.g. 30) to skip the LLM call unless the family is "
             "definitely large. Ignored when --no-llm-packet-dedup "
             "is set.",
    )
    p_audit.add_argument(
        "--only-lang",
        action="append",
        default=None,
        metavar="LANG",
        help="Restrict the audit to one or more languages. May be passed "
             "multiple times or as a comma-separated list "
             "(--only-lang php --only-lang js  OR  --only-lang php,js). "
             "Tokens: " + ", ".join(canonical_language_tokens()) + ". "
             "Aliases: js/ts/typescript -> javascript, kt -> kotlin, "
             "py -> python, rs -> rust, cs/c# -> csharp, cpp/c++ -> c_cpp, "
             "sol -> solidity. Affects three stages: (1) skips sensor "
             "patterns whose language doesn't match, (2) drops semgrep "
             "hits in files outside the requested languages, (3) filters "
             "sensor hits at the packet-build stage as a safety net.",
    )
    p_audit.add_argument(
        "--exclude-lang",
        action="append",
        default=None,
        metavar="LANG",
        help="Skip one or more languages. Same token set as --only-lang. "
             "Useful for polyglot repos where you want to audit "
             "everything EXCEPT, say, the JS frontend: --exclude-lang js. "
             "Cannot exclude what you've also passed via --only-lang.",
    )

    # --- sra dev (Phase 8 — developer tools wrapping ToB meta-skills) ---
    p_dev = subparsers.add_parser(
        "dev",
        help="Developer tools that wrap Trail of Bits meta-skills "
             "(rule authoring, skill review, workflow design). These "
             "do NOT run the audit pipeline — they invoke a single "
             "ToB SKILL.md via `claude -p` and print the result.",
    )
    dev_subs = p_dev.add_subparsers(dest="dev_command", required=True)

    p_dev_rule = dev_subs.add_parser(
        "create-semgrep-rule",
        help="Invoke ToB `semgrep-rule-creator` to produce a draft "
             "Semgrep YAML rule for a given pseudo-code pattern.",
    )
    p_dev_rule.add_argument(
        "--pattern", required=True,
        help="Pseudo-code description of the pattern to detect, "
             "e.g. 'eval(user_input)'.",
    )
    p_dev_rule.add_argument(
        "--lang", required=True,
        help="Target language for the rule (e.g. javascript, python, go).",
    )
    p_dev_rule.add_argument(
        "--out", default=None,
        help="If given, write the result here instead of stdout.",
    )
    p_dev_rule.add_argument(
        "--model", default=None,
        help="Optional --model for `claude -p` (e.g. sonnet, opus).",
    )

    p_dev_variant = dev_subs.add_parser(
        "create-variant",
        help="Invoke ToB `semgrep-rule-variant-creator` to produce "
             "language variants of an existing Semgrep rule.",
    )
    p_dev_variant.add_argument(
        "--rule", required=True,
        help="Path to the existing Semgrep YAML rule.",
    )
    p_dev_variant.add_argument(
        "--out", default=None,
        help="If given, write the result here instead of stdout.",
    )
    p_dev_variant.add_argument(
        "--model", default=None,
        help="Optional --model for `claude -p`.",
    )

    p_dev_improve = dev_subs.add_parser(
        "improve-skill",
        help="Invoke ToB `skill-improver` to review one of our "
             "prompts/skill_<X>.md specs and return suggested fixes.",
    )
    p_dev_improve.add_argument(
        "--skill", required=True,
        help="Short name (e.g. input-validation) of an existing skill "
             "under prompts/, OR a path to any .md skill spec.",
    )
    p_dev_improve.add_argument(
        "--out", default=None,
        help="If given, write the result here instead of stdout.",
    )
    p_dev_improve.add_argument(
        "--model", default=None,
        help="Optional --model for `claude -p`.",
    )

    p_dev_workflow = dev_subs.add_parser(
        "design-workflow",
        help="Invoke ToB `workflow-skill-design` to draft a new "
             "workflow-skill spec for a natural-language goal.",
    )
    p_dev_workflow.add_argument(
        "--description", required=True,
        help="Natural-language description of the workflow / skill "
             "you want to design.",
    )
    p_dev_workflow.add_argument(
        "--out", default=None,
        help="If given, write the result here instead of stdout.",
    )
    p_dev_workflow.add_argument(
        "--model", default=None,
        help="Optional --model for `claude -p`.",
    )

    args = parser.parse_args(argv)

    if args.command == "collect":
        return cmd_collect(args.repo_path)
    if args.command == "fingerprint":
        return cmd_fingerprint(args.repo_path)
    if args.command == "route-packs":
        return cmd_route_packs(args.repo_path)
    if args.command == "plan":
        return cmd_plan(args.repo_path)
    if args.command == "run-sensor":
        lang_filter = _build_lang_filter_from_args(args)
        if lang_filter is None:
            return 2
        return cmd_run_sensor(
            args.repo_path, args.family, args.sensor,
            force=args.force,
            lang_filter=lang_filter if lang_filter.is_active else None,
        )
    if args.command == "build-packets-from-sensors":
        # The standalone subcommand is invoked with an explicit family,
        # which we treat as the same "focused" intent as `sra audit
        # --family X`: bypass the per-family cap. Users who want the
        # default adaptive cap should run `sra audit` (no --family).
        lang_filter = _build_lang_filter_from_args(args)
        if lang_filter is None:
            return 2
        return cmd_build_packets_from_sensors(
            args.repo_path, args.family, cap_override=0,
            lang_filter=lang_filter if lang_filter.is_active else None,
        )
    if args.command == "build-report":
        return cmd_build_report(args.repo_path)
    if args.command == "audit":
        mode = getattr(args, "mode", "audit")
        # --no-skills only makes sense for the default mode (where the
        # skill phase is optional). For alt modes the skill IS the entire
        # mode — refuse the combination so the user gets a clear failure
        # rather than a silent no-op or a half-built output file.
        if mode != "audit" and args.no_skills:
            print(
                f"error: --no-skills cannot be combined with --mode {mode}. "
                "The alt-mode skill IS the mode; skipping it would do "
                "nothing. Drop --no-skills (or switch to --mode audit if "
                "you only want the deterministic stages).",
                file=sys.stderr,
            )
            return 2
        if mode == "audit":
            # Default sensor set: all three. Earlier default was just
            # ripgrep, which silently weakened the audit on families
            # like access-control / business-logic where ripgrep is
            # the PRIMARY signal source (semgrep cannot detect
            # broken access control, IDOR, BOLA — those need the
            # claude-per-packet investigation that ripgrep's route /
            # handler / auth-check hits seed). Users who only want
            # one sensor must pass it explicitly.
            sensors = args.sensor or ["ripgrep", "semgrep", "ast-grep"]
            lang_filter = _build_lang_filter_from_args(args)
            if lang_filter is None:
                return 2
            return cmd_audit(
                args.repo_path,
                sensors=sensors,
                families_arg=args.family,
                with_skills=(not args.no_skills),
                force=args.force,
                model=args.model,
                no_context=args.no_context,
                no_entry_points=args.no_entry_points,
                no_variants=args.no_variants,
                no_fp_check=args.no_fp_check,
                no_synthesis=args.no_synthesis,
                force_context=args.force_context,
                force_entry_points=args.force_entry_points,
                force_variants=args.force_variants,
                force_fp_check=args.force_fp_check,
                force_synthesis=args.force_synthesis,
                parallel=args.parallel,
                micro_fold_threshold=(
                    None if args.no_micro_fold else args.micro_fold_threshold
                ),
                lang_filter=lang_filter if lang_filter.is_active else None,
                no_llm_packet_dedup=args.no_llm_packet_dedup,
                llm_packet_dedup_threshold=args.llm_packet_dedup_threshold,
            )
        if mode == "differential":
            if not args.repo_b:
                print(
                    "error: --mode differential requires --repo-b <path>.",
                    file=sys.stderr,
                )
                return 2
            return cmd_audit_mode_differential(
                args.repo_path, args.repo_b,
                diff_tool=args.diff_tool, model=args.model,
            )
        if mode == "spec-to-code":
            if not args.spec:
                print(
                    "error: --mode spec-to-code requires --spec <path>.",
                    file=sys.stderr,
                )
                return 2
            return cmd_audit_mode_spec_to_code(
                args.repo_path, args.spec, model=args.model,
            )
        if mode == "mutation-testing":
            return cmd_audit_mode_mutation_testing(
                args.repo_path, model=args.model,
            )
        if mode == "property-based-testing":
            return cmd_audit_mode_property_based_testing(
                args.repo_path, model=args.model,
            )
        # argparse's choices= guards against unknown values, but stay
        # defensive in case the list grows out of sync with the dispatch.
        print(f"error: unknown --mode {mode!r}", file=sys.stderr)
        return 2
    if args.command == "dev":
        if args.dev_command == "create-semgrep-rule":
            return cmd_dev_create_semgrep_rule(
                pattern=args.pattern,
                lang=args.lang,
                out=args.out,
                model=args.model,
            )
        if args.dev_command == "create-variant":
            return cmd_dev_create_variant(
                rule_path_str=args.rule,
                out=args.out,
                model=args.model,
            )
        if args.dev_command == "improve-skill":
            return cmd_dev_improve_skill(
                skill_name=args.skill,
                out=args.out,
                model=args.model,
            )
        if args.dev_command == "design-workflow":
            return cmd_dev_design_workflow(
                description=args.description,
                out=args.out,
                model=args.model,
            )
        return 1

    return 1


if __name__ == "__main__":
    # Wrap main() so KeyboardInterrupt anywhere in the pipeline produces
    # a clean exit instead of a Python traceback.
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[interrupt] aborted by user", file=sys.stderr, flush=True)
        sys.exit(130)
