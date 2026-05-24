"""Stage 05 — per-repo audit report aggregator.

Reads every `PACKET-NNN.findings.md` under
`.audit/04-packets-sensors/<family>/` (skill-produced reports), parses
them with a deliberately flexible parser, and aggregates into a single
per-repo report at `.audit/05-report/repo-report.{md,json}`.

Phase 7 extension: also reads `.audit/04-context/{context-building,
entry-points}.md`, `.audit/06-variants/<PACKET-ID>-<finding-index>.md`,
and `.audit/06-fp-check/audit-of-audits.md` when present, links variant
files to their originating confirmed finding (by filename parsing), and
flags confirmed findings that fp-check called out for re-review.

No LLM is invoked. No sensor is run. Pure structural aggregation.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


def _posix(path: Path | str) -> str:
    """Local copy of cli.posix to keep this module self-contained."""
    return str(path).replace(os.sep, "/")


# Section headers we recognise. Lower-cased, with any trailing "(N)" stripped.
_REPORT_KNOWN_SECTIONS: frozenset[str] = frozenset({
    "summary",
    "confirmed issues",
    "dismissed sensor hits",
    "limitations",
    "limitations / what i could not determine",
    "files read during investigation",
})

_REPORT_SECTION_RE  = re.compile(r"^##\s+(.+?)\s*$")
_REPORT_SUBSEC_RE   = re.compile(
    r"^###\s+(?:\d+\.\s+)?(?:\[(?P<sev>[^\]]+)\]\s+)?(?P<title>.+?)\s*$"
)

# Skill outputs use many different schemes to label individual
# findings under a confirmed-issue header. This matcher recognises:
#
#   ### F-1 · Title              (server-side-injection: F- = Finding)
#   ### S-1 · Title              (server-side-injection: S- = Sink)
#   ### H-1 · Title              (parser-state-machine: H- = Hit)
#   ### V-1 · Title              (V- = Vulnerability)
#   ### FIND-001 — Title         (access-control)
#   ### FINDING 1                (access-control)
#   ### FINDING 1 — Title        (access-control)
#   ### ISSUE-001 — Title
#   ### Hit 1                    (server-side-injection per-hit)
#   ### Sensor Hit 1
#
# Separator before title can be `·` (Unicode middle dot — common in
# real outputs), `-`, em/en dash, `:`, or whitespace. Title is
# optional (some skills emit just `### F-1` then put the title in
# bold inside the body).
#
# The DISMISSED equivalents (### D-1, ### Dismissed N) are intentionally
# excluded — those are NOT findings. Dismissed-finding-marker has
# different parent header so this matcher only fires under
# confirmed-bearing sections.
_FINDING_MARKER_RE = re.compile(
    r"^###\s+"
    r"(?:\d+\.\s+)?"                            # optional "1. " numbering
    r"(?:\[(?P<sev>[^\]]+)\]\s+)?"              # optional [HIGH] sev tag
    r"(?P<kind>"
        r"F(?:IND(?:ING)?)?"                    # F-, FIND-, FINDING
        r"|S"                                    # S- (Sink)
        r"|H"                                    # H- (Hit)
        r"|V(?:ULN(?:ERABILITY)?)?"             # V-, VULN-, VULNERABILITY
        r"|ISSUE"                                # ISSUE-
        r"|Hit"                                  # Hit
        r"|Sensor\s+Hit"                         # Sensor Hit
        r"|Finding"                              # Finding (mixed case)
        r"|Issue"                                # Issue (mixed case)
        r"|Vulnerability"                        # Vulnerability (mixed case)
    r")"
    r"(?:[-\s]+(?P<id>\d+|[A-Z]\d*|[A-Z]))?"    # optional id (1, A1, A)
    r"\s*(?:[·:\-—–]\s*)?"                       # optional separator
    r"(?P<title>.*?)\s*$"                        # optional title (can be empty)
)

# Marker for DISMISSED entries (D-N · Title, Dismissed N). These look
# similar to findings but live under a `## Dismissed *` parent.
_DISMISSED_MARKER_RE = re.compile(
    r"^###\s+(?:\d+\.\s+)?D(?:ismissed)?[-\s]+\d+\b", re.IGNORECASE,
)

# Body-level verdict patterns that mark an apparent finding as actually
# a false positive. When a skill investigates per-hit and writes
# `### Hit 1` then `**Verdict:** FALSE POSITIVE` in the body, the parser
# should NOT count Hit 1 as a confirmed finding.
_BODY_VERDICT_FP_RE = re.compile(
    r"(?:^|[\s>*_])"
    r"(?:"
        r"(?:Verdict|Status|Result|Outcome|Conclusion|Classification)"
        r"\s*[:=]?\s*\**\s*"
        r"(?:FALSE\s+POSITIVE|FP|NOT\s+(?:A\s+)?(?:FINDING|BUG|VULN(?:ERABILITY)?)|DISMISSED|CLEARED|SAFE|NEGATIVE|N/A)"
    r"|"
        # Plain inline declarations
        r"(?:This\s+(?:is|was)\s+(?:a\s+)?(?:false\s+positive|FP|safe|not\s+(?:a\s+)?(?:finding|bug|vuln(?:erability)?)))"
    r")",
    re.IGNORECASE | re.MULTILINE,
)
_REPORT_BULLET_RE   = re.compile(r"^\s*[-*]\s+(.+)$")
# Matches backticked path-like tokens with an optional :line or :N-M /
# :N–M range. The range hyphen may be ASCII '-' or U+2013 (en dash) or
# U+2014 (em dash); skills emit both inconsistently.
_REPORT_FILELINE_RE = re.compile(
    r"`(?P<path>[A-Za-z0-9_./\\-]+?\.(?P<ext>[A-Za-z0-9_]+))"
    r"(?::(?P<line>\d+)(?:[\-–—]\d+)?)?`"
)

# Known file extensions (lowercase). Anything matched by
# ``_REPORT_FILELINE_RE`` whose extension isn't on this list AND whose
# path contains no `/` or `\` separator is treated as a CODE
# IDENTIFIER, not a file reference, and dropped before reaching the
# touch-count / fp-check tables. Without this filter we'd accumulate
# noise like ``httpSwagger.WrapHandler``, ``capabilities.drop``,
# ``spec.template.spec.securityContext``, ``cert-manager.io``,
# ``pipedream.net``, ``169.254.169.254`` (an IP literal!) as if they
# were source files.
_KNOWN_FILE_EXTENSIONS: frozenset[str] = frozenset({
    # Source code (general)
    "go", "py", "js", "ts", "tsx", "jsx", "mjs", "cjs",
    "vue", "svelte", "java", "kt", "kts", "scala", "groovy",
    "rs", "c", "cpp", "cc", "cxx", "h", "hpp", "hh", "ino",
    "cs", "fs", "vb", "rb", "php", "swift", "m", "mm",
    "dart", "lua", "pl", "pm", "tcl", "r", "jl", "ex", "exs",
    "elm", "ml", "mli", "hs", "erl", "hrl", "nim", "zig",
    "v", "asm", "s",
    # Smart contract languages
    "sol", "vy", "move", "fc", "func", "tact", "cairo", "tact",
    # Web / markup
    "html", "htm", "xhtml", "xml", "xsd", "xsl", "xslt",
    "css", "scss", "sass", "less", "svg",
    # Config / data
    "json", "json5", "jsonc", "yml", "yaml", "toml", "ini",
    "env", "conf", "config", "cfg", "properties", "lock",
    "mod", "sum", "txt", "csv", "tsv", "log",
    "tf", "tfvars", "hcl", "nomad",
    # Docs
    "md", "markdown", "rst", "adoc", "asciidoc", "tex", "org",
    # Scripts
    "sh", "bash", "zsh", "fish", "ps1", "psm1", "psd1",
    "bat", "cmd", "vbs", "awk", "sed",
    # Build / containers
    "dockerfile", "containerfile",
    # Notebooks
    "ipynb",
})


def _is_filepath_like(path: str, ext: str) -> bool:
    """True if ``(path, ext)`` from `_REPORT_FILELINE_RE` looks like a
    real file reference rather than a code identifier or hostname.

    Two acceptance paths:

      1. ``path`` contains a separator (``/`` or ``\\``) — almost
         certainly a relative/absolute filesystem path.

      2. ``ext`` (the substring after the last ``.``) matches a known
         file-extension whitelist.

    Both case-insensitive. Rejects ``httpSwagger.WrapHandler``
    (Go-style identifier), ``pipedream.net`` (hostname), ``capabilities.
    drop`` (k8s yaml key path), ``169.254.169.254`` (IP literal).
    """
    if "/" in path or "\\" in path:
        return True
    return ext.lower() in _KNOWN_FILE_EXTENSIONS
_REPORT_COUNT_RE    = re.compile(r"\s*\(\d+\)\s*$")
_REPORT_SEVERITY_ORDER = {
    "critical": 0,
    "crit":     0,
    "high":     1,
    "h":        1,
    "medium":   2,
    "med":      2,
    "m":        2,
    "low":      3,
    "l":        3,
    "info":     4,
    "":         5,
}

_TRAILING_SEV_RE = re.compile(
    r"\s*[—–\-]\s*\*{0,2}(?P<sev>critical|crit|high|medium|med|low|info)\*{0,2}\s*$",
    re.IGNORECASE,
)

# Body-level severity extractor. Skills routinely emit lines like:
#   **Severity: Medium-High** **Affected routes...**
#   **Severity:** High **Category:** ...
#   - Severity: medium
# at or near the top of each finding's body. When the title doesn't
# carry a severity (which is the case for ToB-style `## Finding N —
# <plain title>` headings), fall back to the first such body mention.
#
# Compound forms like "Medium-High" / "Low-Medium" are normalised to
# the HIGHER half by default — better to surface a finding too
# prominently than to bury a real one in `info`.
_BODY_SEV_RE = re.compile(
    r"\*{0,2}\s*severity\s*[:：]?\s*\*{0,2}\s*"
    r"(?P<sev>critical|crit|high|medium|med|low|info)"
    r"(?:\s*[\-–—]\s*(?P<sev2>critical|crit|high|medium|med|low|info))?"
    r"\s*\*{0,2}",
    re.IGNORECASE,
)


def _extract_body_severity(body: str) -> str:
    """Return the lowercased severity name found in the FIRST occurrence
    of a `**Severity: X**` (or `Severity: X-Y`) marker in the body,
    or "" if none found. Only the first ~600 chars are scanned so a
    later mention buried in the report (e.g. citing another finding)
    doesn't override the canonical one.
    """
    m = _BODY_SEV_RE.search(body[:600])
    if not m:
        return ""
    sev1 = m.group("sev").lower()
    sev2 = (m.group("sev2") or "").lower()
    if not sev2:
        return sev1
    # Compound severity like "Medium-High" / "Low-Medium" — pick the
    # higher half (lower _REPORT_SEVERITY_ORDER value).
    o1 = _REPORT_SEVERITY_ORDER.get(sev1, 99)
    o2 = _REPORT_SEVERITY_ORDER.get(sev2, 99)
    return sev1 if o1 <= o2 else sev2

# Variant filename: <PACKET-NNN>-<finding-index>.md. The packet ID portion
# is always "PACKET-" + digits (matches the orchestrator's writer in
# `cmd_audit`); the finding index is 1-based and matches the position of
# the confirmed-issue subsection inside the originating
# PACKET-NNN.findings.md.
_VARIANT_FILENAME_RE = re.compile(r"^(?P<packet>PACKET-\d+)-(?P<idx>\d+)$")

# Best-effort matcher for PACKET-NNN references inside arbitrary skill
# output (e.g. fp-check's audit-of-audits.md).
_PACKET_REF_RE = re.compile(r"PACKET-\d+")


def _normalise_section(name: str) -> str:
    n = _REPORT_COUNT_RE.sub("", name).strip().lower()
    # Strip leading numeric prefix like "1. ", "4. " — skills often
    # number top-level analysis sections (`## 4. Findings`, `## 1. TLS
    # Configuration Analysis`). Without this strip, `"4. findings"`
    # falls through the `n == "findings"` check below and the entire
    # section's findings get lost. Real-world hit on salazar's
    # crypto-auth PACKET-001 which had 3 TLS-bypass findings dropped.
    n = re.sub(r"^\d+\.\s*", "", n)
    # Collapse common spelling variants.
    if "limitations" in n:
        return "limitations"
    # Confirmed-issue section: accept the canonical name plus the
    # variants that real skill outputs actually use. We've seen
    # `## Findings`, `## Summary of Findings`, `## Findings & ...`
    # in the wild — without folding these into "confirmed issues",
    # the report aggregator under-counts confirmed findings to 0
    # even when fp-check has separately verified them as true
    # positives. Be permissive: any heading mentioning "confirmed",
    # "findings" (but not "summary of findings" — that's a roll-up
    # of confirmed entries inside the same packet, treat as
    # confirmed too), or "vulnerabilities" rolls up here.
    #
    # CRITICAL guard: must NOT match "dismissed" — that's the OPPOSITE
    # section and the parser handles it separately. Check dismissed
    # FIRST to short-circuit before the catch-all check below.
    if "dismissed" in n:
        return "dismissed sensor hits"
    if (
        "confirmed" in n
        or n == "findings"
        or n.startswith("findings ")
        or n == "summary of findings"
        or n.startswith("summary of findings")
        or "vulnerabilities" in n
        # Server-side-injection / parser-state-machine skills sometimes
        # use category-named headers like "## SQL Sink Analysis",
        # "## SQL Injection Analysis", "## Command Injection Analysis",
        # "## Eval Sink Analysis", "## Template Injection (SSTI) Analysis"
        # — each contains the actual sink-level findings as H3
        # subsections (### S-1, ### F-1, etc). Without folding, all those
        # findings stay invisible to the aggregator.
        or "sink analysis" in n
        or "injection analysis" in n
        or "ssti analysis" in n
        or "eval analysis" in n
        or "code-execution analysis" in n
        or "dynamic-code-execution analysis" in n
        # Hit-by-hit / sensor-hit walkthroughs that some skills produce
        # in lieu of a "Confirmed issues" header. Each subsection is one
        # investigated hit, and the verdict (TRUE POSITIVE / FALSE
        # POSITIVE) lives in the body — handled by the body-verdict
        # filter in _make_confirmed and the dismissal predicate in
        # _parse_findings_md.
        or "sensor hit analysis" in n
        or "sensor hits investigated" in n
        or "hit analysis" in n
        or "hit-by-hit analysis" in n
        or "per-hit analysis" in n
        or n == "hits" or n.startswith("hits ")
        # Plural/singular variants
        or "sink hits" in n
        or "sink hit" in n
    ):
        return "confirmed issues"
    if n.startswith("files read"):
        return "files read during investigation"
    if n == "summary":
        return "summary"
    return n


def _parse_findings_md(
    content: str, family: str, packet_id: str,
) -> dict:
    """Parse one PACKET-NNN.findings.md into structured form.

    The parser supports THREE finding shapes that skills produce in
    the wild and tries them in order; the first that yields entries
    wins:

      A. ``## Finding N — Title`` top-level headings with structural
         subsections (Evidence / Impact / Severity / Remediation /
         Runtime Behavior / ...) underneath. Used by ToB ``insecure-
         defaults`` and some config-deployment outputs. Entire body
         from the heading to the next ``## `` is treated as ONE
         finding.

      B. ``## Confirmed issues`` (or ``## Findings``, ``## Summary of
         Findings``) + ``### N. Subsection`` per finding. The canonical
         schema our own prompts encourage.

      C. Inline ``### Finding: <title>`` markers scattered under
         numbered analysis headings (``## 1. ...``). Used by ToB
         ``business-logic``. Last resort.

    The parser is intentionally lenient — findings.md is skill-
    authored Markdown and shapes drift.
    """
    sections: dict[str, list[str]] = {}
    current = "_preamble"
    buf: list[str] = []
    for line in content.splitlines():
        m = _REPORT_SECTION_RE.match(line)
        if m:
            sections.setdefault(current, []).extend(buf)
            buf = []
            current = _normalise_section(m.group(1))
            continue
        buf.append(line)
    sections.setdefault(current, []).extend(buf)

    summary_lines = sections.get("summary", [])
    summary_text = "\n".join(summary_lines).strip()

    # `finding_index` (1-based) tracks the position of each confirmed entry
    # inside this packet's findings file. It must match the numbering used
    # by Phase 2's variant-analysis writer
    # (`<PACKET-ID>-<finding-index>.md`) so the report can link a variant
    # file back to its originating confirmed entry.
    confirmed: list[dict] = []
    next_idx = 1

    # --- PASS A: `## Finding N — Title` top-level headings.
    # Each such heading is one finding; the body goes from the heading
    # to the next `## ` line. Structural subsections (`### Evidence`,
    # `### Impact`, `### Severity Assessment`, `### Remediation Sketch`)
    # are PARTS of the finding, NOT separate findings. Skip pass B/C
    # when this pass finds any to avoid double-counting.
    #
    # Title patterns matched (case-insensitive):
    #   ## Finding 1 — Container Runs as Root (CONFIRMED)
    #   ## Finding 2 - Fleet-Wide: No Dockerfile Specifies ...
    #   ## Finding: SQL injection in /api/foo
    # The optional trailing `(STATUS)` token is stripped from the title
    # but used as a confidence hint.
    # Accept space-separated forms (`## Finding 1 — Title`),
    # hyphen-joined ToB forms (`## Finding-1: Title`), and the bare
    # `## Finding: Title` / `## Finding 1: Title` shapes. The
    # separator between "Finding" and the optional id can be space
    # OR hyphen; the separator before the title can be `:`, `-`,
    # em/en dash, or whitespace.
    _h2_finding_re = re.compile(
        r"^##\s+Finding[-\s]*(?:\d+|[A-Z])?\s*[:\-—–\s]+"
        r"(?P<title>.+?)\s*$",
        re.IGNORECASE,
    )
    h2_title: str | None = None
    h2_buf: list[str] = []
    for line in content.splitlines():
        mh2 = _h2_finding_re.match(line)
        if mh2:
            # Flush previous, start a new one.
            if h2_title is not None:
                confirmed.append(_make_confirmed(
                    family, packet_id, h2_title, None, h2_buf,
                    finding_index=next_idx,
                ))
                next_idx += 1
            title = mh2.group("title").strip()
            # Strip trailing `(CONFIRMED)` / `(SUSPECTED)` / `(VERIFIED)`
            # status tokens — they are a confidence hint, NOT a severity.
            # Earlier versions passed the status as the `sev` argument
            # which caused entries to appear under a bogus
            # `### Severity: confirmed` bucket in the report. The actual
            # severity comes from the body (handled in `_make_confirmed`).
            title = re.sub(
                r"\s*\(\s*(?:CONFIRMED|SUSPECTED|VERIFIED|UNCONFIRMED|TENTATIVE)\b[^)]*\)\s*$",
                "",
                title,
            ).rstrip(" -—–:")
            h2_title = title
            h2_buf = []
            continue
        # Any other `## ` heading closes the current finding (and is
        # NOT itself a finding — it's some other section like
        # "Ancillary Observations" or "Summary").
        if line.startswith("## ") and h2_title is not None:
            confirmed.append(_make_confirmed(
                family, packet_id, h2_title, None, h2_buf,
                finding_index=next_idx,
            ))
            next_idx += 1
            h2_title = None
            h2_buf = []
            continue
        if h2_title is not None:
            h2_buf.append(line)
    if h2_title is not None:
        confirmed.append(_make_confirmed(
            family, packet_id, h2_title, None, h2_buf,
            finding_index=next_idx,
        ))

    # --- PASS B: `## Confirmed issues` / `## Findings` / `## SQL Sink
    # Analysis` / `## Hit-by-Hit Analysis` etc body, with `### N. Title`
    # OR `### F-N` / `### S-N` / `### Hit N` / `### FINDING N` subsections.
    # `_normalise_section` (above) is permissive about what folds into
    # "confirmed issues"; PASS B then walks those subsections.
    #
    # A subsection that looks like a finding marker (matches
    # `_FINDING_MARKER_RE`) OR is a generic `### Title` (matches the
    # legacy `_REPORT_SUBSEC_RE`) counts. The latter is needed for older
    # canonical-style entries like `### 1. SQL injection in users.go`.
    #
    # Filters that prevent double-counting / FP:
    #  - `_DISMISSED_MARKER_RE` (`### D-N`) entries are skipped
    #  - subsections whose body matches `_BODY_VERDICT_FP_RE`
    #    ("**Verdict:** FALSE POSITIVE", "this is a false positive", etc)
    #    are skipped — the skill explicitly cleared the hit
    if not confirmed:
        body = sections.get("confirmed issues", [])
        sub_title = None
        sub_sev   = None
        sub_buf:  list[str] = []

        def _flush_b(title, sev, buf):
            """Flush an accumulated subsection if it survives the FP filter."""
            nonlocal next_idx
            if title is None:
                return
            body_txt = "\n".join(buf)
            if _BODY_VERDICT_FP_RE.search(body_txt):
                return  # skill marked it as FP/cleared/safe
            confirmed.append(_make_confirmed(
                family, packet_id, title, sev, buf,
                finding_index=next_idx,
            ))
            next_idx += 1

        for line in body:
            # Dismissed marker (### D-N) — skip the entire subsection
            # by treating it as a regular non-finding subsection break.
            if _DISMISSED_MARKER_RE.match(line):
                _flush_b(sub_title, sub_sev, sub_buf)
                sub_title = None
                sub_sev = None
                sub_buf = []
                continue
            # Finding marker (### F-N / ### S-N / ### FIND-NNN / ### Hit N
            # / ### Sensor Hit N / ### FINDING / etc).
            fm = _FINDING_MARKER_RE.match(line)
            if fm:
                _flush_b(sub_title, sub_sev, sub_buf)
                title_raw = (fm.group("title") or "").strip()
                kind_raw  = (fm.group("kind") or "").strip()
                id_raw    = (fm.group("id") or "").strip()
                # Build a useful title: if the marker had no title text
                # (e.g. just "### F-1") synthesize one from kind+id.
                if title_raw:
                    sub_title = title_raw
                elif id_raw:
                    sub_title = f"{kind_raw} {id_raw}".strip()
                else:
                    sub_title = kind_raw
                sub_sev = (fm.group("sev") or "").strip().lower()
                sub_buf = []
                continue
            # Generic `### Title` (legacy canonical-style)
            sm = _REPORT_SUBSEC_RE.match(line)
            if sm:
                _flush_b(sub_title, sub_sev, sub_buf)
                sub_title = sm.group("title").strip()
                sub_sev   = (sm.group("sev") or "").strip().lower()
                sub_buf   = []
                continue
            sub_buf.append(line)
        _flush_b(sub_title, sub_sev, sub_buf)

    # Fallback pass: when the skill structured the report as inline
    # `### Finding: <title>` subsections under analysis headings (rather
    # than a single `## Confirmed issues` block), scan the entire doc
    # for those markers. Real skill outputs from `business-logic` use
    # this pattern. We only run the fallback when the structured pass
    # yielded zero entries so we don't double-count.
    if not confirmed:
        # Accept both space-separated forms (`### Finding: foo`,
        # `### Finding 1: foo`) and hyphen-joined ToB forms
        # (`### FINDING-1: foo`, `### Finding-A: foo`). The separator
        # after the optional id can be `:`, `-`, em/en dash, or
        # whitespace.
        finding_marker_re = re.compile(
            r"^###\s+Finding[-\s]*(?:\d+|[A-Z])?\s*[:\-—–\s]+(?P<title>.+?)\s*$",
            re.IGNORECASE,
        )
        inline_buf: list[str] = []
        inline_title: str | None = None
        for line in content.splitlines():
            fm = finding_marker_re.match(line)
            if fm:
                if inline_title is not None:
                    confirmed.append(_make_confirmed(
                        family, packet_id, inline_title, None, inline_buf,
                        finding_index=next_idx,
                    ))
                    next_idx += 1
                inline_title = fm.group("title").strip()
                inline_buf = []
                continue
            # Stop accumulating once we hit a new `## ` top-level
            # section (these are typically "Dismissed Sensor Hits",
            # "Summary", "Unknowns") — don't bleed the finding body
            # into unrelated trailing content.
            if line.startswith("## ") and inline_title is not None:
                confirmed.append(_make_confirmed(
                    family, packet_id, inline_title, None, inline_buf,
                    finding_index=next_idx,
                ))
                next_idx += 1
                inline_title = None
                inline_buf = []
                continue
            if inline_title is not None:
                inline_buf.append(line)
        if inline_title is not None:
            confirmed.append(_make_confirmed(
                family, packet_id, inline_title, None, inline_buf,
                finding_index=next_idx,
            ))

    # --- PASS D: `## Hit N` / `## Sensor Hit N` standalone H2 packets.
    # Some skill outputs (esp. server-side-injection) walk every sensor
    # hit one-by-one as separate H2 sections, with the verdict declared
    # in the body. There's no `## Confirmed issues` umbrella header.
    #
    # Promote a `## Hit N` to a confirmed finding ONLY when the body
    # carries a positive verdict marker (no FP marker, AND at least one
    # of: "**Severity:** high/critical/medium/low" with the severity
    # explicit, or "TRUE POSITIVE" / "Confirmed" / "real bug" / etc).
    #
    # This is intentionally conservative: a `## Hit N` without an
    # explicit positive verdict is treated as exploration/notes, NOT a
    # finding. Better to under-count slightly than to inflate the
    # confirmed-issue count with hits the skill itself declared safe.
    if not confirmed:
        h2_hit_re = re.compile(
            r"^##\s+"
            r"(?:Hits?|Sensor\s+Hits?)"
            r"(?:\s+(?P<idnums>\d+(?:\s*[-–&,]\s*\d+)*))?"  # "Hit 1", "Hits 3 & 4"
            r"\s*(?:[·:\-—–]\s*)?(?P<title>.*?)\s*$",
            re.IGNORECASE,
        )
        # Positive verdict markers — at least one must appear in the
        # body for a `## Hit N` to be promoted.
        positive_verdict_re = re.compile(
            r"(?:"
                # Explicit verdict: "**Verdict:** TRUE POSITIVE", "Status: Confirmed"
                r"(?:Verdict|Status|Result|Outcome|Conclusion|Classification)"
                r"\s*[:=]?\s*\**\s*(?:TRUE\s+POSITIVE|TP|CONFIRMED|REAL|EXPLOITABLE|VULNERABLE)\b"
            r"|"
                # Explicit severity at a meaningful level
                r"(?:\*\*)?Severity(?:\*\*)?\s*[:=]\s*\**\s*(?:critical|high|medium|low)\b"
            r"|"
                # Inline declarations
                r"(?:This\s+(?:is|was)\s+(?:a\s+)?(?:confirmed|real|true)\s+(?:bug|finding|vulnerab|injection|issue))"
            r")",
            re.IGNORECASE | re.MULTILINE,
        )
        h2_title: str | None = None
        h2_buf: list[str] = []
        def _flush_d(title, buf):
            nonlocal next_idx
            if title is None:
                return
            body_txt = "\n".join(buf)
            # Must have positive verdict AND must NOT have FP verdict
            if not positive_verdict_re.search(body_txt):
                return
            if _BODY_VERDICT_FP_RE.search(body_txt):
                return
            confirmed.append(_make_confirmed(
                family, packet_id, title, None, buf,
                finding_index=next_idx,
            ))
            next_idx += 1

        for line in content.splitlines():
            mh = h2_hit_re.match(line)
            if mh:
                _flush_d(h2_title, h2_buf)
                idnums = (mh.group("idnums") or "").strip()
                title_raw = (mh.group("title") or "").strip()
                if title_raw:
                    h2_title = f"Hit {idnums} — {title_raw}" if idnums else f"Hit — {title_raw}"
                elif idnums:
                    h2_title = f"Hit {idnums}"
                else:
                    h2_title = "Hit"
                h2_buf = []
                continue
            # Any non-Hit `## ` heading closes the current Hit
            if line.startswith("## ") and h2_title is not None:
                _flush_d(h2_title, h2_buf)
                h2_title = None
                h2_buf = []
                continue
            if h2_title is not None:
                h2_buf.append(line)
        _flush_d(h2_title, h2_buf)

    # If "Confirmed issues" exists but has no subsections, look for
    # "None" / "_None._" patterns; treat as zero confirmed. `body` is
    # only set when PASS B ran (PASS A short-circuited it); fall back
    # to the canonical section directly so we never UnboundLocalError.
    body_for_none_check = sections.get("confirmed issues", [])
    body_text_lower = " ".join(body_for_none_check).lower()
    confirmed_explicitly_none = (
        not confirmed and ("none" in body_text_lower or "_none_" in body_text_lower)
    )

    # --- Dismissed: just count bullets that point to file:line refs.
    dismissed_bullets = 0
    dismissed_files: set[str] = set()
    for line in sections.get("dismissed sensor hits", []):
        bm = _REPORT_BULLET_RE.match(line)
        if not bm:
            continue
        dismissed_bullets += 1
        for fl in _REPORT_FILELINE_RE.finditer(bm.group(1)):
            if _is_filepath_like(fl.group("path"), fl.group("ext")):
                dismissed_files.add(fl.group("path"))

    # --- Limitations: bullets, each one item.
    limitations: list[dict] = []
    for line in sections.get("limitations", []):
        bm = _REPORT_BULLET_RE.match(line)
        if not bm:
            continue
        text = bm.group(1).strip()
        if not text:
            continue
        limitations.append({
            "family":   family,
            "packet":   packet_id,
            "text":     text,
        })

    # --- Files read during investigation: gather file paths.
    files_read: set[str] = set()
    for line in sections.get("files read during investigation", []):
        for fl in _REPORT_FILELINE_RE.finditer(line):
            if _is_filepath_like(fl.group("path"), fl.group("ext")):
                files_read.add(fl.group("path"))

    return {
        "family":               family,
        "packet_id":            packet_id,
        "summary":              summary_text,
        "confirmed":            confirmed,
        "confirmed_count":      len(confirmed),
        "confirmed_none":       confirmed_explicitly_none,
        "dismissed_bullets":    dismissed_bullets,
        "dismissed_files":      sorted(dismissed_files),
        "limitations":          limitations,
        "limitations_count":    len(limitations),
        "files_read":           sorted(files_read),
    }


def _make_confirmed(
    family: str, packet_id: str, title: str, sev: str | None,
    body_lines: list[str], *, finding_index: int = 0,
) -> dict:
    body = "\n".join(body_lines).strip()
    refs: list[tuple[str, int]] = []
    blob = title + "\n" + body
    seen: set[tuple[str, int]] = set()
    for fl in _REPORT_FILELINE_RE.finditer(blob):
        path = fl.group("path")
        if not _is_filepath_like(path, fl.group("ext")):
            continue
        line_raw = fl.group("line")
        try:
            line = int(line_raw) if line_raw else 0
        except ValueError:
            line = 0
        key = (path, line)
        if key in seen:
            continue
        seen.add(key)
        refs.append((path, line))

    severity_norm = (sev or "").strip().lower()
    # Fallback 1: severity at the end of the title, e.g. "Some title — med".
    # Strip it from the visible title to avoid noisy repetition.
    if not severity_norm:
        m = _TRAILING_SEV_RE.search(title)
        if m:
            severity_norm = m.group("sev").lower()
            title = _TRAILING_SEV_RE.sub("", title).strip()
    # Fallback 2: skill puts severity in the BODY as
    # "**Severity: Medium-High**" / "**Severity:** High" / etc. The
    # PASS A `## Finding N — Title` shape never embeds severity in the
    # title, so this is the path used for ToB-style outputs (access-
    # control, config-deployment). Without this fallback every Medium/
    # High finding was being bucketed under "Severity: info" and burying
    # the real ones under reams of unranked entries.
    if not severity_norm or severity_norm == "info":
        body_sev = _extract_body_severity(body)
        if body_sev:
            severity_norm = body_sev
    # Normalise abbreviations.
    if severity_norm == "med":
        severity_norm = "medium"
    elif severity_norm == "crit":
        severity_norm = "critical"
    return {
        "family":         family,
        "packet":         packet_id,
        "finding_index":  finding_index,
        "severity":       severity_norm,
        "title":          title,
        "refs":           refs,
        "body":           body,
        "is_dismissed":   _is_dismissed_finding(title, body),
    }


# Title patterns the skill uses to MARK a would-be finding as
# explicitly NOT a vulnerability. These are meta-statements ("I looked
# here and found nothing") and must not be counted as confirmed
# findings — they're noise in the report headline and obscure the
# real findings.
_DISMISSED_TITLE_PATTERNS: tuple[re.Pattern, ...] = (
    # Skill output uses uppercase "DISMISSED" as an explicit verdict
    # token. Match it as a word, not as a substring of another word
    # (won't match "Dismissive" or similar).
    re.compile(r"\bDISMISSED\b"),
    # "No <something> Vulnerabilities Found" / "No <something>
    # Vulnerabilities" — explicit negative finding.
    re.compile(r"\bno\b.*\bvulnerabilit", re.IGNORECASE),
    # "No <X> Found in This Cluster" — skill's standard phrasing
    # when a cluster turns out to be a non-issue.
    re.compile(r"\bno\b.*\bfound in this cluster\b", re.IGNORECASE),
    # "No BOLA Pattern in This Cluster" / "No Bypass Paths in This Cluster"
    re.compile(
        r"\bno\b.*\b(bola|bypass|idor|injection|auth)\b.*\bcluster\b",
        re.IGNORECASE,
    ),
    # Exact "Dismissed Hits" / "Dismissed Sensor Hits" as a finding title
    # (the section header that wandered into the structured pass).
    re.compile(r"^\s*Dismissed\s+(Hits|Sensor\s+Hits)\s*$", re.IGNORECASE),
)


def _is_dismissed_finding(title: str, body: str) -> bool:
    """True when this 'finding' is a skill's meta-statement that it
    found nothing here, not an actual vulnerability.

    Real-world examples we drop:
      - "3: DISMISSED — No Bypass Paths in This Cluster"
      - "No Access-Control Vulnerabilities Found in This Cluster"
      - "1: DISMISSED — Frontend Permission Checks Are Not a Security
         Boundary"
      - "Dismissed Hits"
    """
    for pat in _DISMISSED_TITLE_PATTERNS:
        if pat.search(title):
            return True
    # Also drop entries whose body opens with "**Status: DISMISSED**"
    # or "**Verdict: Not a vulnerability**" — same meta-signal in body.
    body_head = body[:300].lower()
    if "status: dismissed" in body_head or "verdict: not a vulnerability" in body_head:
        return True
    return False


def _walk_findings(repo_path: Path) -> list[tuple[str, str, Path]]:
    """Walk `.audit/04-packets-sensors/<family>/PACKET-*.findings.md`.

    Returns list of (family, packet_id, path) tuples.
    """
    root = repo_path.resolve() / ".audit" / "04-packets-sensors"
    if not root.is_dir():
        return []
    out: list[tuple[str, str, Path]] = []
    for family_dir in sorted(root.iterdir()):
        if not family_dir.is_dir():
            continue
        slug = family_dir.name
        if not slug.startswith("audit-"):
            continue
        family = "audit/" + slug[len("audit-"):]
        for f in sorted(family_dir.glob("PACKET-*.findings.md")):
            packet_id = f.stem.replace(".findings", "")
            out.append((family, packet_id, f))
    return out


def _walk_findings_extended(repo_path: Path) -> dict:
    """Discover all Phase-7 audit artefacts under `<repo>/.audit/`.

    Returns a structured view of the disk layout introduced in the ToB
    refactor:

    - ``findings``: existing per-family findings files (same as
      :func:`_walk_findings`).
    - ``context_building``: ``04-context/context-building.md`` if present.
    - ``entry_points``:     ``04-context/entry-points.md`` if present.
    - ``variants``:         sorted list of ``06-variants/*.md`` files.
    - ``fp_check``:         ``06-fp-check/audit-of-audits.md`` if present.

    Missing artefacts are reported as ``None`` (or an empty list for
    ``variants``) so the caller can render an empty "new section" without
    branching on existence checks.
    """
    audit_root = repo_path.resolve() / ".audit"

    ctx_md = audit_root / "04-context" / "context-building.md"
    ep_md  = audit_root / "04-context" / "entry-points.md"
    fp_md  = audit_root / "06-fp-check" / "audit-of-audits.md"

    variants: list[Path] = []
    variants_dir = audit_root / "06-variants"
    if variants_dir.is_dir():
        # Variants are now stored per-family at `06-variants/<family-slug>/
        # <PACKET-ID>-<idx>.md` to avoid cross-family collisions when two
        # families both produce PACKET-N + finding #M. Walk recursively
        # so we also pick up legacy flat layout (pre-fix audits).
        variants = sorted(variants_dir.rglob("*.md"))

    # Families that were elected and had sensors run, but produced
    # zero packets (no sensor patterns matched). Surface these so the
    # auditor can tell the difference between "family wasn't elected"
    # and "family ran but found nothing to investigate". On salazar:
    # business-logic + server-side-injection elected by backstop,
    # sensors ran on both, but the patterns are tuned for Node
    # idioms (GORM-using Go repos produce 0 hits because GORM is
    # parametrised-by-default — which is itself a positive signal).
    skipped_families: list[dict] = []
    packets_root = audit_root / "04-packets-sensors"
    if packets_root.is_dir():
        for fam_dir in sorted(packets_root.iterdir()):
            if not fam_dir.is_dir() or not fam_dir.name.startswith("audit-"):
                continue
            idx = fam_dir / "packet-index.json"
            if not idx.is_file():
                continue
            # If at least one PACKET-NNN.md exists, the family has packets.
            if any(
                p.suffix == ".md" and p.stem.startswith("PACKET-")
                and not p.stem.endswith(".findings")
                for p in fam_dir.iterdir()
            ):
                continue
            fam_name = "audit/" + fam_dir.name[len("audit-"):]
            skipped_families.append({
                "family": fam_name,
                "reason": "sensors ran but produced 0 hits",
            })

    return {
        "findings":         _walk_findings(repo_path),
        "context_building": ctx_md if ctx_md.is_file() else None,
        "entry_points":     ep_md if ep_md.is_file() else None,
        "variants":         variants,
        "fp_check":         fp_md if fp_md.is_file() else None,
        "skipped_families": skipped_families,
    }


def _build_coverage_map(
    repo_path: Path,
    by_family: dict | None,
    skipped_families: list[dict] | None = None,
) -> list[dict]:
    """Build the per-family coverage table for the structural report.

    The Coverage Map distinguishes families that were *investigated*
    (sensors ran, possibly produced findings) from families *never
    elected* (blind spots). Without it, "audit/server-side-injection: 0
    findings" in the report is ambiguous: it could mean the family was
    investigated and the repo is genuinely clean on SSI, or that we
    never looked. This function gives the reader an explicit answer for
    every family in :data:`sra.cli.SENSOR_SUPPORTED_FAMILIES`.

    Inputs:

    - ``repo_path``: the audited repo. We read
      ``<repo>/.audit/01-pack-router/selected-packs.json`` (best-effort)
      and walk ``<repo>/.audit/04-packets-sensors/<slug>/`` for each
      supported family.
    - ``by_family``: the ``agg["by_family"]`` dict from
      :func:`_aggregate_findings`. Provides ``packets`` + ``confirmed``
      counts for families that produced findings.
    - ``skipped_families``: the list emitted by
      :func:`_walk_findings_extended` for families where sensors ran but
      no packets were produced.

    Returns a sorted list of row dicts:

        {"family": "audit/<name>",
         "status": "Investigated" | "Elected (clean)" |
                   "Elected (pending)" | "CLI override" | "Not in scope",
         "source": "LLM" | "Backstop" | "CLI" | "—",
         "packets":   int | None,
         "confirmed": int | None}

    On-disk state under ``04-packets-sensors/`` is authoritative for the
    *status*: if a PACKET-NNN.md exists OR the family appears in
    ``by_family``, the family was investigated regardless of what
    ``selected-packs.json`` says. ``selected-packs.json`` only drives
    the *source* attribution (and the ``Elected (pending)`` status when
    a family was elected but its sensors never ran).

    When ``selected-packs.json`` is absent (e.g. only ``sra collect``
    has been run, or the file was deleted), every row falls back to
    ``source="—"`` and the status is derived purely from on-disk
    presence; no spurious ``CLI override`` attribution is invented.
    """
    # Lazy import: cli.py imports `cmd_build_report` from this module,
    # so importing SENSOR_SUPPORTED_FAMILIES at module load creates a
    # circular import. Deferring it to call time keeps both modules
    # importable in any order.
    from sra.cli import SENSOR_SUPPORTED_FAMILIES

    audit_root   = repo_path.resolve() / ".audit"
    packets_root = audit_root / "04-packets-sensors"

    # Read selected-packs.json (best-effort).
    selected_path = audit_root / "01-pack-router" / "selected-packs.json"
    selected_present = False
    elected_audit: set[str] = set()
    backstop_packs: set[str] = set()
    try:
        data = json.loads(selected_path.read_text(encoding="utf-8"))
        selected_present = True
    except (OSError, json.JSONDecodeError):
        data = None
    if isinstance(data, dict):
        sp = data.get("selected_packs")
        if isinstance(sp, dict):
            audit_list = sp.get("audit", [])
            if isinstance(audit_list, list):
                elected_audit = {p for p in audit_list if isinstance(p, str)}
        ba = data.get("backstop_additions") or []
        if isinstance(ba, list):
            backstop_packs = {
                b.get("pack") for b in ba
                if isinstance(b, dict) and isinstance(b.get("pack"), str)
            }

    by_family   = by_family or {}
    skipped_set = {
        e.get("family") for e in (skipped_families or [])
        if isinstance(e, dict) and isinstance(e.get("family"), str)
    }

    rows: list[dict] = []
    for fam in SENSOR_SUPPORTED_FAMILIES:
        slug    = fam.replace("/", "-")
        fam_dir = packets_root / slug
        idx_file = fam_dir / "packet-index.json"
        has_idx       = idx_file.is_file()
        has_packet_md = False
        if fam_dir.is_dir():
            for child in fam_dir.iterdir():
                name = child.name
                if (name.startswith("PACKET-")
                        and name.endswith(".md")
                        and not name.endswith(".findings.md")):
                    has_packet_md = True
                    break

        in_elected   = fam in elected_audit
        in_backstop  = fam in backstop_packs
        in_by_family = fam in by_family
        in_skipped   = fam in skipped_set

        # Status: on-disk truth wins.
        if has_packet_md or in_by_family:
            if not selected_present or in_elected:
                # selected-packs.json missing → can't tell if it was an
                # override; default to "Investigated" rather than invent
                # a false "CLI override" attribution.
                status = "Investigated"
            else:
                status = "CLI override"
        elif has_idx or in_skipped:
            status = "Elected (clean)"
        elif in_elected:
            # Listed in selected_packs but sensors never ran (or ran and
            # crashed before writing packet-index.json).
            status = "Elected (pending)"
        else:
            status = "Not in scope"

        # Source: how did the family end up elected?
        if not selected_present:
            source = "—"
        elif in_backstop:
            source = "Backstop"
        elif in_elected:
            source = "LLM"
        elif status in (
            "Investigated", "CLI override",
            "Elected (clean)", "Elected (pending)",
        ):
            # On-disk artefacts exist but family wasn't in
            # selected_packs.json → user passed `--family X` on the CLI.
            source = "CLI"
        else:
            source = "—"

        if status == "Not in scope":
            packets   = None
            confirmed = None
        else:
            row = by_family.get(fam, {})
            packets   = int(row.get("packets",   0)) if row else 0
            confirmed = int(row.get("confirmed", 0)) if row else 0

        rows.append({
            "family":    fam,
            "status":    status,
            "source":    source,
            "packets":   packets,
            "confirmed": confirmed,
        })

    # Sort: investigated/CLI-override first, then elected-but-clean,
    # then elected-pending, then not-in-scope. Within each bucket,
    # alphabetical by family.
    status_priority = {
        "Investigated":      0,
        "CLI override":      0,
        "Elected (clean)":   1,
        "Elected (pending)": 1,
        "Not in scope":      2,
    }
    rows.sort(key=lambda r: (status_priority.get(r["status"], 99), r["family"]))
    return rows


def _read_text_safely(path: Path) -> str:
    """Best-effort UTF-8 read; bytes that don't decode are replaced.

    Phase 2 noted that some PACKET-NNN.findings.md files are UTF-16 LE
    (Windows redirect quirk). For Phase 7 we want artefact reads
    (context, entry-points, variants, fp-check) to be just as forgiving
    so a stray encoding glitch never breaks the report build.
    """
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _consolidate_touch_counts(counts: dict[str, int]) -> dict[str, int]:
    """Fold bare-filename touch counts into qualified-path counts.

    Skills cite the same file two ways across a report — sometimes
    `app.go` (bare), sometimes `salazar-api/app/app.go` (qualified).
    The aggregator collected both as separate keys, fragmenting the
    top-files ranking. This pass:

    1. Canonicalises separators to `/` so `a\\b\\file.go` and
       `a/b/file.go` are treated as the same key.
    2. Splits paths into "bare" (no `/`) and "qualified" (has `/`).
    3. For each bare path, finds qualified paths that END with
       `/<bare>`. If EXACTLY ONE qualified match exists, the bare
       count is added to the qualified one and the bare row dropped.
    4. If 0 qualified matches: keep the bare row.
       If >1 matches: distribute the bare count EVENLY across the
       matches (instead of keeping a single inflated bare row that
       outranked the legitimate qualified hits in the table).
    """
    # Step 1: canonicalise separator. Two qualified rows that
    # differ only by `/` vs `\` would otherwise stay separate.
    canonical: dict[str, int] = {}
    for p, c in counts.items():
        norm = p.replace("\\", "/")
        canonical[norm] = canonical.get(norm, 0) + c

    qualified = {p: c for p, c in canonical.items() if "/" in p}
    bare      = {p: c for p, c in canonical.items() if p not in qualified}
    out = dict(qualified)
    for bp, bcount in bare.items():
        suffix = "/" + bp
        matches = [qp for qp in qualified if qp.endswith(suffix)]
        if len(matches) == 1:
            out[matches[0]] = out.get(matches[0], 0) + bcount
        elif len(matches) > 1:
            # Distribute evenly to avoid one inflated bare row
            # outranking the legit qualified hits. Integer division
            # leaves a small remainder we drop on the floor; the bare
            # row is removed.
            share = bcount // len(matches)
            for m in matches:
                out[m] = out.get(m, 0) + share
        else:
            # 0 matches: lone bare reference, keep it.
            out[bp] = bcount
    return out


def _extract_preview(content: str, *, max_chars: int = 600) -> str:
    """Return a 2-3 sentence preview from a long markdown blob.

    Two-phase scan:

      1. Skip leading conversational intro lines that ``claude -p`` in
         stream-json capture mode includes verbatim before the real
         report (e.g. "I'll start by exploring...", "Now let me dive
         into...", "Here is the report:"). These are byproducts of the
         agentic loop's intermediate text messages and have no
         informational value in a preview.

      2. After the intro is stripped, behave as before: skip headings,
         collect the first non-empty paragraph, return up to 3
         sentences capped at ``max_chars``.

    If the entire content is conversational (no real paragraph after
    the intros), fall back to the first non-intro paragraph rather
    than returning empty.
    """
    # Conversational-AI lead-in prefixes (case-insensitive). Lines that
    # START with one of these and live BEFORE any real paragraph are
    # discarded. We don't pattern-match mid-paragraph because the same
    # phrasing can legitimately appear in skill output later.
    _CONV_PREFIXES = (
        "i'll ", "i will ", "let me ", "now let me ", "now i have ",
        "i now have ", "here is ", "here's ", "based on ",
        "after analyzing ", "after reviewing ", "let's ",
    )

    def _looks_conversational(s: str) -> bool:
        sl = s.lower()
        return any(sl.startswith(p) for p in _CONV_PREFIXES)

    # PHASE 1: skip intro lines (conversational + headings + blanks +
    # horizontal rules) until we hit the first real paragraph line.
    lines = content.splitlines()
    i = 0
    fallback: list[str] = []
    while i < len(lines):
        s = lines[i].strip()
        if not s or s.startswith("#") or s == "---":
            i += 1
            continue
        if _looks_conversational(s):
            # Remember it as a fallback in case the whole doc is
            # conversational, then skip to next paragraph break.
            fallback.append(s)
            i += 1
            while i < len(lines) and lines[i].strip():
                i += 1
            continue
        break

    # PHASE 2: collect the first real paragraph at position `i`.
    para: list[str] = []
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("#"):
            if para:
                break
            i += 1
            continue
        if not s:
            if para:
                break
            i += 1
            continue
        para.append(s)
        i += 1

    if not para:
        # Whole document was conversational — return the best fallback
        # we collected so the preview isn't empty.
        para = fallback[:1]
    if not para:
        return ""
    text = " ".join(para).strip()
    # If the first paragraph ends mid-thought with a colon (`...
    # composed of 7 microservices:` — usually preceding a table), the
    # standard sentence-split returns just that one fragment and loses
    # the next paragraph's substance. Detect this and pull the second
    # paragraph too. We only look one paragraph forward to stay short.
    if text.rstrip().endswith(":"):
        # Find the next non-empty non-heading paragraph after position `i`.
        next_para: list[str] = []
        while i < len(lines):
            s = lines[i].strip()
            i += 1
            if not s or s.startswith("#") or s.startswith("|") or s.startswith("---"):
                if next_para:
                    break
                continue
            next_para.append(s)
        if next_para:
            text = text + " " + " ".join(next_para)
    # Pull up to the first 3 sentence boundaries; degrade gracefully if
    # the paragraph has no clear sentence breaks.
    parts = re.split(r"(?<=[.!?])\s+", text, maxsplit=3)
    preview = " ".join(parts[:3]).strip()
    if len(preview) > max_chars:
        preview = preview[: max_chars - 3] + "..."
    return preview


def _parse_variant_file(path: Path) -> dict | None:
    """Parse one variant file.

    Layout supported (in order):

      1. ``06-variants/<family-slug>/<PACKET-ID>-<idx>.md``
         The current writer convention. Family slug is the immediate
         parent directory; PACKET-ID + finding-index are encoded in
         the filename.

      2. ``06-variants/<PACKET-ID>-<idx>.md``
         The pre-fix flat layout. Family is unknown — we surface this
         as None so the renderer can still link the variant to its
         confirmed entry by ``(packet_id, finding_index)`` alone (the
         only collision case requires two families with both PACKET-N
         and finding #M, which is rare in pre-fix audits because the
         old flat layout would have silently overwritten one of them).

    Returns ``None`` if the filename does not match
    ``<PACKET-ID>-<finding-index>.md``.
    """
    m = _VARIANT_FILENAME_RE.match(path.stem)
    if m is None:
        return None
    packet_id     = m.group("packet")
    finding_index = int(m.group("idx"))
    # Family slug is the parent directory under 06-variants/ when the
    # new layout is in use. When the flat (legacy) layout is in use,
    # the parent is 06-variants itself so we treat it as None.
    parent = path.parent.name
    family_slug = parent if parent.startswith("audit-") else None

    content = _read_text_safely(path)
    # Empty / near-empty variant file (e.g. claude -p produced no output
    # and we wrote a 0- or 2-byte stub). Without this guard the renderer
    # emits a ghost "Variant N" heading + empty body. Real-world: salazar
    # had `PACKET-025-1.md` of 2 bytes that rendered as an empty entry
    # below the originating finding.
    if not content.strip():
        return None
    lines   = content.splitlines()

    # Title: first non-empty line, with leading '#'s stripped. Falls back
    # to "Variant N" when the file is empty or starts with content that
    # cleans to an empty title.
    title = f"Variant {finding_index}"
    first_idx: int | None = None
    for i, ln in enumerate(lines):
        if ln.strip():
            stripped = ln.strip().lstrip("#").strip()
            if stripped:
                title = stripped
            first_idx = i
            break

    # Summary: first paragraph AFTER the title line (skip subsequent
    # heading-only lines so the summary doesn't end up being a heading).
    summary_para: list[str] = []
    if first_idx is not None:
        for ln in lines[first_idx + 1:]:
            s = ln.strip()
            if not s:
                if summary_para:
                    break
                continue
            if s.startswith("#"):
                if summary_para:
                    break
                continue
            summary_para.append(s)
    summary = " ".join(summary_para).strip()
    if len(summary) > 400:
        summary = summary[:397] + "..."

    return {
        "packet":         packet_id,
        "finding_index":  finding_index,
        "family_slug":    family_slug,
        "path":           path,
        "title":          title,
        "summary":        summary,
        "content":        content,
    }


def _parse_fp_check(content: str) -> dict:
    """Best-effort parse of ``06-fp-check/audit-of-audits.md``.

    Builds two indexes:

    - ``flagged_refs[(path, line)] -> note`` for every backticked
      ``file:line`` reference found in the document.
    - ``flagged_packets[packet_id] -> note`` for every ``PACKET-NNN``
      mention.

    The aggregator uses these indexes to flip ``fp_flagged`` on confirmed
    findings whose path/line or packet id appears anywhere in the
    audit-of-audits report. The note is the surrounding line, captured
    verbatim so a human auditor can jump straight to the verdict
    sentence.
    """
    summary = _extract_preview(content, max_chars=800)

    flagged_refs:    dict[tuple[str, int], str] = {}
    flagged_packets: dict[str, str] = {}

    for ln in content.splitlines():
        if not ln.strip():
            continue
        for fl in _REPORT_FILELINE_RE.finditer(ln):
            path = fl.group("path")
            if not _is_filepath_like(path, fl.group("ext")):
                continue
            line_raw = fl.group("line")
            try:
                line_no = int(line_raw) if line_raw else 0
            except ValueError:
                line_no = 0
            flagged_refs.setdefault((path, line_no), ln.strip())
            # File-level fallback `(path, 0)`: only safe for QUALIFIED
            # paths (with `/` or `\` separator). For bare filenames
            # like `config.json`, the fallback would flag any finding
            # citing that bare name regardless of the actual file (a
            # repo can have many `config.json`s). Real-world impact on
            # salazar: every finding mentioning `config.json` was
            # over-flagged because fp-check mentioned `config.json:10`
            # of ONE specific service.
            if "/" in path or "\\" in path:
                flagged_refs.setdefault((path, 0), ln.strip())
        for pm in _PACKET_REF_RE.finditer(ln):
            flagged_packets.setdefault(pm.group(0), ln.strip())

    return {
        "summary":         summary,
        "flagged_refs":    flagged_refs,
        "flagged_packets": flagged_packets,
    }


def _aggregate_findings(
    parsed: list[dict],
    *,
    variants: list[dict] | None = None,
    fp_check_data: dict | None = None,
    repo_root: Path | None = None,
) -> dict:
    """Aggregate per-packet parsed findings into a per-repo view.

    The optional ``variants`` (parsed by :func:`_parse_variant_file`) and
    ``fp_check_data`` (from :func:`_parse_fp_check`) are linked back onto
    each confirmed finding:

    - ``c["variants"]``  — list of ``{path, title, summary}`` dicts for
      every ``<PACKET-ID>-<finding-index>.md`` that matches this
      confirmed entry by ``(packet, finding_index)``.
    - ``c["fp_flagged"]`` / ``c["fp_note"]`` — True + the surrounding
      audit-of-audits line if fp-check mentioned this finding's
      file:line (or its packet id) anywhere.

    When ``repo_root`` is provided, every variant path in the returned
    structure is rewritten to a repo-relative posix string so report
    links are stable across machines; otherwise an absolute posix string
    is emitted.
    """
    def _path_str(p: Path | str) -> str:
        if isinstance(p, str):
            return p
        if repo_root is not None:
            return _relative_or_posix(repo_root, p)
        return _posix(p)
    by_family: dict[str, dict] = {}
    confirmed_all: list[dict] = []
    limitations_all: list[dict] = []
    file_touch_count: dict[str, int] = {}

    for p in parsed:
        fam = p["family"]
        fam_row = by_family.setdefault(fam, {
            "packets":     0,
            "confirmed":   0,
            "dismissed":   0,
            "limitations": 0,
        })
        # Split confirmed into "real" and "explicitly dismissed by the
        # skill". Real ones contribute to the family confirmed count
        # and the rolled-up "Confirmed issues" section. Dismissed ones
        # are folded into the dismissed counter (they're meta-statements
        # the skill made — "I looked here and found nothing", "Status:
        # DISMISSED — frontend permission checks are cosmetic" — they
        # are NOT vulnerabilities and should not inflate the headline).
        real_confirmed = [c for c in p["confirmed"] if not c.get("is_dismissed")]
        skill_dismissed = [c for c in p["confirmed"] if c.get("is_dismissed")]

        fam_row["packets"]     += 1
        fam_row["confirmed"]   += len(real_confirmed)
        fam_row["dismissed"]   += p["dismissed_bullets"] + len(skill_dismissed)
        fam_row["limitations"] += p["limitations_count"]

        confirmed_all.extend(real_confirmed)
        limitations_all.extend(p["limitations"])

        # Count file mentions: confirmed refs weighted higher. Skill-
        # dismissed entries still contribute weak file-touch signal
        # because they tell us a human DID review that file.
        for c in real_confirmed:
            for fpath, _ in c.get("refs") or []:
                file_touch_count[fpath] = file_touch_count.get(fpath, 0) + 3
        for c in skill_dismissed:
            for fpath, _ in c.get("refs") or []:
                file_touch_count[fpath] = file_touch_count.get(fpath, 0) + 1
        for fpath in p["dismissed_files"]:
            file_touch_count[fpath] = file_touch_count.get(fpath, 0) + 1
        for fpath in p["files_read"]:
            file_touch_count[fpath] = file_touch_count.get(fpath, 0) + 1

    # Sort confirmed by family first, then severity within family,
    # then by first file ref. Reading the report as a security
    # auditor: you want the full story of `audit/access-control`
    # together (highest-sev first) before moving to the next
    # family. Old key was (severity, family, ref) which scattered
    # each family across the whole report.
    def conf_key(c: dict) -> tuple:
        sev = c.get("severity", "")
        sord = _REPORT_SEVERITY_ORDER.get(sev, 5)
        first_ref = (c.get("refs") or [("", 0)])[0]
        return (c.get("family", ""), sord, first_ref[0], first_ref[1])

    confirmed_all.sort(key=conf_key)

    # Cross-packet dedup.
    #
    # Old logic keyed on (family, refs[0]). That undercollapsed when
    # two packets cited the same vuln through different first-refs
    # and over-collapsed when two unrelated findings shared a single
    # config-file line. Current logic uses a 4-tier key:
    #
    #   1. exact title (case-folded, prefix-stripped, status-stripped)
    #      within the same family — same vuln re-reported by multiple
    #      packets;
    #   2. cross-family same-title collapse — the same hardcoded
    #      secret can be flagged by both crypto-auth AND config-
    #      deployment; we keep the higher-severity instance and
    #      track `also_in_families`.
    #   3. SORTED-FIRST then top-3 refs (sorted) — same vuln found at
    #      same evidence regardless of title phrasing. Note: sort
    #      happens BEFORE the slice so two packets that cited the
    #      same 5 refs but in different orders both end up keyed by
    #      the same top-3 of the sorted set.
    #   4. fallback: first ref alone (legacy behaviour).
    #
    # `also_in_packets` and `also_in_families` collect attribution
    # so the renderer can surface "this finding showed up across N
    # packets / 2 families" without losing data.
    #
    # `_title_key` strips:
    #   - leading "Finding N: " / "Finding N — " / "Finding-N: "
    #     prefixes so different packets that prefix their version
    #     of the same finding with different numbers still collapse;
    #   - trailing "(CONFIRMED)" / "(SUSPECTED)" / etc. status tokens;
    #   - extra whitespace.
    _title_prefix_re = re.compile(
        r"^\s*finding[-\s]*\d*\s*[:\-—–]\s*", re.IGNORECASE,
    )
    _title_suffix_re = re.compile(
        r"\s*\(\s*(?:CONFIRMED|SUSPECTED|VERIFIED|UNCONFIRMED|TENTATIVE)"
        r"\b[^)]*\)\s*$",
        re.IGNORECASE,
    )

    def _title_key(s: str) -> str:
        s = _title_prefix_re.sub("", s)
        s = _title_suffix_re.sub("", s)
        return " ".join(s.lower().split())

    dedup: list[dict] = []
    by_title:        dict[tuple, dict] = {}   # (family, title)
    by_xfam_title:   dict[str, dict]   = {}   # title (no family) — cross-family
    by_refset:       dict[tuple, dict] = {}   # (family, sorted top-3 refs)
    for c in confirmed_all:
        refs = c.get("refs") or []
        fam = c.get("family", "")
        title_norm = _title_key(c.get("title", ""))
        title_k = (fam, title_norm)
        # Tier 1: same family, same normalised title.
        if title_norm and title_k in by_title:
            existing = by_title[title_k]
            if existing.get("packet") != c.get("packet"):
                existing.setdefault("also_in_packets", []).append(
                    c.get("packet", "")
                )
            continue
        # Tier 2: same NORMALISED title across families. We keep the
        # higher-severity (lower order int) entry and track the other
        # families in `also_in_families`. Safety guard: only fire when
        # the title is substantive (>= 30 chars) so we don't fold
        # generic 1-word titles like "Insecure default".
        if title_norm and len(title_norm) >= 30 and title_norm in by_xfam_title:
            existing = by_xfam_title[title_norm]
            # Track the cross-family attribution.
            other_fam = c.get("family", "")
            existing_fam = existing.get("family", "")
            if other_fam and other_fam != existing_fam:
                existing.setdefault("also_in_families", [])
                if other_fam not in existing["also_in_families"]:
                    existing["also_in_families"].append(other_fam)
            # If incoming is higher severity, swap which is kept.
            existing_sev = _REPORT_SEVERITY_ORDER.get(
                existing.get("severity", ""), 5
            )
            new_sev = _REPORT_SEVERITY_ORDER.get(
                c.get("severity", ""), 5
            )
            if new_sev < existing_sev:
                # Replace fields in `existing` with the new (higher-
                # sev) entry's content, preserving the attribution
                # lists.
                preserved = {
                    "also_in_packets":  existing.get("also_in_packets", []),
                    "also_in_families": existing.get("also_in_families", []),
                }
                preserved["also_in_families"].append(existing_fam)
                existing.clear()
                existing.update(c)
                existing.update(preserved)
            continue
        # Tier 3: same family, sorted-then-top-3 refs. Sort FIRST so
        # the top-3 are the 3 lowest by (path, line), not the first
        # 3 by author order. Prevents two packets that cite the same
        # 5 refs from missing dedup because the order differs.
        refset_k = None
        if refs:
            sorted_all = sorted((p, ln) for p, ln in refs)
            sorted_refs = tuple(sorted_all[:3])
            refset_k = (fam, sorted_refs)
            if refset_k in by_refset:
                existing = by_refset[refset_k]
                if existing.get("packet") != c.get("packet"):
                    existing.setdefault("also_in_packets", []).append(
                        c.get("packet", "")
                    )
                continue
        # New entry — record under all keys for the next pass.
        entry = dict(c)
        entry.setdefault("also_in_packets", [])
        entry.setdefault("also_in_families", [])
        dedup.append(entry)
        if title_norm:
            by_title[title_k] = entry
            if len(title_norm) >= 30:
                by_xfam_title[title_norm] = entry
        if refset_k is not None:
            by_refset[refset_k] = entry
    confirmed_all = dedup

    # --- Phase 7: link variants and fp-check flags onto confirmed entries.
    # Normalise each variant's path eagerly so downstream consumers
    # (the renderer's content lookup, the JSON emitter) all see the same
    # repo-relative string.
    variants = [
        {**v, "path_str": _path_str(v["path"])}
        for v in (variants or [])
    ]
    # Key includes family_slug to disambiguate cross-family collisions.
    # Before this fix, a confirmed finding in family A with PACKET-001
    # + finding #1 would erroneously get attached a variant from
    # family B's PACKET-001 + finding #1 (they share the same packet/
    # idx). Variants from the legacy flat layout have `family_slug=None`
    # and still match by (packet, idx) for backward compat.
    variants_by_key: dict[tuple[str | None, str, int], list[dict]] = {}
    for v in variants:
        key = (
            v.get("family_slug"),
            v.get("packet", ""),
            int(v.get("finding_index") or 0),
        )
        variants_by_key.setdefault(key, []).append(v)

    for c in confirmed_all:
        c_fam_slug = (c.get("family", "") or "").replace("/", "-")
        c_packet = c.get("packet", "")
        c_idx = int(c.get("finding_index") or 0)
        # Try family-scoped first, then fall back to legacy flat
        # (family_slug=None) for variants produced before the path
        # migration.
        v_list = variants_by_key.get((c_fam_slug, c_packet, c_idx), [])
        if not v_list:
            v_list = variants_by_key.get((None, c_packet, c_idx), [])
        c["variants"] = [
            {
                "path":    v["path_str"],
                "title":   v.get("title", ""),
                "summary": v.get("summary", ""),
            }
            for v in v_list
        ]

    fp_data = fp_check_data or {}
    fp_refs:    dict[tuple[str, int], str] = fp_data.get("flagged_refs", {})
    fp_packets: dict[str, str] = fp_data.get("flagged_packets", {})
    for c in confirmed_all:
        flagged = False
        note    = ""
        # Most reliable signal: fp-check mentioned THIS finding's
        # (file, line). The captured line is the verdict context.
        for path, line in (c.get("refs") or []):
            if (path, line) in fp_refs:
                flagged = True
                note    = fp_refs[(path, line)]
                break
            if (path, 0) in fp_refs:
                flagged = True
                note    = fp_refs[(path, 0)]
                break
        # Packet-level fallback: fp-check mentioned the PACKET id
        # somewhere. We still flag the finding (worth re-reviewing),
        # but DON'T attach a note — the first packet mention is
        # almost never the verdict for THIS specific finding (a
        # packet usually has several findings; the first mention
        # picks an arbitrary one). Attaching it produced consistently
        # misleading "fp-check: ..." annotations in real output.
        if not flagged:
            pid = c.get("packet", "")
            if pid in fp_packets:
                flagged = True
                # leave note empty; the per-finding-file output and
                # the linked audit-of-audits.md are the source of truth.
        c["fp_flagged"] = flagged
        c["fp_note"]    = note

    # Skills frequently cite the same file by both its bare name
    # (`app.go`) AND its qualified path (`salazar-api/app/app.go`)
    # depending on where in the body the reference appears. Without
    # consolidation the top-files table fragments the rank:
    #   app.go (34), salazar-api/app/app.go (7), app/app.go (45)
    # — three rows for one file. Fold bare-name counts into the
    # qualified path WHEN there is exactly one qualified path whose
    # tail matches the bare name. If multiple qualified paths share
    # the tail (e.g. `app.go` exists in 5 microservices), we cannot
    # safely fold so the bare row is kept as-is.
    file_touch_count = _consolidate_touch_counts(file_touch_count)
    top_files = sorted(
        file_touch_count.items(), key=lambda kv: (-kv[1], kv[0]),
    )[:30]

    variant_count     = sum(len(c.get("variants") or []) for c in confirmed_all)
    fp_flagged_count  = sum(1 for c in confirmed_all if c.get("fp_flagged"))

    return {
        "by_family":         by_family,
        "confirmed":         confirmed_all,
        "limitations":       limitations_all,
        "top_files":         top_files,
        "packet_total":      len(parsed),
        "variants":          variants,
        "variant_count":     variant_count,
        "fp_check":          fp_data,
        "fp_flagged_count":  fp_flagged_count,
    }


def _render_report_md(
    repo_name: str,
    agg: dict,
    *,
    context_preview: str = "",
    context_path:    str = "",
    entry_points_preview: str = "",
    entry_points_path:    str = "",
    fp_check_path:        str = "",
    skipped_families: list[dict] | None = None,
    coverage_map: list[dict] | None = None,
) -> str:
    lines: list[str] = []
    out = lines.append

    total_confirmed   = sum(f["confirmed"]   for f in agg["by_family"].values())
    total_dismissed   = sum(f["dismissed"]   for f in agg["by_family"].values())
    total_limitations = sum(f["limitations"] for f in agg["by_family"].values())
    variant_count     = agg.get("variant_count", 0)
    fp_flagged_count  = agg.get("fp_flagged_count", 0)

    out(f"# Audit report — `{repo_name}`")
    out("")
    out("> Aggregated from skill-produced `PACKET-NNN.findings.md` under "
        "`.audit/04-packets-sensors/`. No new investigation was performed "
        "at this stage; this is a structural roll-up.")
    out("")

    out("## Headline")
    out("")
    out(f"- Packets reviewed: **{agg['packet_total']}**")
    out(f"- Families covered: **{len(agg['by_family'])}**")
    out(f"- Confirmed issues: **{total_confirmed}**")
    out(f"- Dismissed sensor hits: **{total_dismissed}**")
    out(f"- Open limitations / architectural observations: **{total_limitations}**")
    out(f"- Variants discovered: **{variant_count}**")
    out(f"- Findings flagged by fp-check for re-review: **{fp_flagged_count}**")
    out("")

    out("## Repo context")
    out("")
    if context_preview or context_path:
        if context_preview:
            out(context_preview)
            out("")
        if context_path:
            out(f"_Full context-building report: [`{context_path}`]({context_path})_")
            out("")
    else:
        out("_Not produced for this audit (run `sra audit` with "
            "context-building enabled to populate this section)._")
        out("")

    # "Entry points" is only emitted on smart-contract audits (the ToB
    # entry-point-analyzer skill is contracts-only and is auto-skipped
    # by cmd_audit on non-contract repos). Hide the section entirely
    # when there's no content — emitting "Not produced" on every Go /
    # Python / Node audit was misleading (suggested the user forgot
    # a flag when actually the section is N/A for that repo).
    if entry_points_preview or entry_points_path:
        out("## Entry points")
        out("")
        if entry_points_preview:
            out(entry_points_preview)
            out("")
        if entry_points_path:
            out(f"_Full entry-point map: [`{entry_points_path}`]({entry_points_path})_")
            out("")

    # Coverage Map — what was investigated, regardless of findings.
    # Lets the reader distinguish "family ran and is clean" from "family
    # was never elected (blind spot)". Families with a sensor catalogue
    # but no elected status appear as "Not in scope" so blind spots are
    # explicit, not silent.
    if coverage_map:
        out("## Coverage Map")
        out("")
        out("Per-family scan coverage. Distinguishes families that were "
            "investigated (with or without findings) from families that "
            "were never elected. A reader can use this to verify no "
            "relevant family was silently skipped.")
        out("")
        out("- **Investigated** — sensors ran AND produced packets to review.")
        out("- **Elected (clean)** — sensors ran but produced 0 packets (often a positive signal).")
        out("- **Elected (pending)** — listed in `selected-packs.json` but sensors have not yet run.")
        out("- **CLI override** — investigated via `--family X` flag, not via fingerprint election.")
        out("- **Not in scope** — supported by sensors but not elected for this audit.")
        out("")
        out("| Family | Status | Source | Packets | Confirmed |")
        out("|---|---|---|---:|---:|")
        for r in coverage_map:
            pkt = "—" if r["packets"]   is None else str(r["packets"])
            cnf = "—" if r["confirmed"] is None else str(r["confirmed"])
            out(
                f"| `{r['family']}` | {r['status']} | {r['source']} | "
                f"{pkt} | {cnf} |"
            )
        out("")

    out("## Per-family breakdown")
    out("")
    out("| Family | Packets | Confirmed | Dismissed | Limitations |")
    out("|---|---:|---:|---:|---:|")
    for fam in sorted(agg["by_family"]):
        f = agg["by_family"][fam]
        out(
            f"| `{fam}` | {f['packets']} | {f['confirmed']} | "
            f"{f['dismissed']} | {f['limitations']} |"
        )
    out("")

    # Families that were elected but produced zero packets (sensors
    # ran, no patterns matched). Worth surfacing so the auditor can
    # tell that we DID look at the family — and on a well-architected
    # codebase, "no sensor hits" is itself a (positive) signal.
    if skipped_families:
        out("## Families elected but with no packets to investigate")
        out("")
        out("> These families were elected by the fingerprint / backstop, "
            "and the sensors (ripgrep + semgrep + ast-grep) ran against the "
            "repo for each — but the patterns produced zero hits. On a "
            "well-architected codebase this is often a positive signal "
            "(e.g. no raw SQL means no SQL-injection-shaped patterns "
            "to flag). For each, you may want to do a manual spot-check "
            "to confirm.")
        out("")
        for entry in skipped_families:
            out(f"- `{entry['family']}` — {entry['reason']}")
        out("")

    out("## Confirmed issues")
    out("")
    if not agg["confirmed"]:
        out("_None._")
    else:
        # Group by FAMILY first, then by severity within family.
        # Auditor experience: you read access-control's whole story
        # together (high → info), then move to crypto-auth's whole
        # story, then config-deployment's. Earlier we grouped by
        # severity globally which scattered each family across the
        # report and required jumping back and forth to follow one
        # vuln class.
        last_fam = None
        last_sev = None
        for c in agg["confirmed"]:
            fam = c.get("family") or "audit/(unknown)"
            if fam != last_fam:
                out(f"### Family: `{fam}`")
                out("")
                last_fam = fam
                last_sev = None
            sev = c.get("severity") or "unrated"
            if sev != last_sev:
                # Render unrated explicitly so it's visually distinct
                # from the actual "info" severity bucket.
                label = "unrated (parser could not extract)" if sev == "unrated" else sev
                out(f"#### Severity: `{label}`")
                out("")
                last_sev = sev
            ref_str = ""
            if c.get("refs"):
                ref_str = " — " + ", ".join(
                    f"`{p}:{ln}`" for (p, ln) in c["refs"][:3]
                )
                if len(c["refs"]) > 3:
                    ref_str += f" (+{len(c['refs']) - 3} more)"
            fp_tag = " ⚠ fp-check flagged" if c.get("fp_flagged") else ""
            out(f"- **{c['title']}**{ref_str}{fp_tag}")
            packet_line = f"  - Family: `{c['family']}` · Packet: `{c['packet']}`"
            also_in = c.get("also_in_packets") or []
            if also_in:
                packet_line += " (also flagged by: " + ", ".join(
                    f"`{p}`" for p in also_in
                ) + ")"
            out(packet_line)
            also_fams = c.get("also_in_families") or []
            if also_fams:
                out(
                    f"  - Also surfaced under: "
                    + ", ".join(f"`{f}`" for f in also_fams)
                )
            body_short = c.get("body", "").strip()
            if body_short:
                preview_lines: list[str] = []
                for ln in body_short.splitlines():
                    if ln.strip().startswith("```"):
                        continue
                    preview_lines.append(ln)
                    if len(preview_lines) >= 4:
                        break
                preview = " ".join(s.strip() for s in preview_lines if s.strip())
                if len(preview) > 320:
                    preview = preview[:317] + "..."
                if preview:
                    out(f"  - {preview}")
            # We used to render `- fp-check: <note>` inline here. The
            # `<note>` was the FIRST audit-of-audits line that mentioned
            # this finding's file (or just the packet id), which in
            # practice was the verdict for some OTHER finding that
            # happened to be cited in the same row. The result was a
            # consistently misleading annotation. We now only render the
            # `⚠ fp-check flagged` icon next to the title (handled
            # earlier) and link to `audit-of-audits.md` at the bottom
            # of the report for the real verdict.
            for v in (c.get("variants") or []):
                out(
                    f"  - Variant: **{v.get('title', '')}** "
                    f"([`{v['path']}`]({v['path']}))"
                )
                v_summary = (v.get("summary") or "").strip()
                if v_summary:
                    short = v_summary if len(v_summary) <= 240 else v_summary[:237] + "..."
                    out(f"    - {short}")
        out("")

    out("## Variant findings")
    out("")
    # Render variants as a flat link list grouped by parent confirmed
    # finding. Old behaviour dumped the FULL content of each variant
    # file inline — which pollutes the report's heading hierarchy
    # because variant files contain their own `## Original Finding`,
    # `## Root Cause Analysis`, etc. sections that get promoted to
    # top-level of the aggregated report. Linking out is cleaner and
    # the auditor can open the variant file when they need the
    # details.
    confirmed_with_variants = [
        c for c in agg["confirmed"] if c.get("variants")
    ]
    orphan_variants = list(agg.get("variants") or [])
    if confirmed_with_variants:
        seen_paths: set[str] = set()
        for c in confirmed_with_variants:
            title = c.get("title") or "(untitled)"
            out(
                f"### From confirmed: {title} "
                f"(`{c['family']}` / `{c['packet']}` "
                f"#{c.get('finding_index', 0)})"
            )
            out("")
            for v in c.get("variants") or []:
                path_str = v.get("path", "")
                seen_paths.add(path_str)
                v_title = v.get("title", "") or "(variant)"
                out(f"- **{v_title}** — [`{path_str}`]({path_str})")
                # Find the summary in orphan_variants; trim to 200 chars
                # so the report stays scannable.
                summary = ""
                for raw in orphan_variants:
                    if raw.get("path_str") == path_str:
                        summary = raw.get("summary", "") or ""
                        break
                if summary:
                    short = summary if len(summary) <= 200 else summary[:197] + "..."
                    out(f"  - {short}")
            out("")
        # Surface variants whose filename did not match any confirmed
        # finding (e.g. PACKET-NNN-9.md with no #9 confirmed in the
        # findings file). Render them under their own subhead so the
        # content is still visible to the auditor.
        orphans = [
            v for v in orphan_variants
            if v.get("path_str") not in seen_paths
        ]
        if orphans:
            out("### Unmatched variants")
            out("")
            out("_The variant filename did not match any confirmed "
                "finding (the originating finding may have been "
                "dismissed since the variant was produced, or the "
                "filename is non-canonical)._")
            out("")
            for v in orphans:
                path_str = v.get("path_str", "")
                v_title = v.get("title", "") or "(variant)"
                out(f"- **{v_title}** — [`{path_str}`]({path_str})")
                summary = v.get("summary", "") or ""
                if summary:
                    short = summary if len(summary) <= 200 else summary[:197] + "..."
                    out(f"  - {short}")
            out("")
    elif orphan_variants:
        out("_No confirmed finding matched a variant filename — "
            "variants are shown unattached below._")
        out("")
        for v in orphan_variants:
            path_str = v.get("path_str", "")
            v_title = v.get("title", "") or "(variant)"
            out(f"- **{v_title}** — [`{path_str}`]({path_str})")
            summary = v.get("summary", "") or ""
            if summary:
                short = summary if len(summary) <= 200 else summary[:197] + "..."
                out(f"  - {short}")
        out("")
    else:
        out("_None produced for this audit._")
        out("")

    out("## FP-check audit-of-audits")
    out("")
    fp_data = agg.get("fp_check") or {}
    fp_summary = (fp_data.get("summary") or "").strip()
    if fp_summary or fp_check_path:
        if fp_summary:
            out(fp_summary)
            out("")
        if fp_check_path:
            out(f"_Full audit-of-audits report: [`{fp_check_path}`]({fp_check_path})_")
            out("")
        flagged_rows = [c for c in agg["confirmed"] if c.get("fp_flagged")]
        if flagged_rows:
            out("**Findings flagged for re-review:**")
            out("")
            for c in flagged_rows:
                ref = ""
                if c.get("refs"):
                    p, ln = c["refs"][0]
                    ref = f" (`{p}:{ln}`)"
                out(
                    f"- **{c.get('title', '')}**{ref} — "
                    f"`{c['family']}` / `{c['packet']}`"
                )
                # fp_note intentionally NOT rendered (see comment in the
                # main confirmed-issues loop). Use the link to the
                # full audit-of-audits.md for the actual verdict.
            out("")
        else:
            out("_fp-check did not flag any confirmed finding for re-review._")
            out("")
    else:
        out("_Not produced for this audit (run `sra audit` with "
            "fp-check enabled to populate this section)._")
        out("")

    out("## Limitations / architectural observations")
    out("")
    if not agg["limitations"]:
        out("_None recorded._")
    else:
        # Group near-duplicate limitations together. Skills sometimes
        # raise the same architectural observation in many packets
        # (e.g. "packet's cluster directory contains only audit
        # metadata" raised by 14 different input-validation packets
        # on salazar). Dedup by the first ~80 chars of the text so
        # each unique observation appears once with an "(also raised
        # by N other packets)" annotation.
        seen_keys: dict[str, dict] = {}
        for l in agg["limitations"]:
            text = l["text"]
            key = " ".join(text[:80].lower().split())
            existing = seen_keys.get(key)
            if existing is None:
                seen_keys[key] = {
                    "text":    text,
                    "family":  l["family"],
                    "packet":  l["packet"],
                    "extras":  [],
                }
            else:
                existing["extras"].append((l["family"], l["packet"]))
        for entry in seen_keys.values():
            text = entry["text"]
            if len(text) > 400:
                text = text[:397] + "..."
            out(f"- {text}")
            packet_line = f"  - Family: `{entry['family']}` · Packet: `{entry['packet']}`"
            if entry["extras"]:
                packet_line += (
                    f" (also raised by {len(entry['extras'])} other packet"
                    f"{'s' if len(entry['extras']) != 1 else ''})"
                )
            out(packet_line)
        out("")

    out("## Top files by audit touch count")
    out("")
    out("Files most often cited across confirmed issues, dismissed hits, "
        "and `Files read` sections. A high count means several skills "
        "pointed at this file — read it first.")
    out("")
    if not agg["top_files"]:
        out("_None._")
    else:
        out("| File | Touches |")
        out("|---|---:|")
        for path, n in agg["top_files"]:
            out(f"| `{path}` | {n} |")
        out("")

    out("## Next steps for a human auditor")
    out("")
    out("1. **Review confirmed issues** above. Severities are skill hints, "
        "not authoritative.")
    out("2. **Read the top files** in the touch-count table to build "
        "intuition before deeper review.")
    out("3. **Validate the limitations** — these are observations the "
        "skill could not fully decide. Each is a candidate question for "
        "the team that owns the code.")
    out("4. For each confirmed finding, open the linked file:line, read "
        "the surrounding function, and decide whether to escalate.")
    out("")

    return "\n".join(lines) + "\n"


def _relative_or_posix(target: Path, path: Path) -> str:
    """Best-effort repo-relative path string for report links.

    Falls back to the posix-style absolute path if the artefact lives
    outside ``target`` (shouldn't happen in practice — every artefact is
    under ``target/.audit/`` — but we don't want to crash if it does).
    """
    try:
        rel = path.resolve().relative_to(target)
        return _posix(rel)
    except ValueError:
        return _posix(path)


def cmd_build_report(repo_path_str: str) -> int:
    repo_path = Path(repo_path_str).expanduser()
    if not repo_path.exists():
        print(f"error: path does not exist: {repo_path}", file=sys.stderr)
        return 2
    if not repo_path.is_dir():
        print(f"error: not a directory: {repo_path}", file=sys.stderr)
        return 2

    target = repo_path.resolve()
    artefacts = _walk_findings_extended(target)
    findings_files = artefacts["findings"]
    if not findings_files:
        print(
            f"error: no findings files found under "
            f"{target}/.audit/04-packets-sensors/<family>/PACKET-*.findings.md",
            file=sys.stderr,
        )
        return 2

    parsed: list[dict] = []
    parse_errors: list[str] = []
    for family, packet_id, path in findings_files:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as e:
            parse_errors.append(f"{path}: {e}")
            continue
        try:
            doc = _parse_findings_md(content, family, packet_id)
        except Exception as e:  # noqa: BLE001
            parse_errors.append(f"{path}: parser error: {e}")
            continue
        parsed.append(doc)

    # Phase 7 artefacts. Each parser is tolerant; missing files just skip.
    parsed_variants: list[dict] = []
    for v_path in artefacts.get("variants") or []:
        # Silent skip for empty / whitespace-only files (claude -p
        # wrote no useful content). Don't surface as parse error —
        # the on-disk empty file is itself the signal that the run
        # produced nothing.
        try:
            if v_path.stat().st_size == 0:
                continue
        except OSError:
            pass
        try:
            v = _parse_variant_file(v_path)
        except Exception as e:  # noqa: BLE001
            parse_errors.append(f"{v_path}: variant parser error: {e}")
            continue
        if v is None:
            # Distinguish two cases that both return None: filename
            # mismatch (worth flagging as parse error so the user
            # knows their layout is wrong) vs. empty body (handled
            # silently above; if we got here it means the read failed
            # or the body parse rejected it). Re-check content cheaply.
            try:
                content = v_path.read_text(encoding="utf-8")
            except OSError:
                content = ""
            if not content.strip():
                continue  # silent skip
            parse_errors.append(
                f"{v_path}: filename does not match "
                f"<PACKET-NNN>-<finding-index>.md; skipped"
            )
            continue
        parsed_variants.append(v)

    fp_check_data: dict = {}
    fp_path: Path | None = artefacts.get("fp_check")
    if fp_path is not None:
        try:
            fp_check_data = _parse_fp_check(_read_text_safely(fp_path))
        except Exception as e:  # noqa: BLE001
            parse_errors.append(f"{fp_path}: fp-check parser error: {e}")

    context_preview = ""
    context_path_str = ""
    ctx_path: Path | None = artefacts.get("context_building")
    if ctx_path is not None:
        context_preview  = _extract_preview(_read_text_safely(ctx_path))
        context_path_str = _relative_or_posix(target, ctx_path)

    entry_points_preview = ""
    entry_points_path_str = ""
    ep_path: Path | None = artefacts.get("entry_points")
    if ep_path is not None:
        entry_points_preview  = _extract_preview(_read_text_safely(ep_path))
        entry_points_path_str = _relative_or_posix(target, ep_path)

    fp_check_path_str = ""
    if fp_path is not None:
        fp_check_path_str = _relative_or_posix(target, fp_path)

    agg = _aggregate_findings(
        parsed,
        variants=parsed_variants,
        fp_check_data=fp_check_data,
        repo_root=target,
    )
    coverage_map = _build_coverage_map(
        target,
        by_family=agg["by_family"],
        skipped_families=artefacts.get("skipped_families"),
    )
    repo_name = target.name
    md = _render_report_md(
        repo_name, agg,
        context_preview=context_preview,
        context_path=context_path_str,
        entry_points_preview=entry_points_preview,
        entry_points_path=entry_points_path_str,
        fp_check_path=fp_check_path_str,
        skipped_families=artefacts.get("skipped_families"),
        coverage_map=coverage_map,
    )

    out_dir = target / ".audit" / "05-report"
    out_dir.mkdir(parents=True, exist_ok=True)

    md_path   = out_dir / "repo-report.md"
    json_path = out_dir / "repo-report.json"

    md_path.write_text(md, encoding="utf-8")

    # Strip the in-memory variant content blobs from the JSON copy; the
    # paths are persisted instead so consumers can re-read on demand.
    variants_json = [
        {
            "packet":         v.get("packet", ""),
            "finding_index":  v.get("finding_index", 0),
            "path":           _relative_or_posix(target, v["path"]),
            "title":          v.get("title", ""),
            "summary":        v.get("summary", ""),
        }
        for v in parsed_variants
    ]
    fp_check_json = {
        "path":              fp_check_path_str or None,
        "summary":           fp_check_data.get("summary", "") if fp_check_data else "",
        # JSON emission of `flagged_refs` drops the file-level (path, 0)
        # entries that are only used internally by `_aggregate_findings`
        # to fold near-line matches onto file-level. Without this filter
        # the JSON had every entry duplicated as (path, real_line) +
        # (path, 0), inflating the noise for external tooling.
        "flagged_refs":      [
            {"path": p, "line": ln, "note": note}
            for (p, ln), note in
            (fp_check_data.get("flagged_refs") or {}).items()
            if ln != 0
        ] if fp_check_data else [],
        "flagged_packets":   [
            {"packet": pid, "note": note}
            for pid, note in
            (fp_check_data.get("flagged_packets") or {}).items()
        ] if fp_check_data else [],
    }

    json_doc = {
        "schema_version":   2,
        "repo_path":        _posix(target),
        "repo_name":        repo_name,
        "packet_total":     agg["packet_total"],
        "by_family":        agg["by_family"],
        "confirmed":        agg["confirmed"],
        "limitations":      agg["limitations"],
        "top_files":        agg["top_files"],
        "context_building": context_path_str or None,
        "entry_points":     entry_points_path_str or None,
        "coverage_map":     coverage_map,
        "variants":         variants_json,
        "fp_check":         fp_check_json,
        "parse_errors":     parse_errors,
        "notes": [
            f"Aggregated {agg['packet_total']} packet findings across "
            f"{len(agg['by_family'])} families.",
            f"Variants discovered: {agg.get('variant_count', 0)}.",
            f"Findings flagged by fp-check: {agg.get('fp_flagged_count', 0)}.",
            "Severity is a skill hint, not authoritative.",
            "No LLM was invoked at this stage; no new investigation.",
        ],
    }
    json_path.write_text(
        json.dumps(json_doc, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        f"sra: wrote report for {repo_name}: "
        f"{agg['packet_total']} packets, "
        f"{sum(f['confirmed'] for f in agg['by_family'].values())} confirmed, "
        f"{sum(f['limitations'] for f in agg['by_family'].values())} limitations, "
        f"{agg.get('variant_count', 0)} variants, "
        f"{agg.get('fp_flagged_count', 0)} fp-flagged -> "
        f"{md_path}",
        file=sys.stderr,
    )
    if parse_errors:
        print(
            f"warning: {len(parse_errors)} parse errors (see "
            f"repo-report.json `parse_errors`)",
            file=sys.stderr,
        )
    return 0
