"""Structured reporter for the `sra audit` pipeline.

The legacy approach was a closure ``announce(msg)`` inside ``cmd_audit``
that printed ``[audit] <msg>`` to stderr. After the pipeline grew to ~10
phases with parallel skill invocations, heartbeats, fp-check, variant
analysis and synthesis, the output became unreadable:

  - 263 ``skip ... already has findings.md`` lines on a resumed run.
  - No global progress (X of N packets across all families).
  - No running tally of confirmed findings during the run.
  - Inconsistent prefixes (``[audit]``, ``[audit/family / PACKET]``,
    ``[fp-check]``, ``[audit-synthesis]``).
  - No final summary — pipeline ended with a bare ``done.``.

This module replaces ``announce`` with a :class:`Reporter` object that
exposes:

  - Generic line-emitters: ``info()``, ``warn()``, ``section()``.
  - Structured events: ``phase_start()``, ``phase_end()``,
    ``packet_start()``, ``packet_done()``, ``final_summary()``.
  - Worker-tracking for long-running subprocess invocations:
    ``worker_register()``, ``worker_unregister()`` (drive the live
    dashboard's in-flight section and the plain-mode heartbeats).

Two concrete implementations:

  - :class:`PlainReporter` — one newline-terminated line per event.
    Pipe-friendly, grep-friendly, works in CI and when redirecting to
    a file. Colors disabled when not a TTY.

  - :class:`LiveReporter` — appends persistent events above a fixed
    bottom dashboard (progress bar + in-flight workers + running
    totals), redrawn in place via ANSI escapes. Used when stderr is
    an interactive TTY.

Mode selection:

  - ``SRA_OUTPUT=plain`` — always plain.
  - ``SRA_OUTPUT=live`` — live if isatty, plain otherwise.
  - ``SRA_OUTPUT=auto`` (default) — same as ``live``.
  - ``NO_COLOR=1`` — disables ANSI colors in both modes.

No third-party deps (the package keeps ``dependencies = []`` in
pyproject). All terminal control is hand-rolled ANSI.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────
# ANSI escape codes. We only use the conservative subset that every
# modern terminal (Windows Terminal, PowerShell ≥ 7, cmd.exe with VT
# enabled, all *nix terminals) supports.
# ─────────────────────────────────────────────────────────────────────

class _Ansi:
    RESET   = "\x1b[0m"
    BOLD    = "\x1b[1m"
    DIM     = "\x1b[2m"

    RED     = "\x1b[31m"
    GREEN   = "\x1b[32m"
    YELLOW  = "\x1b[33m"
    BLUE    = "\x1b[34m"
    MAGENTA = "\x1b[35m"
    CYAN    = "\x1b[36m"
    GRAY    = "\x1b[90m"

    CLEAR_LINE  = "\x1b[2K"
    CLEAR_BELOW = "\x1b[J"
    HIDE_CURSOR = "\x1b[?25l"
    SHOW_CURSOR = "\x1b[?25h"

    @staticmethod
    def up(n: int) -> str:
        return f"\x1b[{n}A" if n > 0 else ""


# Strip ANSI codes for length calculation.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _visible_len(s: str) -> int:
    return len(_ANSI_RE.sub("", s))


def _fmt_duration(secs: float) -> str:
    """Compact duration: ``45s``, ``2m17s``, ``1h12m``."""
    if secs < 0:
        secs = 0
    s = int(secs)
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def _fmt_count(n: int) -> str:
    """Compact count with thin-space thousands for readability."""
    if n < 1000:
        return str(n)
    return f"{n:,}".replace(",", " ")


def _enable_windows_vt() -> None:
    """Best-effort: enable ANSI processing on legacy Windows consoles.

    Windows 10 build 14393+ (Anniversary Update, 2016) supports VT
    escape sequences but the mode must be opt-in via
    ``ENABLE_VIRTUAL_TERMINAL_PROCESSING``. Windows Terminal and
    PowerShell 7 set it automatically; legacy cmd.exe and PowerShell
    5.1 do not. A no-op on non-Windows.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # GetStdHandle(-12) = STDERR; -11 = STDOUT.
        for h in (-11, -12):
            handle = kernel32.GetStdHandle(h)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                continue
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:  # noqa: BLE001 — best effort
        pass


def _ensure_utf8_stderr() -> bool:
    """Reconfigure ``sys.stderr`` to UTF-8 with replace-on-error.

    Without this, Python on a console whose codepage is cp1252 (the
    default in Git Bash / older PowerShell on Windows) renders the
    box-drawing glyphs we emit (``─``, ``━``, ``█``) as literal
    ``\\u2500`` escape sequences. UTF-8 + ``errors='replace'`` means
    glyphs render normally on any UTF-8 terminal and degrade to ``?``
    on the rare codec that can't encode them.

    Returns True if the stream now accepts UTF-8, False if we had to
    bail (very old Python on a non-reconfigurable stream).
    """
    err = sys.stderr
    if getattr(err, "encoding", "").lower().replace("-", "") == "utf8":
        return True
    try:
        # Python 3.7+: TextIOWrapper.reconfigure
        err.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        return True
    except (AttributeError, OSError):
        return False


# Glyphs we use across the reporter. Some terminals / encodings can't
# render the fancy box-drawing or check-marks; the ``_AsciiGlyphs``
# fallback drops to plain ASCII so the output stays readable.
class _Glyphs:
    DIVIDER_THIN  = "─"
    DIVIDER_THICK = "━"
    BANNER        = "═"
    OK            = "✓"
    FAIL          = "✗"
    START         = "▶"
    BAR_FULL      = "█"
    BAR_EMPTY     = "░"
    SEP           = "·"
    ELLIPSIS      = "…"


class _AsciiGlyphs:
    DIVIDER_THIN  = "-"
    DIVIDER_THICK = "="
    BANNER        = "="
    OK            = "+"
    FAIL          = "x"
    START         = ">"
    BAR_FULL      = "#"
    BAR_EMPTY     = "."
    SEP           = "-"
    ELLIPSIS      = "..."


# ─────────────────────────────────────────────────────────────────────
# State containers
# ─────────────────────────────────────────────────────────────────────

@dataclass
class _Worker:
    """A long-running subprocess invocation tracked by the reporter."""
    label: str
    start: float
    extra: str = ""


@dataclass
class _PhaseState:
    """Per-phase accounting. The reporter holds at most one active
    phase at a time; nested phases just overwrite (the design is
    flat-by-construction in cmd_audit)."""
    code: str                 # e.g. "04"
    title: str                # e.g. "skill audit"
    started: float
    ended: float = 0.0        # set by phase_end; 0 while active
    total: int = 0            # items to process this phase
    cached: int = 0           # items skipped because output already exists
    done: int = 0             # items completed OK this run
    failed: int = 0           # items that failed this run
    findings_added: int = 0   # confirmed findings produced this phase
    extras: dict[str, int] = field(default_factory=dict)

    @property
    def elapsed(self) -> float:
        return (self.ended or time.time()) - self.started


# ─────────────────────────────────────────────────────────────────────
# Reporter base — plain line-based
# ─────────────────────────────────────────────────────────────────────

class Reporter:
    """Line-based reporter. One newline-terminated event per call.

    Thread-safe: an internal lock serialises emission, so workers
    calling :meth:`packet_done` from multiple threads can't interleave
    half-written lines.
    """

    DIVIDER_WIDTH = 64

    def __init__(self, *, use_color: bool, ascii_only: bool = False):
        self.use_color = use_color
        self._g: type = _AsciiGlyphs if ascii_only else _Glyphs
        self._lock = threading.RLock()
        self._phase: Optional[_PhaseState] = None
        self._global_start = time.time()
        self._total_findings = 0
        self._total_fp_flagged = 0
        self._workers: dict[str, _Worker] = {}
        # Per-phase elapsed totals are accumulated for the final banner.
        self._phase_history: list[_PhaseState] = []

    # ---------------------------------------------------------------
    # Color helpers
    # ---------------------------------------------------------------

    def _c(self, code: str, text: str) -> str:
        if not self.use_color or not text:
            return text
        return f"{code}{text}{_Ansi.RESET}"

    def _bold(self, text: str) -> str:
        return self._c(_Ansi.BOLD, text)

    def _dim(self, text: str) -> str:
        return self._c(_Ansi.DIM, text)

    def _ok(self, text: str) -> str:
        return self._c(_Ansi.GREEN, text)

    def _fail(self, text: str) -> str:
        return self._c(_Ansi.RED, text)

    def _warn(self, text: str) -> str:
        return self._c(_Ansi.YELLOW, text)

    def _accent(self, text: str) -> str:
        return self._c(_Ansi.CYAN, text)

    # ---------------------------------------------------------------
    # Low-level emit (override in LiveReporter to manage footer)
    # ---------------------------------------------------------------

    def _emit(self, line: str) -> None:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()

    # ---------------------------------------------------------------
    # Public API — generic
    # ---------------------------------------------------------------

    def info(self, msg: str) -> None:
        """Plain informational line. Drop-in for legacy ``announce``."""
        with self._lock:
            self._emit(f"  {msg}")

    def note(self, msg: str) -> None:
        """Dim informational line — for secondary detail."""
        with self._lock:
            self._emit("  " + self._dim(msg))

    def warn(self, msg: str) -> None:
        with self._lock:
            self._emit(f"  {self._warn('warning:')} {msg}")

    def error(self, msg: str) -> None:
        with self._lock:
            self._emit(f"  {self._fail('error:')} {msg}")

    def section(self, title: str) -> None:
        """Major divider — printed between unrelated phases. Use
        :meth:`phase_start` for accounting; this is only for the
        visual break (e.g. before the report-build step)."""
        with self._lock:
            self._emit("")
            d = self._g.DIVIDER_THIN
            bar = d * max(0, self.DIVIDER_WIDTH - _visible_len(title) - 4)
            self._emit(self._accent(f"{d}{d} {title} {bar}"))

    # ---------------------------------------------------------------
    # Public API — phase lifecycle
    # ---------------------------------------------------------------

    def phase_start(
        self,
        code: str,
        title: str,
        *,
        total: int = 0,
        cached: int = 0,
        parallel: int = 1,
        extras: Optional[dict[str, int]] = None,
        note: str = "",
    ) -> None:
        """Open a new phase. ``code`` is the canonical stage tag
        (``04``, ``06a`` …), ``title`` is the human description.
        ``total``/``cached`` describe the work split. ``parallel`` is
        the worker count when relevant. ``note`` is a free-form trailing
        annotation (e.g. ``[model: opus]``)."""
        with self._lock:
            phase = _PhaseState(
                code=code, title=title, started=time.time(),
                total=total, cached=cached,
                extras=dict(extras or {}),
            )
            self._phase = phase
            self._emit("")
            d   = self._g.DIVIDER_THIN
            sep = self._g.SEP
            header = f"phase {code} {sep} {title}"
            bar = d * max(0, self.DIVIDER_WIDTH - _visible_len(header) - 4)
            self._emit(self._accent(self._bold(f"{d}{d} {header} {bar}")))
            parts: list[str] = []
            if total or cached:
                parts.append(f"{_fmt_count(total + cached)} total")
                if cached:
                    parts.append(self._dim(f"{_fmt_count(cached)} cached"))
                parts.append(f"{_fmt_count(total)} to run")
            if parallel and parallel > 1:
                parts.append(self._dim(f"parallel={parallel}"))
            if note:
                parts.append(self._dim(note))
            for k, v in (extras or {}).items():
                parts.append(self._dim(f"{k}={_fmt_count(v)}"))
            if parts:
                self._emit("  " + f" {sep} ".join(parts))

    def phase_end(self, *, note: str = "") -> None:
        """Close the current phase and emit a summary line. Safe to
        call when no phase is open (no-op)."""
        with self._lock:
            phase = self._phase
            if phase is None:
                return
            phase.ended = time.time()
            phase_elapsed = phase.elapsed
            self._phase = None
            self._phase_history.append(phase)
            sep = self._g.SEP
            parts: list[str] = []
            if phase.done:
                parts.append(self._ok(f"{_fmt_count(phase.done)} ran"))
            else:
                parts.append(self._dim("0 ran"))
            if phase.failed:
                parts.append(self._fail(f"{_fmt_count(phase.failed)} failed"))
            else:
                parts.append(self._dim("0 failed"))
            if phase.cached:
                parts.append(self._dim(f"{_fmt_count(phase.cached)} cached"))
            parts.append(_fmt_duration(phase_elapsed))
            if phase.findings_added:
                parts.append(
                    self._ok(f"{_fmt_count(phase.findings_added)} new findings")
                )
            if note:
                parts.append(self._dim(note))
            self._emit("  " + self._dim("summary: ") + f" {sep} ".join(parts))

    def phase_progress(self, *, done_delta: int = 0, cached_delta: int = 0,
                       failed_delta: int = 0, findings_delta: int = 0) -> None:
        """Incrementally update phase counters without emitting a line.
        Used by helpers that aggregate sub-steps."""
        with self._lock:
            phase = self._phase
            if phase is None:
                return
            phase.done += done_delta
            phase.cached += cached_delta
            phase.failed += failed_delta
            phase.findings_added += findings_delta
            self._total_findings += findings_delta

    # ---------------------------------------------------------------
    # Public API — packet lifecycle
    # ---------------------------------------------------------------

    def packet_start(self, label: str, *, extra: str = "") -> None:
        """A unit of work begins. ``label`` is the human identifier
        (e.g. ``crypto-auth/PACKET-058``). ``extra`` is a trailing
        annotation (composed sub-skills, model override, etc.).

        Plain mode emits an immediate ``▶`` line so the user sees
        what's being attempted; live mode just registers the worker
        and the dashboard footer renders it."""
        with self._lock:
            self._workers[label] = _Worker(
                label=label, start=time.time(), extra=extra,
            )
            self._on_worker_start(label, extra)

    def packet_done(
        self,
        label: str,
        *,
        ok: bool,
        findings: int = 0,
        error: str = "",
        index: Optional[tuple[int, int]] = None,
    ) -> None:
        """A unit of work completed. ``findings`` is the count of
        confirmed findings produced by this packet (parsed by the
        caller via :func:`sra.report._parse_findings_md`).

        ``index = (i, n)`` produces a ``[i/n]`` prefix; pass ``None``
        for non-counted work (e.g. one-shot skill invocations)."""
        with self._lock:
            w = self._workers.pop(label, None)
            elapsed = (time.time() - w.start) if w else 0
            if self._phase:
                if ok:
                    self._phase.done += 1
                    self._phase.findings_added += findings
                else:
                    self._phase.failed += 1
            if ok:
                self._total_findings += findings
            self._on_worker_done(
                label, ok=ok, findings=findings, elapsed=elapsed,
                error=error, index=index,
            )

    # ---------------------------------------------------------------
    # Worker tracking (heartbeats / dashboard in-flight section)
    # ---------------------------------------------------------------

    def worker_register(self, label: str, *, extra: str = "") -> None:
        """Track a long-running subprocess. Distinct from
        :meth:`packet_start` because some invocations (fp-check,
        synthesis) aren't per-packet but still need a heartbeat."""
        with self._lock:
            self._workers[label] = _Worker(
                label=label, start=time.time(), extra=extra,
            )

    def worker_unregister(self, label: str) -> float:
        """Stop tracking. Returns elapsed seconds."""
        with self._lock:
            w = self._workers.pop(label, None)
            return (time.time() - w.start) if w else 0.0

    def worker_heartbeat(self, label: str, elapsed: int) -> None:
        """Plain-mode heartbeat tick. Override in subclasses; the live
        reporter's footer thread updates timers on its own, so live
        mode ignores this."""
        with self._lock:
            self._emit(self._dim(f"  {label} · still running ({elapsed}s)"))

    # ---------------------------------------------------------------
    # Hooks that LiveReporter overrides
    # ---------------------------------------------------------------

    def _on_worker_start(self, label: str, extra: str) -> None:
        sep = self._g.SEP
        tail = self._dim(f" {sep} {extra}") if extra else ""
        self._emit(f"  {self._accent(self._g.START)} {label}{tail}")

    def _on_worker_done(
        self, label: str, *, ok: bool, findings: int, elapsed: float,
        error: str, index: Optional[tuple[int, int]],
    ) -> None:
        sep = self._g.SEP
        idx_str = ""
        if index is not None:
            i, n = index
            width = len(str(n))
            idx_str = self._dim(f"[{i:>{width}}/{n}] ")
        if ok:
            mark = self._ok(self._g.OK)
            tail = _fmt_duration(elapsed)
            if findings:
                tail += f" {sep} " + self._ok(
                    f"{findings} finding{'s' if findings != 1 else ''}"
                )
            running_total = self._dim(f"  [total: {self._total_findings}]")
            self._emit(f"  {idx_str}{mark} {label} {sep} {tail}{running_total}")
        else:
            mark = self._fail(self._g.FAIL)
            err = error or "failed"
            self._emit(f"  {idx_str}{mark} {label} {sep} {self._fail(err)}")

    # ---------------------------------------------------------------
    # Final banner
    # ---------------------------------------------------------------

    def final_summary(
        self, *, report_path: str = "", fp_flagged: Optional[int] = None,
        interrupted: bool = False,
        repo_total_findings: Optional[int] = None,
        repo_total_variants: Optional[int] = None,
        repo_total_packets: Optional[int] = None,
    ) -> None:
        """Banner emitted once at the end of ``cmd_audit``. Includes
        total wall time, per-phase breakdown, findings count, and the
        report path.

        Counts can come from two places:

        - Internal trackers (``self._total_findings``,
          ``self._total_fp_flagged``) — these accumulate work done in
          THIS invocation only, so they're 0 on a fully-cached resume.
        - Explicit ``repo_total_*`` kwargs — pass the totals from the
          finalised ``repo-report.json`` so a resumed run still shows
          accurate whole-repo numbers, not just the delta.

        When both are present, the kwargs win for the headline numbers
        but ``self._total_findings`` is still surfaced as
        ``new this run`` if it's a strict subset.
        """
        with self._lock:
            elapsed = time.time() - self._global_start
            flagged = fp_flagged if fp_flagged is not None else self._total_fp_flagged
            self._emit("")
            self._emit(self._accent(self._bold(
                self._g.BANNER * self.DIVIDER_WIDTH
            )))
            if interrupted:
                head = self._warn(f"audit interrupted after {_fmt_duration(elapsed)}")
            else:
                head = self._ok(self._bold(
                    f"audit complete in {_fmt_duration(elapsed)}"
                ))
            self._emit("  " + head)
            self._emit("")
            # Per-phase breakdown
            if self._phase_history:
                for ph in self._phase_history:
                    line = self._fmt_phase_row(ph)
                    if line:
                        self._emit("  " + line)
                self._emit("")
            # Totals — prefer repo-wide if provided, fall back to in-run.
            shown_findings = (
                repo_total_findings if repo_total_findings is not None
                else self._total_findings
            )
            tail = ""
            if (repo_total_findings is not None
                    and self._total_findings
                    and self._total_findings != repo_total_findings):
                tail = self._dim(
                    f"  ({_fmt_count(self._total_findings)} new this run)"
                )
            self._emit(
                "  " + self._bold("total findings: ")
                + self._ok(_fmt_count(shown_findings))
                + tail
            )
            if repo_total_variants:
                self._emit(
                    "  " + self._bold("total variants: ")
                    + _fmt_count(repo_total_variants)
                )
            if flagged:
                self._emit(
                    "  " + self._bold("fp-check flagged: ")
                    + self._warn(_fmt_count(flagged))
                )
            if repo_total_packets:
                self._emit(
                    "  " + self._dim(
                        f"{_fmt_count(repo_total_packets)} packet(s) processed"
                    )
                )
            if report_path:
                self._emit("  " + self._bold("report: ") + report_path)
            self._emit(self._accent(self._bold(
                self._g.BANNER * self.DIVIDER_WIDTH
            )))

    def _fmt_phase_row(self, ph: _PhaseState) -> str:
        """One row per phase in the final banner."""
        sep = self._g.SEP
        label = f"phase {ph.code} {sep} {ph.title}"
        # Pad label to a stable column so the metric tails line up.
        label_w = 32
        label_padded = label + " " * max(0, label_w - _visible_len(label))
        parts: list[str] = []
        if ph.done:
            parts.append(f"{_fmt_count(ph.done)} ran")
        if ph.cached:
            parts.append(self._dim(f"{_fmt_count(ph.cached)} cached"))
        if ph.failed:
            parts.append(self._fail(f"{_fmt_count(ph.failed)} failed"))
        parts.append(self._dim(_fmt_duration(ph.elapsed)))
        if ph.findings_added:
            parts.append(self._ok(
                f"{_fmt_count(ph.findings_added)} finding"
                + ("s" if ph.findings_added != 1 else "")
            ))
        if not parts:
            parts.append(self._dim("(no work)"))
        return label_padded + f" {sep} ".join(parts)

    # ---------------------------------------------------------------
    # State queries (for tests / external introspection)
    # ---------------------------------------------------------------

    @property
    def total_findings(self) -> int:
        with self._lock:
            return self._total_findings

    def add_fp_flagged(self, n: int) -> None:
        with self._lock:
            self._total_fp_flagged += n

    # ---------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------

    def shutdown(self) -> None:
        """Release any background resources. Plain reporter has none."""


# ─────────────────────────────────────────────────────────────────────
# Live reporter — appends persistent events above a redrawn footer
# ─────────────────────────────────────────────────────────────────────

class LiveReporter(Reporter):
    """Interactive TTY reporter.

    Maintains a fixed footer at the bottom of the screen showing:
      - current phase + progress bar + elapsed + ETA
      - running findings tally
      - in-flight workers with per-worker elapsed time

    Persistent events (``packet_done``, ``phase_end``, etc.) print as
    normal log lines but the footer is redrawn after every print so it
    stays anchored at the bottom. A background thread redraws the
    footer every 500 ms so worker timers tick even when no event
    arrives.

    Implementation notes:
      - We track ``_footer_lines`` = number of lines the last drawn
        footer occupied, so before printing a new event we can move
        the cursor up that many lines and clear from there.
      - Footer width is capped to terminal width minus 1 to prevent
        line wrap (which would break the line-count assumption).
      - We hide the cursor while running and restore on
        :meth:`shutdown` to avoid the cursor flicker during redraws.
    """

    FOOTER_REDRAW_INTERVAL = 0.5  # seconds
    MAX_INFLIGHT_LINES     = 6
    DEFAULT_WIDTH          = 80

    def __init__(self, *, use_color: bool, ascii_only: bool = False):
        super().__init__(use_color=use_color, ascii_only=ascii_only)
        self._footer_lines = 0
        self._render_lock = threading.RLock()
        self._stop = threading.Event()
        # Hide the cursor for the duration of the run.
        if self.use_color:
            sys.stderr.write(_Ansi.HIDE_CURSOR)
            sys.stderr.flush()
        self._renderer = threading.Thread(
            target=self._render_loop, daemon=True, name="sra-live-render",
        )
        self._renderer.start()

    # ---------------------------------------------------------------
    # Width detection
    # ---------------------------------------------------------------

    def _term_width(self) -> int:
        try:
            w = shutil.get_terminal_size((self.DEFAULT_WIDTH, 24)).columns
        except OSError:
            w = self.DEFAULT_WIDTH
        return max(40, w - 1)

    # ---------------------------------------------------------------
    # Footer composition
    # ---------------------------------------------------------------

    def _compose_footer(self) -> list[str]:
        phase = self._phase
        if phase is None and not self._workers:
            return []
        w = self._term_width()
        out: list[str] = []
        sep = self._g.SEP
        out.append(self._accent(self._g.DIVIDER_THICK * w))

        if phase is not None:
            total = phase.total
            done  = phase.done + phase.failed
            pct = (done / total * 100) if total else 0
            bar_width = max(10, w - 50)
            filled = int((done / total) * bar_width) if total else 0
            prog = self._g.BAR_FULL * filled + self._g.BAR_EMPTY * (bar_width - filled)
            elapsed = time.time() - phase.started
            eta_str = ""
            if total and done > 0 and done < total:
                rate = done / elapsed if elapsed > 0 else 0
                if rate > 0:
                    eta = (total - done) / rate
                    eta_str = f" {sep} eta ~{_fmt_duration(eta)}"
            head = (
                f" phase {phase.code} {sep} " + self._accent(prog)
                + f" {done}/{total} ({pct:>3.0f}%) {sep} {_fmt_duration(elapsed)}"
                + self._dim(eta_str)
            )
            out.append(self._truncate(head, w))
            findings_line = (
                f" findings: {self._ok(_fmt_count(self._total_findings))} confirmed"
            )
            if phase.failed:
                findings_line += (
                    f" {sep} {self._fail(_fmt_count(phase.failed) + ' failed')}"
                )
            if phase.cached:
                findings_line += self._dim(
                    f" {sep} {_fmt_count(phase.cached)} cached"
                )
            out.append(self._truncate(findings_line, w))

        if self._workers:
            out.append(self._dim(" in-flight:"))
            items = sorted(
                self._workers.values(), key=lambda x: x.start,
            )[: self.MAX_INFLIGHT_LINES]
            for wkr in items:
                age = time.time() - wkr.start
                extra = self._dim(f" {sep} {wkr.extra}") if wkr.extra else ""
                row = f"   {wkr.label} {sep} {_fmt_duration(age)}{extra}"
                out.append(self._truncate(row, w))
            hidden = len(self._workers) - len(items)
            if hidden > 0:
                out.append(self._dim(f"   {self._g.ELLIPSIS} +{hidden} more"))
        out.append(self._accent(self._g.DIVIDER_THICK * w))
        return out

    def _truncate(self, line: str, width: int) -> str:
        """Truncate a line (counting visible chars, not ANSI escapes)
        so it doesn't wrap and break our line-count bookkeeping."""
        if _visible_len(line) <= width:
            return line
        # Best-effort plain-text truncate. We don't try to preserve
        # ANSI state across the cut; just strip codes if we have to.
        plain = _ANSI_RE.sub("", line)
        return plain[: width - 1] + self._g.ELLIPSIS

    # ---------------------------------------------------------------
    # Footer redraw machinery
    # ---------------------------------------------------------------

    def _erase_footer(self) -> None:
        if self._footer_lines > 0:
            sys.stderr.write("\r" + _Ansi.up(self._footer_lines) + _Ansi.CLEAR_BELOW)
            sys.stderr.flush()
            self._footer_lines = 0

    def _draw_footer(self) -> None:
        lines = self._compose_footer()
        if not lines:
            return
        for ln in lines:
            sys.stderr.write(ln + "\n")
        sys.stderr.flush()
        self._footer_lines = len(lines)

    # Override _emit: erase footer, write event, redraw footer.
    def _emit(self, line: str) -> None:
        with self._render_lock:
            self._erase_footer()
            sys.stderr.write(line + "\n")
            sys.stderr.flush()
            self._draw_footer()

    def _render_loop(self) -> None:
        while not self._stop.wait(self.FOOTER_REDRAW_INTERVAL):
            with self._render_lock:
                if self._phase is not None or self._workers:
                    self._erase_footer()
                    self._draw_footer()

    # In live mode the dashboard already shows worker progress, so
    # silence per-worker heartbeat lines (they would scroll the
    # log endlessly).
    def worker_heartbeat(self, label: str, elapsed: int) -> None:
        pass

    # Also suppress the per-worker ``▶`` start line — the dashboard
    # in-flight section already shows it, and on a 4-way parallel run
    # we'd otherwise get 4× start spam right before the dashboard
    # renders.
    def _on_worker_start(self, label: str, extra: str) -> None:
        pass  # rendered by footer

    def shutdown(self) -> None:
        self._stop.set()
        try:
            self._renderer.join(timeout=1.5)
        except RuntimeError:
            pass
        with self._render_lock:
            self._erase_footer()
            if self.use_color:
                sys.stderr.write(_Ansi.SHOW_CURSOR)
                sys.stderr.flush()


# ─────────────────────────────────────────────────────────────────────
# Factory + singleton
# ─────────────────────────────────────────────────────────────────────

_REPORTER: Optional[Reporter] = None
_REPORTER_LOCK = threading.Lock()


def _decide_mode() -> tuple[str, bool]:
    """Return (mode, use_color). mode ∈ {'plain', 'live'}."""
    requested = os.environ.get("SRA_OUTPUT", "auto").strip().lower()
    is_tty = sys.stderr.isatty()
    no_color = bool(os.environ.get("NO_COLOR"))
    use_color = is_tty and not no_color

    if requested == "plain":
        return "plain", use_color
    if requested == "live":
        return ("live", use_color) if is_tty else ("plain", use_color)
    # auto
    return ("live", use_color) if is_tty else ("plain", use_color)


def _stream_supports_unicode() -> bool:
    """Decide whether the stderr stream can render the fancy glyphs we
    want to use. After :func:`_ensure_utf8_stderr` UTF-8 is the norm,
    but a user may force ASCII via ``SRA_OUTPUT_ASCII=1`` (useful when
    piping into a tool that strips non-ASCII)."""
    if os.environ.get("SRA_OUTPUT_ASCII"):
        return False
    enc = (getattr(sys.stderr, "encoding", "") or "").lower().replace("-", "")
    return enc in {"utf8", "utf16", "utf32"}


def get_reporter() -> Reporter:
    """Return the process-wide reporter. Thread-safe lazy init."""
    global _REPORTER
    if _REPORTER is not None:
        return _REPORTER
    with _REPORTER_LOCK:
        if _REPORTER is not None:
            return _REPORTER
        _enable_windows_vt()
        _ensure_utf8_stderr()
        mode, use_color = _decide_mode()
        ascii_only = not _stream_supports_unicode()
        if mode == "live":
            _REPORTER = LiveReporter(use_color=use_color, ascii_only=ascii_only)
        else:
            _REPORTER = Reporter(use_color=use_color, ascii_only=ascii_only)
        return _REPORTER


def reset_reporter_for_tests() -> None:
    """Drop the cached reporter. Tests only — not for production use."""
    global _REPORTER
    with _REPORTER_LOCK:
        if _REPORTER is not None:
            try:
                _REPORTER.shutdown()
            except Exception:  # noqa: BLE001
                pass
        _REPORTER = None
