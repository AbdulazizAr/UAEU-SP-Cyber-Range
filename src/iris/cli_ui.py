"""Small terminal-UI helpers for long-running CLI commands.

Gives the slow commands (fragment recording, dataset build) a watchable face: a live
spinner with the current phase and elapsed time, a text progress bar with percentage and
ETA, and tidy per-item result lines with running totals.

Design notes:
- Dependency-free: only ``click`` (already required) and the standard library.
- TTY-aware: animations and in-place redraws happen only when stdout is a terminal; piped
  or captured output falls back to plain one-line-per-event logging, so logs stay clean.
- Monotonic clock only (never wall-clock time), so this module respects the real-clock ban
  enforced by ``iris.devtools.boundaries``.
"""

from __future__ import annotations

import shutil
import sys
import threading
import time
from dataclasses import dataclass, field

import click

SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
CHECK = "✓"
CROSS = "✗"


def _isatty() -> bool:
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def _clip(text: str, visible_budget: int) -> str:
    """Trim by visible length; ANSI styling is applied after clipping so colour codes do
    not count against the terminal width."""
    return text if len(text) <= visible_budget else text[: max(0, visible_budget - 1)] + "…"


def fmt_dur(seconds: float) -> str:
    """Human duration: ``mm:ss`` under an hour, else ``h:mm:ss``."""
    secs = max(0, int(seconds))
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def bar(frac: float, width: int = 22) -> str:
    frac = min(1.0, max(0.0, frac))
    filled = round(frac * width)
    return "█" * filled + "░" * (width - filled)


@dataclass
class Progress:
    """Overall progress across a known number of items, timed on the monotonic clock."""

    total: int
    done: int = 0
    start: float = field(default_factory=time.monotonic)

    def tick(self, n: int = 1) -> None:
        self.done += n

    @property
    def frac(self) -> float:
        return self.done / self.total if self.total else 1.0

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start

    def eta(self) -> float | None:
        if self.done == 0:
            return None
        return (self.elapsed / self.done) * (self.total - self.done)

    def line(self, width: int = 22) -> str:
        eta = self.eta()
        tail = f"~{fmt_dur(eta)} left" if eta is not None else "estimating…"
        pct = int(self.frac * 100)
        return (
            f"{bar(self.frac, width)} {pct:3d}%  {self.done}/{self.total}  "
            f"{fmt_dur(self.elapsed)} elapsed · {tail}"
        )


class Spinner:
    """A one-line live status with an animated spinner and per-item elapsed time.

    On a TTY it redraws in place ~10x/s on a daemon thread; otherwise it prints each label
    once. ``set_label`` changes the phase text; the context manager clears the line on exit
    so the caller can print a permanent result line in its place.
    """

    def __init__(self, label: str = "", enabled: bool | None = None) -> None:
        self.label = label
        self.enabled = _isatty() if enabled is None else enabled
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._start = time.monotonic()
        self._lock = threading.Lock()

    def set_label(self, label: str) -> None:
        with self._lock:
            if label != self.label and not self.enabled:
                click.echo(f"  … {label}")
            self.label = label

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def _draw(self, frame: str) -> None:
        with self._lock:
            label = self.label
        el = fmt_dur(self.elapsed)
        budget = max(0, _width() - len(el) - 6)  # room for frame, spaces and elapsed
        text = f"{_clip(label, budget)}"
        line = f"\r{click.style(frame, fg='cyan')}  {text}  {click.style(el, dim=True)}"
        sys.stdout.write(line + "\033[K")  # clear to end of line
        sys.stdout.flush()

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set():
            self._draw(SPIN[i % len(SPIN)])
            i += 1
            time.sleep(0.1)

    def __enter__(self) -> Spinner:
        if self.enabled:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        else:
            click.echo(f"  … {self.label}")
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        if self.enabled:
            sys.stdout.write("\r\033[K")  # clear the spinner line
            sys.stdout.flush()


def header(title: str, subtitle: str = "") -> None:
    click.echo()
    click.secho(f"  {title}", fg="cyan", bold=True, nl=not subtitle)
    if subtitle:
        click.secho(f"  ·  {subtitle}", dim=True)
    click.secho("  " + "─" * min(60, _width() - 4), dim=True)


def result_line(ok: bool, head: str, detail: str, elapsed: float, progress: Progress | None = None) -> None:
    mark = click.style(CHECK, fg="green") if ok else click.style(CROSS, fg="red")
    tail = click.style(f"  {fmt_dur(elapsed)}", dim=True)
    click.echo(f"  {mark}  {head}  {detail}{tail}")
    if progress is not None:
        click.secho(f"     {progress.line()}", dim=True)


def footer(label: str, good: bool = True) -> None:
    click.secho("  " + "─" * min(60, _width() - 4), dim=True)
    click.secho(f"  {label}", fg="green" if good else "yellow", bold=True)
    click.echo()
