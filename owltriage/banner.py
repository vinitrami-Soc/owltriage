"""The OwlTriage owl: the logo, and the animation that plays while a hunt runs.

The owl sits on its branch next to the name and looks around, hops down onto the loading bar
when the hunt starts, walks along with the real progress (stopping to look around when work
stalls), and flies back to its branch when the hunt is done. About 1.5 s of extra time in
total, and only on an interactive terminal: never for pipes, cron, CI, --quiet, --svg or
--no-anim, where nothing is animated at all.

Frames are pure functions of (time, progress). Rich's Live refresh thread draws them, so the
analysis is never slowed down; tests drive them with a fake clock.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.text import Text

from . import __version__

# Big letters (ANSI Shadow figlet font), baked in so there is no extra dependency.
OWL_WORD = [" ██████╗ ██╗    ██╗██╗", "██╔═══██╗██║    ██║██║", "██║   ██║██║ █╗ ██║██║",
            "██║   ██║██║███╗██║██║", "╚██████╔╝╚███╔███╔╝███████╗", " ╚═════╝  ╚══╝╚══╝ ╚══════╝"]
TRIAGE_WORD = ["████████╗██████╗ ██╗ █████╗  ██████╗ ███████╗", "╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝",
               "   ██║   ██████╔╝██║███████║██║  ███╗█████╗", "   ██║   ██╔══██╗██║██╔══██║██║   ██║██╔══╝",
               "   ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗", "   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝"]
TAGLINE = "Sees in the dark. Triages before you wake up."
COMPACT_OWL = "(◉▼◉)"

PALETTE = {"b": "bold #3b82f6", "y": "bold #fbbf24", "p": "bold #0b1220 on #fbbf24", "e": "on #fbbf24",
           "o": "bold #f97316", "l": "#93c5fd", "w": "#8b5a2b", "k": "bold #1e3a8a"}
EYES = {
    "center": ("██ ● ██ ██ ● ██", "yyepeyy.yyepeyy"),
    "left": ("██●  ██ ██●  ██", "yypeeyy.yypeeyy"),
    "right": ("██  ●██ ██  ●██", "yyeepyy.yyeepyy"),
    "blink": ("█▄▄▄▄▄█ █▄▄▄▄▄█", "ykkkkky.ykkkkky"),
}
OWL_WIDTH, OWL_HEIGHT, HEAD_ROWS = 21, 10, 6  # sprite without its branch; rows 0-5 turn on the neck


def owl_rows(look: str = "center") -> List[Tuple[str, str]]:
    """The owl as (characters, colour codes) rows; the last row is its branch."""
    eyes, codes = EYES[look]
    return [
        ("  ▄▄             ▄▄  ", "  bb             bb  "),
        ("  ███▄▄▄▄▄▄▄▄▄▄▄███  ", "  bbbbbbbbbbbbbbbbb  "),
        (" ▐█▀▀▀▀▀▀█▀█▀▀▀▀▀▀█▌ ", " bbbbbbbbbbbbbbbbbbb "),
        (" ▐▌▄█████▄ ▄█████▄▐▌ ", " bbyyyyyyy.yyyyyyybb "),
        (f" ▐▌{eyes}▐▌ ", f" bb{codes}bb "),
        (" ▐▌▀█████▀▼▀█████▀▐▌ ", " bbyyyyyyyoyyyyyyybb "),
        ("  █▄  ˅ ˅ ˅ ˅ ˅  ▄█  ", "  bb..l.l.l.l.l..bb  "),
        ("   █▄  ˅ ˅ ˅ ˅  ▄█   ", "   bb..l.l.l.l..bb   "),
        ("    ▀█▄ ˅ ˅ ˅ ▄█▀    ", "    bbb.l.l.l.bbb    "),
        ("      ▀▀█▀▀▀█▀▀      ", "      bbobbbobb      "),
        ("━━━━━━━━┻━━━┻━━━━━━━━", "wwwwwwwwwwwwwwwwwwwww"),
    ]


def _blend(c1: str, c2: str, t: float) -> str:
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b))


def _word_cells(lines: List[str], c1: str, c2: str) -> List[List[Tuple[str, str]]]:
    width = max(len(line) for line in lines)
    return [[(ch, f"bold {_blend(c1, c2, i / (width - 1))}" if ch == "█" else "#334155")
             for i, ch in enumerate(line)] for line in lines]


OWL_CELLS = _word_cells(OWL_WORD, "#fbbf24", "#f59e0b")
TRIAGE_CELLS = _word_cells(TRIAGE_WORD, "#60a5fa", "#2563eb")


def _cells_text(rows: List[List[Tuple[str, str]]]) -> Text:
    out = Text()
    for i, row in enumerate(rows):
        for ch, style in row:
            out.append(ch, style=style)
        if i < len(rows) - 1:
            out.append("\n")
    return out


def _owl_text(look: str = "center") -> Text:
    return _cells_text([[(ch, PALETTE.get(code, "")) for ch, code in zip(chars, codes.ljust(len(chars), "."))]
                        for chars, codes in owl_rows(look)])


def meta_line(rules: Optional[int] = None) -> Text:
    parts = [f"v{__version__}", "Linux · web · Windows logs"]
    if rules:
        parts.append(f"{rules} rules")
    parts.append("MITRE ATT&CK-mapped")
    return Text("  " + "  ·  ".join(parts), style="#94a3b8")


def logo(rules: Optional[int] = None, look: str = "center") -> Group:
    """The full static logo: owl on its branch, OWL / TRIAGE, tagline."""
    grid = Table.grid(padding=(0, 3))
    grid.add_column(vertical="middle")
    grid.add_column(vertical="middle")
    grid.add_row(_owl_text(look), _cells_text(OWL_CELLS + TRIAGE_CELLS))
    return Group(grid, Text("  " + TAGLINE, style="bold #fbbf24"), meta_line(rules))


def compact_logo(rules: Optional[int] = None) -> Text:
    line = Text("  ")
    line.append(COMPACT_OWL, style="bold #fbbf24")
    line.append(" OwlTriage ", style="bold #60a5fa")
    line.append_text(meta_line(rules)[2:] if rules else Text(f"v{__version__}", style="#64748b"))
    return line


def print_logo(console: Console, rules: Optional[int] = None) -> None:
    console.print(logo(rules) if console.width >= 76 else compact_logo(rules))
    console.print()


# ------------------------------------------------------------------ animation
INTRO, HOP, FLY, HOLD = 0.45, 0.45, 0.45, 0.15   # ≈ 1.5 s of extra time per interactive hunt
STEP_SECONDS = 0.02                                # catch-up walking speed (columns per second = 50)
LOOK_AROUND = [(0.35, "center", 0), (0.75, "left", -1), (0.95, "center", 0), (1.35, "right", 1),
               (1.5, "blink", 0), (1.9, "center", 0)]


def look_around(seconds: float) -> Tuple[str, int]:
    phase = seconds % LOOK_AROUND[-1][0]
    return next((eyes, head) for end, eyes, head in LOOK_AROUND if phase < end)


def animation_mode(console: Console, wanted: bool = True) -> str:
    """'full' (the owl story), 'compact' (a small walking owl) or 'off'."""
    if not wanted or not console.is_terminal or console.is_dumb_terminal:
        return "off"
    if os.environ.get("CI") or os.environ.get("OWLTRIAGE_NO_ANIM"):
        return "off"
    width, height = console.size
    if width >= 100 and height >= 30:
        return "full"
    return "compact" if width >= 60 else "off"


@dataclass
class HuntProgress:
    file: str = ""
    file_no: int = 0
    files: int = 0
    events: int = 0
    findings: int = 0
    fraction: float = 0.0


@dataclass
class Pose:
    x: int
    y: int
    eyes: str = "center"
    head: int = 0
    feet: str = "both"  # both | left_up | right_up | tucked


class _Canvas:
    def __init__(self, width: int, height: int) -> None:
        self.cells = [[(" ", "")] * width for _ in range(height)]
        self.width, self.height = width, height

    def put(self, x: int, y: int, ch: str, style: str = "", force: bool = False) -> None:
        if 0 <= y < self.height and 0 <= x < self.width and (ch != " " or force):
            self.cells[y][x] = (ch, style)

    def blit(self, x: int, y: int, rows: List[List[Tuple[str, str]]]) -> None:
        for r, row in enumerate(rows):
            for c, (ch, style) in enumerate(row):
                self.put(x + c, y + r, ch, style)

    def write(self, x: int, y: int, text: Text) -> None:
        for c, ch in enumerate(text.plain):
            style = str(text.style) if text.style else ""
            for span in text.spans:
                if span.start <= c < span.end:
                    style = str(span.style)
            self.put(x + c, y, ch, style)

    def text(self) -> Text:
        return _cells_text(self.cells)


def status_text(p: HuntProgress, stage: str, done_note: Optional[Text] = None) -> Text:
    if done_note is not None:
        return done_note
    if stage == "loading" or not p.files:
        return Text("waking up: loading rules and threat intel ...", style="#94a3b8")
    status = Text()
    status.append(f"hunting {p.file}", style="bold #e2e8f0")
    status.append(f"  ({p.file_no}/{p.files})  ", style="#64748b")
    status.append(f"{p.events:,} events", style="#93c5fd")
    status.append("  ·  ", style="#64748b")
    status.append(f"{p.findings} findings", style="bold #f87171" if p.findings else "#94a3b8")
    status.append(f"  ·  {int(p.fraction * 100)}%", style="bold #e2e8f0")
    return status


class OwlShow:
    """Runs the animation around a hunt:

        show = OwlShow(console, animation_mode(console))
        show.start()
        ... analyze(..., on_progress=show.update) ...
        show.finish(Text("hunt complete"))     # waits for the owl to get home, then clears the screen area
    """

    def __init__(self, console: Console, mode: str, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.console, self.mode, self.clock, self.sleep = console, mode, clock, sleep
        self.progress = HuntProgress()
        self._lock = threading.Lock()
        self._live: Optional[Live] = None
        self._started = 0.0
        self._finished_at: Optional[float] = None
        self._done_note: Optional[Text] = None
        self._x = 0.0
        self._last_frame = 0.0
        self._last_moved = -1.0
        self._still_since = 0.0
        self.width = max(60, min(console.width - 2, 112))

    # -- lifecycle -------------------------------------------------------------
    def start(self) -> None:
        if self.mode == "off":
            return
        self._started = self._last_frame = self._still_since = self.clock()
        self._live = Live(self, console=self.console, refresh_per_second=20, transient=True,
                          redirect_stdout=False, redirect_stderr=True)
        self._live.start()

    def update(self, progress: HuntProgress) -> None:
        with self._lock:
            self.progress = progress

    def finish(self, note: Optional[Text] = None) -> None:
        if self._live is None:
            return
        now = self.clock()
        with self._lock:
            self._finished_at = max(now, self._started + (INTRO + HOP if self.mode == "full" else 0))
            self._done_note = note
        if self.mode == "full":
            remaining = self._finished_at + FLY + HOLD - now
            if remaining > 0:
                self.sleep(remaining)
        self.stop()

    def stop(self) -> None:
        if self._live is not None:
            self._live.stop()
            self._live = None

    def __enter__(self) -> "OwlShow":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- frames ----------------------------------------------------------------
    def __rich__(self):
        with self._lock:
            progress, finished, note = self.progress, self._finished_at, self._done_note
        return self.render(self.clock() - self._started, progress, finished, note)

    def render(self, t: float, progress: HuntProgress, finished_at: Optional[float] = None,
               note: Optional[Text] = None):
        finished_t = None if finished_at is None else finished_at - self._started
        if self.mode == "compact":
            return self._compact(t, progress, note)
        return self._full(t, progress, finished_t, note)

    def _walk_target(self, progress: HuntProgress, span: int) -> float:
        return 5 + max(0.0, min(1.0, progress.fraction)) * (span - 5)

    def _follow(self, t: float, target: float) -> bool:
        """Move the displayed owl toward the progress position; returns True while it is walking."""
        elapsed = max(0.0, t - self._last_frame)
        self._last_frame = t
        step = elapsed / STEP_SECONDS
        if abs(target - self._x) > 0.5:
            self._x += max(-step, min(step, target - self._x))
            self._last_moved = t
            return True
        return t - self._last_moved < 0.15

    def _full(self, t: float, p: HuntProgress, finished_t: Optional[float], note: Optional[Text]):
        width = self.width
        text_x, ground_y = 2 + OWL_WIDTH + 4, 14
        bar_y, status_y = ground_y + OWL_HEIGHT, ground_y + OWL_HEIGHT + 1
        span = width - OWL_WIDTH - 4
        canvas = _Canvas(width, status_y + 1)
        canvas.blit(text_x, 0, OWL_CELLS)
        canvas.blit(text_x, 6, TRIAGE_CELLS)
        branch = owl_rows()[-1][0]
        for c, ch in enumerate(branch):
            canvas.put(2 + c, OWL_HEIGHT, ch, PALETTE["w"])
        canvas.write(2, 12, Text(TAGLINE, style="bold #fbbf24"))

        stage = "loading" if t < INTRO + HOP else "hunting"
        if t < INTRO:                                             # looking around on the branch
            eyes, head = look_around(t + 0.3)
            pose, bar = Pose(2, 0, eyes, head), 0
        elif t < INTRO + HOP:                                     # hop down onto the bar
            s = (t - INTRO) / HOP
            pose = Pose(2 + round(3 * s), round(ground_y * s * s), "center", 0, "both" if s > 0.92 else "tucked")
            self._x = pose.x - 2
            bar = 0
        elif finished_t is None or t < finished_t:                # walk with the progress
            walking = self._follow(t, self._walk_target(p, span))
            x = 2 + round(self._x)
            if walking:
                self._still_since = t
                blink = (t % 3.1) > 2.95
                pose = Pose(x, ground_y, "blink" if blink else "right", 1 if (x // 2) % 2 else 0,
                            "left_up" if x % 2 else "right_up")
            else:
                eyes, head = look_around(t - self._still_since)
                pose = Pose(x, ground_y, eyes, head)
            bar = x + OWL_WIDTH // 2 - 2
        else:                                                     # fly home
            s = min(1.0, (t - finished_t) / FLY)
            start_x = 2 + round(self._x)
            if s < 1.0:
                pose = Pose(round(start_x + (2 - start_x) * s), round(ground_y * (1 - (1 - (1 - s) ** 2))),
                            "left", -1 if s < 0.8 else 0, "tucked")
            else:
                pose = Pose(2, 0, "blink" if (t - finished_t - FLY) < 0.08 else "center")
            bar = width - 4
        if finished_t is not None and t >= finished_t:
            bar = width - 4
        for c in range(width - 4):
            canvas.put(2 + c, bar_y, "━" if c < bar else "╍", "#3b82f6" if c < bar else "#334155")
        canvas.write(2, status_y, status_text(p, stage, note if finished_t is not None and t >= finished_t else None))
        self._draw_owl(canvas, pose)
        return canvas.text()

    @staticmethod
    def _draw_owl(canvas: _Canvas, pose: Pose) -> None:
        rows = owl_rows(pose.eyes)[:-1]
        chars, codes = rows[-1]
        if pose.feet in ("left_up", "tucked"):
            chars = chars[:8] + "▀" + chars[9:]
        if pose.feet in ("right_up", "tucked"):
            chars = chars[:12] + "▀" + chars[13:]
        rows[-1] = (chars, codes)
        for r, (chars, codes) in enumerate(rows):
            dx = pose.head if r < HEAD_ROWS else 0
            inside = [i for i, ch in enumerate(chars) if ch != " "]
            left, right = (inside[0], inside[-1]) if inside else (0, -1)
            for c, (ch, code) in enumerate(zip(chars, codes.ljust(len(chars), "."))):
                canvas.put(pose.x + dx + c, pose.y + r, ch, PALETTE.get(code, ""), force=left <= c <= right)

    def _compact(self, t: float, p: HuntProgress, note: Optional[Text]) -> Text:
        track = max(20, min(self.width - 50, 40))
        self._follow(t, p.fraction * (track - 5))
        x = max(0, min(track - 5, round(self._x)))
        owl = Text(" " * (2 + x))
        owl.append("(-▼-)" if (t % 3.1) > 2.95 else COMPACT_OWL, style="bold #fbbf24")
        bar = Text("  ")
        filled = x + 2
        bar.append("━" * filled, style="#3b82f6")
        bar.append("╍" * max(0, track - filled), style="#334155")
        bar.append("  ")
        bar.append_text(status_text(p, "hunting", note))
        return Text("\n").join([owl, bar])
