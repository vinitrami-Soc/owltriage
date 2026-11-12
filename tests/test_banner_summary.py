"""The owl (logo + animation) and the owl's summary."""
import io
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
from rich.console import Console
from rich.text import Text

from owltriage import banner
from owltriage.banner import (FLY, HOLD, HOP, INTRO, HuntProgress, OwlShow, animation_mode, compact_logo, logo,
                              owl_rows)
from owltriage.defense import plan_blocks
from owltriage.detectors import analyze
from owltriage.intel import BadIPList
from owltriage.summary import summarize

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "owltriage" / "resources" / "samples"


def terminal(width=120, height=40):
    return Console(file=io.StringIO(), force_terminal=True, width=width, height=height, color_system="truecolor")


# ---------------------------------------------------------------- when does the owl move?
def test_animation_only_on_an_interactive_terminal(monkeypatch):
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("OWLTRIAGE_NO_ANIM", raising=False)
    assert animation_mode(Console(file=io.StringIO())) == "off"           # pipe / file / cron
    assert animation_mode(terminal(120, 40)) == "full"
    assert animation_mode(terminal(80, 24)) == "compact"                    # small terminal: one-line owl
    assert animation_mode(terminal(50, 20)) == "off"
    assert animation_mode(terminal(), wanted=False) == "off"                # --no-anim / --quiet / --svg
    monkeypatch.setenv("CI", "true")
    assert animation_mode(terminal()) == "off"
    monkeypatch.delenv("CI")
    monkeypatch.setenv("OWLTRIAGE_NO_ANIM", "1")
    assert animation_mode(terminal()) == "off"


def test_owl_sprite_rows_are_aligned_in_every_pose():
    for look in banner.EYES:
        rows = owl_rows(look)
        assert {len(chars) for chars, _ in rows} == {21}
        assert all(len(codes) == len(chars) for chars, codes in rows)


def test_static_logo_and_compact_logo_render():
    console = terminal(110)
    console.print(logo(59))
    out = console.file.getvalue()
    assert "Sees in the dark" in out and "59 rules" in out
    assert "OwlTriage" in compact_logo(59).plain


# ---------------------------------------------------------------- the story, frame by frame
class FakeClock:
    def __init__(self):
        self.now = 100.0
        self.slept = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept += seconds
        self.now += seconds


def full_show(clock):
    show = OwlShow(terminal(112, 40), "full", clock=clock, sleep=clock.sleep)
    show._started = show._last_frame = show._still_since = clock()
    return show


def owl_top_left(frame: Text):
    """Row and column of the owl's left ear in a rendered frame."""
    for row, line in enumerate(frame.plain.split("\n")):
        col = line.find("▄▄             ▄▄")
        if col != -1:
            return row, col
    return None


def test_story_owl_leaves_the_branch_walks_with_progress_and_flies_home():
    clock = FakeClock()
    show = full_show(clock)
    heights = set()

    def frame(t, fraction, finished=None, note=None):
        f = show.render(t, HuntProgress("auth.log", 1, 1, 10, 2, fraction), finished, note)
        heights.add(len(f.plain.split("\n")))
        return f

    assert owl_top_left(frame(0.1, 0.0))[0] == 0                      # on its branch next to the name
    assert "waking up" in frame(0.2, 0.0).plain
    landed = [owl_top_left(frame(INTRO + HOP + 0.05 + i * 0.05, 0.0)) for i in range(3)][-1]
    assert landed[0] == 14                                             # standing on the loading bar
    x_start = landed[1]
    for i in range(60):                                                # progress 0 -> 60 %
        frame(INTRO + HOP + 0.2 + i * 0.05, 0.01 * i)
    walked = owl_top_left(frame(INTRO + HOP + 3.3, 0.6))
    assert walked[0] == 14 and walked[1] > x_start + 30                # walked along with the progress
    assert "60%" in frame(INTRO + HOP + 3.35, 0.6).plain
    done_at = clock.now - 100 + INTRO + HOP + 3.4
    final = frame(done_at + FLY + 0.05, 1.0, finished=done_at + show._started, note=Text("✔ hunt complete"))
    assert owl_top_left(final)[0] == 0                                 # back on its branch
    assert "✔ hunt complete" in final.plain
    assert len(heights) == 1                                           # the frame never changes height (no jumping)


def test_owl_is_opaque_in_flight():
    clock = FakeClock()
    show = full_show(clock)
    # mid-hop the owl passes in front of the tagline: none of the hidden letters may show inside its body
    mid = show.render(INTRO + HOP * 0.75, HuntProgress())
    tagline_row = [line for line in mid.plain.split("\n") if "Sees" in line or "▄█" in line]
    assert tagline_row  # sanity: frame rendered
    assert "Sees in the dark. Triages before you wake up." not in mid.plain


def test_owl_looks_around_while_work_is_stalled():
    clock = FakeClock()
    show = full_show(clock)
    eyes_seen = set()
    for i in range(80):  # progress stuck at 30 %: the owl stands still and looks around
        frame = show.render(INTRO + HOP + 0.5 + i * 0.05, HuntProgress("big.evtx", 1, 1, 5, 0, 0.3))
        eye_row = frame.plain.split("\n")[14 + 4]
        eyes_seen.add("left" if "██●  ██" in eye_row else "right" if "██  ●██" in eye_row else
                      "blink" if "█▄▄▄▄▄█" in eye_row else "center")
    assert {"left", "right", "center", "blink"} <= eyes_seen


def test_extra_time_is_about_one_and_a_half_seconds_for_a_fast_hunt():
    clock = FakeClock()
    show = OwlShow(terminal(112, 40), "full", clock=clock, sleep=clock.sleep)
    show._live = type("FakeLive", (), {"stop": lambda self: None})()   # no real terminal needed
    show._started = clock()
    clock.now += 0.05                                                  # the hunt itself took 50 ms
    show.finish(Text("done"))
    total = clock.now - show._started
    assert abs(total - (INTRO + HOP + FLY + HOLD)) < 0.01 and total <= 1.55


def test_compact_mode_never_adds_time():
    clock = FakeClock()
    show = OwlShow(terminal(80, 24), "compact", clock=clock, sleep=clock.sleep)
    show._live = type("FakeLive", (), {"stop": lambda self: None})()
    show._started = clock()
    frame = show.render(0.3, HuntProgress("auth.log", 1, 2, 100, 3, 0.5))
    assert "(◉▼◉)" in frame.plain or "(-▼-)" in frame.plain
    show.finish(Text("done"))
    assert clock.slept == 0


def test_off_mode_is_a_no_op():
    show = OwlShow(Console(file=io.StringIO()), "off")
    show.start()
    show.update(HuntProgress())
    show.finish(Text("done"))
    assert show._live is None


@pytest.mark.skipif(sys.platform == "win32", reason="pty is POSIX-only")
def test_real_terminal_run_animates_and_stays_within_budget(tmp_path):
    import fcntl
    import pty
    import select
    import struct
    import termios
    env = {**os.environ, "PYTHONPATH": str(ROOT), "OWLTRIAGE_FEEDS_DIR": str(tmp_path / "none"),
           "TERM": "xterm-256color"}
    env.pop("CI", None)
    env.pop("OWLTRIAGE_NO_ANIM", None)

    def run(*extra):
        pid, fd = pty.fork()
        if pid == 0:
            os.execvpe(sys.executable, [sys.executable, "-m", "owltriage", "hunt", "--demo", "--out-dir",
                                        str(tmp_path), *extra], env)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 112, 0, 0))
        started, out = time.monotonic(), b""
        while True:
            ready, _, _ = select.select([fd], [], [], 0.1)
            if fd in ready:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
        _, status = os.waitpid(pid, 0)
        return os.waitstatus_to_exitcode(status), time.monotonic() - started, out.decode("utf-8", "replace")

    code, with_owl, text = run()
    plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
    assert code == 0 and "\x1b[?25l" in text and "waking up" in plain and "Traceback" not in plain
    code, without, text = run("--no-anim")
    assert code == 0 and "\x1b[?25l" not in text
    assert 1.0 < with_owl - without < 2.5  # the agreed ~1.5 s, with slack for slow CI machines


# ---------------------------------------------------------------- the owl's summary
@pytest.fixture(scope="module")
def demo_summary():
    result = analyze([SAMPLES / "auth.log", SAMPLES / "access.log", SAMPLES / "windows_security.xml"],
                     BadIPList.load(SAMPLES / "bad_ips.txt"))
    return result, summarize(result, plan_blocks(result.findings)[0])


def test_summary_tells_the_attack_stories(demo_summary):
    _, summary = demo_summary
    stories = {s.who: s for s in summary.stories}
    assert stories["198.51.100.77"].severity == "critical"
    assert stories["198.51.100.77"].text == "RDP brute force, then logged in as 'administrator' on FS01.corp.example"
    assert stories["203.0.113.5"].text == "SSH brute force, then logged in as 'admin' on web01"
    assert stories["FS01.corp.example"].text == "Backups / shadow copies deleted"
    assert stories["198.51.100.23"].text.startswith("SSH password spraying")
    assert stories["203.0.113.50"].text.startswith("SQL injection")
    assert "C2 server" in stories["203.0.113.99"].text
    assert [s.severity for s in summary.stories] == sorted(
        (s.severity for s in summary.stories), key=["critical", "high", "medium", "low"].index)


def test_summary_next_steps_are_actionable(demo_summary):
    _, summary = demo_summary
    steps = "\n".join(summary.steps)
    assert "Reset passwords and end active sessions for: administrator (FS01.corp.example), admin (web01)" in steps
    assert "Isolate and collect memory/disk before cleaning: FS01.corp.example, web01" in steps
    assert "6 attacker IP(s) inbound, 1 C2 outbound" in steps
    assert "Event logs were cleared" in steps


def test_summary_of_a_clean_log_is_empty(tmp_path):
    log = tmp_path / "ok.log"
    log.write_text("Nov  9 03:00:14 web01 sshd[1]: Accepted publickey for ops from 192.168.1.10 port 5 ssh2\n")
    result = analyze([log])
    summary = summarize(result, [])
    assert summary.stories == [] and summary.steps == []


def test_summary_is_in_every_report(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(ROOT), "OWLTRIAGE_FEEDS_DIR": str(tmp_path / "none")}
    run = subprocess.run([sys.executable, "-m", "owltriage", "hunt", "--demo", "--out-dir", str(tmp_path)],
                         capture_output=True, text=True, encoding="utf-8", env=env, timeout=120)
    assert run.returncode == 0
    assert "The owl's summary" in run.stdout and "What to do next" in run.stdout
    assert "\x1b[" not in run.stdout and "██████╗" not in run.stdout   # piped: no colours, no big logo
    text = (tmp_path / "triage_report.txt").read_text(encoding="utf-8")
    assert "THE OWL'S SUMMARY" in text and "Reset passwords" in text
    import json
    data = json.loads((tmp_path / "triage_report.json").read_text(encoding="utf-8"))
    assert data["summary"]["stories"][0]["severity"] == "critical" and data["summary"]["next_steps"]


def test_bare_command_shows_usage():
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    run = subprocess.run([sys.executable, "-m", "owltriage"], capture_output=True, text=True, encoding="utf-8", env=env, timeout=60)
    assert run.returncode == 0 and "usage: owltriage" in run.stdout
