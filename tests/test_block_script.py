"""Execute the generated block_ips.sh against a fake iptables to prove it is idempotent and correct.

A real iptables needs root and would change this machine's firewall, so a small
shell stand-in on PATH records rules in a state file instead.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from owltriage.defense import BlockRule, write_script

FAKE_IPTABLES = r"""#!/usr/bin/env bash
state="${FAKE_IPT_STATE:?}"
touch "$state"
op="$1"; shift
rule="$(basename "$0") $*"
case "$op" in
  -C) grep -qxF -- "$rule" "$state" ;;
  -A) echo "$rule" >> "$state" ;;
  -D) grep -vxF -- "$rule" "$state" > "$state.tmp" || true; mv "$state.tmp" "$state" ;;
  *)  echo "unexpected option $op" >&2; exit 2 ;;
esac
"""

pytestmark = pytest.mark.skipif(shutil.which("bash") is None or sys.platform == "win32",
                                reason="needs a POSIX shell (iptables only exists on Linux anyway)")


@pytest.fixture
def fake_firewall(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("iptables", "ip6tables"):
        tool = bin_dir / name
        tool.write_text(FAKE_IPTABLES)
        tool.chmod(0o755)
    state = tmp_path / "rules.txt"
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "FAKE_IPT_STATE": str(state)}
    return env, state


RULES = [BlockRule("203.0.113.5", "inbound", ["SSH_BRUTE_FORCE"]),
         BlockRule("2001:db8::bad", "inbound", ["BAD_IP_MATCH"]),
         BlockRule("203.0.113.99", "outbound", ["C2_INDICATOR"])]
EXPECTED = ["iptables INPUT -s 203.0.113.5 -j DROP",
            "ip6tables INPUT -s 2001:db8::bad -j DROP",
            "iptables OUTPUT -d 203.0.113.99 -j DROP"]


def run(script: Path, env):
    return subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, encoding="utf-8", timeout=30)


def test_script_applies_each_rule_once_even_when_run_twice(tmp_path, fake_firewall):
    env, state = fake_firewall
    script = write_script(RULES, tmp_path / "block_ips.sh")

    first = run(script, env)
    assert first.returncode == 0, first.stderr
    assert "Applied 3 block rule(s)." in first.stdout
    assert state.read_text(encoding="utf-8").splitlines() == EXPECTED

    second = run(script, env)
    assert second.returncode == 0, second.stderr
    assert state.read_text(encoding="utf-8").splitlines() == EXPECTED  # no duplicates


def test_undo_commands_remove_the_rules(tmp_path, fake_firewall):
    env, state = fake_firewall
    script = write_script(RULES, tmp_path / "block_ips.sh")
    run(script, env)
    undo = [line[2:] for line in script.read_text(encoding="utf-8").splitlines() if line.startswith("# ip") and " -D " in line]
    undo_script = tmp_path / "undo.sh"
    undo_script.write_text("set -euo pipefail\n" + "\n".join(undo) + "\n")
    assert run(undo_script, env).returncode == 0
    assert state.read_text(encoding="utf-8") == ""


def test_script_stops_if_firewall_command_fails(tmp_path, fake_firewall):
    env, _ = fake_firewall
    broken = Path(env["PATH"].split(":")[0]) / "iptables"
    broken.write_text("#!/usr/bin/env bash\nexit 4\n")
    script = write_script(RULES[:1], tmp_path / "block_ips.sh")
    result = run(script, env)
    assert result.returncode != 0  # set -e: a failed -A must not be reported as success
    assert "Applied" not in result.stdout
