"""Installing owltriage must bring everything it needs, without breaking installs on unusual hardware."""
import importlib.util
import platform
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
packaging_markers = pytest.importorskip("packaging.markers")


def evtx_requirement(text):
    found = [line for line in re.findall(r'"([^"\n]*)"|\'([^\'\n]*)\'', text) for line in line if line.startswith("evtx")]
    assert len(found) == 1, found
    name, _, marker = found[0].partition(";")
    return name.strip(), packaging_markers.Marker(marker.strip())


def runtime_dependencies():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    return text[text.index("dependencies = ["):text.index("]", text.index("dependencies = ["))]


def env(sys_platform, machine):
    return {"sys_platform": sys_platform, "platform_machine": machine}


@pytest.mark.parametrize("sys_platform, machine, wanted", [
    ("linux", "x86_64", True), ("linux", "aarch64", True), ("darwin", "arm64", True), ("darwin", "x86_64", True),
    ("win32", "AMD64", True),
    # no evtx wheel exists here: requiring it would make `pip install owltriage` fail outright
    ("linux", "armv7l", False), ("win32", "ARM64", False), ("win32", "x86", False), ("linux", "ppc64le", False),
])
def test_evtx_is_installed_by_default_where_a_wheel_exists(sys_platform, machine, wanted):
    name, marker = evtx_requirement(runtime_dependencies())
    assert name.startswith("evtx>=")
    assert marker.evaluate(env(sys_platform, machine)) is wanted


def test_requirements_txt_matches_pyproject():
    _, from_pyproject = evtx_requirement(runtime_dependencies())
    lines = [line for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
             if line.startswith("evtx")]
    assert len(lines) == 1
    assert str(packaging_markers.Marker(lines[0].partition(";")[2].strip())) == str(from_pyproject)


def test_evtx_really_is_installed_on_supported_platforms():
    """The .evtx tests skip without the package; this one makes a missing install fail loudly instead."""
    _, marker = evtx_requirement(runtime_dependencies())
    if not marker.evaluate(env(sys.platform, platform.machine())):
        pytest.skip(f"no evtx wheel for {sys.platform}/{platform.machine()}")
    assert importlib.util.find_spec("evtx") is not None, "evtx should come with a plain `pip install owltriage`"
