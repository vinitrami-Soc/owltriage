"""tools/rulepack.py: what the GitHub workflow runs to sign and publish rules packs."""
import base64
import importlib.util
from pathlib import Path

import pytest

from owltriage import ed25519, rulepack
from owltriage.rules import builtin_rules_version, packaged_rule_texts

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("rulepack_tool", ROOT / "tools" / "rulepack.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

SEED = bytes(range(32))
SECRET = base64.b64encode(SEED).decode()
PUBLIC = ed25519.public_key(SEED)
TRUSTED = {rulepack.key_id(PUBLIC): base64.b64encode(PUBLIC).decode()}


@pytest.fixture
def signing_key(monkeypatch):
    monkeypatch.setenv("RULES_SIGNING_KEY", SECRET)
    monkeypatch.setattr(rulepack, "TRUSTED_KEYS", TRUSTED)


def test_build_signs_the_built_in_rules_into_a_pack_owltriage_accepts(tmp_path, signing_key):
    out = tmp_path / "owltriage-rules.json"
    assert tool.main(["build", str(out), "--source", "abc1234"]) == 0
    pack = rulepack.read_pack(out.read_bytes())
    assert pack.version == builtin_rules_version()[0] and pack.source == "abc1234"
    assert pack.files == packaged_rule_texts()


def test_build_refuses_when_the_rules_version_was_not_bumped(tmp_path, signing_key, monkeypatch, capsys):
    monkeypatch.setattr(tool, "builtin_rules_version", lambda: ("2026.11.21", "sha256:stale"))
    assert tool.main(["build", str(tmp_path / "p.json")]) == 1
    assert "owltriage/rules/VERSION" in capsys.readouterr().err


def test_build_needs_the_secret(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("RULES_SIGNING_KEY", raising=False)
    assert tool.main(["build", str(tmp_path / "p.json")]) == 1
    assert "RULES_SIGNING_KEY" in capsys.readouterr().err


def test_pubkey_tells_the_maintainer_which_key_to_trust(monkeypatch, capsys):
    monkeypatch.setenv("RULES_SIGNING_KEY", SECRET)
    monkeypatch.setattr(rulepack, "TRUSTED_KEYS", {})
    assert tool.main(["pubkey", "--require-trusted"]) == 1
    out = capsys.readouterr()
    assert rulepack.key_id(PUBLIC) in out.out and base64.b64encode(PUBLIC).decode() in out.out
    assert "::error::" in out.out and SECRET not in out.out + out.err      # never print the secret back
    monkeypatch.setattr(rulepack, "TRUSTED_KEYS", TRUSTED)
    assert tool.main(["pubkey", "--require-trusted"]) == 0


def test_keygen_makes_a_working_key(monkeypatch, capsys):
    assert tool.main(["keygen"]) == 0
    secret = [line.split()[-1] for line in capsys.readouterr().out.splitlines() if line.startswith("RULES_SIGNING_KEY")][0]
    assert len(base64.b64decode(secret)) == 32


def pack_file(tmp_path, name, version, extra=""):
    files = dict(packaged_rule_texts())
    if extra:
        files["extra.yml"] = extra
    path = tmp_path / name
    path.write_bytes(rulepack.build_pack(files, version, SEED, created="2099-01-01T00:00:00Z"))
    return path


@pytest.mark.parametrize("published, new, extra, outcome", [
    (None, "2099.01.01", "", "publish=true"),
    ("2099.01.01", "2099.01.02", "", "publish=true"),
    ("2099.01.01", "2099.01.01", "", "publish=false"),                 # nothing new: no empty commit
])
def test_decide_publishes_only_newer_packs(tmp_path, signing_key, capsys, published, new, extra, outcome):
    new_path = pack_file(tmp_path, "new.json", new, extra)
    old_path = pack_file(tmp_path, "old.json", published) if published else tmp_path / "missing.json"
    assert tool.main(["decide", str(new_path), "--published", str(old_path)]) == 0
    out = capsys.readouterr().out.split()
    assert outcome in out and f"version={new}" in out


@pytest.mark.parametrize("published, new, extra", [
    ("2099.01.01", "2099.01.01", "- id: x\n"),                         # rules changed, version did not
    ("2099.01.02", "2099.01.01", ""),                                  # going backwards
])
def test_decide_fails_loudly_when_the_version_is_wrong(tmp_path, signing_key, capsys, published, new, extra):
    new_path = pack_file(tmp_path, "new.json", new, extra)
    old_path = pack_file(tmp_path, "old.json", published)
    assert tool.main(["decide", str(new_path), "--published", str(old_path)]) == 1
    assert "VERSION" in capsys.readouterr().err


def test_the_workflow_publishes_only_with_the_secret_and_ci_skips_the_pack_branch():
    workflow = (ROOT / ".github" / "workflows" / "rules-pack.yml").read_text(encoding="utf-8")
    assert "secrets.RULES_SIGNING_KEY" in workflow and "tools/rulepack.py build" in workflow
    assert "steps.build.outputs.publish == 'true'" in workflow
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "branches-ignore: [rules-pack]" in ci
