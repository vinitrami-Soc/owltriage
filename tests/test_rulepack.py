"""Signed rules packs: newer rules without a new owltriage release, and nothing unsigned, older or broken gets in."""
import base64
import json

import pytest

from owltriage import ed25519, rulepack
from owltriage.cli import main
from owltriage.rulepack import PackError, build_pack, install_pack, load_active_rules, read_pack, rollback
from owltriage.rules import builtin_rules_version, packaged_rule_texts

SEED = bytes(range(32))
PUBLIC = ed25519.public_key(SEED)
TRUSTED = {rulepack.key_id(PUBLIC): base64.b64encode(PUBLIC).decode()}
BUILTIN, _ = builtin_rules_version()
EXTRA_RULE = """- id: cmd-test-pack-rule
  name: SUSPICIOUS_COMMAND
  title: Rule that only exists in the test pack
  type: command
  severity: medium
  mitre: [T1059]
  pattern: '\\bowl-pack-test\\b'
  tests:
    match: ["owl-pack-test --now"]
    no_match: ["owl pack test"]
"""


def make_pack(version="2099.01.01", extra=True, files=None, seed=SEED, **payload):
    files = dict(packaged_rule_texts()) if files is None else files
    if extra:
        files["extra.yml"] = EXTRA_RULE
    return build_pack(files, version, seed, created="2099-01-01T00:00:00Z", source="test", **payload)


def resign(data: bytes, change) -> bytes:
    """Edit a pack's payload, then sign it properly with the test key (a well-signed but bad pack)."""
    envelope = json.loads(data)
    payload = json.loads(base64.b64decode(envelope["payload"]))
    change(payload)
    raw = json.dumps(payload).encode()
    envelope["payload"] = base64.b64encode(raw).decode()
    envelope["signature"] = base64.b64encode(ed25519.sign(SEED, raw)).decode()
    return json.dumps(envelope).encode()


@pytest.fixture
def trusted(monkeypatch):
    monkeypatch.setattr(rulepack, "TRUSTED_KEYS", TRUSTED)


# -- reading and checking a pack --------------------------------------------------------------
def test_the_built_in_trusted_keys_are_well_formed():
    """A typo when pasting a key would make every real pack fail; catch it here instead."""
    assert rulepack.TRUSTED_KEYS
    for kid, encoded in rulepack.TRUSTED_KEYS.items():
        public = base64.b64decode(encoded, validate=True)
        assert len(public) == 32 and rulepack.key_id(public) == kid
        assert ed25519._decompress(public) is not None                   # a real curve point


def test_a_signed_pack_round_trips():
    pack = read_pack(make_pack(), TRUSTED)
    assert pack.version == "2099.01.01" and pack.key_id == rulepack.key_id(PUBLIC)
    assert pack.files["extra.yml"] == EXTRA_RULE
    ruleset = rulepack.validate_pack(pack)
    assert "cmd-test-pack-rule" in ruleset.rules and "cmd-ntds-dump" in ruleset.rules


def test_a_changed_payload_fails_the_signature():
    envelope = json.loads(make_pack())
    payload = base64.b64decode(envelope["payload"]).replace(b"owl-pack-test", b"owl-pack-tesX")
    envelope["payload"] = base64.b64encode(payload).decode()
    with pytest.raises(PackError, match="signature"):
        read_pack(json.dumps(envelope).encode(), TRUSTED)


def test_only_keys_built_into_owltriage_are_trusted():
    with pytest.raises(PackError, match="unknown key"):
        read_pack(make_pack(seed=bytes(32)), TRUSTED)
    with pytest.raises(PackError, match="no rules-pack signing key"):
        read_pack(make_pack(), {})


@pytest.mark.parametrize("data, reason", [
    (b"not json", "not a rules pack"),
    (b'{"format": 2}', "format"),
    (b"[1, 2]", "not a rules pack"),
])
def test_garbage_is_rejected(data, reason):
    with pytest.raises(PackError, match=reason):
        read_pack(data, TRUSTED)


def test_oversized_packs_are_refused_before_parsing():
    with pytest.raises(PackError, match="larger than"):
        read_pack(b" " * (rulepack.MAX_PACK_BYTES + 1), TRUSTED)


@pytest.mark.parametrize("change, reason", [
    (lambda p: p["files"].update({"../../.bashrc.yml": "x"}), "file name"),
    (lambda p: p["files"].update({"VERSION": "x"}), "file name"),
    (lambda p: p.update(version="next week"), "version"),
    (lambda p: p.update(files=["a.yml"]), "files"),
])
def test_well_signed_but_malformed_payloads_are_rejected(change, reason):
    with pytest.raises(PackError, match=reason):
        read_pack(resign(make_pack(), change), TRUSTED)


def test_a_pack_for_a_newer_rules_engine_asks_for_an_upgrade():
    pack = read_pack(make_pack(engine=99), TRUSTED)
    with pytest.raises(PackError, match="newer owltriage"):
        rulepack.validate_pack(pack)


def test_every_rule_must_pass_its_own_examples():
    broken = EXTRA_RULE.replace('no_match: ["owl pack test"]', 'no_match: ["owl-pack-test"]')
    pack = read_pack(make_pack(files={**packaged_rule_texts(), "extra.yml": broken}, extra=False), TRUSTED)
    with pytest.raises(PackError, match="cmd-test-pack-rule"):
        rulepack.validate_pack(pack)


def test_rules_that_do_not_load_are_rejected():
    pack = read_pack(make_pack(files={"windows.yml": "- id: x\n  type: [unclosed\n"}, extra=False), TRUSTED)
    with pytest.raises(PackError, match="does not load"):
        rulepack.validate_pack(pack)


def test_a_pack_that_detects_nothing_in_the_attack_samples_is_rejected():
    pack = read_pack(make_pack(files={"extra.yml": EXTRA_RULE}, extra=False), TRUSTED)
    with pytest.raises(PackError, match="finds nothing"):
        rulepack.validate_pack(pack)


# -- installing, choosing and rolling back ------------------------------------------------------
def test_install_makes_the_pack_the_active_rules(tmp_path):
    result = install_pack(make_pack(), tmp_path, TRUSTED)
    assert result.status == "installed" and result.before == BUILTIN and result.after == "2099.01.01"
    assert result.added == ["cmd-test-pack-rule"] and result.removed == []
    active = load_active_rules(pack_dir=tmp_path, trusted=TRUSTED)
    assert (active.source, active.version) == ("pack", "2099.01.01")
    assert "cmd-test-pack-rule" in active.ruleset.rules and not active.note


def test_the_same_or_an_older_pack_changes_nothing(tmp_path):
    install_pack(make_pack("2099.01.02"), tmp_path, TRUSTED)
    for version in ("2099.01.02", "2099.01.01", "2020.01.01"):            # replay and downgrade attempts
        result = install_pack(make_pack(version), tmp_path, TRUSTED)
        assert result.status == "not-newer" and result.before == "2099.01.02"
    assert load_active_rules(pack_dir=tmp_path, trusted=TRUSTED).version == "2099.01.02"


def test_a_pack_older_than_the_built_in_rules_is_not_installed(tmp_path):
    assert install_pack(make_pack("2020.01.01"), tmp_path, TRUSTED).status == "not-newer"
    assert not (tmp_path / "current.json").exists()


def test_a_rejected_pack_leaves_the_working_one_in_place(tmp_path):
    install_pack(make_pack("2099.01.01"), tmp_path, TRUSTED)
    bad = resign(make_pack("2099.01.05"), lambda p: p["files"].update({"windows.yml": "- [oops"}))
    with pytest.raises(PackError):
        install_pack(bad, tmp_path, TRUSTED)
    assert load_active_rules(pack_dir=tmp_path, trusted=TRUSTED).version == "2099.01.01"


def test_rollback_steps_back_to_the_previous_pack_then_the_built_in_rules(tmp_path):
    install_pack(make_pack("2099.01.01"), tmp_path, TRUSTED)
    install_pack(make_pack("2099.01.02"), tmp_path, TRUSTED)
    assert rollback(tmp_path) == "pack"
    assert load_active_rules(pack_dir=tmp_path, trusted=TRUSTED).version == "2099.01.01"
    assert rollback(tmp_path) == "built-in"
    active = load_active_rules(pack_dir=tmp_path, trusted=TRUSTED)
    assert (active.source, active.version) == ("built-in", BUILTIN)
    assert rollback(tmp_path) is None


def test_a_tampered_or_corrupt_installed_pack_falls_back_to_the_built_in_rules(tmp_path):
    install_pack(make_pack(), tmp_path, TRUSTED)
    current = tmp_path / "current.json"
    current.write_bytes(current.read_bytes().replace(b'"signature": "', b'"signature": "AA'))
    active = load_active_rules(pack_dir=tmp_path, trusted=TRUSTED)
    assert active.source == "built-in" and "ignored" in active.note
    current.write_text("{", encoding="utf-8")
    assert load_active_rules(pack_dir=tmp_path, trusted=TRUSTED).source == "built-in"


def test_upgrading_owltriage_past_the_pack_uses_the_newer_built_in_rules(tmp_path, monkeypatch):
    install_pack(make_pack("2099.01.01"), tmp_path, TRUSTED)
    monkeypatch.setattr(rulepack, "builtin_rules_version", lambda: ("2099.06.01", "sha256:x"))
    active = load_active_rules(pack_dir=tmp_path, trusted=TRUSTED)
    assert (active.source, active.version) == ("built-in", "2099.06.01") and not active.note


def test_your_own_rules_still_apply_on_top_of_a_pack(tmp_path):
    install_pack(make_pack(), tmp_path / "pack", TRUSTED)
    mine = tmp_path / "mine"
    mine.mkdir()
    (mine / "tune.yml").write_text("- id: cmd-test-pack-rule\n  enabled: false\n", encoding="utf-8")
    active = load_active_rules([mine], pack_dir=tmp_path / "pack", trusted=TRUSTED)
    assert active.source == "pack" and not active.ruleset.rules["cmd-test-pack-rule"].enabled


# -- downloading ---------------------------------------------------------------------------------
class FakeResponse:
    def __init__(self, body: bytes, status=200):
        self.body, self.status_code = body, status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"{self.status_code}", response=self)

    def iter_content(self, size):
        for i in range(0, len(self.body), size):
            yield self.body[i:i + size]


class FakeSession:
    def __init__(self, body: bytes, status=200):
        self.body, self.status, self.urls, self.headers = body, status, [], {}

    def get(self, url, timeout, stream):
        self.urls.append(url)
        return FakeResponse(self.body, self.status)


def test_download_is_https_only_and_size_capped():
    session = FakeSession(b"{}")
    assert rulepack.fetch_pack("https://example.org/p.json", session) == b"{}"
    with pytest.raises(PackError, match="https"):
        rulepack.fetch_pack("http://example.org/p.json", session)
    with pytest.raises(PackError, match="larger than"):
        rulepack.fetch_pack("https://example.org/p.json", FakeSession(b"x" * (rulepack.MAX_PACK_BYTES + 1)))
    with pytest.raises(PackError, match="no rules pack published"):
        rulepack.fetch_pack("https://example.org/p.json", FakeSession(b"", status=404))


# -- the command line ------------------------------------------------------------------------------
def test_update_rules_from_a_file_then_rollback(tmp_path, trusted, capsys):
    pack = tmp_path / "owltriage-rules.json"
    pack.write_bytes(make_pack())
    assert main(["update-rules", "--file", str(pack)]) == 0
    out = capsys.readouterr().out
    assert f"{BUILTIN} -> 2099.01.01" in out and "cmd-test-pack-rule" in out
    assert main(["rules", "list", "--type", "command"]) == 0
    assert "rules 2099.01.01 (signed pack)" in capsys.readouterr().out
    assert main(["update-rules", "--file", str(pack)]) == 0
    assert "already" in capsys.readouterr().out
    assert main(["update-rules", "--rollback"]) == 0
    assert f"built-in rules {BUILTIN}" in capsys.readouterr().out


def test_update_rules_rejects_a_tampered_file_and_says_nothing_changed(tmp_path, trusted, capsys):
    pack = tmp_path / "owltriage-rules.json"
    pack.write_bytes(make_pack().replace(b'"signature": "', b'"signature": "AA'))
    assert main(["update-rules", "--file", str(pack)]) == 1
    err = " ".join(capsys.readouterr().err.split())                # the terminal may wrap the line
    assert "Rules pack rejected" in err and "Nothing was changed" in err


def test_update_rules_check_reports_a_newer_pack_without_installing(trusted, monkeypatch, capsys):
    monkeypatch.setattr(rulepack, "fetch_pack", lambda url, session=None: make_pack("2099.01.03"))
    assert main(["update-rules", "--check"]) == 0
    assert "Newer rules available: 2099.01.03" in capsys.readouterr().out
    assert load_active_rules().source == "built-in"


def test_version_shows_the_built_in_rules_version(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert f"rules {BUILTIN}" in capsys.readouterr().out
