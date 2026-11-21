"""The built-in rules carry a version, so a newer signed rules pack can replace them (and an older one cannot)."""
import re
from pathlib import Path

from owltriage.rules import (PACKAGED_RULES, RULES_ENGINE, builtin_rules_version, load_rules, packaged_rule_texts,
                             rules_digest, version_key)

ROOT = Path(__file__).resolve().parent.parent


def test_rules_version_is_bumped_whenever_a_rule_file_changes():
    version, digest = builtin_rules_version()
    assert re.match(r"^\d{4}\.\d{2}\.\d{2}(?:\.\d{1,3})?$", version)
    actual = rules_digest(packaged_rule_texts())
    assert digest == actual, (
        "The built-in rules changed, so owltriage/rules/VERSION must change too: set 'version' to today's date "
        f"(YYYY.MM.DD; add .2, .3 for a second or third change that day) and 'digest' to {actual}")


def test_the_digest_ignores_windows_line_endings_but_not_content():
    files = {"a.yml": "- id: x\n  title: y\n"}
    assert rules_digest(files) == rules_digest({"a.yml": "- id: x\r\n  title: y\r\n"})
    assert rules_digest(files) != rules_digest({"a.yml": "- id: x\n  title: z\n"})
    assert rules_digest(files) != rules_digest({"b.yml": "- id: x\n  title: y\n"})


def test_versions_compare_as_dates_then_counters():
    assert version_key("2026.11.21") < version_key("2026.11.21.1") < version_key("2026.11.21.2")
    assert version_key("2026.11.21.10") > version_key("2026.11.21.9")
    assert version_key("2026.12.01") > version_key("2026.11.30.5")


def test_rules_load_from_text_exactly_as_from_the_folder():
    from_folder = load_rules()
    from_text = load_rules(packaged_texts=packaged_rule_texts())
    assert set(from_text.rules) == set(from_folder.rules)
    assert from_text.rules["cmd-ntds-dump"].pattern.pattern == from_folder.rules["cmd-ntds-dump"].pattern.pattern
    assert RULES_ENGINE >= 1


def test_the_version_file_ships_in_the_wheel():
    assert (PACKAGED_RULES / "VERSION").is_file()
    assert '"rules/VERSION"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
