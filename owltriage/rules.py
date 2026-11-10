"""Detection-as-code: load, validate and self-test YAML rules.

Rule types
  web          regex on HTTP request fields (decoded path, user_agent, referrer)
  command      regex on command lines: sudo COMMAND=, Windows 4688 / Sysmon 1, decoded payloads
  line         regex on raw text log lines (auth.log, syslog, ...)
  event        structured match on Windows events: event_id + provider/channel + field regexes
  correlation  built-in stateful logic (brute force, blocklist, ...); YAML tunes it

Packaged rules live in owltriage/rules/. Extra directories (`--rules-dir`) are
merged on top: a rule with an existing `id` updates only the keys it sets, so
`{id: auth-brute-force, threshold: 10}` or `{id: web-xss, enabled: false}` is
all it takes to tune or disable a rule. See docs/RULES.md.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

from .utils import SEVERITIES, clean

PACKAGED_RULES = Path(__file__).resolve().parent / "rules"
ATTACK_FILE = Path(__file__).resolve().parent / "resources" / "attack.yml"
RULE_TYPES = ("web", "command", "line", "event", "correlation")
WEB_FIELDS = ("path", "user_agent", "referrer")
BUILTIN_CORRELATIONS = ("auth-brute-force", "auth-success-after-brute-force", "auth-success-from-bad-ip",
                        "blocklist-match", "encoded-payload", "hidden-ip-in-payload")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,40}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
MAX_INPUT = 8192  # regexes never see more than this many characters: bounds worst-case time
KNOWN_KEYS = {"id", "name", "title", "type", "severity", "mitre", "description", "pattern", "fields", "match",
              "detail", "block", "tests", "references", "author", "enabled", "ignore_case", "ip_field",
              "false_positives"}


class RuleError(ValueError):
    pass


def load_techniques(path: Path = ATTACK_FILE) -> Dict[str, dict]:
    with Path(path).open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


_TEMPLATE = re.compile(r"\{(\w+)\}")


def render_template(template: str, values: Dict[str, Any], limit: int = 80) -> str:
    """'{TargetUserName} by {SubjectUserName}' -> values. Plain substitution only: unlike
    str.format, a crafted template or value cannot reach object attributes."""
    def value(match) -> str:
        text = values.get(match.group(1), "?")
        return "" if text in ("", "-") else clean(text, limit)  # Windows writes "-" for empty fields
    return re.sub(r"\s{2,}", " ", _TEMPLATE.sub(value, template)).strip()


@dataclass
class Rule:
    id: str
    name: str
    title: str
    type: str
    severity: str
    mitre: List[str] = field(default_factory=list)
    description: str = ""
    pattern: Optional["re.Pattern[str]"] = None
    fields: List[str] = field(default_factory=lambda: ["path"])
    event_ids: List[int] = field(default_factory=list)
    provider: str = ""
    channel: str = ""
    field_patterns: Dict[str, "re.Pattern[str]"] = field(default_factory=dict)
    detail: str = ""
    ip_field: str = ""
    block: Optional[str] = None
    tests: Dict[str, list] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)
    author: str = ""
    enabled: bool = True
    origin: str = ""
    params: Dict[str, Any] = field(default_factory=dict)  # extra keys for correlation rules

    def param(self, key: str, default: Any = None) -> Any:
        return self.params.get(key, default)

    def search(self, text: Optional[str]):
        if not text or self.pattern is None:
            return None
        return self.pattern.search(text[:MAX_INPUT])

    def search_web(self, path: Optional[str], user_agent: Optional[str] = None, referrer: Optional[str] = None):
        values = {"path": path, "user_agent": user_agent, "referrer": referrer}
        for name in self.fields:
            text = values.get(name)
            if not text:
                continue
            found = self.search(text)
            if not found and name == "path" and "+" in text:
                found = self.search(text.replace("+", " "))  # '+' means space in query strings
            if found:
                return found
        return None

    def matches_record(self, event_id: Optional[int], provider: str, channel: str, fields: Dict[str, str]) -> bool:
        if self.event_ids and event_id not in self.event_ids:
            return False
        if self.provider and self.provider.lower() not in (provider or "").lower():
            return False
        if self.channel and self.channel.lower() != (channel or "").lower():
            return False
        for name, pattern in self.field_patterns.items():
            if name == "*":  # any field: for events whose <Data> elements have no names
                if not any(pattern.search(str(value)[:MAX_INPUT]) for value in fields.values()):
                    return False
            elif not pattern.search(str(fields.get(name, ""))[:MAX_INPUT]):
                return False
        return True

    def format_title(self, match=None) -> str:
        if match is not None and "{match}" in self.title:
            return self.title.replace("{match}", clean(match.group(0), 40).lower())
        return self.title


def _compile(pattern: str, ignore_case: bool, where: str) -> "re.Pattern[str]":
    try:
        return re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error as exc:
        raise RuleError(f"{where}: invalid regex: {exc}") from None


def build_rule(data: Dict[str, Any], techniques: Dict[str, dict], origin: str = "") -> Rule:
    rid = data.get("id")
    where = f"{origin}: rule {rid!r}" if origin else f"rule {rid!r}"
    if not isinstance(rid, str) or not ID_RE.match(rid):
        raise RuleError(f"{where}: 'id' must be lowercase-kebab-case, 3-64 chars")
    for key in ("name", "title", "type", "severity"):
        if not isinstance(data.get(key), str) or not data.get(key):
            raise RuleError(f"{where}: missing '{key}'")
    if not NAME_RE.match(data["name"]):
        raise RuleError(f"{where}: 'name' must be UPPER_SNAKE_CASE (it groups findings, e.g. SQL_INJECTION)")
    rtype = data["type"]
    if rtype not in RULE_TYPES:
        raise RuleError(f"{where}: unknown type {rtype!r} (use one of {', '.join(RULE_TYPES)})")
    if data["severity"] not in SEVERITIES:
        raise RuleError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
    if rtype != "correlation":
        unknown = sorted(set(data) - KNOWN_KEYS)
        if unknown:
            raise RuleError(f"{where}: unknown key(s) {unknown} (typo?)")

    mitre_keys = [k for k in data if k == "mitre" or k.startswith("mitre_")]
    for key in mitre_keys:
        values = data.get(key) or []
        if not isinstance(values, list):
            raise RuleError(f"{where}: '{key}' must be a list like [T1110.001]")
        for technique in values:
            if not isinstance(technique, str) or not TECHNIQUE_RE.match(technique):
                raise RuleError(f"{where}: {technique!r} is not an ATT&CK technique ID")
            if technique not in techniques:
                raise RuleError(f"{where}: {technique} is not in resources/attack.yml; add it with its official name")
    severity_keys = [k for k in data if k.startswith("severity_")]
    for key in severity_keys:
        if data[key] not in SEVERITIES:
            raise RuleError(f"{where}: '{key}' must be one of {', '.join(SEVERITIES)}")
    if data.get("block") not in (None, "inbound", "outbound"):
        raise RuleError(f"{where}: 'block' must be inbound or outbound")

    ignore_case = bool(data.get("ignore_case", True))
    rule = Rule(
        id=rid, name=data["name"], title=data["title"], type=rtype, severity=data["severity"],
        mitre=list(data.get("mitre") or []), description=str(data.get("description") or "").strip(),
        detail=str(data.get("detail") or ""), ip_field=str(data.get("ip_field") or ""),
        block=data.get("block"), tests=data.get("tests") or {}, references=list(data.get("references") or []),
        false_positives=list(data.get("false_positives") or []), author=str(data.get("author") or ""),
        enabled=bool(data.get("enabled", True)), origin=origin,
    )

    if rtype in ("web", "command", "line"):
        if not isinstance(data.get("pattern"), str) or not data["pattern"]:
            raise RuleError(f"{where}: {rtype} rules need a 'pattern' (regex)")
        rule.pattern = _compile(data["pattern"], ignore_case, where)
        if rtype == "web":
            rule.fields = list(data.get("fields") or ["path"])
            unknown = [f for f in rule.fields if f not in WEB_FIELDS]
            if unknown:
                raise RuleError(f"{where}: unknown web field(s) {unknown}; use {', '.join(WEB_FIELDS)}")
    elif rtype == "event":
        match = data.get("match")
        if not isinstance(match, dict) or "event_id" not in match:
            raise RuleError(f"{where}: event rules need 'match: {{event_id: ...}}'")
        ids = match["event_id"] if isinstance(match["event_id"], list) else [match["event_id"]]
        try:
            rule.event_ids = [int(i) for i in ids]
        except (TypeError, ValueError):
            raise RuleError(f"{where}: event_id must be a number or a list of numbers") from None
        rule.provider = str(match.get("provider") or "")
        rule.channel = str(match.get("channel") or "")
        for name, pattern in (match.get("fields") or {}).items():
            rule.field_patterns[str(name)] = _compile(str(pattern), ignore_case, f"{where} field {name}")
    else:  # correlation
        if rid not in BUILTIN_CORRELATIONS:
            raise RuleError(f"{where}: unknown correlation; built-ins are {', '.join(BUILTIN_CORRELATIONS)}")
        rule.params = {k: v for k, v in data.items() if k not in KNOWN_KEYS}
    return rule


def _rule_files(directory: Path) -> List[Path]:
    return sorted(p for p in Path(directory).rglob("*") if p.suffix in (".yml", ".yaml") and p.is_file())


def _read_rule_file(path: Path) -> List[Dict[str, Any]]:
    try:
        with path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)  # safe_load: rule files never execute code
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from None
    if data is None:
        return []
    items = data if isinstance(data, list) else [data]
    if not all(isinstance(item, dict) for item in items):
        raise RuleError(f"{path}: expected a rule mapping or a list of rule mappings")
    return items


@dataclass
class RuleSet:
    rules: Dict[str, Rule]
    techniques: Dict[str, dict]

    def enabled(self, rule_type: Optional[str] = None) -> List[Rule]:
        return [r for r in self.rules.values() if r.enabled and (rule_type is None or r.type == rule_type)]

    def correlation(self, rule_id: str) -> Optional[Rule]:
        rule = self.rules.get(rule_id)
        return rule if rule is not None and rule.enabled else None

    def technique_name(self, technique: str) -> str:
        return (self.techniques.get(technique) or {}).get("name", technique)


def load_rules(extra_dirs: Sequence = (), packaged_dir: Path = PACKAGED_RULES) -> RuleSet:
    techniques = load_techniques()
    raw: Dict[str, Dict[str, Any]] = {}
    origins: Dict[str, str] = {}
    for path in _rule_files(packaged_dir):
        for item in _read_rule_file(path):
            rid = item.get("id")
            if rid in raw:
                raise RuleError(f"{path.name}: duplicate rule id {rid!r} (also in {origins[rid]})")
            raw[rid] = dict(item)
            origins[rid] = path.name
    for directory in extra_dirs:
        folder = Path(directory)
        if not folder.is_dir():
            raise RuleError(f"rules directory not found: {folder}")
        for path in _rule_files(folder):
            for item in _read_rule_file(path):
                rid = item.get("id")
                if rid in raw:
                    raw[rid].update(item)  # partial override: tune or disable a packaged rule
                else:
                    raw[rid] = dict(item)
                origins[rid] = str(path)
    rules = {rid: build_rule(data, techniques, origins[rid]) for rid, data in raw.items()}
    return RuleSet(rules, techniques)


# -- self tests --------------------------------------------------------------------
@dataclass
class RuleTestResult:
    rule: Rule
    failures: List[str] = field(default_factory=list)
    examples: int = 0

    @property
    def ok(self) -> bool:
        return not self.failures


def _event_sample(sample: Any) -> Tuple[Optional[int], str, str, Dict[str, str]]:
    if not isinstance(sample, dict):
        raise RuleError("event rule test samples must be mappings with event_id and fields")
    values = dict(sample)
    event_id = values.pop("event_id", None)
    provider = str(values.pop("provider", ""))
    channel = str(values.pop("channel", ""))
    return (int(event_id) if event_id is not None else None), provider, channel, {k: str(v) for k, v in values.items()}


def sample_matches(rule: Rule, sample: Any) -> bool:
    if rule.type == "web":
        if isinstance(sample, dict):
            return rule.search_web(sample.get("path"), sample.get("user_agent"), sample.get("referrer")) is not None
        return rule.search_web(str(sample)) is not None
    if rule.type in ("command", "line"):
        return rule.search(str(sample)) is not None
    if rule.type == "event":
        return rule.matches_record(*_event_sample(sample))
    return False


def run_rule_tests(ruleset: RuleSet, rule_ids: Iterable[str] = ()) -> List[RuleTestResult]:
    wanted = set(rule_ids)
    results = []
    for rule in ruleset.rules.values():
        if rule.type == "correlation" or (wanted and rule.id not in wanted):
            continue
        result = RuleTestResult(rule)
        tests = rule.tests or {}
        for sample in tests.get("match") or []:
            result.examples += 1
            if not sample_matches(rule, sample):
                result.failures.append(f"should match: {clean(sample, 100)}")
        for sample in tests.get("no_match") or []:
            result.examples += 1
            if sample_matches(rule, sample):
                result.failures.append(f"should NOT match: {clean(sample, 100)}")
        if not tests.get("match"):
            result.failures.append("no 'tests: match:' examples (every rule needs at least one)")
        results.append(result)
    return results
