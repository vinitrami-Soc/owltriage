"""tools/rule_watch.py: the weekly look at CISA KEV, nuclei templates and MITRE ATT&CK."""
import importlib.util
import json
import shutil
import sys
from datetime import date
from pathlib import Path

import pytest
import yaml

from owltriage.rules import builtin_rules_version, load_rules, packaged_rule_texts, rules_digest, run_rule_tests

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("rule_watch", ROOT / "tools" / "rule_watch.py")
watch = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = watch            # dataclasses look their module up here
spec.loader.exec_module(watch)

TODAY = date(2026, 11, 23)


def kev_entry(cve, added, vendor="Acme", product="Gateway", ransomware="Unknown"):
    return {"cveID": cve, "vendorProject": vendor, "product": product, "vulnerabilityName": f"{vendor} {product} RCE",
            "dateAdded": added, "shortDescription": "Remote code execution.", "requiredAction": "Patch.",
            "dueDate": "2026-12-01", "knownRansomwareCampaignUse": ransomware, "forensicTriage": "No",
            "notes": "", "cwes": ["CWE-78"]}


KEV = {"vulnerabilities": [
    kev_entry("CVE-2099-40217", "2026-11-20", "Acme", "Guardrails", ransomware="Known"),   # distinctive path
    kev_entry("CVE-2099-102895", "2026-11-19", "Bolt", "Server"),                           # only GET / and /version
    kev_entry("CVE-2099-116606", "2026-11-18", "Barra", "Mail Gateway"),                    # path also in normal traffic
    kev_entry("CVE-2099-55555", "2026-11-17", "Nobody", "Router"),                          # no template
    kev_entry("CVE-2099-11111", "2026-11-16"),                                              # reported last week
    kev_entry("CVE-2025-00001", "2026-09-01"),                                              # outside the window
]}
NUCLEI_INDEX = "\n".join(json.dumps({"ID": cve, "Info": {}, "file_path": path}) for cve, path in [
    ("CVE-2099-40217", "http/cves/2026/CVE-2099-40217.yaml"),
    ("CVE-2099-102895", "http/cves/2026/CVE-2099-102895.yaml"),
    ("CVE-2099-116606", "http/cves/2026/CVE-2099-116606.yaml"),
    ("CVE-2099-77777", "network/cves/2026/CVE-2099-77777.yaml"),
])
TEMPLATES = {
    "CVE-2099-40217": """id: CVE-2099-40217
http:
  - method: GET
    path:
      - "{{BaseURL}}"
  - method: POST
    path:
      - "{{BaseURL}}/guardrails/test_custom_code"
      - "{{BaseURL}}/guardrails/test_custom_code?run={{randstr}}"
""",
    "CVE-2099-102895": """id: CVE-2099-102895
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
      - |
        GET /version HTTP/1.1
        Host: {{Hostname}}
""",
    "CVE-2099-116606": """id: CVE-2099-116606
http:
  - raw:
      - |
        POST /cgi-mod/index.cgi HTTP/1.1
        Host: {{Hostname}}
""",
}
PREVIOUS = "Last week\n<!-- kev:CVE-2099-11111 -->\n"
BENIGN = "\n".join([
    '10.0.0.1 - - [20/Nov/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
    '10.0.0.2 - - [20/Nov/2026:10:00:01 +0000] "GET /cgi-mod/index.cgi?page=home HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
])


def technique(tid, name, stix_id, revoked=False, deprecated=False):
    return {"type": "attack-pattern", "id": stix_id, "name": name, "revoked": revoked, "x_mitre_deprecated": deprecated,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "stealth"}]}


ATTACK = {"type": "bundle", "objects": [
    technique("T1190", "Exploit Public-Facing Application", "attack-pattern--1"),
    technique("T1222", "File and Directory Permissions Modification", "attack-pattern--2"),
    technique("T1222.002", "Linux and Mac Permissions", "attack-pattern--3"),                  # renamed
    technique("T1070.001", "Clear Windows Event Logs", "attack-pattern--4", revoked=True),      # revoked
    technique("T1685.005", "Clear Windows Event Logs", "attack-pattern--5"),
    technique("T1036.009", "Break Process Trees", "attack-pattern--6", deprecated=True),        # deprecated
    {"type": "relationship", "relationship_type": "revoked-by", "source_ref": "attack-pattern--4",
     "target_ref": "attack-pattern--5"},
]}


ATTACK_YML = """# test copy
T1190: {name: Exploit Public-Facing Application, tactics: [initial-access]}
T1222.002: {name: "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification", tactics: [defense-evasion]}
T1070.001: {name: "Indicator Removal: Clear Windows Event Logs", tactics: [defense-evasion]}
"""


# -- KEV -----------------------------------------------------------------------------------------
def test_new_kev_entries_are_recent_and_not_reported_before():
    entries = watch.load_kev(KEV)
    seen = watch.reported(PREVIOUS)["kev"]
    fresh = watch.new_kev(entries, seen, TODAY)
    assert [e.cve for e in fresh] == ["CVE-2099-40217", "CVE-2099-102895", "CVE-2099-116606", "CVE-2099-55555"]
    assert fresh[0].ransomware == "Known"


def test_only_http_templates_are_indexed():
    index = watch.nuclei_index(NUCLEI_INDEX)
    assert "CVE-2099-40217" in index and "CVE-2099-77777" not in index


# -- nuclei paths ---------------------------------------------------------------------------------
def test_request_paths_from_path_and_raw_templates_keep_only_the_static_part():
    assert watch.request_paths(TEMPLATES["CVE-2099-40217"]) == ["/", "/guardrails/test_custom_code",
                                                                "/guardrails/test_custom_code?run="]
    assert watch.request_paths(TEMPLATES["CVE-2099-102895"]) == ["/", "/version"]
    assert watch.request_paths("- just a list") == [] and watch.request_paths("{bad: [yaml") == []


@pytest.mark.parametrize("path, ok", [
    ("/guardrails/test_custom_code", True), ("/cgi-mod/index.cgi", True),
    ("/wp-content/plugins/acme-forms/upload.php", True),
    ("/", False), ("/version", False), ("/users/sign_in", False), ("/graphql", False), ("/api/v1", False),
    ("/index.php", False), ("/login.php", False),
    ("/v2/users/me", False), ("/api/v4/ci/lint", False), ("/apps/richdocumentscode/proxy.php", True),
])
def test_only_distinctive_paths_become_rules(path, ok):
    assert watch.distinctive(path) is ok


def test_a_candidate_rule_is_valid_and_tests_itself():
    entry = watch.load_kev(KEV)[0]
    rule = watch.candidate_rule(entry, TEMPLATES["CVE-2099-40217"], "http/cves/2026/CVE-2099-40217.yaml")
    assert rule["id"] == "web-cve-2099-40217" and rule["type"] == "web" and rule["mitre"] == ["T1190"]
    assert "Acme Guardrails" in rule["title"] and "block" not in rule              # never auto-block on a guess
    assert rule["severity"] == "high"                                             # KEV says ransomware uses it
    assert rule["tests"]["match"] == ["/guardrails/test_custom_code"]
    ruleset = load_rules(packaged_texts={**packaged_rule_texts(), "web-kev.yml": yaml.safe_dump([rule])})
    result = run_rule_tests(ruleset, ["web-cve-2099-40217"])[0]
    assert result.ok, result.failures
    assert watch.candidate_rule(watch.load_kev(KEV)[1], TEMPLATES["CVE-2099-102895"], "x") is None


# -- ATT&CK ---------------------------------------------------------------------------------------
def test_attack_changes_split_renames_from_revocations():
    ours = {"T1190": {"name": "Exploit Public-Facing Application", "tactics": ["initial-access"]},
            "T1222.002": {"name": "File and Directory Permissions Modification: Linux and Mac File and Directory "
                                   "Permissions Modification", "tactics": ["defense-evasion"]},
            "T1070.001": {"name": "Indicator Removal: Clear Windows Event Logs", "tactics": ["defense-evasion"]},
            "T1036.009": {"name": "Masquerading: Break Process Trees", "tactics": ["defense-evasion"]},
            "T1999": {"name": "Gone", "tactics": []}}
    changes = {c.tid: c for c in watch.attack_changes(ATTACK, ours, {"T1070.001": ["win-log-cleared"]})}
    assert set(changes) == {"T1222.002", "T1070.001", "T1036.009", "T1999"}
    assert changes["T1222.002"].kind == "renamed"
    assert changes["T1222.002"].new_name == "File and Directory Permissions Modification: Linux and Mac Permissions"
    assert (changes["T1070.001"].kind, changes["T1070.001"].replacement) == ("revoked", "T1685.005")
    assert changes["T1070.001"].used_by == ["win-log-cleared"]
    assert changes["T1036.009"].kind == "deprecated" and changes["T1999"].kind == "missing"


# -- versions -------------------------------------------------------------------------------------
@pytest.mark.parametrize("current, expected", [
    ("2026.11.21", "2026.11.23"), ("2026.11.23", "2026.11.23.2"), ("2026.11.23.2", "2026.11.23.3"),
    ("2026.11.30", "2026.11.30.1"),                          # clock behind the last version: still goes up
])
def test_bump_version_always_goes_up(current, expected):
    assert watch.bump_version(current, TODAY) == expected


# -- the whole run ----------------------------------------------------------------------------------
@pytest.fixture
def repo(tmp_path):
    for sub in ("owltriage/rules", "owltriage/resources"):
        (tmp_path / sub).mkdir(parents=True)
    for path in (ROOT / "owltriage" / "rules").iterdir():
        if path.is_file():
            shutil.copy(path, tmp_path / "owltriage" / "rules" / path.name)
    (tmp_path / "owltriage" / "resources" / "attack.yml").write_text(ATTACK_YML, encoding="utf-8")
    data = tmp_path / "data"
    data.mkdir()
    (data / "kev.json").write_text(json.dumps(KEV), encoding="utf-8")
    (data / "nuclei.json").write_text(NUCLEI_INDEX, encoding="utf-8")
    (data / "attack.json").write_text(json.dumps(ATTACK), encoding="utf-8")
    (data / "benign.log").write_text(BENIGN, encoding="utf-8")
    (data / "previous.txt").write_text(PREVIOUS, encoding="utf-8")
    templates = data / "templates"
    templates.mkdir()
    for cve, text in TEMPLATES.items():
        (templates / f"{cve}.yaml").write_text(text, encoding="utf-8")
    return tmp_path


def run(repo, capsys, previous="previous.txt"):
    data = repo / "data"
    code = watch.main(["--repo", str(repo), "--kev", str(data / "kev.json"), "--nuclei-index", str(data / "nuclei.json"),
                       "--attack", str(data / "attack.json"), "--benign", str(data / "benign.log"),
                       "--previous", str(data / previous), "--templates-dir", str(data / "templates"),
                       "--today", TODAY.isoformat(), "--issue", str(data / "issue.md"), "--pr", str(data / "pr.md")])
    outputs = dict(line.split("=", 1) for line in capsys.readouterr().out.split() if "=" in line)
    return code, outputs


def test_a_weekly_run_proposes_rules_fixes_names_and_reports_the_rest(repo, capsys):
    rules_dir = repo / "owltriage" / "rules"
    before = builtin_rules_version(rules_dir)[0]
    users = sorted(r.id for r in load_rules(packaged_dir=rules_dir).rules.values() if "T1070.001" in r.mitre)
    code, outputs = run(repo, capsys)
    assert code == 0 and outputs == {"report": "true", "changes": "true"}

    generated = yaml.safe_load((rules_dir / "web-kev.yml").read_text(encoding="utf-8"))
    ids = [r["id"] for r in generated]
    assert "web-cve-2099-40217" in ids and "web-cve-2099-116606" not in ids  # 116606 matched normal traffic
    ruleset = load_rules(packaged_dir=rules_dir)
    assert all(r.ok for r in run_rule_tests(ruleset)), "every rule, old and new, passes its examples"

    version, digest = builtin_rules_version(rules_dir)
    assert version == watch.bump_version(before, TODAY) and digest == rules_digest(packaged_rule_texts(rules_dir))

    attack = yaml.safe_load((repo / "owltriage/resources/attack.yml").read_text(encoding="utf-8"))
    assert attack["T1222.002"]["name"] == "File and Directory Permissions Modification: Linux and Mac Permissions"
    assert attack["T1222.002"]["tactics"] == ["defense-evasion"]          # only the name changes
    assert "T1070.001" in attack                                           # revocations wait for a human

    issue = (repo / "data" / "issue.md").read_text(encoding="utf-8")
    for text in ("CVE-2099-40217", "CVE-2099-55555", "Known", "web-cve-2099-40217", "T1685.005", *users,
                 "<!-- kev:CVE-2099-40217 -->", "<!-- attack:T1070.001:revoked -->"):
        assert text in issue, text
    assert "CVE-2099-11111" not in issue
    pr = (repo / "data" / "pr.md").read_text(encoding="utf-8")
    assert "web-cve-2099-40217" in pr and "/guardrails/test_custom_code" in pr and "normal traffic" in pr


def test_next_week_nothing_is_reported_twice(repo, capsys):
    run(repo, capsys)
    previous = repo / "data" / "previous.txt"                             # the workflow passes every earlier issue
    previous.write_text(previous.read_text(encoding="utf-8") + (repo / "data" / "issue.md").read_text(encoding="utf-8"),
                        encoding="utf-8")
    code, outputs = run(repo, capsys)
    assert code == 0 and outputs["report"] == "false"
    assert outputs["changes"] == "false"                                   # rule exists, name already fixed


def test_summary_has_a_readable_name_for_generated_rules():
    from owltriage.summary import HUMAN
    assert HUMAN["KNOWN_EXPLOITED_CVE"]


def test_the_weekly_workflow_proposes_but_never_merges():
    text = (ROOT / ".github" / "workflows" / "rule-watch.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    triggers = workflow.get("on") or workflow.get(True)                    # YAML 1.1 reads `on:` as True
    assert triggers["schedule"] and "workflow_dispatch" in triggers
    steps = [s.get("name") for s in workflow["jobs"]["watch"]["steps"]]
    assert steps.index("Test the proposed changes") < steps.index("Propose the changes")
    assert "gh pr merge" not in text and "git push -q origin main" not in text
