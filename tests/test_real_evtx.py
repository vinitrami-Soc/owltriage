"""Regression test against real attack recordings (EVTX-ATTACK-SAMPLES). Skipped unless available:

    git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES /tmp/evtx-samples
    BLUETRIAGE_EVTX_SAMPLES=/tmp/evtx-samples python -m pytest tests/test_real_evtx.py
"""
import os
from pathlib import Path

import pytest

from bluetriage.detectors import analyze
from bluetriage.rules import load_rules

ROOT = Path(os.environ.get("BLUETRIAGE_EVTX_SAMPLES", "/nonexistent"))
pytestmark = pytest.mark.skipif(not ROOT.is_dir(), reason="set BLUETRIAGE_EVTX_SAMPLES to run")
RULES = load_rules() if ROOT.is_dir() else None

EXPECTED = {
    "Credential Access/CA_DCSync_4662.evtx": "win-dcsync",
    "Credential Access/kerberos_pwd_spray_4771.evtx": "auth-brute-force",
    "Credential Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx": "cmd-lsass-dump",
    "Credential Access/CA_hashdump_4663_4656_lsass_access.evtx": "win-lsass-handle",
    "Credential Access/dc_applog_ntdsutil_dfir_325_326_327.evtx": "win-ntds-snapshot",
    "Credential Access/sysmon_10_11_lsass_memdump.evtx": "win-sysmon-lsass-access",
    "Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx": "cmd-lsass-dump",
    "Credential Access/sysmon_rdrleakdiag_lsass_dump.evtx": "cmd-lsass-dump",
    "Defense Evasion/de_portforward_netsh_rdp_sysmon_13_1.evtx": "win-portproxy-registry",
    "Execution/exec_wmic_xsl_internet_sysmon_3_1_11.evtx": "cmd-wmic-remote-xsl",
    "Execution/susp_explorer_exec.evtx": "cmd-powershell-obfuscated-iex",
    "AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx": "cmd-schtasks-create",
}


@pytest.mark.parametrize("sample, rule_id", sorted(EXPECTED.items()))
def test_known_attack_is_detected(sample, rule_id):
    pytest.importorskip("evtx")
    result = analyze([ROOT / sample], ruleset=RULES)
    assert rule_id in {f.rule_id for f in result.findings}


def test_every_sample_parses_without_crashing():
    pytest.importorskip("evtx")
    files = sorted(ROOT.rglob("*.evtx"))
    assert len(files) > 200
    for path in files:
        analyze([path], ruleset=RULES)  # must not raise
