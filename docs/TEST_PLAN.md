# Test plan

## Run it

```bash
pip install -e ".[dev,evtx]"
bluetriage rules test                     # every rule's match / no_match examples
python -m pytest -q                       # full suite (~50 s)
python -m pytest --cov=bluetriage         # with coverage
ruff check bluetriage tests main.py

# regression on ~280 real attack recordings (also a CI job)
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES /tmp/evtx-samples
BLUETRIAGE_EVTX_SAMPLES=/tmp/evtx-samples python -m pytest -q tests/test_real_evtx.py
```

## Strategy

bluetriage reads input written by attackers (logs, event exports, alerts) and its output
drives firewall changes and team notifications. So besides "does it detect attacks", the
suite proves what happens when input is hostile, malformed, huge or from another tool
version, and when an external service misbehaves.

| Layer | Where | What it proves |
|---|---|---|
| Rule self-tests | `bluetriage/rules/*.yml` → `test_rules.py` | Each of the 53 regex/event rules matches its `match` examples and none of its `no_match` look-alikes (160+ examples); every rule has both kinds; ATT&CK IDs exist; invalid rules fail loudly with file + rule id |
| Unit | `test_log_parser.py`, `test_detectors.py`, `test_defense.py`, `test_pipeline.py` | Parsing, brute-force thresholds, compromise logic, web signatures, block-rule planning, API response parsing |
| Windows | `test_windows.py` | wevtutil XML, UTF-16 exports, Winlogbeat/flat JSON, Kerberos 4768/4771 spraying, PowerShell 4104, Sysmon 3 outbound, UTF-16 `-enc` decoding, truncated XML, XML entity refusal, missing optional `evtx` package |
| Time windows & feeds | `test_feeds_exporters.py` | Window boundaries, feed download (size cap, HTTP errors, HTML instead of a list, atomic write), private/huge ranges refused, prefix-index lookups equal a naive scan (Hypothesis) |
| Exports | `test_feeds_exporters.py` | STIX 2.1 validated by the official `stix2` library with deterministic IDs, ATT&CK Navigator layer, ECS-style NDJSON, IOC CSV |
| HTTP integration | `test_http_integration.py` | Real HTTP to a local fake VirusTotal/AbuseIPDB/Discord/Slack/TheHive: headers, auth, 401/429/502, timeouts, partial TheHive failures |
| E2E | `test_cli.py`, `test_block_script.py` | The CLI as a subprocess (exit codes 0/1/2, `--demo`, `--quiet`, `--allow`, `--fail-on`, custom and overriding rules, cached feeds, NDJSON alerts); `block_ips.sh` executed against a fake `iptables` (idempotent, undo, aborts on failure) |
| Security & robustness | `test_security_robustness.py` | ANSI/markup/bidi injection, forged report lines, `@everyone`, Discord/Slack size limits, malformed alerts, Hypothesis fuzzing, ReDoS inputs, no Trojan-Source characters in the repo |
| Real attacks | `test_real_evtx.py` | ~280 EVTX-ATTACK-SAMPLES files parse without crashing; 12 known attacks stay detected |
| Performance | `test_performance.py` | 100k lines well under the limit; memory does not grow with file size |

Python 3.9 (oldest supported) and 3.13 were both run locally with the full suite and the
real-EVTX regression. CI covers 3.9-3.13 on Linux plus Windows and macOS.

## Mutation testing

Bugs are injected into security-critical code one at a time; each must make the suite fail.

| Injected bug | Caught by |
|---|---|
| SSH IP-spoof protection removed | `test_crafted_username_cannot_spoof_the_source_ip` |
| Brute-force threshold off by one | `test_brute_force_needs_threshold` |
| Time window ignored | `test_slow_failures_outside_the_window_are_not_brute_force` |
| Compromise detection removed | `test_demo_hunt_writes_every_output` |
| Base64 printable filter disabled | `test_base64_of_control_bytes_is_ignored` |
| PowerShell UTF-16 decoding removed | `test_windows_attack_story_is_detected` |
| VirusTotal `> 5` becomes `>= 5` | `test_virustotal_threshold_boundary` |
| Un-normalized IP reaches iptables | `test_equivalent_ip_spellings_become_one_canonical_rule` |
| Block script loses `set -e` | `test_script_stops_if_firewall_command_fails` |
| Terminal sanitizer disabled | `test_hostile_log_content_cannot_control_the_terminal` |
| Discord `@everyone` guard removed | `test_mock_pipeline_escalates_malicious_alert` |
| Discord size budget removed | `test_chat_payloads_respect_platform_limits` |
| Webhook error leaks the secret URL | `test_webhook_failure_never_leaks_the_url` |
| Internal IPs sent to VirusTotal | `test_internal_and_agent_ips_are_not_sent_to_apis` |
| CIDR lookup broken | `test_blocklist_matches_single_ips_and_cidr_ranges` |
| Feeds allowed to flag private ranges | `test_cached_feeds_are_loaded_and_reported` |
| defusedxml swapped for stdlib XML | `test_record_parser_refuses_entities_and_dtds` |
| Kerberos 4768/4771 mapping removed | `test_kerberos_spraying_and_success` |
| YAML `safe_load` → unsafe loader | `test_yaml_cannot_execute_code` |
| Regex input bound removed | `test_rule_regexes_have_bounded_input` |
| Unknown rule keys accepted | `test_invalid_rules_are_rejected_with_a_clear_message` |
| Feed download size limit removed | `test_update_feeds_end_to_end` |

**Score: 22/22.** The first run scored 21/22: the bounded-input test used a rule whose own quantifier already limited it, so it could not tell. It now uses an unbounded pattern.

## Bugs found by testing v2 (all fixed)

| Bug | Found by | Impact |
|---|---|---|
| Malformed / truncated XML raised `ParseError` (a `SyntaxError`, not `ValueError`) and aborted the whole hunt | `test_truncated_xml_keeps_parsed_events_and_warns` | One bad export would hide findings from every other file |
| On Python 3.9, pip installs `evtx` 0.8.9, which joins unnamed `<Data>` values into one string; the ntds.dit rule only looked at `Data5` | Real-EVTX regression on 3.9 | Missed ntds.dit theft on 3.9; rules can now match any field with `'*'` |
| Kerberos spraying with unknown usernames (4768 status 0x6) was not counted | Real sample `kerberos_pwd_spray_4771.evtx` | Missed kerbrute-style spraying and the compromise that followed |
| Abbreviated `netsh I p a v` evaded the portproxy command rule | Real sample `de_portforward_netsh_rdp_sysmon_13_1.evtx` | Added a registry-based rule that renaming cannot dodge |
| Obfuscated `IEX(... [char]0x53 ...)` payloads were only "low" | Real samples | New obfuscated-IEX rule (high) |
| Throughput dropped with 4× more rules | Profiling | Cached timestamp parsing: about +20 % |

## Known gaps

- Live services (VirusTotal, AbuseIPDB, Discord, Slack, TheHive, Wazuh) are exercised
  through local fakes that follow their documented APIs, not the real services.
- Real `iptables` is never run (a fake records the calls). Try `block_ips.sh` on a VM first.
- The Dockerfile was not built here (no Docker daemon in the test environment).
- Threat-feed downloads were tested live only for GitHub-hosted feeds (IPsum, FireHOL);
  abuse.ch, blocklist.de and Emerging Threats were unreachable from the test sandbox.
- No benign Windows corpus was available, so false-positive rates on busy Windows estates
  are untested. Please report false positives with the issue template.
