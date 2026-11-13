# Test plan

**Status:** 310 tests passing on Python 3.9 and 3.13 (incl. 278 real attack EVTX files) · 163 rule examples · mutation score 25/25

## Run it

```bash
pip install -e ".[dev,evtx]"
owltriage rules test                     # every rule's match / no_match examples
python -m pytest -q                       # full suite (~50 s)
python -m pytest --cov=owltriage         # with coverage
ruff check owltriage tests main.py

# regression on ~280 real attack recordings (also a CI job)
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES /tmp/evtx-samples
OWLTRIAGE_EVTX_SAMPLES=/tmp/evtx-samples python -m pytest -q tests/test_real_evtx.py
```

## Strategy

owltriage reads input written by attackers (logs, event exports, alerts) and its output
drives firewall changes and team notifications. So besides "does it detect attacks", the
suite proves what happens when input is hostile, malformed, huge or from another tool
version, and when an external service misbehaves.

| Layer | Where | What it proves |
|---|---|---|
| Rule self-tests | `owltriage/rules/*.yml` → `test_rules.py` | Each of the 58 regex/event rules matches its `match` examples and none of its `no_match` look-alikes (180+ examples); every rule has both kinds; ATT&CK IDs exist; invalid rules fail loudly with file + rule id |
| Unit | `test_log_parser.py`, `test_detectors.py`, `test_defense.py`, `test_pipeline.py` | Parsing, brute-force thresholds, compromise logic, web signatures, block-rule planning, API response parsing |
| Windows | `test_windows.py` | wevtutil XML, UTF-16 exports, Winlogbeat/flat JSON, Kerberos 4768/4771 spraying, PowerShell 4104, Sysmon 3 outbound, UTF-16 `-enc` decoding, truncated XML, XML entity refusal, missing optional `evtx` package |
| Time windows & feeds | `test_feeds_exporters.py` | Window boundaries, feed download (size cap, HTTP errors, HTML instead of a list, atomic write), private/huge ranges refused, prefix-index lookups equal a naive scan (Hypothesis) |
| Exports | `test_feeds_exporters.py` | STIX 2.1 validated by the official `stix2` library with deterministic IDs, ATT&CK Navigator layer, ECS-style NDJSON, IOC CSV |
| HTTP integration | `test_http_integration.py` | Real HTTP to a local fake VirusTotal/AbuseIPDB/Discord/Slack/TheHive: headers, auth, 401/429/502, timeouts, partial TheHive failures |
| E2E | `test_cli.py`, `test_block_script.py` | The CLI as a subprocess (exit codes 0/1/2, `--demo`, `--quiet`, `--allow`, `--fail-on`, custom and overriding rules, cached feeds, NDJSON alerts); `block_ips.sh` executed against a fake `iptables` (idempotent, undo, aborts on failure) |
| Security & robustness | `test_security_robustness.py` | ANSI/markup/bidi injection, forged report lines, `@everyone`, Discord/Slack size limits, malformed alerts, Hypothesis fuzzing, ReDoS inputs, no Trojan-Source characters in the repo |
| The owl & the summary | `test_banner_summary.py` | Animation only on an interactive terminal (off for pipes, CI, `--quiet`, `--no-anim`, tiny terminals); every frame of the story with a fake clock (branch → bar → walks with progress → looks around when stalled → home), constant frame height, ≤ 1.5 s budget, compact mode adds no time; a **real PTY run** checks the animation and its cost; the owl's summary tells the right stories and next steps; piped output has no colors or big logo |
| Real attacks | `test_real_evtx.py` | ~280 EVTX-ATTACK-SAMPLES files parse without crashing; 12 known attacks stay detected |
| Performance | `test_performance.py` | 100k lines well under the limit; memory does not grow with file size |
| Pre-release review fixes | `test_review_fixes.py` | One regression test per review finding (gzip logs, file order, repeated-message memory, New Year, BOMs, malformed alerts, flag limits, IPv6, gzip progress); Hypothesis proves the brute-force window is exact for ordered events and never over-counts in any order |

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
| Owl animation forced on for pipes | `test_animation_only_on_an_interactive_terminal` |
| Animation budget blown (+2 s on finish) | `test_extra_time_is_about_one_and_a_half_seconds_for_a_fast_hunt` |
| Owl's summary drops compromised accounts | `test_summary_tells_the_attack_stories` |

**Score: 25/25.** The first run scored 21/22: the bounded-input test used a rule whose own quantifier already limited it, so it could not tell. It now uses an unbounded pattern.

## Bugs found by testing v2 (all fixed)

| Bug | Found by | Impact |
|---|---|---|
| Malformed / truncated XML raised `ParseError` (a `SyntaxError`, not `ValueError`) and aborted the whole hunt | `test_truncated_xml_keeps_parsed_events_and_warns` | One bad export would hide findings from every other file |
| On Python 3.9, pip installs `evtx` 0.8.9, which joins unnamed `<Data>` values into one string; the ntds.dit rule only looked at `Data5` | Real-EVTX regression on 3.9 | Missed ntds.dit theft on 3.9; rules can now match any field with `'*'` |
| Kerberos spraying with unknown usernames (4768 status 0x6) was not counted | Real sample `kerberos_pwd_spray_4771.evtx` | Missed kerbrute-style spraying and the compromise that followed |
| Abbreviated `netsh I p a v` evaded the portproxy command rule | Real sample `de_portforward_netsh_rdp_sysmon_13_1.evtx` | Added a registry-based rule that renaming cannot dodge |
| Obfuscated `IEX(... [char]0x53 ...)` payloads were only "low" | Real samples | New obfuscated-IEX rule (high) |
| Throughput dropped with 4× more rules | Profiling | Cached timestamp parsing: about +20 % |
| Docker: `docker run -v "$PWD:/work"` crashed with a PermissionError traceback for normal users | Building and running the image | Docs use `--user`; unreadable logs and a read-only `--out-dir` exit 2 with a hint |

## Pre-release round (v2.0.0)

A last round before the release, using a risk-based gap analysis, a full code review and
long dynamic runs instead of more line coverage.

| Method | Result |
|---|---|
| Branch coverage, CLI subprocesses included | 95 % (cli.py 91 %); the remaining lines are defensive branches |
| Input-class probing (BOM, CRLF, `.gz`, empty files, odd flag values, non-object alerts) | 6 defects, all fixed |
| Code review of the whole package | 10 findings, all reproduced first and fixed test-first |
| Long fuzzing: 6 targets x 4,000 Hypothesis examples (hostile log lines, random bytes as `.gz`/EVTX/XML/JSON, arbitrary alert JSON through the whole pipeline) | No crash, no invalid IP ever extracted |
| Mutation testing, 45 injected bugs (25 earlier + 20 for this round's fixes) | 45/45 caught by a test assertion. Three needed work first: gzipped JSON lines had no test (added), the repeated-message memory test took 15 min to fail on the mutant (now 1 min, same limit), and the unreadable-log mutant is only caught as a non-root user, as in CI |
| All 278 EVTX-ATTACK-SAMPLES and the demo, before vs after the fixes | Identical findings (82 and 32) |
| Throughput before vs after (same machine, same load) | Text about 6 % slower (25.8k vs 24.3k lines/s on 200k mixed lines), EVTX unchanged, same findings. On an idle CPU: 26.7k text lines/s, 9.2k EVTX records/s |
| Real PTY run on a 18 MB log packed into `.gz` | Full animation; the bar climbs smoothly instead of jumping to 98 % |

| Bug | Found by | Impact |
|---|---|---|
| Rotated `.gz` logs gave 0 findings and exit 0 | Input-class probing | `hunt /var/log/auth.log*` silently skipped older days |
| Files read newest-first shared one brute-force window | Code review | False brute force and false "login after brute force" |
| "message repeated N times" stored N timestamps | Code review | A 244 KB crafted log took 1.6 GB (now 35 MB) |
| Year-less syslog crossing New Year went back a year | Code review | Brute force across midnight missed |
| UTF-8 BOM in alert files and blocklists | Input-class probing | Windows-saved files rejected, or the first blocklist IP lost |
| Non-object NDJSON alerts, `Infinity` rule level | Input-class probing, code review | Traceback instead of a message |
| `--threshold 0`, negative `--window` | Input-class probing | Silently clamped |
| IPv6 only in `full_log` | Code review | Never enriched |
| Progress bar used the compressed size of `.gz` logs | PTY run | Bar stuck at 98 % for most of the hunt |

## Validation on public datasets (v2.1.0)

The detections were run on logs the tool had never seen: 15 Windows recordings from the
[Hayabusa sample EVTX](https://github.com/Yamato-Security/hayabusa-sample-evtx) set (DeepBlueCLI,
Yamato Security, EVTX-to-MITRE-Attack), 15 files from [Splunk attack_data](https://github.com/splunk/attack_data)
(checksums verified against their Git LFS pointers), 4 [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets)
recordings, sections of the [OSSEC log samples](https://github.com/ossec/ossec-docs), access logs from
[fail2ban's test files](https://github.com/fail2ban/fail2ban), the [Loghub](https://github.com/logpai/loghub) OpenSSH
sample and 10,000 ordinary requests from [Elastic's apache_logs](https://github.com/elastic/examples). Each file
was labelled with the attack it records before the run.

| Platform | Caught before | Caught after | Notes |
|---|---|---|---|
| Windows (attack recordings the tool can read) | 15 of 19 | **19 of 19** | Added: spraying with explicit credentials (4648), Mimikatz by binary name, PsExec in the Security log (4697, 5145), createdump LSASS dumps |
| Linux | 4 of 5 | **5 of 5** | Added: SUSE `useradd`, old OpenSSH lines without a port |
| Web | 3 of 5 | **6 of 8** | Added: remote file inclusion, admin-panel probes, brute force on HTTP logins. Missed: 4 POSTs (under the threshold of 5) and an OSSEC sample with an anonymised, reordered line |
| Ordinary traffic (10 files, incl. 10,000 web requests) | no high alerts | **no new alerts** | 2 low notes on base64 in URLs, as before |

Mutation testing on the new code injected 11 bugs; 10 are caught, and the 11th (a non-greedy username
in the old-OpenSSH pattern) changes nothing, because the end-of-line anchor already pins the IP.

The same comparison on all 278 EVTX-ATTACK-SAMPLES files, the OTRF recordings, the Loghub sample
and the demo only **added** findings (Mimikatz in two recordings, RemCom and PsExec share access),
each checked against the file it came from; no earlier finding disappeared.

Not covered yet: Splunk's own key=value export of Windows events (3 files), AS-REP roasting,
PowerShell v2 downgrade, BITS jobs, `doas`, Linux discovery commands, spam bots and malformed requests.
The AIT Log Data Set (Zenodo) and SecRepo could not be downloaded from the test environment.

| Bug found by the datasets | Impact | Fix |
|---|---|---|
| Five 401s inside 4 seconds, one logged a moment late, peaked at 4 | Missed brute force on fail2ban's traefik sample | The brute-force count is the whole current window, which only ever holds failures within the window of each other |
| Mimikatz detail read `???C:\...\mimikatz.exe (??)` | Unreadable finding | Templates take `{ProcessName\|Image\|SourceImage}`: the first field present |
| The new 4648 spray check rescanned its window for every event | 30,000 events in one window took 54 s, 100,000 about 10 minutes (found while reviewing the change) | A running count per source: 100,000 events in 0.3 s; `test_a_flood_of_explicit_credential_logons_stays_linear` |

## Known gaps

- Live services (VirusTotal, AbuseIPDB, Discord, Slack, TheHive, Wazuh) are exercised
  through local fakes that follow their documented APIs, not the real services.
- Real `iptables` is never run (a fake records the calls). Try `block_ips.sh` on a VM first.
- The Docker image is built and run by hand, not in CI. Checked: `hunt --demo`, hunting your own logs and
  `alert --demo` as a non-root host user with `--user`; a root-only log and a read-only folder fail with
  a clear message (exit 2) instead of a traceback.
- Threat-feed downloads were tested live only for GitHub-hosted feeds (IPsum, FireHOL);
  abuse.ch, blocklist.de and Emerging Threats were unreachable from the test sandbox.
- No benign Windows corpus was available, so false-positive rates on busy Windows estates
  are untested. Please report false positives with the issue template.
