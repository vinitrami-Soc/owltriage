# Test Plan: Blue Team Auto-Triage

**Status:** 122 tests passing · 96% line coverage of `triage/` · mutation score 13/13 · ~47,000 log lines/sec

## Run it

```bash
pip install -r requirements-dev.txt
python -m pytest                                  # everything (~25 s)
python -m pytest --cov=triage --cov-report=term-missing
python -m pytest tests/test_log_parser.py tests/test_detectors.py   # fast inner loop (< 1 s)
ruff check main.py triage/ tests/
```

## Strategy

This is a security tool whose input (log lines, alert JSON) is written by attackers. So beyond "does it detect attacks", the plan focuses on what happens when the input is hostile, malformed, huge, or when an external service misbehaves.

```
            E2E (15)            main.py as a subprocess, real files, exit codes
        Integration (11)        real HTTP to a local fake SOC + generated bash run against a fake iptables
     Security / robustness (33) hostile input, malformed alerts, fuzzing, ReDoS, platform limits
          Unit (61)             parser, detectors, defense planner, API response parsing
        Performance (2)         throughput, memory stays flat as files grow
```

## Coverage by area

| Area | Test type | File | What is proven |
|---|---|---|---|
| Log parsing | Unit | `test_log_parser.py` | SSH failed/accepted/invalid-user lines, `message repeated N times`, IPv6 and IPv4-mapped IPs, invalid IPs rejected, triple URL-decoding |
| Detection rules | Unit | `test_detectors.py` | Brute-force threshold boundary, password spraying, compromise-after-brute-force, CIDR blocklist, 8 attack payloads detected, 6 benign URLs **not** flagged, base64 noise ignored |
| Sample attack story | Regression | `test_reports_and_config.py` | Every planted attack in `data/` is found and every legitimate IP stays CLEAN |
| Firewall rules | Unit + Integration | `test_defense.py`, `test_block_script.py` | Only validated, canonical IPs reach `iptables`; allowlist/loopback never blocked; generated script **actually executed** against a fake `iptables`: idempotent on re-run, undo works, aborts on failure |
| Threat intel APIs | Unit + Integration | `test_pipeline.py`, `test_http_integration.py` | VirusTotal/AbuseIPDB parsing, the `> 5` boundary, 401/404/429/502, timeouts, unreachable hosts, rate limiter |
| Notifications and cases | Integration | `test_http_integration.py` | Full live pipeline over HTTP: correct headers, auth, JSON bodies; TheHive 401 and partial observable failure |
| Chat payload limits | Security | `test_security_robustness.py` | Discord 256/1024/4096/6000-char and 25-field limits, Slack 150/2000/3000, with 10,000-char inputs |
| Hostile input | Security | `test_security_robustness.py` | ANSI escapes, OSC links, Rich markup, `\r`, bidi characters cannot reach the terminal or forge report lines; `@everyone` / `<!channel>` neutralized |
| Malformed alerts | Robustness | `test_security_robustness.py` | 9 broken alert shapes (wrong types, missing keys, 200 KB fields) never crash |
| Fuzzing | Property-based (Hypothesis) | `test_security_robustness.py` | 900 random inputs: analyzer never crashes, every block command matches a strict pattern |
| ReDoS | Performance/Security | `test_security_robustness.py` | 6 pathological inputs (up to 200 KB) each finish in < 2 s |
| CLI | E2E | `test_cli.py` | Exit codes 0/1/2, clear error messages and no tracebacks, `--allow`, `--fail-on`, `--svg`, NDJSON, run from any directory |
| Config | Unit | `test_reports_and_config.py` | `.env` loading, environment overrides file, bad numbers give a readable error, secrets hidden from `repr` |
| Source hygiene | Static | `test_security_robustness.py` + ruff | No hidden bidi/zero-width ("Trojan Source") characters anywhere in the repo |

## Mutation testing

Bugs were deliberately injected into security-critical code, one at a time, to prove the suite catches them:

| Injected bug | Caught by |
|---|---|
| SSH IP-spoof protection removed | `test_crafted_username_cannot_spoof_the_source_ip` |
| Brute-force threshold off by one | `test_brute_force_needs_threshold` |
| VirusTotal `> 5` becomes `>= 5` | `test_virustotal_threshold_boundary` |
| Un-normalized IP reaches `iptables` | `test_equivalent_ip_spellings_become_one_canonical_rule` |
| Terminal sanitizer disabled | `test_hostile_log_content_cannot_control_the_terminal` |
| Discord `@everyone` guard removed | `test_mock_pipeline_escalates_malicious_alert` |
| Internal IPs sent to VirusTotal | `test_internal_and_agent_ips_are_not_sent_to_apis` |
| Webhook error leaks the secret URL | `test_webhook_failure_never_leaks_the_url` |
| Base64 printable filter disabled | `test_base64_of_control_bytes_is_ignored` |
| Block script loses `set -e` | `test_script_stops_if_firewall_command_fails` |
| CIDR blocklist matching broken | `test_hunt_writes_every_output` |
| Compromise detection removed | `test_hunt_writes_every_output` |
| Discord size budget removed | `test_chat_payloads_respect_platform_limits` |

The first run scored 10/13; the three survivors exposed missing boundary tests, which were then added.

## Bugs found by this testing (all fixed)

| # | Bug | Impact |
|---|---|---|
| 1 | Discord embed had no total-size budget; long alerts exceeded the 6,000-char / 4,096-char limits | Discord returns HTTP 400 and **the alert is silently lost** |
| 2 | `rule.mitre.id` sent as a string (`"T1105"`) was split into `T`,`1`,`1`,`0`,`5` | Wrong TheHive tags |
| 3 | Slack header block passed alert text through unescaped | `<!channel>`-style text reached Slack |
| 4 | Literal invisible bidi characters (incl. U+202E) in `triage/utils.py` and a test file | GitHub "hidden Unicode" warning; Trojan-Source risk in a security tool |
| 5 | IP parsing repeated for every line | +31% throughput after caching |
| 6 | Invalid blocklist entries were reported without saying which entry | Hard to fix the file |
| 7 | Block script was group-readable (`0o750`) | Now owner-only (`0o700`) |

## Known gaps (not covered)

- **Real third-party services.** VirusTotal, AbuseIPDB, Discord, Slack and TheHive are exercised through a local fake that mimics their documented responses, not the live services. Run `python main.py alert --dry-run` with real keys once before relying on it.
- **Real `iptables`.** The generated script runs against a fake `iptables` (no root needed). Test it on a disposable VM before production.
- **Python versions.** Tests run on Python 3.13. `vermin` reports the code needs ≥ 3.7, and the README promises 3.9+, but no older interpreter was run.
- **Windows.** The block-script tests need `bash` and are skipped without it.
