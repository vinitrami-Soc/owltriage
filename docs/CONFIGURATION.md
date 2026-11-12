# Configuration reference

This page covers every setting in OwlTriage. Settings come from four places:

| Level | Where | Use it for |
|---|---|---|
| Command-line flags | `owltriage <command> --flag` | Per-run choices: which logs, thresholds, outputs |
| `.env` file | `./.env` or `--env-file` | Secrets and thresholds for the alert pipeline |
| Environment variables | your shell, cron, CI | Machine-wide behavior: feed cache, animation, colors |
| YAML files | `--rules-dir`, `--feeds-config` | Your own detection rules, overrides, threat feeds |

**Contents:** [hunt](#owltriage-hunt) · [alert](#owltriage-alert) · [rules](#owltriage-rules) ·
[update-feeds](#owltriage-update-feeds) · [.env settings](#env-settings) ·
[environment variables](#environment-variables) · [detection rules](#detection-rules) ·
[threat feeds](#threat-feeds) · [output files](#output-files) · [the owl](#the-owl-animation) ·
[exit codes](#exit-codes) · [recipes](#recipes)

---

## Commands at a glance

```bash
owltriage hunt [LOGS...] [options]   # analyze log files offline
owltriage alert [ALERT_FILE] [opts]  # enrich Wazuh alerts, notify, open cases
owltriage rules {list,test} [IDS]    # inspect and self-test detection rules
owltriage update-feeds [options]     # download free IP threat feeds
owltriage --version
owltriage                            # no arguments: shows the logo and usage
```

From a source checkout without installing, `python main.py ...` and `python -m owltriage ...` behave the same.

---

## `owltriage hunt`

`hunt` reads log files, runs every enabled rule over them and writes the reports.

```bash
owltriage hunt /var/log/auth.log /var/log/nginx/access.log Security.evtx
```

**Input formats** are detected from file content, not the extension, so you can mix them in one run:

| Format | Examples |
|---|---|
| Syslog text | `/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog` |
| Web access logs | Apache / Nginx combined format |
| Windows `.evtx` | `Security.evtx`, `Sysmon/Operational.evtx` (needs the `[evtx]` extra) |
| Windows XML | `wevtutil qe Security /f:xml > security.xml` (UTF-8 or UTF-16) |
| JSON lines | Winlogbeat / Elastic (`winlog.*`) or flat events with `EventID`; non-Windows lines are read as text |

| Flag | Default | What it does |
|---|---|---|
| `LOGS...` | none | Log files to scan. |
| `--demo` | off | Scan the bundled Linux + web + Windows attack samples with the sample blocklist. Ignores threat feeds so results are the same everywhere. |
| `--bad-ips FILE` | none | Your own blocklist: one IP or CIDR per line, text after `#` is the label shown in reports. Repeatable. |
| `--feeds-dir DIR` | `~/.cache/owltriage/feeds` | Where downloaded threat feeds are read from (see [environment variables](#environment-variables)). |
| `--no-feeds` | off | Don't load downloaded threat feeds for this run. |
| `--rules-dir DIR` | none | Extra YAML rules, or overrides of built-in rules by `id`. Repeatable. |
| `--threshold N` | `5` (from the rule) | Failed logins from one IP that count as brute force. Overrides the `auth-brute-force` rule for this run. |
| `--window SECONDS` | `600` (from the rule) | Time window for the threshold. `0` counts across the whole file. |
| `--year YYYY` | current year | Year to assume for syslog timestamps, which have none. Set it when hunting last year's logs. |
| `--allow IP_OR_CIDR` | none | Never write a block rule for this address or range (your VPN, office, scanners you run). Repeatable. |
| `--fail-on SEVERITY` | off | Exit with code `1` if any finding is at least `low`, `medium`, `high` or `critical`. For cron and CI. |
| `--no-anim` | off | No owl animation. It is already off automatically when it can't help ([details](#the-owl-animation)). |
| `--out-dir DIR` | `./owltriage-output` | Where reports are written. Created if missing; files are overwritten each run. Checked before the hunt starts. |
| `--quiet` | off | No terminal report. Files and the exit code only. |
| `--svg FILE` | none | Also save the terminal output as an SVG image (for docs and write-ups). |

---

## `owltriage alert`

`alert` takes Wazuh alerts and looks up the attacker IP and file hash with VirusTotal and AbuseIPDB. When a
score crosses the threshold, it sends a Discord/Slack message and opens a TheHive case.

```bash
owltriage alert --demo                                     # sample alert, fake answers, nothing sent
owltriage alert /var/ossec/logs/alerts/alerts.json --dry-run
```

| Flag | Default | What it does |
|---|---|---|
| `ALERT_FILE` | none | One JSON alert, a JSON list of alerts, or Wazuh's `alerts.json` (one alert per line). |
| `--demo` | off | Use the bundled sample alert with `--mock --dry-run`. |
| `--mock` | off | Answer VirusTotal/AbuseIPDB lookups from built-in fake responses. No keys or internet needed. |
| `--dry-run` | off | Build the Discord, Slack and TheHive payloads and save them to `OUT_DIR/dry_run/` instead of sending. |
| `--no-notify` | off | Never send chat notifications. |
| `--no-case` | off | Never create TheHive cases. |
| `--env-file FILE` | `./.env` | Where to read [settings](#env-settings) from. |
| `--out-dir DIR` | `./owltriage-output` | Where `alert_results.ndjson` and dry-run payloads go. |
| `--quiet` / `--svg FILE` | off | As for `hunt`. |

**What it reads from an alert:**

| Indicator | Alert fields (first match wins for file hashes) |
|---|---|
| IP addresses | `data.srcip`, `data.src_ip`, `data.source.ip`, `data.win.eventdata.ipAddress`, `data.dstip`, plus any IP in `full_log` |
| File hash | `syscheck.sha256_after`, else `sha1_after`, else `md5_after`; also `data.sha256`, `data.sha1`, `data.md5`, `data.hash`, `data.file_hash`; `full_log` if nothing else was found |
| User | `data.srcuser`, `data.dstuser`, `syscheck.uname_after` (used in recommendations) |

Private addresses are never sent to external APIs: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
`100.64.0.0/10`, `fc00::/7`, loopback, link-local, and the agent's own IP.

**Severity and escalation:**

| Severity | When | Notify + open case? |
|---|---|---|
| critical | VirusTotal *and* AbuseIPDB flag it, or VirusTotal malicious count ≥ 4 × threshold | yes |
| high | VirusTotal malicious count > `VT_MALICIOUS_THRESHOLD`, or AbuseIPDB confidence ≥ `ABUSEIPDB_CONFIDENCE_THRESHOLD` | yes |
| medium | some detections, but below both thresholds | no |
| low | nothing found | no |

---

## `owltriage rules`

```bash
owltriage rules list                       # every rule, grouped by type, with ATT&CK ids; disabled ones are marked
owltriage rules list --type event          # only one type: web, command, line, event, correlation
owltriage rules test                       # run every rule's match / no_match examples
owltriage rules test web-xss cmd-lsass-dump
owltriage rules test --rules-dir ./my-rules   # include your own rules
```

`rules test` exits with `1` if any example fails, so it can gate a pull request.

---

## `owltriage update-feeds`

```bash
owltriage update-feeds                      # download every enabled feed
owltriage update-feeds --list               # what is configured, how many entries are cached, how old
owltriage update-feeds --only feodo-tracker # one feed (also works for feeds disabled by default)
owltriage update-feeds --feeds-config my-feeds.yml --feeds-dir /var/lib/owltriage/feeds
```

| Flag | Default | What it does |
|---|---|---|
| `--feeds-dir DIR` | `~/.cache/owltriage/feeds` | Where feeds are cached. Use the same value for `hunt`. |
| `--feeds-config FILE` | built-in list | Your own list of feeds ([format](#threat-feeds)). |
| `--only ID` | all enabled | Update only this feed. Repeatable. |
| `--list` | off | Show the feeds and the cache, download nothing. |
| `--quiet` | off | Print only failures, to stderr. For cron, which mails you only when there is output. |

`update-feeds` exits with `1` only if every feed it tried failed, so one unreachable provider doesn't fail
the run.

---

## `.env` settings

`owltriage alert` reads these settings; `hunt` needs none of them. Copy [`.env.example`](../.env.example) to
`.env` and fill in what you use, since every setting is optional. Git ignores `.env`, so your keys stay out of
commits. Real environment variables take precedence over the file.

| Variable | Default | Meaning |
|---|---|---|
| `VT_API_KEY` | none | VirusTotal API key. Without it (and without `--mock`) VirusTotal lookups are skipped. |
| `ABUSEIPDB_API_KEY` | none | AbuseIPDB API key. Optional. |
| `DISCORD_WEBHOOK_URL` | none | Discord channel webhook. Treat it as a secret: it is never printed, even in errors. |
| `SLACK_WEBHOOK_URL` | none | Slack incoming webhook. Also a secret. |
| `THEHIVE_URL` | none | TheHive 5 base URL, e.g. `https://thehive.example.org`. |
| `THEHIVE_API_KEY` | none | TheHive API key of a user allowed to create cases. |
| `THEHIVE_VERIFY_TLS` | `true` | Set `false` only for a lab TheHive with a self-signed certificate. |
| `VT_MALICIOUS_THRESHOLD` | `5` | Escalate when more than this many VirusTotal engines say malicious. |
| `ABUSEIPDB_CONFIDENCE_THRESHOLD` | `50` | Escalate when the AbuseIPDB confidence score is at least this (0-100). |
| `VT_REQUESTS_PER_MINUTE` | `4` | Client-side rate limit (the free VirusTotal tier allows 4/minute). `0` turns it off for paid keys. |

Chat messages are sent only to the webhooks you set, and a TheHive case is opened only when both
`THEHIVE_URL` and `THEHIVE_API_KEY` are set. A value that should be a number but isn't stops the run
with a clear error.

---

## Environment variables

These apply to every command.

| Variable | Effect |
|---|---|
| `OWLTRIAGE_FEEDS_DIR` | Default feed cache directory (instead of `~/.cache/owltriage/feeds`). |
| `XDG_CACHE_HOME` | Standard cache root; the default feed cache is `$XDG_CACHE_HOME/owltriage/feeds`. |
| `OWLTRIAGE_NO_ANIM` | Any value turns the owl animation off, like `--no-anim` on every run. |
| `CI` | Set by CI systems; the animation stays off. |
| `NO_COLOR` | Any value turns colors off ([no-color.org](https://no-color.org)). |
| `OWLTRIAGE_EVTX_SAMPLES` | Tests only: path to an EVTX-ATTACK-SAMPLES checkout for the real-attack regression tests. |

---

## Detection rules

The 59 built-in rules live in [`owltriage/rules/`](../owltriage/rules/). To add rules or change built-in
ones without forking, put YAML files in a directory and pass it with `--rules-dir`. A rule whose `id` already
exists only changes the keys you set:

```yaml
# my-rules/tuning.yml
- id: auth-brute-force
  threshold: 10          # failed logins...
  window_seconds: 300    # ...within 5 minutes
- id: win-kerberoasting
  enabled: false         # we still run legacy RC4 services
```

```bash
owltriage rules test --rules-dir my-rules        # check it before using it
owltriage hunt logs/*.log --rules-dir my-rules
```

`--threshold` and `--window` override the brute-force values for a single run without a file.

To write new rules (types, fields, examples and the quality checklist), see [docs/RULES.md](RULES.md).

---

## Threat feeds

`update-feeds` downloads plain IP/CIDR lists into the cache; `hunt` loads every cached feed automatically
and warns when the cache is older than 7 days. Built-in feeds:

| id | Enabled by default | Contents |
|---|---|---|
| `ipsum-level3` | yes | IPs on 3 or more public blocklists (daily) |
| `feodo-tracker` | yes | Botnet C2 servers from abuse.ch |
| `blocklist-de-ssh` | yes | IPs reported for SSH attacks in the last 48 hours |
| `et-compromised` | yes | Emerging Threats compromised hosts |
| `firehol-level1` | no | Large, conservative CIDR aggregate |

Each provider has its own terms of use; check them before commercial use.

**Your own feed list** (`--feeds-config my-feeds.yml`) uses the same format:

```yaml
- id: my-intel                         # lowercase-kebab-case, becomes the cache file name
  name: Our internal blocklist
  url: https://intel.example.org/bad-ips.txt
  homepage: https://intel.example.org
  description: IPs our SOC has confirmed as hostile
  enabled: true
```

A feed is a text file with one IP or CIDR per line. Comments starting with `#`, `;` or `//`, and extra
columns after the address (like IPsum's counts), are ignored. For safety, private, reserved and
documentation ranges and anything wider than `/8` (IPv4) or `/16` (IPv6) are dropped, so a broken feed
can't mark your own network as malicious. Downloads are capped at 25 MB per feed.

---

## Output files

Everything goes to `--out-dir` (default `./owltriage-output`).

| File | Written by | Format | Use it for |
|---|---|---|---|
| `triage_report.txt` | `hunt` | text | Reading: the owl's summary, findings, ATT&CK coverage, IP verdicts, block rules |
| `triage_report.json` | `hunt` | JSON | Scripts; includes `summary.stories` and `summary.next_steps` |
| `findings.ndjson` | `hunt` | one JSON per line, ECS-style (`@timestamp`, `rule.*`, `threat.technique.*`, `source.ip`, `log.file.path`) | Elastic, Splunk, Wazuh, Graylog, `jq` |
| `iocs.csv` | `hunt` | CSV: `ip, verdict, max_severity, reasons, mitre, events, failed_logins` | Spreadsheets, firewall and EDR imports |
| `iocs.stix.json` | `hunt` | STIX 2.1 bundle; the same IP keeps the same id across runs | MISP, OpenCTI and other TIPs |
| `attack_layer.json` | `hunt` | MITRE ATT&CK Navigator layer | Heat map of what happened |
| `block_ips.sh` | `hunt`, only if there is something to block | bash, owner-only permissions | Reviewing, then running `sudo bash block_ips.sh` |
| `alert_results.ndjson` | `alert` | one JSON per alert, **appended** | An audit trail of every enrichment |
| `dry_run/*.json` | `alert --dry-run` | the exact Discord, Slack and TheHive payloads | Checking messages before going live |

`block_ips.sh` adds each rule only if it isn't there yet (`iptables -C ... || iptables -A ...`), stops on the
first error, and lists the matching `iptables -D` undo commands at the end. OwlTriage never runs it for you.

---

## The owl animation

On an interactive terminal the owl hops from the logo onto the loading bar, walks with the progress and flies
back when the hunt is done. It adds about 1.5 seconds.

| Situation | What you see |
|---|---|
| Terminal at least 100 × 30 | The full animation |
| Terminal at least 60 columns wide | A one-line `(◉▼◉)` walker, no extra time |
| Smaller terminal, output piped or redirected, `CI` set, `--quiet`, `--svg`, `--no-anim`, `OWLTRIAGE_NO_ANIM` | No animation |

The static logo is printed above the report only on a terminal (and in `--svg` screenshots), never in piped
or redirected output.

---

## Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `hunt` | finished | `--fail-on` matched a finding | bad input: no log file, a missing or unreadable file, a folder instead of files, bad `--allow`, invalid rule file, `--out-dir` not writable |
| `alert` | finished | | bad input: missing, unreadable or invalid alert file, `--out-dir` not writable |
| `rules list` / `rules test` | all good | a rule example failed (`test`) | invalid rule file |
| `update-feeds` | at least one feed updated (or `--list`) | every attempted feed failed | invalid feeds config |

---

## Recipes

**Hunt every 15 minutes and fail loudly on serious findings** (`/etc/cron.d/owltriage`):

```cron
5 3 * * *    root  owltriage update-feeds --feeds-dir /var/lib/owltriage/feeds --quiet
*/15 * * * * root  owltriage hunt /var/log/auth.log /var/log/nginx/access.log --feeds-dir /var/lib/owltriage/feeds --out-dir /var/lib/owltriage/latest --allow 10.0.0.0/8 --fail-on high --quiet || logger -t owltriage "high-severity findings, see /var/lib/owltriage/latest/triage_report.txt"
```

**Gate a CI pipeline on a log bundle:**

```bash
owltriage hunt artifacts/*.log --no-feeds --fail-on high --quiet --out-dir report/
```

**A noisy network:** allow your own scanners and VPN, and require more failures before calling it brute force:

```bash
owltriage hunt auth.log --allow 192.0.2.0/24 --allow 198.51.100.7 --threshold 15 --window 120
```

**An air-gapped analysis box:** run `owltriage update-feeds` on a connected machine, copy
`~/.cache/owltriage/feeds/` across, and point `--feeds-dir` (or `OWLTRIAGE_FEEDS_DIR`) at it.

**Wazuh:** to enrich alerts automatically, follow [docs/WAZUH.md](WAZUH.md).
