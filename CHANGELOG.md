# Changelog

## 2.1.0 (2026-11-13)

Found by testing on public attack datasets (Hayabusa, Splunk attack_data, OTRF, OSSEC, fail2ban, Loghub).

### Added
- Windows: password spraying with explicit credentials (event 4648, ten or more accounts from one source
  within 10 minutes), Mimikatz by binary name, PsExec / RemCom / PAExec in the Security log (4697 service
  install, 5145 admin-share access), LSASS dumps with `createdump`.
- Web: remote file inclusion (`?page=http://host/file?`), probes for phpMyAdmin and other admin panels,
  and brute force on HTTP logins: 401 responses and rejected POSTs (403) count as failed logins.
- Linux: `useradd` lines from SUSE, and old OpenSSH `Invalid user` / `Illegal user` lines without a port.
- Rule detail templates accept `{FieldA|FieldB}`: the first field that has a value.

### Fixed
- A failed login logged a moment after a later one no longer lowers the brute-force count (five HTTP 401s
  inside 4 seconds were seen as four).

## 2.0.0 (2026-11-12)

Rebuilt for the wider blue team community, and renamed **OwlTriage**.

### Added
- **The owl's summary** at the top of every report: attack stories in plain sentences and numbered
  next steps (accounts to reset, hosts to isolate, IPs to block, persistence to remove); also in the
  text and JSON reports.
- **The owl**: a logo, and a ~1.5 s loading animation on interactive terminals. The owl hops onto
  the loading bar, walks with real progress and flies home. Off for pipes, cron, CI, `--quiet` and
  `--no-anim`; a one-line walker on small terminals.
- Findings carry the host that logged them (syslog hostname, Windows Computer).
- **Detection as code**: 59 YAML rules (web, command, line, event, correlation), every one mapped to
  MITRE ATT&CK and shipped with `match` / `no_match` examples. `owltriage rules list | test`.
  Override or disable any rule from your own directory with `--rules-dir`.
- **Windows support**: `.evtx` (optional `evtx` package), `wevtutil` XML (UTF-8 or UTF-16) and
  Winlogbeat / flat JSON lines. Security 4624/4625/4688/4768/4771/4104, Sysmon 1/3/10/12/13/17/18,
  System 7045 and more.
- New detections: Kerberos password spraying, DCSync, ntds.dit dumping, LSASS access/dumping,
  Kerberoasting, log clearing, privileged group changes, suspicious services, PsExec pipes,
  shadow-copy deletion, Defender tampering, PowerShell encoded commands / download cradles /
  obfuscated IEX, LOLBins (certutil, wmic XSL, netsh portproxy), Log4Shell, Shellshock,
  command injection, secret-file probes, cron / SSH-key persistence, reverse shells.
- **Time-window correlation** for brute force (default 5 failures in 10 minutes).
- **Threat feeds**: `owltriage update-feeds` (IPsum, Feodo Tracker, blocklist.de, ET, FireHOL).
- **Exports**: ECS-style `findings.ndjson`, `iocs.csv`, STIX 2.1 `iocs.stix.json`,
  ATT&CK Navigator `attack_layer.json`; `alert_results.ndjson` audit trail for the alert pipeline.
- `pip install`-able package with a `owltriage` command, `--demo`, `--quiet`, Dockerfile,
  Wazuh custom integration, CI on Linux/Windows/macOS and a regression job on real attack samples.
- **Documentation**: a five-minute quick start in the README, and
  [docs/CONFIGURATION.md](docs/CONFIGURATION.md) with every flag, `.env` setting, environment variable,
  output file and exit code, plus recipes for cron, CI and air-gapped machines.
- `owltriage update-feeds --quiet` for cron: failures only, on stderr.
- `owltriage rules list` groups rules by type and marks disabled ones.

### Changed
- Project renamed OwlTriage (package and command `owltriage`, was `triage`); `SSH_BRUTE_FORCE` → `BRUTE_FORCE` (also RDP/Kerberos).
- Default output directory is `./owltriage-output`; `.env` is read from the current directory.

### Fixed
- Malformed XML no longer aborts a whole hunt (reported as a warning).
- Bad input stops with a one-line explanation and exit code 2 instead of a traceback: an unreadable
  log, a folder instead of log files, an `--out-dir` you can't write to, or an invalid `--allow` value.
- Docker instructions use `--user "$(id -u):$(id -g)"` so the container can write the report into
  your folder.
- Rotated `.gz` logs (`auth.log.2.gz`) are read instead of silently giving zero findings.
- Brute-force windows no longer mix files read newest-first (`auth.log auth.log.1`), which gave false
  brute-force and "login after brute force" findings; a syslog file that crosses New Year keeps
  its order.
- "message repeated N times" lines no longer use memory per repeat (a 244 KB crafted log took 1.6 GB).
- Alert files and blocklists saved with a UTF-8 BOM (Windows PowerShell) are read correctly; alert
  NDJSON lines that are not objects and an `Infinity` rule level no longer crash the pipeline.
- IPv6 addresses in an alert's `full_log` are enriched; `--threshold` below 1 and a negative
  `--window` are refused.
