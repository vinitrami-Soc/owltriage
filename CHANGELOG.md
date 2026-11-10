# Changelog

## 2.0.0

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

### Changed
- Project renamed OwlTriage (package and command `owltriage`, was `triage`); `SSH_BRUTE_FORCE` → `BRUTE_FORCE` (also RDP/Kerberos).
- Default output directory is `./owltriage-output`; `.env` is read from the current directory.

### Fixed
- Malformed XML no longer aborts a whole hunt (reported as a warning).

## 1.0.0
- First release: offline SSH/web log hunt and VirusTotal / AbuseIPDB / Discord / Slack / TheHive pipeline.
