# Changelog

## 2.0.0

Rebuilt for the wider blue team community.

### Added
- **Detection as code**: 59 YAML rules (web, command, line, event, correlation), every one mapped to
  MITRE ATT&CK and shipped with `match` / `no_match` examples. `bluetriage rules list | test`.
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
- **Threat feeds**: `bluetriage update-feeds` (IPsum, Feodo Tracker, blocklist.de, ET, FireHOL).
- **Exports**: ECS-style `findings.ndjson`, `iocs.csv`, STIX 2.1 `iocs.stix.json`,
  ATT&CK Navigator `attack_layer.json`; `alert_results.ndjson` audit trail for the alert pipeline.
- `pip install`-able package with a `bluetriage` command, `--demo`, `--quiet`, Dockerfile,
  Wazuh custom integration, CI on Linux/Windows/macOS and a regression job on real attack samples.

### Changed
- Package renamed `triage` → `bluetriage`; `SSH_BRUTE_FORCE` → `BRUTE_FORCE` (also RDP/Kerberos).
- Default output directory is `./bluetriage-output`; `.env` is read from the current directory.

### Fixed
- Malformed XML no longer aborts a whole hunt (reported as a warning).

## 1.0.0
- First release: offline SSH/web log hunt and VirusTotal / AbuseIPDB / Discord / Slack / TheHive pipeline.
