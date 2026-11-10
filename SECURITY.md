# Security policy

owltriage parses attacker-controlled input (logs, event exports, alerts), so we take
parser and output-handling bugs seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting
(repository → *Security* → *Report a vulnerability*). Include the version, a minimal
input file that triggers the problem, and what you observed.

You should get a first response within 7 days. Once a fix is released you will be
credited in the CHANGELOG unless you ask otherwise.

## In scope

- Crashes, hangs or excessive memory use on crafted log / XML / EVTX / JSON input
- Regex denial of service (ReDoS) in packaged rules
- Anything that lets log content reach a shell command (`block_ips.sh`), forge report
  lines, control the terminal, or trigger mentions in Discord/Slack
- Leaking API keys or webhook URLs into output, logs or errors

## Design guarantees

- Nothing is executed automatically; firewall commands are only written to a script.
- Only addresses validated by Python's `ipaddress` module are written into that script.
- XML is parsed with `defusedxml` (no DTDs, entity expansion or external entities).
- YAML is loaded with `yaml.safe_load` only.
- Threat feeds cannot list private, reserved or wider-than-/8 ranges.
