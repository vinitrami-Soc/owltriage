# Contributing

Thanks for helping defenders! The most valuable contributions, in order:

1. **Detection rules** with good examples (see [docs/RULES.md](docs/RULES.md))
2. **False-positive reports** (the *False positive* issue template)
3. Parsers for more log sources, and bug fixes

## Development setup

```bash
git clone https://github.com/vinitrami-Soc/owltriage.git
cd owltriage
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,evtx]"

owltriage hunt --demo          # sanity check
owltriage rules test           # every rule's examples
python -m pytest -q             # full suite (~45 s)
ruff check owltriage tests main.py
```

Optional: run the regression suite against ~280 real attack recordings:

```bash
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES /tmp/evtx-samples
OWLTRIAGE_EVTX_SAMPLES=/tmp/evtx-samples python -m pytest -q tests/test_real_evtx.py
```

## Adding a rule in 5 steps

1. Find the right file in `owltriage/rules/` (`web.yml`, `commands.yml`, `linux.yml`,
   `windows.yml`) or create a new `.yml` file there.
2. Write the rule with a `tests:` block containing `match` **and** `no_match` examples.
3. If you use a new ATT&CK technique, add it to `owltriage/resources/attack.yml` with the
   official name from attack.mitre.org.
4. `owltriage rules test your-rule-id`
5. If the attack is in EVTX-ATTACK-SAMPLES, add the file to `EXPECTED` in
   `tests/test_real_evtx.py` so it stays detected.

## Ground rules

- **Never commit real logs** from your organisation. Sanitize: use the documentation IP
  ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), fake
  hostnames and usernames.
- Treat every log field as attacker-controlled: print it with `Text(clean(...))`, never as
  Rich markup; never pass it to a shell; validate IPs with `ipaddress`.
- New dependencies need a strong reason; the core install should stay small.
- Keep pull requests focused. Update `CHANGELOG.md`.

By contributing you agree that your work is released under the MIT license.
