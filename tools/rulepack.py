"""Sign and publish rules packs. Maintainers and the `Rules pack` GitHub workflow run this; users never do.

    python tools/rulepack.py keygen                     # make a signing key (once)
    python tools/rulepack.py pubkey [--require-trusted] # public key for $RULES_SIGNING_KEY
    python tools/rulepack.py build OUT [--source SHA]   # sign owltriage/rules/ with $RULES_SIGNING_KEY
    python tools/rulepack.py verify PACK                # check a pack exactly as `owltriage update-rules` does
    python tools/rulepack.py decide NEW --published OLD # publish=true|false for the workflow

The secret is the base64 of 32 random bytes, kept only in the RULES_SIGNING_KEY secret on GitHub.
Its public key must be listed in TRUSTED_KEYS in owltriage/rulepack.py, or owltriage refuses the packs.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from owltriage import ed25519, rulepack  # noqa: E402
from owltriage.rules import builtin_rules_version, packaged_rule_texts, rules_digest, version_key  # noqa: E402


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def signing_seed() -> bytes:
    secret = os.environ.get("RULES_SIGNING_KEY", "").strip()
    if not secret:
        raise ValueError("set RULES_SIGNING_KEY (base64 of 32 random bytes) to sign packs")
    try:
        seed = base64.b64decode(secret, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("RULES_SIGNING_KEY is not base64") from None
    if len(seed) != 32:
        raise ValueError(f"RULES_SIGNING_KEY must decode to 32 bytes, not {len(seed)}")
    return seed


def cmd_keygen(_args) -> int:
    seed = secrets.token_bytes(32)
    public = ed25519.public_key(seed)
    print("Save the value on the next line as the secret RULES_SIGNING_KEY on GitHub, and nowhere else.")
    print(f"RULES_SIGNING_KEY  {base64.b64encode(seed).decode()}")
    print(f"public key         {rulepack.key_id(public)}: {base64.b64encode(public).decode()}")
    return 0


def cmd_pubkey(args) -> int:
    public = ed25519.public_key(signing_seed())
    kid, encoded = rulepack.key_id(public), base64.b64encode(public).decode()
    print(f"::notice::Rules signing public key {kid}: {encoded}")
    if args.require_trusted and rulepack.TRUSTED_KEYS.get(kid) != encoded:
        print(f'::error::This key is not in TRUSTED_KEYS in owltriage/rulepack.py, so owltriage would refuse its '
              f'packs. Add  "{kid}": "{encoded}",  and push.')
        return 1
    return 0


def cmd_build(args) -> int:
    seed = signing_seed()
    files = packaged_rule_texts()
    version, digest = builtin_rules_version()
    if rules_digest(files) != digest:
        return fail("the rules changed but owltriage/rules/VERSION did not; run pytest tests/test_rules_version.py "
                    "for the new digest and bump the version")
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = rulepack.build_pack(files, version, seed, created=created, source=args.source)
    try:
        rulepack.validate_pack(rulepack.read_pack(data))  # exactly what owltriage will check
    except rulepack.PackError as exc:
        return fail(str(exc))
    Path(args.out).write_bytes(data)
    print(f"built rules pack {version} ({len(files)} files, {len(data):,} bytes) -> {args.out}")
    return 0


def cmd_verify(args) -> int:
    try:
        pack = rulepack.read_pack(Path(args.pack).read_bytes())
        ruleset = rulepack.validate_pack(pack)
    except (OSError, rulepack.PackError) as exc:
        return fail(str(exc))
    print(f"ok: rules pack {pack.version}, {len(ruleset.rules)} rules, signed with key {pack.key_id}")
    return 0


def cmd_decide(args) -> int:
    new = rulepack.read_pack(Path(args.new).read_bytes())
    old = None
    published = Path(args.published) if args.published else None
    if published and published.is_file() and published.stat().st_size:
        try:
            old = rulepack.read_pack(published.read_bytes())
        except rulepack.PackError as exc:  # e.g. signed with a retired key: the new pack replaces it
            print(f"published pack not readable ({exc}); publishing the new one", file=sys.stderr)
    if old is None or version_key(new.version) > version_key(old.version):
        publish = True
    elif new.version == old.version and rules_digest(new.files) == rules_digest(old.files):
        publish = False
    else:
        return fail(f"rules pack {new.version} would replace the published {old.version} with different rules; "
                    "bump the version in owltriage/rules/VERSION")
    print(f"publish={'true' if publish else 'false'}")
    print(f"version={new.version}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="rulepack.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("keygen", help="make a new signing key")
    pub = sub.add_parser("pubkey", help="public key of $RULES_SIGNING_KEY")
    pub.add_argument("--require-trusted", action="store_true", help="fail unless owltriage already trusts it")
    build = sub.add_parser("build", help="sign the built-in rules into a pack")
    build.add_argument("out")
    build.add_argument("--source", default="", help="git commit the rules come from")
    verify = sub.add_parser("verify", help="check a pack like owltriage does")
    verify.add_argument("pack")
    decide = sub.add_parser("decide", help="should the workflow publish this pack?")
    decide.add_argument("new")
    decide.add_argument("--published", help="the pack currently on the rules-pack branch, if any")
    args = parser.parse_args(argv)
    try:
        return {"keygen": cmd_keygen, "pubkey": cmd_pubkey, "build": cmd_build, "verify": cmd_verify,
                "decide": cmd_decide}[args.command](args)
    except ValueError as exc:  # includes PackError
        return fail(str(exc))


if __name__ == "__main__":
    sys.exit(main())
