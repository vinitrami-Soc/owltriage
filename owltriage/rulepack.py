"""Signed rules packs (`owltriage update-rules`): newer detection rules without a new owltriage release.

A pack is one JSON file:
    {"format": 1, "key_id": "<16 hex>", "payload": "<base64>", "signature": "<base64 Ed25519 of the payload>"}
whose payload is JSON:
    {"version": "2026.11.21", "engine": 1, "created": "...", "source": "<git commit>",
     "files": {"windows.yml": "<YAML>", ...}}

Nothing is installed unless it is signed by a key built into owltriage (TRUSTED_KEYS), is for a
rules engine this owltriage reads, is newer than the rules in use, loads, passes every rule's own
examples and still finds the attacks in the bundled samples. The pack is kept exactly as received
and its signature is checked again on every run; one that fails is ignored for the built-in rules.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

import requests

from . import __version__, ed25519
from .rules import RULES_ENGINE, RuleError, RuleSet, builtin_rules_version, load_rules, run_rule_tests, version_key
from .utils import clean

PACK_FORMAT = 1
DEFAULT_PACK_URL = "https://raw.githubusercontent.com/vinitrami-Soc/owltriage/rules-pack/owltriage-rules.json"
MAX_PACK_BYTES = 5_000_000
MAX_FILES = 100
# key id -> base64 Ed25519 public key of the maintainers' signing key. Packs signed by any other key are refused.
TRUSTED_KEYS: Dict[str, str] = {}
SAMPLES = Path(__file__).resolve().parent / "resources" / "samples"
SAMPLE_LOGS = ("auth.log", "access.log", "windows_security.xml")
_VERSION = re.compile(r"^\d{4}\.\d{2}\.\d{2}(?:\.\d{1,3})?$")
_FILE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}\.yml$")


class PackError(ValueError):
    pass


def default_pack_dir() -> Path:
    if os.environ.get("OWLTRIAGE_RULES_PACK_DIR"):
        return Path(os.environ["OWLTRIAGE_RULES_PACK_DIR"])
    data = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return data / "owltriage" / "rules-pack"


def default_pack_url() -> str:
    return os.environ.get("OWLTRIAGE_RULES_URL") or DEFAULT_PACK_URL


def key_id(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()[:16]


@dataclass
class RulesPack:
    version: str
    engine: int
    created: str
    source: str
    files: Dict[str, str]
    key_id: str
    raw: bytes = field(default=b"", repr=False)


def build_pack(files: Mapping[str, str], version: str, seed: bytes, created: str, source: str = "",
               engine: int = RULES_ENGINE) -> bytes:
    """Sign rule files into a pack (tools/rulepack.py and the tests; owltriage itself only reads packs)."""
    payload = json.dumps({"version": version, "engine": engine, "created": created, "source": source,
                          "files": dict(files)}, ensure_ascii=False, sort_keys=True).encode("utf-8")
    public = ed25519.public_key(seed)
    envelope = {"format": PACK_FORMAT, "key_id": key_id(public),
                "payload": base64.b64encode(payload).decode("ascii"),
                "signature": base64.b64encode(ed25519.sign(seed, payload)).decode("ascii")}
    return (json.dumps(envelope, indent=1) + "\n").encode("ascii")


def _b64(value, what: str) -> bytes:
    if not isinstance(value, str):
        raise PackError(f"not a rules pack: no {what}")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise PackError(f"not a rules pack: {what} is not base64") from None


def read_pack(data: bytes, trusted: Optional[Mapping[str, str]] = None) -> RulesPack:
    """Check a pack's signature and shape. Whether its rules actually work is validate_pack's job."""
    trusted = TRUSTED_KEYS if trusted is None else trusted
    if len(data) > MAX_PACK_BYTES:
        raise PackError(f"pack is larger than {MAX_PACK_BYTES // 1_000_000} MB; refusing")
    try:
        envelope = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        raise PackError("not a rules pack (not JSON)") from None
    if not isinstance(envelope, dict):
        raise PackError("not a rules pack")
    if envelope.get("format") != PACK_FORMAT:
        raise PackError(f"unsupported pack format {clean(envelope.get('format'), 20)}; upgrade owltriage")
    if not trusted:
        raise PackError("this owltriage has no rules-pack signing key built in; upgrade owltriage itself for newer rules")
    kid = envelope.get("key_id")
    if not isinstance(kid, str) or kid not in trusted:
        raise PackError(f"signed with an unknown key ({clean(kid, 40)}); only packs from the owltriage maintainers "
                        "are accepted")
    payload, signature = _b64(envelope.get("payload"), "payload"), _b64(envelope.get("signature"), "signature")
    if not ed25519.verify(base64.b64decode(trusted[kid]), payload, signature):
        raise PackError("signature check failed: the pack was changed after it was signed")

    try:
        body = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        body = None
    if not isinstance(body, dict):
        raise PackError("signed payload is not a JSON object")
    version, engine, files = body.get("version"), body.get("engine"), body.get("files")
    if not isinstance(version, str) or not _VERSION.match(version):
        raise PackError(f"bad pack version {clean(version, 30)}")
    if not isinstance(engine, int) or isinstance(engine, bool) or engine < 1:
        raise PackError(f"bad rules engine {clean(engine, 20)}")
    if not isinstance(files, dict) or not files or len(files) > MAX_FILES:
        raise PackError("pack files must be a mapping of rule file names to YAML")
    for name, text in files.items():
        if not _FILE_NAME.match(name):
            raise PackError(f"bad rule file name {clean(name, 60)!r}")
        if not isinstance(text, str):
            raise PackError(f"{name}: not text")
    return RulesPack(version, engine, clean(body.get("created", ""), 40), clean(body.get("source", ""), 80),
                     dict(files), kid, data)


def validate_pack(pack: RulesPack) -> RuleSet:
    """The rules must load here, pass their own examples and still find the attacks in the bundled samples."""
    if pack.engine > RULES_ENGINE:
        raise PackError(f"rules pack {pack.version} needs a newer owltriage (rules engine {pack.engine}; "
                        f"owltriage {__version__} reads {RULES_ENGINE}): pipx upgrade owltriage")
    try:
        ruleset = load_rules(packaged_texts=pack.files)
    except RuleError as exc:
        raise PackError(f"rules pack {pack.version} does not load with owltriage {__version__} "
                        f"({clean(exc, 200)}); upgrading owltriage may help") from None
    failed = [result for result in run_rule_tests(ruleset) if not result.ok]
    if failed:
        details = "; ".join(f"{r.rule.id}: {r.failures[0]}" for r in failed[:3])
        raise PackError(f"rules pack {pack.version} fails its own rule tests ({details})")
    from .detectors import analyze  # here, not at the top: detectors imports the rules module too
    try:
        result = analyze([SAMPLES / name for name in SAMPLE_LOGS], ruleset=ruleset)
    except Exception as exc:  # noqa: BLE001 - whatever the reason, a pack that breaks a hunt stays out
        raise PackError(f"rules pack {pack.version} crashes on the bundled samples ({type(exc).__name__})") from None
    if not result.findings:
        raise PackError(f"rules pack {pack.version} finds nothing in the bundled attack samples; refusing it")
    return ruleset


def installed_pack(pack_dir: Optional[Path] = None, trusted: Optional[Mapping[str, str]] = None) -> Optional[RulesPack]:
    path = Path(pack_dir or default_pack_dir()) / "current.json"
    return read_pack(path.read_bytes(), trusted) if path.is_file() else None


@dataclass
class ActiveRules:
    ruleset: RuleSet
    version: str
    source: str              # "built-in" or "pack"
    note: str = ""           # why an installed pack is not being used
    pack: Optional[RulesPack] = None

    @property
    def label(self) -> str:
        return f"rules {self.version} ({'signed pack' if self.source == 'pack' else 'built-in'})"


def load_active_rules(extra_dirs: Sequence = (), pack_dir: Optional[Path] = None,
                      trusted: Optional[Mapping[str, str]] = None) -> ActiveRules:
    """The installed pack if it verifies and is newer than the built-in rules, else the built-in rules;
    your own --rules-dir rules go on top either way. Raises RuleError only for problems in those."""
    builtin, _ = builtin_rules_version()
    note = ""
    try:
        pack = installed_pack(pack_dir, trusted)
    except (PackError, OSError) as exc:
        pack, note = None, f"Installed rules pack ignored ({clean(exc, 160)}); using the built-in rules {builtin}."
    if pack is not None and pack.engine > RULES_ENGINE:
        note = f"Installed rules pack {pack.version} needs a newer owltriage; using the built-in rules {builtin}."
    elif pack is not None and version_key(pack.version) > version_key(builtin):
        try:
            return ActiveRules(load_rules(extra_dirs, packaged_texts=pack.files), pack.version, "pack", pack=pack)
        except RuleError as exc:
            try:
                load_rules(packaged_texts=pack.files)
            except RuleError:
                note = f"Installed rules pack {pack.version} ignored ({clean(exc, 160)}); using the built-in rules {builtin}."
            else:
                raise  # the pack is fine; the problem is in your own --rules-dir
    return ActiveRules(load_rules(extra_dirs), builtin, "built-in", note)


@dataclass
class InstallResult:
    status: str              # "installed" or "not-newer"
    before: str              # rules version in use before
    after: str               # rules version in use now
    pack: RulesPack
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    rules: int = 0


def install_pack(data: bytes, pack_dir: Optional[Path] = None,
                 trusted: Optional[Mapping[str, str]] = None) -> InstallResult:
    """Verify and install a pack. Raises PackError (nothing changed) if it is unsigned, tampered or broken."""
    pack_dir = Path(pack_dir or default_pack_dir())
    pack = read_pack(data, trusted)
    active = load_active_rules(pack_dir=pack_dir, trusted=trusted)
    if version_key(pack.version) <= version_key(active.version):  # also refuses replaying an older signed pack
        return InstallResult("not-newer", active.version, active.version, pack)
    ruleset = validate_pack(pack)
    pack_dir.mkdir(parents=True, exist_ok=True)
    current, previous, incoming = pack_dir / "current.json", pack_dir / "previous.json", pack_dir / "incoming.tmp"
    incoming.write_bytes(pack.raw)
    if active.source == "pack":
        os.replace(current, previous)           # kept for `update-rules --rollback`
    elif current.exists():
        current.unlink()                        # an older or broken pack is not worth keeping
    os.replace(incoming, current)               # atomic: a hunt never reads a half-written pack
    before, after = set(active.ruleset.rules), set(ruleset.rules)
    return InstallResult("installed", active.version, pack.version, pack, sorted(after - before),
                         sorted(before - after), len(after))


def rollback(pack_dir: Optional[Path] = None) -> Optional[str]:
    """Back to the previous pack ("pack"), else to the built-in rules ("built-in"); None if nothing to undo."""
    pack_dir = Path(pack_dir or default_pack_dir())
    current, previous = pack_dir / "current.json", pack_dir / "previous.json"
    if previous.exists():
        os.replace(previous, current)
        return "pack"
    if current.exists():
        current.unlink()
        return "built-in"
    return None


def fetch_pack(url: str, session: Optional[requests.Session] = None, timeout: float = 30) -> bytes:
    if not url.startswith("https://"):
        raise PackError("rules packs are only downloaded over https://")
    session = session or requests.Session()
    if hasattr(session, "headers"):
        session.headers["User-Agent"] = f"owltriage/{__version__} (+rules updater)"
    chunks, size = [], 0
    try:
        with session.get(url, timeout=timeout, stream=True) as response:
            if response.status_code == 404:
                raise PackError("no rules pack published at that address yet")
            response.raise_for_status()
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > MAX_PACK_BYTES:
                    raise PackError(f"pack is larger than {MAX_PACK_BYTES // 1_000_000} MB; refusing")
                chunks.append(chunk)
    except requests.RequestException as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        reason = f"HTTP {status}" if status else clean(f"{type(exc).__name__}: {exc}", 120)
        raise PackError(f"download failed: {reason}") from None
    return b"".join(chunks)
