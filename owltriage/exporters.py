"""Machine-readable outputs for the rest of the blue team stack.

  findings.ndjson     one ECS-style JSON object per finding  -> Elastic, Splunk, Wazuh, Graylog, jq
  iocs.csv            malicious / suspicious IPs              -> spreadsheets, firewalls, EDR lists
  iocs.stix.json      STIX 2.1 bundle of indicators            -> MISP, OpenCTI, any TIP
  attack_layer.json   MITRE ATT&CK Navigator layer             -> https://mitre-attack.github.io/attack-navigator/
"""
from __future__ import annotations

import csv
import ipaddress
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from . import __version__
from .detectors import AnalysisResult
from .rules import RuleSet
from .utils import SEVERITY_RANK

# Deterministic STIX ids: the same IP gets the same indicator id on every run,
# so re-importing into MISP/OpenCTI updates instead of duplicating.
STIX_NAMESPACE = uuid.UUID("6a2f3c1e-8b8d-4c6f-9a51-3f4b2d7e9c10")
IDENTITY_ID = f"identity--{uuid.uuid5(STIX_NAMESPACE, 'owltriage')}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def write_findings_ndjson(result: AnalysisResult, ruleset: RuleSet, path) -> Path:
    path = Path(path)
    generated = _now()
    with path.open("w", encoding="utf-8") as handle:
        for f in result.findings:
            doc = {
                "@timestamp": f.timestamp or generated,
                "event": {"kind": "alert", "module": "owltriage", "severity": SEVERITY_RANK[f.severity],
                          "count": f.count, "created": generated},
                "rule": {"id": f.rule_id, "name": f.rule, "description": f.title},
                "threat": {"framework": "MITRE ATT&CK", "technique": {
                    "id": f.mitre, "name": [ruleset.technique_name(t) for t in f.mitre]}},
                "message": f"{f.title}: {f.detail}",
                "log": {"file": {"path": f.source}, "line": f.line_no},
                "owltriage": {"severity": f.severity, "evidence": f.evidence[:2000], "block": f.block},
            }
            if f.ip:
                doc["source"] = {"ip": f.ip}
            if f.user:
                doc["user"] = {"name": f.user}
            handle.write(json.dumps(doc, ensure_ascii=False) + "\n")
    return path


def _ioc_rows(result: AnalysisResult) -> List[dict]:
    return [row for row in result.ip_verdicts() if row["verdict"] in ("MALICIOUS", "SUSPICIOUS")]


def write_iocs_csv(result: AnalysisResult, path) -> Path:
    path = Path(path)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ip", "verdict", "max_severity", "reasons", "mitre", "events", "failed_logins"])
        for row in _ioc_rows(result):
            writer.writerow([row["ip"], row["verdict"], row["max_severity"], ";".join(row["reasons"]),
                             ";".join(row["mitre"]), row["lines"], row["failed_logins"]])
    return path


def write_stix_bundle(result: AnalysisResult, path) -> Path:
    path = Path(path)
    now = _now()
    objects: List[dict] = [{
        "type": "identity", "spec_version": "2.1", "id": IDENTITY_ID, "created": now, "modified": now,
        "name": "OwlTriage", "identity_class": "system",
    }]
    for row in _ioc_rows(result):
        kind = "ipv6-addr" if ipaddress.ip_address(row["ip"]).version == 6 else "ipv4-addr"
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid5(STIX_NAMESPACE, row['ip'])}",
            "created": now, "modified": now, "valid_from": now, "created_by_ref": IDENTITY_ID,
            "name": f"{row['verdict'].title()} IP {row['ip']}",
            "description": f"Observed by owltriage: {', '.join(row['reasons'])}",
            "indicator_types": ["malicious-activity"] if row["verdict"] == "MALICIOUS" else ["anomalous-activity"],
            "pattern": f"[{kind}:value = '{row['ip']}']", "pattern_type": "stix",
            "confidence": 85 if row["verdict"] == "MALICIOUS" else 50,
            "labels": [f"mitre:{t}" for t in row["mitre"]] or ["owltriage"],
        })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return path


def write_attack_layer(result: AnalysisResult, ruleset: RuleSet, path) -> Path:
    """Upload at https://mitre-attack.github.io/attack-navigator/ -> Open Existing Layer."""
    path = Path(path)
    counts = result.technique_counts()
    rules_by_technique: dict = {}
    for f in result.findings:
        for technique in f.mitre:
            rules_by_technique.setdefault(technique, set()).add(f.title)
    layer = {
        "name": "owltriage findings",
        "versions": {"layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Techniques observed by owltriage {__version__} in: "
                       + ", ".join(Path(f).name for f in result.files),
        "sorting": 3,
        "hideDisabled": False,
        "techniques": [
            {"techniqueID": technique, "score": count, "enabled": True, "showSubtechniques": True,
             "comment": "; ".join(sorted(rules_by_technique.get(technique, ())))[:500]}
            for technique, count in sorted(counts.items())
        ],
        "gradient": {"colors": ["#ffe0a3", "#ff6666"], "minValue": 0, "maxValue": max(counts.values(), default=1)},
        "legendItems": [],
        "metadata": [{"name": "generated_by", "value": f"owltriage {__version__}"}],
    }
    path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    return path
