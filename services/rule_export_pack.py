"""Zip export: rules by format + manifest (MITRE, platform, version)."""
from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import yaml

from db.models import RuleImplementation


def _safe_filename(name: str, max_len: int = 64) -> str:
    s = re.sub(r"[^\w\-.]+", "_", name.strip()) or "rule"
    return s[:max_len]


def _ext_for_format(fmt: Optional[str]) -> str:
    f = (fmt or "sigma").lower()
    if f == "sigma":
        return ".yml"
    if f == "splunk":
        return ".spl"
    if f == "kql":
        return ".kql"
    return ".txt"


def build_rules_export_zip(
    rules: List[RuleImplementation],
    use_case_titles: Optional[Dict[int, str]] = None,
) -> bytes:
    """
    Build a zip with:
      manifest.yaml
      sigma/, splunk/, kql/, other/ — one file per rule
    """
    use_case_titles = use_case_titles or {}
    buf = io.BytesIO()
    manifest_rules: List[Dict[str, Any]] = []

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rule in rules:
            fmt = (rule.rule_format or "other").lower()
            if fmt not in ("sigma", "splunk", "kql"):
                folder = "other"
            else:
                folder = fmt
            base = _safe_filename(f"{rule.id}_{rule.rule_name}")
            fn = f"{folder}/{base}{_ext_for_format(fmt)}"
            zf.writestr(fn, rule.rule_text or "")
            uc_id = rule.use_case_id
            manifest_rules.append(
                {
                    "id": rule.id,
                    "rule_name": rule.rule_name,
                    "rule_format": rule.rule_format,
                    "platform": rule.platform,
                    "mitre_technique_id": rule.mitre_technique_id,
                    "mitre_technique_ids": rule.mitre_technique_ids,
                    "version": rule.version or 1,
                    "operational_status": getattr(rule, "operational_status", None),
                    "use_case_id": uc_id,
                    "use_case_title": use_case_titles.get(uc_id) if uc_id else None,
                    "file": fn,
                    "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
                }
            )

        manifest = {
            "export_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "rule_count": len(manifest_rules),
            "rules": manifest_rules,
        }
        zf.writestr(
            "manifest.yaml",
            yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True),
        )

    return buf.getvalue()
