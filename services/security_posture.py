"""Security posture checks for production hardening."""

from __future__ import annotations

import os
from typing import List

from db.session import DATABASE_URL
from services.auth import load_rbac_config
from services.webhooks import load_webhook_config


def is_production_env() -> bool:
    env = str(os.getenv("APP_ENV", "")).strip().lower()
    return env in {"prod", "production"}


def security_findings() -> List[str]:
    findings: List[str] = []
    if not is_production_env():
        return findings

    if str(DATABASE_URL).startswith("sqlite"):
        findings.append("Production mode uses SQLite. Prefer PostgreSQL for multi-user reliability.")

    users = load_rbac_config().get("users", {})
    if isinstance(users, dict):
        weak = [
            u
            for u, row in users.items()
            if isinstance(row, dict) and not str(row.get("password_hash", "")).strip()
        ]
        if weak:
            findings.append(
                "Accounts without password_hash in production: "
                + ", ".join(sorted(str(x) for x in weak)[:10])
            )

    wcfg = load_webhook_config()
    if bool(wcfg.get("enabled")):
        global_secret_env = str(wcfg.get("signing_secret_env", "")).strip()
        endpoints = wcfg.get("endpoints", [])
        if isinstance(endpoints, list):
            unsigned = 0
            for ep in endpoints:
                if not isinstance(ep, dict):
                    continue
                local_env = str(ep.get("signing_secret_env", "")).strip()
                chosen = local_env or global_secret_env
                if not chosen or not str(os.getenv(chosen, "")).strip():
                    unsigned += 1
            if unsigned > 0:
                findings.append(
                    f"{unsigned} webhook endpoint(s) have no signing secret env configured/resolved."
                )
    return findings
