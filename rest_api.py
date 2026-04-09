"""
Optional read-only REST API for external SOC tooling.

Run separately from Streamlit, e.g.:
  uvicorn rest_api:app --host 127.0.0.1 --port 8080

Auth: Authorization: Bearer <token> (see config/rest_api.yaml).
"""
from __future__ import annotations

import os
import secrets
from typing import Any, Dict, List, Optional

import yaml
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.models import RuleImplementation, UseCase
from db.session import SessionLocal

CONFIG_PATH = os.path.join("config", "rest_api.yaml")

security = HTTPBearer(auto_error=False)


def _load_config() -> Dict[str, Any]:
    defaults = {"enabled": False, "tokens": []}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            if isinstance(loaded, dict):
                defaults.update(loaded)
        except Exception:
            pass
    if not isinstance(defaults.get("tokens"), list):
        defaults["tokens"] = []
    return defaults


def _valid_token(token: str) -> bool:
    cfg = _load_config()
    if not cfg.get("enabled"):
        return False
    for entry in cfg.get("tokens") or []:
        if not isinstance(entry, dict):
            continue
        t = entry.get("token")
        if isinstance(t, str) and t and secrets.compare_digest(t, token):
            return True
    return False


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_bearer(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> str:
    if creds is None or (creds.scheme or "").lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer token required")
    if not _valid_token(creds.credentials):
        raise HTTPException(status_code=403, detail="Invalid or disabled token")
    return creds.credentials


app = FastAPI(title="Detection Rules Factory API", version="0.1")


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


class RuleOut(BaseModel):
    id: int
    rule_name: str
    platform: Optional[str]
    rule_format: Optional[str]
    mitre_technique_id: Optional[str]
    enabled: bool
    use_case_id: Optional[int]


class UseCaseOut(BaseModel):
    id: int
    name: str
    status: Optional[str]


@app.get("/api/v1/rules", response_model=List[RuleOut])
def list_rules(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: str = Depends(require_bearer),
):
    cfg = _load_config()
    if not cfg.get("enabled"):
        raise HTTPException(status_code=503, detail="REST API disabled in config/rest_api.yaml")
    lim = max(1, min(limit, 500))
    rows = db.query(RuleImplementation).order_by(RuleImplementation.id.desc()).limit(lim).all()
    return [
        RuleOut(
            id=r.id,
            rule_name=r.rule_name,
            platform=r.platform,
            rule_format=r.rule_format,
            mitre_technique_id=r.mitre_technique_id,
            enabled=bool(r.enabled),
            use_case_id=r.use_case_id,
        )
        for r in rows
    ]


@app.get("/api/v1/rules/{rule_id}", response_model=RuleOut)
def get_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(require_bearer),
):
    cfg = _load_config()
    if not cfg.get("enabled"):
        raise HTTPException(status_code=503, detail="REST API disabled")
    r = db.query(RuleImplementation).filter(RuleImplementation.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")
    return RuleOut(
        id=r.id,
        rule_name=r.rule_name,
        platform=r.platform,
        rule_format=r.rule_format,
        mitre_technique_id=r.mitre_technique_id,
        enabled=bool(r.enabled),
        use_case_id=r.use_case_id,
    )


@app.get("/api/v1/use-cases", response_model=List[UseCaseOut])
def list_use_cases(
    limit: int = 100,
    db: Session = Depends(get_db),
    _: str = Depends(require_bearer),
):
    cfg = _load_config()
    if not cfg.get("enabled"):
        raise HTTPException(status_code=503, detail="REST API disabled")
    lim = max(1, min(limit, 500))
    rows = db.query(UseCase).order_by(UseCase.id.desc()).limit(lim).all()
    return [UseCaseOut(id=u.id, name=u.name, status=u.status) for u in rows]
