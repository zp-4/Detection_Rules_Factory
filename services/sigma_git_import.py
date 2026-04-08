"""Import Sigma rules from a shallow-cloned Git repository (MVP)."""
from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import yaml
from sqlalchemy.orm import Session

from db.models import RuleImplementation
from db.repo import RuleRepository
from utils.hashing import compute_rule_hash


@dataclass
class ParsedSigma:
    title: str
    rule_text: str
    platform: str
    mitre_technique_ids: List[str]


_TAG_ATTACK = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)


def _guess_platform(data: Dict[str, Any]) -> str:
    ls = data.get("logsource") or {}
    if not isinstance(ls, dict):
        return "Sigma"
    product = str(ls.get("product") or "").lower()
    category = str(ls.get("category") or "").lower()
    combined = f"{product} {category}"
    if "windows" in combined or product == "windows":
        return "Windows"
    if "linux" in combined or "linux" in product:
        return "Linux"
    if "macos" in combined or "darwin" in combined:
        return "macOS"
    if "aws" in combined or "azure" in combined or "gcp" in combined:
        return "Cloud"
    if "okta" in combined or "saas" in combined:
        return "SaaS"
    return "Sigma"


def _extract_mitre_tags(tags: Any) -> List[str]:
    out: List[str] = []
    if not isinstance(tags, list):
        return out
    for t in tags:
        if not isinstance(t, str):
            continue
        m = _TAG_ATTACK.match(t.strip())
        if m:
            tid = m.group(1).upper()
            if not tid.startswith("T"):
                continue
            if tid not in out:
                out.append(tid)
    return out[:5]


def parse_sigma_yaml(content: str, source_hint: str = "") -> Optional[ParsedSigma]:
    """Parse Sigma YAML text; return None if not a valid rule document."""
    try:
        data = yaml.safe_load(content)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if "detection" not in data:
        return None
    title = str(data.get("title") or "").strip() or Path(source_hint).stem or "imported_sigma"
    if len(title) > 240:
        title = title[:237] + "..."
    platform = _guess_platform(data)
    mitre_technique_ids = _extract_mitre_tags(data.get("tags"))
    return ParsedSigma(
        title=title,
        rule_text=content.strip(),
        platform=platform,
        mitre_technique_ids=mitre_technique_ids,
    )


def iter_sigma_files(root: Path, subdir: str = "") -> Iterator[Path]:
    base = (root / subdir.strip("/ ")) if subdir else root
    if not base.exists():
        return
    seen = set()
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in (".yml", ".yaml"):
            continue
        rp = path.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        yield path


def git_shallow_clone(repo_url: str, branch: str, dest: Path, timeout_sec: int = 240) -> Tuple[bool, str]:
    """Clone ``repo_url`` into ``dest`` (depth 1). Returns (ok, message)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--branch",
        branch,
        repo_url,
        str(dest),
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout or "git clone failed")[:2000]
        return True, "ok"
    except FileNotFoundError:
        return False, "git executable not found on PATH"
    except subprocess.TimeoutExpired:
        return False, "git clone timed out"


@dataclass
class ImportStats:
    created: int = 0
    skipped_duplicate: int = 0
    skipped_invalid: int = 0
    errors: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


def import_sigma_from_directory(
    db: Session,
    clone_root: Path,
    subdirectory: str = "",
    use_case_id: Optional[int] = None,
    import_tag: str = "imported/git-sigma",
) -> ImportStats:
    """
    Walk ``clone_root`` / ``subdirectory`` for ``*.yml`` / ``*.yaml``, create rules.
    Skips files that parse to the same ``rule_hash`` as an existing rule.
    """
    stats = ImportStats()
    for path in iter_sigma_files(clone_root, subdirectory):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception as ex:
            stats.errors.append(f"{path}: read error {ex}")
            continue
        parsed = parse_sigma_yaml(text, source_hint=str(path))
        if not parsed:
            stats.skipped_invalid += 1
            continue
        rh = compute_rule_hash(parsed.rule_text, parsed.platform, "sigma")
        existing = RuleRepository.get_by_hash(db, rh)
        if existing:
            stats.skipped_duplicate += 1
            continue
        mitre_id = parsed.mitre_technique_ids[0] if parsed.mitre_technique_ids else None
        mitre_ids_json = parsed.mitre_technique_ids if len(parsed.mitre_technique_ids) > 1 else None
        rule = RuleImplementation(
            use_case_id=use_case_id,
            platform=parsed.platform,
            rule_name=parsed.title,
            rule_text=parsed.rule_text,
            rule_format="sigma",
            rule_hash=rh,
            tags=[import_tag],
            mitre_technique_id=mitre_id,
            mitre_technique_ids=mitre_ids_json,
            enabled=True,
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        stats.created += 1
    return stats


def import_sigma_from_git(
    db: Session,
    repo_url: str,
    branch: str,
    subdirectory: str = "",
    use_case_id: Optional[int] = None,
) -> Tuple[ImportStats, Optional[str]]:
    """
    Shallow-clone ``repo_url`` to a temp directory, import rules, delete temp dir.
    Returns ``(stats, error_message)`` — ``error_message`` is set when clone fails.
    """
    with tempfile.TemporaryDirectory(prefix="sigma_git_") as tmp:
        clone_path = Path(tmp) / "repo"
        ok, msg = git_shallow_clone(repo_url, branch, clone_path)
        if not ok:
            return ImportStats(), msg
        stats = import_sigma_from_directory(
            db, clone_path, subdirectory=subdirectory, use_case_id=use_case_id
        )
        return stats, None
