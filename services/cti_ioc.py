"""IOC parsing and local-only classification (no external enrichment APIs)."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List


_IPV4_RE = re.compile(
    r"(?<![0-9.])((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9.])"
)
# Simplified domain (no full IDNA)
_DOMAIN_RE = re.compile(
    r"(?:^|[\s\"'<>])([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)(?:$|[\s\"'<>])"
)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def _classify_ip(raw: str) -> Dict[str, Any]:
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        return {"type": "ipv4" if "." in raw else "ipv6", "value": raw, "valid": False, "note": "invalid IP"}
    info: Dict[str, Any] = {
        "type": "ipv6" if ip.version == 6 else "ipv4",
        "value": str(ip),
        "valid": True,
        "is_private": ip.is_private,
        "is_multicast": ip.is_multicast,
        "is_reserved": ip.is_reserved if hasattr(ip, "is_reserved") else False,
    }
    if info["is_private"]:
        info["note"] = "private/special-use range — internal context only"
    return info


def _hash_type(s: str) -> str:
    ls = len(s)
    if ls == 32:
        return "md5"
    if ls == 40:
        return "sha1"
    if ls == 64:
        return "sha256"
    return "hash"


def parse_iocs_from_text(text: str) -> List[Dict[str, Any]]:
    """
    Extract IOC-like tokens from pasted text. Conservative heuristics.
    """
    if not text or not text.strip():
        return []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    seen = set()
    results: List[Dict[str, Any]] = []

    def add(entry: Dict[str, Any]) -> None:
        key = (entry["type"], entry["value"].lower())
        if key in seen:
            return
        seen.add(key)
        results.append(entry)

    blob = "\n".join(lines)

    for m in _IPV4_RE.finditer(blob):
        val = m.group(0)
        add(_classify_ip(val))

    for raw in re.findall(r"\S+", blob):
        w = raw.strip("[]<>\"'")
        if ":" in w and w.count(":") >= 2:
            try:
                ipaddress.ip_address(w)
            except ValueError:
                continue
            add(_classify_ip(w))

    for m in _MD5_RE.finditer(blob):
        add({"type": "md5", "value": m.group(0).lower(), "valid": True, "note": ""})
    for m in _SHA1_RE.finditer(blob):
        add({"type": "sha1", "value": m.group(0).lower(), "valid": True, "note": ""})
    for m in _SHA256_RE.finditer(blob):
        add({"type": "sha256", "value": m.group(0).lower(), "valid": True, "note": ""})

    for m in _DOMAIN_RE.finditer(" " + blob + " "):
        dom = m.group(1)
        if "." in dom and len(dom) > 3 and not dom.replace(".", "").isdigit():
            add({"type": "domain", "value": dom.lower(), "valid": True, "note": ""})

    return results
