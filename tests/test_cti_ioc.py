from services.cti_ioc import parse_iocs_from_text


def test_ipv4_and_hash():
    t = "connect 192.168.1.1 evil.com md5 abcdef0123456789abcdef0123456789"
    rows = parse_iocs_from_text(t)
    types = {r["type"] for r in rows}
    assert "ipv4" in types or "domain" in types
    assert any(r["type"] == "md5" for r in rows)


def test_empty():
    assert parse_iocs_from_text("") == []
