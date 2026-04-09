from services.cti_refs import build_cti_refs_from_entry_ids, normalize_cti_refs


def test_normalize_empty():
    assert normalize_cti_refs(None) == []


def test_normalize_skips_bad():
    assert normalize_cti_refs([{"x": 1}, {"cti_entry_id": "a"}]) == []


def test_build_from_ids():
    r = build_cti_refs_from_entry_ids([1, 2], "note")
    assert len(r) == 2
    assert r[0]["cti_entry_id"] == 1
    assert r[0]["note"] == "note"
