import services.business_tags as btmod


def test_validate_enforce(monkeypatch, tmp_path):
    p = tmp_path / "business_tags.yaml"
    monkeypatch.setattr(btmod, "TAGS_PATH", str(p))
    cfg = {"allowed_tags": ["a", "b"], "enforce_catalogue_tags": True}
    ok, err = btmod.validate_rule_tags(["a", "x"], cfg)
    assert not ok
    ok2, _ = btmod.validate_rule_tags(["a", "b"], cfg)
    assert ok2
