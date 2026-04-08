from services.rule_similarity import find_similar_rules, similarity_ratio


def test_identical():
    t = "title: x\nlogsource:\n  product: windows\n"
    assert similarity_ratio(t, t) == 1.0


def test_find_similar():
    cand = [
        (1, "a", "hello world sigma rule"),
        (2, "b", "hello world sigma rules"),
        (3, "c", "completely different content here"),
    ]
    out = find_similar_rules(cand[0][2], 1, cand, min_ratio=0.85)
    assert len(out) >= 1
    assert out[0]["rule_id"] == 2
