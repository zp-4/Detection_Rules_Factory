from services.mentions import extract_mention_tokens, resolve_mentions


def test_extract():
    assert "alice" in extract_mention_tokens("hi @alice and @bob")


def test_resolve_known():
    known = {"alice", "bob"}
    assert resolve_mentions("@alice hello", known) == ["alice"]
