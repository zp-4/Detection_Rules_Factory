"""Review SLA due date helper."""
from datetime import datetime

from services.review_schedule import review_due_at_from_start


def test_no_sla():
    t = datetime(2025, 1, 1)
    assert review_due_at_from_start(t, None) is None
    assert review_due_at_from_start(t, 0) is None


def test_positive_sla():
    t = datetime(2025, 1, 1)
    d = review_due_at_from_start(t, 7)
    assert d == datetime(2025, 1, 8)
