"""Review SLA due dates when a use case enters ``review`` status."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional


def review_due_at_from_start(
    started_at: datetime, sla_days: Optional[int]
) -> Optional[datetime]:
    """Return due datetime if ``sla_days`` is a positive integer, else None."""
    if sla_days is None:
        return None
    try:
        n = int(sla_days)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    return started_at + timedelta(days=n)
