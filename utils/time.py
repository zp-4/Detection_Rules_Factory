"""Time utilities."""
from datetime import datetime, timezone


def get_current_period() -> str:
    """Get current period in YYYY-MM format."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m")


def parse_period(period_str: str) -> datetime:
    """Parse period string (YYYY-MM) to datetime."""
    return datetime.strptime(period_str, "%Y-%m")


def format_datetime(dt: datetime) -> str:
    """Format datetime for display."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")

