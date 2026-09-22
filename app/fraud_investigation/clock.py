from datetime import datetime


def now() -> datetime:
    """Current time as a naive datetime in the bank's local time - the convention for every
    timestamp in the fraud investigation module."""
    return datetime.now().replace(microsecond=0)
