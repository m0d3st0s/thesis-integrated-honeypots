"""Calendar-day boundaries in an explicit IANA timezone."""
import re
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def reporting_zone(name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_+/-]+', name):
        raise ValueError('Expected an IANA timezone such as UTC or Europe/Athens.')
    try:
        return ZoneInfo(name)
    except (ValueError, ZoneInfoNotFoundError) as exc:
        raise ValueError('Timezone unavailable: ' + name + '; check system tzdata.') from exc


def day_window(name, instant=None, previous=True):
    zone = reporting_zone(name)
    instant = instant or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ValueError('Reference time must include a timezone.')
    today = instant.astimezone(zone).date()
    start_date = today - timedelta(days=1) if previous else today
    start = datetime.combine(start_date, time.min, tzinfo=zone)
    finish = datetime.combine(today, time.min, tzinfo=zone) if previous else instant
    return start.astimezone(timezone.utc).isoformat(), finish.astimezone(timezone.utc).isoformat()
