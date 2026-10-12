from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from detectforge.models import Event

ROOT = Path(__file__).resolve().parent.parent
BASE_TIME = datetime(2026, 10, 12, 8, 0, tzinfo=UTC)


def make_event(offset_seconds: float = 0, **data) -> Event:
    return Event(data=data, timestamp=BASE_TIME + timedelta(seconds=offset_seconds))


@pytest.fixture
def root() -> Path:
    return ROOT
