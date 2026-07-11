from rules.bulk_data_access import detect_bulk_data_access
from tests.rules.helpers import make_event


CONFIG = {
    "window_minutes": 15,
    "actions": ["download", "export"],
    "count_threshold": 3,
    "historical_window_days": 7,
    "historical_multiplier": 5.0,
    "minimum_count_for_baseline": 2,
}


def test_bulk_data_access_not_triggered() -> None:
    events = [
        make_event(action="download", seconds_offset=0),
        make_event(action="download", seconds_offset=120),
    ]
    result = detect_bulk_data_access(events[-1], events, CONFIG)
    assert result.flagged is False


def test_bulk_data_access_triggered() -> None:
    events = [
        make_event(action="download", seconds_offset=0),
        make_event(action="download", seconds_offset=120),
        make_event(action="export", seconds_offset=240),
    ]
    result = detect_bulk_data_access(events[-1], events, CONFIG)
    assert result.flagged is True
