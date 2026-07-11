from rules.scraping_pattern import detect_scraping_pattern
from tests.rules.helpers import make_event


CONFIG = {
    "window_minutes": 10,
    "distinct_resource_threshold": 4,
}


def test_scraping_pattern_not_triggered() -> None:
    events = [
        make_event(resource="reports/1", seconds_offset=0),
        make_event(resource="reports/2", seconds_offset=60),
        make_event(resource="reports/2", seconds_offset=120),
    ]
    result = detect_scraping_pattern(events[-1], events, CONFIG)
    assert result.flagged is False


def test_scraping_pattern_triggered() -> None:
    events = [
        make_event(resource="reports/1", seconds_offset=0),
        make_event(resource="reports/2", seconds_offset=60),
        make_event(resource="reports/3", seconds_offset=120),
        make_event(resource="reports/4", seconds_offset=180),
    ]
    result = detect_scraping_pattern(events[-1], events, CONFIG)
    assert result.flagged is True
