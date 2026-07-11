from rules.bot_like_timing import detect_bot_like_timing
from tests.rules.helpers import make_event


CONFIG = {
    "last_n_actions": 10,
    "min_required_gaps": 4,
    "avg_gap_threshold_seconds": 1.2,
    "stddev_gap_threshold_seconds": 0.2,
}


def test_bot_like_timing_not_triggered() -> None:
    offsets = [0, 7, 17, 35, 52]
    events = [make_event(seconds_offset=value) for value in offsets]
    result = detect_bot_like_timing(events[-1], events, CONFIG)
    assert result.flagged is False


def test_bot_like_timing_triggered() -> None:
    offsets = [0, 1, 2, 3, 4, 5]
    events = [make_event(seconds_offset=value) for value in offsets]
    result = detect_bot_like_timing(events[-1], events, CONFIG)
    assert result.flagged is True
