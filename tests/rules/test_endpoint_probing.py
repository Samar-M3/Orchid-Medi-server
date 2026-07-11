from rules.endpoint_probing import detect_endpoint_probing
from tests.rules.helpers import make_event


CONFIG = {
    "window_minutes": 10,
    "status_codes": [403, 404],
    "threshold": 3,
}


def test_endpoint_probing_not_triggered() -> None:
    events = [
        make_event(status_code=404, seconds_offset=0),
        make_event(status_code=403, seconds_offset=60),
        make_event(status_code=200, seconds_offset=120),
    ]
    result = detect_endpoint_probing(events[-1], events, CONFIG)
    assert result.flagged is False


def test_endpoint_probing_triggered() -> None:
    events = [
        make_event(status_code=404, seconds_offset=0),
        make_event(status_code=403, seconds_offset=60),
        make_event(status_code=404, seconds_offset=120),
    ]
    result = detect_endpoint_probing(events[-1], events, CONFIG)
    assert result.flagged is True
