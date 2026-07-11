from rules.ip_traffic_spike import detect_ip_traffic_spike
from tests.rules.helpers import make_event


CONFIG = {
    "window_minutes": 5,
    "threshold": 4,
}


def test_ip_traffic_spike_not_triggered() -> None:
    events = [
        make_event(seconds_offset=0),
        make_event(seconds_offset=60),
        make_event(seconds_offset=120),
    ]
    result = detect_ip_traffic_spike(events[-1], events, CONFIG)
    assert result.flagged is False


def test_ip_traffic_spike_triggered() -> None:
    events = [
        make_event(seconds_offset=0),
        make_event(seconds_offset=60),
        make_event(seconds_offset=120),
        make_event(seconds_offset=180),
    ]
    result = detect_ip_traffic_spike(events[-1], events, CONFIG)
    assert result.flagged is True
