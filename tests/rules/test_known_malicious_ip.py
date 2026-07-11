from rules.known_malicious_ip import detect_known_malicious_ip
from tests.rules.helpers import make_event


CONFIG = {"abuse_score_threshold": 70}


def test_known_malicious_ip_not_triggered() -> None:
    event = make_event()
    result = detect_known_malicious_ip(event, [event], CONFIG, abuse_score=10)
    assert result.flagged is False


def test_known_malicious_ip_triggered() -> None:
    event = make_event()
    result = detect_known_malicious_ip(event, [event], CONFIG, abuse_score=90)
    assert result.flagged is True
