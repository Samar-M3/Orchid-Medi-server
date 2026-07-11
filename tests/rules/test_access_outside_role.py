from rules.access_outside_role import detect_access_outside_role
from tests.rules.helpers import make_event


CONFIG = {"severity": "medium"}
ROLE_PERMISSIONS = {
    "viewer": ["login", "view"],
    "editor": ["login", "view", "edit"],
}


def test_access_outside_role_not_triggered() -> None:
    event = make_event(role="viewer", action="view")
    result = detect_access_outside_role(event, [event], CONFIG, ROLE_PERMISSIONS)
    assert result.flagged is False


def test_access_outside_role_triggered() -> None:
    event = make_event(role="viewer", action="edit")
    result = detect_access_outside_role(event, [event], CONFIG, ROLE_PERMISSIONS)
    assert result.flagged is True
