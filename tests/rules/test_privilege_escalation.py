from rules.privilege_escalation import detect_privilege_escalation
from tests.rules.helpers import make_event


CONFIG = {
    "admin_only_actions": ["manage_users", "change_role", "delete_user", "access_admin"],
    "admin_endpoint_keywords": ["/admin", "admin/"],
}


def test_privilege_escalation_not_triggered_for_admin() -> None:
    event = make_event(role="admin", action="manage_users", resource="admin/users")
    result = detect_privilege_escalation(event, [event], CONFIG)
    assert result.flagged is False


def test_privilege_escalation_triggered_for_non_admin() -> None:
    event = make_event(role="viewer", action="manage_users", resource="admin/users")
    result = detect_privilege_escalation(event, [event], CONFIG)
    assert result.flagged is True
