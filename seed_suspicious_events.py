from __future__ import annotations

import random
from datetime import datetime, timedelta

from evaluate import DetectionEvaluator, get_context_events
from suspicious_models import ActivityEvent
from suspicious_store import init_detection_db, save_event


def _normal_event(base_time: datetime, index: int) -> ActivityEvent:
    users = [
        ("u-view-1", "viewer"),
        ("u-edit-1", "editor"),
        ("u-admin-1", "admin"),
    ]
    user_id, role = random.choice(users)
    actions = ["login", "view", "edit", "download"] if role != "viewer" else ["login", "view"]
    action = random.choice(actions)
    resource = f"reports/{random.randint(1, 120)}"
    return ActivityEvent(
        user_id=user_id,
        role=role,
        action=action,
        resource=resource,
        resource_type="report",
        ip=f"10.0.0.{random.randint(1, 8)}",
        user_agent="seed-script",
        status_code=200,
        timestamp=base_time + timedelta(seconds=index * 20),
    )


def run_seed() -> None:
    random.seed(11)
    init_detection_db()
    evaluator = DetectionEvaluator()

    base = datetime.utcnow() - timedelta(minutes=20)

    for index in range(150):
        event = _normal_event(base, index)
        save_event(event)
        evaluator.evaluate_event(event, get_context_events())

    suspicious_base = datetime.utcnow() - timedelta(minutes=5)

    for index in range(40):
        event = ActivityEvent(
            user_id="u-scraper",
            role="viewer",
            action="download",
            resource=f"reports/{1000 + index}",
            resource_type="report",
            ip="185.10.10.10",
            user_agent="seed-script",
            status_code=200,
            timestamp=suspicious_base + timedelta(seconds=index * 4),
        )
        save_event(event)
        evaluator.evaluate_event(event, get_context_events())

    for index in range(30):
        event = ActivityEvent(
            user_id="u-prober",
            role="viewer",
            action="view",
            resource=f"admin/hidden/{index}",
            resource_type="endpoint",
            ip="103.24.88.7",
            user_agent="seed-script",
            status_code=404 if index % 2 == 0 else 403,
            timestamp=suspicious_base + timedelta(seconds=index * 3),
        )
        save_event(event)
        evaluator.evaluate_event(event, get_context_events())

    priv_event = ActivityEvent(
        user_id="u-editor-rogue",
        role="editor",
        action="manage_users",
        resource="admin/users",
        resource_type="user",
        ip="172.16.44.9",
        user_agent="seed-script",
        status_code=403,
        timestamp=datetime.utcnow(),
    )
    save_event(priv_event)
    evaluator.evaluate_event(priv_event, get_context_events())

    evaluator.run_scheduled_scan(datetime.utcnow())
    print("Seed complete. Normal and suspicious sequences inserted.")


if __name__ == "__main__":
    run_seed()
