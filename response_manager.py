from datetime import datetime, timedelta, timezone

from models import Alert


class ResponseManager:
    def __init__(self) -> None:
        self.throttled_until: dict[str, datetime] = {}
        self.isolated_devices: set[str] = set()

    def escalate(self, alert: Alert) -> str:
        if alert.severity == "critical":
            device_id = alert.affected_device
            if device_id:
                self.isolated_devices.add(device_id)
            return "isolate"

        if alert.severity == "high":
            target = alert.affected_user or alert.affected_device
            if target:
                self.throttled_until[target] = datetime.now(timezone.utc) + timedelta(minutes=5)
            return "throttle"

        if alert.severity == "medium":
            return "notify_only"

        return "notify_only"

    def isolate_device(self, device_id: str) -> None:
        self.isolated_devices.add(device_id)

    def release_device(self, device_id: str) -> None:
        self.isolated_devices.discard(device_id)

    def get_status(self, user_or_device: str) -> dict:
        throttled_until = self.throttled_until.get(user_or_device)
        return {
            "id": user_or_device,
            "isolated": user_or_device in self.isolated_devices,
            "throttled": throttled_until is not None and throttled_until > datetime.now(timezone.utc),
            "throttled_until": throttled_until.isoformat() if throttled_until else None,
        }

    def get_devices(self) -> dict:
        now = datetime.now(timezone.utc)
        active_throttles = {
            key: value.isoformat()
            for key, value in self.throttled_until.items()
            if value > now
        }
        return {
            "isolated_devices": sorted(self.isolated_devices),
            "throttled": active_throttles,
        }
