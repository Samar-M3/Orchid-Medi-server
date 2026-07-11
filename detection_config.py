from __future__ import annotations

DETECTION_CONFIG = {
    "scheduler": {
        "rescan_interval_seconds": 120,
    },
    "role_permissions": {
        "viewer": ["login", "view"],
        "editor": ["login", "view", "edit", "download", "export"],
        "admin": [
            "login",
            "view",
            "edit",
            "download",
            "export",
            "delete",
            "manage_users",
            "change_role",
            "delete_user",
        ],
    },
    "rules": {
        "bulk_data_access": {
            "window_minutes": 15,
            "actions": ["download", "export"],
            "count_threshold": 30,
            "historical_window_days": 7,
            "historical_multiplier": 5.0,
            "minimum_count_for_baseline": 10,
            "severity": "high",
        },
        "access_outside_role": {
            "severity": "medium",
        },
        "scraping_pattern": {
            "window_minutes": 10,
            "distinct_resource_threshold": 40,
            "severity": "high",
        },
        "privilege_escalation": {
            "admin_only_actions": [
                "manage_users",
                "change_role",
                "delete_user",
                "access_admin",
            ],
            "admin_endpoint_keywords": ["/admin", "admin/"],
            "severity": "high",
        },
        "bot_like_timing": {
            "last_n_actions": 12,
            "min_required_gaps": 6,
            "avg_gap_threshold_seconds": 1.2,
            "stddev_gap_threshold_seconds": 0.2,
            "severity": "medium",
        },
        "endpoint_probing": {
            "window_minutes": 10,
            "status_codes": [403, 404],
            "threshold": 20,
            "severity": "medium",
        },
        "ip_traffic_spike": {
            "window_minutes": 5,
            "threshold": 250,
            "severity": "high",
        },
        "known_malicious_ip": {
            "abuse_score_threshold": 70,
            "cache_ttl_minutes": 60,
            "severity": "high",
        },
    },
}
