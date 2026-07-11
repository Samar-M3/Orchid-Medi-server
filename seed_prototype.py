#!/usr/bin/env python3
"""
Comprehensive seed script for MediShield prototype demo.
Populates the database with realistic fake data for hackathon demo.
"""

import json
import random
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "medishield.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                affected_user TEXT,
                affected_device TEXT,
                affected_file TEXT,
                reason TEXT,
                status TEXT NOT NULL,
                details TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS access_trends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                department TEXT NOT NULL,
                patient_id TEXT NOT NULL,
                action TEXT NOT NULL,
                record_count INTEGER NOT NULL,
                triggered_rules TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS suspicious_activity (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                ip TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                details TEXT
            )
        """)


def row_to_alert(row):
    details_val = None
    try:
        if row["details"]:
            details_val = json.loads(row["details"])
    except (json.JSONDecodeError, KeyError):
        pass
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "source": row["source"],
        "severity": row["severity"],
        "title": row["title"],
        "description": row["description"],
        "affected_user": row["affected_user"],
        "affected_device": row["affected_device"],
        "affected_file": row["affected_file"],
        "reason": row["reason"],
        "status": row["status"],
        "details": details_val,
    }


USERS = [
    ("dr-asha", "doctor", "cardiology"),
    ("dr-karma", "doctor", "oncology"),
    ("dr-milan", "doctor", "neurology"),
    ("dr-priya", "doctor", "psychiatry"),
    ("nurse-bikash", "nurse", "emergency"),
    ("nurse-sita", "nurse", "icu"),
    ("nurse-kiran", "nurse", "pediatrics"),
    ("nurse-maya", "nurse", "cardiology"),
    ("clerk-sita", "billing_clerk", "billing"),
    ("clerk-rajesh", "billing_clerk", "billing"),
    ("clerk-anita", "billing_clerk", "billing"),
    ("admin-suresh", "admin", "it"),
    ("tech-ramesh", "tech", "radiology"),
    ("tech-sunita", "tech", "lab"),
    ("intern-rahul", "intern", "general"),
    ("intern-pooja", "intern", "emergency"),
]

DEVICES = [
    ("workstation-cardio-01", "dr-asha"),
    ("workstation-onco-01", "dr-karma"),
    ("workstation-neuro-01", "dr-milan"),
    ("workstation-psych-01", "dr-priya"),
    ("mobile-er-01", "nurse-bikash"),
    ("mobile-icu-01", "nurse-sita"),
    ("mobile-peds-01", "nurse-kiran"),
    ("mobile-cardio-02", "nurse-maya"),
    ("billing-terminal-01", "clerk-sita"),
    ("billing-terminal-02", "clerk-rajesh"),
    ("billing-terminal-03", "clerk-anita"),
    ("admin-laptop-01", "admin-suresh"),
    ("radiology-ws-01", "tech-ramesh"),
    ("lab-ws-01", "tech-sunita"),
    ("intern-laptop-01", "intern-rahul"),
    ("intern-laptop-02", "intern-pooja"),
]

SOURCES = ["access_log", "file_monitor", "phi_scan", "override", "suspicious_activity"]
SEVERITIES = ["low", "medium", "high", "critical"]
STATUSES = ["new", "acknowledged", "resolved"]


def seed_access_trends(days=7, events_per_day=50):
    """Seed realistic access log trends with some anomalies."""
    print("Seeding access trends...")
    with get_connection() as conn:
        base = datetime.utcnow() - timedelta(days=days)
        for day in range(days):
            day_base = base + timedelta(days=day)
            for _ in range(events_per_day):
                user_id, role, dept = random.choice(USERS)
                patient_id = f"P-{random.randint(1000, 1150):04d}"
                hour = random.randint(6, 22) if random.random() > 0.1 else random.randint(0, 23)
                minute = random.randint(0, 59)
                ts = day_base.replace(hour=hour, minute=minute, second=random.randint(0, 59))
                
                action = random.choices(
                    ["view", "edit", "download", "print", "export"],
                    weights=[0.5, 0.2, 0.15, 0.1, 0.05]
                )[0]
                record_count = 1
                rules = []
                
                if action == "export" and record_count > 20:
                    rules.append("bulk_export")
                if hour < 6 or hour > 22:
                    rules.append("after_hours")
                if role == "billing_clerk" and dept != "billing":
                    rules.append("dept_mismatch")
                    
                conn.execute("""
                    INSERT INTO access_trends (timestamp, user_id, role, department, patient_id, action, record_count, triggered_rules)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (ts.isoformat(), user_id, role, dept, patient_id, action, record_count, ",".join(rules)))
        
        # Inject suspicious sequences
        suspicious_base = datetime.utcnow() - timedelta(hours=2)
        
        # Bulk export by clerk-sita
        for i in range(35):
            ts = suspicious_base + timedelta(minutes=i * 2)
            conn.execute("""
                INSERT INTO access_trends (timestamp, user_id, role, department, patient_id, action, record_count, triggered_rules)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (ts.isoformat(), "clerk-sita", "billing_clerk", "cardiology", f"P-SENSITIVE-{1000+i:04d}", "export", 1, "bulk_export,after_hours,dept_mismatch"))
        
        # Scraping pattern by intern-rahul
        for i in range(50):
            ts = suspicious_base + timedelta(seconds=i * 15)
            conn.execute("""
                INSERT INTO access_trends (timestamp, user_id, role, department, patient_id, action, record_count, triggered_rules)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (ts.isoformat(), "intern-rahul", "intern", "general", f"P-{1000+i:04d}", "view", 1, "scraping_pattern"))
        
        # Privilege escalation attempt
        for i in range(10):
            ts = suspicious_base + timedelta(minutes=i * 5)
            conn.execute("""
                INSERT INTO access_trends (timestamp, user_id, role, department, patient_id, action, record_count, triggered_rules)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (ts.isoformat(), "nurse-bikash", "nurse", "emergency", "admin/users", "manage_users", 1, "privilege_escalation"))


def seed_alerts(count=80):
    """Seed diverse alerts for dashboard demo."""
    print(f"Seeding {count} alerts...")
    with get_connection() as conn:
        base_time = datetime.utcnow() - timedelta(hours=48)
        
        alert_templates = [
            # Access log alerts
            {
                "source": "access_log",
                "severity": "high",
                "titles": [
                    "Bulk export detected: 35 records in 10 minutes",
                    "After-hours bulk access by billing clerk",
                    "Department mismatch: billing clerk accessing cardiology",
                    "Mass patient record download detected",
                ],
                "users": ["clerk-sita", "clerk-rajesh", "clerk-anita"],
                "devices": ["billing-terminal-01", "billing-terminal-02", "billing-terminal-03"],
                "details_template": lambda u, d, f=None: {"triggered_rules": ["bulk_export", "after_hours", "dept_mismatch"], "record_count": 35, "time_window_minutes": 10}
            },
            {
                "source": "access_log",
                "severity": "medium",
                "titles": [
                    "After-hours access by night shift nurse",
                    "Unusual department access pattern",
                    "Multiple failed login attempts",
                ],
                "users": ["night-nabin", "nurse-bikash", "intern-rahul"],
                "devices": ["mobile-icu-01", "mobile-er-01", "intern-laptop-01"],
                "details_template": lambda u, d, f=None: {"triggered_rules": ["after_hours"], "record_count": 1}
            },
            {
                "source": "access_log",
                "severity": "low",
                "titles": [
                    "Routine after-hours access",
                    "Cross-department view (authorized)",
                ],
                "users": ["dr-asha", "dr-karma", "tech-ramesh"],
                "devices": ["workstation-cardio-01", "workstation-onco-01", "radiology-ws-01"],
                "details_template": lambda u, d, f=None: {"triggered_rules": ["after_hours"], "record_count": 1}
            },
            
            # File monitor alerts
            {
                "source": "file_monitor",
                "severity": "critical",
                "titles": [
                    "HONEYFILE ACCESS: patient_record_P-1008.txt touched",
                    "RANSOMWARE INDICATOR: Mass file encryption detected",
                    "Honeyfile triggered on protected_files/honeyfiles/",
                ],
                "users": ["unknown", "intern-rahul", "clerk-sita"],
                "devices": ["local-filesystem-monitor", "intern-laptop-01", "billing-terminal-01"],
                "files": ["patient_record_P-1008.txt", "patient_record_P-1009.txt", "patient_record_P-1010.txt"],
                "details_template": lambda u, d, f: {"honeypot": True, "file_path": f"protected_files/honeyfiles/{f}", "action": "write", "entropy_score": 0.95}
            },
            {
                "source": "file_monitor",
                "severity": "high",
                "titles": [
                    "Mass file modification: 12 files in 8 seconds",
                    "Entropy spike detected on patient records",
                    "Rapid sequential file access pattern",
                ],
                "users": ["tech-ramesh", "intern-rahul", "nurse-bikash"],
                "devices": ["radiology-ws-01", "intern-laptop-01", "mobile-er-01"],
                "files": [f"patient_record_P-{1000+i:04d}.txt" for i in range(12)],
                "details_template": lambda u, d, f: {"file_count": 12, "time_window_seconds": 8, "entropy_avg": 0.87}
            },
            {
                "source": "file_monitor",
                "severity": "medium",
                "titles": [
                    "Unusual file access outside normal hours",
                    "Access to archived patient records",
                ],
                "users": ["clerk-rajesh", "intern-pooja"],
                "devices": ["billing-terminal-02", "intern-laptop-02"],
                "files": ["archive/P-0900.txt", "archive/P-0901.txt"],
                "details_template": lambda u, d, f: {"file_path": f"protected_files/{f}", "action": "read", "hour": 2}
            },
            
            # PHI scan alerts
            {
                "source": "phi_scan",
                "severity": "high",
                "titles": [
                    "PHI detected in outbound email: SSN + HIV diagnosis",
                    "Outbound scan: Patient citizenship ID + psychiatric notes",
                    "Multiple PHI indicators in outgoing attachment",
                ],
                "users": ["clerk-sita", "dr-priya", "tech-sunita"],
                "devices": ["billing-terminal-01", "workstation-psych-01", "lab-ws-01"],
                "files": ["lab-email.txt", "referral-letter.pdf", "discharge-summary.docx"],
                "details_template": lambda u, d, f: {
                    "matches": [
                        {"type": "SSN", "count": 1},
                        {"type": "HIV_KEYWORD", "count": 1},
                        {"type": "MEDICAL_RECORD_NUM", "count": 2}
                    ],
                    "filename": f,
                    "direction": "outbound"
                }
            },
            {
                "source": "phi_scan",
                "severity": "medium",
                "titles": [
                    "Single PHI indicator in outbound traffic",
                    "Patient ID detected in uploaded file",
                ],
                "users": ["nurse-sita", "clerk-anita"],
                "devices": ["mobile-icu-01", "billing-terminal-03"],
                "files": ["shift-handoff.pdf", "billing-export.csv"],
                "details_template": lambda u, d, f: {
                    "matches": [{"type": "MEDICAL_RECORD_NUM", "count": 1}],
                    "filename": f,
                    "direction": "outbound"
                }
            },
            
            # Suspicious activity alerts
            {
                "source": "suspicious_activity",
                "severity": "high",
                "titles": [
                    "Scraping pattern: 50 report downloads in 12 minutes",
                    "Endpoint probing: 404/403 errors on admin paths",
                    "Bot-like timing: Requests at exact 2-second intervals",
                ],
                "users": ["intern-rahul", "u-prober", "u-scraper"],
                "devices": ["intern-laptop-01", "unknown-device-01", "unknown-device-02"],
                "files": None,
                "details_template": lambda u, d, f=None: {
                    "rule_id": "scraping_pattern",
                    "event_count": 50,
                    "time_window_seconds": 720
                }
            },
            {
                "source": "suspicious_activity",
                "severity": "medium",
                "titles": [
                    "Privilege escalation attempt: editor -> admin",
                    "Known malicious IP detected",
                    "IP traffic spike: 500 requests/minute",
                ],
                "users": ["nurse-bikash", "unknown-user", "unknown-user"],
                "devices": ["mobile-er-01", "185.10.10.10", "103.24.88.7"],
                "files": None,
                "details_template": lambda u, d, f=None: {"rule_id": "privilege_escalation"}
            },
            
            # Override alerts
            {
                "source": "override",
                "severity": "high",
                "titles": [
                    "Break-glass override: Surgeon workstation for emergency procedure",
                    "Break-glass override: ICU monitor released for patient transfer",
                    "Break-glass override: Radiology workstation for critical scan",
                ],
                "users": ["dr-asha", "nurse-sita", "tech-ramesh"],
                "devices": ["workstation-cardio-01", "mobile-icu-01", "radiology-ws-01"],
                "files": None,
                "details_template": lambda u, d, f=None: {
                    "override_reason": d,
                    "released_by": "admin-suresh",
                    "original_action": "isolate"
                }
            },
        ]
        
        for i in range(count):
            template = random.choice(alert_templates)
            ts = base_time + timedelta(minutes=random.randint(0, 48*60))
            
            user = random.choice(template["users"])
            device = random.choice(template["devices"])
            severity = template["severity"]
            title = random.choice(template["titles"])
            
            if template.get("files"):
                file = random.choice(template["files"])
                details = template["details_template"](user, device, file)
                affected_file = file
            else:
                details = template["details_template"](user, device, None)
                affected_file = None
            
            details["auto_generated"] = True
            details["seed_index"] = i
            
            # Weight status toward 'new' and 'acknowledged' for demo
            status = random.choices(STATUSES, weights=[0.5, 0.3, 0.2])[0]
            
            reason = None
            if template["source"] == "override":
                reason = details.get("override_reason")
            elif severity == "critical":
                reason = "Automatic isolation triggered"
            elif severity == "high":
                reason = "Automatic throttle triggered"
            
            alert_id = str(uuid.uuid4())
            conn.execute("""
                INSERT INTO alerts (id, timestamp, source, severity, title, description,
                                   affected_user, affected_device, affected_file, reason, status, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_id,
                ts.isoformat(),
                template["source"],
                severity,
                title,
                f"{title} - Auto-generated demo alert",
                user,
                device,
                affected_file,
                reason,
                status,
                json.dumps(details)
            ))
        
        # Ensure we have some critical alerts for demo
        critical_alerts = [
            {
                "id": str(uuid.uuid4()),
                "timestamp": (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
                "source": "file_monitor",
                "severity": "critical",
                "title": "HONEYFILE ACCESS: patient_record_P-1008.txt touched",
                "description": "Honeypot file accessed - potential ransomware or insider threat",
                "affected_user": "unknown",
                "affected_device": "local-filesystem-monitor",
                "affected_file": "patient_record_P-1008.txt",
                "reason": "Automatic isolation triggered",
                "status": "new",
                "details": json.dumps({"honeypot": True, "file_path": "protected_files/honeyfiles/patient_record_P-1008.txt", "action": "write", "entropy_score": 0.98, "auto_isolated": True})
            },
            {
                "id": str(uuid.uuid4()),
                "timestamp": (datetime.utcnow() - timedelta(minutes=15)).isoformat(),
                "source": "file_monitor",
                "severity": "critical",
                "title": "RANSOMWARE INDICATOR: Mass encryption detected",
                "description": "Entropy spike + rapid file modification pattern matching ransomware",
                "affected_user": "intern-rahul",
                "affected_device": "intern-laptop-01",
                "affected_file": None,
                "reason": "Automatic isolation triggered",
                "status": "acknowledged",
                "details": json.dumps({"file_count": 25, "time_window_seconds": 10, "entropy_avg": 0.96, "auto_isolated": True})
            },
        ]
        
        for alert in critical_alerts:
            conn.execute("""
                INSERT OR IGNORE INTO alerts (id, timestamp, source, severity, title, description,
                                             affected_user, affected_device, affected_file, reason, status, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (alert["id"], alert["timestamp"], alert["source"], alert["severity"],
                  alert["title"], alert["description"], alert["affected_user"],
                  alert["affected_device"], alert["affected_file"], alert["reason"],
                  alert["status"], alert["details"]))


def seed_suspicious_activity(count=30):
    """Seed suspicious activity events."""
    print(f"Seeding {count} suspicious activity events...")
    with get_connection() as conn:
        base = datetime.utcnow() - timedelta(hours=6)
        
        rules = [
            ("scraping_pattern", "high", "Scraping pattern: bulk sequential resource access"),
            ("endpoint_probing", "medium", "Endpoint probing: repeated 404/403 on admin paths"),
            ("bot_like_timing", "medium", "Bot-like timing: requests at fixed intervals"),
            ("privilege_escalation", "high", "Privilege escalation attempt"),
            ("bulk_data_access", "high", "Bulk data access beyond role limits"),
            ("access_outside_role", "medium", "Access outside assigned role/department"),
            ("ip_traffic_spike", "high", "IP traffic spike detected"),
            ("known_malicious_ip", "critical", "Known malicious IP address detected"),
        ]
        
        for i in range(count):
            rule_id, severity, desc = random.choice(rules)
            user_id, role, _ = random.choice(USERS)
            
            if rule_id == "known_malicious_ip":
                user_id = "185.10.10.10"
                role = "unknown"
            elif rule_id == "ip_traffic_spike":
                user_id = "103.24.88.7"
                role = "unknown"
            
            ts = base + timedelta(minutes=random.randint(0, 360))
            
            event_ids = [str(uuid.uuid4()) for _ in range(random.randint(5, 30))]
            details = {
                "rule_id": rule_id,
                "window_seconds": 300,
                "event_count": len(event_ids),
            }
            
            status = random.choices(["open", "reviewed", "dismissed"], weights=[0.6, 0.2, 0.2])[0]
            
            window_start = (ts - timedelta(minutes=5)).isoformat()
            window_end = ts.isoformat()
            
            conn.execute("""
                INSERT INTO suspicious_activity (id, user_id, ip, rule_id, severity, details, event_ids, created_at, status, window_start, window_end)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()),
                user_id,
                f"10.0.0.{random.randint(1, 255)}" if role != "unknown" else user_id,
                rule_id,
                severity,
                json.dumps(details),
                ",".join(event_ids),
                ts.isoformat(),
                status,
                window_start,
                window_end,
            ))


def seed_devices():
    """Seed device isolation/throttle states."""
    print("Seeding device states...")
    with get_connection() as conn:
        # Ensure response_manager tables exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_status (
                device_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                isolated_at TEXT,
                isolated_by TEXT,
                throttle_until TEXT,
                throttle_reason TEXT
            )
        """)
        
        # Some devices with active states for demo
        states = [
            ("local-filesystem-monitor", "isolated", (datetime.utcnow() - timedelta(minutes=5)).isoformat(), "auto", None, None),
            ("intern-laptop-01", "isolated", (datetime.utcnow() - timedelta(minutes=15)).isoformat(), "auto", None, None),
            ("billing-terminal-01", "throttled", None, None, (datetime.utcnow() + timedelta(minutes=5)).isoformat(), "bulk_export"),
            ("mobile-er-01", "normal", None, None, None, None),
        ]
        
        for device_id, status, isolated_at, isolated_by, throttle_until, throttle_reason in states:
            conn.execute("""
                INSERT OR REPLACE INTO device_status (device_id, status, isolated_at, isolated_by, throttle_until, throttle_reason)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (device_id, status, isolated_at, isolated_by, throttle_until, throttle_reason))


def seed_phi_scans():
    """Seed some PHI scan results."""
    print("Seeding PHI scan alerts...")
    # These are already covered in seed_alerts with source="phi_scan"
    pass


def print_summary():
    """Print database summary."""
    with get_connection() as conn:
        print("\n=== DATABASE SUMMARY ===")
        
        # Alerts
        total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_severity = conn.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall()
        by_source = conn.execute("SELECT source, COUNT(*) FROM alerts GROUP BY source").fetchall()
        by_status = conn.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status").fetchall()
        
        print(f"\nTotal Alerts: {total}")
        print("By Severity:")
        for row in by_severity:
            print(f"  {row[0]}: {row[1]}")
        print("By Source:")
        for row in by_source:
            print(f"  {row[0]}: {row[1]}")
        print("By Status:")
        for row in by_status:
            print(f"  {row[0]}: {row[1]}")
        
        # Access trends
        trends = conn.execute("SELECT COUNT(*) FROM access_trends").fetchone()[0]
        print(f"\nAccess Trend Records: {trends}")
        
        # Suspicious activity
        sus = conn.execute("SELECT COUNT(*) FROM suspicious_activity").fetchone()[0]
        print(f"Suspicious Activity Events: {sus}")
        
        # Device states
        devices = conn.execute("SELECT device_id, status FROM device_status").fetchall()
        print("\nDevice States:")
        for d in devices:
            print(f"  {d[0]}: {d[1]}")


def main():
    print("=" * 50)
    print("MediShield Prototype Data Seeder")
    print("=" * 50)
    
    init_schema()
    seed_access_trends(days=7, events_per_day=40)
    seed_alerts(count=100)
    seed_suspicious_activity(count=40)
    seed_devices()
    print_summary()
    
    print("\n✅ Seed complete! Database ready for demo.")
    print(f"Database location: {DB_PATH}")


if __name__ == "__main__":
    main()