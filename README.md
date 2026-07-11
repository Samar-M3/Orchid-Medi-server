# MediShield Backend

Hackathon MVP backend for local, rule-based hospital security monitoring.

## Run

```powershell
cd medishield-backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload
```

The server runs at `http://127.0.0.1:8000`.

## Endpoints

- `GET /alerts` returns recent stored alerts.
- `GET /alerts?severity=high&status=new` filters recent alerts.
- `POST /alerts/{id}/status` updates an alert to `new`, `acknowledged`, or `resolved`.
- `POST /simulate/access-log` evaluates one access log event.
- `POST /scan/outbound` scans outbound text for PHI indicators.
- `GET /stats/summary` returns 24-hour alert counts by severity and source.
- `GET /devices` returns isolated devices and active throttles.
- `GET /status/{user_or_device}` returns response status for one user or device.
- `POST /devices/{device_id}/isolate` manually isolates a device.
- `POST /devices/{device_id}/release` manually releases a device.
- `POST /override/{device_id}` performs a logged break-glass release.
- `WS /ws/alerts` streams new alerts in real time.

## Admin Audit Panel (Phase 3 — Compliance & Data-Leak Audit Trail)

The frontend serves an admin audit panel at `/admin` (separate from the live operator Dashboard at `/`).  
**Demo password** (MVP mock gate, replace with real RBAC before production): `admin123`

### Admin endpoints (backed by `GET /admin/audit-log`)

| Endpoint | Purpose |
|----------|---------|
| `GET /admin/audit-log` | Paginated, filterable list of all alerts from all engines |
| `GET /admin/audit-log/{id}` | Single alert detail with response action + linked override info |
| `GET /admin/audit-log/export` | CSV download of filtered results (for regulatory reporting) |
| `GET /admin/audit-log/stats` | Aggregate counts (total, by source, by severity, by status, override count) |

**Why this view exists:** The live operator Dashboard focuses on real-time monitoring and immediate response. The Admin Panel is a *compliance-style* view designed for retrospective audit review — searching historical records, filtering by date/source/severity/status, examining the full lifecycle of each alert (detection → automatic response → break-glass override), and exporting evidence for regulators. This directly addresses the gap Nepal's data protection law leaves around mandatory audit logging for healthcare institutions.

## Demo Scenario 1: Insider Misuse

```powershell
curl.exe -X POST http://127.0.0.1:8000/simulate/access-log `
  -H "Content-Type: application/json" `
  -d "{\"timestamp\":\"2026-07-11T23:30:00\",\"user_id\":\"clerk-sita\",\"role\":\"billing_clerk\",\"department\":\"cardiology\",\"patient_id\":\"P-SENSITIVE-001\",\"action\":\"export\",\"record_count\":35}"
```

This triggers time, department mismatch, bulk export, and sensitive-category rules.

## Demo Scenario 2: Honeyfile

Touching a honeyfile immediately creates a critical ransomware alert.

```powershell
Add-Content .\protected_files\honeyfiles\patient_record_P-1008.txt "test"
curl.exe http://127.0.0.1:8000/alerts
```

## Demo Scenario 3: Mass Modification / Entropy

Modify more than 5 protected records within 10 seconds for a high-severity early warning:

```powershell
1..6 | ForEach-Object { Add-Content ".\protected_files\patient_record_P-100$_.txt" "changed $_" }
curl.exe http://127.0.0.1:8000/alerts
```

To simulate encryption-like entropy spikes, overwrite 3 files with random-looking bytes:

```powershell
1..3 | ForEach-Object {
  $bytes = New-Object byte[] 512
  [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
  [System.IO.File]::WriteAllBytes((Resolve-Path ".\protected_files\patient_record_P-100$_.txt"), $bytes)
}
curl.exe http://127.0.0.1:8000/alerts
```

## WebSocket Smoke Test

Install a WebSocket client such as `wscat`, then run:

```powershell
wscat -c ws://127.0.0.1:8000/ws/alerts
```

Trigger one of the demo scenarios in another terminal and the alert JSON will appear in the WebSocket client.

## Phase 2 Demo: PHI Outbound Scanner

One general PHI indicator creates a medium alert. Two or more indicators, or any sensitive psychiatric/HIV term, creates a high alert.

```powershell
curl.exe -X POST http://127.0.0.1:8000/scan/outbound `
  -H "Content-Type: application/json" `
  -d "{\"filename\":\"lab-email.txt\",\"content\":\"Patient citizenship 12-34-56-78901 has diabetes and HIV follow-up notes.\"}"

curl.exe "http://127.0.0.1:8000/alerts?severity=high&status=new"
```

## Phase 2 Demo: Throttle And Isolate

High alerts throttle the affected user or device for 5 minutes. The insider demo above affects `clerk-sita`, so after posting it:

```powershell
curl.exe http://127.0.0.1:8000/status/clerk-sita
curl.exe http://127.0.0.1:8000/devices
```

Critical alerts isolate the affected device. Touching a honeyfile isolates the simulated device `local-filesystem-monitor`:

```powershell
Add-Content .\protected_files\honeyfiles\patient_record_P-1008.txt "test"
curl.exe http://127.0.0.1:8000/devices
```

## Phase 2 Demo: Break-Glass Override

The override releases the device and creates its own high-severity audit alert.

```powershell
curl.exe -X POST http://127.0.0.1:8000/override/local-filesystem-monitor `
  -H "Content-Type: application/json" `
  -d "{\"reason\":\"Surgeon workstation needed for emergency procedure\"}"

curl.exe http://127.0.0.1:8000/devices
curl.exe "http://127.0.0.1:8000/alerts?severity=high&status=new"
```

## Phase 2 Demo: Stats Panel

```powershell
curl.exe http://127.0.0.1:8000/stats/summary
```

## Suspicious Activity Detection (Events -> Rules -> Flags)

The backend now includes a server-side suspicious activity pipeline that ingests activity events and writes flagged results to a dedicated `suspicious_activity` table.

### New API endpoints

- `POST /api/events` ingests one event and runs immediate rules.
- `GET /api/suspicious-activity` returns flagged activity with filters:
  - `status=open|reviewed|dismissed`
  - `severity=low|medium|high`
  - `userId=<id>`
  - `date_from=<ISO datetime>`
  - `date_to=<ISO datetime>`
- `PATCH /api/suspicious-activity/{id}` updates status to `reviewed` or `dismissed`.

### Rule configuration

- Python runtime config: `detection_config.py`
- JS mirror for easier sharing with frontend/docs: `detectionConfig.js`

Tune thresholds and windows in the `DETECTION_CONFIG["rules"]` object. No rule code changes are needed for normal threshold tuning.

### Rule modules

Rules live under `rules/` as pure functions and are unit-tested under `tests/rules/`:

- `bulk_data_access.py`
- `access_outside_role.py`
- `scraping_pattern.py`
- `privilege_escalation.py`
- `bot_like_timing.py`
- `endpoint_probing.py`
- `ip_traffic_spike.py`
- `known_malicious_ip.py`

Note: port scanning detection is intentionally not implemented at app level. It belongs at network/WAF controls (for example Cloudflare WAF or fail2ban).

### Scheduled rescans

The backend runs a scheduled rescan loop (default every 120 seconds) for volume/rate patterns.
Adjust with:

- `DETECTION_CONFIG["scheduler"]["rescan_interval_seconds"]`

### Seed suspicious scenarios

Run the seed script for realistic normal traffic plus injected suspicious sequences:

```powershell
python .\seed_suspicious_events.py
```

### Run unit tests

```powershell
pytest
```

### Add a new rule

1. Add a pure function in `rules/<new_rule>.py` returning `RuleEvaluation`.
2. Add threshold values in `detection_config.py`.
3. Register the rule in `evaluate.py` in either immediate event checks or scheduled scans.
4. Add two unit tests (normal + triggered) under `tests/rules/`.
