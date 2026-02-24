# AiTelDa Backend API

AI-Native Data Audit & Optimization Engine — REST API

Built with Flask · SQLite · PyJWT · ReportLab

---

## Quick Start

```bash
# 1. Copy environment config
cp .env.example .env

# 2. Edit .env — at minimum, set a strong SECRET_KEY

# 3. Run the server
python -m app

# Server starts at http://localhost:5000
```

The SQLite database (`aitelda.db`) and PDF output directory (`dispute_pdfs/`) are
created automatically on first run.

---

## Architecture

```
aitelda_backend/
├── app/
│   ├── __init__.py          # Flask app factory, blueprint registration
│   ├── models/
│   │   └── schema.py        # SQLite schema + init_db()
│   ├── routes/
│   │   ├── auth.py          # Auth endpoints (register/login/refresh/logout/me)
│   │   ├── devices.py       # Device registration & management
│   │   ├── ingest.py        # Packet-Sentry data ingestion pipeline
│   │   ├── disputes.py      # Dispute-Forge case management
│   │   └── analytics.py     # Dashboard analytics & baselines
│   ├── services/
│   │   ├── variance.py      # V = |D_device - D_telco| engine + baseline EMA
│   │   └── pdf_generator.py # ReportLab forensic PDF generation
│   └── utils/
│       ├── auth.py          # JWT token helpers + @jwt_required decorator
│       ├── validators.py    # Input validation helpers
│       └── responses.py     # Standardised API response wrappers
├── tests/
│   └── test_api.py          # Full test suite (32 tests)
├── dispute_pdfs/            # Generated PDF reports (auto-created)
├── requirements.txt
├── .env.example
└── README.md
```

---

## Database Schema

| Table | Purpose |
|-------|---------|
| `users` | Consumer accounts |
| `devices` | Registered Android/iOS devices |
| `packet_sessions` | Monitoring sessions from Packet-Sentry |
| `usage_snapshots` | Per-app byte breakdown within a session |
| `telco_reports` | Telco deductions from SMS/USSD parsing |
| `anomaly_events` | Aura-Brain flagged anomalies |
| `dispute_cases` | Dispute-Forge cases with status tracking |
| `app_baselines` | 7-day EMA rolling baseline per device+app |
| `refresh_tokens` | JWT refresh token store (hashed) |

---

## API Reference

### Authentication

All protected endpoints require:
```
Authorization: Bearer <access_token>
```

#### `POST /api/auth/register`
```json
{
  "email": "user@example.ng",
  "password": "SecurePass1",
  "full_name": "Amaka Obi",
  "phone": "+2348012345678"
}
```
Returns `access_token` + `refresh_token`.

Password rules: ≥8 chars, 1 uppercase, 1 number.

#### `POST /api/auth/login`
```json
{ "email": "user@example.ng", "password": "SecurePass1" }
```

#### `POST /api/auth/refresh`
```json
{ "refresh_token": "<token>" }
```
Rotates the refresh token (old token is revoked).

#### `POST /api/auth/logout`
```json
{ "refresh_token": "<token>" }
```

#### `GET /api/auth/me`
Returns current user profile and device count.

---

### Devices

#### `POST /api/devices/register`
```json
{
  "device_id": "ANDROID-UUID-HERE",
  "platform": "android",
  "model": "Samsung Galaxy A54",
  "os_version": "Android 14",
  "app_version": "1.0.0",
  "telco": "mtn"
}
```
Valid platforms: `android`, `ios`
Valid telcos: `mtn`, `airtel`, `glo`, `9mobile`

#### `GET /api/devices`
List all registered devices.

#### `GET /api/devices/<device_id>`
Device detail with aggregate stats (sessions, bytes monitored, anomaly count, dispute count).

#### `DELETE /api/devices/<device_id>`
Deregister a device (cascades to all related data).

#### `PATCH /api/devices/<device_id>/heartbeat`
Update last-seen timestamp.

---

### Data Ingestion (Packet-Sentry → Backend)

#### `POST /api/ingest/session`
Open a monitoring session:
```json
{
  "device_id": "DEVICE-001",
  "session_start": "2024-10-15T02:00:00Z",
  "screen_state": "off"
}
```

#### `POST /api/ingest/session/<session_id>/end`
```json
{
  "session_end": "2024-10-15T06:00:00Z",
  "total_bytes_tx": 5000000,
  "total_bytes_rx": 60000000
}
```

#### `POST /api/ingest/snapshots`
Bulk per-app usage data:
```json
{
  "session_id": 1,
  "snapshots": [
    {
      "app_uid": "com.whatsapp",
      "app_name": "WhatsApp",
      "bytes_tx": 1000000,
      "bytes_rx": 5000000,
      "dest_ips": ["157.240.1.35"],
      "is_whitelisted": true,
      "snapshot_time": "2024-10-15T02:30:00Z"
    }
  ]
}
```
Automatically updates the rolling EMA baseline for each app.

#### `POST /api/ingest/telco-report`
Log what the telco claims was consumed (from SMS/USSD parsing):
```json
{
  "device_id": "DEVICE-001",
  "report_date": "2024-10-31",
  "bytes_reported": 104857600,
  "source": "sms",
  "raw_message": "MTN: Your data balance is now 500MB...",
  "billing_period_start": "2024-10-01",
  "billing_period_end": "2024-10-31"
}
```
Sources: `sms`, `ussd`, `manual`

#### `POST /api/ingest/anomaly`
Report an Aura-Brain anomaly event:
```json
{
  "device_id": "DEVICE-001",
  "session_id": 5,
  "app_uid": "com.tiktok.musically",
  "detected_at": "2024-10-15T02:14:33Z",
  "screen_state": "off",
  "baseline_bytes": 2200000,
  "actual_bytes": 40265318,
  "deviation_pct": 17.30
}
```
Severity is calculated server-side: `low` (<50%), `medium` (<200%), `high` (≥200%).

#### `GET /api/ingest/sessions?device_id=<id>&limit=50&offset=0`
#### `GET /api/ingest/sessions/<session_id>`
Session detail with full per-app breakdown.

---

### Dispute Cases (Dispute-Forge)

#### `POST /api/disputes`
Initiate a dispute — runs the variance engine automatically:
```json
{
  "device_id": "DEVICE-001",
  "period_start": "2024-10-01T00:00:00Z",
  "period_end": "2024-10-31T23:59:59Z"
}
```
Returns variance analysis and a dispute reference (e.g. `AIT-2024-8C4072`).

**Requires a telco report to exist for the period.**

#### `GET /api/disputes?status=pending&limit=20`
#### `GET /api/disputes/<reference>`
Full detail with re-run variance analysis.

#### `POST /api/disputes/<reference>/generate`
Generates the forensic PDF report including:
- Consumer & device details
- Audit period and session count
- V = |D_device − D_telco| calculation table
- Per-app byte breakdown
- Aura-Brain anomaly events
- NCC General Consumer Code §5.3 legal citation
- Consumer declaration with signature block

#### `GET /api/disputes/<reference>/download`
Download the generated PDF.

#### `POST /api/disputes/<reference>/submit`
Submit to NCC consumer portal. Returns an NCC submission reference.

#### `PATCH /api/disputes/<reference>/status`
```json
{ "status": "resolved", "resolution_note": "Telco refunded 40MB credit" }
```
Valid statuses: `pending`, `pdf_generated`, `submitted`, `acknowledged`, `resolved`, `rejected`

---

### Analytics

#### `GET /api/analytics/summary`
Dashboard summary: device count, dispute breakdown by status, total bytes monitored,
anomaly count (last 30 days), highest-variance dispute.

#### `GET /api/analytics/device/<device_id>?days=30`
Per-device analytics:
- Daily usage trend
- Top 15 apps by bytes consumed
- Anomaly event trend by day
- Screen-on vs screen-off data breakdown

#### `GET /api/analytics/baselines/<device_id>`
All app baselines for a device (EMA daily average + sample count).

#### `POST /api/analytics/check-anomaly`
Stateless threshold check (mobile app can call before ingesting):
```json
{ "baseline_bytes": 2200000, "actual_bytes": 40265318 }
```
Returns `is_anomaly`, `deviation_pct`, `severity`, `threshold_pct`.

---

## The Variance Algorithm

```
V = |D_device - D_telco|
```

- **D_device**: Sum of `total_bytes_tx + total_bytes_rx` across all packet sessions
  in the billing period, from Packet-Sentry system logs.
- **D_telco**: `bytes_reported` from the matched telco report (SMS/USSD).
- **Threshold**: If `V / D_telco > 5%` AND `D_device < D_telco`, the case is flagged
  as a **Suspected Over-billing Event**.

### App Baseline (Aura-Brain)
Uses **Exponential Moving Average** over a 7-day window:

```
alpha = 2 / (BASELINE_DAYS + 1)  # = 0.25 for 7 days
new_avg = alpha * actual + (1 - alpha) * prev_avg
```

Anomaly trigger: `deviation > 25%` from baseline during screen-off (idle) states.

---

## Configuration (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | — | JWT signing key (**must change in production**) |
| `JWT_ACCESS_EXPIRES_MINUTES` | `60` | Access token lifetime |
| `JWT_REFRESH_EXPIRES_DAYS` | `30` | Refresh token lifetime |
| `DATABASE_PATH` | `aitelda.db` | SQLite file path |
| `VARIANCE_THRESHOLD` | `0.05` | Over-billing threshold (5%) |
| `ANOMALY_THRESHOLD` | `0.25` | Idle anomaly threshold (25%) |
| `BASELINE_DAYS` | `7` | EMA window for baselines |
| `NCC_PORTAL_URL` | — | NCC API endpoint for production submission |
| `PDF_OUTPUT_DIR` | `dispute_pdfs` | Where to store generated PDFs |

---

## Security

- Passwords hashed with Werkzeug `pbkdf2:sha256`
- JWT tokens signed with HS256
- Refresh tokens stored as SHA-256 hashes only — raw token never persisted
- Refresh token rotation on every use — old token revoked immediately
- All endpoints enforce device-to-user ownership checks
- PRAGMA `foreign_keys=ON` and `journal_mode=WAL` for SQLite integrity
- No packet content is ever stored — metadata only (UID, IP, byte count)

---

## Running Tests

```bash
# With pytest installed:
pip install pytest
python -m pytest tests/ -v

# Without pytest (built-in runner):
python -m app.tests   # or use the functional test script
```

All 32 tests cover: auth flow, token rotation, device management, full ingestion
pipeline, variance engine, anomaly detection, PDF generation, NCC submission,
analytics, and error handling.
