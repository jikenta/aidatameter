"""
AiTelDa Backend Test Suite

Tests for: auth, devices, ingestion pipeline, variance engine, disputes, analytics
Run with: python -m pytest tests/ -v
"""

import json
import pytest
import tempfile
import os

from app import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": db_path,
        "SECRET_KEY": "test-secret-key",
        "JWT_ACCESS_EXPIRES_MINUTES": 60,
        "JWT_REFRESH_EXPIRES_DAYS": 7,
        "PDF_OUTPUT_DIR": tempfile.mkdtemp(),
    })
    yield app
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_headers(client):
    """Register a user and return auth headers."""
    client.post("/api/auth/register", json={
        "email": "test@aitelda.ng",
        "password": "SecurePass1",
        "full_name": "Test User",
        "phone": "+2348012345678",
    })
    resp = client.post("/api/auth/login", json={
        "email": "test@aitelda.ng",
        "password": "SecurePass1",
    })
    data = resp.get_json()
    token = data["data"]["access_token"]
    refresh = data["data"]["refresh_token"]
    return {"Authorization": f"Bearer {token}", "_refresh": refresh}


@pytest.fixture
def registered_device(client, auth_headers):
    """Register a device and return device_id."""
    resp = client.post("/api/devices/register", json={
        "device_id": "TEST-DEVICE-001",
        "platform": "android",
        "model": "Samsung Galaxy A54",
        "os_version": "Android 14",
        "app_version": "1.0.0",
        "telco": "mtn",
    }, headers=auth_headers)
    assert resp.status_code == 201
    return "TEST-DEVICE-001"


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_api_root(client):
    resp = client.get("/api")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "endpoints" in data


# ---------------------------------------------------------------------------
# Auth Tests
# ---------------------------------------------------------------------------

class TestAuth:
    def test_register_success(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "newuser@aitelda.ng",
            "password": "SecurePass1",
            "full_name": "New User",
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["success"] is True
        assert "access_token" in data["data"]
        assert "refresh_token" in data["data"]

    def test_register_duplicate_email(self, client, auth_headers):
        resp = client.post("/api/auth/register", json={
            "email": "test@aitelda.ng",
            "password": "SecurePass1",
            "full_name": "Duplicate User",
        })
        assert resp.status_code == 409

    def test_register_invalid_email(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "not-an-email",
            "password": "SecurePass1",
            "full_name": "Bad Email",
        })
        assert resp.status_code == 422

    def test_register_weak_password(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "weak@aitelda.ng",
            "password": "short",
            "full_name": "Weak Pass",
        })
        assert resp.status_code == 422

    def test_login_success(self, client, auth_headers):
        resp = client.post("/api/auth/login", json={
            "email": "test@aitelda.ng",
            "password": "SecurePass1",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.get_json()["data"]

    def test_login_wrong_password(self, client, auth_headers):
        resp = client.post("/api/auth/login", json={
            "email": "test@aitelda.ng",
            "password": "WrongPassword1",
        })
        assert resp.status_code == 401

    def test_me_authenticated(self, client, auth_headers):
        resp = client.get("/api/auth/me", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert data["email"] == "test@aitelda.ng"

    def test_me_unauthenticated(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_token_refresh(self, client, auth_headers):
        resp = client.post("/api/auth/refresh", json={
            "refresh_token": auth_headers["_refresh"],
        })
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert "access_token" in data
        assert "refresh_token" in data

    def test_logout(self, client, auth_headers):
        resp = client.post("/api/auth/logout", json={
            "refresh_token": auth_headers["_refresh"],
        }, headers=auth_headers)
        assert resp.status_code == 200

        # Refresh token should now be invalid
        resp2 = client.post("/api/auth/refresh", json={
            "refresh_token": auth_headers["_refresh"],
        })
        assert resp2.status_code == 401


# ---------------------------------------------------------------------------
# Device Tests
# ---------------------------------------------------------------------------

class TestDevices:
    def test_register_device(self, client, auth_headers):
        resp = client.post("/api/devices/register", json={
            "device_id": "DEVICE-TEST-XYZ",
            "platform": "android",
            "telco": "mtn",
        }, headers=auth_headers)
        assert resp.status_code == 201

    def test_register_invalid_platform(self, client, auth_headers):
        resp = client.post("/api/devices/register", json={
            "device_id": "BAD-PLATFORM",
            "platform": "windows",
        }, headers=auth_headers)
        assert resp.status_code == 422

    def test_list_devices(self, client, auth_headers, registered_device):
        resp = client.get("/api/devices", headers=auth_headers)
        assert resp.status_code == 200
        devices = resp.get_json()["data"]
        assert len(devices) >= 1

    def test_get_device_detail(self, client, auth_headers, registered_device):
        resp = client.get(f"/api/devices/{registered_device}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert data["device_id"] == registered_device
        assert "stats" in data

    def test_heartbeat(self, client, auth_headers, registered_device):
        resp = client.patch(
            f"/api/devices/{registered_device}/heartbeat",
            json={"app_version": "1.0.1"},
            headers=auth_headers,
        )
        assert resp.status_code == 200

    def test_deregister_device(self, client, auth_headers, registered_device):
        resp = client.delete(f"/api/devices/{registered_device}", headers=auth_headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Ingestion Pipeline Tests
# ---------------------------------------------------------------------------

class TestIngest:
    def test_open_session(self, client, auth_headers, registered_device):
        resp = client.post("/api/ingest/session", json={
            "device_id": registered_device,
            "session_start": "2024-10-15T02:00:00Z",
            "screen_state": "off",
        }, headers=auth_headers)
        assert resp.status_code == 201
        return resp.get_json()["data"]["session_id"]

    def test_close_session(self, client, auth_headers, registered_device):
        open_resp = client.post("/api/ingest/session", json={
            "device_id": registered_device,
            "session_start": "2024-10-15T02:00:00Z",
        }, headers=auth_headers)
        session_id = open_resp.get_json()["data"]["session_id"]

        resp = client.post(f"/api/ingest/session/{session_id}/end", json={
            "session_end": "2024-10-15T06:00:00Z",
            "total_bytes_tx": 5000000,
            "total_bytes_rx": 20000000,
        }, headers=auth_headers)
        assert resp.status_code == 200

    def test_ingest_snapshots(self, client, auth_headers, registered_device):
        open_resp = client.post("/api/ingest/session", json={
            "device_id": registered_device,
            "session_start": "2024-10-15T02:00:00Z",
        }, headers=auth_headers)
        session_id = open_resp.get_json()["data"]["session_id"]

        resp = client.post("/api/ingest/snapshots", json={
            "session_id": session_id,
            "snapshots": [
                {
                    "app_uid": "com.whatsapp",
                    "app_name": "WhatsApp",
                    "bytes_tx": 1000000,
                    "bytes_rx": 5000000,
                    "dest_ips": ["157.240.1.35"],
                    "is_whitelisted": True,
                    "snapshot_time": "2024-10-15T02:30:00Z",
                },
                {
                    "app_uid": "com.tiktok.musically",
                    "app_name": "TikTok",
                    "bytes_tx": 500000,
                    "bytes_rx": 18000000,
                    "is_whitelisted": False,
                    "snapshot_time": "2024-10-15T02:30:00Z",
                },
            ],
        }, headers=auth_headers)
        assert resp.status_code == 201
        assert resp.get_json()["data"]["inserted"] == 2

    def test_telco_report(self, client, auth_headers, registered_device):
        resp = client.post("/api/ingest/telco-report", json={
            "device_id": registered_device,
            "report_date": "2024-10-31",
            "bytes_reported": 52428800,
            "source": "sms",
            "raw_message": "Your MTN data deduction: 50MB. Balance: 500MB",
            "billing_period_start": "2024-10-01",
            "billing_period_end": "2024-10-31",
        }, headers=auth_headers)
        assert resp.status_code == 201

    def test_anomaly_event(self, client, auth_headers, registered_device):
        resp = client.post("/api/ingest/anomaly", json={
            "device_id": registered_device,
            "app_uid": "com.tiktok.musically",
            "detected_at": "2024-10-15T02:14:33Z",
            "screen_state": "off",
            "baseline_bytes": 2200000,
            "actual_bytes": 40265318,
            "deviation_pct": 17.30,
        }, headers=auth_headers)
        assert resp.status_code == 201
        assert resp.get_json()["data"]["severity"] == "high"

    def test_list_sessions(self, client, auth_headers, registered_device):
        resp = client.get(
            f"/api/ingest/sessions?device_id={registered_device}",
            headers=auth_headers,
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Variance Engine Tests
# ---------------------------------------------------------------------------

class TestVariance:
    def test_check_anomaly_below_threshold(self, client, auth_headers):
        resp = client.post("/api/analytics/check-anomaly", json={
            "baseline_bytes": 10000000,
            "actual_bytes": 11000000,  # 10% deviation — below 25%
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert data["is_anomaly"] is False

    def test_check_anomaly_above_threshold(self, client, auth_headers):
        resp = client.post("/api/analytics/check-anomaly", json={
            "baseline_bytes": 2200000,
            "actual_bytes": 40265318,  # ~1730% deviation
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert data["is_anomaly"] is True
        assert data["severity"] == "high"

    def test_check_anomaly_zero_baseline(self, client, auth_headers):
        resp = client.post("/api/analytics/check-anomaly", json={
            "baseline_bytes": 0,
            "actual_bytes": 5000000,
        }, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["data"]["is_anomaly"] is False


# ---------------------------------------------------------------------------
# Dispute Tests
# ---------------------------------------------------------------------------

class TestDisputes:
    def _setup_data(self, client, auth_headers, registered_device):
        """Helper: create a session + snapshots + telco report."""
        # Session
        sr = client.post("/api/ingest/session", json={
            "device_id": registered_device,
            "session_start": "2024-10-15T02:00:00Z",
        }, headers=auth_headers)
        sid = sr.get_json()["data"]["session_id"]

        client.post(f"/api/ingest/session/{sid}/end", json={
            "session_end": "2024-10-15T06:00:00Z",
            "total_bytes_tx": 5000000,
            "total_bytes_rx": 60000000,  # 65MB
        }, headers=auth_headers)

        client.post("/api/ingest/snapshots", json={
            "session_id": sid,
            "snapshots": [{
                "app_uid": "com.tiktok.musically",
                "bytes_tx": 5000000,
                "bytes_rx": 60000000,
            }],
        }, headers=auth_headers)

        # Telco claims 100MB — device recorded only 65MB → telco over-reported
        client.post("/api/ingest/telco-report", json={
            "device_id": registered_device,
            "report_date": "2024-10-31",
            "bytes_reported": 104857600,  # 100MB
            "source": "sms",
            "billing_period_start": "2024-10-01",
            "billing_period_end": "2024-10-31",
        }, headers=auth_headers)

    def test_create_dispute(self, client, auth_headers, registered_device):
        self._setup_data(client, auth_headers, registered_device)
        resp = client.post("/api/disputes", json={
            "device_id": registered_device,
            "period_start": "2024-10-01T00:00:00Z",
            "period_end": "2024-10-31T23:59:59Z",
        }, headers=auth_headers)
        assert resp.status_code == 201
        data = resp.get_json()["data"]
        assert "reference" in data
        assert data["reference"].startswith("AIT-")
        return data["reference"]

    def test_list_disputes(self, client, auth_headers, registered_device):
        self._setup_data(client, auth_headers, registered_device)
        client.post("/api/disputes", json={
            "device_id": registered_device,
            "period_start": "2024-10-01T00:00:00Z",
            "period_end": "2024-10-31T23:59:59Z",
        }, headers=auth_headers)
        resp = client.get("/api/disputes", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["data"]["total"] >= 1

    def test_generate_pdf(self, client, auth_headers, registered_device):
        self._setup_data(client, auth_headers, registered_device)
        create_resp = client.post("/api/disputes", json={
            "device_id": registered_device,
            "period_start": "2024-10-01T00:00:00Z",
            "period_end": "2024-10-31T23:59:59Z",
        }, headers=auth_headers)
        ref = create_resp.get_json()["data"]["reference"]

        resp = client.post(f"/api/disputes/{ref}/generate", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert data["status"] == "pdf_generated"
        assert "pdf_path" in data

    def test_submit_to_ncc(self, client, auth_headers, registered_device):
        self._setup_data(client, auth_headers, registered_device)
        create_resp = client.post("/api/disputes", json={
            "device_id": registered_device,
            "period_start": "2024-10-01T00:00:00Z",
            "period_end": "2024-10-31T23:59:59Z",
        }, headers=auth_headers)
        ref = create_resp.get_json()["data"]["reference"]
        client.post(f"/api/disputes/{ref}/generate", headers=auth_headers)

        resp = client.post(f"/api/disputes/{ref}/submit", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert data["status"] == "submitted"
        assert "ncc_submission_ref" in data


# ---------------------------------------------------------------------------
# Analytics Tests
# ---------------------------------------------------------------------------

class TestAnalytics:
    def test_summary(self, client, auth_headers):
        resp = client.get("/api/analytics/summary", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert "registered_devices" in data
        assert "total_bytes_monitored" in data

    def test_device_analytics(self, client, auth_headers, registered_device):
        resp = client.get(
            f"/api/analytics/device/{registered_device}?days=30",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert "daily_usage" in data
        assert "top_apps" in data

    def test_baselines(self, client, auth_headers, registered_device):
        resp = client.get(
            f"/api/analytics/baselines/{registered_device}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
