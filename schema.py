"""
AiTelDa Database Models — v2.0
SQLite via Python's built-in sqlite3 module.

Schema covers:
  Core:       users, devices, refresh_tokens
  Monitoring: packet_sessions, usage_snapshots, telco_reports, app_baselines
  Threats:    anomaly_events, quarantined_apps, dns_blocked_domains,
              phishing_intercepts, update_queue, zero_perm_audits
  Billing:    dispute_cases
  Content:    blog_posts, blog_comments, blog_likes
  Diagnostics: diagnostic_runs, diagnostic_results
  Kill Switch: kill_switch_settings, kill_switch_events
"""

import sqlite3
import os

DB_PATH = os.environ.get("DATABASE_PATH", "aitelda.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # ── USERS ─────────────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            email           TEXT    NOT NULL UNIQUE,
            phone           TEXT,
            password_hash   TEXT    NOT NULL,
            full_name       TEXT    NOT NULL,
            telco           TEXT,
            is_active       INTEGER NOT NULL DEFAULT 1,
            is_verified     INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── DEVICES ───────────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            device_id       TEXT    NOT NULL UNIQUE,
            platform        TEXT    NOT NULL,
            model           TEXT,
            os_version      TEXT,
            app_version     TEXT,
            telco           TEXT,
            msisdn          TEXT,
            registered_at   TEXT    NOT NULL DEFAULT (datetime('now')),
            last_seen       TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── PACKET SESSIONS ───────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS packet_sessions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       TEXT    NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            session_start   TEXT    NOT NULL,
            session_end     TEXT,
            screen_state    TEXT    NOT NULL DEFAULT 'off',
            total_bytes_tx  INTEGER NOT NULL DEFAULT 0,
            total_bytes_rx  INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── USAGE SNAPSHOTS ───────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usage_snapshots (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      INTEGER NOT NULL REFERENCES packet_sessions(id) ON DELETE CASCADE,
            app_uid         TEXT    NOT NULL,
            app_name        TEXT,
            bytes_tx        INTEGER NOT NULL DEFAULT 0,
            bytes_rx        INTEGER NOT NULL DEFAULT 0,
            dest_ips        TEXT,
            is_whitelisted  INTEGER NOT NULL DEFAULT 0,
            snapshot_time   TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── TELCO REPORTS ─────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS telco_reports (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id            TEXT    NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            report_date          TEXT    NOT NULL,
            bytes_reported       INTEGER NOT NULL,
            source               TEXT    NOT NULL DEFAULT 'sms',
            raw_message          TEXT,
            billing_period_start TEXT,
            billing_period_end   TEXT,
            created_at           TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── ANOMALY EVENTS ────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS anomaly_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       TEXT    NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            session_id      INTEGER REFERENCES packet_sessions(id),
            app_uid         TEXT    NOT NULL,
            app_name        TEXT,
            detected_at     TEXT    NOT NULL,
            screen_state    TEXT    NOT NULL DEFAULT 'off',
            baseline_bytes  INTEGER NOT NULL,
            actual_bytes    INTEGER NOT NULL,
            deviation_pct   REAL    NOT NULL,
            severity        TEXT    NOT NULL DEFAULT 'medium',
            anomaly_type    TEXT    NOT NULL DEFAULT 'idle_drain',
            is_acknowledged INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── QUARANTINED APPS ──────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS quarantined_apps (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       TEXT    NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            app_uid         TEXT    NOT NULL,
            app_name        TEXT,
            reason          TEXT,
            quarantined_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            released_at     TEXT,
            is_active       INTEGER NOT NULL DEFAULT 1,
            UNIQUE(device_id, app_uid)
        )
    """)

    # ── DNS BLOCKED DOMAINS ───────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dns_blocked_domains (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       TEXT    NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            domain          TEXT    NOT NULL,
            category        TEXT    NOT NULL DEFAULT 'tracker',
            blocked_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            request_count   INTEGER NOT NULL DEFAULT 1,
            bytes_saved     INTEGER NOT NULL DEFAULT 0
        )
    """)

    # ── DNS BLACKLISTS (global, admin-managed) ────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dns_blacklists (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            domain          TEXT    NOT NULL UNIQUE,
            category        TEXT    NOT NULL DEFAULT 'tracker',
            source          TEXT    NOT NULL DEFAULT 'aitelda',
            added_at        TEXT    NOT NULL DEFAULT (datetime('now')),
            is_active       INTEGER NOT NULL DEFAULT 1
        )
    """)

    # ── PHISHING INTERCEPTS ───────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS phishing_intercepts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       TEXT    NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            url             TEXT    NOT NULL,
            domain          TEXT    NOT NULL,
            threat_type     TEXT    NOT NULL DEFAULT 'phishing',
            source_list     TEXT    NOT NULL DEFAULT 'aitelda',
            bytes_prevented INTEGER NOT NULL DEFAULT 0,
            intercepted_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── UPDATE QUEUE (Update Guardian) ────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS update_queue (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       TEXT    NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            app_uid         TEXT    NOT NULL,
            app_name        TEXT,
            update_type     TEXT    NOT NULL DEFAULT 'app',
            size_bytes      INTEGER NOT NULL DEFAULT 0,
            status          TEXT    NOT NULL DEFAULT 'held',
            held_at         TEXT    NOT NULL DEFAULT (datetime('now')),
            approved_at     TEXT,
            released_at     TEXT,
            policy          TEXT    NOT NULL DEFAULT 'wifi_only',
            UNIQUE(device_id, app_uid)
        )
    """)

    # ── VIDEO GOVERNOR SETTINGS ───────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS video_governor_settings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       TEXT    NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            app_uid         TEXT    NOT NULL,
            app_name        TEXT,
            max_quality     TEXT    NOT NULL DEFAULT '480p',
            is_enabled      INTEGER NOT NULL DEFAULT 1,
            bytes_saved     INTEGER NOT NULL DEFAULT 0,
            updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(device_id, app_uid)
        )
    """)

    # ── ZERO-PERM AUDITS ──────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS zero_perm_audits (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       TEXT    NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            app_uid         TEXT    NOT NULL,
            app_name        TEXT,
            data_used_bytes INTEGER NOT NULL DEFAULT 0,
            permissions     TEXT,
            risk_score      REAL    NOT NULL DEFAULT 0,
            verdict         TEXT,
            recommendation  TEXT    NOT NULL DEFAULT 'monitor',
            audited_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── KILL SWITCH SETTINGS ──────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS kill_switch_settings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       TEXT    NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE UNIQUE,
            is_enabled      INTEGER NOT NULL DEFAULT 1,
            whitelist       TEXT    DEFAULT '[]',
            bytes_blocked   INTEGER NOT NULL DEFAULT 0,
            money_saved_ngn REAL    NOT NULL DEFAULT 0,
            updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── KILL SWITCH EVENTS ────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS kill_switch_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       TEXT    NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            app_uid         TEXT    NOT NULL,
            app_name        TEXT,
            bytes_blocked   INTEGER NOT NULL DEFAULT 0,
            event_time      TEXT    NOT NULL DEFAULT (datetime('now')),
            screen_state    TEXT    NOT NULL DEFAULT 'off'
        )
    """)

    # ── DISPUTE CASES ─────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dispute_cases (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            reference          TEXT    NOT NULL UNIQUE,
            user_id            INTEGER NOT NULL REFERENCES users(id),
            device_id          TEXT    NOT NULL REFERENCES devices(device_id),
            telco_report_id    INTEGER REFERENCES telco_reports(id),
            device_bytes       INTEGER NOT NULL,
            telco_bytes        INTEGER NOT NULL,
            variance_bytes     INTEGER NOT NULL,
            variance_pct       REAL    NOT NULL,
            period_start       TEXT    NOT NULL,
            period_end         TEXT    NOT NULL,
            status             TEXT    NOT NULL DEFAULT 'pending',
            pdf_path           TEXT,
            ncc_submission_ref TEXT,
            ncc_submitted_at   TEXT,
            resolved_at        TEXT,
            resolution_note    TEXT,
            created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at         TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── APP BASELINES ─────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_baselines (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       TEXT    NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            app_uid         TEXT    NOT NULL,
            avg_daily_bytes INTEGER NOT NULL DEFAULT 0,
            sample_days     INTEGER NOT NULL DEFAULT 0,
            last_updated    TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(device_id, app_uid)
        )
    """)

    # ── REFRESH TOKENS ────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash  TEXT    NOT NULL UNIQUE,
            expires_at  TEXT    NOT NULL,
            revoked     INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── BLOG POSTS ────────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blog_posts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            slug        TEXT    NOT NULL UNIQUE,
            title       TEXT    NOT NULL,
            excerpt     TEXT,
            content     TEXT    NOT NULL,
            author      TEXT    NOT NULL DEFAULT 'AiTelDa Research Team',
            author_role TEXT    NOT NULL DEFAULT 'Editorial',
            category    TEXT    NOT NULL DEFAULT 'industry',
            tags        TEXT    DEFAULT '[]',
            icon        TEXT    DEFAULT '📡',
            read_time   TEXT    DEFAULT '5 min',
            likes_count INTEGER NOT NULL DEFAULT 0,
            is_featured INTEGER NOT NULL DEFAULT 0,
            is_published INTEGER NOT NULL DEFAULT 1,
            published_at TEXT   NOT NULL DEFAULT (datetime('now')),
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── BLOG COMMENTS ─────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blog_comments (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id     INTEGER NOT NULL REFERENCES blog_posts(id) ON DELETE CASCADE,
            user_id     INTEGER REFERENCES users(id),
            author_name TEXT    NOT NULL DEFAULT 'Anonymous',
            body        TEXT    NOT NULL,
            likes_count INTEGER NOT NULL DEFAULT 0,
            parent_id   INTEGER REFERENCES blog_comments(id),
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ── BLOG LIKES ────────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blog_likes (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL REFERENCES blog_posts(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            liked_at TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(post_id, user_id)
        )
    """)

    # ── DIAGNOSTIC RUNS ───────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS diagnostic_runs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            device_id   TEXT    REFERENCES devices(device_id),
            tool        TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'running',
            started_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            finished_at TEXT,
            summary     TEXT
        )
    """)

    # ── Indexes ───────────────────────────────────────────────────────────
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_usage_session     ON usage_snapshots(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_device   ON packet_sessions(device_id)",
        "CREATE INDEX IF NOT EXISTS idx_anomaly_device    ON anomaly_events(device_id)",
        "CREATE INDEX IF NOT EXISTS idx_disputes_user     ON dispute_cases(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_telco_device      ON telco_reports(device_id)",
        "CREATE INDEX IF NOT EXISTS idx_baseline_device   ON app_baselines(device_id, app_uid)",
        "CREATE INDEX IF NOT EXISTS idx_blog_slug         ON blog_posts(slug)",
        "CREATE INDEX IF NOT EXISTS idx_blog_pub          ON blog_posts(is_published, published_at)",
        "CREATE INDEX IF NOT EXISTS idx_comments_post     ON blog_comments(post_id)",
        "CREATE INDEX IF NOT EXISTS idx_dns_device        ON dns_blocked_domains(device_id)",
        "CREATE INDEX IF NOT EXISTS idx_quarantine_device ON quarantined_apps(device_id)",
        "CREATE INDEX IF NOT EXISTS idx_ks_device         ON kill_switch_events(device_id)",
        "CREATE INDEX IF NOT EXISTS idx_update_device     ON update_queue(device_id)",
    ]
    for idx in indexes:
        cur.execute(idx)

    conn.commit()
    conn.close()
    print("[AiTelDa] Database v2.0 initialized successfully.")


def seed_dns_blacklist(conn=None):
    """Seed the DNS blacklist with common tracker domains."""
    close = False
    if conn is None:
        conn = get_db()
        close = True

    domains = [
        ("googletagmanager.com", "analytics", "google"),
        ("google-analytics.com", "analytics", "google"),
        ("analytics.google.com", "analytics", "google"),
        ("doubleclick.net", "advertising", "google"),
        ("googlesyndication.com", "advertising", "google"),
        ("connect.facebook.net", "tracker", "meta"),
        ("graph.facebook.com", "tracker", "meta"),
        ("pixel.facebook.com", "advertising", "meta"),
        ("static.ads-twitter.com", "advertising", "twitter"),
        ("ads.twitter.com", "advertising", "twitter"),
        ("hotjar.com", "analytics", "hotjar"),
        ("amplitude.com", "analytics", "amplitude"),
        ("mixpanel.com", "analytics", "mixpanel"),
        ("segment.io", "analytics", "segment"),
        ("api.segment.io", "analytics", "segment"),
        ("branch.io", "tracker", "branch"),
        ("app.link", "tracker", "branch"),
        ("crashlytics.com", "analytics", "google"),
        ("scorecardresearch.com", "tracker", "comscore"),
        ("moatads.com", "advertising", "oracle"),
    ]
    for domain, category, source in domains:
        try:
            conn.execute(
                "INSERT OR IGNORE INTO dns_blacklists (domain, category, source) VALUES (?, ?, ?)",
                (domain, category, source),
            )
        except Exception:
            pass

    if close:
        conn.commit()
        conn.close()
    else:
        conn.commit()
