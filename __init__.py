"""
AiTelDa Backend — Flask Application Factory v2.0
"""

import os
from flask import Flask, jsonify
from dotenv import load_dotenv

load_dotenv()


def create_app(config_override: dict = None) -> Flask:
    app = Flask(__name__, instance_relative_config=False)

    # ── Configuration ──────────────────────────────────────────────────
    app.config["SECRET_KEY"]                 = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["JWT_ACCESS_EXPIRES_MINUTES"] = int(os.environ.get("JWT_ACCESS_EXPIRES_MINUTES", 60))
    app.config["JWT_REFRESH_EXPIRES_DAYS"]   = int(os.environ.get("JWT_REFRESH_EXPIRES_DAYS", 30))
    app.config["NCC_PORTAL_URL"]             = os.environ.get("NCC_PORTAL_URL", "")
    app.config["PDF_OUTPUT_DIR"]             = os.environ.get("PDF_OUTPUT_DIR", "dispute_pdfs")
    app.config["DATABASE_PATH"]              = os.environ.get("DATABASE_PATH", "aitelda.db")

    if config_override:
        app.config.update(config_override)

    os.environ["DATABASE_PATH"] = app.config["DATABASE_PATH"]

    # ── CORS ──────────────────────────────────────────────────────────
    @app.after_request
    def add_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"]  = os.environ.get("CORS_ORIGIN", "*")
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        return response

    @app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
    @app.route("/<path:path>", methods=["OPTIONS"])
    def options_handler(path):
        return jsonify({}), 200

    # ── Database ──────────────────────────────────────────────────────
    from app.models.schema import init_db, seed_dns_blacklist
    with app.app_context():
        init_db()
        seed_dns_blacklist()

    # ── Blueprints ────────────────────────────────────────────────────
    from app.routes.auth        import auth_bp
    from app.routes.devices     import devices_bp
    from app.routes.ingest      import ingest_bp
    from app.routes.disputes    import disputes_bp
    from app.routes.analytics   import analytics_bp
    from app.routes.diagnostics import diag_bp
    from app.routes.kill_switch import ks_bp
    from app.routes.blog        import blog_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(ingest_bp)
    app.register_blueprint(disputes_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(diag_bp)
    app.register_blueprint(ks_bp)
    app.register_blueprint(blog_bp)

    # ── Health / Root ──────────────────────────────────────────────────
    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "service": "AiTelDa Backend", "version": "2.0.0"})

    @app.route("/api", methods=["GET"])
    def api_root():
        return jsonify({
            "service": "AiTelDa API",
            "version": "2.0.0",
            "endpoints": {
                "auth": {
                    "POST /api/auth/register":  "Create account",
                    "POST /api/auth/login":     "Login, receive JWT",
                    "POST /api/auth/refresh":   "Rotate refresh token",
                    "POST /api/auth/logout":    "Revoke refresh token",
                    "GET  /api/auth/me":        "Current user profile",
                },
                "devices": {
                    "POST   /api/devices/register":              "Register/update device",
                    "GET    /api/devices":                       "List devices",
                    "GET    /api/devices/<id>":                  "Device detail + stats",
                    "DELETE /api/devices/<id>":                  "Deregister device",
                    "PATCH  /api/devices/<id>/heartbeat":        "Update last-seen",
                },
                "ingest": {
                    "POST /api/ingest/session":             "Open monitoring session",
                    "POST /api/ingest/session/<id>/end":   "Close session",
                    "POST /api/ingest/snapshots":           "Bulk per-app usage",
                    "POST /api/ingest/telco-report":        "Submit telco deduction",
                    "POST /api/ingest/anomaly":             "Report Aura-Brain anomaly",
                    "GET  /api/ingest/sessions":            "List sessions",
                    "GET  /api/ingest/sessions/<id>":       "Session detail",
                },
                "disputes": {
                    "POST  /api/disputes":                     "Initiate dispute",
                    "GET   /api/disputes":                     "List disputes",
                    "GET   /api/disputes/<ref>":               "Dispute detail",
                    "POST  /api/disputes/<ref>/generate":      "Generate forensic PDF",
                    "GET   /api/disputes/<ref>/download":      "Download PDF",
                    "POST  /api/disputes/<ref>/submit":        "Submit to NCC",
                    "PATCH /api/disputes/<ref>/status":        "Update status",
                },
                "analytics": {
                    "GET  /api/analytics/summary":             "User-level summary",
                    "GET  /api/analytics/device/<id>":         "Device deep analytics",
                    "GET  /api/analytics/baselines/<id>":      "App baselines",
                    "POST /api/analytics/check-anomaly":       "Stateless anomaly check",
                    "GET  /api/analytics/dashboard/<id>":      "Full dashboard payload",
                    "GET  /api/analytics/trend/<id>":          "Chart time-series data",
                    "GET  /api/analytics/savings/<id>":        "Savings breakdown",
                },
                "diagnostics": {
                    "GET  /api/diagnostics/summary":                   "Threat summary",
                    "POST /api/diagnostics/run-all":                   "Run full suite",
                    "GET  /api/diagnostics/malware/scan":              "Malware scan",
                    "POST /api/diagnostics/malware/quarantine":        "Quarantine app",
                    "POST /api/diagnostics/malware/release":           "Release quarantine",
                    "GET  /api/diagnostics/malware/quarantined":       "List quarantined",
                    "GET  /api/diagnostics/dns/stats":                 "DNS block stats",
                    "POST /api/diagnostics/dns/check":                 "Check domain",
                    "POST /api/diagnostics/dns/block":                 "Log DNS block",
                    "GET  /api/diagnostics/dns/blacklist":             "Get blacklist",
                    "POST /api/diagnostics/dns/blacklist":             "Add to blacklist",
                    "POST /api/diagnostics/phishing/check":            "Check URL safety",
                    "POST /api/diagnostics/phishing/report":           "Log intercept",
                    "GET  /api/diagnostics/phishing/events":           "List intercepts",
                    "GET  /api/diagnostics/updates/queue":             "View update queue",
                    "POST /api/diagnostics/updates/queue":             "Add to queue",
                    "POST /api/diagnostics/updates/approve":           "Approve update",
                    "POST /api/diagnostics/updates/policy":            "Set policy",
                    "GET  /api/diagnostics/video/settings":            "Video governor settings",
                    "POST /api/diagnostics/video/set-quality":         "Set quality cap",
                    "POST /api/diagnostics/video/log-savings":         "Log video savings",
                    "POST /api/diagnostics/zeroperm/audit":            "Run zero-perm audit",
                    "POST /api/diagnostics/zeroperm/check":            "Stateless risk check",
                    "GET  /api/diagnostics/zeroperm/history":          "Audit history",
                },
                "kill_switch": {
                    "GET  /api/killswitch":                  "Get settings",
                    "POST /api/killswitch/enable":           "Enable Kill Switch",
                    "POST /api/killswitch/disable":          "Disable Kill Switch",
                    "POST /api/killswitch/whitelist/add":    "Whitelist an app",
                    "POST /api/killswitch/whitelist/remove": "Remove from whitelist",
                    "POST /api/killswitch/event":            "Log block event",
                    "GET  /api/killswitch/events":           "List block events",
                    "GET  /api/killswitch/stats":            "Savings statistics",
                },
                "blog": {
                    "GET  /api/blog/posts":                           "List posts",
                    "POST /api/blog/posts":                           "Create post",
                    "GET  /api/blog/posts/<slug>":                    "Single post + comments",
                    "PUT  /api/blog/posts/<slug>":                    "Update post",
                    "POST /api/blog/posts/<slug>/like":               "Toggle like",
                    "POST /api/blog/posts/<slug>/comments":           "Add comment",
                    "POST /api/blog/posts/<slug>/comments/<id>/like": "Like comment",
                    "GET  /api/blog/trending":                        "Trending posts",
                    "GET  /api/blog/watchlist":                       "Telco watchlist",
                },
            }
        })

    # ── Error Handlers ─────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"success": False, "error": "Endpoint not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"success": False, "error": "Method not allowed"}), 405

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.error(f"Internal server error: {e}")
        return jsonify({"success": False, "error": "Internal server error"}), 500

    return app
