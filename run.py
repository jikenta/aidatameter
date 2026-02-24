"""
AiTelDa Backend — Entry Point v2.0
Run with: python run.py
"""
import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "true").lower() == "true"

    print(f"\n{'='*60}")
    print(f"  AiTelDa Backend v2.0 — http://0.0.0.0:{port}")
    print(f"  Health:    http://localhost:{port}/api/health")
    print(f"  API index: http://localhost:{port}/api")
    print(f"{'='*60}")
    print(f"  Blueprints: auth · devices · ingest · disputes")
    print(f"              analytics · diagnostics · kill_switch · blog")
    print(f"{'='*60}\n")

    app.run(host="0.0.0.0", port=port, debug=debug)
