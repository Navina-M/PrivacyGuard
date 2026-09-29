"""
main.py

Main entry point for PrivacyGuard Edge application and REST APIs.
Automatically loads environment configuration from .env if present.
"""
import os
import sys

def load_dotenv_if_exists():
    """Load key-value pairs from .env into os.environ if .env exists."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip("'\"")
                    if key and key not in os.environ:
                        os.environ[key] = value
        except Exception as e:
            print(f"Note: Error reading .env file: {e}")

# Load environment before initializing application
load_dotenv_if_exists()

# Import the configured Flask app and API routes
from app import app

# Expose app for WSGI servers (gunicorn, waitress, uwsgi)
application = app

if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "true").lower() in ("true", "1", "yes")
    print(f"🔒 Starting PrivacyGuard Edge on http://{host}:{port} (debug={debug})")
    app.run(host=host, port=port, debug=debug)
