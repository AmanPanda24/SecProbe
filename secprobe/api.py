"""
SecProbe - REST API Server (Free AI Edition)
Author: Aman Kumar Panda
"""

import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from .scanner import SecProbe

app = Flask(__name__)
CORS(app)

API_KEY_REQUIRED = os.environ.get("SECPROBE_API_KEY")


def require_api_key(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if API_KEY_REQUIRED:
            key = request.headers.get("X-API-Key") or request.args.get("api_key")
            if key != API_KEY_REQUIRED:
                return jsonify({"error": "Unauthorized", "message": "Invalid or missing API key"}), 401
        return f(*args, **kwargs)
    return decorated


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "name": "SecProbe API",
        "version": "1.0.0",
        "author": "Aman Kumar Panda",
        "description": "AI-Assisted Web Security Misconfiguration Scanner",
        "ai_providers": {
            "gemini": "Free - set GEMINI_API_KEY env var (https://aistudio.google.com/app/apikey)",
            "groq": "Free - set GROQ_API_KEY env var (https://console.groq.com/keys)",
            "offline": "Always available - no key needed",
        },
        "endpoints": {
            "POST /scan": "Run a security scan",
            "GET /health": "Health check",
            "GET /docs": "API documentation",
        },
    })


@app.route("/health", methods=["GET"])
def health():
    gemini = bool(os.environ.get("GEMINI_API_KEY"))
    groq = bool(os.environ.get("GROQ_API_KEY"))
    provider = "gemini" if gemini else ("groq" if groq else "offline")
    return jsonify({
        "status": "ok",
        "service": "SecProbe API",
        "ai_provider": provider,
        "ai_keys_configured": {"gemini": gemini, "groq": groq},
    })


@app.route("/docs", methods=["GET"])
def docs():
    return jsonify({
        "POST /scan": {
            "description": "Scan a target URL for security misconfigurations",
            "body": {
                "target": "(required) URL or domain. e.g. 'example.com'",
                "scan_ports": "(optional, bool) Enable port scanning. Default: false",
                "use_ai": "(optional, bool) Enable AI enrichment. Default: false. Uses free providers automatically.",
            },
            "ai_providers": {
                "auto_selection": "Gemini (if GEMINI_API_KEY set) → Groq (if GROQ_API_KEY set) → Offline (always)",
                "gemini_key_url": "https://aistudio.google.com/app/apikey",
                "groq_key_url": "https://console.groq.com/keys",
            },
            "example_request": {"target": "example.com", "scan_ports": False, "use_ai": True},
        }
    })


@app.route("/scan", methods=["POST"])
@require_api_key
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target")
    if not target:
        return jsonify({"error": "Bad Request", "message": "Missing required field: 'target'"}), 400

    try:
        scanner = SecProbe(
            target=target,
            scan_ports=bool(data.get("scan_ports", False)),
            use_ai=bool(data.get("use_ai", False)),
            gemini_key=os.environ.get("GEMINI_API_KEY"),
            groq_key=os.environ.get("GROQ_API_KEY"),
        )
        return jsonify(scanner.run()), 200
    except Exception as e:
        return jsonify({"error": "Scan Failed", "message": str(e)}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not Found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method Not Allowed"}), 405


def run_api():
    app.run(
        host=os.environ.get("SECPROBE_HOST", "0.0.0.0"),
        port=int(os.environ.get("SECPROBE_PORT", 5000)),
        debug=os.environ.get("SECPROBE_DEBUG", "false").lower() == "true",
    )


if __name__ == "__main__":
    run_api()
