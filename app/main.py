"""
main.py
--------
Flask application exposing:
  GET  /                -> the web UI (frontend/index.html)
  POST /api/analyze     -> {"text": "..."} -> full risk assessment JSON
  GET  /api/health       -> liveness check

Run locally with:  python -m app.main
Or via gunicorn:    gunicorn app.main:app
"""

import os
from flask import Flask, request, jsonify, send_from_directory

from app.risk_engine import assess
from app.conversation_engine import analyze_thread

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")

MAX_MESSAGE_LENGTH = 8000


@app.after_request
def add_cors_headers(response):
    # Permissive CORS so the frontend can be hosted separately (e.g. GitHub
    # Pages / Vercel) from the API (e.g. Render) if you choose to split them.
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.route("/api/analyze", methods=["OPTIONS"])
def analyze_options():
    return "", 204


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    payload = request.get_json(silent=True) or {}
    text = (payload.get("text") or "").strip()

    if not text:
        return jsonify({"error": "Please provide a non-empty 'text' field."}), 400
    if len(text) > MAX_MESSAGE_LENGTH:
        return jsonify({"error": f"Message too long (max {MAX_MESSAGE_LENGTH} characters)."}), 413

    result = assess(text)
    return jsonify(result.to_dict())


@app.route("/api/analyze_thread", methods=["OPTIONS"])
def analyze_thread_options():
    return "", 204


@app.route("/api/analyze_thread", methods=["POST"])
def analyze_thread_route():
    payload = request.get_json(silent=True) or {}
    messages = payload.get("messages")

    if not isinstance(messages, list) or not messages:
        return jsonify({"error": "Please provide a non-empty 'messages' list."}), 400
    if len(messages) > 60:
        return jsonify({"error": "Too many messages (max 60)."}), 413
    if any(len(m or "") > MAX_MESSAGE_LENGTH for m in messages):
        return jsonify({"error": f"One or more messages exceed {MAX_MESSAGE_LENGTH} characters."}), 413

    result = analyze_thread(messages)
    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
