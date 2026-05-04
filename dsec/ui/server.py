"""
DSEC Dashboard Server – Real-time visualization API.
"""
import json
import os
from pathlib import Path
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
# Restrict CORS to localhost — this dashboard exposes session content +
# knowledge graph; allowing arbitrary origins lets any visited site read it.
CORS(
    app,
    origins=[
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:3000",  # common dev frontend
        "http://127.0.0.1:3000",
    ],
)

DSEC_HOME = Path.home() / ".dsec"

# Hard cap on JSON files we read for the dashboard. Prevents OOM if a
# session/cron/graph file is corrupted or maliciously enormous.
_MAX_JSON_BYTES = 10 * 1024 * 1024  # 10 MB


def _read_json_capped(path: Path):
    """Load JSON file with a size cap. Returns None if the file exceeds the cap."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > _MAX_JSON_BYTES:
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


@app.route("/api/stats")
def get_stats():
    # Context & Memory stats
    from dsec.memory import graph_stats
    g_stats = graph_stats()

    # Sessions
    sessions_dir = DSEC_HOME / "sessions"
    sessions = []
    if sessions_dir.exists():
        for f in sessions_dir.glob("*.json"):
            sessions.append(f.stem)

    # Routines
    routines_file = DSEC_HOME / "cron_jobs.json"
    routines_count = 0
    if routines_file.exists():
        routines = _read_json_capped(routines_file) or []
        routines_count = len(routines) if isinstance(routines, list) else 0

    return jsonify({
        "knowledge_graph": g_stats,
        "active_sessions": len(sessions),
        "total_routines": routines_count,
        "uptime": "Active",
    })

@app.route("/api/graph")
def get_graph():
    graph_file = DSEC_HOME / "memory" / "knowledge_graph.json"
    if graph_file.exists():
        data = _read_json_capped(graph_file)
        if data is not None:
            return jsonify(data)
    return jsonify({"nodes": {}, "edges": []})

@app.route("/api/sessions")
def get_sessions():
    sessions_dir = DSEC_HOME / "sessions"
    data = []
    if sessions_dir.exists():
        for f in sorted(sessions_dir.glob("*.json"), key=os.path.getmtime, reverse=True)[:5]:
            s_data = _read_json_capped(f)
            if not isinstance(s_data, dict):
                continue
            try:
                data.append({
                    "name": f.stem,
                    "last_msg": s_data["history"][-1]["content"][:100] if s_data.get("history") else "No history",
                    "mtime": os.path.getmtime(f)
                })
            except (KeyError, OSError, IndexError, TypeError):
                pass
    return jsonify(data)

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory("static", path)

def run_dashboard(port=8080):
    app.run(host="127.0.0.1", port=port)
