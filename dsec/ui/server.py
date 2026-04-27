"""
DSEC Dashboard Server – Real-time visualization API.
"""
import json
import os
from pathlib import Path
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DSEC_HOME = Path.home() / ".dsec"

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
        routines = json.loads(routines_file.read_text())
        routines_count = len(routines)

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
        return jsonify(json.loads(graph_file.read_text()))
    return jsonify({"nodes": {}, "edges": []})

@app.route("/api/sessions")
def get_sessions():
    sessions_dir = DSEC_HOME / "sessions"
    data = []
    if sessions_dir.exists():
        for f in sorted(sessions_dir.glob("*.json"), key=os.path.getmtime, reverse=True)[:5]:
            try:
                s_data = json.loads(f.read_text())
                data.append({
                    "name": f.stem,
                    "last_msg": s_data["history"][-1]["content"][:100] if s_data.get("history") else "No history",
                    "mtime": os.path.getmtime(f)
                })
            except (json.JSONDecodeError, KeyError, OSError):
                pass
    return jsonify(data)

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory("static", path)

def run_dashboard(port=8080):
    app.run(host="0.0.0.0", port=port)
