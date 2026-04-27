import json
import os
import uuid
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

DSEC_HOME = Path.home() / ".dsec"
JOBS_FILE = DSEC_HOME / "cron_jobs.json"

def ensure_dsec_home():
    DSEC_HOME.mkdir(parents=True, exist_ok=True)
    if not JOBS_FILE.exists():
        with open(JOBS_FILE, "w") as f:
            json.dump([], f)

def load_jobs() -> List[Dict[str, Any]]:
    ensure_dsec_home()
    try:
        with open(JOBS_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

def save_jobs(jobs: List[Dict[str, Any]]):
    ensure_dsec_home()
    with open(JOBS_FILE, "w") as f:
        json.dump(jobs, f, indent=2)

def create_job(prompt: str, schedule: str, name: Optional[str] = None, deliver: str = "local") -> Dict[str, Any]:
    job = {
        "id": str(uuid.uuid4())[:8],
        "name": name or f"Job {int(time.time())}",
        "prompt": prompt,
        "schedule": schedule,
        "deliver": deliver,
        "enabled": True,
        "created_at": datetime.now().isoformat(),
        "last_run_at": None,
        "next_run_at": None, # Will be calculated by scheduler
        "status": "pending"
    }
    jobs = load_jobs()
    jobs.append(job)
    save_jobs(jobs)
    return job

def list_jobs() -> List[Dict[str, Any]]:
    return load_jobs()

def remove_job(job_id: str) -> bool:
    jobs = load_jobs()
    new_jobs = [j for j in jobs if j["id"] != job_id]
    if len(new_jobs) == len(jobs):
        return False
    save_jobs(new_jobs)
    return True

def update_job(job_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    jobs = load_jobs()
    for job in jobs:
        if job["id"] == job_id:
            job.update(updates)
            save_jobs(jobs)
            return job
    return None
