import time
import logging
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional
import re

from dsec.cron.jobs import load_jobs, save_jobs, update_job

logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    """Aware UTC timestamp. All scheduler comparisons use UTC to avoid DST and
    timezone-shift bugs that would fire jobs twice or skip them entirely."""
    return datetime.now(timezone.utc)


def _parse_iso(s: str) -> Optional[datetime]:
    """Parse an ISO timestamp; coerce naive values to UTC for comparison safety."""
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt

def parse_duration(s: str) -> Optional[int]:
    """Parse duration like '30m', '2h', '1d' into minutes."""
    s = s.strip().lower()
    match = re.match(r'^(\d+)\s*(m|h|d)$', s)
    if not match:
        return None
    value = int(match.group(1))
    unit = match.group(2)
    multipliers = {'m': 1, 'h': 60, 'd': 1440}
    return value * multipliers[unit]

def calculate_next_run(schedule: str, last_run_at: Optional[str] = None) -> Optional[datetime]:
    """Calculate the next run time based on the schedule string. Returns aware UTC."""
    now = _now_utc()
    schedule = schedule.strip().lower()

    # Interval: "every 30m"
    if schedule.startswith("every "):
        duration_str = schedule[6:].strip()
        minutes = parse_duration(duration_str)
        if minutes is None:
            return None

        if last_run_at:
            last_run = _parse_iso(last_run_at)
            if last_run is None:
                return now
            return last_run + timedelta(minutes=minutes)
        return now  # Run immediately on creation if never run

    # One-shot duration: "30m" (run once in 30 minutes)
    minutes = parse_duration(schedule)
    if minutes is not None:
        if last_run_at:
            return None  # Already run once
        return now + timedelta(minutes=minutes)

    # Specific ISO timestamp
    parsed = _parse_iso(schedule)
    if parsed is not None:
        if last_run_at:
            return None
        return parsed

    return None

def run_job(job: Dict[str, Any]):
    """Execute the job by calling dsec CLI."""
    logger.info(f"Running job {job['id']}: {job['name']}")
    
    # We run dsec in a subprocess to ensure it's a fresh session
    # Usage: dsec run "<prompt>" --deliver <target>
    cmd = [sys.executable, "-m", "dsec.cli", "run", job["prompt"], "--deliver", job.get("deliver", "local")]
    
    try:
        # Update status to running
        update_job(job["id"], {"status": "running", "last_run_at": _now_utc().isoformat()})

        # Execute
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        status = "ok" if result.returncode == 0 else "error"
        error_msg = result.stderr if result.returncode != 0 else None

        # Calculate next run
        next_run = calculate_next_run(job["schedule"], _now_utc().isoformat())
        
        update_job(job["id"], {
            "status": status,
            "last_error": error_msg,
            "next_run_at": next_run.isoformat() if next_run else None,
            "enabled": next_run is not None
        })
        
        logger.info(f"Job {job['id']} finished with status: {status}")
        
    except Exception as e:
        logger.error(f"Failed to run job {job['id']}: {e}")
        update_job(job["id"], {"status": "error", "last_error": str(e)})

def tick():
    """Check all jobs and run those that are due."""
    jobs = load_jobs()
    now = _now_utc()

    for job in jobs:
        if not job.get("enabled", True):
            continue
        if job.get("status") == "running":
            continue

        next_run_str = job.get("next_run_at")
        if not next_run_str:
            # Initialize next_run_at if missing
            next_run = calculate_next_run(job["schedule"], job.get("last_run_at"))
            if next_run:
                update_job(job["id"], {"next_run_at": next_run.isoformat()})
                next_run_str = next_run.isoformat()
            else:
                continue

        next_run_dt = _parse_iso(next_run_str)
        if next_run_dt is None:
            continue
        if next_run_dt <= now:
            run_job(job)

def main():
    logging.basicConfig(level=logging.INFO)
    logger.info("DSEC Cron Scheduler started.")
    try:
        while True:
            tick()
            time.sleep(10) # Check every 10 seconds
    except KeyboardInterrupt:
        logger.info("Scheduler stopped.")

if __name__ == "__main__":
    main()
