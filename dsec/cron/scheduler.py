import time
import logging
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional
import re

from dsec.cron.jobs import load_jobs, save_jobs, update_job

logger = logging.getLogger(__name__)

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
    """Calculate the next run time based on the schedule string."""
    now = datetime.now()
    schedule = schedule.strip().lower()

    # Interval: "every 30m"
    if schedule.startswith("every "):
        duration_str = schedule[6:].strip()
        minutes = parse_duration(duration_str)
        if minutes is None:
            return None
        
        if last_run_at:
            last_run = datetime.fromisoformat(last_run_at)
            return last_run + timedelta(minutes=minutes)
        else:
            return now # Run immediately on creation if never run

    # One-shot duration: "30m" (run once in 30 minutes)
    minutes = parse_duration(schedule)
    if minutes is not None:
        if last_run_at:
            return None # Already run once
        return now + timedelta(minutes=minutes)

    # Specific ISO timestamp
    try:
        dt = datetime.fromisoformat(schedule)
        if last_run_at:
            return None
        return dt
    except ValueError:
        pass

    return None

def run_job(job: Dict[str, Any]):
    """Execute the job by calling dsec CLI."""
    logger.info(f"Running job {job['id']}: {job['name']}")
    
    # We run dsec in a subprocess to ensure it's a fresh session
    # Usage: dsec run "<prompt>" --deliver <target>
    cmd = [sys.executable, "-m", "dsec.cli", "run", job["prompt"], "--deliver", job.get("deliver", "local")]
    
    try:
        # Update status to running
        update_job(job["id"], {"status": "running", "last_run_at": datetime.now().isoformat()})
        
        # Execute
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        status = "ok" if result.returncode == 0 else "error"
        error_msg = result.stderr if result.returncode != 0 else None
        
        # Calculate next run
        next_run = calculate_next_run(job["schedule"], datetime.now().isoformat())
        
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
    now = datetime.now()
    
    for job in jobs:
        if not job.get("enabled", True):
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

        next_run_dt = datetime.fromisoformat(next_run_str)
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
