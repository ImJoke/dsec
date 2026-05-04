import json
from dsec.core.registry import register
from dsec.cron import jobs
from typing import Optional

@register(
    name="dsec_cron_create",
    description="Schedule a new background task (routine). Schedule can be 'every 1h', 'every 30m', '2h' (one-shot), or ISO timestamp.",
    roles=("brain",),
)
def dsec_cron_create(prompt: str, schedule: str, name: Optional[str] = None, deliver: str = "local"):
    try:
        job = jobs.create_job(prompt, schedule, name, deliver)
        return json.dumps({"success": True, "job": job})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})

@register(
    name="dsec_cron_list",
    description="List all scheduled background tasks.",
    roles=("brain",),
)
def dsec_cron_list():
    try:
        all_jobs = jobs.list_jobs()
        return json.dumps({"success": True, "jobs": all_jobs})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})

@register(
    name="dsec_cron_remove",
    description="Remove a scheduled background task by its ID.",
    roles=("brain",),
)
def dsec_cron_remove(job_id: str):
    try:
        success = jobs.remove_job(job_id)
        return json.dumps({"success": success, "message": "Job removed" if success else "Job not found"})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})
