"""
DSEC LLM Utils – Intelligent extraction and summarization helpers.
"""
import json
from typing import List, Dict, Any, Optional
from dsec.client import chat
from dsec.config import load_config

def get_best_model() -> str:
    cfg = load_config()
    return cfg.get("default_model", "deepseek-expert-r1")

def llm_extract_facts(text: str) -> List[Dict[str, Any]]:
    """
    Use LLM to extract structured facts and relationships from text.
    Returns a list of dicts: {"type": "fact|relation", "content": "...", "entities": [...]}
    """
    model = get_best_model()
    prompt = f"""
Extract key security facts and entity relationships from the following text.
Format your response as a JSON list of objects.
Each object must have:
- "type": either "fact" (a standalone observation) or "relation" (how two entities interact).
- "content": the descriptive text of the fact or relation.
- "entities": a list of specific entities involved (e.g., IPs, hostnames, usernames, CVEs, software names).

TEXT:
{text}
"""
    from dsec.config import get_next_token
    token = get_next_token()
    try:
        res = chat(prompt, model=model, token=token)
        content = res.get("content", "")
        # Basic JSON extraction
        if "[" in content and "]" in content:
            json_str = content[content.find("["):content.rfind("]")+1]
            return json.loads(json_str)
    except Exception:
        pass
    return []

def llm_summarize(text: str, focus: str = "general") -> str:
    """
    Generate a dense, information-rich summary of the provided text.
    """
    model = get_best_model()
    prompt = f"""You are summarizing a penetration testing session for context compression.
The summary will be injected back as a system message so the AI can continue the attack seamlessly.

CRITICAL: The summary MUST preserve ALL of the following (never omit):
1. TARGET: IP address, hostname, domain name
2. CREDENTIALS: every username, password, NTLM hash, Kerberos ticket found (exact values)
3. ATTACK POSITION: current foothold, compromised accounts, gained shells/access
4. COMPLETED STEPS: what was already tried and succeeded
5. FAILED APPROACHES: what was tried and failed (so AI doesn't repeat them)
6. NEXT STEP: the exact planned next action when the session continues

Additional focus: {focus}

Format your summary as structured bullet points under these headings.
Be dense and technical — preserve exact IPs, exact hashes, exact command flags, exact error messages.
Do NOT summarize away credential values or IP addresses.

CONVERSATION TO SUMMARIZE:
{text}
"""
    from dsec.config import get_next_token
    token = get_next_token()
    try:
        res = chat(prompt, model=model, token=token)
        return res.get("content", "Summary failed.")
    except Exception:
        return "Summary failed."
