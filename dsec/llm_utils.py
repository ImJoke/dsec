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
        # Try parsing whole response first (model may return clean JSON)
        try:
            parsed = json.loads(content.strip())
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            pass
        # Walk each "[" position and try to parse a valid array from there
        # (rfind("]") is wrong — it grabs the LAST bracket which may be in trailing text)
        pos = 0
        while True:
            start = content.find("[", pos)
            if start == -1:
                break
            depth = 0
            end = -1
            for i in range(start, len(content)):
                if content[i] == "[":
                    depth += 1
                elif content[i] == "]":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            if end == -1:
                break
            try:
                parsed = json.loads(content[start:end + 1])
                if isinstance(parsed, list):
                    return parsed
            except json.JSONDecodeError:
                pass
            pos = start + 1
    except Exception:
        pass
    return []

_MAX_SUMMARIZE_CHARS = 28_000  # ~7k tokens — safe for any DeepSeek model variant


def llm_summarize(text: str, focus: str = "general") -> str:
    """
    Generate a dense, information-rich summary of the provided text.
    """
    # Hard cap: sending >28k chars to the API causes 服务暂时不可用 / context-too-large errors
    # which then cascade into the server-error retry loop.
    # Keep the START (credentials/targets established early) and END (most recent state).
    if len(text) > _MAX_SUMMARIZE_CHARS:
        half = _MAX_SUMMARIZE_CHARS // 2
        text = (
            text[:half]
            + f"\n\n...[{len(text) - _MAX_SUMMARIZE_CHARS:,} chars omitted for length]...\n\n"
            + text[-half:]
        )
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
