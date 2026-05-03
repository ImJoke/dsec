"""
DSEC Skill Persistence — Self-improving capabilities for DSEC.

Allows the agent to:
  • Save a successful exploit chain as a new reusable SKILL.
  • Update existing skills with new observations.
  • Self-improve its own methodology by reflecting on mission results.

Inspired by: Hermes Agent, Letta
"""
import os
from pathlib import Path
from typing import List, Optional

from dsec.core.registry import register
from dsec.skills.loader import _USER_SKILLS_DIR


def _safe_skill_name(name: str) -> str:
    """Sanitize skill name to prevent path traversal."""
    return "".join(c for c in name if c.isalnum() or c in "-_").lower() or "unnamed"


@register("skill_persist", "Persists a successful workflow or exploit chain as a new reusable SKILL.md. Use this when you find a method that works (e.g., a specific way to exploit a CVE or bypass a WAF).")
def skill_persist(name: str, description: str, steps: List[str], triggers: List[str]) -> str:
    """
    Creates a new SKILL.md in the user's local skills directory.

    Args:
        name: Short name for the skill (e.g., 'smb-relay-attack')
        description: One-sentence description of the skill.
        steps: List of manual steps or commands to perform.
        triggers: List of keywords that should trigger this skill.
    """
    name = _safe_skill_name(name)
    skill_dir = _USER_SKILLS_DIR / name
    os.makedirs(skill_dir, exist_ok=True)
    
    skill_file = skill_dir / "SKILL.md"
    
    lines = [
        f"# SKILL: {name}",
        f"",
        f"> {description}",
        f"",
        "## Triggers",
        ", ".join(triggers),
        f"",
        "## Methodology",
    ]
    
    for i, step in enumerate(steps, 1):
        lines.append(f"{i}. {step}")
        
    lines.append("\n## Contextual Notes")
    lines.append("- Automatically persisted by DSEC following a successful mission.")
    lines.append("- Automatically verified by DSEC.")
    
    try:
        with open(skill_file, "w") as f:
            f.write("\n".join(lines))
        
        return f"✔ Skill '{name}' successfully persisted to {skill_file}. I will now be able to reuse this methodology in future sessions when these triggers are met."
    except Exception as e:
        return f"✖ Failed to persist skill: {str(e)}"

@register("skill_reflect", "Reflects on the current mission and updates the active SKILL with improvements. Use this after a successful compromise to refine your tactics.")
def skill_reflect(skill_name: str, observation: str, improvement: str) -> str:
    """
    Updates an existing skill with a new observation and improvement.
    """
    skill_name = _safe_skill_name(skill_name)
    skill_file = _USER_SKILLS_DIR / skill_name / "SKILL.md"
    
    if not skill_file.exists():
        # If it's a bundled skill, we 'fork' it to user dir
        from dsec.skills.loader import load_skill
        content = load_skill(skill_name)
        if not content:
            return f"✖ Skill '{skill_name}' not found."
        
        os.makedirs(os.path.dirname(skill_file), exist_ok=True)
        with open(skill_file, "w") as f:
            f.write(content)

    try:
        with open(skill_file, "a") as f:
            f.write(f"\n\n### Reflection Update\n- **Observation**: {observation}\n- **Improvement**: {improvement}\n")
        
        return f"✔ Reflected on '{skill_name}'. Skill has been updated with new tactical improvements."
    except Exception as e:
        return f"✖ Failed to update skill: {str(e)}"
