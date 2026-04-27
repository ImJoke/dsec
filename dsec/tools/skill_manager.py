"""
DSEC Skill Manager Tool — Learning Loop

Allows the agent to write newly learned methodologies to disk as permanent SKILL.md files.
This enables the agent to "learn" from successful engagements.
"""
import os
from pathlib import Path
from typing import List

from dsec.core.registry import register


@register(
    "save_skill",
    "Save a newly learned security methodology as a permanent skill. "
    "Use this when you successfully execute a complex attack path and want to document it "
    "for future sessions. Trigger phrases will cause this skill to auto-load when the user mentions them."
)
def save_skill(name: str, description: str, trigger_phrases: List[str], methodology_markdown: str) -> str:
    """
    Saves a skill to ~/.dsec/skills/<name>/SKILL.md
    
    Args:
        name: A short, hyphenated name for the skill (e.g., 'cve-2024-1234', 'custom-pivot-technique').
        description: A 1-2 sentence description of the skill.
        trigger_phrases: A list of 3-5 keywords that should trigger this skill to load.
        methodology_markdown: The actual checklist/methodology formatted in Markdown.
    """
    try:
        user_skills_dir = Path(os.path.expanduser("~/.dsec/skills"))
        
        # Format the skill name safely
        safe_name = "".join(c if c.isalnum() or c == "-" else "-" for c in name.lower()).strip("-")
        if not safe_name:
            return "Error: Invalid skill name provided."
            
        skill_dir = user_skills_dir / safe_name
        skill_dir.mkdir(parents=True, exist_ok=True)
        
        skill_file = skill_dir / "SKILL.md"
        
        # Build the structured markdown
        content = [
            f"# SKILL: {name.replace('-', ' ').title()}",
            "",
            "## Description",
            description,
            "",
            "## Trigger Phrases",
            ", ".join(trigger_phrases),
            "",
            "## Methodology",
            methodology_markdown
        ]
        
        skill_file.write_text("\n".join(content), encoding="utf-8")
        
        # Important: we must also update the running _TRIGGER_PHRASES in the loader
        # so it's immediately available without restarting.
        try:
            from dsec.skills.loader import _TRIGGER_PHRASES
            _TRIGGER_PHRASES[safe_name] = [p.lower() for p in trigger_phrases]
        except ImportError:
            pass # Loader might not be fully initialized yet, that's fine
            
        return f"Successfully saved new skill '{safe_name}' to {skill_file}. It will now be available in future sessions."
        
    except Exception as e:
        return f"Failed to save skill: {e}"
