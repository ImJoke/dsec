"""
DSEC Agent-Writable Skills

Lets the AI create and update skill playbooks at runtime.
Skills are stored in ~/.dsec/skills/<name>/SKILL.md (user skill dir only).

Tools:
  create_skill  — create a new skill or overwrite an existing one
  update_skill  — append content to or patch an existing skill
  list_user_skills — list skills the agent has created/modified
"""
from pathlib import Path
from dsec.core.registry import register

_USER_SKILLS_DIR = Path.home() / ".dsec" / "skills"


def _skill_path(name: str) -> Path:
    safe_name = "".join(c for c in name if c.isalnum() or c in "-_").lower()
    if not safe_name:
        raise ValueError("Invalid skill name")
    return _USER_SKILLS_DIR / safe_name / "SKILL.md"


@register(
    "create_skill",
    (
        "Create or overwrite a reusable skill/playbook in ~/.dsec/skills/.\n"
        "\n"
        "USE WHEN: You discover a repeatable exploitation technique, methodology, or\n"
        "  checklist that should be remembered for future sessions.\n"
        "\n"
        "PARAMETERS:\n"
        "  name         short identifier (alphanumeric + hyphens), e.g. 'spring-rce'\n"
        "  description  one-line description of what this skill covers\n"
        "  content      full skill content in Markdown format\n"
        "  domain       which domain this applies to: htb, bugbounty, ctf, research (optional)\n"
        "\n"
        "RETURNS: path to the written file\n"
        "\n"
        "NOTES:\n"
        "  - Only writes to ~/.dsec/skills/ (user skill dir), never bundled skills\n"
        "  - Use /skill <name> in the shell to activate a skill in the next session\n"
        "  - Use update_skill to append without overwriting\n"
    ),
)
def create_skill(
    name: str,
    description: str,
    content: str,
    domain: str = "",
) -> str:
    if not name or not name.strip():
        return "[error: 'name' is required]"
    if not content or not content.strip():
        return "[error: 'content' is required]"

    try:
        path = _skill_path(name)
    except ValueError as e:
        return f"[error: {e}]"

    path.parent.mkdir(parents=True, exist_ok=True)

    header = f"# SKILL: {name}\n\n"
    if description:
        header += f"## Description\n{description.strip()}\n\n"
    if domain:
        header += f"## Domain\n{domain.strip()}\n\n"

    full_content = header + content.strip() + "\n"

    try:
        path.write_text(full_content, encoding="utf-8")
    except OSError as e:
        return f"[error writing skill: {e}]"

    size = path.stat().st_size
    return f"[Skill '{name}' saved to '{path}' — {size} bytes. Use /skill {name} to activate.]"


@register(
    "update_skill",
    (
        "Append a section or patch an existing skill playbook.\n"
        "\n"
        "USE WHEN: You want to add new findings, steps, or corrections to an existing skill\n"
        "  without rewriting the whole thing.\n"
        "\n"
        "PARAMETERS:\n"
        "  name        name of the existing skill (same as used in create_skill)\n"
        "  append      text to append at the end of the skill file\n"
        "  old_string  (optional) existing text to find for targeted replacement\n"
        "  new_string  (optional) replacement text (used with old_string)\n"
        "\n"
        "NOTES:\n"
        "  - If old_string is provided, performs find-and-replace (first occurrence).\n"
        "  - If only append is provided, adds it to the end of the file.\n"
        "  - Use create_skill to completely overwrite.\n"
    ),
)
def update_skill(
    name: str,
    append: str = "",
    old_string: str = "",
    new_string: str = "",
) -> str:
    if not name or not name.strip():
        return "[error: 'name' is required]"
    if not append and not old_string:
        return "[error: provide 'append' or 'old_string'/'new_string']"

    try:
        path = _skill_path(name)
    except ValueError as e:
        return f"[error: {e}]"

    if not path.exists():
        return (
            f"[error: skill '{name}' not found in user skills dir. "
            "Use create_skill to create it first.]"
        )

    try:
        original = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return f"[error reading skill: {e}]"

    if old_string:
        if old_string not in original:
            snippet = "\n".join(original.splitlines()[:15])
            return (
                f"[error: old_string not found in '{name}']\n"
                f"First 15 lines:\n{snippet}"
            )
        modified = original.replace(old_string, new_string, 1)
    else:
        modified = original

    if append:
        modified = modified.rstrip() + "\n\n" + append.strip() + "\n"

    try:
        path.write_text(modified, encoding="utf-8")
    except OSError as e:
        return f"[error writing skill: {e}]"

    size = path.stat().st_size
    action = "patched" if old_string else "appended"
    return f"[Skill '{name}' {action} — {size} bytes total]"


@register(
    "list_user_skills",
    (
        "List all skills the agent has created or that live in the user skill directory.\n"
        "\n"
        "Returns a summary table of user-created skills with their names and descriptions.\n"
        "Bundled (built-in) skills are not listed here — use /skill without args in the shell.\n"
    ),
)
def list_user_skills() -> str:
    if not _USER_SKILLS_DIR.exists():
        return "[No user skills directory found — no skills created yet]"

    results = []
    for entry in sorted(_USER_SKILLS_DIR.iterdir()):
        if not entry.is_dir():
            continue
        skill_file = entry / "SKILL.md"
        if not skill_file.exists():
            continue
        try:
            text = skill_file.read_text(encoding="utf-8", errors="replace")
            desc = "(no description)"
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("##"):
                    desc = line[:100]
                    break
            size = skill_file.stat().st_size
            results.append(f"  {entry.name:<24} {size:>5} bytes  {desc}")
        except Exception:
            results.append(f"  {entry.name}  (read error)")

    if not results:
        return "[No user-created skills found in ~/.dsec/skills/]"

    header = f"User Skills ({len(results)} total in ~/.dsec/skills/):\n"
    return header + "\n".join(results)
