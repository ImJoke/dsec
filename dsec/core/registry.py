import inspect
import json
from typing import Any, Callable, Dict, List, Optional, Tuple

_REGISTRY: Dict[str, Dict[str, Any]] = {}

# Default role membership when a tool is registered without an explicit
# `roles=` argument. Keeps the legacy single-agent flow seeing every tool.
_DEFAULT_ROLES: Tuple[str, ...] = ("brain", "research", "executor")


def register(
    name: str,
    description: str,
    *,
    roles: Optional[Tuple[str, ...]] = None,
):
    """
    Decorator to register a Python function as a tool for the agent.

    The function's docstring and type hints are automatically parsed to build
    the JSON schema for the tool. The optional `roles` argument restricts
    which agent roles (brain / research / executor) can see and call this
    tool. Default = all three roles.
    """
    role_set: Tuple[str, ...] = tuple(roles) if roles else _DEFAULT_ROLES

    def decorator(func: Callable) -> Callable:
        sig = inspect.signature(func)
        properties = {}
        required = []

        for param_name, param in sig.parameters.items():
            if param_name == "self":
                continue
            if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
                continue

            param_type = "string"
            ann = param.annotation
            if ann is int:
                param_type = "integer"
            elif ann is bool:
                param_type = "boolean"
            elif ann is float:
                param_type = "number"
            elif ann is list or getattr(ann, "__origin__", None) is list:
                param_type = "array"
            elif ann is dict or getattr(ann, "__origin__", None) is dict:
                param_type = "object"

            properties[param_name] = {
                "type": param_type,
                "description": f"Parameter {param_name}"
            }

            if param.default is inspect.Parameter.empty:
                required.append(param_name)

        schema = {
            "type": "object",
            "properties": properties,
            "required": required
        }

        _REGISTRY[name] = {
            "name": name,
            "description": description,
            "schema": schema,
            "func": func,
            "roles": role_set,
        }
        return func
    return decorator

def get_tool(name: str) -> Optional[Dict[str, Any]]:
    return _REGISTRY.get(name)

def list_tools() -> List[Dict[str, Any]]:
    return list(_REGISTRY.values())


def list_tools_for_role(role: str) -> List[Dict[str, Any]]:
    """Return tools whose role-set includes `role`."""
    return [t for t in _REGISTRY.values() if role in t.get("roles", _DEFAULT_ROLES)]


def get_registry_as_openai() -> List[Dict[str, Any]]:
    """Returns the tools formatted as OpenAI function definitions."""
    tools = []
    for tool_data in _REGISTRY.values():
        tools.append({
            "type": "function",
            "function": {
                "name": tool_data["name"],
                "description": tool_data["description"],
                "parameters": tool_data["schema"]
            }
        })
    return tools

def call_tool(
    name: str,
    arguments: Dict[str, Any],
    *,
    caller_role: Optional[str] = None,
) -> Any:
    tool = get_tool(name)
    if not tool:
        raise ValueError(f"Unknown tool: {name}")

    if caller_role is not None:
        allowed = tool.get("roles", _DEFAULT_ROLES)
        if caller_role not in allowed:
            return (
                f"[error: tool '{name}' is not available to role '{caller_role}'. "
                f"Allowed roles: {list(allowed)}]"
            )

    # Defensive: model occasionally emits arguments as a string ("{}" without
    # parsing), a list, or None. Coerce to {} so the alias/required logic
    # below doesn't crash with AttributeError on .keys() / TypeError on dict().
    if not isinstance(arguments, dict):
        arguments = {}

    # Resolve common argument aliases before dispatch so the AI doesn't have
    # to remember exact parameter names for every tool.
    # Maps alias → canonical name (only applied when canonical is missing).
    _ALIASES: Dict[str, str] = {
        "filepath": "path", "file_path": "path",       # programmer_create_file → write_file
        "text": "content", "file_content": "content", "body": "content",
        "cmd": "command",                               # background tool
        "id": "job_id", "pane": "job_id", "pane_id": "job_id",
    }
    required = tool["schema"].get("required", [])
    # Unwrap double-nested arguments: model sometimes outputs {"arguments": {...}}
    # instead of the flat param dict directly.
    if list(arguments.keys()) == ["arguments"] and isinstance(arguments.get("arguments"), dict):
        arguments = arguments["arguments"]
    resolved = dict(arguments)
    for alias, canonical in _ALIASES.items():
        if alias in resolved and canonical not in resolved:
            resolved[canonical] = resolved.pop(alias)

    # Check required params and return a friendly error instead of a raw TypeError.
    missing = [r for r in required if r not in resolved]
    if missing:
        params = ", ".join(f"{k}" for k in tool["schema"]["properties"])
        return (
            f"[error: '{name}' missing required argument(s): {missing}. "
            f"Required params: {required}. All params: {params}]"
        )

    try:
        return tool["func"](**resolved)
    except TypeError as e:
        return f"[error: {name}() call failed — {e}]"

def build_tools_system_prompt() -> str:
    """Builds a system prompt string explaining the available Python tools."""
    if not _REGISTRY:
        return ""

    lines = ["[AVAILABLE NATIVE TOOLS]"]
    for tool in _REGISTRY.values():
        lines.append(f"  {tool['name']}: {tool['description']}")
        if tool["schema"]["properties"]:
            lines.append(f"    params: {json.dumps(tool['schema']['properties'])}")
    lines.append("[END NATIVE TOOLS]")
    return "\n".join(lines)


def build_tools_system_prompt_for_role(role: str) -> str:
    """Builds the system prompt section listing only tools available to the given role."""
    tools_for_role = list_tools_for_role(role)
    if not tools_for_role:
        return ""

    lines = [f"[AVAILABLE NATIVE TOOLS — role={role}]"]
    for tool in tools_for_role:
        lines.append(f"  {tool['name']}: {tool['description']}")
        if tool["schema"]["properties"]:
            lines.append(f"    params: {json.dumps(tool['schema']['properties'])}")
    lines.append("[END NATIVE TOOLS]")
    return "\n".join(lines)
