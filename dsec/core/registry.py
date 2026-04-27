import inspect
import json
from typing import Any, Callable, Dict, List, Optional

_REGISTRY: Dict[str, Dict[str, Any]] = {}

def register(name: str, description: str):
    """
    Decorator to register a Python function as a tool for the agent.
    
    The function's docstring and type hints are automatically parsed to build
    the JSON schema for the tool.
    """
    def decorator(func: Callable) -> Callable:
        sig = inspect.signature(func)
        properties = {}
        required = []
        
        for param_name, param in sig.parameters.items():
            if param_name == "self":
                continue
                
            param_type = "string"
            if param.annotation is int:
                param_type = "integer"
            elif param.annotation is bool:
                param_type = "boolean"
            elif param.annotation is float:
                param_type = "number"
                
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
            "func": func
        }
        return func
    return decorator

def get_tool(name: str) -> Optional[Dict[str, Any]]:
    return _REGISTRY.get(name)

def list_tools() -> List[Dict[str, Any]]:
    return list(_REGISTRY.values())

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

def call_tool(name: str, arguments: Dict[str, Any]) -> Any:
    tool = get_tool(name)
    if not tool:
        raise ValueError(f"Unknown tool: {name}")
    
    return tool["func"](**arguments)

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
