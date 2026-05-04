"""
DSEC Scope Enforcement
Validates tool execution targets against a defined bug bounty scope.
Supports exact domains, wildcards (*.example.com), IPs, and CIDR blocks.
"""
import ipaddress
import re
import threading
from typing import List

_scope_lock = threading.Lock()
_IN_SCOPE: List[str] = []
_OUT_OF_SCOPE: List[str] = []

def add_in_scope(target: str):
    """Add a target to the in-scope list."""
    normalized = target.strip().lower() if target else ""
    if normalized:
        with _scope_lock:
            if normalized not in _IN_SCOPE:
                _IN_SCOPE.append(normalized)

def add_out_of_scope(target: str):
    """Add a target to the out-of-scope list."""
    normalized = target.strip().lower() if target else ""
    if normalized:
        with _scope_lock:
            if normalized not in _OUT_OF_SCOPE:
                _OUT_OF_SCOPE.append(normalized)

def clear_scope():
    """Clear all scope definitions."""
    with _scope_lock:
        _IN_SCOPE.clear()
        _OUT_OF_SCOPE.clear()

def get_scope() -> dict:
    """Return current scope configuration."""
    with _scope_lock:
        return {"in_scope": _IN_SCOPE.copy(), "out_of_scope": _OUT_OF_SCOPE.copy()}

def _is_match(target: str, pattern: str) -> bool:
    target = target.lower()
    pattern = pattern.lower()

    # Exact match
    if target == pattern:
        return True

    # Wildcard domain (*.example.com)
    if pattern.startswith("*."):
        base_domain = pattern[2:]
        if target == base_domain or target.endswith("." + base_domain):
            return True

    # CIDR match — strip port from target (e.g. "10.10.10.5:8080" → "10.10.10.5")
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            ip_str = target.rsplit(":", 1)[0] if ":" in target and "." in target else target
            ip = ipaddress.ip_address(ip_str)
            return ip in net
        except ValueError:
            pass

    return False

_LOCAL_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]
_LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain"}


def _is_local(target: str) -> bool:
    if target.lower() in _LOCAL_HOSTNAMES:
        return True
    try:
        addr = ipaddress.ip_address(target)
        return any(addr in net for net in _LOCAL_NETWORKS)
    except ValueError:
        return False


def validate_target(target: str) -> tuple[bool, str]:
    """
    Validates if a target is allowed to be attacked.
    Returns (is_allowed, reason_string).
    """
    with _scope_lock:
        in_scope = list(_IN_SCOPE)
        out_of_scope = list(_OUT_OF_SCOPE)

    if not in_scope and not out_of_scope:
        return True, "No scope defined."

    target = target.strip().lower()

    if _is_local(target):
        return True, f"Target '{target}' is a local address (always allowed)."

    # 1. Check out of scope first (explicit deny overrides everything)
    for oos in out_of_scope:
        if _is_match(target, oos):
            return False, f"Target '{target}' matches OUT OF SCOPE rule: {oos}"

    # 2. Check in scope
    if not in_scope:
        return True, "No in-scope rules defined (only out-of-scope list exists)."

    for ins in in_scope:
        if _is_match(target, ins):
            return True, f"Target '{target}' matches IN SCOPE rule: {ins}"

    return False, f"Target '{target}' is NOT explicitly in scope."

def scan_command_for_targets(cmd: str) -> list[str]:
    """
    Extracts potential domains/IPs from a bash command using regex.
    """
    targets = []
    # Match dotted-decimal candidates, then validate each octet is 0-255
    ip_candidate_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    for candidate in re.findall(ip_candidate_pattern, cmd):
        try:
            ipaddress.ip_address(candidate)
            targets.append(candidate)
        except ValueError:
            pass

    # Match domains (basic heuristic, looks for typical domain structures)
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    targets.extend(re.findall(domain_pattern, cmd))

    return list(set(targets))
