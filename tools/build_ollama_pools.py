#!/usr/bin/env python3
"""
Build dsec Ollama provider pools from an OllamaHound scanner CSV.

Pipeline:
  1. Parse scan CSV → keep `vuln=patched generate=200` rows only.
  2. Per role (brain/exec/research/utility), pick endpoints that advertise
     a target model.
  3. Probe each candidate with /api/tags (HEAD-style health) → drop dead.
  4. Probe survivors with /api/chat ("ping" 1-token completion) → keep
     only those that produce a response within HARD_PROBE_TIMEOUT.
  5. Sort by latency. Take top --pool-size per role.
  6. Either print `dsec providers/roles` commands OR write directly to
     ~/.dsec/config.json (idempotent — replaces previous pool keys).

Usage:
  python3 tools/build_ollama_pools.py --csv <path> --pool-size 5
  python3 tools/build_ollama_pools.py --csv <path> --apply        # write config
  python3 tools/build_ollama_pools.py --csv <path> --dry-run       # print only

Defaults to dry-run. --apply commits to ~/.dsec/config.json.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import httpx
except ImportError:
    print("install httpx first: pip install httpx", file=sys.stderr)
    sys.exit(1)


# ── Role → preferred model substrings (most → least preferred) ───────────
# Cloud-tagged frontier models can be slow on first probe (cold-start +
# model load up to 3-5 min). CHAT_TIMEOUT=360s + num_predict=8 +
# think:false gives them room to ack with content or thinking tokens.
ROLE_MODELS: Dict[str, List[str]] = {
    "brain": [
        # Cloud frontier — strongest reasoning / planning first
        "deepseek-v4-pro:cloud",
        "kimi-k2.6:cloud",
        "deepseek-v3.1:671b-cloud",
        "kimi-k2.5:cloud",
        "deepseek-v3.2:cloud",
        "glm-5.1:cloud",
        "glm-5:cloud",
        "deepseek-v4-flash:cloud",
        # Local frontier tail-fallbacks
        "gpt-oss:120b",
        "deepseek-r1:70b",
        "qwen3:32b",
    ],
    "executor": [
        # Cloud coder specialists — biggest first
        "qwen3-coder:480b-cloud",
        "qwen3-coder-next:cloud",
        "devstral-2:123b-cloud",
        "minimax-m2:cloud",
        # Local fallbacks
        "qwen3-coder:30b",
        "qwen2.5-coder:32b",
        "devstral-small-2",
    ],
    "research": [
        # Frontier monster first
        "qwen3.5:397b-cloud",
        "kimi-k2-thinking:cloud",
        "qwen3.6:35b",
        "qwen3.5:cloud",
        "glm-4.7:cloud",
        "glm-4.6:cloud",
        "gpt-oss:120b-cloud",
        # Local fallbacks
        "qwen3.6:27b",
        "qwen3:14b",
        "gpt-oss:20b",
    ],
    "utility": [
        # Newest minimax first (m2.7 has 96 hosts, supersedes m2.5)
        "minimax-m2.7:cloud",
        "minimax-m2.5:cloud",
        "gemini-3-flash-preview:cloud",
        "minimax-m2:cloud",
        "gpt-oss:20b-cloud",
        # Local fallbacks
        "qwen3:8b",
        "llama3.2:3b",
    ],
}

PROBE_TIMEOUT = 5.0       # /api/tags health check
CHAT_TIMEOUT = 360.0      # /api/chat — frontier MoE cold-start can take 3-5min on first hit
HARD_PROBE_TIMEOUT = 480.0  # outer cap
DEFAULT_POOL_SIZE = 5
MAX_WORKERS = 50


@dataclass
class Endpoint:
    url: str
    matched_model: str   # exact model name on this endpoint
    role: str
    health_ok: bool = False
    chat_ok: bool = False
    chat_latency_s: float = 0.0
    error: Optional[str] = None


# ── CSV parsing ──────────────────────────────────────────────────────────


def load_scan(csv_path: Path) -> List[Dict[str, str]]:
    with open(csv_path) as f:
        return list(csv.DictReader(f))


def usable_rows(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    return [
        r for r in rows
        if r.get("vuln") == "patched" and r.get("generate") == "200"
        and r.get("models")
    ]


def find_candidates_for_role(
    rows: List[Dict[str, str]], role: str, max_per_model: int = 30
) -> List[Endpoint]:
    """Return candidate endpoints for a role, ordered by model preference."""
    out: List[Endpoint] = []
    seen_urls: set = set()
    for model_pref in ROLE_MODELS[role]:
        per_model_count = 0
        for r in rows:
            ip = r["ip"].strip()
            port = r.get("port", "11434").strip() or "11434"
            url = f"http://{ip}:{port}"
            if url in seen_urls:
                continue
            models_str = r.get("models", "")
            # match by substring
            matched = None
            for m in models_str.split(","):
                m = m.strip()
                if model_pref in m:
                    matched = m
                    break
            if matched:
                out.append(Endpoint(url=url, matched_model=matched, role=role))
                seen_urls.add(url)
                per_model_count += 1
                if per_model_count >= max_per_model:
                    break
    return out


# ── Probes ───────────────────────────────────────────────────────────────


def probe_health(ep: Endpoint, client: httpx.Client) -> None:
    try:
        r = client.get(f"{ep.url}/api/tags", timeout=PROBE_TIMEOUT)
        ep.health_ok = r.status_code == 200
        if not ep.health_ok:
            ep.error = f"tags HTTP {r.status_code}"
    except Exception as exc:
        ep.error = f"tags: {type(exc).__name__}"


def probe_chat(ep: Endpoint, client: httpx.Client) -> None:
    if not ep.health_ok:
        return
    payload = {
        "model": ep.matched_model,
        "messages": [{"role": "user", "content": "hi"}],
        "stream": False,
        # num_predict=8 leaves room for content after thinking models
        # burn budget on reasoning tokens. think:false asks Ollama to
        # skip thinking on supported models — harmless on others.
        "options": {"num_predict": 8, "temperature": 0, "think": False},
    }
    t0 = time.time()
    try:
        r = client.post(f"{ep.url}/api/chat", json=payload, timeout=CHAT_TIMEOUT)
        ep.chat_latency_s = time.time() - t0
        if r.status_code != 200:
            ep.error = f"chat HTTP {r.status_code}"
            return
        data = r.json()
        msg = data.get("message") or {}
        content = msg.get("content") or ""
        thinking = msg.get("thinking") or ""
        if content.strip() or thinking.strip():
            ep.chat_ok = True
        else:
            ep.error = "chat: empty response"
    except Exception as exc:
        ep.error = f"chat: {type(exc).__name__}"
        ep.chat_latency_s = time.time() - t0


def probe_one(ep: Endpoint) -> Endpoint:
    with httpx.Client(verify=False) as client:
        probe_health(ep, client)
        probe_chat(ep, client)
    return ep


def probe_all(endpoints: List[Endpoint]) -> List[Endpoint]:
    print(f"  probing {len(endpoints)} endpoints (concurrency={MAX_WORKERS}, "
          f"chat-timeout={CHAT_TIMEOUT:.0f}s)...", flush=True)
    print(f"  frontier-MoE cold-start can take 1-2 min — be patient.", flush=True)
    out: List[Endpoint] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(probe_one, ep): ep for ep in endpoints}
        done = 0
        for fut in as_completed(futures, timeout=HARD_PROBE_TIMEOUT * 2):
            try:
                ep = fut.result()
                out.append(ep)
                if ep.chat_ok:
                    print(f"    ✓ {ep.url}  →  {ep.matched_model}  "
                          f"({ep.chat_latency_s:.1f}s)", flush=True)
                elif ep.error:
                    print(f"    ✗ {ep.url}  →  {ep.matched_model}  "
                          f"[{ep.error}]", flush=True)
            except Exception as exc:
                print(f"    ✗ probe crashed: {type(exc).__name__}: {exc}", flush=True)
            done += 1
            if done % 10 == 0 or done == len(endpoints):
                ok = sum(1 for e in out if e.chat_ok)
                print(f"    [{done}/{len(endpoints)} probed, {ok} chat-ok]", flush=True)
    return out


def _pick_best_model(
    chat_ok: List[Endpoint], role: str, pool_size: int, min_endpoints: int = 2
) -> Tuple[str, List[Endpoint]]:
    """Pick the highest-priority ROLE_MODELS entry that has enough endpoints.

    Walk ROLE_MODELS[role] in declared order. For each preferred substring,
    collect endpoints whose matched_model contains it. Take the first
    preference that yields >= min_endpoints (so the pool has redundancy).
    Sort that group by latency, return top pool_size.

    If no preference meets min_endpoints, fall back to the largest group
    (so we still produce a usable pool from whatever survived). Worst-case:
    return [] if no chat-ok endpoints exist.
    """
    if not chat_ok:
        return "", []

    by_model: Dict[str, List[Endpoint]] = {}
    for ep in chat_ok:
        by_model.setdefault(ep.matched_model, []).append(ep)

    prefs = ROLE_MODELS.get(role, [])
    # Walk priorities; first one with enough endpoints wins.
    for pref in prefs:
        eps: List[Endpoint] = []
        chosen_model = ""
        for model_key, group in by_model.items():
            if pref in model_key:
                eps.extend(group)
                # Stable winner: smallest model_key string for determinism
                # when multiple variants match (e.g. ":cloud" vs ":latest")
                if not chosen_model or len(model_key) < len(chosen_model):
                    chosen_model = model_key
        if len(eps) >= min_endpoints:
            # Restrict to a single advertised model name so pool is uniform
            uniform = [e for e in eps if e.matched_model == chosen_model]
            uniform.sort(key=lambda e: e.chat_latency_s)
            return chosen_model, uniform[:pool_size]

    # No preference met threshold — fall back to largest single-model group.
    largest = max(by_model.items(), key=lambda kv: len(kv[1]))
    largest[1].sort(key=lambda e: e.chat_latency_s)
    return largest[0], largest[1][:pool_size]


RoleResult = Tuple[str, List[Endpoint]]  # (model, endpoints)


def render_shell_commands(pools: Dict[str, RoleResult]) -> str:
    lines: List[str] = []
    role_to_provider_key = {
        "brain": "brain_pool",
        "executor": "exec_pool",
        "research": "research_pool",
        "utility": "util_pool",
    }
    for role, (model, endpoints) in pools.items():
        if not endpoints:
            lines.append(f"# {role}: no working endpoints found, skipped")
            continue
        provider_key = role_to_provider_key[role]
        endpoints_csv = ",".join(ep.url for ep in endpoints)
        lines.append(
            f"dsec providers add {provider_key} --type ollama --model '{model}' \\"
        )
        lines.append(f"  --endpoints '{endpoints_csv}' --fallback deepseek")
        lines.append(
            f"dsec roles set {role} --provider {provider_key} --fallback deepseek"
        )
        lines.append("")
    lines.append("dsec config --set enable_multi_agent true")
    return "\n".join(lines)


def apply_to_config(pools: Dict[str, RoleResult]) -> None:
    config_path = Path.home() / ".dsec" / "config.json"
    if not config_path.exists():
        print(f"  config not found at {config_path}; run dsec once first", file=sys.stderr)
        sys.exit(2)
    cfg = json.loads(config_path.read_text())
    cfg.setdefault("providers", {})
    cfg.setdefault("roles", {})

    role_to_provider_key = {
        "brain": "brain_pool",
        "executor": "exec_pool",
        "research": "research_pool",
        "utility": "util_pool",
    }
    for role, (model, endpoints) in pools.items():
        if not endpoints:
            continue
        provider_key = role_to_provider_key[role]
        cfg["providers"][provider_key] = {
            "type": "ollama",
            "model": model,
            "endpoints": [ep.url for ep in endpoints],
            "fallback": "deepseek",
        }
        cfg["roles"][role] = {"provider": provider_key, "fallback": "deepseek"}

    cfg["enable_multi_agent"] = True

    # Backup current config first.
    backup = config_path.with_suffix(".json.bak")
    backup.write_text(config_path.read_text())
    # Atomic write: write to temp file in same dir, then os.replace().
    # If the write fails partway, config.json keeps prior content.
    import os
    tmp_path = config_path.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(cfg, indent=2) + "\n")
    os.replace(tmp_path, config_path)
    print(f"  config written to {config_path}")
    print(f"  backup at {backup}")


# ── Main ─────────────────────────────────────────────────────────────────


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True, help="OllamaHound scanner CSV path")
    p.add_argument("--pool-size", type=int, default=DEFAULT_POOL_SIZE,
                   help="Endpoints per role pool (default: 5)")
    p.add_argument("--apply", action="store_true",
                   help="Write to ~/.dsec/config.json (default: dry-run)")
    p.add_argument("--candidates-per-role", type=int, default=30,
                   help="Candidates probed per role before pool selection (default: 30)")
    p.add_argument("--roles", nargs="*", choices=list(ROLE_MODELS),
                   default=list(ROLE_MODELS),
                   help="Roles to build pools for (default: all)")
    args = p.parse_args()

    csv_path = Path(args.csv).expanduser()
    if not csv_path.exists():
        print(f"CSV not found: {csv_path}", file=sys.stderr)
        return 1

    print(f"[1/3] loading {csv_path}")
    rows = load_scan(csv_path)
    use = usable_rows(rows)
    print(f"    {len(rows)} total → {len(use)} usable (patched + generate=200)")

    pools: Dict[str, RoleResult] = {}
    for role in args.roles:
        print(f"[2/3] role={role}")
        candidates = find_candidates_for_role(use, role,
                                              max_per_model=args.candidates_per_role)
        print(f"    {len(candidates)} candidates")
        if not candidates:
            pools[role] = ("", [])
            continue
        probed = probe_all(candidates)
        chat_ok = [e for e in probed if e.chat_ok]
        model, winners = _pick_best_model(chat_ok, role, args.pool_size)
        print(f"    {len(chat_ok)} chat-ok, "
              f"selected model={model!r}, kept {len(winners)} endpoints:")
        for e in winners:
            print(f"      ✓ {e.url}  →  {e.matched_model}  ({e.chat_latency_s:.1f}s)")
        pools[role] = (model, winners)

    print(f"\n[3/3] result")
    if args.apply:
        apply_to_config(pools)
        print("\nRestart dsec to pick up new config:")
        print("  Ctrl+D from current shell, then dsec --session NAME ...")
    else:
        print("---")
        print(render_shell_commands(pools))
        print("---")
        print("(dry-run; pass --apply to write directly to ~/.dsec/config.json)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
