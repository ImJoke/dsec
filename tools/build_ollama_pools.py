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
# Cloud-tagged frontier models work — they're just SLOW on first probe
# (cold-start + model load can take 60-120s). With CHAT_TIMEOUT bumped
# to 180s + num_predict=1, they have time to respond.
ROLE_MODELS: Dict[str, List[str]] = {
    "brain": [
        # Frontier cloud (best long-horizon planning)
        "glm-5.1",
        "deepseek-v4-pro",
        "kimi-k2.6",
        "deepseek-v3.2",
        "kimi-k2.5",
        "glm-5",
        # Local frontier (fallback — usually faster cold-start)
        "gpt-oss:120b",
        "qwen3:32b",
        "deepseek-r1:70b",
        "deepseek-r1:32b",
        "qwq:32b",
    ],
    "executor": [
        "qwen3-coder-next",
        "qwen3-coder:480b",
        "devstral-2:123b",
        "minimax-m2.7",
        "qwen3-coder:30b",
        "qwen3-coder:14b",
        "qwen2.5-coder:32b",
        "devstral-small-2",
    ],
    "research": [
        "qwen3.6:35b",
        "qwen3.6:27b",
        "glm-4.7-flash",
        "gpt-oss:20b",
        "magistral:24b",
        "qwen3:32b",
        "qwen3:14b",
    ],
    "utility": [
        "qwen3:8b",
        "qwen3:4b",
        "granite4:8b",
        "granite4:3b",
        "lfm2.5-thinking:1.2b",
        "llama3.2:3b",
    ],
}

PROBE_TIMEOUT = 5.0       # /api/tags health check
CHAT_TIMEOUT = 180.0      # /api/chat — frontier MoE cold-start can take 1-2min
HARD_PROBE_TIMEOUT = 240.0  # outer cap
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
        # 1 token = fastest possible ack. We just want to confirm the
        # endpoint can complete a chat turn for THIS model — content
        # quality is irrelevant.
        "options": {"num_predict": 1, "temperature": 0},
    }
    t0 = time.time()
    try:
        r = client.post(f"{ep.url}/api/chat", json=payload, timeout=CHAT_TIMEOUT)
        ep.chat_latency_s = time.time() - t0
        if r.status_code != 200:
            ep.error = f"chat HTTP {r.status_code}"
            return
        data = r.json()
        content = (data.get("message") or {}).get("content", "")
        if content:
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
                # Live progress — print each chat-OK as it lands
                if ep.chat_ok:
                    print(f"    ✓ {ep.url}  →  {ep.matched_model}  "
                          f"({ep.chat_latency_s:.1f}s)", flush=True)
            except Exception:
                pass
            done += 1
            if done % 10 == 0 or done == len(endpoints):
                ok = sum(1 for e in out if e.chat_ok)
                print(f"    [{done}/{len(endpoints)} probed, {ok} chat-ok]", flush=True)
    return out


def winnow(endpoints: List[Endpoint], pool_size: int) -> List[Endpoint]:
    """Keep only chat_ok=True; sort by latency; take pool_size."""
    alive = [e for e in endpoints if e.chat_ok]
    alive.sort(key=lambda e: e.chat_latency_s)
    return alive[:pool_size]


# ── Output ───────────────────────────────────────────────────────────────


def _pick_majority_model(pool: List[Endpoint]) -> Tuple[str, List[Endpoint]]:
    """Pick the most-common model in pool; filter pool to only that model.

    A dsec provider pool advertises ONE model — all endpoints must serve
    it. Picking the majority maximises pool size; falling back to the
    first endpoint's model when there's a tie keeps determinism.
    """
    if not pool:
        return "", []
    from collections import Counter
    counts = Counter(ep.matched_model for ep in pool)
    # Most common; ties broken by latency-order via first-occurrence in pool
    model, _ = counts.most_common(1)[0]
    filtered = [ep for ep in pool if ep.matched_model == model]
    return model, filtered


def render_shell_commands(pools: Dict[str, List[Endpoint]]) -> str:
    lines: List[str] = []
    role_to_provider_key = {
        "brain": "brain_pool",
        "executor": "exec_pool",
        "research": "research_pool",
        "utility": "util_pool",
    }
    for role, pool in pools.items():
        if not pool:
            lines.append(f"# {role}: no working endpoints found, skipped")
            continue
        provider_key = role_to_provider_key[role]
        model, filtered = _pick_majority_model(pool)
        endpoints_csv = ",".join(ep.url for ep in filtered)
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


def apply_to_config(pools: Dict[str, List[Endpoint]]) -> None:
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
    for role, pool in pools.items():
        if not pool:
            continue
        provider_key = role_to_provider_key[role]
        model, filtered = _pick_majority_model(pool)
        cfg["providers"][provider_key] = {
            "type": "ollama",
            "model": model,
            "endpoints": [ep.url for ep in filtered],
            "fallback": "deepseek",
        }
        cfg["roles"][role] = {"provider": provider_key, "fallback": "deepseek"}

    cfg["enable_multi_agent"] = True

    # Backup
    backup = config_path.with_suffix(".json.bak")
    backup.write_text(config_path.read_text())
    config_path.write_text(json.dumps(cfg, indent=2) + "\n")
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
                   help="Candidates probed per role before winnowing (default: 30)")
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

    pools: Dict[str, List[Endpoint]] = {}
    for role in args.roles:
        print(f"[2/3] role={role}")
        candidates = find_candidates_for_role(use, role,
                                              max_per_model=args.candidates_per_role)
        print(f"    {len(candidates)} candidates")
        if not candidates:
            pools[role] = []
            continue
        probed = probe_all(candidates)
        winners = winnow(probed, args.pool_size)
        print(f"    {sum(1 for e in probed if e.chat_ok)} chat-ok, "
              f"keeping top {len(winners)}:")
        for e in winners:
            print(f"      ✓ {e.url}  →  {e.matched_model}  ({e.chat_latency_s:.1f}s)")
        pools[role] = winners

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
