"""
DSEC Context Manager — Hermes-inspired context window management.

Tracks estimated token usage per turn, auto-compresses older turns when
nearing the context budget, and provides context usage stats for the UI.
"""
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Rough approximation: ~4 characters per token for English text
CHARS_PER_TOKEN = 4

# Default context budgets per domain (in tokens)
_DOMAIN_BUDGETS: Dict[str, int] = {
    "auto": 128_000,
    "htb": 128_000,
    "bugbounty": 128_000,
    "ctf": 128_000,
    "research": 256_000,
    "osint": 256_000,
    "programmer": 512_000,
}

# Static fallback table — only consulted when an Ollama `/api/show` probe
# fails AND no disk cache entry is present. The probe (Ollama 0.5+ exposes
# `model_info.<family>.context_length`) is authoritative; this table only
# covers a handful of well-known models so we still have *some* sensible
# budget when the user is offline or the endpoint refuses /api/show.
# Values intentionally conservative — better to compress early than overrun.
_MODEL_BUDGETS_FALLBACK: Dict[str, int] = {
    # ── DeepSeek ──
    "deepseek-chat": 128_000,
    "deepseek-coder": 128_000,
    "deepseek-reasoner": 128_000,
    "deepseek-r1": 128_000,
    "deepseek-r1:14b": 128_000,
    "deepseek-r1:32b": 128_000,
    "deepseek-r1:70b": 128_000,
    "deepseek-v3": 128_000,
    "deepseek-v3.1:671b-cloud": 128_000,
    "deepseek-v3.2:cloud": 128_000,
    # DeepSeek V4: official 1,048,576-token ("1M agent context") release
    # April 2026; Ollama /api/show confirms 1048576 for v4-pro:cloud.
    "deepseek-v4": 1_048_576,
    "deepseek-v4-pro:cloud": 1_048_576,
    "deepseek-v4-flash:cloud": 1_048_576,
    "deepseek-v3-1m": 1_000_000,
    "deepseek-v4-1m": 1_000_000,
    "deepseek-r1-1m": 1_000_000,
    "deepseek-expert-r1": 128_000,
    "deepseek-expert-r1-search": 128_000,
    # ── Qwen3 / Qwen3-Coder / Qwen2.5 ──
    "qwen3:4b": 128_000,
    "qwen3:8b": 128_000,
    "qwen3:14b": 128_000,
    "qwen3:32b": 128_000,
    "qwen3-coder:14b": 256_000,
    "qwen3-coder:30b": 256_000,
    "qwen3-coder:480b-cloud": 256_000,
    "qwen3-coder-next:cloud": 256_000,
    "qwen3-next:80b-cloud": 256_000,
    "qwen3-vl:235b-cloud": 256_000,
    "qwen3.5:cloud": 128_000,
    "qwen3.5:397b-cloud": 256_000,
    "qwen3.6:27b": 128_000,
    "qwen3.6:35b": 128_000,
    "qwen2.5-coder:14b": 128_000,
    "qwen2.5-coder:32b": 128_000,
    "qwen-2.5-72b": 128_000,
    # ── Kimi (Moonshot) — K2.6 tech blog: ctx=262144 ──
    "kimi-k2:1t-cloud": 262_144,
    "kimi-k2.5:cloud": 262_144,
    "kimi-k2.6:cloud": 262_144,
    "kimi-k2-thinking:cloud": 262_144,
    # ── Zhipu / GLM — GLM-5.1 docs: 200K ctx, 128K max-out ──
    "glm-4.6:cloud": 200_000,
    "glm-4.7:cloud": 200_000,
    "glm-4.7-flash": 200_000,
    "glm-5:cloud": 200_000,
    "glm-5.1:cloud": 200_000,
    "gemma4:31b-cloud": 128_000,
    # ── MiniMax M2 — Ollama /api/show confirms 204800 for m2.7 ──
    "minimax-m2:cloud": 204_800,
    "minimax-m2.1:cloud": 204_800,
    "minimax-m2.5:cloud": 204_800,
    "minimax-m2.7:cloud": 204_800,
    # ── Google Gemini ──
    "gemini-3-flash-preview:cloud": 1_000_000,
    "gemini-2.5-pro": 1_000_000,
    # ── GPT-OSS / OpenAI ──
    "gpt-oss:20b": 128_000,
    "gpt-oss:20b-cloud": 128_000,
    "gpt-oss:120b": 128_000,
    "gpt-oss:120b-cloud": 128_000,
    "gpt-4o": 128_000,
    "gpt-4-turbo": 128_000,
    # ── Mistral / Devstral ──
    "devstral-2:123b-cloud": 128_000,
    "devstral-small-2": 128_000,
    "devstral-small-2:24b-cloud": 128_000,
    # ── Llama / Meta ──
    "llama3-70b": 128_000,
    "llama3.1:8b": 128_000,
    "llama3.2:3b": 128_000,
    "llama3.3": 128_000,
    # ── Anthropic Claude ──
    "claude-3-opus": 200_000,
    "claude-3.5-sonnet": 200_000,
    "claude-4-opus": 200_000,
    # ── NVIDIA Nemotron ──
    "nemotron-3-super:cloud": 128_000,
    "nemotron-mini:latest": 128_000,
    # ── Magistral (Mistral-derived) ──
    "magistral:24b": 128_000,
}

DEFAULT_BUDGET = 32_000
COMPRESSION_THRESHOLD = 0.70  # Compress at 70% of budget


# ---------------------------------------------------------------------------
# Turn data
# ---------------------------------------------------------------------------

@dataclass
class Turn:
    """A single conversation turn."""
    role: str               # "user" or "assistant"
    content: str
    thinking: str = ""
    timestamp: str = ""
    tokens_estimate: int = 0
    is_compressed: bool = False


# ---------------------------------------------------------------------------
# Context Manager
# ---------------------------------------------------------------------------

class ContextManager:
    """
    Tracks conversation context and provides auto-compression.

    Usage:
        cm = ContextManager(domain="htb")
        cm.add_turn("user", "nmap scan on 10.10.11.23")
        cm.add_turn("assistant", "Let me scan that target...", thinking="...")
        if cm.should_compress():
            cm.compress()
        print(cm.usage_summary())
    """

    def __init__(self, domain: str = "auto", budget: Optional[int] = None, model: str = ""):
        self.domain = domain
        # Priority:
        #   1. explicit `budget` arg (caller knows best)
        #   2. live probe via Ollama `/api/show` against the configured
        #      brain pool (authoritative — beats any stale lookup table)
        #   3. hardcoded model → ctx table (offline fallback)
        #   4. domain default
        #   5. DEFAULT_BUDGET (32K)
        if budget:
            self.budget = budget
        else:
            self.budget = 0
            # Stage 2 — Ollama probe
            try:
                from dsec.providers.ollama_caps import best_effort_context_for_pool
                from dsec.config import load_config
                _cfg = load_config()
                if _cfg.get("enable_multi_agent"):
                    _roles = _cfg.get("roles") or {}
                    _entry = _roles.get("brain") or {}
                    _pkey = _entry.get("provider")
                    if isinstance(_pkey, str) and _pkey.strip():
                        probed = best_effort_context_for_pool(_pkey.strip(), fallback=0)
                        if probed and probed > 0:
                            self.budget = probed
            except Exception:
                pass
            # Stage 3 — model→ctx table
            if not self.budget and model:
                self.budget = _MODEL_BUDGETS_FALLBACK.get(model, 0)
                if not self.budget:
                    for k, v in sorted(_MODEL_BUDGETS_FALLBACK.items(), key=lambda x: -len(x[0])):
                        if model.startswith(k) or k.startswith(model):
                            self.budget = v
                            break
            # Stage 4 — domain default
            if not self.budget:
                self.budget = _DOMAIN_BUDGETS.get(domain, DEFAULT_BUDGET)
        self.turns: List[Turn] = []
        self.system_prompt_tokens: int = 0
        self._compressed_block: str = ""

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count from text length."""
        if not text:
            return 0
        return max(1, len(text) // CHARS_PER_TOKEN)

    def set_system_prompt_tokens(self, prompt: str) -> None:
        """Track the system prompt token count."""
        self.system_prompt_tokens = self.estimate_tokens(prompt)

    def add_turn(self, role: str, content: str, thinking: str = "") -> None:
        """Add a conversation turn and estimate its tokens."""
        tokens = self.estimate_tokens(content) + self.estimate_tokens(thinking)
        turn = Turn(
            role=role,
            content=content,
            thinking=thinking,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tokens_estimate=tokens,
        )
        self.turns.append(turn)

    @property
    def total_tokens(self) -> int:
        """Total estimated tokens in the conversation."""
        turn_tokens = sum(t.tokens_estimate for t in self.turns)
        compressed_tokens = self.estimate_tokens(self._compressed_block)
        return self.system_prompt_tokens + turn_tokens + compressed_tokens

    @property
    def usage_percent(self) -> int:
        """Context usage as percentage of budget."""
        if self.budget <= 0:
            return 0
        return min(100, int((self.total_tokens / self.budget) * 100))

    @property
    def remaining_tokens(self) -> int:
        """Estimated remaining tokens."""
        return max(0, self.budget - self.total_tokens)

    def should_compress(self) -> bool:
        """Check if context should be compressed."""
        return self.total_tokens >= int(self.budget * COMPRESSION_THRESHOLD)

    def compress(self, keep_recent: int = 5) -> str:
        """
        Compress older turns into a summary block.

        Keeps the most recent `keep_recent` turns verbatim and
        compresses older turns into bullet points.

        Returns the compression summary.
        """
        if len(self.turns) <= keep_recent:
            return "(nothing to compress)"

        old_turns = self.turns[:-keep_recent]
        recent_turns = self.turns[-keep_recent:]

        # Build intelligent agentic summary using LLM
        from dsec.llm_utils import llm_summarize
        
        raw_text = "\n".join([f"{t.role.upper()}: {t.content[:600]}" for t in old_turns])
        try:
            summary = llm_summarize(raw_text, focus="HTB attack progress: preserve all credentials/hashes, IPs, current foothold, exact next step")
        except Exception as _sum_exc:
            # Summarization failed — keep turns intact rather than losing history
            from dsec.formatter import print_warning
            print_warning(f"LLM summarization failed ({_sum_exc}), keeping full context.")
            return f"(compression skipped: summarization failed)"

        summary_lines = [
            "[SESSION SUMMARY — RECON & EXPLOIT PROGRESS (LLM Generated)]",
            summary,
            "[END SESSION SUMMARY — Continue from recent context]"
        ]

        self._compressed_block = "\n".join(summary_lines)

        # Replace turns with only recent ones — AFTER successful summary
        old_token_count = sum(t.tokens_estimate for t in old_turns)
        new_compressed_tokens = self.estimate_tokens(self._compressed_block)

        self.turns = recent_turns

        saved = old_token_count - new_compressed_tokens
        return (
            f"Compressed {len(old_turns)} turns → saved ~{saved:,} tokens "
            f"(context now at {self.usage_percent}%)"
        )

    @property
    def compressed_context(self) -> str:
        """Return the compressed context block for prompt injection."""
        return self._compressed_block

    def usage_summary(self) -> str:
        """One-line usage summary for status bar."""
        used = self.total_tokens
        budget = self.budget
        pct = self.usage_percent
        turns = len(self.turns)

        # Color indicator
        if pct >= 90:
            indicator = "🔴"
        elif pct >= 70:
            indicator = "🟡"
        else:
            indicator = "🟢"

        return (
            f"{indicator} {pct}% Context ({used:,}/{budget:,})"
        )

    def to_messages(self, limit: Optional[int] = None) -> List[Dict[str, str]]:
        """
        Convert current turns to OpenAI-compatible messages list.
        
        If `limit` is provided, prunes oldest turns first until total
        tokens are below the limit. Automatically generates an 
        intelligent summary of discarded turns.
        """
        messages: List[Dict[str, str]] = []
        
        # Determine how many turns we can keep if limited
        eligible_turns = self.turns
        discarded_turns = []
        
        if limit:
            current_count = self.system_prompt_tokens
            keep_indices: List[int] = []
            
            # Walk backwards to keep recent context
            for i in range(len(self.turns) - 1, -1, -1):
                turn_tokens = self.turns[i].tokens_estimate
                if current_count + turn_tokens > limit and keep_indices:
                    break
                current_count += turn_tokens
                keep_indices.insert(0, i)
            
            eligible_turns = [self.turns[i] for i in keep_indices]
            discarded_turns = [self.turns[i] for i in range(len(self.turns)) if i not in keep_indices]

        # Generate summary of discarded context to prevent state loss
        if discarded_turns:
            from dsec.formatter import print_info
            print_info(f"Generating LLM summary for {len(discarded_turns)} discarded turns...")

            from dsec.llm_utils import llm_summarize, _MAX_SUMMARIZE_CHARS
            # Per-turn cap + total cap: prefer recent turns (walk backwards, fill budget)
            per_turn_cap = 500
            budget = _MAX_SUMMARIZE_CHARS
            chunks: list = []
            for t in reversed(discarded_turns):
                piece = f"{t.role.upper()}: {t.content[:per_turn_cap]}"
                if budget - len(piece) < 0:
                    break
                chunks.append(piece)
                budget -= len(piece) + 1
            raw_text = "\n".join(reversed(chunks))
            try:
                summary_text = llm_summarize(raw_text, focus="HTB attack progress: preserve all credentials/hashes, IPs, current foothold, exact next step")
            except Exception as _sum_exc:
                from dsec.formatter import print_warning as _pw
                _pw(f"LLM summarization failed in to_messages ({_sum_exc}), skipping summary.")
                summary_text = "(summarization failed — some prior context may be missing)"
            self._compressed_block = summary_text

            messages.append({
                "role": "system",
                "content": f"[PREVIOUS SESSION SUMMARY — ATTACK STATE]\n{summary_text}\n[END SUMMARY — Resume attack from exact position above]",
            })

        # Assemble eligible messages, skipping degenerate turns that would
        # confuse the model (e.g. turns that are only a Ctrl-C cancellation marker).
        _SKIP_MARKERS = ("✖ Response cancelled.",)
        # Ensure first non-system message is a user message (required by most APIs).
        started = False
        msgs_before_turns = len(messages)
        for turn in eligible_turns:
            content = turn.content
            if content and content.strip() in _SKIP_MARKERS:
                continue  # discard bare cancellation turns from context
            if not started and turn.role == "assistant":
                continue  # skip leading assistant turns
            started = True
            if turn.thinking and turn.role == "assistant":
                if "<think>" not in content:
                    content = f"<think>\n{turn.thinking}\n</think>\n{content}"
            messages.append({"role": turn.role, "content": content})

        # Safety net: if pruning left us with system-only messages (all eligible
        # turns were assistant or skip-markers), inject a synthetic user turn so
        # the API call doesn't fail with "messages must contain a user message".
        if len(messages) == msgs_before_turns:
            messages.append({
                "role": "user",
                "content": "[Context resumed from session summary] Continue from where the attack left off.",
            })

        return messages

    def get_summary_text(self) -> str:
        """Return the most recently generated compressed/summary block."""
        return self._compressed_block

    def usage_dict(self) -> Dict[str, Any]:
        """Return usage stats as a dictionary."""
        return {
            "total_tokens": self.total_tokens,
            "budget": self.budget,
            "usage_percent": self.usage_percent,
            "remaining": self.remaining_tokens,
            "turns": len(self.turns),
            "system_tokens": self.system_prompt_tokens,
            "compressed": bool(self._compressed_block),
        }
