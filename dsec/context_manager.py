"""
DSEC Context Manager — Hermes-inspired context window management.

Tracks estimated token usage per turn, auto-compresses older turns when
nearing the context budget, and provides context usage stats for the UI.
"""
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Rough approximation: ~4 characters per token for English text
CHARS_PER_TOKEN = 4

# Default context budgets per domain (in tokens)
_DOMAIN_BUDGETS: Dict[str, int] = {
    "htb": 128_000,
    "bugbounty": 128_000,
    "ctf": 128_000,
    "research": 256_000,
    "osint": 256_000,
    "programmer": 512_000,
}

# Model-specific overrides — these take precedence over domain budgets
_MODEL_BUDGETS: Dict[str, int] = {
    "deepseek-chat": 128_000,
    "deepseek-coder": 128_000,
    "deepseek-reasoner": 128_000,
    "deepseek-r1": 128_000,
    "deepseek-v3": 128_000,
    "deepseek-v4": 1_000_000,
    "deepseek-expert-r1": 128_000,
    "deepseek-expert-r1-search": 128_000,
    # Extended context models
    "deepseek-v3-1m": 1_000_000,
    "deepseek-v4-1m": 1_000_000,
    "deepseek-r1-1m": 1_000_000,
    "gpt-4o": 128_000,
    "gpt-4-turbo": 128_000,
    "claude-3-opus": 200_000,
    "claude-3.5-sonnet": 200_000,
    "claude-4-opus": 200_000,
    "gemini-2.5-pro": 1_000_000,
    "llama3-70b": 128_000,
    "qwen-2.5-72b": 128_000,
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

    def __init__(self, domain: str = "htb", budget: Optional[int] = None, model: str = ""):
        self.domain = domain
        # Priority: explicit budget > model budget > domain budget > default
        if budget:
            self.budget = budget
        elif model:
            # Try exact match first, then prefix match
            self.budget = _MODEL_BUDGETS.get(model, 0)
            if not self.budget:
                for k, v in _MODEL_BUDGETS.items():
                    if k in model or model in k:
                        self.budget = v
                        break
            if not self.budget:
                self.budget = _DOMAIN_BUDGETS.get(domain, DEFAULT_BUDGET)
        else:
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
        
        raw_text = "\n".join([f"{t.role.upper()}: {t.content}" for t in old_turns])
        summary = llm_summarize(raw_text, focus="recon progress and findings")
        
        summary_lines = [
            "[SESSION SUMMARY — RECON & EXPLOIT PROGRESS (LLM Generated)]",
            summary,
            "[END SESSION SUMMARY — Continue from recent context]"
        ]

        self._compressed_block = "\n".join(summary_lines)

        # Replace turns with only recent ones
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
            
            # Temporarily set turns to discarded to use the compress logic
            original_turns = self.turns
            self.turns = discarded_turns
            summary = self.compress(keep_recent=0)
            self.turns = original_turns
            
            messages.append({
                "role": "system", 
                "content": summary
            })

        # Assemble eligible messages
        for turn in eligible_turns:
            content = turn.content
            if turn.thinking and turn.role == "assistant":
                if "<think>" not in content:
                    content = f"<think>\n{turn.thinking}\n</think>\n{content}"
            messages.append({"role": turn.role, "content": content})
            
        return messages

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
