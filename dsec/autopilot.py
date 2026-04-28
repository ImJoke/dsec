"""Autopilot bug finder for DSEC.

This module keeps a lightweight watch over agentic loop progress and writes an
`issue.txt` report when the loop appears to stop for a tool/runtime bug rather
than for a normal completion or an explicit user interrupt.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class IssueRecord:
    issue_id: str
    timestamp: str
    severity: str
    category: str
    title: str
    description: str
    session_name: str
    domain: str
    model: str
    signals: List[str] = field(default_factory=list)
    affected_tools: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


class AutopilotBugFinder:
    """Detect unexpected agentic loop halts and write a compact report."""

    def __init__(
        self,
        *,
        session_name: str,
        domain: str,
        model: str,
        issue_path: Path | None = None,
        enabled: bool = True,
    ) -> None:
        self.session_name = session_name
        self.domain = domain
        self.model = model
        self.issue_path = issue_path or Path.cwd() / "issue.txt"
        self.enabled = enabled
        self._tool_failures: Dict[str, int] = {}
        self._signals: List[str] = []
        self._evidence: List[str] = []
        self._user_interrupt = False
        self._last_activity = datetime.now(timezone.utc)

    def note_user_interrupt(self) -> None:
        self._user_interrupt = True

    def record_tool_result(self, tool_name: str, result_text: str) -> None:
        """Record tool output and keep heuristics simple and conservative."""
        self._last_activity = datetime.now(timezone.utc)
        text = (result_text or "").lower()
        if not text:
            return

        if "cancelled after" in text or "timed out" in text or "timeout" in text:
            self._tool_failures[tool_name] = self._tool_failures.get(tool_name, 0) + 1
            self._signals.append(f"{tool_name}: timeout or cancellation")
            self._evidence.append(f"{tool_name}: {result_text[:240]}")
        elif text.startswith("[error:") or "[error:" in text or "failed" in text:
            self._tool_failures[tool_name] = self._tool_failures.get(tool_name, 0) + 1
            self._signals.append(f"{tool_name}: error result")
            self._evidence.append(f"{tool_name}: {result_text[:240]}")

    def should_write_issue(self, *, had_tool_calls: bool, loop_ended_normally: bool, new_content: Optional[str]) -> bool:
        if not self.enabled:
            return False
        if self._user_interrupt:
            return False
        if not had_tool_calls:
            return False
        if new_content is None:
            return True
        if not loop_ended_normally and self._tool_failures:
            return True
        if self._tool_failures and loop_ended_normally:
            return True
        return False

    def build_issue(self, *, reason: str, had_tool_calls: bool, loop_ended_normally: bool, new_content: Optional[str]) -> IssueRecord:
        failures = sorted(self._tool_failures.items(), key=lambda item: (-item[1], item[0]))
        affected_tools = [name for name, _count in failures]
        if affected_tools:
            category = "tool_failure"
            severity = "high"
            title = "Unexpected loop stop caused by tool/runtime failure"
        elif new_content is None:
            category = "model_halt"
            severity = "medium"
            title = "Agent loop stopped after tool execution without a follow-up"
        else:
            category = "unknown_halt"
            severity = "medium"
            title = "Unexpected agent loop stop"

        description = (
            f"The agentic loop stopped for a reason that does not look like a normal task completion.\n"
            f"Reason: {reason}\n"
            f"Had tool calls: {had_tool_calls}\n"
            f"Loop ended normally: {loop_ended_normally}\n"
            f"New content present: {new_content is not None}\n"
        )
        if affected_tools:
            description += f"Likely impacted tools: {', '.join(affected_tools)}\n"

        recommendations = [
            "Inspect the last tool response and the tool implementation for blocking calls or exceptions.",
            "If the halt came from a timeout, add a tighter timeout/error path instead of retrying blindly.",
            "If the halt came from the model producing no follow-up, capture the full prompt and last tool outputs.",
        ]
        if affected_tools:
            recommendations.insert(0, "Fix the failing tool path first, then rerun the same agent step.")

        signals = list(dict.fromkeys(self._signals))
        if not signals and reason:
            signals.append(reason)

        issue_id = datetime.now(timezone.utc).strftime("autopilot-%Y%m%d-%H%M%S")
        return IssueRecord(
            issue_id=issue_id,
            timestamp=self._utc_now(),
            severity=severity,
            category=category,
            title=title,
            description=description.strip(),
            session_name=self.session_name,
            domain=self.domain,
            model=self.model,
            signals=signals,
            affected_tools=affected_tools,
            recommendations=recommendations,
            evidence=list(dict.fromkeys(self._evidence)),
        )

    def write_issue(self, record: IssueRecord) -> Path:
        self.issue_path.parent.mkdir(parents=True, exist_ok=True)
        text = self._render_issue(record)
        self.issue_path.write_text(text, encoding="utf-8")
        return self.issue_path

    def finalize(self, *, reason: str, had_tool_calls: bool, loop_ended_normally: bool, new_content: Optional[str]) -> Optional[Path]:
        if not self.should_write_issue(
            had_tool_calls=had_tool_calls,
            loop_ended_normally=loop_ended_normally,
            new_content=new_content,
        ):
            return None
        record = self.build_issue(
            reason=reason,
            had_tool_calls=had_tool_calls,
            loop_ended_normally=loop_ended_normally,
            new_content=new_content,
        )
        return self.write_issue(record)

    def _render_issue(self, record: IssueRecord) -> str:
        lines: List[str] = [
            "DSEC AUTOPILOT BUG FINDER",
            f"issue_id: {record.issue_id}",
            f"timestamp: {record.timestamp}",
            f"severity: {record.severity}",
            f"category: {record.category}",
            f"session: {record.session_name}",
            f"domain: {record.domain}",
            f"model: {record.model}",
            "",
            f"title: {record.title}",
            "",
            "description:",
            record.description,
            "",
            "signals:",
        ]
        if record.signals:
            lines.extend(f"- {signal}" for signal in record.signals)
        else:
            lines.append("- none recorded")

        lines.append("")
        lines.append("affected_tools:")
        if record.affected_tools:
            lines.extend(f"- {tool}" for tool in record.affected_tools)
        else:
            lines.append("- none")

        lines.append("")
        lines.append("evidence:")
        if record.evidence:
            lines.extend(f"- {item}" for item in record.evidence)
        else:
            lines.append("- none")

        lines.append("")
        lines.append("recommendations:")
        lines.extend(f"- {item}" for item in record.recommendations)
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()
