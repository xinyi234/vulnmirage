"""Assess trace quality without inventing events that the framework omitted."""

from __future__ import annotations

from .models import NormalizedEvent, ToolCallRecord, TraceCompleteness


def assess_completeness(
    events: list[NormalizedEvent],
    tool_calls: list[ToolCallRecord],
    *,
    file_access_count: int,
    invalid_line_count: int = 0,
    unknown_event_count: int = 0,
    unavailable_status: str | None = None,
) -> TraceCompleteness:
    if unavailable_status in {"missing", "empty"}:
        return TraceCompleteness(
            status="missing",
            limitations=["no native trace events were available"],
        )
    if unavailable_status == "unsupported":
        return TraceCompleteness(
            status="unsupported",
            invalid_line_count=invalid_line_count,
            limitations=["native output was present but no supported events were parsed"],
        )
    if unavailable_status == "disabled":
        return TraceCompleteness(
            status="disabled",
            limitations=["trace normalization was disabled for this agent configuration"],
        )

    call_ids = {
        (call.session_id, call.agent_id, call.tool_call_id or call.event_id) for call in tool_calls
    }
    terminal_call_ids = {
        (call.session_id, call.agent_id, call.tool_call_id or call.event_id)
        for call in tool_calls
        if (call.status or "").lower() in {"completed", "error"}
    }
    tool_call_count = len(call_ids)
    terminal_tool_calls = len(terminal_call_ids)
    terminal_step = any(
        event.source_type == "step_finish" and (event.status or "").lower() == "stop"
        for event in events
    )
    final_text = any(
        event.source_type == "text" and bool((event.text or "").strip()) for event in events
    )
    limitations: list[str] = []
    if not terminal_step:
        limitations.append("no step_finish event with reason=stop was observed")
    if not final_text:
        limitations.append("no non-empty text event was observed")
    if invalid_line_count:
        limitations.append(f"{invalid_line_count} non-empty source line(s) were invalid JSON")
    if unknown_event_count:
        limitations.append(f"{unknown_event_count} event(s) used unknown source types")
    if terminal_tool_calls < tool_call_count:
        limitations.append("one or more tool calls had no terminal state")
    status = "complete" if not limitations else "partial"
    return TraceCompleteness(
        status=status,
        event_count=len(events),
        tool_call_count=tool_call_count,
        terminal_tool_call_count=terminal_tool_calls,
        tool_terminal_rate=(terminal_tool_calls / tool_call_count) if tool_call_count else None,
        file_access_count=file_access_count,
        terminal_step_observed=terminal_step,
        final_text_observed=final_text,
        invalid_line_count=invalid_line_count,
        unknown_event_count=unknown_event_count,
        limitations=limitations,
    )


__all__ = ["assess_completeness"]
