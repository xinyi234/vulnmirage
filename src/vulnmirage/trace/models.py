"""Stable, framework-neutral contracts for archived agent traces."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..hashing import utc_now_iso

TRACE_SCHEMA_VERSION = "1.0"
OPENCODE_ADAPTER_VERSION = "opencode-jsonl-v2"
# Validation evidence is release-specific and is intentionally not bundled with the
# runtime-only benchmark distribution. Formal experiments must register their audited
# framework version before treating a trace as mechanism-grade evidence.
OPENCODE_VALIDATED_VERSIONS: tuple[str, ...] = ()


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NormalizedEvent(_Strict):
    schema_version: str = TRACE_SCHEMA_VERSION
    event_id: str
    sequence: int = Field(ge=1)
    event_type: str
    source_type: str
    session_id: str | None = None
    timestamp: str | int | float | None = None
    tool_call_id: str | None = None
    tool_name: str | None = None
    status: str | None = None
    text: str | None = None
    input_summary: dict[str, Any] = Field(default_factory=dict)
    output_preview: str | None = None
    output_sha256: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolCallRecord(_Strict):
    schema_version: str = TRACE_SCHEMA_VERSION
    event_id: str
    sequence: int = Field(ge=1)
    tool_call_id: str | None = None
    session_id: str | None = None
    agent_id: str | None = None
    tool_name: str
    status: str | None = None
    duration_ms: float | None = Field(default=None, ge=0)
    input_summary: dict[str, Any] = Field(default_factory=dict)
    output_sha256: str | None = None
    content_returned_to_model: bool = False


class FileAccessRecord(_Strict):
    schema_version: str = TRACE_SCHEMA_VERSION
    event_id: str
    sequence: int = Field(ge=1)
    path: str
    tool_call_id: str | None = None
    session_id: str | None = None
    agent_id: str | None = None
    tool_name: str
    access_type: str
    content_returned_to_model: bool = False


class TraceManifest(_Strict):
    schema_version: str = TRACE_SCHEMA_VERSION
    adapter: str
    adapter_version: str | None = None
    framework: str | None = None
    framework_version: str | None = None
    compatibility_status: Literal["validated_fixture", "unvalidated", "unknown"] = "unknown"
    status: Literal["ok", "partial", "missing", "empty", "unsupported", "disabled"]
    source_file: str | None = None
    source_sha256: str | None = None
    source_lines: int = 0
    parsed_events: int = 0
    invalid_lines: int = 0
    unknown_event_types: list[str] = Field(default_factory=list)
    output_sha256: dict[str, str] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    produced_at: str = Field(default_factory=utc_now_iso)


class TraceCompleteness(_Strict):
    schema_version: str = TRACE_SCHEMA_VERSION
    status: Literal["complete", "partial", "missing", "unsupported", "disabled"]
    event_count: int = 0
    tool_call_count: int = 0
    terminal_tool_call_count: int = 0
    tool_terminal_rate: float | None = None
    file_access_count: int = 0
    terminal_step_observed: bool = False
    final_text_observed: bool = False
    invalid_line_count: int = 0
    unknown_event_count: int = 0
    limitations: list[str] = Field(default_factory=list)
    assessed_at: str = Field(default_factory=utc_now_iso)


__all__ = [
    "FileAccessRecord",
    "NormalizedEvent",
    "OPENCODE_ADAPTER_VERSION",
    "OPENCODE_VALIDATED_VERSIONS",
    "TRACE_SCHEMA_VERSION",
    "ToolCallRecord",
    "TraceCompleteness",
    "TraceManifest",
]
