"""Native agent trace adapters and framework-neutral contracts."""

from .claude_code import parse_claude_code_jsonl
from .completeness import assess_completeness
from .models import (
    FileAccessRecord,
    NormalizedEvent,
    ToolCallRecord,
    TraceCompleteness,
    TraceManifest,
)
from .normalize import normalize_trace
from .opencode import parse_opencode_jsonl

__all__ = [
    "FileAccessRecord",
    "NormalizedEvent",
    "ToolCallRecord",
    "TraceCompleteness",
    "TraceManifest",
    "assess_completeness",
    "normalize_trace",
    "parse_opencode_jsonl",
    "parse_claude_code_jsonl",
]
