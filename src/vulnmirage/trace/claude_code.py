"""Claude Code stream/hook/session adapter. Model-bound is not provider receipt.

Raw capture envelopes preserve native records; this adapter joins observations by
(session, agent, tool_use_id), with serialized results preferred to structured
outputs. A transcript export backfills missing records without counting twice.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..hashing import canonical_json, sha256_text, stable_id
from .models import FileAccessRecord, NormalizedEvent, ToolCallRecord
from .opencode import ParseResult, _redact, _redact_text, _relative_path

CLAUDE_ADAPTER_VERSION = "claude-code-jsonl-v1"
CLAUDE_VALIDATED_VERSIONS = ("2.1.322",)
CAPTURE_SCHEMA = "claude-code-capture-v1"
HOOKS = (
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "InstructionsLoaded",
    "SubagentStart",
    "SubagentStop",
    "PreCompact",
    "PostCompact",
    "Stop",
    "StopFailure",
    "CwdChanged",
)
_FILE_TOOLS = {
    "Read": "read",
    "Grep": "search",
    "Glob": "list",
    "Write": "write",
    "Edit": "write",
    "NotebookEdit": "write",
}


@dataclass
class ClaudeParseResult(ParseResult):
    exposures: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    capture: dict[str, Any] = field(default_factory=dict)
    quality_issues: list[str] = field(default_factory=list)


def _strings(value: Any, pointer: str = ""):
    if isinstance(value, str):
        yield pointer, value
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, f"{pointer}/{index}")
    elif isinstance(value, dict):
        for key, item in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            yield f"{pointer}/{escaped}/@key", str(key)
            yield from _strings(item, f"{pointer}/{escaped}")


def _text(value: Any) -> str:
    return value if isinstance(value, str) else canonical_json(value)


def parse_claude_code_jsonl(
    source: Path,
    *,
    repo_root: Path,
    secret_values: tuple[str, ...] = (),
    catalog: list[dict[str, Any]] | None = None,
) -> ClaudeParseResult:
    """Accept native stream-json or the richer capture envelope JSONL."""
    result = ClaudeParseResult()
    if not source.is_file():
        return result
    parser = _Parser(result, source, repo_root, secret_values, catalog or [])
    with source.open(encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            result.source_lines += 1
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError("not an object")
                if catalog is None and record.get("kind") == "capture_start":
                    parser.catalog = record.get("payload", {}).get("catalog", [])
                parser.consume(number, record)
            except (KeyError, TypeError, ValueError):
                result.invalid_lines += 1
    parser.finish()
    return result


class _Parser:
    def __init__(self, result, source, repo, secrets, catalog):
        self.result = result
        self.source = source
        self.repo = repo
        self.secrets = secrets
        self.catalog = catalog
        self.calls: dict[tuple[str, str, str], dict] = {}
        self.messages: set[tuple[str, str, str]] = set()
        self.exposure_keys: set[tuple] = set()
        self.exposure_index: dict[tuple, dict] = {}
        self.hook_events: set[str] = set()
        self.terminal_sessions: set[str] = set()
        self.session = ""
        self.agent = ""
        self.ref = ""
        self.origin = ""
        self.time = None
        self.observed_ns = None
        self.historical = False
        self.run_end = None
        self.cwd = self.repo.resolve()
        self.cwd_by_scope = {}

    def emit(self, kind: str, *, source_type: str | None = None, **kwargs):
        sequence = len(self.result.events) + 1
        metadata = kwargs.pop("metadata", {})
        event = NormalizedEvent(
            event_id=stable_id("CEVT", self.source.name, sequence, self.ref, kind),
            sequence=sequence,
            event_type=kind,
            source_type=source_type or f"claude_{kind}",
            session_id=self.session or None,
            timestamp=self.time,
            metadata={
                "evidence_ref": self.ref,
                "origin": self.origin,
                "cwd": _relative_path(str(self.cwd), self.repo),
                "observed_monotonic_ns": self.observed_ns,
                "agent_id": self.agent or None,
                "historical": self.historical,
                "model_received_payload": "unknown",
                **metadata,
            },
            **kwargs,
        )
        self.result.events.append(event)
        return event

    def match(self, value: Any, stage: str, event: NormalizedEvent, tool_id: str | None = None):
        for pointer, text in _strings(value):
            for payload in self.catalog:
                for needle in payload["needles"]:
                    offset = text.find(needle)
                    if offset < 0:
                        continue
                    key = (
                        self.session,
                        self.agent,
                        tool_id or event.event_id,
                        payload["id"],
                        needle,
                        stage,
                        self.historical,
                    )
                    if key in self.exposure_keys:
                        if event.metadata.get("batch_barrier"):
                            self.exposure_index[key]["batch_sequence"] = event.sequence
                            self.exposure_index[key]["batch_evidence_ref"] = self.ref
                        continue
                    self.exposure_keys.add(key)
                    self.result.exposures.append(
                        {
                            "session_id": self.session,
                            "agent_id": self.agent or None,
                            "payload_id": payload["id"],
                            "payload_path": payload.get("path"),
                            "stage": stage,
                            "event_id": event.event_id,
                            "sequence": event.sequence,
                            "tool_call_id": tool_id,
                            "evidence_ref": self.ref,
                            "json_pointer": pointer,
                            "character_offset": offset,
                            "needle_sha256": sha256_text(needle),
                            "historical": self.historical,
                            "model_received_payload": "unknown",
                            "evidence_origin": self.origin,
                            "batch_sequence": event.sequence
                            if event.metadata.get("batch_barrier")
                            else None,
                        }
                    )
                    self.exposure_index[key] = self.result.exposures[-1]

    def call(self, tool_id: str, name: str | None = None, inputs: Any = None):
        key = (self.session, self.agent, tool_id)
        item = self.calls.setdefault(
            key,
            {
                "id": tool_id,
                "session": self.session,
                "agent": self.agent,
                "name": "unknown",
                "input": {},
                "start": None,
                "terminal": None,
                "output_rank": -1,
                "output": None,
                "duration_ms": None,
                "stage": "unknown",
                "status": None,
                "cwd": self.cwd,
            },
        )
        if name:
            item["name"] = name
        if isinstance(inputs, dict):
            item["input"] = inputs
        return item

    def tool_start(self, tool_id, name, inputs, metadata=None):
        item = self.call(tool_id, name, inputs)
        if self.origin == "hook":
            item["cwd"] = self.cwd
            if item["start"] is not None:
                item["start"].metadata["cwd"] = _relative_path(str(self.cwd), self.repo)
                item["start"].input_summary = self.safe_input(inputs, self.cwd)
        if item["start"] is not None:
            # Keep native PreToolUse as independent evidence, but count one action.
            if self.origin == "hook":
                self.emit(
                    "tool_hook",
                    tool_call_id=tool_id,
                    tool_name=name,
                    input_summary=_redact(inputs, self.secrets),
                    metadata=metadata or {},
                )
            return
        event = self.emit(
            "tool_use",
            source_type="tool_use",
            tool_call_id=tool_id,
            tool_name=name,
            status="running",
            input_summary=self.safe_input(inputs, item["cwd"]),
            metadata=metadata or {},
        )
        item["start"] = event

    def safe_input(self, inputs, cwd=None):
        data = _redact(inputs if isinstance(inputs, dict) else {}, self.secrets)
        for key in ("file_path", "path", "notebook_path", "directory"):
            if isinstance(data.get(key), str):
                data[key] = _relative_path(str(Path(cwd or self.cwd) / data[key]), self.repo)
        return data

    def tool_result(
        self,
        tool_id,
        output,
        *,
        stage,
        error=None,
        name=None,
        inputs=None,
        duration=None,
        batch_barrier=False,
    ):
        item = self.call(tool_id, name, inputs)
        if error is None:
            error = item["status"] == "error"
        rank = 2 if stage == "model_bound" else 1
        clean = _redact_text(_text(output), self.secrets)
        event = self.emit(
            "tool_result",
            source_type="tool_use",
            tool_call_id=tool_id,
            tool_name=item["name"],
            status="error" if error else "completed",
            input_summary=self.safe_input(item["input"], item["cwd"]),
            output_preview=clean[:2000],
            output_sha256=sha256_text(clean),
            metadata={
                "content_stage": stage,
                "provider_receipt": "unknown",
                "batch_barrier": batch_barrier,
            },
        )
        self.match(output, stage, event, tool_id)
        if rank >= item["output_rank"]:
            item.update(
                terminal=event,
                output_rank=rank,
                output=clean,
                stage=stage,
                status="error" if error else "completed",
            )
        if isinstance(duration, (int, float)) and not isinstance(duration, bool) and duration >= 0:
            item["duration_ms"] = duration

    def consume(self, number, envelope):
        self.ref = f"{self.source.name}:{number}"
        kind = envelope.get("kind") if envelope.get("schema") == CAPTURE_SCHEMA else "stream"
        payload = envelope.get("payload", {}) if kind != "stream" else envelope
        if envelope.get("schema") == CAPTURE_SCHEMA:
            payload = envelope.get("payload", {})
        if not isinstance(payload, dict):
            self.result.invalid_lines += 1
            return
        self.origin = kind
        self.time = envelope.get("observed_at") or payload.get("timestamp")
        self.observed_ns = envelope.get("observed_monotonic_ns")
        self.session = str(payload.get("session_id") or envelope.get("session_id") or self.session)
        self.agent = str(envelope.get("agent_id") or payload.get("agent_id") or "")
        self.historical = bool(
            envelope.get("historical") or payload.get("isReplay") or payload.get("is_replay")
        )
        scope = (self.session, self.agent)
        if isinstance(payload.get("cwd"), str):
            self.cwd_by_scope[scope] = Path(payload["cwd"])
        self.cwd = self.cwd_by_scope.get(scope, self.repo.resolve())
        if kind == "capture_start":
            self.result.capture.update({k: v for k, v in payload.items() if k != "catalog"})
            self.emit("capture_start", metadata=self.result.capture)
        elif kind == "capture_end":
            self.run_end = payload
            self.result.capture.update(payload)
            self.emit("capture_end", status=payload.get("status"), metadata=payload)
        elif kind == "hook":
            self.hook(payload)
        elif kind == "session":
            self.message(payload)
        elif kind == "diagnostic":
            self.result.limitations.append(str(payload.get("error", "capture diagnostic")))
            self.emit("diagnostic", status="error", metadata=_redact(payload, self.secrets))
        else:
            self.stream(payload)

    def hook(self, payload):
        event = payload.get("hook_event_name", "unknown")
        self.hook_events.add(event)
        if event == "PreToolUse":
            self.tool_start(
                payload["tool_use_id"],
                payload["tool_name"],
                payload.get("tool_input", {}),
                {"hook": event, "os_read_verified": False},
            )
        elif event in {"PostToolUse", "PostToolUseFailure"}:
            failed = event == "PostToolUseFailure"
            self.tool_result(
                payload["tool_use_id"],
                payload.get("error") if failed else payload.get("tool_response"),
                stage="tool_output",
                error=failed,
                name=payload["tool_name"],
                inputs=payload.get("tool_input"),
                duration=payload.get("duration_ms"),
            )
        elif event == "PostToolBatch":
            for call in payload.get("tool_calls", []):
                self.tool_result(
                    call["tool_use_id"],
                    call.get("tool_response"),
                    stage="model_bound",
                    name=call.get("tool_name"),
                    inputs=call.get("tool_input"),
                    error=call.get("is_error"),
                    batch_barrier=True,
                )
        else:
            e = self.emit("lifecycle", metadata=_redact(payload, self.secrets))
            if event == "UserPromptSubmit":
                self.match(payload.get("prompt", ""), "user_prompt", e)
            if event in {"PreCompact", "PostCompact"}:
                self.result.limitations.append(
                    "context compaction occurred; exact pre-exposure history is not preserved"
                )
            if event == "InstructionsLoaded":
                self.result.limitations.append(
                    "InstructionsLoaded gives file/load metadata, not verified loaded bytes"
                )

    def message(self, payload):
        message = payload.get("message", {})
        if not isinstance(message, dict):
            return
        identifier = str(payload.get("uuid") or message.get("id") or self.ref)
        key = (self.session, self.agent, identifier)
        if key in self.messages:
            return
        self.messages.add(key)
        # Historical prefix is archived for context, never counted as this run's actions.
        if self.historical:
            e = self.emit("historical_message", metadata={"message_uuid": identifier})
            self.match(message.get("content", ""), "historical_context", e)
            return
        content = message.get("content", [])
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        for block in content:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "tool_use":
                self.tool_start(
                    block["id"],
                    block["name"],
                    block.get("input", {}),
                    {"parent_tool_call_id": payload.get("parent_tool_use_id")},
                )
            elif kind == "tool_result":
                self.tool_result(
                    block["tool_use_id"],
                    block.get("content", ""),
                    stage="model_bound",
                    error=bool(block.get("is_error")),
                )
            elif kind == "text" and message.get("role") == "assistant":
                self.emit(
                    "text",
                    source_type="text",
                    text=_redact_text(block.get("text", ""), self.secrets),
                    metadata={"message_uuid": identifier},
                )
            elif kind == "text" and message.get("role") == "user":
                e = self.emit(
                    "user_context",
                    text=_redact_text(block.get("text", ""), self.secrets)[:2000],
                    metadata={"message_uuid": identifier},
                )
                self.match(block.get("text", ""), "user_context", e)
            elif kind == "thinking":
                self.emit(
                    "reasoning",
                    source_type="reasoning",
                    text=_redact_text(block.get("thinking", ""), self.secrets),
                    metadata={"visibility": "only text disclosed by native API"},
                )
            elif kind == "redacted_thinking":
                self.emit("reasoning_redacted", metadata={"visibility": "not_available"})

    def stream(self, payload):
        kind = payload.get("type")
        if kind in {"assistant", "user"}:
            self.message(payload)
        elif kind == "result":
            self.result.usage = {
                k: payload[k]
                for k in (
                    "usage",
                    "modelUsage",
                    "total_cost_usd",
                    "duration_ms",
                    "duration_api_ms",
                    "num_turns",
                    "subtype",
                    "is_error",
                )
                if k in payload
            }
            success = payload.get("subtype") == "success" and not payload.get("is_error")
            self.terminal_sessions.add(self.session)
            if isinstance(payload.get("result"), str) and payload["result"].strip():
                value = _redact_text(payload["result"], self.secrets)
                if not any(e.source_type == "text" and e.text == value for e in self.result.events):
                    self.emit("text", source_type="text", text=value)
            self.emit(
                "step_finish",
                source_type="step_finish",
                status="stop" if success else "error",
                metadata=self.result.usage,
            )
        elif kind == "system":
            self.emit(
                "system",
                metadata={
                    "subtype": payload.get("subtype"),
                    "framework_version": payload.get("claude_code_version"),
                },
            )
        elif kind in {
            "stream_event",
            "tool_progress",
            "tool_use_summary",
            "auth_status",
            "rate_limit_event",
        }:
            self.emit("progress", metadata={"native_type": kind})
        else:
            self.result.unknown_events += 1
            self.result.unknown_event_types.append(str(kind))
            self.emit("unknown", metadata={"native_type": kind})

    def finish(self):
        for item in self.calls.values():
            event = item["terminal"] or item["start"]
            if event is None:
                continue
            if item["start"] is None:
                self.result.quality_issues.append("a tool result had no matching tool-use request")
            self.result.tool_calls.append(
                ToolCallRecord(
                    event_id=event.event_id,
                    sequence=(item["start"] or event).sequence,
                    tool_call_id=item["id"],
                    tool_name=item["name"],
                    status=item["status"] or "running",
                    session_id=item["session"],
                    agent_id=item["agent"] or None,
                    duration_ms=item["duration_ms"],
                    input_summary=self.safe_input(item["input"], item["cwd"]),
                    output_sha256=sha256_text(item["output"])
                    if item["output"] is not None
                    else None,
                    content_returned_to_model=False,
                )
            )
            name = item["name"]
            if name in _FILE_TOOLS:
                inputs = item["input"]
                raw = next(
                    (inputs[k] for k in ("file_path", "notebook_path", "path") if k in inputs), None
                )
                if raw is None and name in {"Grep", "Glob"}:
                    raw = "."
                path = (
                    _relative_path(str(item["cwd"] / raw), self.repo)
                    if isinstance(raw, str)
                    else None
                )
                if path:
                    self.result.file_access.append(
                        FileAccessRecord(
                            event_id=event.event_id,
                            sequence=event.sequence,
                            path=path,
                            tool_call_id=item["id"],
                            tool_name=name,
                            access_type=(
                                _FILE_TOOLS[name]
                                if item["status"] == "completed"
                                else _FILE_TOOLS[name] + "_attempt"
                            ),
                            session_id=item["session"],
                            agent_id=item["agent"] or None,
                            content_returned_to_model=False,
                        )
                    )
        if "PreToolUse" not in self.hook_events:
            self.result.quality_issues.append(
                "native PreToolUse observations unavailable; stream/session backfill only"
            )
        if "PostToolBatch" not in self.hook_events:
            self.result.limitations.append(
                "PostToolBatch not observed; serialized results rely on user tool_result records"
            )
        if self.run_end and self.run_end.get("status") != "success":
            self.result.quality_issues.append(
                f"capture did not complete successfully: {self.run_end.get('status')}"
            )
        self.result.limitations.extend(
            [
                "model-bound tool_result content does not prove provider receipt or adoption",
                "Bash file I/O and semantic/paraphrased payload exposure are not inferred",
            ]
        )
        self.result.unknown_event_types = sorted(set(self.result.unknown_event_types))


__all__ = [
    "CAPTURE_SCHEMA",
    "CLAUDE_ADAPTER_VERSION",
    "CLAUDE_VALIDATED_VERSIONS",
    "HOOKS",
    "parse_claude_code_jsonl",
]
