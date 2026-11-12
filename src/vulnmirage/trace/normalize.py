"""Write normalized trace artefacts beside every archived run."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..hashing import atomic_write_json, atomic_write_text, sha256_file
from .claude_code import (
    CLAUDE_ADAPTER_VERSION,
    CLAUDE_VALIDATED_VERSIONS,
    ClaudeParseResult,
    parse_claude_code_jsonl,
)
from .claude_metrics import behavior_metrics
from .completeness import assess_completeness
from .models import (
    OPENCODE_ADAPTER_VERSION,
    OPENCODE_VALIDATED_VERSIONS,
    TraceManifest,
)
from .opencode import ParseResult, parse_opencode_jsonl

TRACE_OUTPUTS = (
    "events.normalized.jsonl",
    "tool_calls.jsonl",
    "file_access.jsonl",
)


def _write_jsonl(path: Path, rows: Iterable[Any]) -> None:
    lines = []
    for row in rows:
        payload = row.model_dump(mode="json") if hasattr(row, "model_dump") else row
        lines.append(json.dumps(payload, sort_keys=True, ensure_ascii=False))
    atomic_write_text(path, "".join(line + "\n" for line in lines))


def normalize_trace(
    source_path: str | Path | None,
    output_dir: str | Path,
    *,
    adapter: str,
    repo_root: str | Path,
    framework_version: str | None = None,
    secret_values: Iterable[str] = (),
    payload_catalog: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    source = Path(source_path) if source_path else None
    adapter_version: str | None = None
    result = ClaudeParseResult() if adapter == "claude_code_jsonl" else ParseResult()
    limitations: list[str] = []
    framework: str | None = None
    compatibility_status = "unknown"

    # Runtime identity is independent of whether stdout exists. A crash that
    # produces no source trace must still retain the framework version used.
    if adapter == "opencode_jsonl":
        framework = "opencode"
        adapter_version = OPENCODE_ADAPTER_VERSION
        if framework_version in OPENCODE_VALIDATED_VERSIONS:
            compatibility_status = "validated_fixture"
        elif framework_version:
            compatibility_status = "unvalidated"
            limitations.append(
                "OpenCode framework version is not registered as validated in this runtime build: "
                f"{framework_version}"
            )
    elif adapter == "claude_code_jsonl":
        framework = "claude_code"
        adapter_version = CLAUDE_ADAPTER_VERSION

    if adapter == "none":
        status = "disabled"
        unavailable = "disabled"
    elif source is None or not source.is_file():
        status = "missing"
        unavailable = "missing"
    elif source.stat().st_size == 0:
        status = "empty"
        unavailable = "empty"
    elif adapter == "opencode_jsonl":
        result = parse_opencode_jsonl(
            source,
            repo_root=Path(repo_root),
            secret_values=tuple(value for value in secret_values if value),
        )
        if not result.events:
            status = "unsupported"
            unavailable = "unsupported"
        else:
            unavailable = None
            status = "partial" if result.invalid_lines else "ok"
            if compatibility_status == "unvalidated":
                status = "partial"
    elif adapter == "claude_code_jsonl":
        import re

        framework = "claude_code"
        adapter_version = CLAUDE_ADAPTER_VERSION
        result = parse_claude_code_jsonl(
            source,
            repo_root=Path(repo_root),
            secret_values=tuple(v for v in secret_values if v),
            catalog=payload_catalog,
        )
        framework_version = framework_version or result.capture.get("framework_version")
        if not framework_version:
            framework_version = next(
                (
                    e.metadata.get("framework_version")
                    for e in result.events
                    if e.metadata.get("framework_version")
                ),
                None,
            )
        version = re.search(r"\b\d+\.\d+\.\d+\b", framework_version or "")
        observations = [framework_version, result.capture.get("framework_version")]
        observations.extend(e.metadata.get("framework_version") for e in result.events)
        versions = {
            m.group()
            for value in observations
            if value
            for m in [re.search(r"\b\d+\.\d+\.\d+\b", value)]
            if m
        }
        if len(versions) > 1:
            result.quality_issues.append(
                "framework version identity conflicts across native sources"
            )
        compatibility_status = (
            "validated_fixture"
            if version and version.group() in CLAUDE_VALIDATED_VERSIONS
            else "unvalidated"
            if framework_version
            else "unknown"
        )
        status = "ok" if result.events else "unsupported"
        unavailable = None if result.events else "unsupported"
        if (
            result.invalid_lines
            or result.quality_issues
            or compatibility_status != "validated_fixture"
        ):
            status = "partial" if result.events else "unsupported"
        limitations.extend(result.limitations + result.quality_issues)
        if compatibility_status != "validated_fixture":
            limitations.append(
                "Claude Code version is not registered by the local native-CLI validation fixture"
            )
    else:
        status = "unsupported"
        unavailable = "unsupported"
        limitations.append(f"unknown trace adapter: {adapter}")

    completeness = assess_completeness(
        result.events,
        result.tool_calls,
        file_access_count=len(result.file_access),
        invalid_line_count=result.invalid_lines,
        unknown_event_count=result.unknown_events,
        unavailable_status=unavailable,
    )
    if status == "ok" and completeness.status == "partial":
        status = "partial"
    if adapter == "claude_code_jsonl" and getattr(result, "quality_issues", []):
        completeness = completeness.model_copy(
            update={
                "status": "partial",
                "limitations": completeness.limitations + result.quality_issues,
            }
        )
    limitations.extend(completeness.limitations)

    _write_jsonl(out / TRACE_OUTPUTS[0], result.events)
    _write_jsonl(out / TRACE_OUTPUTS[1], result.tool_calls)
    _write_jsonl(out / TRACE_OUTPUTS[2], result.file_access)
    atomic_write_json(out / "trace_completeness.json", completeness)
    extra_outputs = []
    if adapter == "claude_code_jsonl" and hasattr(result, "exposures"):
        _write_jsonl(out / "payload_exposure.jsonl", result.exposures)
        atomic_write_json(out / "behavior_metrics.json", behavior_metrics(result))
        extra_outputs = ["payload_exposure.jsonl", "behavior_metrics.json"]
    output_hashes = {
        name: sha256_file(out / name)
        for name in (*TRACE_OUTPUTS, "trace_completeness.json", *extra_outputs)
    }
    manifest = TraceManifest(
        adapter=adapter,
        adapter_version=adapter_version,
        framework=framework,
        framework_version=framework_version,
        compatibility_status=compatibility_status,
        status=status,
        source_file=source.name if source is not None else None,
        source_sha256=sha256_file(source) if source is not None and source.is_file() else None,
        source_lines=result.source_lines,
        parsed_events=len(result.events),
        invalid_lines=result.invalid_lines,
        unknown_event_types=result.unknown_event_types,
        output_sha256=output_hashes,
        limitations=limitations,
    )
    atomic_write_json(out / "trace_manifest.json", manifest)
    return {
        "status": status,
        "completeness": completeness.status,
        "events": len(result.events),
        "tool_calls": len(result.tool_calls),
        "file_accesses": len(result.file_access),
        "manifest": manifest,
    }


__all__ = ["TRACE_OUTPUTS", "normalize_trace"]
