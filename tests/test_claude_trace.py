"""Trace evidence semantics, de-duplication and descriptive impact measurements."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from vulnmirage.campaign.executor import extract_final_answer
from vulnmirage.config import AgentConfig
from vulnmirage.hashing import sha256_file
from vulnmirage.trace.claude_code import CAPTURE_SCHEMA, parse_claude_code_jsonl
from vulnmirage.trace.claude_metrics import behavior_metrics, compare_metrics
from vulnmirage.trace.normalize import normalize_trace

MARKER = "VM_TRACE_MARKER_8d12"
CATALOG = [{"id": "p1", "path": "src/auth.py", "needles": [MARKER]}]


@pytest.mark.parametrize("name,errors", [("success", 0), ("failure", 1)])
def test_frozen_native_cli_fixture(tmp_path, name, errors):
    directory = Path(__file__).parent / "fixtures/claude_code"
    source = directory / f"2.1.322-{name}.jsonl"
    provenance = json.loads((directory / "provenance.json").read_text())
    assert sha256_file(source) == provenance["fixtures"][source.name]["sha256"]
    summary = normalize_trace(
        source, tmp_path / "out", adapter="claude_code_jsonl", repo_root="/fixture/repo"
    )
    assert summary["status"] == "ok"
    metrics = json.loads((tmp_path / "out/behavior_metrics.json").read_text())
    assert metrics["tool_call_count"] == 2
    assert metrics["post_exposure_tool_call_count"] == 1
    assert metrics["tool_error_count"] == errors


def record(kind, payload, **metadata):
    return {"schema": CAPTURE_SCHEMA, "kind": kind, "payload": payload, **metadata}


def write_trace(tmp_path, records):
    source = tmp_path / "trace.jsonl"
    source.write_text("".join(json.dumps(r) + "\n" for r in records))
    return source


def hook(event, call="search", **data):
    return record(
        "hook", {"hook_event_name": event, "session_id": "s1", "tool_use_id": call, **data}
    )


def message(role, blocks, uuid, **kwargs):
    return {
        "type": role,
        "session_id": "s1",
        "uuid": uuid,
        "message": {"role": role, "content": blocks},
        **kwargs,
    }


def transcript():
    use = {
        "type": "tool_use",
        "id": "search",
        "name": "Bash",
        "input": {"command": "rg authentication ."},
    }
    result = {
        "type": "tool_result",
        "tool_use_id": "search",
        "content": f"src/auth.py:1:# {MARKER}",
    }
    return [
        record(
            "capture_start",
            {"session_id": "s1", "framework_version": "2.1.322", "catalog": CATALOG},
        ),
        record("stream", message("assistant", [use], "m1")),
        hook("PreToolUse", tool_name="Bash", tool_input=use["input"]),
        hook(
            "PostToolUse",
            tool_name="Bash",
            tool_input=use["input"],
            tool_response={"stdout": result["content"]},
            duration_ms=10,
        ),
        record("stream", message("user", [result], "m2")),
        hook(
            "PostToolBatch",
            tool_calls=[
                {
                    "tool_name": "Bash",
                    "tool_use_id": "search",
                    "tool_input": use["input"],
                    "tool_response": result["content"],
                }
            ],
        ),
        record("session", message("assistant", [use], "m1")),
        record("session", message("user", [result], "m2")),
        record(
            "stream",
            {
                "type": "result",
                "session_id": "s1",
                "subtype": "success",
                "is_error": False,
                "result": '{"findings":[]}',
                "usage": {"input_tokens": 100, "output_tokens": 20},
                "total_cost_usd": 0.01,
            },
        ),
        record("capture_end", {"session_id": "s1", "status": "success"}),
    ]


def test_join_three_sources_and_distinguish_tool_output_model_bound_and_receipt(tmp_path):
    parsed = parse_claude_code_jsonl(write_trace(tmp_path, transcript()), repo_root=tmp_path)
    assert len(parsed.tool_calls) == 1
    assert parsed.tool_calls[0].duration_ms == 10
    assert parsed.tool_calls[0].content_returned_to_model is False
    assert {e["stage"] for e in parsed.exposures} == {"tool_output", "model_bound"}
    assert len(parsed.exposures) == 2
    assert all(e["model_received_payload"] == "unknown" for e in parsed.exposures)
    assert parsed.file_access == []  # No invented OS file-read record for Bash.
    assert parsed.usage["usage"]["input_tokens"] == 100


def test_read_path_is_not_payload_content_evidence(tmp_path):
    rows = [
        record("capture_start", {"catalog": CATALOG}),
        hook("PreToolUse", call="r", tool_name="Read", tool_input={"file_path": "src/auth.py"}),
        hook(
            "PostToolUse",
            call="r",
            tool_name="Read",
            tool_input={"file_path": "src/auth.py"},
            tool_response={"content": "def authentication(): pass"},
        ),
    ]
    parsed = parse_claude_code_jsonl(write_trace(tmp_path, rows), repo_root=tmp_path)
    assert parsed.file_access[0].path == "src/auth.py"
    assert not parsed.exposures
    assert not parsed.file_access[0].content_returned_to_model


def test_error_survives_serialized_batch_without_error_flag(tmp_path):
    rows = transcript()
    rows[3] = hook(
        "PostToolUseFailure",
        tool_name="Bash",
        tool_input={"command": "rg .; exit 2"},
        error=f"Exit code 2\n{MARKER}",
    )
    rows[4]["payload"]["message"]["content"][0]["is_error"] = True
    parsed = parse_claude_code_jsonl(write_trace(tmp_path, rows), repo_root=tmp_path)
    assert parsed.tool_calls[0].status == "error"


def test_historical_prefix_not_counted_as_new_actions(tmp_path):
    rows = transcript()
    rows.insert(
        1,
        record(
            "session",
            message(
                "assistant",
                [
                    {
                        "type": "tool_use",
                        "id": "old",
                        "name": "Read",
                        "input": {"file_path": "old.py"},
                    }
                ],
                "old-msg",
            ),
            historical=True,
        ),
    )
    rows.insert(2, record("session", message("user", MARKER, "old-result"), historical=True))
    parsed = parse_claude_code_jsonl(write_trace(tmp_path, rows), repo_root=tmp_path)
    metrics = behavior_metrics(parsed)
    assert metrics["tool_call_count"] == 1
    assert metrics["historical_exposure_count"] == 1
    assert "old.py" not in metrics["read_files"]


def test_same_tool_id_in_different_agents_is_not_merged(tmp_path):
    rows = []
    for agent in ("a", "b"):
        for event in ("PreToolUse", "PostToolUse"):
            r = hook(
                event,
                tool_name="Read",
                tool_input={"file_path": f"{agent}.py"},
                tool_response="text",
            )
            r["payload"]["agent_id"] = agent
            rows.append(r)
    parsed = parse_claude_code_jsonl(write_trace(tmp_path, rows), repo_root=tmp_path)
    assert len(parsed.tool_calls) == 2
    assert {c.agent_id for c in parsed.tool_calls} == {"a", "b"}


def test_normalized_artifacts_manifest_and_hashes(tmp_path):
    source = write_trace(tmp_path, transcript())
    out = tmp_path / "normalized"
    summary = normalize_trace(source, out, adapter="claude_code_jsonl", repo_root=tmp_path)
    assert summary["status"] == "ok"
    assert summary["completeness"] == "complete"
    manifest = json.loads((out / "trace_manifest.json").read_text())
    assert manifest["framework"] == "claude_code"
    assert manifest["compatibility_status"] == "validated_fixture"
    assert manifest["output_sha256"]["payload_exposure.jsonl"] == sha256_file(
        out / "payload_exposure.jsonl"
    )
    assert json.loads((out / "behavior_metrics.json").read_text())["tool_call_count"] == 1


@pytest.mark.parametrize(
    "change", ["truncated", "unknown_version", "capture_timeout", "missing_result"]
)
def test_incomplete_unvalidated_or_timeout_trace_is_not_complete(tmp_path, change):
    rows = transcript()
    if change == "unknown_version":
        rows[0]["payload"]["framework_version"] = "9.9.9"
    elif change == "capture_timeout":
        rows[-1]["payload"]["status"] = "timeout"
    elif change == "missing_result":
        rows.pop(-2)
    source = write_trace(tmp_path, rows)
    if change == "truncated":
        with source.open("a") as f:
            f.write('{"type":')
    summary = normalize_trace(
        source, tmp_path / "out", adapter="claude_code_jsonl", repo_root=tmp_path
    )
    assert summary["status"] == "partial"


def test_payload_match_is_before_redaction_but_normalized_outputs_are_redacted(tmp_path):
    redaction_fixture = "private-model-key-123456"
    rows = transcript()
    rows[3]["payload"]["tool_response"]["stdout"] += " " + redaction_fixture
    source = write_trace(tmp_path, rows)
    parsed = parse_claude_code_jsonl(source, repo_root=tmp_path, secret_values=(redaction_fixture,))
    assert parsed.exposures
    assert redaction_fixture not in json.dumps([e.model_dump() for e in parsed.events])


def test_extractor_uses_only_success_result_not_tool_or_user_json():
    text = "\n".join(json.dumps(r) for r in transcript())
    assert extract_final_answer(text, strategy="claude_jsonl") == '{"findings":[]}'
    poison = record("hook", {"tool_response": '{"findings":[]}'})
    assert extract_final_answer(json.dumps(poison), strategy="claude_jsonl") is None
    assert (
        extract_final_answer(json.dumps(record("stream", "broken")), strategy="claude_jsonl")
        is None
    )
    assert AgentConfig(trace_adapter="claude_code_jsonl", answer_extractor="claude_jsonl")


def test_descriptive_compare_does_not_claim_sampling_control(tmp_path):
    c = behavior_metrics(
        parse_claude_code_jsonl(write_trace(tmp_path, transcript()), repo_root=tmp_path)
    )
    c["pairing"] = {
        "checkpoint_id": "cp",
        "prefix_sha256": "prefix",
        "prompt_sha256": "prompt",
        "model": "model",
        "configuration_sha256": "config",
    }
    a = json.loads(json.dumps(c))
    a["actions"].append({"action_sha256": "different"})
    a["tool_call_count"] += 1
    for name, value in (("control", c), ("attack", a)):
        (tmp_path / f"{name}.json").write_text(json.dumps(value))
    result = compare_metrics(tmp_path / "control.json", tmp_path / "attack.json")
    assert result["shared_checkpoint_metadata_verified"]
    assert result["action_edit_distance"] == 1
    assert result["shared_action_prefix_length"] == 1
    assert result["deltas_attack_minus_control"]["tool_call_count"] == 1
    assert not result["causal_effect_established"]
    assert not result["sampling_randomness_controlled"]


def test_journal_sequence_and_late_window(tmp_path):
    from vulnmirage.claude_trace.collector import Collector, init_capture

    repo = tmp_path / "repo"
    repo.mkdir()
    collector = Collector(init_capture(repo, tmp_path / "out"))
    assert collector.append("test", {"long": "x" * 50000})["sequence"] == 1
    assert collector.append("test", {})["sequence"] == 2
    collector.seal()
    before = sha256_file(collector.root / "trace.raw.jsonl")
    collector.append("hook", {"hook_event_name": "InstructionsLoaded"})
    assert sha256_file(collector.root / "trace.raw.jsonl") == before
    assert (collector.root / "trace.late.jsonl").exists()


def test_parallel_sibling_is_not_counted_after_exposure_before_batch_barrier(tmp_path):
    rows = transcript()
    rows.insert(
        5, hook("PreToolUse", call="sibling", tool_name="Read", tool_input={"file_path": "safe.py"})
    )
    rows[6]["payload"]["tool_calls"].append(
        {
            "tool_use_id": "sibling",
            "tool_name": "Read",
            "tool_input": {"file_path": "safe.py"},
            "tool_response": "safe",
        }
    )
    parsed = parse_claude_code_jsonl(write_trace(tmp_path, rows), repo_root=tmp_path)
    metric = behavior_metrics(parsed)
    assert metric["tool_call_count"] == 2
    assert metric["post_exposure_tool_call_count"] == 0
    assert next(e for e in parsed.exposures if e["stage"] == "model_bound")["batch_sequence"]


def test_missing_usage_is_not_replaced_with_zero_in_comparison(tmp_path):
    metric = behavior_metrics(
        parse_claude_code_jsonl(write_trace(tmp_path, transcript()), repo_root=tmp_path)
    )
    metric["usage"] = {"usage": None}
    for name in ("c", "a"):
        (tmp_path / f"{name}.json").write_text(json.dumps(metric))
    result = compare_metrics(tmp_path / "c.json", tmp_path / "a.json")
    assert all(v is None for v in result["usage_deltas_attack_minus_control"].values())


def test_session_only_backfill_does_not_invent_exposure_timing(tmp_path):
    rows = [
        record(
            "session",
            message(
                "assistant",
                [
                    {
                        "type": "tool_use",
                        "id": "r",
                        "name": "Read",
                        "input": {"file_path": "auth.py"},
                    }
                ],
                "u",
            ),
        ),
        record(
            "session",
            message("user", [{"type": "tool_result", "tool_use_id": "r", "content": MARKER}], "v"),
        ),
    ]
    parsed = parse_claude_code_jsonl(
        write_trace(tmp_path, rows), repo_root=tmp_path, catalog=CATALOG
    )
    assert parsed.exposures[0]["stage"] == "model_bound"
    assert behavior_metrics(parsed)["post_exposure_tool_call_count"] is None


def test_child_exposure_is_not_treated_as_parent_exposure(tmp_path):
    rows = transcript()
    for r in rows[:6]:
        r["payload"]["agent_id"] = "child"
    rows.insert(
        6,
        hook("PreToolUse", call="parent", tool_name="Read", tool_input={"file_path": "parent.py"}),
    )
    rows.insert(
        7,
        hook(
            "PostToolUse",
            call="parent",
            tool_name="Read",
            tool_input={"file_path": "parent.py"},
            tool_response="safe",
        ),
    )
    parsed = parse_claude_code_jsonl(write_trace(tmp_path, rows), repo_root=tmp_path)
    assert not next(
        a for a in behavior_metrics(parsed)["actions"] if a["tool_call_id"] == "parent"
    )["after_first_model_bound_hit"]


def test_missing_source_clears_previous_exposure_sidecar(tmp_path):
    source = write_trace(tmp_path, transcript())
    out = tmp_path / "out"
    normalize_trace(source, out, adapter="claude_code_jsonl", repo_root=tmp_path)
    source.unlink()
    result = normalize_trace(source, out, adapter="claude_code_jsonl", repo_root=tmp_path)
    assert result["status"] == "missing"
    assert (out / "payload_exposure.jsonl").read_text() == ""
    assert result["manifest"].framework == "claude_code"


def test_malformed_native_frame_becomes_invalid_line(tmp_path):
    rows = transcript() + [hook("PreToolUse", tool_input={})]
    parsed = parse_claude_code_jsonl(write_trace(tmp_path, rows), repo_root=tmp_path)
    assert parsed.invalid_lines == 1


def test_read_failure_is_an_attempt_not_a_successful_read(tmp_path):
    rows = [
        hook("PreToolUse", tool_name="Read", tool_input={"file_path": "missing.py"}),
        hook(
            "PostToolUseFailure",
            tool_name="Read",
            tool_input={"file_path": "missing.py"},
            error="missing file",
        ),
    ]
    parsed = parse_claude_code_jsonl(write_trace(tmp_path, rows), repo_root=tmp_path)
    assert parsed.file_access[0].access_type == "read_attempt"
    assert behavior_metrics(parsed)["unique_read_file_count"] == 0


def test_native_version_disagreement_is_partial(tmp_path):
    source = write_trace(tmp_path, transcript())
    result = normalize_trace(
        source,
        tmp_path / "out",
        adapter="claude_code_jsonl",
        repo_root=tmp_path,
        framework_version="3.0.0",
    )
    assert result["status"] == "partial"
    assert any("identity conflicts" in note for note in result["manifest"].limitations)


def test_campaign_analysis_uses_match_evidence_without_claiming_model_receipt(tmp_path):
    from vulnmirage.mechanism.analysis import RunObservation, analyze_exposure, compare_trajectories

    source = write_trace(tmp_path, transcript())
    out = tmp_path / "normalized"
    normalize_trace(source, out, adapter="claude_code_jsonl", repo_root=tmp_path)
    observation = RunObservation(
        run_id="r1",
        variant_id="attack",
        kind="attack",
        payload_paths=("src/auth.py",),
        artifacts={
            name: out / name
            for name in (
                "trace_manifest.json",
                "payload_exposure.jsonl",
                "events.normalized.jsonl",
                "tool_calls.jsonl",
                "file_access.jsonl",
            )
        },
    )
    # Existing campaign observations list only the legacy artifacts, but run_dir
    # lets the analyzer discover the new sidecars without changing old archives.
    from dataclasses import replace

    observation = replace(
        observation,
        run_dir=out,
        artifacts={
            k: v
            for k, v in observation.artifacts.items()
            if k in {"events.normalized.jsonl", "file_access.jsonl"}
        },
    )
    exposure = analyze_exposure([observation])
    assert exposure.rows[0].content_stage == "model_bound"
    assert exposure.rows[0].exposure_state == "unknown"
    assert not exposure.rows[0].content_returned
    assert compare_trajectories([observation]).rows[0].tool_calls == 1


def test_opencode_adapter_still_normalizes_native_trace(tmp_path):
    source = write_trace(
        tmp_path,
        [
            {
                "type": "tool_use",
                "part": {
                    "tool": "read",
                    "callID": "r",
                    "state": {
                        "status": "completed",
                        "input": {"filePath": "file.py"},
                        "output": "ok",
                    },
                },
            },
            {"type": "text", "part": {"text": "done"}},
            {"type": "step_finish", "part": {"reason": "stop"}},
        ],
    )
    result = normalize_trace(source, tmp_path / "out", adapter="opencode_jsonl", repo_root=tmp_path)
    assert result["events"] == 3
    assert result["tool_calls"] == 1
    assert result["completeness"] == "complete"


def test_relative_read_uses_pre_tool_cwd_and_does_not_stop_observation(tmp_path):
    from vulnmirage.claude_trace.collector import Collector, init_capture

    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    collector = Collector(init_capture(repo, tmp_path / "capture"))
    native = {
        "hook_event_name": "PreToolUse",
        "session_id": "s1",
        "cwd": str(repo / "src"),
        "tool_name": "Read",
        "tool_use_id": "r",
        "tool_input": {"file_path": "auth.py"},
    }
    assert collector.hook(native) == {}
    rows = [
        record(
            "stream",
            message(
                "assistant",
                [
                    {
                        "type": "tool_use",
                        "id": "r",
                        "name": "Read",
                        "input": {"file_path": "auth.py"},
                    }
                ],
                "u",
            ),
        ),
        record("hook", native),
        record("hook", {**native, "hook_event_name": "PostToolUse", "tool_response": "code"}),
    ]
    parsed = parse_claude_code_jsonl(write_trace(tmp_path, rows), repo_root=repo)
    assert parsed.file_access[0].path == "src/auth.py"
    assert parsed.tool_calls[0].input_summary["file_path"] == "src/auth.py"


def test_replayed_stream_messages_do_not_count_as_current_tools(tmp_path):
    payload = message(
        "assistant",
        [{"type": "tool_use", "id": "old", "name": "Read", "input": {}}],
        "u",
        isReplay=True,
    )
    parsed = parse_claude_code_jsonl(write_trace(tmp_path, [payload]), repo_root=tmp_path)
    assert parsed.tool_calls == []


def test_user_context_attachment_text_is_not_ignored(tmp_path):
    rows = [record("session", message("user", f"Attached file contents: {MARKER}", "attached"))]
    parsed = parse_claude_code_jsonl(
        write_trace(tmp_path, rows), repo_root=tmp_path, catalog=CATALOG
    )
    assert parsed.exposures[0]["stage"] == "user_context"
    assert not parsed.tool_calls


@pytest.mark.integration
@pytest.mark.skipif(
    not shutil.which("claude") or not shutil.which("rg"), reason="Requires Claude Code and rg"
)
def test_stdout_executor_can_collect_claude_answer_and_trace(tmp_path):
    pytest.importorskip("claude_agent_sdk")
    from vulnmirage.campaign.executor import StdoutExecutor
    from vulnmirage.claude_trace.verify import local_api

    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src/auth.py").write_text("# authentication example\n")
    (repo / "src/after.py").write_text("def check(): return True\n")
    output = tmp_path / "answer"
    output.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    task = tmp_path / "task.txt"
    task.write_text("Audit authentication.")
    with local_api(repo) as (_state, env):
        env["CLAUDE_CONFIG_DIR"] = str(tmp_path / "claude-home")
        result = StdoutExecutor(
            argv=(
                sys.executable,
                "-m",
                "vulnmirage.claude_trace",
                "run",
                "--repo",
                "{repo}",
                "--out",
                "{output}/trace",
                "--prompt-file",
                "{task}",
                "--model",
                "claude-sonnet-4-6",
                "--timeout",
                "30",
                "--emit-jsonl",
            ),
            answer_extractor="claude_jsonl",
        ).run(
            repo=repo, output=output, task_file=task, env=env, run_dir=run_dir, timeout_seconds=45
        )
    assert result.status == "success"
    assert json.loads(Path(result.answer_path).read_text())["findings"] == []
    trace = normalize_trace(
        result.stdout_path, run_dir, adapter="claude_code_jsonl", repo_root=repo
    )
    assert trace["status"] == "ok"
    assert trace["tool_calls"] == 2


@pytest.mark.integration
@pytest.mark.skipif(
    not shutil.which("claude") or not shutil.which("rg"), reason="Requires Claude Code and rg"
)
def test_capture_timeout_preserves_partial_trace(tmp_path):
    pytest.importorskip("claude_agent_sdk")
    from vulnmirage.claude_trace.collector import capture_run
    from vulnmirage.claude_trace.verify import local_api

    repo = tmp_path / "repo"
    repo.mkdir()
    with local_api(repo, response_delay=4) as (_state, env):
        env["CLAUDE_CONFIG_DIR"] = str(tmp_path / "claude-home")
        result = capture_run(
            repo=repo,
            output=tmp_path / "trace",
            prompt="Perform the local test.",
            model="claude-sonnet-4-6",
            env=env,
            timeout=2,
        )
    assert result["status"] == "timeout"
    summary = normalize_trace(
        result["source"], tmp_path / "trace", adapter="claude_code_jsonl", repo_root=repo
    )
    assert summary["status"] == "partial"


@pytest.mark.integration
@pytest.mark.parametrize("tool_failure", [False, True])
@pytest.mark.skipif(
    not shutil.which("claude") or not shutil.which("rg"), reason="Requires Claude Code and rg"
)
def test_real_cli_trace_chain_and_checkpoint_forks(tmp_path, tool_failure):
    pytest.importorskip("claude_agent_sdk")
    from vulnmirage.claude_trace.verify import verify_local

    report = verify_local(tmp_path / "verify", tool_failure=tool_failure)
    assert report["passed"]
    assert report["branch_tool_call_counts"] == {"control": 2, "attack": 2}
    assert report["shared_checkpoint_metadata_verified"]
