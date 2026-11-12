"""Observable behavior measures; single-run deltas are not causal estimates."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from ..hashing import atomic_write_json, canonical_json, sha256_text


def behavior_metrics(result) -> dict:
    exposures = [e for e in result.exposures if not e["historical"]]
    bound = [e for e in exposures if e["stage"] == "model_bound"]
    ordered_bound = [e for e in bound if e.get("evidence_origin") != "session"]
    first = min((e.get("batch_sequence") or e["sequence"] for e in ordered_bound), default=None)
    by_scope = {}
    for e in ordered_bound:
        scope = (e["session_id"], e["agent_id"])
        sequence = e.get("batch_sequence") or e["sequence"]
        by_scope[scope] = min(sequence, by_scope.get(scope, sequence))
    actions = []
    root = result.capture.get("repo", "")
    for call in sorted(result.tool_calls, key=lambda c: c.sequence):
        start = result.events[call.sequence - 1]
        order_known = start.metadata.get("origin") in {"hook", "stream"}
        scope_first = by_scope.get((call.session_id, call.agent_id))
        inputs = dict(call.input_summary)
        if root and isinstance(inputs.get("command"), str):
            inputs["command"] = inputs["command"].replace(root, "${REPO}")
        # Native descriptions are often resampled prose, so action identity excludes them.
        identity = {
            "tool": call.tool_name,
            "cwd": start.metadata.get("cwd"),
            "input": {k: v for k, v in inputs.items() if k != "description"},
        }
        actions.append(
            {
                "sequence": call.sequence,
                "tool_call_id": call.tool_call_id,
                "session_id": call.session_id,
                "agent_id": call.agent_id,
                "tool": call.tool_name,
                "input": inputs,
                "status": call.status,
                "action_sha256": sha256_text(canonical_json(identity)),
                "ordering_basis": "native_observation" if order_known else "session_backfill",
                "after_first_model_bound_hit": (
                    (call.sequence > scope_first) if order_known else None
                )
                if scope_first is not None
                else False,
            }
        )
    reads = sorted({f.path for f in result.file_access if f.access_type == "read"})
    return {
        "schema_version": "1.0",
        "scope": "observed behavior; no adoption/causal label",
        "pairing": {
            k: result.capture.get(k)
            for k in (
                "checkpoint_id",
                "prefix_sha256",
                "prompt_sha256",
                "model",
                "configuration_sha256",
            )
        },
        "tool_call_count": len(actions),
        "tool_error_count": sum(a["status"] == "error" for a in actions),
        "tool_counts": dict(Counter(a["tool"] for a in actions)),
        "file_access_count": len(result.file_access),
        "read_files": reads,
        "unique_read_file_count": len(reads),
        "first_model_bound_hit_sequence": first,
        "first_model_bound_hit_by_agent": [
            {"session_id": s, "agent_id": a, "sequence": n} for (s, a), n in by_scope.items()
        ],
        "post_exposure_tool_call_count": sum(
            a["after_first_model_bound_hit"] is True for a in actions
        )
        if first and all(a["after_first_model_bound_hit"] is not None for a in actions)
        else None,
        "exposure_counts_by_stage": dict(Counter(e["stage"] for e in exposures)),
        "exposure_window_basis": "serialized batch barrier, else native observation; per agent",
        "historical_exposure_count": sum(e["historical"] for e in result.exposures),
        "usage": result.usage,
        "duration_seconds": result.capture.get("duration_seconds"),
        "action_identity_basis": "tool and redacted/truncated input summary; description excluded",
        "actions": actions,
        "model_received_payload": "unknown",
        "limitations": [
            "no exact/semantic hit is not proof of non-exposure",
            "file scopes for Grep/Glob are not proof that every file's content was read",
            "agent time and tool counts include instrumentation effects",
        ],
    }


def _edit_distance(a, b):
    previous = list(range(len(b) + 1))
    for i, item in enumerate(a, 1):
        row = [i]
        for j, other in enumerate(b, 1):
            row.append(min(row[-1] + 1, previous[j] + 1, previous[j - 1] + (item != other)))
        previous = row
    return previous[-1]


def compare_metrics(control: Path, attack: Path, output: Path | None = None) -> dict:
    def load(path):
        return json.loads((path / "behavior_metrics.json" if path.is_dir() else path).read_text())

    c, a = load(control), load(attack)

    def tokens(metric):
        return metric["usage"].get("usage") or {}

    pc, pa = c["pairing"], a["pairing"]
    matched = all(
        pc.get(k) and pc.get(k) == pa.get(k)
        for k in (
            "checkpoint_id",
            "prefix_sha256",
            "prompt_sha256",
            "model",
            "configuration_sha256",
        )
    )
    left = [x["action_sha256"] for x in c["actions"]]
    right = [x["action_sha256"] for x in a["actions"]]
    index = next(
        (i for i, pair in enumerate(zip(left, right, strict=False)) if pair[0] != pair[1]),
        min(len(left), len(right)),
    )
    distance = _edit_distance(left, right)
    cfiles, afiles = set(c["read_files"]), set(a["read_files"])
    numeric = (
        "tool_call_count",
        "tool_error_count",
        "file_access_count",
        "unique_read_file_count",
        "post_exposure_tool_call_count",
    )
    report = {
        "schema_version": "1.0",
        "shared_checkpoint_metadata_verified": bool(matched),
        "pairing_basis": (
            "recorded checkpoint, semantic prefix, prompt and model labels; "
            "request bodies not compared"
        ),
        "causal_effect_established": False,
        "sampling_randomness_controlled": False,
        "deltas_attack_minus_control": {
            k: a[k] - c[k] if a[k] is not None and c[k] is not None else None for k in numeric
        },
        "action_edit_distance": distance,
        "normalized_action_edit_distance": distance / max(len(left), len(right))
        if left or right
        else 0.0,
        "shared_action_prefix_length": index,
        "first_divergence_action_index": index if left != right else None,
        "read_file_jaccard": len(cfiles & afiles) / len(cfiles | afiles)
        if cfiles | afiles
        else None,
        "additional_read_files": sorted(afiles - cfiles),
        "missing_read_files": sorted(cfiles - afiles),
        "usage_deltas_attack_minus_control": {
            k: tokens(a).get(k) - tokens(c).get(k)
            if all(isinstance(tokens(m).get(k), (int, float)) for m in (c, a))
            else None
            for k in (
                "input_tokens",
                "output_tokens",
                "cache_read_input_tokens",
                "cache_creation_input_tokens",
            )
        },
        "limitations": [
            "natural drift requires repeated control/control and control/attack trials",
            "requests, compaction, context loads, and unknown exposure can confound the comparison",
        ],
    }
    if output:
        atomic_write_json(output, report)
    return report
