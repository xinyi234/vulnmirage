"""Trusted, local hook controller. No LLM calls; native sessions use the public SDK.

Evidence describes observations, never claims that a hook sees provider input.
The controller is deliberately conservative about unsupported context channels.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from vulnmirage.hashing import atomic_write_json, canonical_json, sha256_file, utc_now_iso

IGNORED = {".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
EVENTS = (
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "InstructionsLoaded",
    "SubagentStart",
    "PreCompact",
)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def replacement_spec(value: Any) -> tuple[str, list[str]]:
    """A string is shorthand; multiline variants can register shorter exact fragments."""
    text = value if isinstance(value, str) else value["text"]
    needles = ([text] if text else []) if isinstance(value, str) else value["needles"]
    if not isinstance(text, str) or not isinstance(needles, list):
        raise ValueError("Variant needs text and a list of exact needles")
    if text and not needles:
        raise ValueError("Nonempty variants require detection needles")
    if any(not isinstance(n, str) or not n or n not in text for n in needles):
        raise ValueError("Variant needles must be nonempty fragments of replacement text")
    return text, needles


def relative_file(root: Path, name: str) -> Path:
    """Only ordinary files inside an owned workspace; reject symlink traversal."""
    rel = Path(name)
    if rel.is_absolute() or ".." in rel.parts or not rel.parts:
        raise ValueError(f"Invalid relative file: {name}")
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Symlinks unsupported: {name}")
    if not current.resolve().is_relative_to(root.resolve()):
        raise ValueError("Path escapes workspace")
    return current


def copy_tree(source: Path, target: Path) -> dict[str, Any]:
    """Bounded, content-addressed file snapshot including .git, rejecting special files."""
    target.mkdir(parents=True, exist_ok=False)
    manifest: dict[str, Any] = {}
    total = 0
    for base, dirs, files in os.walk(source, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED)
        for name in dirs + sorted(files):
            src = Path(base) / name
            if src.is_symlink():
                raise ValueError(f"Symlinks unsupported in snapshot: {src}")
            if src.is_dir():
                (target / src.relative_to(source)).mkdir(exist_ok=True)
                continue
            if not stat.S_ISREG(src.stat().st_mode):
                raise ValueError(f"Special file unsupported: {src}")
            total += src.stat().st_size
            if len(manifest) >= 10000 or total > 128 * 1024 * 1024:
                raise ValueError("Prototype snapshot limit: 10000 files / 128 MiB")
            rel = src.relative_to(source).as_posix()
            dst = target / rel
            shutil.copy2(src, dst)
            manifest[rel] = {"sha256": sha256_file(dst), "mode": stat.S_IMODE(dst.stat().st_mode)}
    return manifest


def verify_tree(root: Path, manifest: dict[str, Any]) -> None:
    actual = {
        (Path(base) / name).relative_to(root).as_posix()
        for base, dirs, files in os.walk(root, followlinks=False)
        for name in files
    }
    if actual != set(manifest):
        raise ValueError("Snapshot file set changed")
    for name, expected in manifest.items():
        file = relative_file(root, name)
        if (
            sha256_file(file) != expected["sha256"]
            or stat.S_IMODE(file.stat().st_mode) != expected["mode"]
        ):
            raise ValueError(f"Snapshot integrity check failed: {name}")
    for base, dirs, _ in os.walk(root, followlinks=False):
        if any((Path(base) / d).is_symlink() for d in dirs):
            raise ValueError("Snapshot contains symlink directory")


def init_run(source: Path, output: Path, catalog: list[dict[str, Any]]) -> Path:
    source, output = source.resolve(), output.resolve()
    if output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError("Control directory and source repository must be separate")
    if not catalog or len({p["id"] for p in catalog}) != len(catalog):
        raise ValueError("Payload catalog needs unique ids")
    if len({p["path"] for p in catalog}) != len(catalog):
        raise ValueError("Prototype supports one injection region per file")
    for item in catalog:
        relative_file(source, item["path"])
        if not item.get("text") or not item.get("needles"):
            raise ValueError("Each payload needs nonempty text and exact detection needles")
        replacement_spec(item)
        if item["text"] not in relative_file(source, item["path"]).read_text():
            raise ValueError(f"Payload absent from configured file: {item['path']}")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    copy_tree(source, output / "workspace")
    (output / "checkpoints").mkdir()
    (output / "branches").mkdir()
    (output / "claude-home").mkdir()
    config = {
        "schema_version": 1,
        "root": str(output),
        "workspace": str(output / "workspace"),
        "catalog": catalog,
        "claude_config_dir": str(output / "claude-home"),
        "coverage": "exact registered fragments; top-level tool hooks only",
        "mode": "capture",
    }
    config_path = output / "config.json"
    atomic_write_json(config_path, config)
    command = shlex.join(
        [
            sys.executable,
            "-m",
            "vulnmirage.claude_checkpoint",
            "hook",
            "--config",
            str(config_path),
        ]
    )
    hooks = {}
    for event in EVENTS:
        entry: dict[str, Any] = {"type": "command", "command": command, "timeout": 60}
        if event in {
            "PreToolUse",
            "PostToolUse",
            "PostToolUseFailure",
            "PostToolBatch",
            "UserPromptSubmit",
        }:
            entry["onFailure"] = "block"
        # Omitted matchers apply to every tool. InstructionsLoaded is observational only.
        hooks[event] = [{"hooks": [entry]}]
    atomic_write_json(output / "settings.json", {"hooks": hooks})
    atomic_write_json(
        output / "state.json", {"sessions": {}, "branch_configs": {}, "next_event": 1}
    )
    return config_path


class Controller:
    def __init__(self, config_path: Path):
        self.config_path = config_path.resolve()
        self.config = read_json(self.config_path)
        self.root = Path(self.config["root"])
        self.workspace = Path(self.config["workspace"])

    @contextmanager
    def locked(self):
        with (self.root / "controller.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = read_json(self.root / "state.json")
            try:
                yield state
            finally:
                atomic_write_json(self.root / "state.json", state)
                fcntl.flock(lock, fcntl.LOCK_UN)

    def hits(self, value: Any) -> list[dict[str, Any]]:
        """Search ALL response strings, regardless of tool name or file name."""
        found: list[dict[str, Any]] = []

        def walk(item: Any, pointer: str):
            if isinstance(item, str):
                for payload in self.config["catalog"]:
                    for needle in payload["needles"]:
                        index = item.find(needle)
                        if index >= 0:
                            found.append(
                                {
                                    "payload_id": payload["id"],
                                    "json_pointer": pointer,
                                    "character_offset": index,
                                    "needle_sha256": digest(needle),
                                }
                            )
            elif isinstance(item, list):
                for i, child in enumerate(item):
                    walk(child, f"{pointer}/{i}")
            elif isinstance(item, dict):
                for key, child in item.items():
                    escaped = str(key).replace("~", "~0").replace("/", "~1")
                    walk(str(key), f"{pointer}/{escaped}/@key")
                    walk(child, f"{pointer}/{escaped}")

        walk(value, "")
        return found

    def event(self, state: dict, sid: str, stage: str, **evidence) -> int:
        number = state["next_event"]
        state["next_event"] += 1
        entry = {
            "sequence": number,
            "time": utc_now_iso(),
            "session_id": sid,
            "stage": stage,
            **evidence,
        }
        with (self.root / "events.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(entry) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return number

    def invalidate(self, state: dict, sid: str, session: dict, reason: str, **evidence):
        session["invalid_reasons"].append(reason)
        session["checkpoint_eligible"] = False
        self.event(state, sid, "checkpoint_scope_invalid", reason=reason, **evidence)

    def instruction_preflight(self) -> list[dict[str, Any]]:
        """Conservative inventory, not proof of what Claude has actually loaded."""
        files: set[Path] = set()
        for directory in [self.workspace, *self.workspace.parents]:
            for name in ("CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "README.md"):
                if (directory / name).is_file():
                    files.add(directory / name)
            rules = directory / ".claude" / "rules"
            if rules.is_dir():
                files.update(rules.rglob("*.md"))
            if (directory / ".claude" / "CLAUDE.md").is_file():
                files.add(directory / ".claude" / "CLAUDE.md")
        for pattern in ("CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "README.md"):
            files.update(self.workspace.rglob(pattern))
        for directory in self.workspace.rglob(".claude"):
            rules = directory / "rules"
            if rules.is_dir():
                files.update(rules.rglob("*.md"))
        matches = []
        for file in sorted(files):
            hits = self.hits(file.read_text(encoding="utf-8", errors="replace"))
            if hits:
                matches.append({"file": str(file), "hits": hits})
        return matches

    @contextmanager
    def sdk_store(self):
        """Scope the public SDK's store selection to this synchronous operation."""
        previous = os.environ.get("CLAUDE_CONFIG_DIR")
        os.environ["CLAUDE_CONFIG_DIR"] = self.config["claude_config_dir"]
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop("CLAUDE_CONFIG_DIR", None)
            else:
                os.environ["CLAUDE_CONFIG_DIR"] = previous

    def messages(self, sid: str) -> list[dict[str, Any]]:
        from claude_agent_sdk import get_session_messages

        with self.sdk_store():
            return [
                {"type": m.type, "uuid": m.uuid, "message": m.message}
                for m in get_session_messages(sid, directory=str(self.workspace))
            ]

    def checkpoint(self, state: dict, sid: str, session: dict, data: dict) -> str | None:
        messages = self.messages(sid)
        if self.hits(messages):
            self.invalidate(state, sid, session, "registered_fragment_already_in_transcript")
            return None
        pending: set[str] = set()
        cut = 0
        for i, message in enumerate(messages):
            content = message["message"].get("content", [])
            if isinstance(content, list):
                for block in content:
                    if block.get("type") == "tool_use":
                        pending.add(block["id"])
                    elif block.get("type") == "tool_result":
                        pending.discard(block["tool_use_id"])
            if not pending:
                cut = i + 1
        if not cut:
            self.invalidate(state, sid, session, "no_balanced_conversation_prefix")
            return None
        prefix = messages[:cut]
        uuid.UUID(prefix[-1]["uuid"])
        checkpoint_id = str(uuid.uuid4())
        folder = self.root / "checkpoints" / checkpoint_id
        folder.mkdir()
        # Transcript is evidence; SDK handles native parent chains and parallel tool turns.
        transcript = Path(data["transcript_path"]).read_bytes()
        for line in transcript.splitlines():
            json.loads(line)  # Fail closed on a partial JSONL write.
        (folder / "transcript.jsonl").write_bytes(transcript)
        # Parallel tools may append a result between the SDK read and the raw copy.
        # Reject that race if a registered fragment is anywhere in the persisted log.
        if self.hits([json.loads(line) for line in transcript.splitlines()]):
            self.invalidate(state, sid, session, "registered_fragment_in_checkpoint_transcript")
            return None
        manifest = copy_tree(self.workspace, folder / "files")
        record = {
            "id": checkpoint_id,
            "session_id": sid,
            "tool_use_id": data.get("tool_use_id"),
            "pending_tool": {"name": data.get("tool_name"), "input": data.get("tool_input")},
            "cut_message_id": prefix[-1]["uuid"],
            "prefix": prefix,
            "prefix_sha256": digest([{k: m[k] for k in ("type", "message")} for m in prefix]),
            "transcript_sha256": sha256_file(folder / "transcript.jsonl"),
            "files": manifest,
            "files_sha256": digest(manifest),
            "pending_turn_rewound": cut != len(messages),
            "filesystem_boundary": "pre_tool_hook_time; requires read-only exploration before cut",
            "model_received_payload": "unknown",
            "scope": "registered exact fragments in observed top-level content",
        }
        atomic_write_json(folder / "checkpoint.json", record)
        sequence = self.event(
            state,
            sid,
            "pre_tool_checkpoint",
            checkpoint_id=checkpoint_id,
            tool_use_id=data.get("tool_use_id"),
            tool_name=data.get("tool_name"),
            cut_message_id=record["cut_message_id"],
        )
        session["candidates"][data["tool_use_id"]] = {
            "checkpoint_id": checkpoint_id,
            "event_sequence": sequence,
        }
        return checkpoint_id

    def handle(self, data: dict) -> dict:
        event = data["hook_event_name"]
        if event not in EVENTS:
            raise ValueError(f"Unsupported hook: {event}")
        sid = data["session_id"]
        uuid.UUID(sid)
        with self.locked() as state:
            branch_path = state.get("branch_configs", {}).get(sid)
            worker = Controller(Path(branch_path)) if branch_path else self
            return worker.handle_locked(state, data)

    def handle_locked(self, state: dict, data: dict) -> dict:
        event = data["hook_event_name"]
        sid = data["session_id"]
        session = state["sessions"].setdefault(
            sid,
            {
                "candidates": {},
                "invalid_reasons": [],
                "first_return_hit": None,
                "selected_checkpoint": None,
                "model_received_payload": "unknown",
                "checkpoint_eligible": False,
            },
        )
        self.event(state, sid, "hook_received", hook=event, tool_use_id=data.get("tool_use_id"))
        source_sid = self.config.get("source_session_id")
        if source_sid:
            source = state["sessions"].get(source_sid, {})
            if (
                source.get("invalid_reasons")
                or not source.get("checkpoint_eligible")
                or source.get("selected_checkpoint") != self.config["source_checkpoint_id"]
            ):
                self.invalidate(state, sid, session, "source_checkpoint_revoked")
        if Path(data["cwd"]).resolve() != self.workspace:
            self.invalidate(state, sid, session, "unexpected_workspace")
        if event in {"SessionStart", "UserPromptSubmit"}:
            matches = self.instruction_preflight()
            if matches:
                self.invalidate(
                    state, sid, session, "potential_startup_instruction_payload", evidence=matches
                )
            if event == "SessionStart":
                for payload in self.config["catalog"]:
                    file = relative_file(self.workspace, payload["path"])
                    self.event(
                        state,
                        sid,
                        "payload_on_disk",
                        path=payload["path"],
                        exists=file.exists(),
                        hits=self.hits(file.read_text()) if file.exists() else [],
                        file_sha256=sha256_file(file) if file.exists() else None,
                    )
            if self.hits(data.get("prompt", "")):
                self.invalidate(state, sid, session, "payload_in_user_prompt")
        elif event == "InstructionsLoaded":
            # File bytes now are not necessarily the bytes already loaded by Claude.
            file = Path(data["file_path"])
            hits = self.hits(file.read_text(errors="replace")) if file.is_file() else []
            self.event(
                state,
                sid,
                "instruction_load_observed",
                path=str(file),
                hits=hits,
                loaded_bytes_verified=False,
                load_reason=data.get("load_reason"),
            )
            if hits or not file.is_file():
                self.invalidate(state, sid, session, "uncontrolled_instruction_load")
        elif event in {"PreCompact", "SubagentStart"}:
            self.invalidate(state, sid, session, f"unsupported_{event}")
        elif event == "PreToolUse":
            if data.get("tool_name") in {"Agent", "Task"}:
                self.invalidate(state, sid, session, "subagents_not_supported")
            if (
                self.config["mode"] == "capture"
                and not session["invalid_reasons"]
                and not session["first_return_hit"]
            ):
                self.checkpoint(state, sid, session, data)
            if data.get("tool_name") == "Read":
                self.event(
                    state,
                    sid,
                    "file_read_attempted",
                    file=data["tool_input"].get("file_path"),
                    tool_use_id=data["tool_use_id"],
                    os_read_verified=False,
                )
        elif event in {"PostToolUse", "PostToolUseFailure", "PostToolBatch"}:
            calls = data.get("tool_calls", []) if event == "PostToolBatch" else [data]
            for call in calls:
                tool_id = call.get("tool_use_id")
                response = (
                    {"error": call.get("error")}
                    if event == "PostToolUseFailure"
                    else call.get("tool_response")
                )
                representation = {
                    "PostToolUse": "structured_tool_output",
                    "PostToolUseFailure": "failure_display_text",
                    "PostToolBatch": "serialized_model_bound_tool_result",
                }[event]
                if call.get("tool_name") == "Read" and event == "PostToolUse":
                    self.event(
                        state,
                        sid,
                        "file_read_tool_completed",
                        tool_use_id=tool_id,
                        os_read_verified=False,
                    )
                hits = self.hits(response)
                if not hits:
                    continue
                evidence_id = str(uuid.uuid4())
                evidence = self.root / f"tool-return-{evidence_id}.json"
                atomic_write_json(evidence, response)
                seq = self.event(
                    state,
                    sid,
                    "tool_response_contains_payload",
                    hits=hits,
                    tool_name=call.get("tool_name"),
                    tool_use_id=tool_id,
                    evidence_file=evidence.name,
                    evidence_sha256=sha256_file(evidence),
                    model_received_payload="unknown",
                    response_representation=representation,
                    hook=event,
                )
                if session["first_return_hit"] is None:
                    candidate = session["candidates"].get(tool_id)
                    session["first_return_hit"] = {"event_sequence": seq, "tool_use_id": tool_id}
                    if self.config["mode"] == "observe":
                        self.event(
                            state,
                            sid,
                            "branch_exposure_observed",
                            tool_use_id=tool_id,
                            model_received_payload="unknown",
                        )
                    elif candidate and not session["invalid_reasons"]:
                        session["selected_checkpoint"] = candidate["checkpoint_id"]
                        session["checkpoint_eligible"] = True
                    else:
                        self.invalidate(state, sid, session, "hit_without_clean_pre_tool_candidate")
        stop = bool(
            session["invalid_reasons"]
            or (self.config["mode"] == "capture" and session["first_return_hit"])
        )
        # InstructionsLoaded and SubagentStart ignore continue; next blocking hook enforces it.
        # 'decision: block' on PostToolUse does NOT hide the original tool result.
        return {"continue": False} if stop else {}

    def fork(self, sid: str, variants: list[dict[str, Any]]) -> dict:
        from claude_agent_sdk import fork_session, get_session_messages

        with self.locked() as state:
            session = state["sessions"][sid]
            if session["invalid_reasons"] or not session["selected_checkpoint"]:
                raise ValueError("No eligible pre-exposure checkpoint; inspect state.json")
            checkpoint_id = session["selected_checkpoint"]
            folder = self.root / "checkpoints" / checkpoint_id
            checkpoint = read_json(folder / "checkpoint.json")
            verify_tree(folder / "files", checkpoint["files"])
            if (
                digest(checkpoint["files"]) != checkpoint["files_sha256"]
                or sha256_file(folder / "transcript.jsonl") != checkpoint["transcript_sha256"]
            ):
                raise ValueError("Checkpoint evidence changed")
            current = self.messages(sid)
            end = next(
                i for i, m in enumerate(current) if m["uuid"] == checkpoint["cut_message_id"]
            )
            semantic = [{k: m[k] for k in ("type", "message")} for m in current[: end + 1]]
            if digest(semantic) != checkpoint["prefix_sha256"] or self.hits(semantic):
                raise ValueError("Source conversation prefix changed or contaminated")
            names = [v["name"] for v in variants]
            if not names or len(set(names)) != len(names):
                raise ValueError("Need unique branch names")
            # Validate all edits before creating native forks.
            for variant in variants:
                if not re.fullmatch(r"[A-Za-z0-9_-]+", variant["name"]):
                    raise ValueError("Invalid branch name")
                if (self.root / "branches" / variant["name"]).exists():
                    raise ValueError("Branch already exists")
                edits = variant["payloads"]
                if set(edits) != {p["id"] for p in self.config["catalog"]}:
                    raise ValueError(
                        "Each branch must specify replacement text for every payload id"
                    )
                for p in self.config["catalog"]:
                    replacement, needles = replacement_spec(edits[p["id"]])
                    temporary = Controller(self.config_path)
                    temporary.config = {
                        **self.config,
                        "catalog": [
                            {**p, "text": replacement, "needles": needles},
                        ],
                    }
                    if temporary.hits(semantic):
                        raise ValueError("Variant text already appears in the common prefix")
                    file = relative_file(folder / "files", p["path"])
                    if file.read_text().count(p["text"]) != 1:
                        raise ValueError(
                            "Payload replacement requires exactly one original occurrence"
                        )
            branches = []
            for variant in variants:
                branch_root = self.root / "branches" / variant["name"]
                branch_root.mkdir()
                files = branch_root / "files"
                copy_tree(folder / "files", files)
                branch_catalog = []
                for p in self.config["catalog"]:
                    file = relative_file(files, p["path"])
                    replacement, needles = replacement_spec(variant["payloads"][p["id"]])
                    file.write_text(
                        file.read_text().replace(p["text"], replacement), encoding="utf-8"
                    )
                    if replacement:
                        branch_catalog.append({**p, "text": replacement, "needles": needles})
                with self.sdk_store():
                    result = fork_session(
                        sid,
                        directory=str(self.workspace),
                        up_to_message_id=checkpoint["cut_message_id"],
                        title=f"VulnMirage {variant['name']}",
                    )
                    copied = get_session_messages(result.session_id, directory=str(self.workspace))
                actual = [{"type": m.type, "message": m.message} for m in copied]
                if digest(actual) != checkpoint["prefix_sha256"]:
                    raise ValueError("Official fork did not preserve the expected semantic prefix")
                branch_config = {
                    **self.config,
                    "catalog": branch_catalog,
                    "mode": "observe",
                    "source_session_id": sid,
                    "source_checkpoint_id": checkpoint_id,
                }
                atomic_write_json(branch_root / "config.json", branch_config)
                state.setdefault("branch_configs", {})[result.session_id] = str(
                    branch_root / "config.json"
                )
                manifest = {}
                for name in checkpoint["files"]:
                    file = relative_file(files, name)
                    manifest[name] = {
                        "sha256": sha256_file(file),
                        "mode": stat.S_IMODE(file.stat().st_mode),
                    }
                branch = {
                    "name": variant["name"],
                    "session_id": result.session_id,
                    "source_session_id": sid,
                    "checkpoint_id": checkpoint_id,
                    "prefix_sha256": checkpoint["prefix_sha256"],
                    "files": manifest,
                }
                atomic_write_json(branch_root / "branch.json", branch)
                branches.append(branch)
            return {
                "branches": branches,
                "execution": "activate and resume serially at original cwd",
            }

    def activate(self, name: str) -> dict:
        """Restore only our owned copy, preserving absolute paths embedded in conversation."""
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise ValueError("Invalid branch name")
        with self.locked() as state:
            folder = self.root / "branches" / name
            branch = read_json(folder / "branch.json")
            source = state["sessions"].get(branch["source_session_id"], {})
            if (
                source.get("invalid_reasons")
                or not source.get("checkpoint_eligible")
                or source.get("selected_checkpoint") != branch["checkpoint_id"]
            ):
                raise ValueError("Source checkpoint has been revoked")
            verify_tree(folder / "files", branch["files"])
            observer = Controller(folder / "config.json")
            if observer.hits(
                [
                    {k: m[k] for k in ("type", "message")}
                    for m in self.messages(branch["session_id"])
                ]
            ):
                raise ValueError("Branch prefix is already contaminated")
            # One workspace only: caller must stop the previous Claude process first.
            if self.workspace.is_symlink():
                raise ValueError("Owned workspace was replaced by a symlink")
            staging = self.root / f"restore-{uuid.uuid4()}"
            copy_tree(folder / "files", staging)
            # Preserve the cwd inode, so a shell inside workspace can resume safely.
            for child in self.workspace.iterdir():
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            for child in staging.iterdir():
                child.rename(self.workspace / child.name)
            staging.rmdir()
            state["active_branch"] = name
            return {
                "session_id": branch["session_id"],
                "cwd": str(self.workspace),
                "note": "Resume serially with the same launch flags and continuation prompt",
            }

    def record_hook_failure(self, data: dict, exception_type: str) -> None:
        sid = data.get("session_id")
        with self.locked() as state:
            if sid in state["sessions"]:
                self.invalidate(
                    state,
                    sid,
                    state["sessions"][sid],
                    "hook_execution_failed",
                    exception_type=exception_type,
                )
