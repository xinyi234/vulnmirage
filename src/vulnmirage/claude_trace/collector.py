"""Native command hooks + stream-json + public SDK session export.

Successful hooks are observational and return no additional model context.
All raw sources live outside the audited repository and share a locked journal.
"""

from __future__ import annotations

import fcntl
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager, suppress
from importlib.metadata import version as package_version
from pathlib import Path

from ..hashing import atomic_write_json, canonical_json, sha256_file, sha256_text, utc_now_iso
from ..trace.claude_code import CAPTURE_SCHEMA, HOOKS


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_catalog(catalog: list[dict], repo: Path):
    ids = set()
    for p in catalog:
        if not isinstance(p.get("id"), str) or not p["id"] or p["id"] in ids:
            raise ValueError("Payload ids must be unique nonempty strings")
        ids.add(p["id"])
        path = Path(p["path"])
        if (
            path.is_absolute()
            or ".." in path.parts
            or not (repo / path).resolve().is_relative_to(repo)
        ):
            raise ValueError("Payload paths must stay inside the repository")
        if (
            not isinstance(p.get("needles"), list)
            or not p["needles"]
            or any(not isinstance(n, str) or not n for n in p["needles"])
        ):
            raise ValueError("Register nonempty exact payload fragments in needles")


def init_capture(
    repo: Path,
    output: Path,
    *,
    catalog: list[dict] | None = None,
    checkpoint_config: Path | None = None,
) -> Path:
    repo, output = repo.resolve(), output.resolve()
    if not repo.is_dir() or output.is_relative_to(repo) or repo.is_relative_to(output):
        raise ValueError("Trace directory must be separate from the audited repository")
    validate_catalog(catalog or [], repo)
    if checkpoint_config:
        checkpoint_config = checkpoint_config.resolve()
        if Path(read_json(checkpoint_config)["workspace"]).resolve() != repo:
            raise ValueError("Checkpoint and trace must observe the same workspace")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    config = {
        "schema": CAPTURE_SCHEMA,
        "repo": str(repo),
        "root": str(output),
        "catalog": catalog or [],
        "checkpoint_config": str(checkpoint_config) if checkpoint_config else None,
    }
    config_path = output / "capture.json"
    atomic_write_json(config_path, config)
    command = shlex.join(
        [sys.executable, "-m", "vulnmirage.claude_trace", "hook", "--config", str(config_path)]
    )
    hooks = {}
    for event in HOOKS:
        hook = {"type": "command", "command": command, "timeout": 60}
        if event in {
            "PreToolUse",
            "PostToolUse",
            "PostToolUseFailure",
            "PostToolBatch",
            "UserPromptSubmit",
        }:
            hook["onFailure"] = "block"
        hooks[event] = [{"hooks": [hook]}]
    atomic_write_json(output / "settings.json", {"hooks": hooks, "autoMemoryEnabled": False})
    return config_path


class Collector:
    def __init__(self, config: Path):
        self.config_path = config.resolve()
        self.config = read_json(config)
        self.root = Path(self.config["root"])
        self.repo = Path(self.config["repo"])

    def append(self, kind: str, payload: dict, **metadata):
        with (self.root / "trace.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            journal = self.root / "trace.raw.jsonl"
            late = (self.root / "capture.sealed.json").exists()
            if late:
                journal = self.root / "trace.late.jsonl"
            # Recover the sequence from the journal itself: no separate state can lag a crash.
            sequence = _last_sequence(journal) + 1
            record = {
                "schema": CAPTURE_SCHEMA,
                "sequence": sequence,
                "kind": kind,
                "observed_at": utc_now_iso(),
                "observed_monotonic_ns": time.monotonic_ns(),
                "payload": payload,
                "outside_capture_window": late,
                **metadata,
            }
            with journal.open("a", encoding="utf-8") as handle:
                handle.write(canonical_json(record) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return record

    def seal(self):
        with (self.root / "trace.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            atomic_write_json(
                self.root / "capture.sealed.json",
                {
                    "time": utc_now_iso(),
                    "source_sha256": sha256_file(self.root / "trace.raw.jsonl"),
                    "late_events": "trace.late.jsonl",
                    "late_events_normalized": False,
                },
            )
        names = (
            "trace.raw.jsonl",
            "stream.native.jsonl",
            "stderr.native.log",
            "session.native.jsonl",
            "capture_summary.json",
            "capture.json",
            "settings.json",
            "capture.sealed.json",
        )
        atomic_write_json(
            self.root / "capture_sources.json",
            {
                "sha256": {
                    n: sha256_file(self.root / n) for n in names if (self.root / n).is_file()
                },
                "late_events": "trace.late.jsonl: asynchronous events outside the frozen window",
            },
        )

    def hook(self, data: dict) -> dict:
        if data.get("hook_event_name") not in HOOKS:
            raise ValueError("Unsupported hook event")
        if Path(data["cwd"]).resolve() != self.repo:
            self.append("diagnostic", {"error": "hook cwd differs from configured repository"})
        self.append("hook", data, session_id=data["session_id"], agent_id=data.get("agent_id"))
        if self.config.get("checkpoint_config"):
            from ..claude_checkpoint.core import EVENTS, Controller

            if data["hook_event_name"] in EVENTS:
                return Controller(Path(self.config["checkpoint_config"])).handle(data)
        return {}

    def export_sessions(self, sid: str, baseline: set[str], *, config_dir: str | None):
        from claude_agent_sdk import get_session_messages, get_subagent_messages, list_subagents

        with session_store(config_dir):
            messages = get_session_messages(sid, directory=str(self.repo))
            if not messages:
                raise ValueError("SDK returned no session messages")
            for m in messages:
                self.append(
                    "session",
                    {"type": m.type, "uuid": m.uuid, "session_id": sid, "message": m.message},
                    historical=m.uuid in baseline,
                )
            for agent in list_subagents(sid, directory=str(self.repo)):
                for m in get_subagent_messages(sid, agent, directory=str(self.repo)):
                    self.append(
                        "session",
                        {
                            "type": m.type,
                            "uuid": m.uuid,
                            "session_id": sid,
                            "message": m.message,
                            "parent_tool_use_id": m.parent_tool_use_id,
                            "parent_agent_id": m.parent_agent_id,
                        },
                        agent_id=agent,
                        historical=m.uuid in baseline,
                    )
        # Copy exactly the observed native transcript; never copy the user's credential store.
        hooks = [
            json.loads(line) for line in (self.root / "trace.raw.jsonl").read_text().splitlines()
        ]
        paths = {
            r["payload"].get("transcript_path")
            for r in hooks
            if r["kind"] == "hook" and r["payload"].get("session_id") == sid
        }
        for path in paths - {None}:
            file = Path(path)
            if file.name != f"{sid}.jsonl" or not file.is_file():
                continue
            target = self.root / "session.native.jsonl"
            shutil.copyfile(file, target)
            return {"messages": len(messages), "native_transcript_sha256": sha256_file(target)}
        return {"messages": len(messages), "native_transcript_sha256": None}


@contextmanager
def session_store(config_dir: str | None):
    old = os.environ.get("CLAUDE_CONFIG_DIR")
    if config_dir:
        os.environ["CLAUDE_CONFIG_DIR"] = config_dir
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
        else:
            os.environ["CLAUDE_CONFIG_DIR"] = old


def _last_sequence(path: Path) -> int:
    if not path.exists() or path.stat().st_size == 0:
        return 0
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        window = 8192
        while True:
            start = max(0, size - window)
            handle.seek(start)
            tail = handle.read()
            if not tail.endswith(b"\n"):
                raise ValueError("Interrupted journal record; refusing to append")
            if start == 0 or tail.count(b"\n") >= 2:
                return json.loads(tail.splitlines()[-1])["sequence"]
            window *= 2


@contextmanager
def _forward_termination(process, interrupted):
    """An outer campaign timeout must also terminate this wrapper's CLI group."""
    previous = {}
    timers = []

    def send(sig):
        if process.poll() is None:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, sig)

    def handler(sig, _frame):
        interrupted.append(sig)
        send(signal.SIGTERM)
        timer = threading.Timer(2, send, args=(signal.SIGKILL,))
        timer.daemon = True
        timers.append(timer)
        timer.start()

    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.signal(sig, handler)
    try:
        yield
    finally:
        for sig, old in previous.items():
            signal.signal(sig, old)
        for timer in timers:
            timer.cancel()
        if process.poll() is None:
            send(signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                send(signal.SIGKILL)
                process.wait(timeout=3)


def capture_run(
    *,
    repo: Path,
    output: Path,
    prompt: str,
    model: str | None = None,
    claude: str = "claude",
    catalog: list[dict] | None = None,
    checkpoint_config: Path | None = None,
    resume: str | None = None,
    timeout: int = 900,
    max_turns: int = 30,
    tools: str = "Bash,Read,Grep,Glob",
    env: dict[str, str] | None = None,
    system_prompt: str | None = None,
) -> dict:
    """Run one native session. No model calls occur until this function is invoked."""
    from claude_agent_sdk import get_session_messages, get_subagent_messages, list_subagents

    child_env = dict(os.environ if env is None else env)
    child_env.pop("CLAUDECODE", None)
    baseline: set[str] = set()
    sid = resume or str(uuid.uuid4())
    uuid.UUID(sid)
    config_dir = child_env.get("CLAUDE_CONFIG_DIR")
    identity = {}
    if checkpoint_config:
        cp = read_json(checkpoint_config)
        child_env["CLAUDE_CONFIG_DIR"] = config_dir = cp["claude_config_dir"]
        state = read_json(Path(cp["root"]) / "state.json")
        branch_file = state.get("branch_configs", {}).get(sid)
        if branch_file:
            branch = read_json(Path(branch_file))
            catalog = catalog if catalog is not None else branch["catalog"]
            branch_info = read_json(Path(branch_file).parent / "branch.json")
            identity = {
                "checkpoint_id": branch_info["checkpoint_id"],
                "prefix_sha256": branch_info["prefix_sha256"],
            }
        elif catalog is None:
            catalog = cp["catalog"]
    if resume:
        with session_store(config_dir):
            previous = get_session_messages(sid, directory=str(repo.resolve()))
            if not previous:
                raise ValueError("Cannot resume a session missing from the official SDK store")
            baseline.update(m.uuid for m in previous)
            for agent in list_subagents(sid, directory=str(repo.resolve())):
                baseline.update(
                    m.uuid for m in get_subagent_messages(sid, agent, directory=str(repo.resolve()))
                )
    config_path = init_capture(repo, output, catalog=catalog, checkpoint_config=checkpoint_config)
    collector = Collector(config_path)
    binary = shutil.which(claude, path=child_env.get("PATH"))
    if not binary:
        raise ValueError("Claude Code executable not found")
    version = subprocess.check_output(
        [binary, "--version"], env=child_env, text=True, timeout=15
    ).strip()
    args = [
        binary,
        "-p",
        prompt,
        "--resume" if resume else "--session-id",
        sid,
        "--output-format",
        "stream-json",
        "--verbose",
        "--include-hook-events",
        "--settings",
        str(collector.root / "settings.json"),
        "--setting-sources",
        "",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--disable-slash-commands",
        "--max-turns",
        str(max_turns),
        "--tools",
        tools,
    ]
    if tools:
        args += ["--allowedTools", *tools.split(",")]
    if model:
        args += ["--model", model]
    if system_prompt:
        args += ["--system-prompt", system_prompt]
    configuration = {
        "model": model,
        "tools": tools,
        "max_turns": max_turns,
        "timeout_seconds": timeout,
        "system_prompt_sha256": sha256_text(system_prompt) if system_prompt is not None else None,
        "framework_version": version,
        "sdk_version": package_version("claude-agent-sdk"),
        "setting_sources": "",
        "external_mcp_servers": False,
        "auto_memory_enabled": False,
        "endpoint_sha256": sha256_text(child_env.get("ANTHROPIC_BASE_URL", "default_anthropic")),
        "checkpoint_enabled": checkpoint_config is not None,
    }
    inventory = []
    for p in catalog or []:
        file = collector.repo / p["path"]
        inventory.append(
            {
                "payload_id": p["id"],
                "path": p["path"],
                "exists": file.is_file(),
                "sha256": sha256_file(file) if file.is_file() else None,
            }
        )
    collector.append(
        "capture_start",
        {
            "session_id": sid,
            "framework_version": version,
            "catalog": catalog or [],
            "repo": str(collector.repo),
            "resume": bool(resume),
            "historical_message_count": len(baseline),
            "prompt_sha256": sha256_text(prompt),
            "model": model,
            "configuration": configuration,
            "configuration_sha256": sha256_text(canonical_json(configuration)),
            "inventory": inventory,
            **identity,
        },
    )
    errors = []

    def stdout_reader(pipe):
        try:
            with (collector.root / "stream.native.jsonl").open("w", encoding="utf-8") as log:
                for line in pipe:
                    log.write(line)
                    log.flush()
                    try:
                        payload = json.loads(line)
                        if not isinstance(payload, dict):
                            raise ValueError("non-object stdout record")
                        collector.append(
                            "stream",
                            payload,
                            historical=(
                                payload.get("uuid") in baseline
                                or bool(payload.get("isReplay") or payload.get("is_replay"))
                            ),
                        )
                    except (ValueError, json.JSONDecodeError):
                        errors.append("invalid native stream line")
        except Exception as exc:
            errors.append(f"stream capture failed: {type(exc).__name__}")

    child_env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    started = time.monotonic()
    timed_out = False
    interrupted = []
    with (collector.root / "stderr.native.log").open("w", encoding="utf-8") as stderr:
        process = subprocess.Popen(
            args,
            cwd=collector.repo,
            env=child_env,
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
        )
        reader = threading.Thread(target=stdout_reader, args=(process.stdout,), daemon=True)
        reader.start()
        with _forward_termination(process, interrupted):
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
            reader.join(timeout=5)
            if reader.is_alive():
                errors.append("stdout reader did not terminate")
    try:
        session_info = collector.export_sessions(sid, baseline, config_dir=config_dir)
    except Exception as exc:
        session_info = {}
        errors.append(f"session export failed: {type(exc).__name__}")
    for error in errors:
        collector.append("diagnostic", {"error": error})
    status = (
        "timeout"
        if timed_out
        else "interrupted"
        if interrupted
        else "success"
        if process.returncode == 0 and not errors
        else "error"
    )
    summary = {
        "session_id": sid,
        "status": status,
        "exit_code": process.returncode,
        "duration_seconds": time.monotonic() - started,
        **session_info,
        **identity,
    }
    collector.append("capture_end", summary)
    atomic_write_json(collector.root / "capture_summary.json", summary)
    collector.seal()
    return {
        **summary,
        "source": str(collector.root / "trace.raw.jsonl"),
        "framework_version": version,
    }
