"""How one audit is executed, and how the answer is collected.

Two shapes are supported, and they differ only in where the answer comes from:

``argv``
    the command is given ``{repo}``, ``{output}`` and ``{task}`` and writes the final
    answer into ``{output}`` itself;
``stdout``
    the command prints; the harness captures stdout and extracts the last JSON
    object (or the last text part of a ``jsonl`` event stream, which is what OpenCode
    emits).

Both run through :func:`vulnmirage.harness.sandbox.run_agent_process`, so both get
the same process control, the same redirect-to-file behaviour and the same timeout
handling.  Neither interprets the answer: extraction only *locates* it.
"""

from __future__ import annotations

import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..errors import CampaignError
from ..harness.sandbox import run_agent_process
from ..isolation.gateway import InferenceGateway, rewrite_opencode_for_gateway
from ..isolation.network import EgressProbeResult, ProbeTarget, probe_egress

#: File names an ``argv`` executor may write the answer to, in priority order.
ANSWER_FILENAMES: tuple[str, ...] = ("final_raw.txt", "final_answer.txt", "answer.json")


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    exit_code: int | None = None
    duration_seconds: float | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    answer_path: str | None = None
    error: str | None = None


class AuditExecutor(Protocol):
    mode: str

    def run(
        self,
        *,
        repo: Path,
        output: Path,
        task_file: Path,
        env: dict[str, str],
        run_dir: Path,
        timeout_seconds: int,
    ) -> ExecutionResult: ...


def expand_argv(
    argv: list[str] | tuple[str, ...], *, repo: Path, output: Path, task: Path
) -> list[str]:
    """Substitute the placeholders an agent config is allowed to use."""
    values = {
        "repo": repo.as_posix(),
        "output": output.as_posix(),
        "task": task.as_posix(),
        "prompt": task.as_posix(),
    }
    expanded: list[str] = []
    for item in argv:
        try:
            expanded.append(item.format(**values))
        except KeyError as exc:
            raise CampaignError(
                "agent argv uses an unknown placeholder",
                details={"argument": item, "unknown": str(exc), "allowed": sorted(values)},
            ) from exc
    return expanded


def os_path_in(argv: list[str], needle: str) -> bool:
    return any(needle in item for item in argv)


def _balanced_objects(text: str) -> list[str]:
    """Return top-level balanced ``{...}`` blocks, ignoring braces in strings."""
    blocks: list[str] = []
    depth = 0
    start: int | None = None
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                blocks.append(text[start : index + 1])
                start = None
    return blocks


def _looks_like_answer(text: str) -> bool:
    stripped = text.strip()
    if not stripped.startswith("{"):
        return False
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return False
    return isinstance(payload, dict) and "findings" in payload


def extract_final_answer(stdout_text: str, *, strategy: str = "jsonl_events") -> str | None:
    """Locate the agent's final answer inside captured stdout.

    Nothing is repaired or completed here: the returned text is either an exact
    block the agent printed, or ``None``.  A ``None`` answer becomes a recorded
    format failure, never an empty "no findings" result.
    """
    text = stdout_text or ""
    if not text.strip():
        return None
    if strategy == "tail":
        return text.strip()
    if strategy == "claude_jsonl":
        answer = None
        for line in text.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if event.get("schema") == "claude-code-capture-v1":
                if event.get("kind") != "stream":
                    continue
                event = event.get("payload", {})
            if not isinstance(event, dict):
                continue
            if (
                event.get("type") == "result"
                and event.get("subtype") == "success"
                and not event.get("is_error")
                and isinstance(event.get("result"), str)
            ):
                answer = event["result"]
        return answer
    if strategy == "jsonl_events":
        parts: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            part = event.get("part")
            candidate = None
            if isinstance(part, dict):
                candidate = part.get("text")
            if candidate is None:
                candidate = event.get("text")
            if isinstance(candidate, str) and candidate.strip():
                parts.append(candidate.strip())
        for candidate in reversed(parts):
            if _looks_like_answer(candidate):
                return candidate
        for candidate in reversed(parts):
            for block in reversed(_balanced_objects(candidate)):
                if _looks_like_answer(block):
                    return block
        return parts[-1] if parts else None
    # json_last_object
    stripped = text.strip()
    if _looks_like_answer(stripped):
        return stripped
    for block in reversed(_balanced_objects(text)):
        if _looks_like_answer(block):
            return block
    return None


@dataclass(frozen=True)
class CommandExecutor:
    """The command writes the answer file itself (``{output}`` is writable)."""

    argv: tuple[str, ...]
    answer_filename: str = ANSWER_FILENAMES[0]
    mode: str = "argv"

    def run(
        self,
        *,
        repo: Path,
        output: Path,
        task_file: Path,
        env: dict[str, str],
        run_dir: Path,
        timeout_seconds: int,
    ) -> ExecutionResult:
        argv = expand_argv(self.argv, repo=repo, output=output, task=task_file)
        stdout_path = run_dir / "stdout.log"
        stderr_path = run_dir / "stderr.log"
        code, timed_out, error, duration = run_agent_process(
            argv,
            cwd=repo,
            env=env,
            timeout_seconds=timeout_seconds,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
        answer = output / self.answer_filename
        status = _status(code, timed_out, error)
        if status == "success" and not answer.is_file():
            status = "missing_answer"
        return ExecutionResult(
            status=status,
            exit_code=code,
            duration_seconds=duration,
            stdout_path=stdout_path.as_posix(),
            stderr_path=stderr_path.as_posix(),
            answer_path=answer.as_posix() if answer.is_file() else None,
            error=error or (None if answer.is_file() else "the command wrote no answer file"),
        )


@dataclass(frozen=True)
class StdoutExecutor:
    """The command prints; stdout is captured and the answer is extracted from it."""

    argv: tuple[str, ...]
    answer_extractor: str = "jsonl_events"
    mode: str = "stdout"

    def run(
        self,
        *,
        repo: Path,
        output: Path,
        task_file: Path,
        env: dict[str, str],
        run_dir: Path,
        timeout_seconds: int,
    ) -> ExecutionResult:
        argv = expand_argv(self.argv, repo=repo, output=output, task=task_file)
        stdout_path = run_dir / "stdout.log"
        stderr_path = run_dir / "stderr.log"
        code, timed_out, error, duration = run_agent_process(
            argv,
            cwd=repo,
            env=env,
            timeout_seconds=timeout_seconds,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
        status = _status(code, timed_out, error)
        answer_path = output / ANSWER_FILENAMES[0]
        if status == "success":
            captured = stdout_path.read_text(encoding="utf-8", errors="replace")
            extracted = extract_final_answer(captured, strategy=self.answer_extractor)
            if extracted is None:
                return ExecutionResult(
                    status="missing_answer",
                    exit_code=code,
                    duration_seconds=duration,
                    stdout_path=stdout_path.as_posix(),
                    stderr_path=stderr_path.as_posix(),
                    error="no final answer could be located in stdout",
                )
            output.mkdir(parents=True, exist_ok=True)
            answer_path.write_text(extracted + "\n", encoding="utf-8")
        return ExecutionResult(
            status=status,
            exit_code=code,
            duration_seconds=duration,
            stdout_path=stdout_path.as_posix(),
            stderr_path=stderr_path.as_posix(),
            answer_path=answer_path.as_posix() if answer_path.is_file() else None,
            error=error,
        )


@dataclass(frozen=True)
class NullExecutor:
    """No agent is executed: the workspace is prepared and attested only."""

    mode: str = "none"

    def run(self, **_: object) -> ExecutionResult:
        return ExecutionResult(status="not_run", error="no executor configured")


if hasattr(socketserver, "UnixStreamServer"):

    class _ProbeUnixServer(  # type: ignore[misc]
        socketserver.ThreadingMixIn, socketserver.UnixStreamServer
    ):
        daemon_threads = True

else:

    class _ProbeUnixServer:  # pragma: no cover - instantiated only on Linux
        def __init__(self, *_: object, **__: object) -> None:
            raise OSError("Unix-domain namespace probe requires Linux")


class _ProbeUnixHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.recv(1)


@dataclass(frozen=True)
class LinuxNamespaceStdoutExecutor:
    """Run OpenCode in a rootless loopback-only Linux network namespace."""

    argv: tuple[str, ...]
    egress_config: object
    answer_extractor: str = "jsonl_events"
    mode: str = "stdout"

    @staticmethod
    def _namespace_command(
        *,
        socket_path: Path,
        evidence_path: Path,
        relay_port: int,
        command: list[str] | None = None,
        probe_only: bool = False,
    ) -> list[str]:
        try:
            parent_netns = os.readlink("/proc/self/ns/net")
        except OSError as exc:
            raise CampaignError(
                "linux_namespace runtime requires Linux /proc network namespaces",
                details={"error": str(exc)},
            ) from exc
        argv = [
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
            "--mount-proc",
            sys.executable,
            "-m",
            "vulnmirage.isolation.namespace_child",
            "--unix-socket",
            str(socket_path),
            "--port",
            str(relay_port),
            "--evidence",
            str(evidence_path),
            "--parent-netns",
            parent_netns,
        ]
        if probe_only:
            argv.append("--probe-only")
        if command:
            argv.extend(["--", *command])
        return argv

    def probe_egress(self, config, *, run_dir: Path) -> EgressProbeResult:
        """Prove the namespace shape before the expensive model invocation."""
        run_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = run_dir / "network_boundary_probe.json"
        with tempfile.TemporaryDirectory(prefix="vulnmirage-gateway-probe-") as temp:
            socket_path = Path(temp) / "gateway.sock"
            server = _ProbeUnixServer(str(socket_path), _ProbeUnixHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                completed = subprocess.run(
                    self._namespace_command(
                        socket_path=socket_path,
                        evidence_path=evidence_path,
                        relay_port=18765,
                        probe_only=True,
                    ),
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                completed = None
                error = str(exc)
            else:
                error = (completed.stderr or completed.stdout)[-1000:]
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
        evidence: dict[str, object] = {}
        if evidence_path.is_file():
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        verified = bool(
            completed is not None
            and completed.returncode == 0
            and evidence.get("enforcement_verified") is True
        )
        upstream = probe_egress(config, blocked_hosts=[])
        gateway_reachable = bool(verified and upstream.gateway_reachable)
        blocked_targets = [
            ProbeTarget(
                host=host,
                resolved=False,
                connected=False,
                error="no external interface or default route in agent namespace",
            )
            for host in config.probe_blocked_hosts
        ]
        notes = [
            "rootless user+network namespace contains loopback only",
            "the local TCP relay reaches an allowlisted Unix-socket inference gateway",
            f"probe evidence: {evidence_path.name}",
        ]
        if not verified:
            notes.append(f"namespace preflight failed: {error}")
        if not upstream.gateway_reachable:
            notes.append("no configured upstream inference host answered from the gateway side")
        return EgressProbeResult(
            mode=config.mode,
            enforcement="linux_user_network_namespace_unix_gateway",
            probe_origin="agent_network_boundary",
            enforcement_verified=verified,
            probe_timeout_seconds=float(config.probe_timeout_seconds),
            blocked_targets=blocked_targets,
            gateway_targets=upstream.gateway_targets,
            reachable_answer_hosts=[],
            gateway_reachable=gateway_reachable,
            verdict="enforced_blocked" if verified else "unknown",
            notes=notes,
        )

    def run(
        self,
        *,
        repo: Path,
        output: Path,
        task_file: Path,
        env: dict[str, str],
        run_dir: Path,
        timeout_seconds: int,
    ) -> ExecutionResult:
        argv = expand_argv(self.argv, repo=repo, output=output, task=task_file)
        source_config = Path(env.get("OPENCODE_CONFIG", ""))
        if not source_config.is_file():
            return ExecutionResult(
                status="error", error="linux_namespace runtime requires OPENCODE_CONFIG"
            )
        runtime_config = run_dir / "opencode.runtime.json"
        gateway_base = "http://127.0.0.1:18765"
        routes = rewrite_opencode_for_gateway(
            source_config,
            runtime_config,
            gateway_base_url=gateway_base,
            allowed_upstream_hosts=set(self.egress_config.inference_gateway_hosts),
        )
        stdout_path = run_dir / "stdout.log"
        stderr_path = run_dir / "stderr.log"
        evidence_path = run_dir / "network_boundary.json"
        child_env = dict(env)
        child_env["OPENCODE_CONFIG"] = str(runtime_config)
        with tempfile.TemporaryDirectory(prefix="vulnmirage-gateway-") as temp:
            socket_path = Path(temp) / "gateway.sock"
            with InferenceGateway(socket_path, routes):
                code, timed_out, error, duration = run_agent_process(
                    self._namespace_command(
                        socket_path=socket_path,
                        evidence_path=evidence_path,
                        relay_port=18765,
                        command=argv,
                    ),
                    cwd=repo,
                    env=child_env,
                    timeout_seconds=timeout_seconds,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                )
        evidence = (
            json.loads(evidence_path.read_text(encoding="utf-8"))
            if evidence_path.is_file()
            else {}
        )
        if evidence.get("enforcement_verified") is not True:
            error = error or "agent network-boundary evidence is missing or failed"
        status = _status(code, timed_out, error)
        answer_path = output / ANSWER_FILENAMES[0]
        if status == "success":
            captured = stdout_path.read_text(encoding="utf-8", errors="replace")
            extracted = extract_final_answer(captured, strategy=self.answer_extractor)
            if extracted is None:
                status = "missing_answer"
                error = "no final answer could be located in stdout"
            else:
                output.mkdir(parents=True, exist_ok=True)
                answer_path.write_text(extracted + "\n", encoding="utf-8")
        return ExecutionResult(
            status=status,
            exit_code=code,
            duration_seconds=duration,
            stdout_path=stdout_path.as_posix(),
            stderr_path=stderr_path.as_posix(),
            answer_path=answer_path.as_posix() if answer_path.is_file() else None,
            error=error,
        )


def _status(code: int | None, timed_out: bool, error: str) -> str:
    if error:
        return "error"
    if timed_out:
        return "timeout"
    if code != 0:
        return "failed"
    return "success"


def build_executor(agent_config, *, egress_config=None) -> AuditExecutor:
    """Pick the executor shape the agent config asks for."""
    argv = tuple(agent_config.argv)
    if not argv:
        raise CampaignError("agent config has an empty argv", details={})
    if agent_config.runtime == "linux_namespace":
        if os.name == "nt":
            raise CampaignError(
                "linux_namespace agent runtime must be launched inside WSL/Linux",
                details={},
            )
        if agent_config.mode != "stdout":
            raise CampaignError(
                "linux_namespace currently supports stdout agents only", details={}
            )
        if egress_config is None or egress_config.mode != "linux_namespace":
            raise CampaignError(
                "linux_namespace agent requires isolation.egress.mode=linux_namespace",
                details={},
            )
        return LinuxNamespaceStdoutExecutor(
            argv=argv,
            answer_extractor=agent_config.answer_extractor,
            egress_config=egress_config,
        )
    if agent_config.mode == "argv":
        return CommandExecutor(argv=argv)
    return StdoutExecutor(argv=argv, answer_extractor=agent_config.answer_extractor)


def detect_framework_version(
    argv: list[str] | tuple[str, ...], *, env: dict[str, str] | None = None
) -> str | None:
    """Return a framework's self-reported version without invoking an agent.

    An explicitly configured command is treated as a reproducibility contract:
    failure is fatal rather than silently archiving an unattributed trace format.
    """
    if not argv:
        return None
    try:
        completed = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CampaignError(
            "could not execute framework version command",
            details={"argv": list(argv), "error": str(exc)},
        ) from exc
    output = completed.stdout.strip() or completed.stderr.strip()
    if completed.returncode != 0 or not output:
        raise CampaignError(
            "framework version command did not return a version",
            details={
                "argv": list(argv),
                "exit_code": completed.returncode,
                "output": output[-1000:],
            },
        )
    return output.splitlines()[0].strip()


__all__ = [
    "ANSWER_FILENAMES",
    "AuditExecutor",
    "CommandExecutor",
    "ExecutionResult",
    "LinuxNamespaceStdoutExecutor",
    "NullExecutor",
    "StdoutExecutor",
    "build_executor",
    "detect_framework_version",
    "expand_argv",
    "extract_final_answer",
]
