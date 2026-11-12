"""Capture, normalize, compare and locally verify Claude Code traces."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .collector import Collector, capture_run, init_capture, read_json


def main() -> int:
    parser = argparse.ArgumentParser(description="Claude Code trace evidence chain")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    run = commands.add_parser("run")
    for cmd in (init, run):
        cmd.add_argument("--repo", type=Path, required=True)
        cmd.add_argument("--out", type=Path, required=True)
        cmd.add_argument("--catalog", type=Path)
        cmd.add_argument("--checkpoint-config", type=Path)
    run.add_argument("--prompt-file", type=Path, required=True)
    run.add_argument("--model")
    run.add_argument("--claude", default="claude")
    run.add_argument("--resume")
    run.add_argument("--timeout", type=int, default=900)
    run.add_argument("--max-turns", type=int, default=30)
    run.add_argument("--tools", default="Bash,Read,Grep,Glob")
    run.add_argument("--system-prompt-file", type=Path)
    run.add_argument(
        "--emit-jsonl",
        action="store_true",
        help="Emit raw evidence envelopes for the campaign stdout adapter",
    )
    hook = commands.add_parser("hook")
    hook.add_argument("--config", type=Path, required=True)
    norm = commands.add_parser("normalize")
    norm.add_argument("--source", type=Path, required=True)
    norm.add_argument("--repo", type=Path, required=True)
    norm.add_argument("--out", type=Path, required=True)
    norm.add_argument("--version")
    norm.add_argument("--catalog", type=Path)
    compare = commands.add_parser("compare")
    compare.add_argument("--control", type=Path, required=True)
    compare.add_argument("--attack", type=Path, required=True)
    compare.add_argument("--out", type=Path)
    verify = commands.add_parser("verify-local")
    verify.add_argument("--out", type=Path, required=True)
    verify.add_argument("--claude", default="claude")
    verify.add_argument("--tool-failure", action="store_true")
    args = parser.parse_args()
    try:
        if args.command in {"init", "run"}:
            catalog = read_json(args.catalog) if args.catalog else None
            if args.command == "init":
                result = {
                    "config": str(
                        init_capture(
                            args.repo,
                            args.out,
                            catalog=catalog,
                            checkpoint_config=args.checkpoint_config,
                        )
                    )
                }
            else:
                result = capture_run(
                    repo=args.repo,
                    output=args.out,
                    prompt=args.prompt_file.read_text(),
                    model=args.model,
                    claude=args.claude,
                    catalog=catalog,
                    checkpoint_config=args.checkpoint_config,
                    resume=args.resume,
                    timeout=args.timeout,
                    max_turns=args.max_turns,
                    tools=args.tools,
                    system_prompt=args.system_prompt_file.read_text()
                    if args.system_prompt_file
                    else None,
                )
                from ..trace.normalize import normalize_trace

                trace = normalize_trace(
                    result["source"],
                    args.out,
                    adapter="claude_code_jsonl",
                    repo_root=args.repo,
                    framework_version=result["framework_version"],
                    secret_values=_secret_values(),
                )
                if args.emit_jsonl:
                    sys.stdout.write(Path(result["source"]).read_text())
                    return 0 if result["status"] == "success" else 1
                result.update(
                    trace_status=trace["status"], trace_completeness=trace["completeness"]
                )
        elif args.command == "hook":
            result = Collector(args.config).hook(json.load(sys.stdin))
        elif args.command == "normalize":
            from ..trace.normalize import normalize_trace

            trace = normalize_trace(
                args.source,
                args.out,
                adapter="claude_code_jsonl",
                repo_root=args.repo,
                framework_version=args.version,
                secret_values=_secret_values(),
                payload_catalog=read_json(args.catalog) if args.catalog else None,
            )
            result = {k: v for k, v in trace.items() if k != "manifest"}
        elif args.command == "compare":
            from ..trace.claude_metrics import compare_metrics

            result = compare_metrics(args.control, args.attack, args.out)
        else:
            from .verify import verify_local

            result = verify_local(args.out, claude=args.claude, tool_failure=args.tool_failure)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:
        if args.command == "hook":
            print('{"continue":false}')
            print(f"Trace hook failed: {type(exc).__name__}", file=sys.stderr)
            return 0
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _secret_values():
    return tuple(
        os.environ[name]
        for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")
        if os.environ.get(name)
    )


if __name__ == "__main__":
    raise SystemExit(main())
