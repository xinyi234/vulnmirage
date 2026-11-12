"""Minimal isolated CLI: python -m vulnmirage.claude_checkpoint --help."""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import suppress
from pathlib import Path

from .core import Controller, init_run, read_json


def main() -> int:
    parser = argparse.ArgumentParser(description="Experimental Claude Code exposure checkpoints")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create an owned workspace and native hook settings")
    init.add_argument("--repo", type=Path, required=True)
    init.add_argument("--out", type=Path, required=True)
    init.add_argument("--catalog", type=Path, required=True)
    verify = commands.add_parser("verify-local", help="Real CLI + local model stub, no paid calls")
    verify.add_argument("--out", type=Path, required=True)
    verify.add_argument("--claude", default="claude")
    verify.add_argument("--tool-failure", action="store_true")
    for name in ("hook", "status", "fork", "activate", "preflight"):
        cmd = commands.add_parser(name)
        cmd.add_argument("--config", type=Path, required=True)
        if name == "fork":
            cmd.add_argument("--session", required=True)
            cmd.add_argument("--variants", type=Path, required=True)
        elif name == "activate":
            cmd.add_argument("--branch", required=True)
    args = parser.parse_args()
    try:
        if args.command == "init":
            result = {"config": str(init_run(args.repo, args.out, read_json(args.catalog)))}
        elif args.command == "verify-local":
            from .verify import verify_local

            result = verify_local(args.out, args.claude, tool_failure=args.tool_failure)
        else:
            controller = Controller(args.config)
            if args.command == "hook":
                data = json.load(sys.stdin)
                result = controller.handle(data)
            elif args.command == "status":
                result = read_json(controller.root / "state.json")
            elif args.command == "preflight":
                matches = controller.instruction_preflight()
                result = {"potential_instruction_hits": matches, "eligible": not matches}
                print(json.dumps(result, ensure_ascii=False))
                return int(bool(matches))
            elif args.command == "fork":
                result = controller.fork(args.session, read_json(args.variants))
            else:
                result = controller.activate(args.branch)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:
        # Fail closed at blocking hooks. Never echo raw hook data into the conversation.
        if args.command == "hook":
            if "controller" in locals() and "data" in locals() and isinstance(data, dict):
                with suppress(Exception):
                    controller.record_hook_failure(data, type(exc).__name__)
            print('{"continue":false}')
            print(f"Checkpoint hook failed: {type(exc).__name__}", file=sys.stderr)
            # Exit 0 selects structured control; the universal stop handles errors too.
            return 0
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
