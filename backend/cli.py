"""`stepcheck` console entrypoint.

  stepcheck up          one port: Studio UI (/studio) + Door 1 proxy + REST + MCP (/mcp) + WS
  stepcheck benchmark   run the 50-turn coding-rot benchmark, print the table
  stepcheck review      regenerate architecture-review.html from benchmarks/results.json
  stepcheck preview     regenerate the self-contained stepcheck-studio-preview.html
  stepcheck audit [p]   read Claude Code session logs (default ~/.claude/projects/) and
                        receipt the cache-cliff waste + dropped-symbol regressions
"""
from __future__ import annotations

import argparse
import os
import runpy
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
ROOT = BACKEND.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def _run_script(name: str) -> int:
    script = ROOT / "benchmarks" / name
    if not script.exists():
        print(f"stepcheck: {script} not found (installed without the repo checkout?)", file=sys.stderr)
        return 2
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def cmd_up(args: argparse.Namespace) -> int:
    import uvicorn

    import server

    studio = "mounted at /studio" if server.STUDIO_DIST.exists() else (
        f"not built — run `npm run build` in {ROOT / 'frontend'} to serve it here"
    )
    print(f"StepCheck gateway  http://{args.host}:{args.port}")
    print(f"  Studio UI        {studio}")
    print(f"  Door 1 proxy     POST /v1/chat/completions · POST /v1/messages")
    print(f"  Door 2           /v1/step/*  ·  MCP (streamable-http) /mcp  ·  WS /v1/ws/{{session_id}}")
    uvicorn.run(server.app, host=args.host, port=args.port, log_level=args.log_level)
    return 0


def cmd_benchmark(_: argparse.Namespace) -> int:
    return _run_script("coding_rot_benchmark.py")


def cmd_review(_: argparse.Namespace) -> int:
    return _run_script("generate_review.py")


def cmd_preview(_: argparse.Namespace) -> int:
    return _run_script("generate_preview.py")


SAMPLE_SESSION = ROOT / "benchmarks" / "fixtures" / "sample_session.jsonl"


def cmd_audit(args: argparse.Namespace) -> int:
    import audit

    target = Path(args.log_path).expanduser() if args.log_path else Path.home() / ".claude" / "projects"
    shown = audit.display_path(target)
    paths = audit.find_logs(target)
    if paths:
        note = f"{len(paths)} log file(s) under {shown}"
    else:
        if not SAMPLE_SESSION.exists():
            print(f"stepcheck audit: no .jsonl logs under {shown} and no sample fixture", file=sys.stderr)
            return 2
        paths, note = [SAMPLE_SESSION], f"no logs under {shown}; showing the bundled sample session"
    if args.limit:
        paths = paths[-args.limit:]
    report = audit.run(paths)
    print(audit.terminal_summary(report, note))
    out = Path(args.out)
    out.write_text(audit.html_receipt(report, note), encoding="utf-8")
    print(f"\nreceipt → {audit.display_path(out)}")
    if args.json:
        Path(args.json).write_text(__import__("json").dumps(report, indent=2), encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stepcheck", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    up = sub.add_parser("up", help="start the unified gateway + Studio + MCP server on one port")
    up.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    up.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8420")))
    up.add_argument("--log-level", default="info")
    up.set_defaults(fn=cmd_up)

    sub.add_parser("benchmark", help="run the 50-turn coding-rot benchmark").set_defaults(fn=cmd_benchmark)
    sub.add_parser("review", help="generate architecture-review.html").set_defaults(fn=cmd_review)
    sub.add_parser("preview", help="generate stepcheck-studio-preview.html").set_defaults(fn=cmd_preview)

    au = sub.add_parser("audit", help="audit Claude Code session logs for cache-cliff waste and dropped-symbol regressions")
    au.add_argument("log_path", nargs="?", help="a .jsonl transcript or a directory of them (default: ~/.claude/projects/)")
    au.add_argument("--out", default="stepcheck-audit.html", help="receipt path (default: ./stepcheck-audit.html)")
    au.add_argument("--json", default=None, help="also write the raw report as JSON here")
    au.add_argument("--limit", type=int, default=0, help="only the N most recent log files")
    au.set_defaults(fn=cmd_audit)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
