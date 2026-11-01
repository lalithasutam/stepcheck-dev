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

    ci = sub.add_parser("ci", help="headless CI/PR gatekeeper: every module must parse, match its attestation, "
                                   "and pass Gates A/B/C with all invariants executed (exit 1 on the first violation)")
    ci.add_argument("path", nargs="?", default=".", help="project root (default: current directory)")
    ci.set_defaults(fn=cmd_ci)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())


# ------------------------------------------------------------- stepcheck ci


def _ci_parse(root: Path) -> list[tuple[str, str]]:
    """(file, problem) for every tracked module that does not parse."""
    import ast

    problems: list[tuple[str, str]] = []
    for p in sorted(root.rglob("*.py")):
        if ".stepcheck" in p.parts or p.name.startswith("."):
            continue
        rel = str(p.relative_to(root))
        try:
            ast.parse(p.read_bytes().decode("utf-8"), filename=rel)
        except UnicodeDecodeError:
            continue  # the kernel leaves non-UTF-8 files untracked
        except SyntaxError as exc:
            problems.append((rel, f"Gate A: invalid AST syntax: {exc.msg} (line {exc.lineno})"))
    return problems


def _ci_frames(root: Path) -> list[tuple[str, str]]:
    """(node, problem) from the existing OKF frames: a node left in
    DIRTY_OMISSION_RISK, or an attested file whose on-disk bytes no longer hash
    to its latest DSSE sha256. No frames yet means nothing to check."""
    import hashlib

    import yaml

    problems: list[tuple[str, str]] = []
    okf = root / ".stepcheck" / "okf"
    if not okf.is_dir():
        return problems
    for frame in sorted(okf.glob("*.md")):
        if frame.name == "index.md":
            continue
        try:
            meta = yaml.safe_load(frame.read_text(encoding="utf-8").split("---\n")[1]) or {}
        except (yaml.YAMLError, IndexError):
            problems.append((frame.stem, f"frame {frame.name} has unreadable frontmatter"))
            continue
        nid = str(meta.get("node_id", frame.stem))
        rel = str(meta.get("path", ""))
        if meta.get("status") == "DIRTY_OMISSION_RISK":
            problems.append((nid, "holds DIRTY_OMISSION_RISK: a dependency's exports changed; "
                                  "check it out and re-verify before merging"))
        verified = meta.get("verified") or []
        if not verified:
            continue
        payload = (verified[-1] or {}).get("payload", {})
        attested, turn = payload.get("sha256"), payload.get("turn")
        target = root / rel
        if not target.is_file():
            problems.append((nid, f"attested file {rel} is missing from the tree"))
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != attested:
            problems.append((nid, f"{rel} on disk (sha256 {actual[:12]}…) differs from its latest "
                                  f"attestation (turn {turn}, sha256 {str(attested)[:12]}…)"))
    return problems


def cmd_ci(args: argparse.Namespace) -> int:
    """Headless gatekeeper. Phases: parse → attestations/dirty nodes → re-commit
    every module through Gates A/B/C (executing all invariants). Exit 0 with a
    table, or 1 naming each failing module and its violation."""
    import tempfile

    from kernel import StateKernel

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"stepcheck ci: {root} is not a directory", file=sys.stderr)
        return 2
    print(f"stepcheck ci — {root}")

    def fail(problems: list[tuple[str, str]], phase: str) -> int:
        for where, what in problems:
            print(f"  FAIL  {where}: {what}")
        where, what = problems[0]
        print(f"stepcheck ci: FAIL — {len(problems)} problem(s) in {phase}; first: {where} — {what}")
        return 1

    problems = _ci_parse(root)
    if problems:
        return fail(problems, "parse")
    print("  parse         every module parses")
    problems = _ci_frames(root)
    if problems:
        return fail(problems, "attestations")
    has_frames = (root / ".stepcheck" / "okf").is_dir()
    print("  attestations  " + ("no dirty nodes; on-disk bytes match every attestation" if has_frames else "no frames yet"))

    previous_home = os.environ.get("STEPCHECK_HOME")
    with tempfile.TemporaryDirectory(prefix="stepcheck-ci-") as scratch:
        if previous_home is None:
            os.environ["STEPCHECK_HOME"] = scratch  # CI machines keep no per-user registry
        try:
            kernel = StateKernel()
            sid = kernel.init_session(root)
            rows: list[tuple[str, str, int, str]] = []
            failures: list[tuple[str, str]] = []
            executed = 0
            for node in kernel.graph(sid)["nodes"]:
                nid, n_inv = node["node_id"], len(node["invariants"])
                verdict = kernel.commit(sid, nid, source=node["source"])
                if verdict.accepted:
                    executed += n_inv
                    rows.append((nid, "PASS", n_inv, verdict.attestation["payload"]["sha256"][:12]))
                else:
                    failures.append((f"{node['path']} ({nid})", f"Gate {verdict.gate}: {verdict.error}"))
                    rows.append((nid, f"FAIL {verdict.gate}", n_inv, "-"))
        finally:
            if previous_home is None:
                os.environ.pop("STEPCHECK_HOME", None)

    width = max([len("node")] + [len(r[0]) for r in rows])
    print(f"  {'node'.ljust(width)}  status  inv  sha256")
    for nid, status, n_inv, sha in rows:
        print(f"  {nid.ljust(width)}  {status:<7} {n_inv:>3}  {sha}")
    if failures:
        return fail(failures, "gates")
    print(f"stepcheck ci: PASS — {len(rows)} modules verified through Gates A·B·C, "
          f"{executed} invariants executed")
    return 0
