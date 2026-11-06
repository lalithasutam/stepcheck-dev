"""`stepcheck` console entrypoint.

  stepcheck up          one port: Studio UI (/studio) + Door 1 proxy + REST + MCP (/mcp) + WS
  stepcheck benchmark   run the 50-turn coding-rot benchmark, print the table
  stepcheck review      regenerate architecture-review.html from benchmarks/results.json
  stepcheck preview     regenerate the self-contained stepcheck-studio-preview.html
  stepcheck audit [p]   read Claude Code session logs (default ~/.claude/projects/) and
                        receipt the cache-cliff waste + dropped-symbol regressions
  stepcheck ci [path]   headless gatekeeper: parse, attestations, Gates A/B/C for every
                        module; exit 1 names the failing module and violation
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


def _utf8_stdio() -> None:
    """Emit UTF-8 on redirected stdout/stderr. A Windows CI runner hands the
    process a cp1252 pipe, where `→` or `✓` in a table is a UnicodeEncodeError;
    streams already on UTF-8 (consoles, pytest capture) are left alone. Defined
    ahead of the `__main__` block so `python -m cli` can call it."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        if reconfigure is None or encoding == "utf8":
            continue
        try:
            reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            pass


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
    """`stepcheck audit [path] --out … [--json …] [--card --card-out …]`: receipt the
    cache-cliff waste and Read-tool bloat in Claude Code transcripts; `--card`
    adds a zero-code-leak SVG + Markdown badge built from the totals only."""
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
    if getattr(args, "card", False):
        card = Path(args.card_out)
        card.write_text(_audit_card_svg(report["total"]), encoding="utf-8", newline="\n")
        print(f"card → {audit.display_path(card)}\n")
        print(_audit_card_md(report["total"]), end="")
    if args.json:
        Path(args.json).write_text(__import__("json").dumps(report, indent=2), encoding="utf-8")
    return 0


# ------------------------------------------------------------- stepcheck ci
# (defined ahead of main() and the __main__ block so `python -m cli` works too)


def _ci_parse(root: Path) -> list[tuple[str, str]]:
    """(file, problem) for every tracked module that does not parse. Decodes the
    way the kernel does (UTF-8, BOM stripped), so a file the kernel tracks never
    fails here. Python is parsed with `ast`; TypeScript / JavaScript modules get
    the kernel's balanced-delimiter check."""
    import ast

    from kernel import _okf, _ts

    problems: list[tuple[str, str]] = []
    for p in _okf.tracked_files(root):
        rel = str(p.relative_to(root))
        try:
            source = _okf.decode_source(p.read_bytes())
        except UnicodeDecodeError:
            continue  # the kernel leaves non-UTF-8 files untracked
        _mod = _okf.lang_module(rel)
        if _mod is not None:
            problem = _mod.syntax_problem(source)
            if problem:
                problems.append((rel, f"Gate A: invalid {_okf.language(rel)} syntax: {problem}"))
            continue
        try:
            ast.parse(source, filename=rel)
        except SyntaxError as exc:
            problems.append((rel, f"Gate A: invalid AST syntax: {exc.msg} (line {exc.lineno})"))
    return problems


def _ci_frames(root: Path, live: dict[str, str]) -> tuple[list[tuple[str, str]], int]:
    """(problems, checked) from the existing OKF frames of the nodes in `live`
    (node_id -> path, the set the current tree actually has): a node left in
    DIRTY_OMISSION_RISK, or an attested file whose on-disk bytes no longer hash
    to its latest DSSE sha256. Frames of nodes that no longer exist under that
    name (left by an older session) are not evidence and are skipped."""
    import hashlib

    import yaml

    problems: list[tuple[str, str]] = []
    checked = 0
    okf = root / ".stepcheck" / "okf"
    if not okf.is_dir():
        return problems, checked
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
        if live.get(nid, None) != rel:
            continue  # stale: no node of that name maps to that file any more
        checked += 1
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
    return problems, checked


def cmd_ci(args: argparse.Namespace) -> int:
    """Headless gatekeeper. Phases: parse → index the tree on an ephemeral kernel
    (writes nothing, anywhere) → attestations/dirty nodes for the tracked set →
    re-commit every module through Gates A/B/C, executing all invariants. Exit 0
    with a table, or 1 naming each failing module and its violation."""
    from kernel import StateKernel

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"stepcheck ci: {root} is not a directory", file=sys.stderr)
        return 2
    print(f"stepcheck ci — {root}")
    if getattr(args, "report", False):
        import licensing

        denial = licensing.gate_env("ci_report")
        if denial is not None:
            print(f"stepcheck ci --report: {denial['message']}", file=sys.stderr)
            return 3

    def fail(problems: list[tuple[str, str]], phase: str) -> int:
        for where, what in problems:
            print(f"  FAIL  {where}: {what}")
        where, what = problems[0]
        print(f"stepcheck ci: FAIL — {len(problems)} problem(s) in {phase}; first: {where} — {what}")
        if getattr(args, "report", False):
            text = _ci_report(root)
            if text is not None:  # the PR still gets the checklist that names the dirty nodes
                print()
                print(text, end="")
                if args.report_out:
                    Path(args.report_out).write_text(text, encoding="utf-8", newline="\n")
        return 1

    problems = _ci_parse(root)
    if problems:
        return fail(problems, "parse")
    print("  parse         every module parses")

    kernel = StateKernel(ephemeral=True)  # verification only: writes nothing, anywhere
    sid = kernel.init_session(root)
    nodes = kernel.graph(sid)["nodes"]
    problems, checked = _ci_frames(root, {n["node_id"]: n["path"] for n in nodes})
    if problems:
        return fail(problems, "attestations")
    print("  attestations  " + (f"{checked} frame(s) checked: no dirty nodes, on-disk bytes match"
                               if checked else "no frames for the tracked modules yet"))

    rows: list[tuple[str, str, int, str]] = []
    failures: list[tuple[str, str]] = []
    executed = 0
    for node in nodes:
        nid, n_inv = node["node_id"], len(node["invariants"])
        verdict = kernel.commit(sid, nid, source=node["source"])
        if verdict.accepted:
            executed += n_inv
            rows.append((nid, "PASS", n_inv, verdict.attestation["payload"]["sha256"][:12]))
        else:
            failures.append((f"{node['path']} ({nid})", f"Gate {verdict.gate}: {verdict.error}"))
            rows.append((nid, f"FAIL {verdict.gate}", n_inv, "-"))

    width = max([len("node")] + [len(r[0]) for r in rows])
    print(f"  {'node'.ljust(width)}  status  inv  sha256")
    for nid, status, n_inv, sha in rows:
        print(f"  {nid.ljust(width)}  {status:<7} {n_inv:>3}  {sha}")
    if failures:
        return fail(failures, "gates")
    print(f"stepcheck ci: PASS — {len(rows)} modules verified through Gates A·B·C, "
          f"{executed} invariants executed")
    if getattr(args, "report", False):
        text = _ci_report(root)
        if text is None:
            print("stepcheck ci --report: no StepCheck session is registered for this root "
                  "(open one with init_project_session, then re-run)")
            return 1
        print()
        print(text, end="")
        if args.report_out:
            Path(args.report_out).write_text(text, encoding="utf-8", newline="\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    _utf8_stdio()
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
    au.add_argument("--card", action="store_true", help="also write a zero-code-leak SVG card and print a Markdown badge")
    au.add_argument("--card-out", default="stepcheck-audit-card.svg", help="card path (default: ./stepcheck-audit-card.svg)")
    au.set_defaults(fn=cmd_audit)

    ci = sub.add_parser("ci", help="headless CI/PR gatekeeper: every module must parse, match its attestation, "
                                   "and pass Gates A/B/C with all invariants executed (exit 1 on the first violation)")
    ci.add_argument("path", nargs="?", default=".", help="project root (default: current directory)")
    ci.add_argument("--report", action="store_true",
                    help="after a PASS, print the PR blast-radius & provenance checklist for the root's latest session")
    ci.add_argument("--report-out", default=None, help="also write the checklist Markdown here")
    ci.set_defaults(fn=cmd_ci)

    ll = sub.add_parser("llms", help="generate llms.txt + llms-full.txt (llmstxt.org) from the repository's own files")
    ll.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "docs"),
                    help="output directory (default: <repo>/docs)")
    ll.set_defaults(fn=cmd_llms)

    hk = sub.add_parser("hooks", help="install the Claude Code lifecycle hooks (.claude/hooks + settings.json) "
                                     "that relay to the gateway's warm POST /v1/step/hook")
    hk.add_argument("path", nargs="?", default=".", help="project root (default: current directory)")
    hk.add_argument("--url", default="http://127.0.0.1:8420/v1/step/hook", help="gateway hook endpoint")
    hk.set_defaults(fn=cmd_hooks)

    cn = sub.add_parser("connect", help="zero-touch setup: install Claude Code hooks, wire .mcp.json, and initialize the project session")
    cn.add_argument("path", nargs="?", default=".", help="project root (default: current directory)")
    cn.add_argument("--url", default="http://127.0.0.1:8420/v1/step/hook", help="gateway hook endpoint")
    cn.set_defaults(fn=cmd_connect)

    cp = sub.add_parser("compliance", help="export the dual-use compliance bundle: DUC.json (public card, hashes and "
                                         "counts only) + DUA-E.json (escrowed in-toto envelopes and control mappings)")
    cp.add_argument("path", nargs="?", default=".", help="project root (default: current directory)")
    cp.add_argument("--out", default="stepcheck-compliance", help="output directory (default: ./stepcheck-compliance)")
    cp.set_defaults(fn=cmd_compliance)

    args = parser.parse_args(argv)
    return args.fn(args)


def cmd_llms(args: argparse.Namespace) -> int:
    """Generate `llms.txt` + `llms-full.txt` (llmstxt.org) from the repository's
    own files: the only numbers in them come from benchmarks/results.json, so a
    regenerated file can never drift from the measured benchmark. Deterministic:
    the same tree yields byte-identical output."""
    import json

    root = Path(__file__).resolve().parents[1]
    final = json.loads((root / "benchmarks" / "results.json").read_text(encoding="utf-8"))
    caught = final.get("caught", [])
    injected = final.get("injected", caught)
    f = final["final"]
    repo = "https://github.com/lalithasutam/stepcheck-dev"
    pages = "https://lalithasutam.github.io/stepcheck-dev"
    summary = (
        "Deterministic context firewall for AI coding agents: AST-skeleton checkouts, three commit gates "
        "(A mechanical, B omission, C executed invariants) and DSSE attestations, served as a Streamable HTTP "
        f"MCP server and a BYOK proxy. 50-turn benchmark: {f['raw_bloated_tokens']:,} raw tokens -> "
        f"{f['compacted_okf_tokens']:,} sent ({f['savings_pct']}% saved), {len(caught)}/{len(injected)} "
        "injected faults caught."
    )
    sections = [
        ("Kernel seams", [
            (f"StateKernel (Seam 1)", f"{repo}/blob/main/backend/kernel/__init__.py",
             "init_session, checkout(focus=), commit(patch=) through Gates A/B/C, lock_node, provenance (in-toto Statement v1)"),
            (f"DualDoorGateway (Seam 2)", f"{repo}/blob/main/backend/server.py",
             "Door 1 BYOK firewall proxy for /v1/messages and /v1/chat/completions; Door 2 REST /v1/step/* plus MCP at /mcp"),
            (f"CLI", f"{repo}/blob/main/backend/cli.py",
             "stepcheck up / benchmark / review / preview / audit / ci / llms"),
            (f"Agent rules", f"{repo}/blob/main/CLAUDE.md",
             "the MCP workflow Claude Code and Cursor follow: session, focused checkout, patch commit, omission check"),
        ]),
        ("Benchmarks", [
            ("benchmarks/results.json", f"{repo}/blob/main/benchmarks/results.json",
             "the 50-turn coding-rot benchmark receipt every figure above is read from"),
            ("Interactive 50-turn replay", f"{pages}/",
             "turn scrubber, OKF graph, patch diff, attestation and cost curve; no install"),
            ("Audit receipt", f"{pages}/audit.html",
             "anonymized stepcheck audit of real Claude Code sessions: cache-cliff re-writes and Read-tool bloat"),
            ("CI", f"{repo}/actions/workflows/ci.yml",
             "pytest at the two public seams plus stepcheck ci on Ubuntu and Windows"),
        ]),
        ("Quickstart", [
            ("README", f"{repo}#run-turnkey",
             "pipx install git+https://github.com/lalithasutam/stepcheck-dev, then stepcheck audit and stepcheck up"),
            ("MCP for Claude Code", f"{repo}#claude-code-slash-commands-work-out-of-the-box-after-cloning",
             "claude mcp add --transport http stepcheck http://127.0.0.1:8420/mcp/ and the four shipped slash commands"),
            ("Release v0.1.0", f"{repo}/releases/tag/v0.1.0",
             "source and the self-contained studio preview"),
        ]),
        ("Optional", [
            ("GLOSSARY", f"{repo}/blob/main/GLOSSARY.md", "ubiquitous language: OKF frame, gates, seams, attestation"),
            ("LAUNCH", f"{repo}/blob/main/LAUNCH.md", "the launch write-up with the metrics table and its sources"),
            ("llms-full.txt", f"{pages}/llms-full.txt", "this index followed by the full README, launch write-up and glossary"),
        ]),
    ]
    out = ["# StepCheck Dev", "", f"> {summary}", "",
           "Apache-2.0. Python projects for now. This file is generated by `stepcheck llms` from the repository's own files.", ""]
    for title, items in sections:
        out.append(f"## {title}")
        out.append("")
        for name, url, desc in items:
            out.append(f"- [{name}]({url}): {desc}")
        out.append("")
    llms = "\n".join(out).rstrip("\n") + "\n"

    readme = (root / "README.md").read_text(encoding="utf-8")
    glossary = (root / "GLOSSARY.md").read_text(encoding="utf-8")
    launch = (root / "LAUNCH.md").read_text(encoding="utf-8")
    post = launch.split("**Post**", 1)[1].split("**First comment", 1)[0] if "**Post**" in launch else ""
    full = (llms + "\n---\n\n# README.md\n\n" + readme.strip() + "\n\n---\n\n# Launch write-up\n\n"
            + post.strip() + "\n\n---\n\n# GLOSSARY.md\n\n" + glossary.strip() + "\n")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in (("llms.txt", llms), ("llms-full.txt", full)):
        (out_dir / name).write_bytes(text.encode("utf-8"))
        print(f"wrote {out_dir / name} ({len(text.encode('utf-8')):,} bytes)")
    return 0


def _registry_latest_session(root: Path) -> str | None:
    """Newest registered StepCheck session whose project root is `root`."""
    import hooks

    root = root.resolve()
    hit = None
    for sid, r in hooks.registry().items():  # insertion order: the newest session wins
        if Path(r).resolve() == root:
            hit = sid
    return hit


def _ci_report(root: Path, session_id: str | None = None) -> str | None:
    """PR blast-radius & decision-provenance checklist for the root's latest
    session: touched modules, dependents re-verified or still dirty, Gate B
    conserved symbols, Gate C executed invariants, per-commit DSSE digests and
    the in-toto Statement v1 envelopes. A pure function of the session state
    (sorted, no timestamps): two runs over the same state are byte-identical."""
    import base64
    import json

    from kernel import StateKernel

    root = root.resolve()
    sid = session_id or _registry_latest_session(root)
    if not sid:
        return None
    kernel = StateKernel()
    try:
        graph = kernel.graph(sid)
    except KeyError:
        return None
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    touched = sorted(nid for nid, n in nodes.items() if n.get("attestation"))

    def short(digest: str | None) -> str:
        return (digest or "")[:16]

    lines = [
        "# StepCheck decision-provenance report",
        "",
        f"Project `{root.name}` · session `{sid}` · {len(touched)} module(s) touched, {len(nodes)} tracked.",
        "",
        "## Touched modules",
        "",
        "| Module | Path | Status | Commits | Latest DSSE sha256 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for nid in touched:
        n = nodes[nid]
        att = n["attestation"] or {}
        lines.append(f"| `{nid}` | `{n['path'].replace(chr(92), '/')}` | {n['status']} | {n.get('verified', 0)} | "
                     f"`{short((att.get('payload') or {}).get('sha256'))}…` |")
    lines += ["", "## Blast radius (dependents of touched modules)", ""]
    any_dep = False
    for nid in touched:
        for dep in sorted(d for d, n in nodes.items() if nid in n.get("deps", []) and d != nid):
            any_dep = True
            n = nodes[dep]
            if n["status"] == "DIRTY_OMISSION_RISK":
                state = "NOT re-verified — DIRTY_OMISSION_RISK (blocks finalize)"
            elif n.get("attestation"):
                state = f"re-verified — `{short(n['attestation']['payload']['sha256'])}…`"
            else:
                state = "unaffected (exports of its dependency unchanged)"
            lines.append(f"- `{dep}` depends on `{nid}`: {state}")
    if not any_dep:
        lines.append("- no tracked module depends on a touched module")
    lines += ["", "## Conserved symbols (Gate B fingerprints every commit had to keep)", ""]
    for nid in touched:
        syms = nodes[nid].get("preserved_symbols", [])
        lines.append(f"- `{nid}`: " + (", ".join(f"`{s}`" for s in syms) if syms else "none"))
    lines += ["", "## Executed invariants (Gate C)", ""]
    for nid in touched:
        n = nodes[nid]
        mined = set(n.get("invariants_auto_mined", []))
        invs = n.get("invariants", [])
        if not invs:
            lines.append(f"- `{nid}`: none")
        for inv in invs:
            lines.append(f"- `{nid}`: `{inv}`" + (" (auto-mined)" if inv in mined else " (hand-written)"))
    lines += ["", "## Attestations (DSSE envelopes)", "", "| Module | payloadType | sha256 | keyid |", "| --- | --- | --- | --- |"]
    for nid in touched:
        att = nodes[nid]["attestation"]
        sig = (att.get("signatures") or [{}])[0]
        lines.append(f"| `{nid}` | `{att.get('payloadType')}` | `{att['payload']['sha256']}` | `{sig.get('keyid')}` |")
    lines += ["", "## Provenance (in-toto Statement v1)", "", "| Module | payloadType | subject sha256 | signature |", "| --- | --- | --- | --- |"]
    for nid in touched:
        env = kernel.provenance(sid, nid)
        statement = json.loads(base64.b64decode(env["payload"]))
        subject = statement["subject"][0]["digest"]["sha256"]
        lines.append(f"| `{nid}` | `{env['payloadType']}` | `{subject}` | `{env['signatures'][0]['sig']}` |")
    dirty = sorted(nid for nid, n in nodes.items() if n["status"] == "DIRTY_OMISSION_RISK")
    lines += ["", "## Verdict", ""]
    lines.append(
        "- can_finalize: **false** — " + ", ".join(f"`{d}`" for d in dirty) + " still DIRTY_OMISSION_RISK"
        if dirty else "- can_finalize: **true** — no DIRTY_OMISSION_RISK nodes"
    )
    return "\n".join(lines) + "\n"


_HOOK_SCRIPT = '''#!/usr/bin/env python3
"""StepCheck lifecycle hook, installed by `stepcheck hooks`. Relays Claude Code's
hook payload (stdin JSON) to the warm gateway endpoint and prints its answer.

Gateway unreachable: Edit / Write / MultiEdit / NotebookEdit and Stop are decided
in-process by the same policy (`backend/hooks.py`: Gates A, B and C against the
project's session), so a dead socket never lets a broken write through. Read stays
fail-open offline (the skeleton swap saves tokens; it is not a safety gate), and
so does every event when no StepCheck install can be found (STEPCHECK_BACKEND,
an installed `backend` package, or $CLAUDE_PROJECT_DIR/backend) or the kernel
itself fails — one line on stderr says so.

A gate denial on an editing tool prints the structured PreToolUse deny and exits 2:
Claude Code blocks the call before any byte lands and hands stderr to the agent.

Offline is detected with a short connect probe (STEPCHECK_HOOK_CONNECT_TIMEOUT,
default 0.25 s). When the gateway URL is local and an install is found, the cold
call also starts `stepcheck up` detached on that port (at most once a minute;
pid in $STEPCHECK_HOME/gateway-<port>.json, output in gateway-<port>.log), so
later calls are answered warm. STEPCHECK_HOOK_AUTOSTART=0 turns that off."""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlsplit

URL = os.environ.get("STEPCHECK_HOOK_URL", "__STEPCHECK_HOOK_URL__")
EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
_DAEMON = ("import json, os, sys; backend, port, state = sys.argv[1:4]; sys.path.insert(0, backend); "
           "open(state, 'w').write(json.dumps({'pid': os.getpid(), 'port': int(port)})); import cli; "
           "sys.exit(cli.main(['up', '--host', '127.0.0.1', '--port', port, '--log-level', 'warning']))")


def _endpoint():
    parts = urlsplit(URL)
    return parts.hostname or "127.0.0.1", parts.port or (443 if parts.scheme == "https" else 80)


def _reachable() -> bool:
    try:
        timeout = float(os.environ.get("STEPCHECK_HOOK_CONNECT_TIMEOUT", "0.25"))
        with socket.create_connection(_endpoint(), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def _warm_gateway(backend) -> bool:
    """Start a detached local gateway on the hook URL's port; True when one was launched."""
    host, port = _endpoint()
    if backend is None or os.environ.get("STEPCHECK_HOOK_AUTOSTART", "1") == "0" or host not in ("127.0.0.1", "localhost"):
        return False
    home = os.environ.get("STEPCHECK_HOME") or os.path.join(os.path.expanduser("~"), ".stepcheck")
    try:
        os.makedirs(home, exist_ok=True)
        lock = os.path.join(home, f"gateway-{port}.lock")
        if os.path.exists(lock) and time.time() - os.path.getmtime(lock) < 60:
            return False  # another hook call launched one moments ago
        if os.path.exists(lock):
            os.remove(lock)
        os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        kwargs = {"stdin": subprocess.DEVNULL, "close_fds": True, "cwd": backend}
        if os.name == "nt":
            kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        with open(os.path.join(home, f"gateway-{port}.log"), "ab") as log:
            subprocess.Popen([sys.executable, "-c", _DAEMON, backend, str(port),
                              os.path.join(home, f"gateway-{port}.json")], stdout=log, stderr=log, **kwargs)
        return True
    except OSError:
        return False


def _backend_dir():
    candidates = [os.environ.get("STEPCHECK_BACKEND")]
    try:
        import importlib.util

        spec = importlib.util.find_spec("backend")
        candidates += list(spec.submodule_search_locations or []) if spec else []
    except (ImportError, ValueError):
        pass
    if os.environ.get("CLAUDE_PROJECT_DIR"):
        candidates.append(os.path.join(os.environ["CLAUDE_PROJECT_DIR"], "backend"))
    for c in candidates:
        if c and os.path.isfile(os.path.join(c, "hooks.py")) and os.path.isfile(os.path.join(c, "kernel", "_gates.py")):
            return c
    return None


def _in_process(event, backend):
    """The gateway's answer computed here, or None when it cannot be."""
    if backend is None:
        return None
    sys.path.insert(0, backend)
    import hooks
    from kernel import StateKernel

    return hooks.decide(event, StateKernel())


def _emit(event, out) -> int:
    if not out:
        return 0
    sys.stdout.write(json.dumps(out, ensure_ascii=False))
    hso = out.get("hookSpecificOutput") or {}
    if hso.get("permissionDecision") == "deny" and event.get("tool_name") in EDIT_TOOLS:
        sys.stderr.write(str(hso.get("permissionDecisionReason") or "StepCheck denied the edit") + "\\n")
        return 2
    return 0


def main() -> int:
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0
    if not isinstance(event, dict):
        return 0
    event.setdefault("cwd", os.getcwd())
    try:
        if not _reachable():
            raise ConnectionRefusedError("connect probe")
        req = urllib.request.Request(URL, data=json.dumps(event).encode("utf-8"),
                                     headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=float(os.environ.get("STEPCHECK_HOOK_TIMEOUT", "2"))) as r:
            out = json.loads(r.read() or b"{}")
    except Exception as exc:  # noqa: BLE001 — offline gateway, bad JSON, timeout
        offline = f"gateway offline ({exc.__class__.__name__})"
        backend = _backend_dir()
        hint = "warming it in the background" if _warm_gateway(backend) else "Run `stepcheck up`."
        if event.get("tool_name") == "Read":
            sys.stderr.write(f"stepcheck hook: {offline}; allowing the Read; {hint}\\n")
            return 0
        try:
            out = _in_process(event, backend)
        except Exception as inner:  # noqa: BLE001 — a kernel failure must not brick the agent
            sys.stderr.write(f"stepcheck hook: {offline}, in-process check failed ({inner!r}); allowing.\\n")
            return 0
        if out is None:
            sys.stderr.write(f"stepcheck hook: {offline}, no StepCheck install found; allowing. Run `stepcheck up`.\\n")
            return 0
    return _emit(event, out)


if __name__ == '__main__':
    sys.exit(main())
'''


def cmd_connect(args: argparse.Namespace) -> int:
    """stepcheck connect [path]: one-command zero-touch setup. Installs Claude Code
    hooks (.claude/hooks + .claude/settings.json), wires .mcp.json for streamable-http
    MCP, and initializes a persistent StepCheck session on the project root."""
    import json
    from kernel import StateKernel

    rc = cmd_hooks(args)
    root = Path(args.path).resolve()
    mcp_path = root / ".mcp.json"
    try:
        mcp_data = json.loads(mcp_path.read_text(encoding="utf-8")) if mcp_path.exists() else {}
    except ValueError:
        mcp_data = {}
    if not isinstance(mcp_data, dict):
        mcp_data = {}
    servers = mcp_data.setdefault("mcpServers", {})
    base_url = args.url.split("/v1/step/hook")[0]
    servers["stepcheck"] = {"type": "http", "url": f"{base_url}/mcp/"}
    rendered = json.dumps(mcp_data, indent=2) + "\n"
    if not mcp_path.exists() or mcp_path.read_text(encoding="utf-8") != rendered:
        mcp_path.write_text(rendered, encoding="utf-8", newline="\n")
    sid = StateKernel().init_session(root)
    print(f"  .mcp.json: wired stepcheck -> {base_url}/mcp/")
    print(f"  session  : initialized {sid} on {root}")
    return rc


def cmd_hooks(args: argparse.Namespace) -> int:
    """`stepcheck hooks [path] [--url …]`: write `.claude/hooks/stepcheck_hook.py`
    and wire it into `.claude/settings.json` for PreToolUse (Read/Edit/Write/
    MultiEdit/NotebookEdit) and Stop. Idempotent: other settings keys and other
    hooks are kept, and a second run changes no byte."""
    import json

    root = Path(args.path).resolve()
    hooks_dir = root / ".claude" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    script = hooks_dir / "stepcheck_hook.py"
    text = _HOOK_SCRIPT.replace("__STEPCHECK_HOOK_URL__", args.url)
    if not script.exists() or script.read_text(encoding="utf-8") != text:
        script.write_text(text, encoding="utf-8", newline="\n")
    settings = root / ".claude" / "settings.json"
    try:
        data = json.loads(settings.read_text(encoding="utf-8")) if settings.exists() else {}
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    hooks_cfg = data.setdefault("hooks", {})
    command = 'python "$CLAUDE_PROJECT_DIR/.claude/hooks/stepcheck_hook.py"'
    added = []
    for event, matcher in (("PreToolUse", "Read|Edit|Write|MultiEdit|NotebookEdit"), ("Stop", None)):
        entries = hooks_cfg.setdefault(event, [])
        if any(h.get("command") == command for e in entries for h in e.get("hooks", [])):
            continue
        entry: dict = {"matcher": matcher} if matcher else {}
        entry["hooks"] = [{"type": "command", "command": command, "timeout": 10}]
        entries.append(entry)
        added.append(event)
    rendered = json.dumps(data, indent=2) + "\n"
    if not settings.exists() or settings.read_text(encoding="utf-8") != rendered:
        settings.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"stepcheck hooks: {script.relative_to(root)} relays to {args.url}")
    print(f"  {settings.relative_to(root)}: " + (f"added {', '.join(added)}" if added else "already wired (no change)"))
    print("  offline gateway = edits checked in-process (Reads allowed) while a local one starts in the background")
    return 0


def _fmt_int(n) -> str:
    return f"{int(n):,}"


def _fmt_usd(x) -> str:
    return f"${float(x):,.2f}"


def _fmt_pct(x) -> str:
    return f"{float(x):.1f}%"


def _audit_card_svg(total: dict) -> str:
    """Shareable audit card from the audit totals only: no file names, session
    ids, paths or code can reach it, because none are inputs."""
    est = "" if total.get("skeleton_exact") else " (est.)"
    v = {
        "sessions": _fmt_int(total["sessions"]), "turns": _fmt_int(total["assistant_turns"]),
        "tax": _fmt_usd(total["gap_waste_usd"]), "gap_turns": _fmt_int(total["cache_gap_turns"]),
        "rebilled": _fmt_int(total["gap_rebilled_tokens"]), "compaction": _fmt_pct(total["read_saving_pct"]),
        "read_tokens": _fmt_int(total["read_tokens"]), "skeleton_tokens": _fmt_int(total["skeleton_tokens"]),
        "regressions": _fmt_int(total["regressions"]), "retries": _fmt_int(total["retry_turns"]),
    }
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="720" height="260" viewBox="0 0 720 260" role="img" aria-label="StepCheck audit card">\n'
        "  <title>StepCheck audit card</title>\n"
        "  <style>\n"
        "    .bg { fill: #0f172a; } .tile { fill: #1e293b; }\n"
        "    .t { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; fill: #e2e8f0; }\n"
        "    .k { font-size: 13px; fill: #94a3b8; } .v { font-size: 30px; font-weight: 700; }\n"
        "    .s { font-size: 12px; fill: #64748b; } .h { font-size: 15px; font-weight: 600; }\n"
        "    .tax { fill: #f87171; } .ok { fill: #34d399; } .warn { fill: #fbbf24; }\n"
        "  </style>\n"
        '  <rect class="bg" width="720" height="260" rx="14"/>\n'
        '  <text class="t h" x="24" y="36">stepcheck audit</text>\n'
        f'  <text class="t s" x="696" y="36" text-anchor="end">{v["sessions"]} sessions · {v["turns"]} assistant turns · no file names, no code</text>\n'
        '  <rect class="tile" x="24" y="56" width="216" height="150" rx="10"/>\n'
        '  <text class="t k" x="40" y="84">cache-cliff tax</text>\n'
        f'  <text class="t v tax" x="40" y="126">{v["tax"]}</text>\n'
        f'  <text class="t s" x="40" y="150">{v["gap_turns"]} turns resumed past the cache TTL</text>\n'
        f'  <text class="t s" x="40" y="168">{v["rebilled"]} tokens re-billed at full rate</text>\n'
        '  <text class="t s" x="40" y="186">above cache-read price</text>\n'
        '  <rect class="tile" x="252" y="56" width="216" height="150" rx="10"/>\n'
        '  <text class="t k" x="268" y="84">read-to-skeleton compaction</text>\n'
        f'  <text class="t v ok" x="268" y="126">{v["compaction"]}</text>\n'
        f'  <text class="t s" x="268" y="150">{v["read_tokens"]} tokens pulled with Read</text>\n'
        f'  <text class="t s" x="268" y="168">{v["skeleton_tokens"]} as AST skeletons{est}</text>\n'
        '  <text class="t s" x="268" y="186">focus=[] checkouts</text>\n'
        '  <rect class="tile" x="480" y="56" width="216" height="150" rx="10"/>\n'
        '  <text class="t k" x="496" y="84">regressions a gate would block</text>\n'
        f'  <text class="t v warn" x="496" y="126">{v["regressions"]}</text>\n'
        '  <text class="t s" x="496" y="150">edits that dropped a decorator</text>\n'
        '  <text class="t s" x="496" y="168">or a leading guard clause</text>\n'
        f'  <text class="t s" x="496" y="186">{v["retries"]} retry turns that followed</text>\n'
        '  <text class="t s" x="24" y="236">Generated locally by stepcheck audit from Claude Code transcripts. Numbers only; the per-session receipt stays on your machine.</text>\n'
        "</svg>\n"
    )


def _audit_card_md(total: dict) -> str:
    """Copy-paste Markdown badge line with the same five numbers as the card."""
    est = "" if total.get("skeleton_exact") else " (est.)"
    return (
        f"**stepcheck audit** · {_fmt_int(total['sessions'])} sessions / {_fmt_int(total['assistant_turns'])} turns · "
        f"cache-cliff tax **{_fmt_usd(total['gap_waste_usd'])}** ({_fmt_int(total['cache_gap_turns'])} resumes past the TTL, "
        f"{_fmt_int(total['gap_rebilled_tokens'])} tokens re-billed) · Read → AST skeleton **{_fmt_pct(total['read_saving_pct'])}** less "
        f"({_fmt_int(total['read_tokens'])} → {_fmt_int(total['skeleton_tokens'])}{est}) · "
        f"**{_fmt_int(total['regressions'])}** edits dropped a decorator/guard a gate would have blocked "
        f"({_fmt_int(total['retry_turns'])} retry turns)\n"
    )


def cmd_compliance(args: argparse.Namespace) -> int:
    """`stepcheck compliance [path] --out <dir>`: DUC.json (public dual-use card:
    repo digest, language counts, gate verdicts, invariant counts, DSSE Merkle
    root, self-verified zero path/code leakage) and DUA-E.json (escrowed bundle:
    every in-toto Statement v1 envelope, the Merkle tree, control mappings for
    OWASP AISVS 1.0 C9.3, SOC 2 CC8.1, PCI DSS 4.0 6.3.2 and EU AI Act Art. 12).
    Enterprise tier when licensing is enforced. Exit 1 without a session."""
    import json

    import licensing
    from kernel import StateKernel

    denial = licensing.gate_env("compliance_bundle")
    if denial is not None:
        print(f"stepcheck compliance: {denial['message']}", file=sys.stderr)
        return 3
    root = Path(args.path).resolve()
    try:
        bundle = StateKernel().compliance_bundle(root)
    except KeyError as exc:
        print(f"stepcheck compliance: {exc} (open a session with init_project_session first)", file=sys.stderr)
        return 1
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, doc in (("DUC.json", bundle["DUC"]), ("DUA-E.json", bundle["DUA-E"])):
        data = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
        (out / name).write_bytes(data.encode("utf-8"))
        print(f"wrote {out / name} ({len(data.encode('utf-8')):,} bytes)")
    duc = bundle["DUC"]
    print(f"files {duc['files']} · languages {duc['languages']} · commits {duc['gates']['commits_accepted']} · "
          f"rejections {duc['gates']['rejections']} · invariants {duc['invariants']['total']} · "
          f"merkle root {duc['attestations']['merkle_root']} · leak check {duc['leak_check']['paths']}/{duc['leak_check']['code']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
