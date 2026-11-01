---
description: Bring the StepCheck gateway up, open a kernel session on this repo, lock the modules named in the arguments, print the live Studio URL
---

Open a StepCheck session for this repository. Modules to lock (space-separated node ids, may be empty): `$ARGUMENTS`

1. **Gateway.** `GET http://127.0.0.1:8420/studio/` must answer 200. If it does not, start `stepcheck up` from the repo root (project venv) as a background task and wait until it answers. If the `stepcheck` MCP server is disconnected in this Claude Code session, tell the user to run `/mcp` and stop — never fall back to built-in file tools for tracked Python modules.
2. **Session.** Call `init_project_session(project_root=<absolute path of the repo root>)`. The result is large (every node's source): do not read it whole — extract `session_id` and the node list (`node_id`, `path`, `deps`, `invariants_auto_mined`) with a small script. Keep the `session_id` for the rest of the task.
3. **Locks.** For each node id in `$ARGUMENTS` call `lock_module_invariants(session_id, node_id)` and confirm `status: LOCKED`. A locked module rejects every mutation at Gate A; lock foundational modules the task will not change (in this repo `_tokens`, `_telemetry` are typical). If no ids were given, lock nothing and say which candidates you would lock.
4. **Report** in one block: `session_id`, node count, locked nodes, and the Studio URL `http://127.0.0.1:8420/studio/?session=<session_id>`.

Notes: node ids are file stems while unique and dotted relative paths otherwise (`backend.kernel.__init__`). A session is persisted under `<root>/.stepcheck/sessions/` and survives gateway restarts; reuse it instead of opening a new one per task.
