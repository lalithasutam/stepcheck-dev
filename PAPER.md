# StepCheck: a deterministic context firewall and gated state engine for AI coding agents

Generated 2026-11-03 from execution receipts by `.stepcheck/discovery/verify_integrity.py`. Kernel evaluated: `80a1539` (pre-slice) and `9103def` (post-slice).

## Abstract

Long agent sessions degrade in two coupled ways: the context re-read every turn grows until attention over it decays, and silent omissions (a dropped decorator, a removed guard clause) pass the tests the agent still runs. StepCheck interposes a deterministic kernel between agent and model: modules are compiled into OKF frames, checked out as AST skeletons with a chosen focus, and modified only through patches that must pass three gates — mechanical (A), omission (B) and executed invariants (C) — before a DSSE attestation lands. We evaluate on an installed corpus of 9 packages (387 files, 152,176 LOC) and on the kernel's own repository.

## 1. Design

The kernel (Seam 1) exposes `init_session`, `checkout(focus=)`, `commit(patch=)`, `lock_node`, `finalize_session` and `provenance`. A gateway (Seam 2) serves the same operations over REST and MCP and a BYOK proxy. Gate A checks syntax, locks and the names dependents import (including names bound inside conditional blocks and lazy `__all__` exports); Gate B fingerprints preserved symbols — definitions, decorators per module and per symbol, calls into dependencies — and refuses mass deletion; Gate C evaluates string, tree and callable invariants, the callable ones auto-mined from leading guard clauses, under a step, wall-clock and recursion-depth budget. Every landed commit yields a deterministic DSSE envelope; `provenance()` re-expresses the latest one as an in-toto Statement v1.

## 2. Evaluation

### 2.1 Fault matrix

| fault matrix (50 faults, 50 valid edits) | value |
| --- | --- |
| precision | 100.0% |
| recall | 100.0% |
| false positive rate | 0.0% |

### 2.2 Compaction and context cost

50-turn benchmark: 120,815 raw tokens versus 14,048 sent (88.4% saved). On the repository's own modules:

| per-turn context source | tokens | saved vs (b) |
| --- | --- | --- |
| (b) raw Read of all tracked modules | 36,215 | — |
| (a) CLAUDE.md compliance, focus on the largest symbol | 22,904 | 36.8% |
| (c) hook-enforced skeleton for modules over the threshold | 16,792 | 53.6% |
| (d) pure focus=[] skeleton | 15,114 | 58.3% |

### 2.3 Latency

| phase | modules | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| parse | 499 | 1.5 ms | 18.5 ms | 51.2 ms |
| analyze | 499 | 5.9 ms | 80.5 ms | 141.4 ms |
| skeleton | 499 | 1.8 ms | 26.3 ms | 67.1 ms |
| checkout_focus_empty | 499 | 8.7 ms | 115.4 ms | 193.7 ms |
| gate_a | 498 | 18.8 ms | 176.7 ms | 269.0 ms |
| gate_b | 498 | 4.2 ms | 73.6 ms | 126.7 ms |
| gate_c | 498 | 3.3 ms | 45.3 ms | 95.7 ms |
| commit_append | 498 | 61.2 ms | 464.2 ms | 837.5 ms |

### 2.4 Symbol addressing on real code

| AST pattern (16 packages + backend) | occurrences |
| --- | --- |
| overload chains | 93 |
| property pairs | 33 |
| comment between decorator and def | 0 |
| async generators | 48 |
| match blocks | 25 |
| duplicate top level defs | 0 |

Method-level slicing saves 6.86% of the class-focus payload in aggregate over 165 classes (median 3.96%).

### 2.5 Robustness

| property | examples | counterexamples / false positives |
| --- | --- | --- |
| _okf.apply_patch | 200 | 0 |
| mine_guard_invariants → gate_c | 72 | 0 |
| _sandbox.guarded | 200 | see recursion row |

Mutual recursion through a real commit left the trace hook unchanged = False; the budget stayed enforced on the next commit = True.

### 2.6 Operational economics

| audit figure | published receipt | re-derived at run time |
| --- | --- | --- |
| sessions | 116 | 122 |
| assistant turns | 5,330 | 6,389 |
| cache gap turns | 67 | 82 |
| gap rebilled tokens | 4,950,678 | 5,335,876 |
| gap waste usd | $13.37 | $14.41 |

| price tier | observed delta above cache-read | annualized, solo | annualized, 25 seats |
| --- | --- | --- | --- |
| sonnet | $14.41 | $33.03 | $825.87 |
| opus | $72.03 | $165.17 | $4,129.33 |

## 3. Limitations

Faults are synthetic AST mutations. All timings come from one Windows machine. The token counter is the kernel's own estimator. SWE-bench Verified rows were fetched. Prices in the economics tables are assumptions recorded in the receipt, not measurements.

## 4. Reproducibility

`python -m pytest -q` (386 passed), `stepcheck ci .` (84 modules), `.stepcheck/paper_eval/run_eval.py`, `.stepcheck/discovery/engine_explorer.py`, `product_explorer.py`, `market_explorer.py`, `gtm_explorer.py`, then `verify_integrity.py`.

## 5. v0.2 campaign results

Red receipt over the new test modules on the unpatched tree: 33 failed, 0 passed, 0 timed out.
Green receipt after landing: 33 passed, 0 failed, 0 timed out.

### 8.1 Dogfooding through the gates

| slice | gated commits | new modules attested | dependents re-verified | finalized | session tokens saved |
| --- | --- | --- | --- | --- | --- |
| slice17 | 2 | 1 | 1 | yes | 13,177 |
| slice18 | 2 | 1 | 7 | yes | 24,502 |
| slice19 | 1 | 1 | 0 | yes | 4,228 |
| slice20 | 7 | 1 | 2 | yes | 51,544 |
| slice20_fix_compactor_language | 1 | 0 | 0 | yes | 0 |
| slice18_fix_hook_template_guard | 1 | 0 | 0 | yes | 0 |

### 8.2 Slice 17 metrics (before → after)

| metric | before | after |
| --- | --- | --- |
| slice | 17 | 17 |
| budget_tokens | 4,000 | 4,000 |
| corpus.files | 387 | 391 |
| corpus.raw_tokens | 1,392,309 | 1,411,546 |
| corpus.b_prime_skeleton_payload_tokens | 2,374,564 | 570,703 |
| corpus.b_prime_saving_pct | -70.5% | 59.6% |
| corpus.c_prime_files | 236 | 240 |
| corpus.c_prime_raw_tokens | 1,185,325 | 1,204,562 |
| corpus.c_prime_focused_payload_tokens | 2,070,880 | 453,074 |
| corpus.c_prime_saving_pct | -74.7% | 62.4% |
| corpus.skeleton_over_budget | 127 | 11 |
| corpus.focused_over_budget | 119 | 22 |
| corpus.public_symbols | 2,152 | 2,188 |
| corpus.public_recalled | 2,152 | 2,188 |
| corpus.files_with_backstop_elision | 0 | 44 |
| corpus.public_recall_pct | 100.0% | 100.0% |
| class_method.classes_measured | 165 | 165 |
| class_method.sum_focus_class_payload_tokens | 1,868,564 | 560,675 |
| class_method.sum_focus_method_payload_tokens | 1,739,559 | 359,289 |
| class_method.aggregate_saving_vs_class_focus_pct | 6.9% | 35.9% |
| class_method.median_saving_vs_class_focus_pct | 3.9% | 17.9% |
| class_method.method_body_rendered | 165 | 165 |
| class_method.method_over_budget | 84 | 20 |
| own_backend.server_raw_tokens | 5,030 | 6,151 |
| own_backend.server_focus_build_mcp_payload_tokens | 3,637 | 2,743 |
| own_backend.server_saving_pct | 27.7% | 55.4% |
| own_backend.server_dependency_skeleton_chars.backend.kernel.__init__ | 4,203 | 1,100 |
| own_backend.statekernel_focus_class_payload_tokens | 7,635 | 5,718 |
| own_backend.statekernel_focus_commit_payload_tokens | 4,856 | 2,076 |
| own_backend.statekernel_method_vs_class_saving_pct | 36.4% | 63.7% |

### 8.3 Slice 18 metrics (before → after)

| metric | before | after |
| --- | --- | --- |
| slice | 18 | 18 |
| subprocess_hooks_track2.read_guard_deny_p50_ms | 375.4 ms | 375.4 ms |
| subprocess_hooks_track2.read_guard_deny_p95_ms | 432.2 ms | 432.2 ms |
| subprocess_hooks_track2.stop_guard_dirty_p50_ms | 270.6 ms | 270.6 ms |
| subprocess_hooks_track2.stop_guard_dirty_p95_ms | 281.9 ms | 281.9 ms |
| warm_endpoint.stop_clean.n | 50 | 50 |
| warm_endpoint.stop_clean.p50_ms | 6.3 ms | 7.8 ms |
| warm_endpoint.stop_clean.p95_ms | 7.7 ms | 9.6 ms |
| warm_endpoint.stop_clean.p99_ms | 8.1 ms | 10.1 ms |
| warm_endpoint.stop_clean.max_ms | 8.1 ms | 10.1 ms |
| warm_endpoint.stop_clean.response_tokens_hint | n/a | 0 |
| warm_endpoint.read_deny_server_py.n | 50 | 50 |
| warm_endpoint.read_deny_server_py.p50_ms | 7.0 ms | 70.1 ms |
| warm_endpoint.read_deny_server_py.p95_ms | 7.9 ms | 125.9 ms |
| warm_endpoint.read_deny_server_py.p99_ms | 12.0 ms | 133.9 ms |
| warm_endpoint.read_deny_server_py.max_ms | 12.0 ms | 133.9 ms |
| warm_endpoint.read_deny_server_py.response_tokens_hint | n/a | 2,416 |
| warm_endpoint.read_allow_small.n | 50 | 50 |
| warm_endpoint.read_allow_small.p50_ms | 7.0 ms | 12.5 ms |
| warm_endpoint.read_allow_small.p95_ms | 8.6 ms | 13.8 ms |
| warm_endpoint.read_allow_small.p99_ms | 10.2 ms | 14.4 ms |
| warm_endpoint.read_allow_small.max_ms | 10.2 ms | 14.4 ms |
| warm_endpoint.read_allow_small.response_tokens_hint | n/a | 0 |
| warm_endpoint.edit_unlocked.n | 50 | 50 |
| warm_endpoint.edit_unlocked.p50_ms | 7.8 ms | 15.1 ms |
| warm_endpoint.edit_unlocked.p95_ms | 9.0 ms | 17.0 ms |
| warm_endpoint.edit_unlocked.p99_ms | 9.4 ms | 18.9 ms |
| warm_endpoint.edit_unlocked.max_ms | 9.4 ms | 18.9 ms |
| warm_endpoint.edit_unlocked.response_tokens_hint | n/a | 0 |

### 8.4 Slice 19 metrics (before → after)

| metric | before | after |
| --- | --- | --- |
| endpoints.openai.status | 200 | 200 |
| endpoints.openai.raw_tokens | 9,685 | 13,920 |
| endpoints.openai.sent_tokens | 474 | 2,015 |
| endpoints.openai.compaction.pruned_messages | — | 3 |
| endpoints.openai.compaction.folded_messages | — | 0 |
| endpoints.openai.compaction.tokens_before | — | 13,912 |
| endpoints.openai.compaction.tokens_after | — | 1,546 |
| endpoints.openai.compaction.saved_pct | — | 88.9% |
| endpoints.openai.all_turn_prompt_reduction_pct | 95.1% | 85.5% |
| endpoints.anthropic.status | 200 | 200 |
| endpoints.anthropic.raw_tokens | 9,677 | 13,912 |
| endpoints.anthropic.sent_tokens | 466 | 2,007 |
| endpoints.anthropic.compaction.pruned_messages | — | 3 |
| endpoints.anthropic.compaction.folded_messages | — | 0 |
| endpoints.anthropic.compaction.tokens_before | — | 13,912 |
| endpoints.anthropic.compaction.tokens_after | — | 1,546 |
| endpoints.anthropic.compaction.saved_pct | — | 88.9% |
| endpoints.anthropic.all_turn_prompt_reduction_pct | 95.2% | 85.6% |
| finops_v2.measured.sessions | 126 | 126 |
| finops_v2.measured.assistant_turns | 6,672 | 6,672 |
| finops_v2.measured.cache_gap_turns | 84 | 84 |
| finops_v2.measured.gap_rebilled_tokens | 5,694,058 | 5,694,058 |
| finops_v2.measured.turns_with_middle_band_saving | 3,774 | 3,774 |
| finops_v2.measured.middle_band_saving_tokens_total | 59,636,494 | 59,636,494 |
| finops_v2.measured.middle_band_saving_pct_of_prompt_tokens | 4.1% | 4.1% |
| finops_v2.measured.prompt_tokens_total | 1,450,942,728 | 1,450,942,728 |
| finops_v2.scenarios.combined|frontier=sonnet|cheap=haiku_4_5.solo_monthly_baseline_usd | $105.12 | $105.12 |
| finops_v2.scenarios.combined|frontier=sonnet|cheap=haiku_4_5.compaction_only_saving_pct | 6.1% | 6.1% |
| finops_v2.scenarios.combined|frontier=sonnet|cheap=haiku_4_5.break_even_pass_rate_pro_29 | 0.50 | 0.50 |
| finops_v2.scenarios.combined|frontier=sonnet|cheap=haiku_4_5.break_even_pass_rate_team_199 | 0.28 | 0.28 |
| finops_v2.scenarios.combined|frontier=sonnet|cheap=local_ollama_vllm.solo_monthly_baseline_usd | $105.12 | $105.12 |
| finops_v2.scenarios.combined|frontier=sonnet|cheap=local_ollama_vllm.compaction_only_saving_pct | 6.1% | 6.1% |
| finops_v2.scenarios.combined|frontier=sonnet|cheap=local_ollama_vllm.break_even_pass_rate_pro_29 | 0.23 | 0.23 |
| finops_v2.scenarios.combined|frontier=sonnet|cheap=local_ollama_vllm.break_even_pass_rate_team_199 | 0.02 | 0.02 |
| finops_v2.scenarios.combined|frontier=opus|cheap=haiku_4_5.solo_monthly_baseline_usd | $525.61 | $525.61 |
| finops_v2.scenarios.combined|frontier=opus|cheap=haiku_4_5.compaction_only_saving_pct | 6.1% | 6.1% |
| finops_v2.scenarios.combined|frontier=opus|cheap=haiku_4_5.break_even_pass_rate_pro_29 | 0.05 | 0.05 |
| finops_v2.scenarios.combined|frontier=opus|cheap=haiku_4_5.break_even_pass_rate_team_199 | 0.00 | 0.00 |
| finops_v2.scenarios.combined|frontier=opus|cheap=local_ollama_vllm.solo_monthly_baseline_usd | $525.61 | $525.61 |
| finops_v2.scenarios.combined|frontier=opus|cheap=local_ollama_vllm.compaction_only_saving_pct | 6.1% | 6.1% |
| finops_v2.scenarios.combined|frontier=opus|cheap=local_ollama_vllm.break_even_pass_rate_pro_29 | 0.00 | 0.00 |
| finops_v2.scenarios.combined|frontier=opus|cheap=local_ollama_vllm.break_even_pass_rate_team_199 | 0.00 | 0.00 |

### 8.5 Slice 20 metrics (before → after)

| metric | before | after |
| --- | --- | --- |
| slice | — | 20 |
| summary.files_on_disk | — | 12 |
| summary.nodes_indexed | — | 12 |
| summary.loc | — | 962 |
| summary.raw_tokens | — | 12,293 |
| summary.skeleton_tokens | — | 4,123 |
| summary.compaction_pct | — | 66.5% |
| summary.export_recall_pct | — | 100.0% |
| summary.edges | — | 19 |

## 9. v0.3 overnight campaign (Slices 21–25)

Red receipt over the new test modules on the unpatched tree: 43 failed, 23 passed, 0 timed out.
Green receipt after landing: 63 passed, 0 failed, 0 timed out.

### 9.1 Dogfooding through the gates

| slice | gated commits | new modules attested | dependents re-verified | finalized | session tokens saved |
| --- | --- | --- | --- | --- | --- |
| slice21 | 4 | 0 | 2 | yes | 20,843 |
| slice22 | 2 | 0 | 0 | yes | 7,061 |
| slice23 | 5 | 4 | 3 | yes | 64,867 |
| slice24 | 3 | 4 | 9 | yes | 61,024 |
| slice21_fix_statekernel_floor | 1 | 0 | 0 | yes | 0 |
| slice25 | 1 | 0 | 0 | yes | 1,994 |
| slice25_r2 | 1 | 0 | 0 | yes | 5,704 |

### 9.2 Slice 21 metrics (before → after)

| metric | before | after |
| --- | --- | --- |
| slice | 21 | 21 |
| budget_tokens | 4,000 | 4,000 |
| hooks.project_modules | 10 | 10 |
| hooks.denied_module_tokens | 6,151 | 6,853 |
| hooks.read_deny_first_call_ms | 67.3 ms | 42.3 ms |
| hooks.read_deny_p50_ms | 41.9 ms | 9.1 ms |
| hooks.read_deny_p95_ms | 92.0 ms | 9.8 ms |
| hooks.read_deny_n | 50 | 50 |
| hooks.stop_p50_ms | 7.7 ms | 8.3 ms |
| hooks.stop_p95_ms | 8.4 ms | 9.1 ms |
| hooks.edit_unlocked_p50_ms | 8.9 ms | 8.8 ms |
| hooks.edit_unlocked_p95_ms | 10.3 ms | 9.9 ms |
| hooks.read_allow_small_p50_ms | 9.6 ms | 8.8 ms |
| hooks.read_allow_small_p95_ms | 10.3 ms | 9.8 ms |
| hooks.turns_charged_in_memory | 51 | 51 |
| hooks.turns_visible_to_a_fresh_kernel_before_flush | 51 | 0 |
| corpus.files | 391 | 399 |
| corpus.raw_tokens | 1,411,546 | 1,441,112 |
| corpus.b_prime_skeleton_payload_tokens | 570,703 | 529,030 |
| corpus.b_prime_saving_pct | 59.6% | 63.3% |
| corpus.c_prime_files | 240 | 248 |
| corpus.c_prime_raw_tokens | 1,204,562 | 1,234,128 |
| corpus.c_prime_focused_payload_tokens | 453,074 | 392,979 |
| corpus.c_prime_saving_pct | 62.4% | 68.2% |
| corpus.skeleton_over_budget | 11 | 0 |
| corpus.focused_over_budget | 22 | 13 |
| corpus.public_symbols | 2,188 | 2,290 |
| corpus.public_recalled | 2,188 | 2,290 |
| corpus.files_with_backstop_elision | 44 | 45 |
| corpus.public_recall_pct | 100.0% | 100.0% |
| class_method.classes_measured | 165 | 165 |
| class_method.sum_focus_class_payload_tokens | 560,675 | 453,925 |
| class_method.sum_focus_method_payload_tokens | 359,289 | 244,032 |
| class_method.aggregate_saving_vs_class_focus_pct | 35.9% | 46.2% |
| class_method.median_saving_vs_class_focus_pct | 17.9% | 23.8% |
| class_method.method_body_rendered | 165 | 165 |
| class_method.method_over_budget | 20 | 5 |
| class_method.payloads_with_folded_sibling_runs | 0 | 73 |
| own_backend.server_raw_tokens | 6,151 | 6,852 |
| own_backend.server_focus_build_mcp_payload_tokens | 2,743 | 2,318 |
| own_backend.server_saving_pct | 55.4% | 66.2% |
| own_backend.statekernel_focus_class_payload_tokens | 5,718 | 6,797 |
| own_backend.statekernel_focus_commit_payload_tokens | 2,076 | 2,054 |
| own_backend.statekernel_method_vs_class_saving_pct | 63.7% | 69.8% |

### 9.3 Slice 22 metrics (before → after)

| metric | before | after |
| --- | --- | --- |
| fixtures.anthropic.messages | 15 | 15 |
| fixtures.anthropic.tokens_before | 20,443 | 20,443 |
| fixtures.anthropic.tokens_after | 15,846 | 1,848 |
| fixtures.anthropic.saved_pct | 22.5% | 91.0% |
| fixtures.anthropic.blocks_skeletonized | 0 | 2 |
| fixtures.anthropic.logs_elided | 0 | 2 |
| fixtures.anthropic.line_prefixes_stripped | 0 | 399 |
| fixtures.anthropic.languages.python | — | 1 |
| fixtures.anthropic.languages.typescript | — | 1 |
| fixtures.anthropic.pruned_messages | 0 | 0 |
| fixtures.anthropic.compaction_ms_p50 | 20.0 ms | 8.4 ms |
| fixtures.anthropic.compaction_ms_p95 | 48.2 ms | 13.6 ms |
| fixtures.openai.messages | 16 | 16 |
| fixtures.openai.tokens_before | 20,443 | 20,443 |
| fixtures.openai.tokens_after | 15,846 | 1,848 |
| fixtures.openai.saved_pct | 22.5% | 91.0% |
| fixtures.openai.blocks_skeletonized | 0 | 2 |
| fixtures.openai.logs_elided | 0 | 2 |
| fixtures.openai.line_prefixes_stripped | 0 | 399 |
| fixtures.openai.languages.python | — | 1 |
| fixtures.openai.languages.typescript | — | 1 |
| fixtures.openai.pruned_messages | 0 | 0 |
| fixtures.openai.compaction_ms_p50 | 19.6 ms | 8.2 ms |
| fixtures.openai.compaction_ms_p95 | 48.7 ms | 8.4 ms |

### 9.4 Slice 23 metrics (before → after)

| metric | before | after |
| --- | --- | --- |
| slice | 23 | 23 |
| typescript.files | 12 | 12 |
| typescript.loc | 950 | 950 |
| typescript.raw_tokens | 7,442 | 7,442 |
| typescript.skeleton_tokens | 1,146 | 1,146 |
| typescript.compaction_pct | 84.6% | 84.6% |
| typescript.declaration_recall_pct | 100.0% | 100.0% |
| typescript.member_symbols | 0 | 0 |
| typescript.mined_guards | 0 | 0 |
| typescript.edges | 19 | 19 |
| go.files | 0 | 2 |
| go.loc | 0 | 206 |
| go.raw_tokens | 0 | 1,258 |
| go.skeleton_tokens | 0 | 174 |
| go.compaction_pct | n/a | 86.2% |
| go.declaration_recall_pct | n/a | 100.0% |
| go.member_symbols | 0 | 10 |
| go.mined_guards | 0 | 5 |
| go.edges | 0 | 1 |
| rust.files | 0 | 2 |
| rust.loc | 0 | 203 |
| rust.raw_tokens | 0 | 1,369 |
| rust.skeleton_tokens | 0 | 231 |
| rust.compaction_pct | n/a | 83.1% |
| rust.declaration_recall_pct | n/a | 100.0% |
| rust.member_symbols | 0 | 15 |
| rust.mined_guards | 0 | 10 |
| rust.edges | 0 | 1 |
| java.files | 0 | 2 |
| java.loc | 0 | 170 |
| java.raw_tokens | 0 | 1,177 |
| java.skeleton_tokens | 0 | 75 |
| java.compaction_pct | n/a | 93.6% |
| java.declaration_recall_pct | n/a | 100.0% |
| java.member_symbols | 0 | 24 |
| java.mined_guards | 0 | 8 |
| java.edges | 0 | 1 |

### 9.5 Slice 24 metrics (before → after)

| metric | before | after |
| --- | --- | --- |
| slice | — | 24 |
| tiers.free.usd_per_month | — | $0.00 |
| tiers.pro.usd_per_month | — | $19.00 |
| tiers.team.usd_per_seat_month | — | $39.00 |
| tiers.enterprise.usd_per_seat_month | — | $79.00 |
| tiers.enterprise.usd_per_year_self_hosted | — | $25,000.00 |
| summary_latency_no_enforcement.n | — | 50 |
| summary_latency_no_enforcement.p50_ms | — | 8.0 ms |
| summary_latency_no_enforcement.p95_ms | — | 9.0 ms |
| summary_latency_no_enforcement.max_ms | — | 55.3 ms |
| hook_stop_latency_no_enforcement.n | — | 50 |
| hook_stop_latency_no_enforcement.p50_ms | — | 8.4 ms |
| hook_stop_latency_no_enforcement.p95_ms | — | 9.4 ms |
| hook_stop_latency_no_enforcement.max_ms | — | 10.0 ms |
| summary_latency_enforced.n | — | 50 |
| summary_latency_enforced.p50_ms | — | 7.9 ms |
| summary_latency_enforced.p95_ms | — | 8.5 ms |
| summary_latency_enforced.max_ms | — | 8.6 ms |
| hook_stop_latency_enforced.n | — | 50 |
| hook_stop_latency_enforced.p50_ms | — | 8.5 ms |
| hook_stop_latency_enforced.p95_ms | — | 9.2 ms |
| hook_stop_latency_enforced.max_ms | — | 9.5 ms |
| door1_402_latency.n | — | 50 |
| door1_402_latency.p50_ms | — | 6.0 ms |
| door1_402_latency.p95_ms | — | 6.8 ms |
| door1_402_latency.max_ms | — | 7.1 ms |
| summary_sessions | — | 1 |
| compliance_bundle_ms | — | 28.1 ms |
| bundle_bytes.DUC | — | 913 |
| bundle_bytes.DUA-E | — | 5,462 |
| duc_leak_check.paths | — | 0 |
| duc_leak_check.code | — | 0 |
| duc_attestations | — | 1 |

### 9.6 Slice 25 metrics (before → after)

| metric | before | after |
| --- | --- | --- |
| slice | — | 25 |
| fuzzer.rounds | — | 4 |
| fuzzer.examples_total | — | 12,716 |
| fuzzer.examples_last_round | — | 3,860 |
| fuzzer.counterexamples_total | — | 32 |
| fuzzer.counterexamples_last_round | — | 0 |
| fuzzer.counterexample_classes_fixed | — | 2 |
| fuzzer.languages | — | 6 |
| fuzzer.seconds_last_round | — | 50.50 |
| red.tests | — | 47 |
| red.failed_before_fix | — | 3 |
| red.landing_rounds | — | 2 |
| journeys.checks | — | 36 |
| journeys.checks_passed | — | 36 |
| journeys.checks_failed | — | 0 |
| journeys.journey1_seconds | — | 9.60 |
| journeys.journey1_transcripts | — | 131 |
| journeys.journey1_forbidden_terms | — | 137 |
| journeys.journey1_card_bytes | — | 2,225 |
| journeys.journey2_stop_p50_ms | — | 7.2 ms |
| journeys.journey2_stop_p95_ms | — | 7.5 ms |
| journeys.journey2_read_deny_p50_ms | — | 8.3 ms |
| journeys.journey2_read_deny_p95_ms | — | 9.1 ms |
| journeys.journey2_nodes_indexed | — | 6 |
| journeys.journey3_door1_warm_ms | — | 102.3 ms |
| journeys.journey3_door1_cliff_ms | — | 57.7 ms |
| journeys.journey3_blocks_skeletonized | — | 2 |
| journeys.journey3_logs_elided | — | 2 |
| journeys.journey3_warm_saved_pct | — | 91.0% |
| journeys.journey3_cliff_saved_pct | — | 99.0% |
| journeys.journey3_team_sessions | — | 2 |
| journeys.journey3_duc_bytes | — | 992 |
| journeys.journey3_duae_bytes | — | 5,854 |

## 10. Privacy fixes release (whole-token leak check, abbreviated audit paths)

Red receipt over the new test modules on the unpatched tree: 2 failed, 13 passed, 0 timed out.
Green receipt after landing: 15 passed, 0 failed, 0 timed out.

### 10.1 Dogfooding through the gates

| slice | gated commits | new modules attested | dependents re-verified | finalized | session tokens saved |
| --- | --- | --- | --- | --- | --- |
| v031_privacy | 2 | 0 | 0 | yes | 6,703 |
| v031_tests_slice24 | 1 | 0 | 0 | yes | 0 |
| v031_tests_audit | 1 | 0 | 0 | yes | 0 |
| v031_hook_cost | 1 | 0 | 0 | yes | 0 |
| v031_tests_slice21 | 1 | 0 | 0 | yes | 0 |

## 11. Hook cost fix (a locked-node rejection no longer re-renders the project)

Red receipt over the new test modules on the unpatched tree: 2 failed, 8 passed, 0 timed out.
Green receipt after landing: 10 passed, 0 failed, 0 timed out.
### Overnight user journeys

| figure | value |
| --- | --- |
| checks | 36 |
| checks_passed | 36 |
| checks_failed | 0 |
| journey1_seconds | 9.60 |
| journey1_transcripts | 131 |
| journey1_forbidden_terms | 137 |
| journey1_card_bytes | 2,225 |
| journey2_stop_p50_ms | 7.2 ms |
| journey2_stop_p95_ms | 7.5 ms |
| journey2_read_deny_p50_ms | 8.3 ms |
| journey2_read_deny_p95_ms | 9.1 ms |
| journey2_nodes_indexed | 6 |
| journey3_door1_warm_ms | 102.3 ms |
| journey3_door1_cliff_ms | 57.7 ms |
| journey3_blocks_skeletonized | 2 |
| journey3_logs_elided | 2 |
| journey3_warm_saved_pct | 91.0% |
| journey3_cliff_saved_pct | 99.0% |
| journey3_team_sessions | 2 |
| journey3_duc_bytes | 992 |
| journey3_duae_bytes | 5,854 |

### Overnight adversarial fuzzing

| figure | value |
| --- | --- |
| rounds | 4 |
| examples_total | 12,716 |
| counterexamples_total | 32 |
| counterexamples_last_round | 0 |
| counterexamples_fixed | 32 |
| seconds_last_round | 50.50 |

### 8.6 Repository sync

Backend LOC 7,399; audit over 131 sessions, 7,612 assistant turns, 95 cache-cliff turns, 5,876,819 re-billed tokens, $15.87 above cache-read.

README / LAUNCH / CLAUDE.md / .cursorrules figures rewritten by `sync_docs.py` from receipts: 49 substitutions.


## 7. Enterprise monorepo scaling (Slices 35 → 36 → 37)

Measured by `.stepcheck/discovery/benchmark_enterprise_scale.py` on the fifteen largest cached modules, the `django/` package, the full django tree, a noise tree and the resilience cases; one column per slice (receipt `receipts/enterprise_scale.json`). The last column's run times `init_session` without tracemalloc attached; the earlier columns carry its overhead. `stepcheck ci` is timed twice in the benchmark process, after the hook probes; a fresh process measures the package at the warm figure.

| Measurement | slice35 | slice36 | slice37 |
| --- | --- | --- | --- |
| Monolith files (15 files, 72,904 LOC): dry-run commit, one function edited | p50 1216.1 / p95 1850.1 / max 1929.7 ms; <25 ms 0.0%, <50 ms 0.0% | p50 453.1 / p95 873.0 / max 921.4 ms; <25 ms 0.0%, <50 ms 0.0% | p50 38.7 / p95 133.7 / max 432.8 ms; <25 ms 5.8%, <50 ms 75.4% |
| Monolith files: landed commit | p50 1285.4 / p95 1979.1 / max 2034.1 ms; <25 ms 0.0%, <50 ms 0.0% | p50 630.5 / p95 813.6 / max 1043.5 ms; <25 ms 0.0%, <50 ms 0.0% | p50 183.3 / p95 223.0 / max 325.2 ms; <25 ms 0.0%, <50 ms 0.0% |
| Monolith files: init_session | p50 396.1 / p95 559.1 / max 594.6 ms; <25 ms 0.0%, <50 ms 0.0% | p50 473.4 / p95 589.9 / max 628.8 ms; <25 ms 0.0%, <50 ms 0.0% | p50 368.0 / p95 572.1 / max 590.9 ms; <25 ms 0.0%, <50 ms 0.0% |
| Monolith files: focused checkout | p50 255.1 / p95 398.4 / max 404.9 ms; <25 ms 0.0%, <50 ms 0.0% | p50 449.1 / p95 615.4 / max 626.1 ms; <25 ms 0.0%, <50 ms 6.7% | p50 273.2 / p95 388.9 / max 552.8 ms; <25 ms 0.0%, <50 ms 6.7% |
| django package (930 files, 170,643 LOC): cold init_session | 135.9 s (6.8 files/s) | 89.9 s (9.8 files/s) | 1.1 s (793.2 files/s) |
| django package: peak memory (tracemalloc / RSS) / session file | 58.9 MB / None MB / 7.7 MB | 58.0 MB / None MB / 7.3 MB | 16.3 MB / None MB / 0.3 MB |
| django package: in-process PreToolUse Edit hook on db/models/sql/query.py | p50 898.3 / p95 1100.1 / max 1100.1 ms; <25 ms 0.0%, <50 ms 0.0% | p50 355.7 / p95 444.3 / max 444.3 ms; <25 ms 0.0%, <50 ms 0.0% | p50 17.6 / p95 234.4 / max 234.4 ms; <25 ms 80.0%, <50 ms 80.0% |
| django package: PreToolUse Read hook | p50 3.2 / p95 97.3 / max 97.3 ms; <25 ms 66.7%, <50 ms 66.7% | p50 4.2 / p95 128.1 / max 128.1 ms; <25 ms 66.7%, <50 ms 66.7% | p50 3.2 / p95 1035.1 / max 1035.1 ms; <25 ms 66.7%, <50 ms 66.7% |
| django package: fresh-process session rehydrate + locate | 138.0 ms | 128.2 ms | 67.6 ms |
| django package: stepcheck ci cold / warm | 107.2 s / 91.0 s, exit 1 | 55.9 s / 46.5 s, exit 1 | 5.2 s / 6.1 s, exit 0 |
| full django tree (2980 files, 537,414 LOC): cold init_session | CRASH after 185.8 s: SyntaxError: invalid syntax (<unknown>, line 48) | 231.4 s (11.5 files/s) | 2.8 s (1016.5 files/s) |
| full django tree: peak memory / session file | CRASH after 185.8 s: SyntaxError: invalid syntax (<unknown>, line 48) | 242.0 MB / 22.1 MB | 57.8 MB / 1.0 MB |
| full django tree: PreToolUse Edit hook | CRASH after 185.8 s: SyntaxError: invalid syntax (<unknown>, line 48) | p50 625.2 / p95 700.7 / max 700.7 ms; <25 ms 0.0%, <50 ms 0.0% | p50 24.0 / p95 341.3 / max 341.3 ms; <25 ms 60.0%, <50 ms 80.0% |
| full django tree: fresh-process session rehydrate + locate | CRASH after 185.8 s: SyntaxError: invalid syntax (<unknown>, line 48) | 435.7 ms | 85.1 ms |
| full django tree: stepcheck ci cold / warm | CRASH after 185.8 s: SyntaxError: invalid syntax (<unknown>, line 48) | 9.7 s / 9.8 s, exit 1 | 14.7 s / 14.5 s, exit 1 |
| Noise tree (migrations, _pb2, .min.js, .d.ts, vendor, dist, build, .gitignored) | 7 noise files tracked of 16 (2 gitignored), init 3237.2 ms | 0 noise files tracked of 16 (0 gitignored), init 104.9 ms | 0 noise files tracked of 16 (0 gitignored), init 110.0 ms |
| Resilience | nesting_120: crash; nesting_400: crash; circular+*: ok; BOM/CRLF: ok | nesting_120: untracked: past the parser's limits, index unaffected; nesting_400: untracked: past the parser's limits, index unaffected; circular+*: ok; BOM/CRLF: ok | nesting_120: untracked: past the parser's limits, index unaffected; nesting_400: untracked: past the parser's limits, index unaffected; circular+*: ok; BOM/CRLF: ok |

### 7.1 Zero-trust audit of Slices 35–37

`audit_not_benchmark_shaped.py` (receipt `receipts/not_benchmark_shaped_audit.json`) diffed `backend/` against 36c6280: 2,346 added lines, 8 corpus-name literals outside tests, every one in a docstring or comment (the receipt lists each with its line). Every exclusion pattern and gate exemption is printed verbatim in the receipt.

Fault injection in guarded functions at the top, middle and bottom of the monoliths, committed through the fast path (stitched on 100.0% of commits): 111 of 124 blocked (89.5%). The accepted faults are `return X` guards neutered to `return None`: the early return survives, the value does not, and a structural guard invariant does not see values.

| fault | blocked | rate | p50 when blocking | p95 |
| --- | --- | --- | --- | --- |
| guard drop | 38 / 38 | 100.0% | 147.5 ms | 293.2 ms |
| relational flip | 13 / 13 | 100.0% | 166.9 ms | 241.1 ms |
| action neuter | 22 / 35 | 62.9% | 137.3 ms | 330.3 ms |
| stub wipe | 38 / 38 | 100.0% | 41.0 ms | 84.7 ms |

Bisimulation over 233 edits (benign function, method, multi-function and module-constant edits, every injected fault, SWE-bench gold patches): the fast path — stitched tree, segment reuse, memory and disk cache — against a cold path with every memo cleared and no stitched tree, against a from-scratch analysis of the edited text, and against Gate C with every probe in scope: 0 divergence(s) in verdict, gate or invariant set.

Zero-shot trees never referenced by the benchmark (fastapi, tornado and scrapy as fresh shallow clones; the Martian online tree, Python and Rust). The two `stepcheck ci` failures are real broken imports in those trees (`maint/test/redbot/red_test.py` imports a symbol tornado removed; `etl/main.py` imports a name its target lacks).

| tree | files | LOC | cold init | stepcheck ci | hook Edit p50 | faults caught |
| --- | --- | --- | --- | --- | --- | --- |
| fastapi | 1,224 | 132,565 | 0.87 s | exit 0 in 3.50 s | 81.3 ms | 75.0% |
| tornado | 117 | 55,462 | 0.42 s | exit 1 in 1.20 s | 11.5 ms | 100.0% |
| scrapy | 543 | 111,640 | 0.54 s | exit 0 in 2.90 s | 32.7 ms | 75.0% |
| martian/online (py+rs) | 52 | 13,904 | 0.33 s | exit 1 in 0.80 s | 9.7 ms | 66.7% |

## 6. Head-to-Head Market Ablation & SWE-bench Verified Analysis

### 6.1 SWE-bench Verified Real-Patch Analysis (receipts/swebench_raw.json)
We analyzed **100** real-world bug-fix instances from princeton-nlp/SWE-bench_Verified across **2** repositories, spanning **126** touched Python files and **204** diff hunks (**47** module-parseable, **10** decorator additions).

### 6.2 3-Way Architectural Ablation (50 Turns, 6-Minute Cache-Cliff Cadence, 4 Injected Regressions)

| Metric (50-Turn Campaign, 4 Faults) | Vanilla Long-Context | Passive Static Repo Map | StepCheck Firewall |
| --- | ---: | ---: | ---: |
| 50-turn context tokens | 2,997,647 | 1,316,161 | **15,079** |
| Post-hoc debug/retry waste tokens (8 turns) | 479,616 | 210,584 | **0** |
| **Total billed input tokens** | 3,477,263 | 1,526,745 | **15,079** (-99.6% vs Vanilla, -99.0% vs Repo Map) |
| Net API cost (Claude Sonnet 4.6) | $10.43 | $4.58 | **$0.05** |
| Net API cost (Claude Opus 4.6) | $52.16 | $22.90 | **$0.23** |
| Signal-to-Noise Ratio (SNR) at Turn 1 | 36.94% | 11.85% | **43.61%** |
| Signal-to-Noise Ratio (SNR) at Turn 25 | 0.43% | 0.97% | **30.01%** |
| **Signal-to-Noise Ratio (SNR) at Turn 50** | 0.11% | 0.25% | **23.68%** (**215x** Vanilla attention density) |
| Pre-commit faults intercepted (Gates A/B/C) | 0/4 (0.0%) | 0/4 (0.0%) | **4/4 (100.0%)** |
| Silent omissions leaked to disk | 2 | 2 | **0** |
