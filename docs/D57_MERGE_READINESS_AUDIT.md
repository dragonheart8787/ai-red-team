# D57 — merge-readiness audit, `origin/main..` D52–D57

Same shape as D47 and D51: nothing assumed from a deliverable number; every claim below was
read from git, the CI history, the tree, or executed. Where the audit found something, it is
fixed in the same change and listed in §5.

## 1. What is being merged — from git

| | |
|---|---|
| `origin/main` (after `git fetch`) | `185208b` "Merge D49-D50 stage…" — the same commit as the D50/D51 merge, **verified, not assumed** |
| local `main` | `185208b` (identical) |
| merge base with the branch | `185208b` — the branch is strictly ahead; no divergence on `main` |
| branch tip before this audit | `377465f` (24 commits ahead) |
| diff against `main` before this audit | 83 files, +11 042 / −218 (36 added, 47 modified); 3 new migrations (`0013`–`0015`) |

**The real scope is D52 through D57, not "D42–D56".** D42–D50 and the D51 audit were already in
`185208b`. The 24 commits, oldest first, grouped by what they are:

| Group | Commits |
|---|---|
| D52 — discovery provenance | `8e8aa23`, `54d53a2` |
| D53 — onboarding skeleton, and its closeout | `a076964`; `d708117` (5.30), `178c9e1` (5.31), `f4c5ab2`; `4adf29e` (5.29), `5138666`, `ed9ab85` |
| D54 — policy boundary: 5.27, 5.35–5.37, 5.20 | `1e56603`; `d60fcbe` (5.36), `f8fe115` (5.35), `17c4a7c`; `2e1c705` (5.37), `55e9818`; `7f3dac5` (5.20), `79caab1`; `ed3bc1b`, `de3eb35` (5.20 follow-up) |
| D55 — Gitleaks through the skeleton | `030d973` |
| D56 — two skeleton gaps | `d133a96` |
| 5.48 and its closeout | `fbfe5b8`, `f6b8e61` (5.50), `377465f` (comment) |

## 2. CI, every commit

CI runs on each **push**; commits pushed together share the run of the pushed head. All 24 are
covered by a green run: 16 by a run on the commit itself (the tip `377465f` is run 136, green) and
8 by the run of the head they were pushed with (`d708117`, `178c9e1` → `f4c5ab2`; `4adf29e` →
`5138666`; `f8fe115`, `d60fcbe` → `17c4a7c`; `2e1c705` → `55e9818`; `7f3dac5` → `79caab1`;
`ed3bc1b` → `de3eb35`). An intermediate commit that was never pushed alone was therefore never
tested alone; each was a step in a series whose head passed.

**There is no red run in the range.** The whole branch history (129 completed runs read) has 23
non-success runs, all on commits that are already in `main` (checked: each is an ancestor of
`185208b`), and **every one has a later green run on a descendant commit** — none is open:

| Reds | Fixed by (first green descendant) |
|---|---|
| runs 63–68 (D31, D32 and fixes 1–4) | run 69 `cd72f5e` |
| 71, 72 (D34) | 73 `695305c` |
| 74, 75 (D35) | 76 `46326fc` |
| 77–81 (D36 stages) | 82 `360c88c` |
| 84 (D37) | 85 `34fb7f8` |
| 88 (D39) | 89 `e6f858f` |
| 97, 98 (D42 docs, design) | 99 `91ae7a6` |
| 101, 102 (D43) | 103 `ab2849a` |
| 111, 112 (D49) | 113 `203d8d6` |

Working tree clean, local and remote branch identical (`377465f`) at the start of the audit.

## 3. Documentation

**ACCEPTANCE 5.20–5.50, row by row** (each opened, not skimmed). 31 items: closed 9 (5.20, 5.25,
5.29, 5.30, 5.31, 5.35, 5.36, 5.37, 5.48); decided or recorded, not open work 4 (5.27, 5.33, 5.39,
5.41); open Class B 12 (5.21–5.24, 5.26, 5.28, 5.32, 5.34, 5.40, 5.45–5.47); open Class C 6 (5.38,
5.42–5.44, 5.49, 5.50). Plus 5.51, added by this audit. All 53 file/test/commit references in
those rows resolve (bare file names resolve to their directory; every `file::test` exists; every
hash is a real commit). Statuses were cross-read against the reports they cite
(`D54_POLICY_SNAPSHOT_FREEZE_DESIGN.md`, `D53_5_29_WEB_POST_BODY_ANALYSIS.md`,
`ADR_GITLEAKS.md`, `D55_SKELETON_FEEDBACK.md`, `ADR_CREDENTIAL_VAULT.md` §9). Found and fixed:

| Finding | Fix |
|---|---|
| **5.20's row contradicted itself**: began "Closed at D54 (built)" and ended "design note written, **not built** … seven decisions **awaiting yours**"; also a doubled "As recorded at D39" lead | stale tail removed; the D39 text kept, labelled as history |
| **D54 section intro was stale**: "5.20 has a design note and is **awaiting a decision before anything is built**" | rewritten: built; note and as-built record named |
| The Class-B narrative paragraph reads as a class list but indexes what each stage added or closed, newest first (it contains closed and Class C items) | labelled as a stage index; the class is per row in §3 |
| 5.1's row says "Open" while §4 says "closed at D25" | **not a defect, left alone**: the document states at its top that items are current *as of its close* and that the successor review holds the newer status (`ACCEPTANCE_MVP15_WEB_AGENT.md`: "closed there") |

**Status pointers in the ADRs** (every `Status:` line in `docs/` listed and read):

| Document | Was | Now |
|---|---|---|
| `ADR_GITLEAKS.md` | accepted (D55) | unchanged — correct |
| `ADR_DISCOVERY_SOURCE.md` | accepted and implemented (D20), refined at D52 | unchanged — correct |
| `ADR_BLOODHOUND_NEO4J.md` | "**investigation only**… no code until §5 confirmed", and "D42-5 **is being decided**" | final status first: decided and implemented D42–D50, **D42-5 = Postgres only, no Neo4j** (confirmed in `provenance/graph.py` and `D42_1_D42_6_DESIGN.md`); the D42-5 sentence corrected; original kept, labelled |
| `ADR_CREDENTIAL_VAULT.md` | "Investigation and design only", no status line | implemented D44, revised D50 (§7.11, §8), extended at the D53 closeout (§9) |
| *found beyond the four named:* `ADR_SEMGREP.md` | "investigation only, D43" | implemented D43, wired D45/D46, private repos D44 — with the six decisions *as implemented* |
| `ADR_CLASSIFICATION_INHERITANCE.md` | "**proposed, D25. Awaiting a decision**" | accepted and implemented, D25 step 2 (`4b0f1b5`); closes 5.1 |
| `D42_1_D42_6_DESIGN.md` | "design only. No code…" | implemented D42 (`91ae7a6`), driven through `propose_action` D45/D46 |
| `D55_SKELETON_FEEDBACK.md` | "report only" with a D56 note above | status line says "as written at D55; see the D56 update" |
| `ADR_GOAL_LAUNDERING.md`, `ADR_REVIEWER_BILLING.md`, `ADR_TASK_IDENTITY.md`, `D54_…DESIGN.md`, `D53_5_29_…` | — | read; accurate as they are |

Original status paragraphs were kept under a marker saying they describe the stage the document
was written in. (The ADR gate for new tools reads the *first* `Status:` line, which is now the
final one.)

**Skeleton documents against the skeleton as built (D55/D56):** `NEW_TOOL_ONBOARDING.md` and
`ADR_NEW_TOOL_TEMPLATE.md` already carried the D56 behaviour (the `NEEDS_DISPATCH` and
`KNOWN_CLASSIFICATION` checks, the action name as a decision). Three statements no longer matched
what D55 did, and are corrected: "*Enforced*" for the `tool_version` host-probe check (true only
for a `<slug>.Dockerfile` image — ACCEPTANCE 5.45); "prefer the Dockerfile route" with no mention
of the scratch route Gitleaks needed (5.44); the self-check "must need no target" (false for a tool
whose failure is a silent no-op). The template's "`code.scan` has none" injection statement is now
historical, and names the second, non-address carrier kind (5.46).

## 4. End-to-end coverage of what this round changed

| Changed | Driven through the real entry point? |
|---|---|
| `dispatch_code_scan` generalized (Gitleaks, Semgrep) | **Yes** — `test_gitleaks_e2e.py` and `test_code_scan_e2e.py`, `propose_action` → OPA → broker → real container → evidence → audit; the three suppression channels also through the pipeline (found by mutation: a helper that hard-coded the defence had let `FETCH_BARE = False` pass) |
| `fetch_repo(depth, bare)` | Yes, by the same tests (`file://` clones; a plain path ignores `--depth`, stated in ADR §7) |
| `dispatch_violations`, `classification_violations` | They *are* checks, run over all 8 registered actions and by `--check`; the probe calls the real `_dispatch_for_action`; negative controls replay the D55 case from the tree's own source; 14 mutations red (one equivalent) |
| `web.render` in `requires_known_classification` | Yes — `test_web_render_e2e.py`, D32's three cases through `propose_action`; every pre-existing `web.render` path registers its target `AUTHORITATIVE`, so none changed (suite unchanged by the rule) |
| **5.20 freeze / shared `_APPLICABLE` fragment** | **Was not** — verified on the loaded policy (`load_effective_policy`) and by a model over random histories, never as a *decision*. **Gap found; closed by `tests/test_baseline_freeze_e2e.py`** (§5) |
| **5.35 customer-scoped layers** | **Same gap** — closed in the same file |
| **5.37 `global_policy_admin`** | Roles and refusal at the database (`test_global_policy_admin.py`, `test_policy_grants.py`), the CLI by subprocess, the overlay crossing the freeze **now as a decision** (§5). Callers: see below |

**Callers aligned with the new models** (read from the tree, not recalled):

* *Global publish / retire* (5.37): the only code that publishes or retires a global layer is
  `scripts/manage_global_policy.py`, `live_run.py`, `d40_three_role.py` and the test helper — all
  on `global_policy_admin_scope`; `d45` publishes an *engagement-scoped* layer on the runtime role,
  which is still allowed. `layers.py` refuses a global layer on any other connection, and a test
  scans the tree for any other module naming the connection.
* *`create_engagement`* (5.20 follow-up): all eight live-run scripts publish a baseline before
  creating the engagement (an AST test orders them); the test session ensures a neutral one;
  `NoBaselinePublished` has its own tests.
* *Writers narrowed by migration 0013* (5.36): the only `UPDATE engagements` in production code set
  `status`, `kill_switch_engaged`, `updated_at`; the only `UPDATE policy_layers` sets `active`. Both
  are inside the granted columns; the catalogue test pins every role's privileges.
* **A state, recorded as 5.51:** `load_effective_policy` has no production caller — only seven
  `scripts/live_run/` harnesses, a read-only listing script and tests. The freeze lives in that
  function, so it reaches a decision only through whichever harness loads the policy; no production
  harness exists (the 5.28 shape). Not a defect. Re-verify when one is written.

## 5. Found by this audit, and what was done

1. **No test drove `propose_action` under a frozen engagement** (5.20, and 5.35's customer scoping):
   the D47/D51 shape — the layer verified on its own function, the decision never asserted.
   `tests/test_baseline_freeze_e2e.py` (4 tests, real `create_engagement`, real `propose_action`,
   each engagement's own `load_effective_policy`): a baseline published after the freeze does not
   change the decision while an engagement created after it follows it; an emergency overlay
   (written by `global_policy_admin`) crosses the freeze and retiring it restores the decision; a
   baseline retired after the freeze still governs the frozen engagement and not a later one; a
   customer layer governs only its customer. Actions are random tokens, because the shared
   development database can hold live baselines that already name any real action. Mutation-verified
   (the freeze clause dropped; the retired-baseline clause dropped: both red).
2. **Stale records**: §3's four fixes and the ADR status pointers.
3. **5.51 recorded.**

Nothing else needed changing; no production code was touched by this audit.

## 6. Scale

| | at `185208b` (last merge) | at this audit |
|---|---|---|
| tests passed | 1 004 (**re-verified**: 1 004 collected on a checkout of `185208b`; the D51 report says the same) | **1 430** (+426) |
| OPA tests | 44 / 44 (re-run on that checkout) | **51 / 51** (+7: four for `code.secrets`, three for `web.render`) |
| migrations | `0012` | `0015` (`0013` narrow grants, `0014` `global_policy_admin`, `0015` baseline freeze) |
| `ruff check .` | clean | clean |
| registered actions | 7 | 8 (`code.secrets`) |

Local full runs this session: 1 298 at the D54 close, 1 369 (D55), 1 423 (D56), 1 426 (5.48),
1 430 (this audit, 730 s). Two runs were discarded because PostgreSQL and then Docker had stopped in
the development container (691 and 93 errors, all "connection refused"); both were restarted and the
suite re-run in full before the numbers above were taken.

## 7. For whoever deploys this

* Apply migrations `0013`–`0015`. `scripts/init_db.sh` creates the `global_policy_admin` role and
  its URL (`GLOBAL_POLICY_ADMIN_DATABASE_URL`); give that URL only to the operator's environment
  (ACCEPTANCE 5.37 states the limit).
* A global baseline must exist **before** an engagement is created: `create_engagement` now refuses
  (`NoBaselinePublished`) rather than freeze an empty one. `scripts/manage_global_policy.py publish`.
* `web.render` now needs a classified target; an unclassified one goes to a human.
* Open at merge, all recorded: 5.21–5.24, 5.26, 5.28, 5.32, 5.34, 5.38, 5.40, 5.42–5.47, 5.49–5.51.
  The D40 three-role harness has not been run against the `web.render` rule (5.50) — the first
  step of its next run is stated in the ACCEPTANCE row and at the top of the script.
