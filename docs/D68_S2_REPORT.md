# D68 S2 -- P1 computed, stored and audited (shadow)

Plan: `docs/D68_IMPLEMENTATION_PLAN.md` section 3. ACCEPTANCE 5.116 (the gap), 5.118 (the stages).
Claims are tagged [R] read, [E] executed, [D] derived, [N] not established.

**What S2 is:** the relation between a proposal and the task it names is computed, stored with the
decision and audited. **It changes no decision**: no policy input reads it, and a test shows the same
proposal is decided identically whatever the relation. It is the measurement S7 needs, and the base S3
makes enforceable.

## 1. The DP-12 condition: does anything depend on the shape of `reviewer_hints`?

DP-12 was approved on a condition: if something validates or depends on the column's shape, the signal
goes in a new column (a migration); if not, it goes in a key of the existing one. Checked before any
code was written.

**In the code** [R] -- every reference to `reviewer_hints` outside `docs/`:

| where | what it does |
|---|---|
| `control_plane/api/function_api.py` `_decide` / `_record_decision` | writes `{"risk_hint", "possible_sensitive_data_hint"}` at the decision |
| `control_plane/api/approved_dispatch.py:192-203, 268` | reads the row, then `hints.get("risk_hint")` and `hints.get("possible_sensitive_data_hint")` -- by key, never the whole object, never its length |
| `control_plane/state/models.py:150` | the column, `JSONB`, no check |
| `tests/test_migrations_roundtrip.py:230` | that the column exists, nothing about its content |

**In the database** [E] (queried as the migration owner, 2026-10-19): on `action_proposals`, no trigger;
five check constraints (`dispatch_state`, `decision`, `pipeline_stage`, `decision_past_received`,
`abandoned_is_undecided`), none mentions the column; no index, view, policy or function body
mentions it; column grants are `INSERT/SELECT/UPDATE` for `cyberorch_app`, `SELECT` for `ui_reader`, and
none of the narrow reader roles (scheduler, reconciler) has it -- adding a key changes no grant.

**Result: clean.** The signal is stored as `reviewer_hints["plan_fit"]`, no migration. The check is
now a test (`test_nothing_in_the_database_depends_on_the_shape_of_reviewer_hints`), so the day
something does depend on the shape, it fails and DP-12 is decided again.

Two things that follow from reading it, for S3: the approval re-derivation takes the keys it knows and
ignores the rest, so the new key is inert there today (every existing approved-dispatch test, 34 of
them, ran with it present and passed); and the name `reviewer_hints` is now slightly off, since P1 is
not a reviewer's hint -- the key is documented in the code as "inputs recorded at the decision and
replayed at re-derivation".

## 2. What was built

* `control_plane/plan_fit/relation.py` (new): `compare` (pure) and `assess_task_relation` (one read of
  `tasks`, confined to the engagement by row-level security). Vocabulary: `matches_task`,
  `differs_from_task`, `task_not_live`, `no_task`, each with a closed set of sub-causes. A value or
  sub-cause outside the vocabulary cannot be constructed.
* `propose_action`, decide stage: after the resolvers, the task is read in the same short transaction
  and compared with the proposal's own identity -- computed by `_task_identity`, the function
  `create_task` uses, so the two cannot come from different rules. The result is stored with the
  decision in the same statement and written as one `plan_fit.assessed` audit event, by the call that
  wins the stage transition (so a retry does not write a second).
* `differs_from_task` records *why*: `different_target`, `different_action`,
  `different_action_and_target`, `task_target_not_canonical`, `proposal_target_not_canonical`, and
  **`same_action_target_inside_task_target`** -- a host or sub-network inside the task's network
  (DP-13). That last one is a sub-cause and nothing more: it is still `differs_from_task`.

## 3. Verification

* **Tests:** `tests/test_plan_fit_relation.py`, 34 tests: the comparison as a table (including the
  containment cases and their negatives: a host outside, a wider network, the same network under
  another action), a grid that proves the whole vocabulary is reachable and nothing else is, the
  real entry point for each relation, another engagement's task read as not found, a retried request
  is one event, **the same proposal decided identically with no task, a matching, a differing and a
  dead task, under an honest and a worried reviewer**, a DENY is assessed too, and the DP-12 check.
* **Mutations** (`scripts/mutations_d68.py`, 10, each run by `mutation_check.py`): every one valid
  (a target test red, none broken by the mutation itself): any live task matches; a finished task is
  live; no task counts as a match; another engagement's task is found; the containment cause removed;
  everything "inside"; the value not stored; stored under another key; not audited; **the relation
  fed into the decision's inputs** (the shadow property). Two entries were first INVALID and were
  repaired rather than accepted: two of them died of a `KeyError` in the test, which the runner
  files under "other" -- the tests now assert that the key is present, so absence is an assertion; one
  edit quoted a line with the wrong indentation.
* **CI:** `test` green on `d423aef` (the soak known-pattern commit) and on `4b87c1d` (this code).
  ruff clean. 3,497 tests collected (3,451 at D67 plus S1's and S2's).
* **Not run in full locally:** the machine was restarted while my own full-suite run was at about 20%
  (`uptime` at the next command: up 1 minute), so the run did not finish. The CI run of the same
  code is the full run (it also has the images this machine lacks). Stated rather than hidden.

## 4. What S2 found

1. **The foreign key on `tasks(task_id)` is global**, so a proposal can name another engagement's
   task and the insert is accepted. Asked afterwards whether P1's read sees such a task or row-level
   security hides it, and **run against the real database (2026-10-20)**: the P1 query returns no row in
   the other engagement's scope, one in the owner's scope, none with no scope set, and the row exists for
   a superuser -- *absent by row-level security*, not found-and-different. P1 reads it as
   `task_not_live / task_not_found` and the audit event carries no status. Not an isolation gap; pinned by
   two tests and two mutations; the convention behind it, and what it does and does not allow, are in
   design note section 13 and ACCEPTANCE 5.119 (not changed).
2. **A task whose target will not canonicalize** (the older audit test creates one with `target={}`)
   matches nothing by design ("a task nobody can reduce matches nothing", ADR_TASK_IDENTITY). Under
   P1 it is `differs_from_task / task_target_not_canonical` for every proposal that names it. That is
   the right fail-closed answer; it is also the kind of fixture S3's enforcement-on suite will surface.
3. `STAGE_OF_EVENT` (audit chain reconstruction) needed the new event type; added as `review`.

## 5. Not done, by design

No policy input, no rule, no switch (S3). Nothing reads `plan_fit` for a decision, so the replay in
`approved_dispatch` is not needed yet and is not written; it is the first item of S3 and 5.116 stays
open until it exists.
