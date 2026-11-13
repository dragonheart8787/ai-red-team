# D69 -- Implementation plan: the production harness (the proposing side)

**Status: plan only. Nothing here is built, and this document authorizes none of it** (section 12). It turns
`docs/D69_PRODUCTION_HARNESS_DESIGN.md` (design checkpoint; its "chosen" lines were made by the review layer under
the owner's standing delegation and the owner may veto each) into independent stages. Written 2026-10-28.

Tags: **[R]** read in code or a document (place named); **[E]** executed (by me, in this session); **[D]** derived,
not observed, never to be quoted as fact; **[N]** not established. This note ran nothing against a database, a
daemon, a model or nmap, so it holds no [E] about the system; the only runs were the two document tests named in the commit report.
"Pending the owner" (待負責人) marks what this plan does not decide.

Standing rules this plan keeps: a call stopped by the service's safety classifier is a failure, recorded and
fail-closed, never re-asked; nothing here rewords a prompt, a goal or an input to lower a failure rate; no switch
(`task_relation_enforce`, `goal_fit_enforce`) is opened, no layer published, no registered file touched.

## How this plan follows `D68_IMPLEMENTATION_PLAN.md`

I read the D68 plan's section 0 (the table of stages: one deliverable each, "none changes a decision until stage 8",
the default stays off, "Every stage ends the same way"), section 1 (choices the plan needs from the owner, each with
options), the per-stage shape of sections 2 and 3 (pieces, why first, verification, tests and mutations, ACCEPTANCE
row, "confirm-in-build items [N]"), and sections 9, 10 and 11 (risks, honest sizing, what the plan does not do) [R].
Kept here: the stage table with a "changes a decision?" column; owner choices up front; per-stage tests, mutation
entries and an ACCEPTANCE note; every stage ends with the full suite, the OPA tests, that stage's mutations, the
ACCEPTANCE numbering test and CI green on the branch tip; one pytest session at a time. Changed: stages are named
**H1-H8** (H for harness) so they cannot be confused with D68's S1-S8; each stage also states what it does **not**
do and how it stops on failure, because the harness is the first resident component that reaches a model and a
container in one loop.

## 0. The stages

Eight stages. Each is one deliverable with its own commit(s), tests, mutation entries and ACCEPTANCE note. **None
changes a decision of the existing pipeline; both enforcement switches stay off throughout** (the harness never
sets, publishes or asks for one: design section 8, rules of the harness [R]).

| # | Stage | Touches | Calls a model / needs a DB or Docker? | Depends on |
|---|---|---|---|---|
| **H1** | Pre-checks: what only reading (and one owner choice) can settle | `docs/` only | no / no | -- |
| **H2** | The action allowlist: filtered candidate lists, three refusal points, tests with the real `_to_proposal` and `_to_tasks` | new harness module, `tests/` | no / test database only | H1 (module location) |
| **H3** | The nmap `Observation` builder | new harness module, `tests/` | no / test database only | H1 (role), H2 |
| **H4** | Task source: Supervisor plan to `create_task`, with the harness's own prefix check | new harness module, `tests/` | no (scripted Supervisor) / test database | H2 |
| **H5** | The proposing loop skeleton (own lock, own enrolment list, stop codes, caps, banner, signals, idempotency key) | new harness module, `scripts/`, possibly a migration | no (scripted roles) / test database; Docker only through fakes | H2, H3, H4 |
| **H6** | The operating description, with the kill limits stated as they are | `docs/` only | no / no | H5 |
| **H7** | Laboratory end to end with scripted roles; the re-verification of ACCEPTANCE 5.28 | `tests/`, `scripts/` | no / database and Docker lab | H3, H5 |
| **H8** | Draft of the shadow pre-registration (fields only, every value empty, no threshold) | `docs/` only | no / no | H6, H7 |

Order that works with one pair of hands: H1 -> H2 -> H3 -> H4 -> H5 -> H6 -> H7 -> H8. Reasons [D]: H1 first because
two of its answers (the database role, the module's location) are inputs of everything after it and one of them
may change what H3 can read; H2 before H3 and H4 because the filter is the property the whole credential-exclusion
argument rests on (design D69-6) and it can be proved with no database role question open; H3 before H5 because the
builder is the new, risky part (5.28) and the loop should be written against a builder that already has its tests;
H4 before H5 so the loop is written against the real task-creation path; H6 after H5 because the operator text must
describe what H5 actually does; H7 last of the code stages because it needs all of them; H8 last because it can
only be registered once the pieces exist (section 10). H2 and H3 do not depend on each other and can swap. H6 can
run beside H5 if the text is revised afterwards.

Every stage ends the same way (section 9): the full suite, the OPA tests, the mutation entries of that stage, the
ACCEPTANCE numbering test, CI green on the branch tip with the enforced count line quoted.

**Sizing, honestly [D].** No measured sizes. From the shape: H1 and H6 and H8 are documents; H2 a few hundred lines
of module plus tests; H3 the largest new logic (reading three tables and one file, a conversion, and the escaped-form
correspondence) with the most tests and mutations; H4 small; H5 the largest in code and in tests (a resident loop,
a lock, stop codes, an enrolment list); H7 mostly tests and a lab script. If one number is wanted: H3 and H5 carry
the risk.

## 1. Choices this plan needs from the owner (not decided here)

The design's "chosen" lines are inherited as they stand and may be vetoed [R: design section 0 note and each chosen
line]. These are what the design did not settle and a stage cannot start without. All are **pending the owner**.

| # | Question | Needed by | Options | Cost / note |
|---|---|---|---|---|
| **P-1** | Which database role does the harness connect as? | H1, H3, H5 | (a) the runtime role `cyberorch_app` (what `d40` uses through `engagement_scope`); (b) a new narrow role for the harness, as D62 made `scheduler_reader` for the scheduler | (a) needs no migration and has SELECT on the tables H3 reads under per-engagement row-level security [R: design section 3, check G]; (b) is safer by construction and costs a migration, a grant test and an operator step [D] |
| **P-2** | Where does the harness code live? | H2 | a package of its own under `control_plane/`; under `agents/`; under `scripts/` | D62's fence says no module under `agents/` or `tool_gateway/` imports `control_plane.scheduler` [R: `D62_SCHEDULER_V0_DESIGN.md` section 4, rule 5]; the harness needs both `agents` (Worker, Supervisor) and `control_plane` (function API), so any choice needs its own import-direction test [D] |
| **P-3** | Where is the harness's own enrolment list stored (D69-1b chose "its own list")? | H5 | (a) a table with its own writer role and an operator CLI, like `scheduler_enrollment` (migration, round-trip test, grant test); (b) a file the operator passes to the command | (a) is auditable and survives restarts and costs a migration stage (H5b below); (b) has no audit trail [D] |
| **P-4** | The rule for `code.scan`, `code.secrets` and for `web.*` | after H7 | v0 proposes only `network.scan` and `network.recon` (D69-6 A', chosen); the `code.*` Observation rule is **[N]** because the two views name no repository (design section 3, check C) | not part of H1-H8 |
| **P-5** | Where do mutation entries live and how are they named | H2 | follow D68: `scripts/mutations_d69.py`, ids `D69-H<stage>-<n>` | a name only; provisional [D] |
| **P-6** | Source of the nmap view fixtures for H3's tests | H3 | (a) hand-written stdout strings fed to the real `nmap.derive_view` (a pure function); (b) a recorded run | no CIDR `-Pn` stdout is stored anywhere in the repository [R: design section 3, check B], so (a) means the fixtures are constructed, not recorded, and must say so in the tests; (b) needs a run of nmap, which this plan does not authorize |
| **P-7** | Does H7 include a soak run with the harness inside (design acceptance 11.10)? | H7 | yes, a separate stage H7b that changes the soak driver; or no, left to a later plan | H7b touches `scripts/soak/` and a 4-hour runner [D]; not included below |
| **P-8** | Which evidence rows, and how much of their content, become a task's `Observation`, and the character ceiling applied to that content | H3, H5 | not chosen; see "P-8" below for the read-only facts | not part of H1-H8's chosen lines; a value, if any, is registered before the first non-test run and not adjusted from data [D] |

### Chosen by the review layer

[2026-10-29 review layer, under the owner's standing delegation; the owner may veto] The P-1..P-7 table above and
its "All are pending the owner" sentence are unchanged by this subsection. Where an item below names a check it
depends on, the choice holds only as long as that check continues to say what it says now; if a later stage's own
reading disagrees, the item reverts to pending the owner rather than being argued around.

* [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **P-1 (a):** keep
  `cyberorch_app`. Verification D (read-only, this round) found that `create_task`, `claim_task`, `complete_task`,
  `propose_action` and `load_effective_policy` each take a `Connection` and choose no role themselves
  [R: `control_plane/api/function_api.py:167-169, 235, 268-270, 510-529`; `control_plane/policy/layers.py:638-640`];
  every production call site binds them through `engagement_scope`, which opens as `cyberorch_app`
  [R: `control_plane/state/db.py:356-361`]. `cyberorch_app` holds INSERT/SELECT (and, on most tables,
  UPDATE/DELETE) on all public tables by grant [R: `db/migrations/versions/0001_core_schema.py:410-417`], while
  `scheduler_reader` is described as "the scheduling decision's inputs, SELECT only"
  [R: `control_plane/state/db.py:99-100, 203-204`] -- too narrow for the three writers among these five functions.
  This choice holds only as long as H1's own reading (item 1, P-1) confirms the same at build time; if H1 finds a
  write path that needs more than `cyberorch_app`'s grants, this reverts to pending the owner.
* [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **P-1, a note on cost:**
  verification D (the prior round) is what showed all five functions take a bare `Connection` and every
  production call site is `cyberorch_app`; that is a fact about today's code, not a cost of the choice. The cost
  is this: the proposing side (this harness) and the dispatching side (already-approved execution, through
  `dispatch_approved`) would then share one database role with no role-level separation between them -- a defect
  in either side's queries reaches the same grants as the other's. P-1 (a) still stands on verification D; the
  separation, if wanted, is a P-1 (b) the owner can still choose.
* [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **P-2:** a new top-level
  package `harness/`, with its own import-direction test in the style of the existing one
  [R: `tests/test_scheduler_structure.py:129-135`,
  `test_nothing_the_agents_or_tools_run_can_import_the_scheduler`]: `harness/` may import `agents.*` and
  `control_plane`'s function API; no module under `agents/` or `control_plane/` may import `harness`.
  Verification E (read-only, this round) found no existing fence between `agents/` and `control_plane/` as wholes
  -- `control_plane` imports `agents.base_agent` in five non-test files
  [R: `control_plane/api/approved_dispatch.py:53`, `control_plane/api/function_api.py:68`,
  `control_plane/plan_fit/goal_fit.py:29`, `control_plane/plan_fit/relation.py:51`,
  `control_plane/plan_fit/shadow.py:24`] and `agents` imports `control_plane.config`,
  `control_plane.plan_fit.*`, `control_plane.canonicalizer.*` and `control_plane.orchestrator.git_fetch` in five
  non-test files [R: `agents/fake/fake_plan_fit.py:18`, `agents/llm/plan_fit_base.py:48`,
  `agents/llm/plan_fit_validators.py:32-33`, `agents/llm/policy_reviewer.py:56`,
  `agents/llm/worker_base.py:68-74`] -- so this is a new, harness-specific rule, not a generalization of one
  already enforced, and it does not ask the existing agents/tool_gateway -> `control_plane.scheduler` fence to
  change. If H2's own import-direction test cannot be written without touching an existing import, this reverts to
  pending the owner.
* [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **P-2, a correction:** the
  P-2 row's own premise -- "D62's fence says no module under `agents/` or `tool_gateway/` imports
  `control_plane.scheduler`" -- was read above as implying a one-directional relationship between `agents` and
  `control_plane` as wholes. Verification E (this round) found that premise does not hold: `control_plane` imports
  `agents.base_agent` in five non-test files and `agents` imports several `control_plane` submodules in five
  non-test files (both lists cited above), each direction already present today. Read strictly, this is exactly
  the condition this subsection itself names -- "if a later stage's own reading disagrees, the item reverts to
  pending the owner" -- so P-2's choice does not stand on that premise as first written. It is kept here only on a
  narrower ground: no existing module imports a package named `harness`, and the existing fence names only
  `control_plane.scheduler`, not `control_plane` as a whole, so a harness-specific import-direction test (`harness`
  may import `agents`/`control_plane`; neither may import `harness`) does not contradict anything verification E
  read. **This narrower ground is offered, not decided: the owner's explicit confirmation or veto is needed before
  H2 relies on it.**
* [2026-10-30 review layer, under the owner's standing delegation; the owner may veto] **P-2 remains
  unconfirmed.** The owner has not yet confirmed or vetoed the narrower ground above. **H1 does not depend on
  it** -- P-2 is needed only by H2 (see the table), not by anything H1 does. **H2 does not start until the owner
  confirms or vetoes it.**
* [2026-11-04 review layer, under the owner's standing delegation; the owner may veto] **P-2: still no answer as
  of today.** The owner has not replied to the narrower ground offered on 2026-10-30, so **H2 does not start**.
  Nothing in this round depends on it: the chosen lines dated 2026-11-04 are about H5's start-up order, and H1's
  report is already written.
* [2026-11-06 the owner's reply, one word, '同意', to the review layer's recommendation] P-2 is confirmed as
  recommended: a new top-level package `harness/` on the narrower ground already recorded (no existing module
  imports a package named `harness`; the existing fence names only `control_plane.scheduler`, not `control_plane`
  as a whole). `harness/` may import `agents.*` and `control_plane`'s function API; nothing under `agents/` or
  `control_plane/` may import `harness`; `harness/` must not import `control_plane.scheduler`; each rule is
  pinned by an import-direction test. The condition recorded earlier stays: if H2's own import-direction test
  cannot be written without touching an existing import, P-2 reverts to pending the owner. This confirmation lets
  H2 be authorized; it does not start H2.
* [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **P-3 (a):** the enrolment
  table with its own operator CLI. H5 is written against a read interface for the enrolment list, with an
  in-memory fake used by every H5 test that is not H5b itself; H5b (the table, its migration, round-trip test and
  grant test) is completed before the loop is run outside a test.
* [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **P-5:** keep the plan's own
  provisional naming (`scripts/mutations_d69.py`, ids `D69-H<stage>-<n>`), unchanged.
* [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **P-6 (a):** hand-written
  stdout fed to the real `nmap.derive_view`; every such fixture is labelled in its test as constructed, not
  recorded.
* [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **P-7:** no H7b. The soak
  driver is not touched by this plan; a harness-inside-soak run is left to a later plan.
* [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **P-4** is not chosen here
  and stays exactly as the table above states it: pending the owner, outside H1-H8.

### P-8 (new; pending the owner -- not chosen)

[2026-10-29 review layer, under the owner's standing delegation; the owner may veto] Which evidence rows become a
task's `Observation`, and the character ceiling on the content handed to the Worker, are not decided here; P-8 in
the table above records only that the question exists. Facts from verification B (read-only, this round): the
production `query_evidence(conn, *, evidence_id)` takes a single `evidence_id` and returns `derived_view` only,
never the raw artifact [R: `control_plane/api/function_api.py:1181-1192`]; it has no notion of "an engagement's
evidence" or "evidence for a target" -- no production function that lists evidence by engagement or by target was
found [N: none found in this reading]. The `evidence_by_target` dict H3/H5 would need something like exists only
in the `d40` script, keyed by the target's identity value from that single run's own in-memory bookkeeping, not
read back from the database [R: `scripts/live_run/d40_three_role.py:444-449`]. `max_observation_chars` is a
script-only CLI flag, not a production setting, and defaults to `None` -- no truncation -- when not passed
[R: `scripts/live_run/d40_three_role.py:354, 368-369, 789`].

Options (none chosen): (a) one evidence row per task, by the `run_id` recorded on the task's own tool run -- no
column linking `tasks` to `tool_runs` was found in this reading [N], so this needs new state, not only new code;
[2026-10-30 review layer, under the owner's standing delegation; the owner may veto] correction (verification M,
read-only, this round): that "no column" finding holds only for a task's *input* evidence (what the Supervisor was
shown before the task existed). The evidence a task's own execution *produces* has a real path -- `action_proposals.task_id`
then `tool_runs.proposal_id` [R: `control_plane/state/models.py:115-135` (`task_id` at line 119),
`control_plane/state/models.py:205-222` (`proposal_id` at line 209)] -- a two-hop join, not a column on `tasks`
itself, but a path that exists, unlike the input side.
(b) every evidence row for the engagement whose target matches the task's target, read fresh each round -- needs
the engagement-listing function verification B found missing, and its selection rule would need the same care
D69-3a already gives the nmap builder; (c) no truncation, as the `d40` script defaults to -- fail-open by size, an
uncapped derived view reaching the Worker; (d) a fixed character ceiling applied identically on both sides of the
Worker boundary (the content given to the Worker and the content `_discovery_provenance` compares) -- fail-closed
by size, but a ceiling applied to only one side (as the `d40` script's own slice is, which trims only the copy
placed in `Observation.content` and not any comparison copy) risks exactly the kind of mismatch H3-c already tests
for. If a ceiling is chosen, its value is left blank here and is registered, the same way as the caps in H5
(D69-5d), before the first non-test run -- not adjusted from data afterward.

[2026-10-30 review layer, under the owner's standing delegation; the owner may veto] Terminology correction: in
this plan, "fail open" means a lure escapes the discovery escalation, not that something is merely large. The
decisive invariant is that the Supervisor, the Worker and `_discovery_provenance` use **the same string**, not the
size of that string on its own. Read in that sense, options (c) and (d) above are relabelled: no truncation at all
costs prompt length and approval volume, not safety by itself; it is a **one-sided** truncation -- the Supervisor,
a Worker's `Observation.content`, or the provenance comparison each getting its own cut of the same underlying
view -- that is the actual fail-open direction, because that is what can make the three disagree about what a row
said.

[2026-10-29 review layer, under the owner's standing delegation; the owner may veto] chosen principle: (i) the
observation set handed to provenance covers every evidence row that any role saw in producing the proposal; (ii)
the Supervisor and the Worker draw on one shared, bounded evidence window, and the Supervisor sees no more than the
provenance set; (iii) rows are all of the engagement's evidence, newest first, up to a cap, not only same-target
rows; (iv) the row count and the per-row character cap are [N], pending the owner, registered before the first run
and not adjusted from data. Reason [D]: provenance escalates only on a target named in the content of an
observation it is given, so a smaller set escalates less (fail open); the cost of the larger set is more untrusted
text in the prompt and more approvals (fail closed).

[2026-10-30 review layer, under the owner's standing delegation; the owner may veto] A further chosen line,
making the principle above concrete: (i) each round reads the evidence window **once**: all of the engagement's
evidence, newest first, up to a cap (the cap is **[N]**, registered before the first non-test run, not adjusted
from data). (ii) If a ceiling truncates that reading, truncation happens once, and the one resulting string is
used for all three of: the Supervisor's prompt, every Worker `Observation.content` built in that round, and the
`_discovery_provenance` comparison -- one string, three uses, not three cuts of the same view. (iii) A task's
Worker observation set must include the snapshot the Supervisor was shown when it created that task (the H3-g and
H4-4 mutation candidates above, restated here as a build rule, not only a test). (iv) The harness proposes only
for tasks it itself created in the current run; the snapshot it read to create them is kept in memory only. A
restart does not resume a task created before it -- that task is counted and reported, never claimed again. v0
does not persist the snapshot; persisting it is a later decision that needs a new schema (section 14). (v) v0's
Supervisor input carries no `findings` at all.

[2026-10-31 review layer, under the owner's standing delegation; the owner may veto] **Correction to (iv):
"never claimed again" is not implementable as written.** `claim_task` takes no `task_id` and no creator filter --
it claims whichever queued task the engagement has, by `priority DESC, created_at ASC`
[R: `control_plane/api/function_api.py:235-263`] -- so a restarted harness on an engagement it has used before
is **handed** the oldest queued task, including one its own previous run left behind; it cannot decline it at the
claim, and there is no function anywhere that returns a claimed task to `queued` (H1 report item 6: the only
`'queued'` occurrence in non-test code is the selection inside `claim_task` itself) [R]. Worse, `complete_task`
has no precondition at all -- no `status` check, no `owner_agent_id` check, `WHERE task_id = :tid` alone -- so a
process can close and overwrite the `result_summary` of a task it never claimed
[R: `control_plane/api/function_api.py:268-279`; H1 report item 6]. The sentence stands as the intent; the
mechanism for it is the chosen line immediately below.

[2026-10-31 review layer, under the owner's standing delegation; the owner may veto] **Chosen: the engagement is
the harness's alone, and a foreign task stops the service.** (i) In v0 the harness runs on an engagement with no
other task creator -- no other Supervisor, no operator-seeded task, no second harness. (ii) When the loop claims a
task whose id is not in this process's own in-memory set, it **stops immediately**, with its own exit code
distinct from the others (H5's code list): it does not propose for that task, does not complete it, does not try
to release it (nothing can), and reports it for a person. (iii) **Cost, stated plainly:** restarting on an
engagement that has already been used will always stop this way as long as one queued task is left over; recovery
is a new engagement or a person clearing the old one by hand, and **H6 must say so** in the operator text rather
than leave an operator to discover it. Reason [D]: fail closed. The alternative -- carrying on with a task whose
provenance snapshot this process never held -- would propose against evidence it cannot show the Worker, which is
the one thing P-8's chosen line exists to prevent; stopping instead of guessing is the same choice D69-5b already
made for a fault outside the closed list.

[2026-11-04 review layer, under the owner's standing delegation; the owner may veto] **Correction to the stop rule
above: stopping at the claim has already done damage, and the cost sentence was wrong.** By the time the loop sees
a foreign task's id, `claim_task` has already written it: `UPDATE tasks SET status = 'claimed', owner_agent_id =
:agent, lease_expires_at = now() + interval '5 minutes'` [R: `control_plane/api/function_api.py:235-263`; H1
report item 6]. So a harness that stops at that point leaves the task **`claimed`, owned by the harness, with a
five-minute lease and nobody to complete it** -- and nothing in the product returns it to `queued`
[R: same]. The consequence for restarts is the opposite of what was written: each restart claims and strands one
more leftover task, so the queue is **consumed one task per restart** and the Nth restart finds the queue empty
and proceeds. "Restarting on an engagement that has already been used will always stop this way as long as one
queued task is left over" is therefore **not true** [R]; the stop rule is still wanted, but only as a backstop
behind the check chosen immediately below.

[2026-11-04 review layer, under the owner's standing delegation; the owner may veto] **Chosen: a read-only
start-up check, before the first claim.** (i) Before claiming anything, the loop lists the engagement's tasks
read-only through `query_state(conn, engagement_id=..., task_status=("queued", "claimed", "running"))`, which
returns `status` and `owner_agent_id` per row and is confined to the engagement by row-level security on the
ordinary `cyberorch_app` connection [R: `control_plane/api/function_api.py:1248-1260` for the columns and the
status filter, `:1215-1222` for "Nothing here writes... Every row is confined to the current engagement by RLS",
`:137` `_LIVE_TASK_STATUSES = ("queued", "claimed", "running")`, `:1326-1328` for the checked status vocabulary].
(ii) Because the harness has created nothing yet at that moment, **any** row returned is foreign: the loop
**refuses to start**, with its own exit code distinct from the claim-time one, claims nothing, proposes nothing,
and reports the rows for a person. (iii) The claim-time stop rule above is kept as the backstop for a task that
appears after the check (another writer, or a race), accepting that by then the task is `claimed` and stranded.
(iv) **H6 must write the recovery down**: a new engagement, or a person clearing or completing the leftover tasks
by hand. Reason [D]: this moves the refusal to before the only write that cannot be undone, which is what makes
"fail closed" mean something here rather than merely stopping after the damage.

*Two limits of the chosen check, stated rather than glossed [R].* `query_tasks` is **not** the function for this:
it matches only on the identity key `(action, canonical target)` and needs an `action` and a `target` to ask
about, so it cannot answer "is there any live task" [R: `control_plane/api/function_api.py:1286-1319`]. And
`query_state`'s task page is capped -- `task_limit: int = 50` by default, `LIMIT :limit`, ordered
`created_at ASC` [R: `:1200`, `:1248-1260`] -- so the check must pass a limit it has chosen and treat a full page
as "found something", never as "that was all of them".

[2026-11-06 review layer, under the owner's standing delegation; the owner may veto] **Scope of the start-up
check: per engagement, not per process.** The loop serves several enrolled engagements serially, and an
engagement can be enrolled after the process started. The check therefore runs before the first claim **for each
engagement**, including one enrolled later, not once at process start. A check done once at start leaves a
later-enrolled engagement's leftover live tasks to be claimed, which is the fail-open direction. Reason [D]: the
harm the check exists to prevent is the claim, and the claim happens per engagement.

[2026-11-04 review layer, under the owner's standing delegation; the owner may veto] **Three more mutation
candidates** (names provisional, not yet in a catalogue): **H5-12** the start-up check is removed altogether -> a
test that seeds one queued task in the engagement and asserts the loop refuses to start, claiming nothing, must
fail; **H5-13** the claim-time backstop is removed while the start-up check stays -> a test that makes a task
appear between the check and the claim and asserts the loop stops without proposing must fail; **H5-14** the
start-up check runs **after** the first claim instead of before it -> a test asserting no `tasks` row was written
(no row moved to `claimed`, no `owner_agent_id` set) when the loop refuses to start must fail. H5-14 is the one
that matters most: it is the ordering bug the correction above describes, and a check in the wrong place passes
H5-12's test while leaving the damage.

[2026-11-06 review layer, under the owner's standing delegation; the owner may veto] **Mutation candidate H5-15**
(name provisional): the start-up check runs only once at process start and not before the first claim of each
engagement -> a test that enrolls a second engagement holding one queued task after the process started, and
asserts the loop refuses that engagement and claims nothing in it, must fail.

[2026-11-07 review layer, under the owner's standing delegation; the owner may veto] **Mutation candidate H5-16** (name
provisional; mirrored here from the H2 record in section 3, where it was first written down): the wrapper
`harness/registry_view.candidates_from_registry` returns the registry's scope objects without the allowlist filter
-> a test that reads the real registry of the test database through the wrapper, and asserts the candidates it
returns carry only allowed actions, must fail. H2 left that wrapper untested, which is why this belongs to H5.

[2026-10-31 review layer, under the owner's standing delegation; the owner may veto] **Chosen: `result_summary`
carries closed-vocabulary text only.** What the harness writes through `complete_task` is assembled from a fixed
set of tokens (the decision, kernel-generated reason codes, and ids such as `proposal_id`, `run_id`,
`evidence_id`) and never from tool output, a model's words, or `ActionOutcome`'s free-text fields (`failure`,
anything carrying an adapter's or an exception's message). The reason this is a decision and not a detail: the
field returns to a model inside a region marked trustworthy -- `TaskRecord.result_summary` is exported by
`as_dict` and `build_prompt` places the whole task ledger in the **trusted** header, not inside `wrap_untrusted`
[R: `agents/llm/supervisor_base.py:128`, `:138`, `:445-449`; H1 report item 8]. Today's four non-test callers
already stay within that rule except `d17`'s hand-written ledger prose, and none copies tool or model text
[R: H1 report item 8]. **New mutation candidate H5-11** (name provisional, not yet in a catalogue):
`result_summary` is built with a free-text field of `ActionOutcome` folded in -> a test asserting every
`result_summary` the harness writes matches the closed vocabulary must fail.

On `tasks` and `decisions` (verification L, read-only, this round): `DecisionRecord`'s own docstring says its
fields are "canonical... or a kernel-generated constant" -- no free-text field exists on it
[R: `agents/llm/supervisor_base.py:144-155`]. `TaskRecord.goal` **is** free text
[R: `agents/llm/supervisor_base.py:113-129`, `goal` at line 124], but it is the platform's own ledger of a goal
someone wrote when calling `create_task`, not tool-derived content, and `build_prompt` places the whole task
ledger inside the trusted header, never inside `wrap_untrusted`
[R: `agents/llm/supervisor_base.py:445-449`, `task_ledger` at line 448] -- so `goal` does not reopen this
exposure on its own; a Supervisor that has already been steered by untrusted evidence into writing a misleading
`goal` is a separate risk this plan does not cover. Leaving `findings` out of v0's Supervisor input is this
round's actual choice, not a fact already true of the code: `FindingRecord.claim` is explicitly "tool-derived"
text placed inside the untrusted block [R: `agents/llm/supervisor_base.py:167-176`, the docstring at line 169],
and if the harness ever did carry findings, there is today no production writer of one at all -- `query_findings`
is the only production function that touches the table, and the only code that ever inserts a row is raw SQL in
two scripts, one of which says so outright: "There is no finding-writing component yet -- nothing in the control
plane creates one" [R: `scripts/live_run/d17_supervisor.py:195-215`, the sentence at lines 199-200], and the other
builds `claim` from a `derived_view` excerpt plus the Reviewer's own flagged words [R: `scripts/live_run/d40_three_role.py:314-342`,
the `claim` assembly at lines 327-330].

**Reason [D].** The window is sliding and capped; a row the Supervisor saw that the Worker's own window has since
dropped can carry a lure `_discovery_provenance` no longer has to compare against, silencing the discovery
escalation -- fail open in the sense corrected above. **Cost.** A restart discards tasks already created and not
yet claimed (wasted work, not a security cost); a shared, larger window and one string used three ways over it
cost more approvals and a longer prompt -- the fail-closed direction.

## 2. H1 -- pre-checks

**Goal.** Close the [N] items of design D69-3a that reading can close, and obtain P-1 and P-2 from the owner. Output:
a short report (`docs/D69_H1_REPORT.md`, name provisional) with each item tagged.

**Does not.** Connect to a database, start Docker, run nmap, call a model, or change anything but the report.

**Items.**
1. The harness's database role (P-1) and, once chosen, its grants on `tool_runs`, `evidence`, `action_proposals`,
   `capabilities` read from the migrations only [R].
2. Whether that role's process can read the evidence store's files: read `control_plane/evidence/store.py` for the
   root and the directory/file modes it creates, and the deployment's expected user [N: modes of an existing store
   cannot be read without looking at a store].
3. Whether `network.scan` accepts an fqdn target end to end through `propose_action` [N]; reading can settle only the
   code path from `_decide` to `build_plan`; an actual run needs separate authorization.
4. Whether under `-Pn` nmap prints a scan report for every address of a CIDR [N]. Reading cannot settle it (the manual
   page is not installed; no CIDR `-Pn` stdout is stored). **The v0 rule does not depend on it**: for connect and
   version scans the builder adds no host identity (design D69-3a FINAL [R]); the item is kept so the approval cost
   (design measurement 5) can be interpreted.
5. How an observed string carrying a port is handled under the `url` type [N]; read `normalize_target` for `url`
   (a read can settle it).

**Acceptance (executable, falsifiable).** Each item has a tag and a place; no item is tagged [R] without a quoted
line; `tests/test_acceptance_numbering.py` and `tests/test_rule_5_27_docs.py` pass with `--noconftest`; CI green.
**Refuted if** an item is tagged [R] and the quoted line does not say it.

**Mutations.** None (no code). **ACCEPTANCE.** No row changes; the report is cited by the H5 note.

**Risks / [N].** P-1 may stay open; then H3 and H5 cannot start. **How it stops.** If the owner does not choose P-1,
the stage ends with the report and nothing else moves.

[2026-10-31 review layer, under the owner's standing delegation; the owner may veto] **Items 6 to 10 were added
to H1 after the list above was written**, and H1's report is `docs/D69_H1_REPORT.md` (the name this section
already provisionally gave it). The five additions are: 6, `complete_task`'s preconditions and whether anything
requeues a claimed task; 7, where the Worker's prompt renders `task.goal` and whether the Worker sees any other
task's text; 8, what today's `complete_task` callers write as `result_summary` and where that field surfaces; 9,
the existing "new engagement per run" patterns and the steps and roles creating one takes; 10, `DockerSandbox()`'s
default image and where it is set. Their source is the corrections and chosen lines dated 2026-10-31 in section 1
(the "never claimed again" correction, the harness-only-engagement stop rule, the `result_summary` vocabulary) and
the laundering-path risk in section 11 -- each needed a fact H1's original five items did not cover. **H1 ending
does not start H2**: P-2 is still the owner's (section 1).

## 3. H2 -- the action allowlist

**Goal.** Make "the roles are offered only allowed actions" a property of the harness, with tests that do not need a
model. Design D69-6 (A') [R]: v0 proposes only `network.scan` and `network.recon`; `ad.collect`, `code.*`, `web.*`
stay out; the harness never passes `credential_id`.

**Pieces [D].**
* A closed allowlist constant and a function that turns the registry's scope objects into `ScopeCandidate`s **with
  `allowed_actions` filtered by the allowlist**; a candidate left with no action is not offered. This replaces the
  unfiltered copy that every script does (`scripts/live_run/d40_three_role.py:273`, `d17_supervisor.py:187`, `d13_worker.py:386`,
  `d15_lookalike.py:324`, each a `ScopeCandidate(` construction) [R: design D69-6 facts].
* Two refusals beyond the filter: a Supervisor task whose action is outside the list is refused before `create_task`;
  a Worker proposal whose action is outside the list is refused before `propose_action` (design D69-6, three points) [R].
* The requirement of design D69-6 [R]: the candidate list is filtered when it is built and a test pins that.

**Tests.** With the **real** `BaseWorker._to_proposal(payload, candidates=...)` (`worker_base.py:661`) and
`BaseSupervisor._to_tasks(payload, candidates=...)` (`supervisor_base.py:481`), fed hand-built payload dicts (no
model; both take a dict [R]): (1) a payload naming an excluded action is refused (`WorkerRefusal` / `SupervisorRefusal`)
against the filtered candidates and passes against the unfiltered ones (the control that shows the filter is what
matters); (2) a payload naming an allowed action passes; (3) a candidate whose only actions are excluded is not
offered; (4) the two harness-side refusals count and do not retry. The fakes (`agents/fake/`) do not check candidates
[R: design check B], so no test relies on them for this property.

[2026-10-29 review layer, under the owner's standing delegation; the owner may veto] Test (4) above is written as
two tests, not one: (4a) a Supervisor task naming an excluded action is refused before `create_task` and counted,
exercising only H2-2; (4b) a Worker proposal naming an excluded action is refused before `propose_action` and
counted, exercising only H2-3. Removing either refusal then fails only its own test, not both, so the mutation
catalogue's claim that H2-2 and H2-3 each "make test (4) fail" is read as (4a) and (4b) respectively, not as one
shared test.

**Does not.** Add a loop, read a database, change the registry, or change what the registry authorizes (the filter
restricts what the roles may choose, not what is authorized [R: design D69-6 facts]).

[2026-11-06 review layer, under the owner's standing delegation; the owner may veto] H2 includes the
import-direction tests for P-2: (i) nothing under `agents/` or `control_plane/` imports `harness`; (ii)
`harness/` does not import `control_plane.scheduler`. Each needs a mutation candidate (H2-5, H2-6; names
provisional): a module under `agents/` or `control_plane/` that imports `harness` -> test (i) must fail; a module
under `harness/` that imports `control_plane.scheduler` -> test (ii) must fail.

**Acceptance.** All tests above green; the full suite; OPA tests; CI. **Refuted if** a payload with an excluded
action is accepted by `_to_proposal` or `_to_tasks` when given the harness's candidates.

**Mutation entries** (design acceptance 11.4: "the three refusal points each have a test that fails when removed")
[R/D]: **H2-1** the candidate builder copies `allowed_actions` unfiltered -> the test of (1) must fail; **H2-2** the
refusal before `create_task` removed -> test (4) must fail; **H2-3** the refusal before `propose_action` removed ->
test (4) must fail; **H2-4** a candidate left with no action is still offered -> test (3) must fail.

**ACCEPTANCE.** Updates the new D69 stage row (section 14); no existing row. **Risks / [N].** Fakes bypass; the
registry may hold scope objects whose actions are all excluded (the harness then has nothing to offer: it must say so
and stop for that engagement, which is H5's concern). **How it stops.** A failing control test (the filtered and
unfiltered candidates behave the same) means the premise is wrong: stop and report; do not continue to H3.

[2026-11-06 review layer, under the owner's standing delegation; the owner may veto] **H2 is built; this is its record.** Commit
`ff7762a2d5701c25a690c450c7595960b46c588d`, new files only -- `git diff --numstat` prints nothing for any existing
path. CI run #308 on that head is green, and its two counting lines are, verbatim:
`4542 passed, 24 warnings in 790.71s (0:13:10)` and `enforced: tests=4542 failures=0 errors=0 skipped=0`. The local
full suite on the same tree: 4518 passed, 0 failed, 24 errors -- the missing-image errors of the baseline, in the
baseline's own 2/16/4/2 split across `tests/scenarios/test_scenario_web_render.py` (2),
`tests/test_ad_collector_credential_delivery.py` (16), `tests/test_browser_escape.py` (4) and
`tests/test_dns_server_kernel_evidence.py` (2). New tests: 11. Mutations: D69-H2-1 to D69-H2-6, six valid, none
equivalent. OPA: 82/82, `opa fmt` clean. The three numbers agree: **4542 = 4518 + 24 = 4531 + 11**, and 4542 is the
number both CI lines carry. The six new files, with line counts and the sha256 of each file's content (recomputed
from the committed blobs, not copied from a report):
* `harness/__init__.py` -- 16 lines,
  `639d38c16a0ef1b8a9862777af0cc553f5def4c15a4a33c0911070cdf9d0a750`
* `harness/action_allowlist.py` -- 160 lines,
  `00ba44f4af0c680598005b52b60ef3545c9d9b36d76f61c9406c217923fdd0af`
* `harness/registry_view.py` -- 24 lines,
  `eff8fc94288ee71fbb5a2a49cb4c962f2959a693ffda6630c242aecc65581e0e`
* `tests/test_harness_action_allowlist.py` -- 271 lines,
  `e28f4704a9eefdd57b659d384f62fc42b1ab0ba8493c06b8c2b7588a1e4ecf93`
* `tests/test_harness_import_direction.py` -- 67 lines,
  `189f5e1f595dfb91db3cc3eda504898c15889f7e357cc3478d4f1f934fd4ff29`
* `scripts/mutations_d69.py` -- 123 lines,
  `86e260bd879aa7c6164850774f558661d9bf84be699300b88e0be218f5f5c7e2`

[2026-11-06 review layer, under the owner's standing delegation; the owner may veto] **P-2's retreat condition did not fire.** Both
import-direction tests were written without touching an existing import, or any other existing file:
`tests/test_harness_import_direction.py` reads imports with `ast` over `agents/`, `control_plane/` and `harness/`,
and the H2 commit's `git diff --numstat` has no output for any existing path. P-2 stands as confirmed; it does not
revert to pending the owner.

[2026-11-06 review layer, under the owner's standing delegation; the owner may veto] **What H2 does not prove.** Three things, written down so
that a later stage does not inherit them as settled:
* (a) the "not re-asked" half of tests (4a) and (4b) is true by construction rather than demonstrated. The test owns
  the loop that asks the role, so it cannot ask twice whatever the code does; no harness loop is exercised, because
  H2 has none. The claim is testable only where a loop exists -- H4 (mutation H4-2) and H5 (mutation H5-4) -- and it
  is those tests, not these, that would go red if a retry were ever added.
* (b) `harness/registry_view.candidates_from_registry` has no test. H2 covers the pure function it delegates to; the
  wrapper itself -- that what the real registry returns is what goes through the filter -- needs a database and
  belongs to H5, against the real registry in the test database. New mutation candidate **H5-16**: the wrapper
  returns the registry's scope objects without the filter -> a test must fail.
* (c) the packaging gap. `harness` imports only because pytest puts the repository root on `sys.path`;
  `pyproject.toml`'s `[tool.setuptools] packages` is an explicit list of `control_plane`, `agents` and
  `tool_gateway`, and does not name `harness` [R: H2 pre-check P4]. Nothing outside a test run can import the
  package from an installed copy. H5 must settle this before anything runs the harness outside pytest.

[2026-11-06 review layer, under the owner's standing delegation; the owner may veto] **Two more mutation entries for H2**, to be added in the
next code commit, which touches only `scripts/mutations_d69.py` and the tests and changes no behaviour: **H2-7** the
refusal counter does not check the reason code (the closed-vocabulary check in `RefusalCounter.record` removed) -> an
existing test must fail; **H2-8** a missing or non-string action is let through (the first branch of each check
removed) -> an existing test must fail. **Stop rule:** either one that no existing test catches is a gap in H2's
tests -- stop and report it; do not write a new test to cover the mutant up.

[2026-11-06 review layer, under the owner's standing delegation; the owner may veto] **One wording correction owed.** `harness/__init__.py`
says that each of the three import rules is pinned by a test in `tests/test_harness_import_direction.py`. Two are.
The third -- that `harness` *may* import `agents.*` and the control plane's function API -- is a permission, not a
rule a direction test can pin, and the test file's own docstring already says so. The correction is a comment-only
change in the next code commit; no code and no test changes.

[2026-11-07 review layer, under the owner's standing delegation; the owner may veto] **H2 follow-up, done.** Commit
`e4e388c5266a41bb887b949b58c273a53fcb0ad0`, two existing files and nothing else: `scripts/mutations_d69.py`
(27 insertions, 0 deletions) and `harness/__init__.py` (8 insertions, 4 deletions, all inside the module docstring;
with the docstring removed, `ast.dump` is `Module(body=[], type_ignores=[])` before and after). No test was added or
changed. The catalogue now holds nine entries and all nine are valid, each red on the test it names:
* **D69-H2-1** -> both control tests (and, as a by-product, the not-offered test);
* **D69-H2-2** -> `test_a_task_whose_action_is_outside_the_allowlist_is_refused_counted_and_not_re_asked`;
* **D69-H2-3** -> `test_a_proposal_whose_action_is_outside_the_allowlist_is_refused_counted_and_not_re_asked`;
* **D69-H2-4** -> `test_a_scope_object_whose_only_actions_are_excluded_is_not_offered_at_all`;
* **D69-H2-5** -> `test_nothing_under_agents_or_the_control_plane_imports_the_harness`;
* **D69-H2-6** -> `test_nothing_under_the_harness_imports_the_scheduler`;
* **D69-H2-7** -> `test_a_refusal_record_takes_a_reason_code_and_not_a_string_a_model_produced`
  (`Failed: DID NOT RAISE ValueError`);
* **D69-H2-8a** -> `test_both_checks_refuse_a_missing_action_and_each_refusal_is_counted_on_its_own_side`
  (`assert 'action_not_in_allowlist' == 'action_missing'`);
* **D69-H2-8b** -> the same test (`assert None == 'action_missing'`).

Local on that tree: the 11 harness tests pass; the full suite is 4518 passed, 0 failed, 24 errors in the baseline's
2/16/4/2 split; `opa test` 82/82, `opa fmt` clean, `ruff check .` clean; the six files were byte-identical before
and after the mutation run, with no probe file and no journal left, and nothing was committed during it. CI run
#310 on that head is green: `enforced: tests=4542 failures=0 errors=0 skipped=0` and
`4542 passed, 24 warnings in 803.33s (0:13:23)`. The three numbers are unchanged, because this commit adds no test:
**4542 = 4518 + 24 = 4531 + 11**.

[2026-11-07 review layer, under the owner's standing delegation; the owner may veto] **About the "N passed" lines quoted in
these records.** For runs #308, #309 and #310 alike, the quoted `N passed` line is the summary of the step "Run test
suite with task_relation enforcement ON", identified by its timestamp falling inside that step's window; the summary
of step 26, "Run test suite", lay outside the single log window each round was allowed to retrieve and is not
independently quoted. The two steps run the same tests, so the numbers are equal -- but what is recorded is one
reading of the enforced step plus that step's own `enforced:` count, not two independent readings.

[2026-11-07 review layer, under the owner's standing delegation; the owner may veto] **Correction to the 2026-11-06 description of
H2-8.** It read "a missing or non-string action is let through", which is not what removing the branch does: with
the branch gone such an action still fails the allowlist test and is refused, only under the other reason code.
That mutant is **H2-8a**, and the test catches it on the reason code
(`assert 'action_not_in_allowlist' == 'action_missing'`). Letting one through takes a branch that returns
`ActionCheck(allowed=True, reason=None)`, which is **H2-8b**. Both are in the catalogue, both are valid, and the two
behaviours are now distinguished instead of conflated.

[2026-11-07 review layer, under the owner's standing delegation; the owner may veto] The two things this section owed -- the extra
mutation entries and the docstring correction -- are done by commit `e4e388c`; no stop rule fired.

## 4. H3 -- the nmap Observation builder

**Goal.** The first production code that builds a Worker-side `Observation` from stored evidence (design: this
satisfies the 5.28 trigger as its precondition, not its closure) [R/D].

**The rule (design D69-3a FINAL, inherited, not changed) [R].** The builder puts into `observed_identities` an IP
literal from the nmap view's `hosts`, in the pipeline's canonical form, **only when the run was a ping scan (`-sn`)**;
for connect and version scans (which add `-Pn`, `nmap.py:218-222`) it adds no host identity from `hosts`; if the scan
type cannot be established from a stored field it adds none. Hostnames, ports and host:port forms are never included;
`observed_identities=(task target,)` as `d40` does is not carried over.

**Requirements (design D69-3a) [R].** (1) The scan type comes from `tool_runs.normalized_params->>'scan_type'`, reached
through `evidence.run_id`, never from `action_proposals.target`; NULL `run_id` or a missing row means unknown.
(2) The Worker sees `o.content` through `json.dumps` (`worker_base.py:645-653`); the provenance check compares the raw
`o.content` (`worker_base.py:573-576`); the two are not bit-for-bit the same, so the builder and its tests pin the
correspondence: every identity in the raw string stays recognisable in the form the Worker sees, and the comparison
does not miss one because of the escaping.

**Pieces [D].** A function from an evidence row (and its `tool_runs` row) to an `Observation` (`source`, `description`,
`content`, `evidence_id`, `run_id`, `observed_identities`); nothing else in H3.

**Tests.** Property tests with a **scripted** Worker, through the **real** builder and the **real**
`_discovery_provenance` (`worker_base.py:494`), with `derive_view` outputs as input (P-6: constructed from hand-written
stdout through the real `nmap.derive_view`, labelled as constructed). At least three view shapes (design D69-3b) [R]:
(a) IP literals only; (b) the "name (address)" form (the token `_HOST_LINE` captures is the name, `nmap.py:93`); (c) a
hostname lure appearing in `hosts`. Each crossed with the scan types ping / connect / version and with "unknown"
(run_id NULL; row missing). Database-backed cases create real `tool_runs` rows through the existing pipeline with a
fake sandbox (as `tests/test_pipeline_stages.py` and `tests/test_scheduler_skips.py` do [R]), including a case in which
the proposal asked for `ping` and the run was `connect`. Escaping cases: an identity with a backslash-escaped dot (the
nmap banner form `_norm_identity` undoes [R: `worker_base.py:304-319`]) and a non-ASCII character, checked in the raw
string and in the Worker-facing form.

**Does not.** Parse raw stdout per host (not adopted [R: design D69-3a FINAL]); handle `code.*`, `web.*`, `ad.collect`;
read anything for a fqdn-target scan beyond "unknown, adds none"; connect as any role other than the one P-1 names.

**Acceptance.** The property tests green; **refuted if** a lure host in `hosts` of a connect or version scan reaches
`observed_identities`, or the scan type is taken from the proposal's target, or an unknown scan type adds an identity.

**Mutation entries (design section 12, (a)-(f)) [R]**, each of which "must make some property test fail":
* **H3-a** the builder puts a hostname into `observed_identities` -> the hostname-lure case must fail;
* **H3-b** the builder puts `(task target,)` there -> the "follow-up not established" case must fail;
* **H3-c** the content given to the Worker and the content compared are not the same string (e.g. the builder
  stores a transformed `content`) -> the escaping-correspondence cases must fail;
* **H3-d** the builder takes `hosts` for a connect or version scan -> the connect/version cases must fail;
* **H3-e** the builder takes `hosts` when the scan type is unknown -> the NULL-`run_id` and missing-row cases must fail;
* **H3-f** the builder reads the scan type from the proposal's target -> the "asked ping, ran connect" case must fail.

**ACCEPTANCE.** Prepares the update of 5.28 (the row stays Open until H7). **Risks / [N].** P-1 (the role may not read
`tool_runs`); P-6 (fixtures constructed); whether a ping scan's `hosts` holds only responders is a [D] that design
measurement 7 is meant to check and H3 cannot (no run) **[N]**; whether the harness may read the raw artifact **[N]**
(not needed by the rule). **How it stops.** If the chosen role cannot read `tool_runs`, the builder cannot establish
the scan type and the FINAL rule makes it add nothing: stop and report to the owner rather than widen the rule.

[2026-10-29 review layer, under the owner's standing delegation; the owner may veto] Given verification F and G
(see the note at the end of H4): if the harness's own Supervisor input gives evidence content the same way `d17`'s
`build_state` does, H3's builder and H4's state-assembly read the same evidence, and H3's observation set for a
task must be built from the same evidence window the Supervisor saw for that task, not filtered down to the task's
own target alone -- a same-target filter would let through exactly the Supervisor-side exposure verification F and
G found. Two mutation candidates follow from this (names provisional, not yet in a catalogue): **H4-4** the
evidence given to the Supervisor is allowed to exceed what the Worker's observation set (and so
`_discovery_provenance`) covers for the resulting task -- a test asserting containment (every evidence row the
Supervisor saw for a task is in that task's observation set) must fail; **H3-g** the builder's row selection
filters evidence to the task's own target rather than the engagement's shared window -- a test built on
verification F/G's scenario (a lure named only in an evidence row for a *different* target the Supervisor was also
shown) must fail. Both are additions to H3's and H4's own mutation lists above, not replacements.

[2026-10-29 review layer, under the owner's standing delegation; the owner may veto] Verification B and I
(read-only, this round) found that getting from a task to the right evidence rows and their scan type needs new
reading code, not a reuse of what exists: `query_evidence` returns `derived_view` but not
`tool_runs.normalized_params`, so the scan type still needs a second, new read of `tool_runs` by `run_id`
[R: `control_plane/api/function_api.py:1181-1192`]; no non-test production code anywhere reads `normalized_params`
back out of `tool_runs` for this purpose -- the only production readers of `evidence`/`tool_runs` found are
single-row, by-id lookups inside `function_api.py`, `control_plane/audit/query.py` and
`control_plane/evidence/store.py`, none of which exposes `normalized_params` [R: see verification I].
**The harness must not rely only on the in-process `ActionOutcome.evidence_id` of the call that produced it**:
that value lives only in the caller's memory for that one call and is lost on a restart, and it is never populated
at all for a proposal whose evidence came from a `HUMAN_APPROVAL` the scheduler later dispatched (verification A,
H5's note) -- the harness was not the caller of that `dispatch_approved` call and holds no `ActionOutcome` for it.
H3 and H4 therefore need their own read, by task or by engagement, not a reuse of a call-scoped value.

[2026-11-08 review layer, under the owner's standing delegation; the owner may veto] **H3 is built; this is its record.** Commit
`29342ea6aed618db2c0f0f11d8d6b07cd005e7b8`: three new files and an append to the mutation catalogue, nothing else
that already existed (52 insertions, 0 deletions on `scripts/mutations_d69.py`).
* `harness/observations.py` -- 175 lines,
  `2546ddb75b38bcdd1d7613a2afa05085fed7c024374723fe0b33057090e22f2e`
* `tests/test_harness_observations.py` -- 303 lines,
  `ab3b4cbe68fccae5725ee93e08418eabaf62a4eb7dd246ac3c98ec468325ead8`
* `tests/test_harness_observations_db.py` -- 247 lines,
  `9ef19601ebaedf570a6c65c872d238f0768189bc223481de16763aea97614bad`
* `scripts/mutations_d69.py` -- 202 lines after the append,
  `0ed2eba0e24727ec91c1123c6977ce3b9d695053b10b55b908ec87184fdef344`

**Mutations: nine new, eighteen in the catalogue, all eighteen valid.** Each H3 entry is red on the test it names,
on an assertion: **H3-a** (a hostname kept as an identity) ->
`test_a_the_name_of_a_resolved_host_is_not_an_observed_identity`; **H3-b** (the requested target counted as
observed) -> `test_d_a_requested_target_with_no_responder_is_not_an_observed_identity`; **H3-c** (the content
transformed after it is built) -> `test_c_the_prompt_content_is_the_observation_content_byte_for_byte`; **H3-d**
(connect and version collected too) -> the `connect` and `version` cases of
`test_a_anything_but_the_exact_ping_value_observes_nothing` and of
`test_b_a_connect_or_version_run_observes_nothing_from_the_same_output`; **H3-e** (an unknown scan type collects)
-> the `missing` case of the first and `test_b_an_evidence_row_with_no_run_observes_nothing`; **H3-f** (the scan
type read from the proposal's target) -> `test_b_a_run_whose_scan_type_differs_from_the_request_observes_nothing`,
on `assert 'ping' == 'connect'`; **H3-g** (the window narrowed to one target) ->
`test_b_the_window_is_newest_first_and_the_limit_bounds_it`; **H3-h** (`source` carrying the requested target) ->
`test_e_source_and_description_carry_no_target_and_no_derived_text`; **H3-i** (an address used as nmap printed it)
-> `test_a_an_ipv6_address_is_canonicalized`. None was unexpressible, and none needed a parameter the production
code does not need. H3-a and H3-i are kept apart deliberately: H3-i drops the canonicalization altogether (so the
IPv6 case goes red as well), H3-a keeps it and only admits what is not an IP.

Local on that tree: 38 new tests (31 without a database, 7 with one), 49 harness tests in all; the full suite is
4556 passed, 0 failed, 24 errors in the baseline's own 2/16/4/2 split; `opa test` 82/82, `opa fmt` clean,
`ruff check .` clean; the nine files were byte-identical before and after the mutation runs, nothing was committed
during them, and no probe file or journal was left. CI run #312 on that head is green:
`enforced: tests=4580 failures=0 errors=0 skipped=0` and `4580 passed, 24 warnings in 727.90s (0:12:07)`, both
lines from the step "Run test suite with task_relation enforcement ON". The three numbers agree:
**4580 = 4556 + 24 = 4542 + 38**.

[2026-11-08 review layer, under the owner's standing delegation; the owner may veto] **What H3 does not prove.**
* (a) that a ping scan's `hosts` holds only responders is still **[D]**, not measured. No nmap was run in this
  stage and no CIDR ping-sweep output exists in the repository to use as a fixture (P-6), so every `derived_view`
  here came from hand-written stdout through the real `nmap.derive_view`, and each test says so. Section 14's
  item 7 is the row that carries this.
* (b) how much evidence a round may carry, and whether a single row's content needs a character ceiling, are the
  owner's and are not decided here. `read_evidence_window` takes a **required** `limit` with no default and
  refuses anything that is not a positive int, so no module quietly picks one; what the number should be is open.
* (c) "the proposal asked for ping, the run was connect" is **not producible through the real pipeline**:
  `execution_constraints` derives the capability's constraints from the proposal's stored target in one place, on
  the ALLOW path and after a human approval alike, and `tool_runs.normalized_params` is `NmapPlan.as_params()` of
  those same constraints (preflight P4). The divergence is therefore constructed with INSERTs on top of a real
  ping proposal, and marked as constructed where it happens. It is the case the rule exists for, so it is tested;
  it is not evidence that the pipeline can produce it.
* (d) that the Supervisor and the Worker read the same window and the same string belongs to H4, not to H3. H3
  establishes that the window is the engagement's and not one target's (H3-g), which is the half of that property
  the builder can carry; the containment between what a Supervisor saw and what a task's observation set covers is
  H4's, with H4-4 as its mutation.
* (e) nothing in the list was unexpressible, so there is nothing recorded under that head.

[2026-11-09 review layer, under the owner's standing delegation; the owner may veto] **H3 follow-up, done.** Commit
`d90c5e0f0296c2f40d7214c2b5356c9dc805ddee`, four existing files and nothing else: `harness/observations.py` (14
insertions, 7 deletions), `scripts/mutations_d69.py` (37, 1), `tests/test_harness_observations.py` (178, 1) and
`tests/test_harness_observations_db.py` (47, 0). The nine deletions are accounted for: the seven in
`observations.py` are the old docstring paragraph (six lines) and the old one-line `json.dumps` call (one); the one in
the mutation file is H3-c's Edit line, whose anchor named that call; the one in the test file is the single assertion
that expected the escaped spelling. 23 tests are new, 72 harness tests in all (61 in the two observation files):
* **T1** `test_content_is_the_derived_view_dumped_once_and_never_transformed` (1) -- the real property that the
  earlier "the prompt's content equals `observation.content`" test only appeared to hold (see (h) below);
* **T2** `test_b_an_evidence_row_pointing_at_another_engagements_run_has_no_scan_type` (1, database; the row is
  constructed);
* **T3** `test_the_ip_is_canonicalized_and_a_host_port_form_is_not_an_identity` (1);
* **T4** `test_a_hosts_value_that_is_not_a_list_of_addresses_observes_nothing` (6: int, dict, str, none, missing key,
  tuple);
* **T5** `test_t5_a_banner_that_names_a_host_in_these_spellings_introduces_it` (2: punycode, nmap's backslash form);
* **T6** `test_t6_a_refused_limit_is_refused_before_any_query_is_sent` (7), and its control
  `test_t6_a_valid_limit_sends_exactly_one_query` (1), which was not in the original authorization and was accepted
  afterwards;
* **T7** `test_t7_a_banner_naming_a_host_with_a_non_ascii_letter_introduces_it` (3: unicode spelling, punycode
  spelling, a host the banner never names);
* **T8** `test_t8_the_content_encodes_reads_back_and_is_what_the_prompt_carries` (1);
and one existing assertion in `test_c_the_prompt_content_is_the_observation_content_byte_for_byte` now expects the
character itself and not its escaped spelling. 1 + 1 + 1 + 6 + 2 + 7 + 1 + 3 + 1 = 23.

**Mutations: twenty-five in the catalogue, all twenty-five valid.** The new ones: **H3-j** (content lower-cased) and
**H3-k** (content cut at 200 characters) are red on T1, `AssertionError: stdout, as nmap prints it`, and on T8 (j) or on
test (c), both T5 cases and both non-control T7 cases (k); **H3-l** (no de-duplication) on
`test_a_a_repeated_address_is_kept_once_in_report_order`; **H3-m** (tool check removed) on
`test_f_a_row_from_another_tool_keeps_its_content_and_observes_nothing`; **H3-o** (type check on `hosts` removed) on
the `dict` case of T4 by assertion, the `int`, `none` and `missing key` cases dying with `TypeError`; **H3-n** (limit not
validated) and **H3-p** (back to the default encoding) are treated separately below. **H3-c**, **H3-j** and **H3-k** had
to be re-anchored: their anchor was the old one-line `json.dumps` call, which the change below rewrote, so they
reported "appears 0 times"; the anchor is now the new three-line call, with the same replacement as before appended to
it, and all three are red again (H3-c on test (c), T1 and T8).

Local on that tree: 4579 passed, 0 failed, 24 errors in the baseline's own 2/16/4/2 split; `opa test` 82/82, `opa fmt`
clean, `ruff check .` clean. CI run #314 on that head is green:
`enforced: tests=4603 failures=0 errors=0 skipped=0` and `4603 passed, 24 warnings in 807.08s (0:13:27)`, the second
from the step "Run test suite with task_relation enforcement ON" (its timestamp falls inside that step; step 26's
summary was not independently read, as recorded above). The three numbers agree: **4603 = 4579 + 24 = 4580 + 23**.
The message of commit `d90c5e0` shows the character itself in two places where it means the escape spelling of that
character (an escaping slip in how the message was typed); the diff is the record, and the message is not amended.

[2026-11-09 review layer, under the owner's standing delegation; the owner may veto] **Decision: `content` is `json.dumps(derived_view, sort_keys=True, default=str, ensure_ascii=False)`.** The
default encoding writes every non-ASCII character as a backslash-u escape, and `_discovery_provenance` matches against
the raw `content`; so a host a banner names with a non-ASCII letter was stored in escaped form and a proposal for it
was not found in it. Read off the real path, with the real `nmap.derive_view`, the real `observation_from_evidence`
and the real `_discovery_provenance`, `candidates` empty, `introduced_by_untrusted` for each pair, the stdout being
constructed (P-6):

```
Z2: content = observation.content (json.dumps default, ensure_ascii=True)
observation \ proposed target                | münchen.lure.example           | xn--mnchen-3ya.lure.example    | dc99.lure.example (control)
(i) visit münchen.lure.example               | False                          | False                          | False
(ii) visit xn--mnchen-3ya.lure.example       | True                           | True                           | False
(iii) visit dc99\\.lure\\.example            | False                          | False                          | True

Z3: content = json.dumps(derived_view, sort_keys=True, default=str, ensure_ascii=False)
observation \ proposed target                | münchen.lure.example           | xn--mnchen-3ya.lure.example    | dc99.lure.example (control)
(i) visit münchen.lure.example               | True                           | True                           | False
(ii) visit xn--mnchen-3ya.lure.example       | True                           | True                           | False
(iii) visit dc99\\.lure\\.example            | False                          | False                          | True

Z4: fragments of observation.content around munchen (the default encoding)
   penSSH 8.9 (visit m\u00fcnchen.lure.example)\nNmap done: 1 I
   non-ASCII characters in content: []
   contains literal ü: False | contains backslash-u00fc: True
```
(The `\\` in the third row label is how the probe's label was typed; the banner given to nmap held one backslash
before each dot.) The effect: under the default encoding row (i) is `False` against every target, including its own
spelling, and the one cell that was `True` for a non-ASCII target was the one where the *banner* was in punycode;
under `ensure_ascii=False` row (i) is `True` for its own spelling and for its punycode form, the control stays `False`,
and nothing changes for rows (ii) and (iii). The Worker prompt is unchanged in kind: `BaseWorker.build_prompt` escapes
the content a second time with its own `json.dumps`, so the model reads an escaped form, and what the prompt decodes to
is still `observation.content` (T8). The string H4 requires the Supervisor and the Worker to share is **this** string,
in this form, which is why the decision had to be taken before H4. T7 pins the three cells above that matter, T1 the
form, T8 the round trip, and H3-p (the argument removed again) is red on T1, T7 (both non-control cases) and T8.

[2026-11-09 review layer, under the owner's standing delegation; the owner may veto] **How H3-n was closed.** Its first form named the existing limit test, which passes `None` as the connection:
with the validation removed the code reached `conn.execute` and died with `AttributeError`, which the runner does not
count as an assertion, so it reported the entry invalid although the test was red. The runner was not loosened and
the existing test was not changed. T6 hands `read_evidence_window` a connection that records its use; with the
validation removed every refused value now gets through and the test fails on `DID NOT RAISE ValueError` (7 of 7), and
the entry names T6. The existing limit test stays in the suite and still goes red under the mutation, as an
`AttributeError`.

[2026-11-09 review layer, under the owner's standing delegation; the owner may veto] **Correction to the record of H3-i.** The description above says H3-i "drops the canonicalization altogether (so
the IPv6 case goes red as well), H3-a keeps it and only admits what is not an IP". That is incomplete: without
`normalize_ip` the helper `_canonical_ip` returns *any* string unchanged, so H3-i also opens the door to hostnames and
overlaps H3-a (the hostname test is red under H3-i too). And the canonicalization of an IPv4 address was not pinned
by any test on its own: every IPv4 fixture was already in canonical form, so only the IPv6 case could show it. T3
adds it (leading whitespace removed, `address:port` not an address); H3-i and H3-a are now both red on T3.

[2026-11-09 review layer, under the owner's standing delegation; the owner may veto] **What H3 does not prove, continued.**
* (f) rows written in one transaction share a `created_at`, so their order is decided by `evidence_id`, not by time;
  when `limit` cuts through such a group the subset that stays is reproducible but arbitrary.
* (g) an evidence row of one engagement may name a run of another: the foreign key `evidence.run_id` is not scoped by
  engagement, so the database does not stop such a row; only row-level security keeps the foreign run out of the join.
  The window then reads `scan_type` and `requested_target` as NULL and the row observes nothing (T2). The row's
  `run_id` field still carries the foreign run's id; this was recorded, not asserted.
* (h) the earlier test (c), "the content in the prompt equals `observation.content`", is true for *any* string that
  `build_prompt` is handed, so it could not have caught a content that had been changed on the way in. The real
  property is that `content` is the derived view dumped once, unchanged (T1).
* (i) the probes used constructed stdout. Whether a real nmap prints a non-ASCII byte as such or as a hexadecimal
  escape of the form `\xHH` is not verified **[N]**; if it is the latter, a stripping of backslashes would leave
  `xC3xBC`, which still would not match the name. That is a different channel from the one decided above, and it is
  not handled here.

[2026-11-09 review layer, under the owner's standing delegation; the owner may veto] **P-8's numbers are still the owner's.** The row ceiling of the evidence window and any per-row character
ceiling are still undecided. Nothing before H5's loop needs them; H4 takes the window size as a parameter and does not
pick one.

[2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **Probe Z5 (read-only, run in the H4 round before any file was written): the two Unicode spellings of one
name, as banner and as proposed target.** NFC is `m` + U+00FC + `nchen`, NFD is `mu` + U+0308 + `nchen`; the targets
are the NFC name, the NFD name and the punycode name; the banners are the NFC spelling, the NFD spelling and a control
that names `dc99.lure.example`. Each cell is `introduced_by_untrusted` from the real `_discovery_provenance` with
`candidates = ()`, over an `Observation` built by the real `observation_from_evidence` from the real
`nmap.derive_view` of constructed stdout (P-6). Output as run:
```
code points  NFC name: ['0x6d', '0xfc', '0x6e', '0x63', '0x68']
code points  NFD name: ['0x6d', '0x75', '0x308', '0x6e', '0x63', '0x68']

Z5b: introduced_by_untrusted (real _discovery_provenance, candidates = ())
observation \ proposed target      | fqdn NFC             | fqdn NFD             | fqdn xn--mnchen-3ya 
(i)   banner NFC  (u+00fc)         | True                 | True                 | True                
(ii)  banner NFD  (u + u+0308)     | True                 | True                 | True                
(iii) banner control dc99          | False                | False                | False               

Z5c: normalize_fqdn
  NFC input  'münchen.lure.example' -> 'xn--mnchen-3ya.lure.example'
  NFD input  'münchen.lure.example' -> 'xn--mnchen-3ya.lure.example'
  the two outputs are equal: True

Z5d: repr() of observation.content around "visit"
  (i)   banner NFC  (u+00fc)         '.9 (visit münchen.lure.example)\\nNma'
  (ii)  banner NFD  (u + u+0308)     '.9 (visit münchen.lure.example)\\nNm'
  (iii) banner control dc99          '.9 (visit dc99.lure.example)\\nNmap d'
  contents differ: True
  utf-8 bytes of the name region, NFC: b'm\xc3\xbcnch'  NFD: b'mu\xcc\x88nch'
  name as it sits inside content (utf-8), NFC: b'm\xc3\xbcnchen'
  name as it sits inside content (utf-8), NFD: b'mu\xcc\x88nchen'
```
In this probe NFC, NFD and punycode are all mutually detected (every banner that names the host, in any of the two
Unicode spellings, introduces every one of the three spellings of the target; the control banner introduces none), and
`normalize_fqdn` outputs the same punycode, `xn--mnchen-3ya.lure.example`, for both Unicode spellings, which is
why the cells agree. **Limits [N]:** only the `fqdn` type was covered, and only constructed stdout; NFKC
compatibility characters and other forms (full-width letters, ligatures, confusables, mixed-script names) were not
tried, so nothing is claimed about them.

## 5. H4 -- the task source

**Goal.** The Supervisor's plan becomes tasks through the product's `create_task`, with the harness's own check for a
prefix-less `cidr` (design D69-2a (A), D69-2b (1) [R]).

**Pieces [D].** (1) The input the Supervisor needs (`StateSummary`, the candidates of H2) built from `query_state`,
`query_findings`, `query_evidence` and the registry: today only scripts do this (`d17_supervisor.py:222`
`build_state`) [R]. (2) For each task the Supervisor returns: if its target is a `cidr` without a prefix length, the
task is refused, counted and recorded; no `create_task`, no re-ask, no retry with different wording [R: design
D69-2b]. (3) Allowed tasks go through `create_task`.

**Tests.** A **scripted** Supervisor (`agents/fake/fake_planner.py` takes `candidates` and ignores them [R]; the tests
that need the real `_to_tasks` use H2's payload method): a prefix-less cidr is refused and counted; a task with a
prefix passes; a bare address typed `ip` passes; a refused task leaves no `tasks` row; a Supervisor `None` or refusal
creates no task and is recorded as a failed call, **with no second call**; the `tasks` row carries `identity_key` and
the `task.created` audit event.

**Does not.** Change the Supervisor's schema, prompt or description (5.122 is closed on the producer side; the
canonicalizer's `/32` reading stays an open owner question there [R]); change `create_task`; decide whether to refuse a
prefix-less cidr inside `create_task` (design D69-2b (2): a separate decision).

**Acceptance.** Tests green; **refuted if** a prefix-less cidr task is created, or a refused or failed Supervisor call
is asked again.

**Mutation entries** [D]: **H4-1** the prefix check removed -> the prefix-less case must fail; **H4-2** a refused
task is re-asked of the Supervisor -> the "no second call" test must fail; **H4-3** the refusal not counted -> the
count assertion must fail.

**ACCEPTANCE.** Appends to 5.122 once built (design section 12, item 5): the harness-side prefix check; the
canonicalizer question stays open. **Risks / [N].** `build_state` is a script function whose production equivalent
is new code over `query_*`; `overlaps_with` and `status_assessment` instability (design D69-2a) are not addressed.
**How it stops.** A classifier stop on the Supervisor is one recorded failure; the round makes no tasks.

[2026-10-29 review layer, under the owner's standing delegation; the owner may veto] Verification F (read-only,
this round) found that the input H4 reads for the Supervisor is not evidence-free: `StateSummary.evidence` carries
`EvidenceRecord(evidence_id, tool, derived_view)` -- the full `derived_view` content, not only an id
[R: `agents/llm/supervisor_base.py:203-219`]; `build_state` fills it from `query_evidence` for a caller-given list
of `evidence_ids` [R: `scripts/live_run/d17_supervisor.py:222-238`]; `BaseSupervisor.build_prompt` places
`state.evidence` inside the same `wrap_untrusted(...)` block as the findings, i.e. the Supervisor is shown evidence
content as untrusted text, exactly as the Worker is [R: `agents/llm/supervisor_base.py:438-474`]. Verification G
(read-only, this round) found that nothing at the task layer checks for this the way the Worker's path does:
`_discovery_provenance` has exactly one production call site, inside the Worker's own proposal path
[R: `agents/llm/worker_base.py:746`]; neither `create_task` nor `BaseSupervisor._to_tasks` performs any check of
whether a task's `target_value` was introduced by untrusted content -- `create_task`'s body validates only overlap
and writes the row [R: `control_plane/api/function_api.py:167-227`], and `_to_tasks`'s checks are schema checks
(`scope_object_id`, `action`, `target_type`, `target_value` non-empty, `goal` non-empty, `priority`) with no
provenance step [R: `agents/llm/supervisor_base.py:481-560`]. **So a lure can enter through a Supervisor-created
task with no provenance check at the task layer; the only place introduced-by-untrusted is judged is the Worker's
observation set, which therefore must cover at least what the Supervisor was shown when it wrote the task's
target.** If H4's own evidence input is ever a strict superset of, or disjoint from, H3's observation set for the
same task, this exposure is not covered by H3's test suite; see the mutation candidates H4-4 and H3-g at the end
of H3 above.

[2026-10-30 review layer, under the owner's standing delegation; the owner may veto] Three more mutation
candidates, following from the P-8 chosen line above (names provisional, not yet in a catalogue): **H4-5** the
string truncated for the Supervisor's prompt and the string truncated for a Worker's `Observation.content`/
`_discovery_provenance` comparison are produced separately -- each side cutting its own copy, rather than one
string used three ways -- a test with a lure that falls inside one party's cut and outside another's must fail;
**H4-6** the harness's own Supervisor input is built with a non-empty `findings` list -- a test asserting
`StateSummary.findings == ()` for every call the harness makes must fail (this entry follows only because v0
chooses to omit `findings`, per the chosen line above; if that choice ever changes, this entry is retired, not
kept as a fossil); **H4-7** after a restart, the harness proposes again for a task it finds already created by an
earlier run -- a test that creates a task, restarts the in-memory snapshot as a fresh process, and asserts no
second proposal for that `task_id` must fail.

[2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **H4 as built.** Commit `411b5ef` (message "D69 H4: the task source (one snapshot per round, plan once,
filter, create)"), CI run #316, head `411b5ef7fa63c6e7bc09085be087d0e790e6a0ac`. Four new files and two changed:
* `harness/round_snapshot.py`, 100 lines, sha256 `1aa147b2aa936cb4e347e026e3270e15afbbcc7cac9d073c727c856b97df1982`;
* `harness/task_source.py`, 142 lines, sha256 `9e34e24f6850a4ff28fa053ad19dec31218f094460141538340c51549917ed98`;
* `tests/test_harness_task_source.py`, 617 lines, 31 tests (no database), sha256
  `0a8d566e0fa94f6b6c8ae60b6523aa6e6ccc5e0224d0f4ff9b36617da7122349`;
* `tests/test_harness_task_source_db.py`, 177 lines, 5 tests (test database), sha256
  `24a52ee0bd07a2c8f3d8e290bb4e9d377b695dbb104523da4be5cdcd3735c623`;
* `harness/action_allowlist.py` 163 lines, sha256 `f7156616f86ffa3c87bb0c4e0312435b5f21dff752d1d46e281a61fbf563e579`:
  three lines added (`REASON_CIDR_WITHOUT_PREFIX` and its addition to `REASON_CODES`), none removed;
* `scripts/mutations_d69.py` 307 lines, sha256 `b5cb7bb7ea35272045e59baff29c6463d7072ce359e4552c60ac3e106bd8a104`:
  69 lines appended at the end of `CATALOGUE`, none removed.

[2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **H4's tests.** No database (31): `test_a_the_snapshot_sends_one_query_when_taken_and_none_after`,
`test_a_the_snapshot_limit_is_required`; `test_b_everything_the_supervisor_sees_is_in_the_set_a_worker_is_judged_against`,
`test_b_the_supervisors_view_is_the_row_as_read_and_nothing_is_cut`,
`test_b_the_worker_set_is_the_whole_window_in_order_and_the_same_for_every_call`;
`test_c_a_task_on_a_host_only_another_scan_names_is_introduced_by_untrusted_text` (fqdn and ip),
`test_c_the_responder_of_the_sweep_is_established_and_is_not_introduced`; the two `test_d_` tests (findings always
empty; tasks and decisions default empty and are used as given); `test_e_a_plan_that_gives_nothing_is_asked_once_creates_nothing_and_records_a_code`
(None, refusal, failure), `test_e_the_failure_vocabulary_is_closed`, `test_e_a_plan_that_succeeds_has_no_failure_and_is_asked_once`,
`test_e_an_exception_other_than_a_refusal_is_not_swallowed`; `test_f_a_cidr_without_a_prefix_is_refused_and_counted_and_the_rest_pass`
(six cases: v4 and v6 without prefix, v4 and v6 with prefix, bare ip, fqdn),
`test_f_the_new_reason_is_in_the_closed_vocabulary_and_the_old_ones_are_kept_in_order`;
`test_g_an_action_outside_the_allowlist_is_refused_and_counted_by_the_check` (the unfiltered candidates let the real
`_to_tasks` pass the action first), `test_g_when_both_rules_apply_the_action_is_what_is_counted`;
`test_h_a_refused_task_does_not_affect_the_other_tasks_of_the_plan`;
`test_each_task_has_its_own_transaction_and_the_caller_supplies_created_by`;
`test_k_a_stand_in_create_task_that_raises_propagates_and_earlier_tasks_stay`;
`test_k2_a_task_whose_transaction_does_not_commit_is_not_in_the_ledger`;
`test_the_ledger_has_add_membership_and_a_read_only_view_and_loads_nothing`;
`test_m2_create_task_is_named_only_in_the_task_source_and_nothing_claims_proposes_or_completes`.
Database (5): `test_i_a_passing_task_has_a_row_an_identity_key_an_audit_event_and_a_ledger_id`,
`test_i_created_by_is_the_callers`, `test_j_a_refused_task_has_no_row_and_the_others_do`,
`test_k_an_exception_from_create_task_propagates_and_earlier_tasks_stay` (the failing input is a task whose `goal`
is `None`, which `create_task` inserts and `NOT NULL` refuses), `test_l_a_new_ledger_starts_empty_whatever_another_holds_and_the_database_holds`.
Test (m) is H2's two import-direction tests, run and passing, plus `test_m2_...` above. In the no-database file
`create_task` and `engagement_scope` are replaced by a recording stand-in (the request allowed either that or the test
database); the database file uses the real ones. Tests not asked for in any form: `test_k2_...`, `test_m2_...`, the
ledger test, the per-task-transaction test, the vocabulary tests of e and f, and `test_i_created_by_is_the_callers`.

[2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **Mutations: thirty-seven in the catalogue, all thirty-seven valid.** The twenty-five earlier ones were re-run
and are all valid, which includes H2's nine entries, seven of whose anchors are in the changed
`harness/action_allowlist.py`. The twelve new
ones, each red by an assertion on the test it names: **H4-1** the prefix check removed (test f, three cases and
test h); **H4-2** the Supervisor asked again after a planning failure (test e, `assert 2 == 1`); **H4-3** a task
refused for its action is not counted (test g); **H4-4** `observations_for_task` without its last row (tests b and c,
four failures); **H4-5** `supervisor_evidence` cuts the view (test b and test c); **H4-6** a finding in the state
(test d); **H4-7** `observations_for_task` re-reads the window (test a, `assert 6 == 1`; three edits, because the
snapshot holds no connection and one has to be added); **H4-8** the `create_task` exception swallowed (test k,
both files); **H4-9** the id added to the ledger before the commit; **H4-10** the action check removed (tests g, h,
j); **H4-10b** the filter order reversed (not in the request; test g's both-rules case); **H4-11** a refused cidr
not counted (not in the request; test f). Three things to know. **H4-8** fails with `DID NOT RAISE`, which the runner
counts as a target failure but which is `pytest.fail`, not an assertion in the code under test; the request said
"by assertion", so this is flagged for the owner. **H4-9** is red on `test_k2_...`, not on test k: adding the id
before `create_task` is not expressible, because the id does not exist yet, and the expressible form is adding it
inside the transaction, before the commit. **The same-target variant of H4-4** (return only the rows of the task's
own target) is not expressible: `observations_for_task` has no parameter, and adding one for the mutation's sake
is exactly the production change that is refused. Names: the provisional H4-4 to H4-7 above are **not** the
catalogue's: the catalogue's H4-4 is the partial window, H4-5 the transformed evidence, H4-6 the non-empty
findings, H4-7 the re-read; the provisional H4-5 (two separate truncations) has no entry because H4 truncates
nothing, and the provisional H4-7 (restart) moved to H5, below. After the runs every file's hash equalled its
pre-run hash; no probe file and no journal.

[2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **Local, on this tree.** The seven harness test files (the two new, H2's two, H3's two, and
`test_stage_vocabulary.py`): 138 passed. Full suite: 4615 passed, 0 failed, 24 errors, the errors in the baseline's
split 2/16/4/2 (`test_scenario_web_render` 2, `test_ad_collector_credential_delivery` 16, `test_browser_escape` 4,
`test_dns_server_kernel_evidence` 2); output at
`/tmp/claude-0/-home-user-ai-red-team/3cc8933a-877a-5b9a-bf4e-a849e674060c/scratchpad/h4_full_suite.txt`.
`opa test`: 82/82; `opa fmt --fail --list`: clean; `ruff check .`: clean.

[2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **CI, run #316, head `411b5ef7fa63c6e7bc09085be087d0e790e6a0ac`, conclusion success.** From one `get_job_logs`
call with `tail_lines=100000`, auto-saved to
`/root/.claude/projects/-home-user-ai-red-team/3cc8933a-877a-5b9a-bf4e-a849e674060c/tool-results/mcp-github-get_job_logs-1794368769620.txt`
(5000 lines came back: from 03:36:16 to 03:44:50). Step 27, "Run test suite with task_relation enforcement ON (zero
failures expected)": `================ 4639 passed, 24 warnings in 728.76s (0:12:08) =================`. Step 28, "Assert the
enforced run had no failure, no error and no skip": `enforced: tests=4639 failures=0 errors=0 skipped=0`. **Step 26,
"Run test suite", also concluded success, but its own `passed` line is not in what the one call returned**: the
window began inside step 27, and the call was not repeated. So that line is not quoted here, and nothing is
claimed about its number beyond the step's conclusion.

[2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **Three-number check.** CI total 4639 (step 27, and the count line of step 28); local 4615 passed + 24 errors
= 4639 (the 24 are the image tests, which run in CI); 4603 + 36 new tests = 4639. They agree.

[2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **H4's design decisions.**
* **R1** One function, `take_round_snapshot(conn, *, limit)`, reads the window once through
  `read_evidence_window` (`limit` required, no default) and returns a frozen `RoundSnapshot` holding the rows and
  `observations_from_window`'s observations. `supervisor_evidence()` returns `EvidenceRecord`s whose `derived_view`
  is the row's object, not transformed and not cut; `observations_for_task()` takes no argument and returns the same
  tuple, the whole window, not filtered by target; no character is truncated anywhere. The `derived_view` objects
  are shared with the rows, neither copied nor frozen.
* **R2** `build_state_summary` fills `evidence` from the snapshot, `findings` is always `()`, and `tasks` and
  `decisions` are the caller's and default empty. They are caller-supplied and default empty **because the
  laundering path (section 11, risk 10; section 14, item 20) is pending the owner**: reading them back from the
  database would put a Supervisor-written `goal` into a trusted prompt half, and H4 does not decide that. The
  pieces (1) of this section's "Pieces" paragraph, a `build_state` over `query_state`, `query_findings` and
  `query_evidence`, is therefore **not** what H4 built: it built the snapshot and the empty-by-default summary.
* **R3** `plan` is called once. `None` is recorded as `plan_returned_none`, a `SupervisorRefusal` as
  `plan_refused`; these two are the whole vocabulary, and no model or exception text is copied. Any other exception
  from `plan` propagates. The real adapters fold refusal and failure into `None`, so the two are not told apart.
* **R4** `check_task_action` first, then a `cidr` whose value has no `/` is refused and counted as
  `cidr_without_prefix` on the task side. A `cidr` whose value is not a string is also refused, under the same
  code (fail closed). Neither refusal is retried or re-asked, and neither touches the other tasks of the plan.
* **R5** Each passing task has its own `engagement_scope` transaction (commit on normal exit, rollback on
  exception, preflight P4), and its id enters the in-memory `RunTaskLedger` only **after** that transaction
  commits. The `create_task` exception is **not caught**: it propagates, the task is not in the ledger, and the
  tasks created before it stay in the ledger and the database. The ledger has `add`, membership and a read-only
  `ids`, and loads nothing from the database.
* **R6** No claim, propose or complete (`test_m2_...` pins that no harness module names those), no stop codes, no
  round cap, no loop.
* **`REASON_CIDR_WITHOUT_PREFIX`** was added to H2's closed vocabulary: it is **H4's only change to an H2 file**, as
  three added lines, so the original tuple stays as H2 wrote it and H2's nine mutation anchors still match.

[2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **What H4 does not prove.** (a) The decoy test uses constructed stdout (P-6) and the real
`_discovery_provenance`; it shows that the observations of the whole window judge a decoy named in another
target's scan as introduced by untrusted text, for one fqdn and one ip, not that every spelling is. (b) The
Supervisor's prompt dumps the evidence with `ensure_ascii=True` and the Observation's content uses
`ensure_ascii=False`; they decode to the same structure and test b pins that, but the two strings are not
byte-equal. (c) The window's `limit` is a parameter; no number was chosen. (d) A prefix-less `cidr` is refused
by this check and not by `create_task`, which still reads it as `/32` or `/128` (the open owner question of
5.122).

[2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **The provisional H4-7 moves to H5.** The 2026-10-30 candidate "after a restart, the harness proposes again for
a task it finds already created by an earlier run" is **moved to H5**: it can only be tested with a loop that
has a restart and a proposal step, and H4 has neither. What H4 provides toward it is an empty-start ledger, which
`test_l_a_new_ledger_starts_empty_whatever_another_holds_and_the_database_holds` pins.

[2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **H4 follow-up as built.** Commit `d4f4ec8d017aa30aa00b5228261013f84470ac27` (message "D69 H4 follow-up: a task whose
target does not canonicalize is refused, and the tests that pin the planning record"), CI run #318. Five existing files
changed, no new file:
* `harness/action_allowlist.py`, 165 lines, +2 -0, sha256 `e8c4cbc6706b25b7038a2d2eba17265ca9229fc9ab7fad61ae24630d2c991fa4`:
  `REASON_TARGET_NOT_CANONICAL = "target_not_canonical"` and its addition to `REASON_CODES`, after the H4 lines;
* `harness/task_source.py`, 149 lines, +7 -0, sha256 `5b51243d212319b01bf27cc5d629c17293c2d0a816ef257e6a48ab609ea9004c`:
  the import of `CanonicalizationError` and `normalize_target`, the import of the new reason, and the third filter;
* `tests/test_harness_task_source.py`, 699 lines, +83 -1, sha256 `da968654eb80c1d7b35f2dd9c22425d1453efe7c818aa34feeb262b067ba00d0`:
  the one deleted line is `assert len(REASON_CODES) == 3`, replaced by `== 4` and a new assertion on the fourth value;
* `tests/test_harness_task_source_db.py`, 197 lines, +20 -0, sha256 `3e61e35391321d68e25fcfd33ef2ab77ba42d81aa10784913cda84a8fed2016c`;
* `scripts/mutations_d69.py`, 333 lines, +26 -0, sha256 `65bbee9eee073df6e38234b629ee85f2d591de082c0eb3e992cc543e64226492`.

[2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **The filter and the probe behind it.** After the action check and the prefix-less `cidr` check, each planned task is
passed to `normalize_target(dict(task.target))`; only `CanonicalizationError` is caught, and the task is then counted as
`target_not_canonical` on the task side and skipped; every other exception propagates. Read-only probe run before the
change (`python -I -c`, no database, no file): `{"type": "cidr", "value": "10.82.0.5/24"}` raises
`CanonicalizationError: cidr '10.82.0.5/24' has host bits set. It is ambiguous between one host and the 256-address network
10.82.0.0/24, and normalizing it would pick the wider reading. Pass 10.82.0.0/24 for the network, or the bare address for the host.`;
`{"type": "cidr", "value": "10.82.0.0/24"}` and `{"type": "fqdn", "value": "host.example"}` normalize; `{"type": "ip", "value":
"not-an-ip"}` raises `CanonicalizationError: invalid ip 'not-an-ip': 'not-an-ip' does not appear to be an IPv4 or IPv6 address`.
`CanonicalizationError` is defined at `control_plane/canonicalizer/target.py:35` and is a `ValueError`. One further probe,
outside the four targets asked for, was needed for the order test: `{"type": "cidr", "value": "not-an-ip"}` (no prefix, and
not a network) raises `CanonicalizationError: invalid cidr 'not-an-ip': 'not-an-ip' does not appear to be an IPv4 or IPv6 network`,
so it is a target that violates both the prefix rule and the canonical rule.

[2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **New tests (10 cases, 11 with the changed one).** T9 `test_t9_a_target_that_does_not_canonicalize_is_refused_counted_and_the_rest_pass`
(5 cases: a `cidr` with host bits and an `ip` that is not one are refused and counted; `10.82.0.0/24`, a bare ip and an fqdn pass;
`plan` is called once in each); T10 `test_t10_when_two_rules_apply_only_the_earlier_one_is_counted` (2 cases: action and not
canonical counts the action only; no prefix and not canonical counts the prefix only); T11
`test_t11_a_target_refused_as_not_canonical_does_not_affect_the_other_tasks`; T12
`test_t12_the_failure_text_exists_where_it_could_be_copied_and_is_in_neither_record` (asserts that
`supervisor.calls[0].failure` holds the words, and that they are in neither `repr(outcome)` nor `repr(counter.entries())`); T13, in
the database file, `test_t13_a_task_that_does_not_canonicalize_has_no_row_and_is_not_in_the_ledger`. The changed line is in
`test_f_the_new_reason_is_in_the_closed_vocabulary_and_the_old_ones_are_kept_in_order`. In all T9 cases the targets expected to be
refused were refused by `normalize_target`; none of them passed.

[2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **Mutations: forty-two in the catalogue, all forty-two valid.** The thirty-seven earlier ones were re-run unchanged and are all
valid, with every H2 and H4 anchor still matching. The five new ones: **H4-12** the not-canonical check removed (T9, two cases, and
T11); **H4-13** a target refused as not canonical is not counted (T9, two cases, and T11); **H4-14** after a refusal the Supervisor is asked
once more and its second refusal swallowed (test e's refusal case, `assert 2 == 1`); **H4-15** `except SupervisorRefusal` widened to
`except Exception` (`test_e_an_exception_other_than_a_refusal_is_not_swallowed`, `Failed: DID NOT RAISE RuntimeError`); **H4-16** the
recorded failure taken from `supervisor.calls[-1].failure` (T12, `assert 'MODEL-WORDS-7c1f' not in "PlanOutcome...WORDS-7c1f')"`, and
test e's failure case, `assert 'MODEL-WORDS-7c1f' == 'plan_returned_none'`; test e's `none` case fails with `IndexError: list index out of
range`, recorded as `other`, as the request said). The T10 cases also turned red under five of the earlier entries (H4-1,
H4-3, H4-10, H4-10b, H4-11); that only widens what they are caught by. After the runs every file's hash equalled its
pre-run hash; no probe file and no journal.

[2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **Local, on this tree.** The seven harness test files: 148 passed (138 before, plus the 10 new cases). Full suite: 4625 passed,
0 failed, 24 errors in the baseline's 2/16/4/2 split (`test_scenario_web_render` 2, `test_ad_collector_credential_delivery` 16,
`test_browser_escape` 4, `test_dns_server_kernel_evidence` 2); output at
`/tmp/claude-0/-home-user-ai-red-team/3cc8933a-877a-5b9a-bf4e-a849e674060c/scratchpad/h4_followup_full_suite.txt`. `opa test`: 82/82;
`opa fmt --fail --list`: clean; `ruff check .`: clean. The three registered files are SAME as the `0747cbe` blobs.

[2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **CI, run #318, head `d4f4ec8d017aa30aa00b5228261013f84470ac27`, conclusion success.** From one `get_job_logs` call with
`tail_lines=100000`, auto-saved to
`/root/.claude/projects/-home-user-ai-red-team/3cc8933a-877a-5b9a-bf4e-a849e674060c/tool-results/mcp-github-get_job_logs-1794536590046.txt`
(5000 lines came back, from 02:10:18 to 02:18:30). Step 27, "Run test suite with task_relation enforcement ON (zero failures
expected)": `================ 4649 passed, 24 warnings in 712.09s (0:11:52) =================`. Step 28, "Assert the enforced run had no
failure, no error and no skip": `enforced: tests=4649 failures=0 errors=0 skipped=0`. Step 26, "Run test suite", concluded success, but
its own `passed` line again lies before the window the one call returned and is not quoted. **Three-number check:** CI total 4649;
local 4625 passed + 24 errors = 4649; 4639 + 10 new cases = 4649. They agree.

[2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **Correction to the record of H4-8 (and H2-7, H3-n).** `Failed: DID NOT RAISE` is produced by `pytest.raises` and is an
assertion-class failure of the test; the review layer rules that H4-8, H2-7 and H3-n are valid, and that H4-10b and H4-11 are accepted. The
two places above that call H4-8 "flagged for the owner" -- the "Three things to know" sentence of the mutations paragraph of "H4 as
built", and section 14, item 38 -- are treated as decided; those older lines are kept as they are.

[2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **Correction of a wording used in this plan.** The sentences that say the Supervisor, the Worker and `_discovery_provenance` use "the
same string", "one string, three uses" or "one string used three ways" (the P-8 chosen lines, section 1; section 1's cost paragraph; section 4's
"(d) the same window and the same string"; and the sentence at the end of section 4's content-encoding decision that H4 requires the two
to "share this string") do not hold as written. The Supervisor's prompt is built by the base class, which dumps each `EvidenceRecord.as_dict()`
with `json.dumps(..., indent=2, sort_keys=True, default=str)`, so with the default `ensure_ascii=True`; a Worker's `Observation.content` is
`json.dumps(derived_view, sort_keys=True, default=str, ensure_ascii=False)`, and the Worker's prompt escapes that once more. The strings
differ in bytes. The invariant that can be tested, and is (test b), is **equality of the data**: `json.loads(observation.content)` equals the
`derived_view` the Supervisor was shown, for every row. `_discovery_provenance` still compares against `Observation.content`, so the
property that matters -- the observation set covers everything the Supervisor was shown -- is unchanged.

[2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **Decision record: a target that does not canonicalize is refused (a review-layer choice; the owner may veto).** Why it is in the
harness: `create_task` computes its identity with `_task_identity`, which turns a `CanonicalizationError` into `(None, None)` and goes on to
insert the task with `identity_key` and `canonical_target` NULL [R: `control_plane/api/function_api.py`, `_task_identity` and `create_task`], so a
task nobody can reduce is created and matches no other task's overlap check. The harness now refuses it before `create_task`, counts it as
`target_not_canonical`, and does not ask the Supervisor again. The new reason code is the fourth in the closed vocabulary; `REASON_CODES`
now has four entries. The order of the three filters is action, prefix-less `cidr`, not canonical, and **each task is counted for one
reason only**, the first that applies (T10). Separately: `create_task` still reads a prefix-less `cidr` as `/32` (or `/128`); the harness
refuses it by the narrower rule in place since H4. That rule is the harness's own and is unrelated to the open owner question of 5.122, so the
closing clause of "What H4 does not prove", (d), above, is corrected to: the question of what `create_task` should do with a prefix-less `cidr`
is not decided here. The module docstring of `harness/task_source.py` still lists two filters; it was not touched because the change was
authorized as code only.

[2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **What H4 does not prove, continued.** (e) The snapshot is read before the planning call and the tasks are created after it, so evidence
written in between is not in the observations a Worker is later judged against; this is a limit the design accepts. (f) The Supervisor's
`tasks` and `decisions` default to empty, so it cannot see the tasks already created and may plan the same work again in the next round;
`create_task` marks the overlap and does not drop the task, and the bound is H5's round cap and call limits. (g) The five mutations added
here protect, respectively: the not-canonical filter existing, its counting, one planning call after a refusal, the exception from `plan`
that is not a refusal propagating, and the recorded failure carrying no model text.

## 6. H5 -- the proposing loop skeleton

**Goal.** A resident, serial loop with its stop rules, built with **scripted** roles, against the real pipeline and
a test database (design D69-1 (A), 5a, 5b, 5c, 5d, 7 (A), 8a (A), 9 (A) [R]).

**Pieces [D] (names provisional).**
* An operator command analogous to `scripts/run_scheduler.py` (`--interval`, `--once`, `SIGINT`/`SIGTERM` finish the
  current task and exit 0), with its **own advisory lock key** (not the scheduler's `0x0D62_5C4E_D000_0001`
  [R: `scheduler/lock.py:26`]) and distinct exit codes in the style of the scheduler's (lock held, DB lost, audit
  failed, Docker unreachable, unexpected, cap reached, no-progress stop) [R/D].
* **Its own enrolment list** (P-3), read each tick; an engagement not in it is never touched.
* Per tick, per enrolled engagement, serially: read pause/kill state; H4's task source; for each task `claim_task`,
  build observations (H3), the Worker call, the allowlist refusal (H2), `load_effective_policy` immediately before
  `propose_action` through **one loader function** (D69-4 (A)), `propose_action` with `task_id` and an idempotency
  key **derived from the task and the attempt**, then `complete_task` on every path the loop controls.
* The closed fault list (design D69-5a): a returned outcome is recorded and the task completed; a Supervisor or
  Worker `None`/refusal/failed call (a classifier stop included) is recorded with its kind, **no re-ask**; anything
  else stops the service (design D69-5b (1): a proposal stranded at `received` is left for a person).
* The bound (D69-5d (a)+(b)): a hard cap on rounds and on model calls per run, and a stop after **N consecutive
  rounds that each produced zero tasks with every model call failing**; both values are written down before the
  first run and are not adjusted from data. The stop does not depend on the kind of failure.
* A start-up banner: database, migration head, the effective values of the two switches, the action set, the
  engagements, the role models and CLI version, and the digests of the Supervisor and Worker prompts and schema
  descriptions (needed for section 10).
* Task claimed and never completed (D69-5c): accepted and reported; no requeue is built here.

**H5b (only if P-3 (a)).** The enrolment table, its writer role and operator CLI, a migration with a round-trip test
(`tests/test_migrations_roundtrip.py` and `tests/test_migrations_rls_writes.py` exist for this [R: file names]) and a grant test. It is its own commit and its own
acceptance.

**Tests.** Scripted Supervisor and Worker; the pipeline with a fake sandbox and the test database. One test per
falsifiable item of design section 11 that the loop owns: 1 (every proposal carries a live task), 2 (policy via the
loader; an AST test over the module), 5 (a fault outside the list stops the service; an injected exception from
`propose_action` leaves the 5.120 state and the service stops), 6 (a stopped call is one call and one recorded
failure), 7 (after `engage_kill_switch` the loop starts no new round or task for that engagement), 8 (`kill -9`
between claim and complete, then restart, leaves no second task or proposal for the same work), 9 (a second
instance exits at once with its own code); plus the caps, the consecutive-zero-task stop, the banner fields, the
signal handling, and a structure test as in `tests/test_task_less_callers.py` (a `ProposedAction` built without a
task in the module is a failing test) [R/D].

**Does not.** Call a model, publish a layer, set a switch, requeue tasks, take any credentialed action, run more than
one task at a time, stop a running container, or start the web console.

**Acceptance.** All tests green; full suite; CI. **Refuted if** any item of design section 11 owned by H5 can be broken
by a single-line change that no test catches (this is what the mutations below measure).

**Mutation entries** (design section 11: "each of 1-9 needs a mutation that breaks it and is caught") [R/D]:
* **H5-1** `propose_action` called with `task_id=None` or another engagement's task -> test 1 must fail;
* **H5-2** the policy passed to `propose_action` is stale or hand-built -> the AST test (2) must fail;
* **H5-3** an exception from `propose_action` is swallowed and the loop continues -> test 5 must fail;
* **H5-4** a stopped Worker or Supervisor call is asked again -> test 6 must fail;
* **H5-5** the pause/kill check removed -> test 7 must fail;
* **H5-6** the idempotency key not derived from task and attempt (a fresh key per call) -> test 8 must fail;
* **H5-7** the lock key shared with the scheduler, or the second instance does not exit -> test 9 must fail;
* **H5-8** the round/call cap removed -> the cap test must fail; **H5-9** the consecutive-zero-task stop removed -> its
  test must fail; **H5-10** a task claimed and left uncompleted on a refusal path -> the completion test must fail.

**ACCEPTANCE.** Updates 5.51 (the policy is loaded through `load_effective_policy` in a production module) and the new
D69 stage row; 5.120's text is not changed. **Risks / [N].** P-3 and P-1; `NetworkInUse` when the scheduler and the
harness dispatch to the same range [D: design D69-1 (A) cost]; whether `propose_action` blocks on a long dispatch
and what the loop's cap then means **[N]**; the stranded `claimed` task residue. **How it stops.** Any mutation that
no test catches, or a test of the loop that needs a model, stops the stage.

[2026-10-29 review layer, under the owner's standing delegation; the owner may veto] Verification A (read-only,
this round) found: for an ALLOW, `propose_action` dispatches inline, in the same call -- `_decide` moves an ALLOW
to `DECIDED` [R: `control_plane/api/function_api.py:844-850`], and `_drive`'s loop continues in the same call
through `_issue` and `_dispatch` [R: `control_plane/api/function_api.py:674-698`]; `_dispatch` calls
`_dispatch_for_action`, which runs the container and commits the evidence before returning
[R: `control_plane/api/function_api.py:1050-1080`]. So **the loop's call to `propose_action` for an ALLOW blocks
until that tool run's evidence is committed or the call fails**; it does not return early to let the loop start a
second task while the first's container is running -- the mechanism behind the design's already-chosen D69-7 (A),
serial. This narrows, without editing, the "whether `propose_action` blocks on a long dispatch" question in the
Risks paragraph above: it does block, for an ALLOW; the worst-case duration of that block remains **[N]**. For a
`DENY` or `HUMAN_APPROVAL`, `_decide` returns an `ActionOutcome` immediately
[R: `control_plane/api/function_api.py:901-907`] -- the call does not wait for a person, and **no evidence exists
yet** for that proposal; evidence for a `HUMAN_APPROVAL` proposal is produced later only if a person approves and
the scheduler calls `dispatch_approved` through `control_plane/scheduler/execute.py`
[R: `control_plane/scheduler/execute.py:59-67`] -- the harness does not drive that step itself, and H3's builder
has nothing to build from until it happens.

[2026-10-29 review layer, under the owner's standing delegation; the owner may veto] To restate plainly: the Risks
paragraph's own question above, "whether `propose_action` blocks on a long dispatch", is now **[R]**, not [N] --
it does block, for an ALLOW; only the worst-case duration of that block stays **[N]**. Verification H (read-only,
this round) found two further facts about the same blocking call. First, when `propose_action`'s ALLOW path
reaches `_dispatch_for_action` with the caller's own `sandbox=None` (its default), the dispatch functions it
routes to construct a **real** `DockerSandbox` themselves -- `sandbox = sandbox or (DockerSandbox(image=adapter_image)
if adapter_image else DockerSandbox())` [R: `control_plane/orchestrator/dispatch.py:844-845`, the same pattern
repeated at `1203-1204` and, by `adapter.IMAGE`, at `1532`] -- so **the harness process itself, not only the
scheduler's, needs a reachable Docker daemon and the sandbox's default image set**; it cannot assume a scripted or
injected sandbox unless it explicitly passes one, which H5's own tests do and a non-test run must also choose to
do or not do. Second, the existing scheduler's own SIGTERM handling (the nearest built model for this) sets a
`threading.Event` that is checked only at the top of its tick loop, before `self.tick()` runs
[R: `control_plane/scheduler/service.py:125-141`]; a tick already dispatching is not interrupted -- the module's
own docstring says a decision that cannot be audited stops the service, and a proposal is "dispatched at most once
per tick" [R: `control_plane/scheduler/service.py:1-13`]. If H5's loop follows the same shape, "finish the current
task" under SIGTERM can take as long as one dispatch's own duration -- bounded, as H6 already states, by the
recorded budget ceiling (ACCEPTANCE 5.24, 1,800 s) [R: H6's own citation; the scheduler's signal handling itself
sets no timer of its own, so the bound is [D], not a new reading of SIGTERM behaviour]. Design D69-9's sentence
that the harness "does not own a running container", if read as meaning no harness process ever starts or waits on
one, does not hold for the ALLOW path: `propose_action`'s own process starts the container and blocks on it, per
this note and the one above.

[2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **Mutation candidate moved here from H4:** after a restart, the harness proposes again for a task it finds
already created by an earlier run -- a test that creates a task, starts a new in-memory ledger as a fresh
process would, and asserts no second proposal for that `task_id` must fail. Name provisional (the catalogue's
H4-7 is a different entry). Reason for the move: it needs the loop, which is H5's. H4 contributes only the
empty-start `RunTaskLedger` (H4's test l).

## 7. H6 -- the operating description

**Goal.** Write down, in an operator document (`docs/D69_OPERATIONS.md`, name provisional), how to start, stop and
kill the harness and **what the kill does not do**: the kill switch flips a database row checked at the stage
boundaries of `propose_action` and by the loop; it does **not** stop a container that is already running (it runs
until its `max_duration_seconds`, the budget ceiling recorded in ACCEPTANCE is 1,800 s), and **a model call that has already started finishes**
[R: ACCEPTANCE 5.24, design section 9; the model-call half is [D], from the absence of any check inside a call].
Also states the private-repository limit of `code.*` (5.57), that no web console start command exists in the
repository, and the start order convention (reconciler `--once`, then the scheduler, then the harness) [R/D].

**Does not.** Build an active kill (D58-16; design D69-9 (B)/(C) is the owner's call for real engagements), add a
compose or service definition, or change any code.

**Acceptance.** Every sentence about behaviour is tagged and cites the stage whose test shows it; the kill paragraph
equals design section 9; `tests/test_acceptance_numbering.py` and `tests/test_rule_5_27_docs.py` pass; CI green.
**Refuted if** the text claims the kill stops a container or a model call.

**Mutations.** None (no code). **ACCEPTANCE.** 5.24 and D58-16 unchanged; the document is cited from them only if the
owner asks. **Risks / [N].** The document can drift from the code; H5's banner and exit codes are the things to
re-read. **How it stops.** If H5 changes after H6, the document is re-read before the next stage closes.

[2026-10-29 review layer, under the owner's standing delegation; the owner may veto] Line-number correction
(verification C): the design document's reference to `headless.py:175` for where the Claude subprocess is started
points, in this tree, at `stdin=subprocess.DEVNULL,`, not the call itself. The call statement is
`completed = runner(` at line 165, and its keyword arguments run through line 177
[R: `agents/llm/headless.py:165-177`]. This plan's own earlier citation at section 11, `headless.py:176` for
`timeout=timeout_seconds`, is unaffected -- line 176 does read `timeout=timeout_seconds, check=False,` in this
tree [R: same lines] -- so only the design document's line number needs correcting, and this plan does not edit
that document.

[2026-10-29 review layer, under the owner's standing delegation; the owner may veto] Operator-text consequence of
the H5 note above: "the harness does not own a running container" is true of the kill switch's own reach (it still
cannot stop one already started, as this section already says), but it is not true that the harness process never
starts or waits on one -- for an ALLOW, it does both, inside the same `propose_action` call. H6's document should
say so plainly rather than imply, by silence, that the harness is a thin requester that only ever waits on a
result handed to it; for the duration of an ALLOW's dispatch it is also whatever process the container runs
inside, up to the recorded ceiling.

## 8. H7 -- laboratory end to end, and the re-verification of ACCEPTANCE 5.28

**Goal.** One run per v0 action (`network.scan`, `network.recon`) in a lab engagement through everything the
harness owns, with **scripted** Supervisor and Worker (no model call), and the end-to-end check that 5.28 names as
its trigger [R: ACCEPTANCE 5.28].

**The check (design D69-3b, chosen) [R].** A real tool run in the lab -> the evidence row -> the **real builder** ->
an observation set -> a scripted Worker that proposes the lure -> `propose_action` with a lure in an in-range
spelling in the untrusted content -> the decision must be `HUMAN_APPROVAL` with `introduced_by_untrusted` true; and
the mirror case (an identity the tool did observe: a ping scan's responder) must not escalate on discovery grounds.
The same cases for a connect scan (where the builder adds nothing): a follow-up proposal for one host is named only
in untrusted content, so it goes to a person, and the count is recorded by scan type (design measurement 5).

**Does not.** Call a model; open a switch; run a shadow; exercise `code.*`, `web.*`, `ad.collect`; claim the harness
works on real traffic (the lab is synthetic).

**Acceptance.** The cases above produce exactly the stated decisions; **refuted if** a lure reaches `ALLOW`. The full
suite and CI as always. P-7 decides whether a soak run with the harness inside follows (stage H7b).

**Mutation entries** [D]: **H7-1** the loop passes no observations to the Worker -> the lure case must fail (the lure
would not be classified as introduced); **H7-2** the builder includes the lure host in `observed_identities` at the
loop level -> the lure case must fail; **H7-3** the loop passes observations from another engagement -> an
isolation case must fail. (H3's own mutations (a)-(f) stay assigned to H3.)

**ACCEPTANCE.** Updates 5.28: the trigger is met and the end-to-end re-verification is executed; **the row's status
is the owner's to change** (this plan does not say Closed). **Risks / [N].** It needs the Docker lab (CI has it; the
local machine lacks some images); a lab nmap scan's real stdout is not stored today, and H7 does not store one by
itself (recording it is a separate act needing authorization to run nmap). **How it stops.** A lure reaching `ALLOW`
stops everything after it and is reported as a defect of H3 or H5.

[2026-10-29 review layer, under the owner's standing delegation; the owner may veto] H7's own authorization
(section 12) must name both nmap and the lab's Docker sandbox explicitly, not only the harness's code: per
verification A (see the note at the end of H5), the lab's real tool run that produces the evidence row H3's
builder reads happens synchronously inside the ALLOW path of a prior `propose_action` call, so H7 cannot get an
evidence row to test the builder against without that authorization already covering a real dispatched run.

## 9. Acceptance conventions (from D68, applied to every stage)

1. **Full suite, 0 failures.** The local run is the whole suite; its 24 errors are the missing browser/bloodhound
   images and must be itemized and **identical to the baseline list** (ACCEPTANCE 5.118 records them as "24 errors that
   are the browser/bloodhound images this machine lacks" at S1, and "the same 24 image errors" at S3, S5 and S6 [R]).
   This plan states no current local pass count: the count belongs to the run of the day [N]. A different error, or a
   failure, stops the stage.
2. **CI green on the branch tip**, quoting the printed line of the step "Run test suite with task_relation enforcement
   ON" (`enforced: tests=... failures=0 errors=0 skipped=0`) and the count of "Run test suite". The count at the time
   of writing is 4531 [R: CI run #300]; each stage states its own expected count as 4531 plus its new tests [D].
3. **Mutations:** every entry valid by `scripts/mutation_check.py`'s rule (a mutation counts only if its change
   compiles and imports, at least one test fails by an **assertion**, none fails by a broken edit, and every test
   named in `targets` is among the target failures [R: the tool's docstring]); an **equivalent mutant is removed
   from the catalogue and the removal is explained**; the files are restored byte for byte and checked; **no commit
   is made during a mutation run or a running full suite**; one pytest or mutation session at a time.
4. **The ACCEPTANCE numbering test** and `tests/test_rule_5_27_docs.py` pass; no pointer to a row that does not exist.
5. **An unauthorized action stops the stage and is reported**: no model call, no switch, no layer publication, no
   nmap, no connection to a database or daemon outside the authorization given for that stage.
6. **Registered files** (the D68 stage-1 plan, wording file and analysis script) are byte-identical to commit
   `0747cbe` before and after each stage's commit; `docs/D68_DP15_RECORD_MODE/stage1/` is never touched.
7. [2026-11-06 review layer, under the owner's standing delegation; the owner may veto] **Where a run's output may go.** A full
   local suite takes about 24 minutes, which is past the limit of a single foreground command, so it is run in the
   background and its output file goes to the session's scratchpad, outside the repository: that is allowed and
   needs no further permission. Nothing else is: a hash list, a daemon's log, any other working file -- unnecessary,
   and not allowed. H2's run wrote three scratchpad files and left one more that the tooling produced, all outside
   the repository and all reported in that stage's report. This rule binds the stages after H2; it is not a
   judgement on H2's run.

## 10. H8 -- the shadow pre-registration: where it goes and when

**Goal.** A draft of the shadow's pre-registration with the fields of design section 8 ("Candidate fields of a
pre-registration") and **every value empty**: unit of analysis; population and how engagements are chosen; number of
engagements, rounds and tasks; roles, models, aliases, CLI version, fallback setting and the **digests of the
prompts and schema descriptions** of each role; the action set; lab or real targets; what counts as a failure (a
classifier stop counts, no re-ask); caps and stop rules; the number and timing of looks and a ledger of looks; the
reading rule written before the data; the registering commit and the hashes of every registered file with a guard in
the runner that refuses to start if they differ [R: design section 8]. The candidate measurements (design section 8,
items 1-7; item 5 and 7 by scan type) are listed; **no threshold is set or proposed**.

**Location and time.** The draft is a document under `docs/` (name provisional, e.g.
`docs/D69_SHADOW/PREREGISTRATION_DRAFT.md`). It becomes a registration only by a commit made **after** the harness
exists and the digests can be computed, and **before** the first shadow run; the registering commit's hash and the
hashes of the registered files are then written in a README beside it, as D68 did for stage 1 [R:
`docs/D68_DP15_RECORD_MODE/stage1/README.md`].

**What must exist before registering [D].** (1) H1-H7 closed, with the full-suite and CI lines quoted; (2) the
harness's prompt and schema-description digests, printed by H5's banner; (3) a runner for the shadow with an
integrity guard in the style of `integrity()` in `scripts/dp15_stage1_run.py` (clean tree, HEAD contains the
registering commit, registered files equal their blobs) -- **this runner and its guard are not part of H1-H8**; they
need their own plan after H8; (4) the owner's decisions on the engagements, the targets (lab or real) and the caps;
(5) the existing shadow report (`scripts/plan_fit_report.py`) shown able to read the harness's engagements without a
change (design acceptance 11.11); (6) the rule that Q1 stays out of the shadow unless the owner opens a new
registration [R: design D69-8a, OUTCOME.md].
[2026-11-04 review layer, under the owner's standing delegation; the owner may veto] (7) **the owner's decision on
the laundering path** (section 11 risk 10, section 14's row): the shadow is the first thing here that puts a real
model in front of a `goal` written in an earlier round, so that decision comes before this registration, not after
it. H7 is unaffected -- scripted roles only.
[2026-11-11 review layer, under the owner's standing delegation; the owner may veto] (8) **verify the form of non-ASCII bytes in a real nmap run's output** -- the raw byte, or a backslash-x
escape of the form `\xHH` -- since the probes use constructed stdout and the second form would be a channel the
content rule does not cover (section 4, what H3 does not prove, (i); section 14, item 29).

**Does not.** Register anything, choose a value, set a threshold, run anything, or decide what the shadow concludes.

**Acceptance.** Every field of the design list is present and empty; no number appears that is a threshold; the file
says it is a draft. **Refuted if** a value or a threshold is filled in. **Mutations.** None. **ACCEPTANCE.** The note
under the D69 stage row. **Risks / [N].** Any change to a prompt or schema description of a role after registration
is a numbered change with a pinned test and a re-run of the shadow (design D69-2b) -- it cannot be done silently.
**How it stops.** If the digests cannot be computed, the draft stays a draft.

## 11. Risks and unknowns

1. **P-1 and P-3 may need migrations** (a narrow role; an enrolment table): the heaviest, least reversible pieces
   (migration round-trip tests, grant tests, an operator step) [D].
2. **The scan-type rule costs approvals.** After a connect or version scan, a follow-up proposal for one host in the
   range goes to a person; the size is unmeasured **[N]** (design measurement 5, by scan type).
3. **No stored CIDR `-Pn` stdout** exists, so H3's fixtures are constructed (P-6) and the claim that a ping scan's
   `hosts` holds only responders stays [D] until measured (design measurement 7) **[N]**.
4. **`code.*` has no Observation rule** (the views name no repository): outside v0 by design; the harness cannot
   exercise a repository target in H1-H8.
5. **The loop reaches a model and a container in one process.** A hung model call blocks the loop; the cap bounds
   rounds and calls but not the duration of one call **[N]**; the headless adapters carry a timeout (`headless.py:176`
   `timeout=timeout_seconds`) [R].
6. **Two processes start containers** (the scheduler and the harness); `NetworkInUse` on one range is "retry later"
   for the dispatcher (D59) [R]; how the harness treats it in v0 is H5's open point.
7. **Stranded `claimed` tasks** after a crash are not requeued (design 0a/0c) [R]; v0 reports them.
8. **The `Observation` correspondence** (escaped form vs raw) is a new place for a fail-open mistake; H3-c exists for it.
10. [2026-10-31 review layer, under the owner's standing delegation; the owner may veto] **The laundering path
    (pending the owner; nothing is chosen here).** A Supervisor whose own prompt carried untrusted evidence writes
    a task `goal`. That text is then shown back to the Supervisor in later rounds inside the **trusted** header --
    the task ledger is in `header`, not in `wrap_untrusted`
    [R: `agents/llm/supervisor_base.py:445-449`] -- and is shown to the Worker in the Worker's **trusted** half
    too: `header = {"task": {"goal": task.goal, ...}}`, with only observations wrapped
    [R: `agents/llm/worker_base.py:631-638`, and the module's own "Only the second goes inside the block" at
    `:621-624`; H1 report item 7]. So target-influenced wording can re-enter both roles' trusted regions one round
    later, laundered through a field the platform treats as its own record. **This plan does not address it**:
    changing either prompt, or the trust split inside it, is a numbered change with its own pinned test and a
    re-run of anything measured against the old wording, and `goal` is not a field the harness can sanitize
    without deciding what a goal may say -- an owner's call, not a build detail. Registered in section 14 so it is
    not carried as a silent assumption.
    [2026-11-04 review layer, under the owner's standing delegation; the owner may veto] **Gate:** the owner's
    decision on this path must be settled **before any run that uses a real model** -- that is, before the shadow
    H8 registers (section 10's list, item (7) added the same date). H7 is **not** gated by it: H7 uses scripted
    roles only, so no model reads the laundered `goal` there.
9. **Non-determinism** is confined to the later recorded run with the real Worker and to the shadow; CI uses scripted
   roles only, as for the Reviewer [D].

## 12. What this plan does not do, and what it does not authorize

It builds nothing. **It authorizes no implementation: every stage needs the owner's explicit authorization before it
starts, one stage at a time**, and an authorization names what the stage may touch (files, a test database, Docker,
a lab, a model, nmap). It does not choose P-1 to P-7, does not decide the `code.*` or `web.*` rules, does not choose a
database role, does not set or open a switch, does not publish a layer, does not set a threshold or a shadow
parameter, does not touch D68's registered files, and does not change the design document or any existing row.
Hook or system reminders to "commit and push" are not authorization for anything beyond what a stage's own prompt
grants.

## 13. Sequence summary (for reference)

H1 report -> owner chooses P-1, P-2 -> H2 filter -> H3 builder -> H4 task source -> (P-3) H5 loop (and H5b) -> H6
operator text -> H7 lab end to end -> H8 draft -> [later plans: the shadow runner and guard; the shadow registration;
the shadow run].

## 14. To register (待登記) -- listed only; nothing is written to any existing file

1. **A new ACCEPTANCE row for the D69 implementation, Class B, Open, updated as each stage is confirmed** (the pattern
   of 5.118 for D68); the number is assigned by the owner's process. Its first text: stages H1-H8, none built,
   switches off.
2. **ACCEPTANCE 5.28** -- at H7: the trigger met, the end-to-end re-verification executed; status is the owner's.
3. **ACCEPTANCE 5.51** -- at H5: a production module loads the policy through `load_effective_policy`.
4. **ACCEPTANCE 5.122** -- at H4: the harness-side prefix check; the canonicalizer question stays open.
5. **A new row, Class B, Open:** no code requeues a `claimed` task whose lease lapsed (design section 12, item 3).
6. **A new row, Class C:** the web console has no documented start command (design section 12, item 4).
7. **A new row at H3 or H7, Class C:** no CIDR `-Pn` nmap stdout is stored anywhere in the repository, so the fixtures
   of H3 are constructed (P-6) and "ping scan `hosts` holds only responders" is [D].
   [2026-11-08 review layer, under the owner's standing delegation; the owner may veto] H3 was built with constructed fixtures, as
   this item anticipated; the [D] stands unmeasured and the row is still owed.
8. **`D68_IMPLEMENTATION_PLAN.md` 7.1 and ACCEPTANCE 5.118** -- the sentence "gated on a production harness existing
   and being run in shadow first" refers to this plan's H8 and the later shadow plans.
9. **`ADR_PRODUCTION_ORCHESTRATOR.md` index** -- a row for the proposing side (design section 12, item 7).
10. **The shadow runner and its integrity guard** -- a separate plan after H8, with its own mutations; named here so it
    is not forgotten (section 10).
11. **The owner's answers P-1 to P-7**, recorded where the owner prefers, before the stages they gate start.
12. [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **P-8**: which evidence
    rows, and how much of their content, become a task's `Observation`, and the character ceiling applied
    identically on both sides of the Worker boundary; no value is proposed here.
13. [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **A new row, Class C:**
    the harness cannot produce evidence for a `HUMAN_APPROVAL` proposal by itself -- evidence after a human
    approval depends on the scheduler calling `dispatch_approved` (verification A); the harness's own loop
    produces evidence only for proposals it dispatches inline (ALLOW).
14. [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **Design document
    `docs/D69_PRODUCTION_HARNESS_DESIGN.md` needs a superseded note**: its "the harness does not own a running
    container" sentence (design section 9) does not hold for the ALLOW path, per verification A and H above --
    this is a separate, single authorization on that document itself; this plan does not make that edit.
15. [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **A new row, Class C:**
    the harness's own rounds and the evidence a round can act on are not synchronous with each other for a
    `HUMAN_APPROVAL` proposal -- that proposal's evidence exists only after a person approves it and the scheduler
    calls `dispatch_approved`, outside the harness's own tick (verification A); a later harness round that wants
    to build on that evidence must read it back, not assume it is available the round after the proposal was made.
16. [2026-10-29 review layer, under the owner's standing delegation; the owner may veto] **Shadow measurement 2's
    denominator ([N]):** design section 8's measurement 2 is counted over `ALLOW` decisions; if most of a lab
    engagement's proposals are `HUMAN_APPROVAL` under the effective policy in force there, that denominator is
    small, and a rate computed on it is correspondingly uncertain -- how small is **[N]**, not measured by this
    plan.
17. [2026-10-30 review layer, under the owner's standing delegation; the owner may veto] **Persisting the
    evidence/task snapshot across a restart is a later decision, needing a new schema** -- v0 keeps it in memory
    only, per the P-8 chosen line above; this plan does not propose that schema.
18. [2026-10-30 review layer, under the owner's standing delegation; the owner may veto] **Restart behaviour:** a
    task the harness created in a run that then restarted is not continued -- only counted and reported, never
    claimed again. Verification N (read-only, this round) found no schema support for telling such a task apart
    from any other queued one: `claim_task` takes no `task_id` and no creator filter at all, claiming whichever
    queued task in the engagement has the highest priority, oldest first
    [R: `control_plane/api/function_api.py:235-263`]; `create_task` does write `created_by`
    [R: `control_plane/api/function_api.py:199-208`; the column at `control_plane/state/models.py:101`], but every
    production caller found passes a fixed agent-identity string, not one scoped to a run
    [R: `scripts/live_run/d17_supervisor.py:471, 628, 828, 850`]; `tasks` carries no run-scoping column at all
    [R: `control_plane/state/models.py:93-113`]. **So the only thing that can tell "created by this run" apart
    from "created by an earlier run of the same agent identity" is the harness's own in-memory set of task ids
    from the current process** -- exactly what the P-8 chosen line already relies on, and exactly what a restart
    loses. This is a precondition H5 must build to, not something H5 can read its way around; recorded here so it
    is not left implicit.
19. [2026-10-31 review layer, under the owner's standing delegation; the owner may veto] **Correction to item 18
    above:** its "never claimed again" is not implementable as written, for the reason recorded in section 1 --
    `claim_task` accepts no `task_id` and no creator filter [R: `control_plane/api/function_api.py:235-263`],
    nothing returns a claimed task to `queued`, and `complete_task` has no `status` or owner precondition
    [R: `control_plane/api/function_api.py:268-279`; `docs/D69_H1_REPORT.md` item 6]. What is registered is the
    replacement: v0's engagement has no other task creator, and a task outside this process's own set stops the
    service with its own exit code (section 1, the 2026-10-31 chosen line), with the restart cost stated in H6.
20. [2026-10-31 review layer, under the owner's standing delegation; the owner may veto] **A new row, Class B,
    pending the owner: the laundering path** -- a Supervisor-written `goal`, possibly shaped by untrusted evidence,
    returns to both the Supervisor's and the Worker's **trusted** prompt halves in later rounds
    [R: `agents/llm/supervisor_base.py:445-449`, `agents/llm/worker_base.py:631-638`;
    `docs/D69_H1_REPORT.md` item 7]. Section 11 risk 10 holds the detail; no mitigation is chosen, and changing a
    prompt is a numbered change this plan does not make.
    [2026-11-04 review layer, under the owner's standing delegation; the owner may veto] **Gate, registered with
    the row:** this decision is required before any real-model run -- before the shadow H8 registers (section 10,
    list item (7)) -- and is **not** required before H7, which runs scripted roles only.
21. [2026-10-31 review layer, under the owner's standing delegation; the owner may veto] **`result_summary` is a
    writable text field that reaches a trusted prompt region** [R: `agents/llm/supervisor_base.py:128`, `:138`,
    `:445-449`], and `complete_task` constrains it in no way
    [R: `control_plane/api/function_api.py:268-279`]. The closed-vocabulary rule chosen in section 1 applies to
    the harness only; whether the product should constrain the field itself is the owner's, and is not decided
    here.
22. [2026-11-06 review layer, under the owner's standing delegation; the owner may veto] **`harness/registry_view` is
    untested as of H2** -- the pure function it delegates to is covered, the wrapper is not. H5 tests it against the
    real registry in a test database, with mutation candidate **H5-16** (the wrapper returns the registry's scope
    objects without the filter -> a test must fail).
23. [2026-11-06 review layer, under the owner's standing delegation; the owner may veto] **The packaging gap:** `harness` imports only because
    pytest puts the repository root on `sys.path`; `pyproject.toml`'s `[tool.setuptools] packages` lists
    `control_plane`, `agents` and `tool_gateway`, and not `harness` [R: H2 pre-check P4]. To be settled in H5,
    before anything runs the harness outside a test run.
24. [2026-11-06 review layer, under the owner's standing delegation; the owner may veto] **Mutation entries H2-7 and H2-8** -- the refusal
    counter not checking the reason code, and a missing or non-string action being let through -- to be added to
    `scripts/mutations_d69.py` in the next code commit, with the stop rule recorded in section 3: either one that no
    existing test catches is a gap in H2's tests, to be reported rather than papered over with a new test.
    [2026-11-07 review layer, under the owner's standing delegation; the owner may veto] Done by commit `e4e388c` as
    H2-7, H2-8a and H2-8b, with the H2-8 description corrected in section 3; all nine entries are valid, so the
    stop rule did not fire.
25. [2026-11-06 review layer, under the owner's standing delegation; the owner may veto] **A wording correction in `harness/__init__.py`**: it
    claims a test for each of the three import rules, but the third is a permission, not a direction a test can
    pin. A comment-only change in the next code commit.
    [2026-11-07 review layer, under the owner's standing delegation; the owner may veto] Done by commit `e4e388c`: the
    docstring now names the test that pins each of the two direction rules, and says the third is a permission no
    test pins.
26. [2026-11-08 review layer, under the owner's standing delegation; the owner may veto] **The evidence window's ceiling:** how many
    rows a round may carry, and whether a row's content needs a character ceiling, are undecided.
    `read_evidence_window` requires `limit` and has no default, so the question cannot be answered by accident;
    the answer itself is the owner's, and H5 is where the loop has to name a number.
27. [2026-11-08 review layer, under the owner's standing delegation; the owner may veto] **The divergence case is constructed:** a run
    whose `scan_type` differs from the proposal's cannot be produced through the pipeline (preflight P4), so
    `tests/test_harness_observations_db.py` builds it with INSERTs on a real ping proposal. If the pipeline ever
    gains a path that can diverge, that test should be rebuilt on it.
28. [2026-11-09 review layer, under the owner's standing delegation; the owner may veto] **`content`'s encoding is decided:** `ensure_ascii=False`
    (section 4, the decision record above, with probes Z2 to Z4). H4 must hand the Supervisor and the Worker this
    string in this form, not a re-encoding of it.
29. [2026-11-09 review layer, under the owner's standing delegation; the owner may veto] **Non-ASCII bytes in real nmap output [N]:** whether nmap prints them
    as the byte or as a backslash-x escape is unverified; the second would be a channel the current content rule does
    not cover. To be settled when a real run's output exists (item 7).
    [2026-11-11 review layer, under the owner's standing delegation; the owner may veto] Now also item (8) of H8's "What must exist before registering" list (section 10): the check is
    a precondition of the registration, not only something to settle when a run exists.
30. [2026-11-09 review layer, under the owner's standing delegation; the owner may veto] **Window order within one transaction is by `evidence_id`:** a
    `limit` that cuts through a group of rows with the same `created_at` keeps a reproducible but arbitrary subset.
    Noted for H5, where the loop names the limit.
31. [2026-11-09 review layer, under the owner's standing delegation; the owner may veto] **Row-level security is the only thing keeping a foreign run out of the
    window's join** (T2): the foreign key does not scope `evidence.run_id` by engagement.
32. [2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **H4 is built and recorded** (section 5): commit `411b5ef`, CI run #316, 36 new tests, thirty-seven
    mutations all valid, the 24 image errors in the 2/16/4/2 split. Step 26's own `passed` line was outside the
    one log call's window and is not quoted; step 27's and step 28's lines are.
33. [2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **`REASON_CIDR_WITHOUT_PREFIX` is in H2's closed vocabulary** -- H4's only change to an H2 file, three
    added lines; `REASON_CODES` now has three entries, and a test pins the order of the first two.
34. [2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **The provisional H4-7 (restart) moved to H5** (section 6): it needs the loop. H4 provides the empty-start
    `RunTaskLedger` and its test l.
35. [2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **Probe Z5** (section 4, end): NFC, NFD and punycode are mutually detected and `normalize_fqdn` gives one
    punycode for both Unicode spellings; only the fqdn type and constructed stdout were covered, and NFKC
    compatibility characters and other forms were not tried **[N]**.
36. [2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **`tasks` and `decisions` in the Supervisor's state are caller-supplied and default empty** in H4, because
    the laundering path (item 20) is pending the owner; each task is created in its own transaction, and enters
    the in-memory ledger only after that transaction commits; the `create_task` exception is not caught.
37. [2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **P-8's numbers are still the owner's**, needed only by H5's loop; H4's snapshot function takes `limit` as a
    required parameter and picks none.
38. [2026-11-11 review layer, under the owner's standing delegation; the owner may veto] **H4-8 fails by `DID NOT RAISE`**, which the runner counts as a target failure and which is not an assertion
    in the code under test; flagged for the owner (section 5).
39. [2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **H4 follow-up is built and recorded** (section 5): commit `d4f4ec8`, CI run #318, 10 new cases, forty-two mutations all valid, the
    24 image errors in the 2/16/4/2 split; step 26's own `passed` line was outside the one log call's window and is not quoted.
40. [2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **H4-8, H2-7 and H3-n are valid** (section 5): `DID NOT RAISE` from `pytest.raises` is an assertion-class failure; item 38 above is
    treated as decided.
41. [2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **The "same string" wording is corrected** (section 5): the testable invariant is equality of data (test b), not of the string; the Supervisor's
    prompt uses `ensure_ascii=True` and a Worker's `content` uses `ensure_ascii=False`.
42. [2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **A target that does not canonicalize is refused by the harness** (section 5): reason code `target_not_canonical`, one reason per task, in the
    order action, prefix-less `cidr`, not canonical; a review-layer choice. The module docstring of `harness/task_source.py` still lists two
    filters and needs a comment-only correction in a later code commit.
43. [2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **What `create_task` does with a prefix-less `cidr` (`/32` or `/128`) and with a target that does not canonicalize (a task with a NULL
    `identity_key`)** is not decided here; the harness refuses both before `create_task`, and the question of changing `create_task` itself
    belongs to the owner and is separate from 5.122.
44. [2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **Two H4 limits** (section 5, "What H4 does not prove", (e) and (f)): evidence written between the snapshot and the creation of a task is
    outside the Worker's observation set, and the Supervisor does not see tasks already created, so it may re-plan the same work; the bound is
    H5's round cap and call limits.
45. [2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **A proposal, not a decision: H5 split into three parts** -- the pieces that need no database, the registry and its migration, and the
    assembly of the loop. To be put forward by the review layer separately; nothing about it is decided and nothing here changes section 6.
46. [2026-11-14 review layer, under the owner's standing delegation; the owner may veto] **Decision: H5 is built in four parts, H5a1, H5a2, H5b and H5c, in that order.** It replaces the effect of item 45's "three parts" proposal, which stays as written; the pieces are named as in `docs/D69_H5_SPLIT_PROPOSAL.md` 2.3 (names provisional).
    * **H5a1:** a1 the stop-code table and the mapping from outcome to code; a2 the `result_summary` builder and its closed-vocabulary validator; a3 the idempotency-key derivation; a4 the bounds as a state machine; a6 the banner formatter.
    * **H5a2:** a5 the start-up decision and the claim-time ownership check; a7 the enrolment read interface and its in-memory fake; a8 the Worker step; a9 the signal wrapper; a10 the loop's control flow against ports.
    * **H5b:** the enrolment table, its writer role, the operator CLI and the database implementation of a7's interface. **H5c:** the real adapters, the operator command, the advisory lock, and the process-level tests.
    * **Why:** H5a as one stage was estimated at 500 to 800 lines of code and 20 to 30 mutation entries, two to three times H4; and the shape of H5b's read interface is fixed by a7, so H5b follows H5a2.
    * **Mutations, each assigned to one stage:** H5a1: H5-6, H5-8, H5-9, H5-11, H5-18, H5-19, H5-23, H5-24. H5a2: H5-2, H5-4, H5-10, H5-12, H5-13, H5-14, H5-15, H5-20, H5-21, H5-22, H5-30, H5-31. H5b: H5-27, H5-28. H5c: H5-1, H5-3, H5-5, H5-7, H5-16, H5-17, H5-25, H5-26, H5-29. (31 entries, H5-1 to H5-31, none twice; H5-29, H5-30 and H5-31 are defined in items 50, 49 and 48.)
47. [2026-11-14 review layer, under the owner's standing delegation; the owner may veto] **Choices made on the proposal's section 3** (`docs/D69_H5_SPLIT_PROPOSAL.md`; each is the proposal's option A unless stated):
    * **3.1 stop codes: A.** 0 to 6 keep the scheduler's meanings, 7 is not used, the harness's own codes start at 10: 10 the start-up check refused, 11 a foreign task, 12 a fault outside the closed list, 13 a cap reached, 14 no progress.
    * **3.3 banner: A.** Standard output only; the fields are the proposal's list. **3.4 SIGTERM during an ALLOW dispatch: A.**
    * **3.5 idempotency key: A.** `h5:<task_id>:<attempt>`, `attempt` starting at 1. **3.6 lock key: A.** `0x0D69_5C4E_D000_0001`, with one test asserting that it is not equal to the scheduler's key.
    * **3.7 leftover live tasks: A plus B.** B is a read-only subcommand that lists the leftover tasks, in H5c's operator command. **3.8 duplicate planning: A.**
    * **3.2 is changed by item 48.** The values of the caps and of N, and P-8's evidence-window ceilings, are still [N] and the owner's, registered before the first non-test run; the window size stays a required parameter. 3.9's open points are read in `docs/D69_H5_PREFLIGHT_REPORT.md` (sections A, B and C) and nothing about them is decided here.
48. [2026-11-14 review layer, under the owner's standing delegation; the owner may veto] **D69-5d (b)'s stop condition is changed.** The loop stops, with code 14, after **N consecutive rounds in which no proposal reached `propose_action`**, in place of "N consecutive rounds that each produced zero tasks with every model call failing". This replaces the effect of H5's piece 5 (`L1139`-`L1141`),
    of the design's D69-5d (b) and of the proposal's 3.2; the original chosen line and 3.2 stay as written.
    * **Why:** the old rule does not see a successful empty plan (H4's test T15 pins that `[]` is not a planning failure), a plan whose tasks the filters all refuse, or a Worker that is refused every time; in each case the loop would run on to its round cap.
    * **Cost, accepted for v0:** an engagement that has legitimately finished also stops with code 14.
    * **New mutation H5-31 (H5a2; name provisional):** the signal "a proposal reached `propose_action`" is replaced by the old condition, and the no-progress test must fail.
49. [2026-11-14 review layer, under the owner's standing delegation; the owner may veto] **Decision: the residue of a controlled stop.** When the loop stops by a signal, by a cap or by the no-progress rule, it calls `complete_task` on every task of its own ledger that it has not claimed, with `result_summary` the new token `not_run`, added to the closed vocabulary of the `result_summary` builder (a2).
    A stop by a fault (codes 10, 11 and 12) does not: it stops and leaves the rows for a person.
    * **Why:** otherwise one clean stop leaves live tasks that the start-up check then refuses on the next start, and no operator tool clears them (`docs/D69_H5_PREFLIGHT_REPORT.md`, section E).
    * **New mutation H5-30 (H5a2; name provisional):** after a controlled stop, a never-claimed task of the loop's ledger is left live.
50. [2026-11-14 review layer, under the owner's standing delegation; the owner may veto] **New mutation H5-29 (H5c).** On the real database, the start-up check runs after the first claim; the test "no `tasks` row was changed to `claimed` or given an owner" must fail. H5-14 is the order of the check and the claim, with a fake that records calls (H5a2);
    H5-25 is the check itself writing a row; H5-29 is the order bug measured on the real tables.
51. [2026-11-14 review layer, under the owner's standing delegation; the owner may veto] **A requirement on H5-26's test (H5c).** The start-up check refuses a restart on an engagement with live tasks, so the test must not depend on a restart: it reads the idempotency key stored in `action_proposals.request_idempotency_key` and asserts that it equals `h5:<task_id>:1`.
52. [2026-11-14 review layer, under the owner's standing delegation; the owner may veto] **A correction.** The message of commit `53138ab` says "all eighteen H4 mutations valid". The count is 19 (H4-1 to H4-18 and H4-10b), all valid, and the catalogue holds 44 entries (9 H2, 16 H3, 19 H4). The message is not amended.
53. [2026-11-14 review layer, under the owner's standing delegation; the owner may veto] **This record and `docs/D69_H5_PREFLIGHT_REPORT.md` authorize no implementation.** H5a1, H5a2, H5b and H5c each need their own authorization, and the preflight report is read before any of them is given.
