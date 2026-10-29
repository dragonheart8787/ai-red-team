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
(b) every evidence row for the engagement whose target matches the task's target, read fresh each round -- needs
the engagement-listing function verification B found missing, and its selection rule would need the same care
D69-3a already gives the nmap builder; (c) no truncation, as the `d40` script defaults to -- fail-open by size, an
uncapped derived view reaching the Worker; (d) a fixed character ceiling applied identically on both sides of the
Worker boundary (the content given to the Worker and the content `_discovery_provenance` compares) -- fail-closed
by size, but a ceiling applied to only one side (as the `d40` script's own slice is, which trims only the copy
placed in `Observation.content` and not any comparison copy) risks exactly the kind of mismatch H3-c already tests
for. If a ceiling is chosen, its value is left blank here and is registered, the same way as the caps in H5
(D69-5d), before the first non-test run -- not adjusted from data afterward.

[2026-10-29 review layer, under the owner's standing delegation; the owner may veto] chosen principle: (i) the
observation set handed to provenance covers every evidence row that any role saw in producing the proposal; (ii)
the Supervisor and the Worker draw on one shared, bounded evidence window, and the Supervisor sees no more than the
provenance set; (iii) rows are all of the engagement's evidence, newest first, up to a cap, not only same-target
rows; (iv) the row count and the per-row character cap are [N], pending the owner, registered before the first run
and not adjusted from data. Reason [D]: provenance escalates only on a target named in the content of an
observation it is given, so a smaller set escalates less (fail open); the cost of the larger set is more untrusted
text in the prompt and more approvals (fail closed).

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
