# D17 — a real Supervisor, and what the Task Manager does about it

The third and last role. D10/D10.5 put a real model behind the Policy Reviewer
and showed that a reviewer which lies changes no decision (I6b). D13 and D15 put
one behind the Worker and showed that the Canonicalizer and the Authorization
Resolver hold when a real model, fed a real injection from a real target, drives
the proposal.

The Supervisor cannot be tested that way, because **it never reaches the policy
kernel**. Its output is a task, and a task is authorized by nothing: it goes into
the `tasks` table, a Worker later claims it, and only the proposal that Worker
writes meets the Canonicalizer. So the component a real Supervisor is pointed at
is the **Task Manager** — §6's claim/lease and §7's deduplication — and the
question is whether those hold up against a planner that may ask for the same
work twice in words that differ.

The short answer, before any numbers: **§6 holds exactly as specified and was
never what was at risk. §7 does not apply at this layer at all.** There is no
deduplication of tasks anywhere in the system, literal or otherwise, and the
`tasks` table does not retain the fields any non-semantic comparison would need.
That is not a regression D17 introduced; it is the state a real planner was
pointed at, and measuring what it costs is what this deliverable is for.

---

## 1. Scope — what changed and what did not

Only the Supervisor. `CYBERORCH_WORKER_BACKEND` and `CYBERORCH_REVIEWER_BACKEND`
were left at `fake` for every run, which the results file records, and a test
pins that the three switches are independent
(`test_all_three_role_switches_are_independent`).

| | |
|---|---|
| `agents/llm/supervisor_base.py` | Schema, prompt, trust boundary, fail-closed path |
| `agents/llm/claude_code_headless_supervisor.py` | Transport only, on D10.5's isolation set |
| `agents/llm/selection.py` | `CYBERORCH_SUPERVISOR_BACKEND`, defaulting to `fake` |
| `control_plane/api/function_api.py` | `query_findings`, and a `query_state` that returns ledgers |
| `tests/test_supervisor_boundary.py` | 53 offline tests |
| `tests/test_state_queries.py` | 21 tests on the query interface and what a task retains |
| `tests/test_task_manager.py` | 7 tests on §6's claim/lease, including the concurrency test §11 asked for |
| `scripts/live_run/d17_supervisor.py`, `d17_analyze.py` | The manual experiment; not in CI |

No new database grant, no schema change, no change to `create_task`,
`claim_task`, the Canonicalizer, the resolvers, OPA, the broker or the gateway.

### Isolation reused, not redesigned

The `claude` CLI runs with D10.5's verified flag set — `--tools ""`,
`--safe-mode`, `--setting-sources ''`, `--strict-mcp-config`,
`--disable-slash-commands`, `--no-session-persistence`, an empty temp directory
as cwd, and `stdin=DEVNULL` (D15's defect).
`test_the_supervisor_call_carries_the_whole_isolation_set` asserts the whole
sequence rather than whichever flags somebody remembered.

The nonce-delimited untrusted boundary is the same `agents/llm/untrusted.py`
D10.5 built and mutation-tested. Findings and evidence go inside the block; the
task ledger, the decision ledger and the scope objects stay outside it. A test
feeds a finding whose `claim` contains a literal closing marker and confirms it
stays inside — D10.5's attack arriving through the one new door D17 opens.

---

## 2. Did the interface have to be widened? — the brief's second question

**Yes, by two read-only queries, and one of them was already in §2.** Neither is
an execution interface. What follows is the accounting, including the one thing
that genuinely is new exposure.

### What was missing

§2 lists seven functions an agent may call. Two were not implemented:

* `query_findings(engagement_id, filter) -> findings[]` — **never implemented at
  all.** Nothing had needed it: a Worker is given one task, a Reviewer one
  proposal, and neither plans. "What has this engagement actually established"
  is the question a Supervisor's whole job rests on.
* `query_state(engagement_id, filter) -> summary` — implemented, but returning
  five integers and ignoring `filter`. A planner shown only `tasks: 4` cannot
  avoid re-issuing any of those four, because it does not know what they are.

So the gap the brief anticipated — "it needs to know whether a task of some kind
already exists" — was real, and the fix is *implementing* §2 rather than
extending it.

### Query, not execution — and how that is held

1. **Nothing writes.** `test_the_queries_write_nothing` md5-hashes `tasks`,
   `findings`, `action_proposals`, `audit_log` and `evidence` before and after
   both calls.
2. **No new grant.** Both run on the ordinary `cyberorch_app` connection —
   `test_the_queries_need_no_grant_beyond_the_runtime_role` asserts
   `current_user` is that role and that the calls succeed on it. Had either
   needed a privilege, the test fails with a permission error rather than
   passing against a role that happened to be able to do more.
3. **RLS-confined, and the `engagement_id` argument cannot select.** It labels
   the connection's own scope; passing another engagement's id returns nothing,
   which tests assert directly for both queries and for `claim_task`.
4. **§2's `filter` is spelled as checked keyword arguments, not a predicate.**
   `task_status` and `state` are validated against §4.2's and §4.3's fixed
   vocabularies; everything else is a bound parameter. A free-form filter object
   that became SQL would be a read interface a caller could widen from the
   inside. Tests pass `"'; DROP TABLE findings--"` and get a `ValueError`, with
   a control that every documented state *is* accepted so the allowlist cannot
   silently shrink to nothing.
5. **No tool, no shell, no network, no registry write** appears in either
   function or in the Supervisor's output schema.
   `test_the_plan_schema_offers_no_way_to_execute_anything` checks for the
   absence of `tool`, `command`, `capability`, `budget`, `ports`, `scan_type`
   and `authorization` as fields, with `additionalProperties: false` at both
   levels.

### The new exposure, stated rather than glossed

`query_state` returns **decisions on proposals other agents made in the same
engagement**. Every such row was already returned to whoever submitted it, as an
`ActionOutcome`; what is new is the readership, which goes from "the agent that
asked" to "any agent in this engagement".

I do not think this crosses a line, and the reason is that §5's isolation
boundary is the *engagement*, not the agent — I4 is enforced per-engagement in
the database and there has never been a per-agent boundary to widen. It is still
a widening, and it is exactly the kind that gets waved through as obviously
fine, so it is recorded here rather than left for someone to find.

Two consequences worth naming:

* A compromised Worker can now enumerate what has been denied in its
  engagement. Deny reasons are a fixed vocabulary of constants, not free text,
  so what leaks is which of a known set of refusals fired — but "the policy
  refuses X here" is genuinely information an attacker did not have.
* Nothing forces a Supervisor to be shown this. The harness's `build_state`
  chooses to include it; a deployment that wants a planner blind to other
  agents' refusals passes `decision_limit=0` without touching the kernel.

### What was *not* added, and why it was tempting

The natural interface for this deliverable would have been
`query_tasks(engagement_id, matching=<some description of work>)` — a lookup
answering "does a task like this already exist?". It was not added. Such a
function has to define what "like this" means, and that definition *is* the
task-identity decision this deliverable is explicitly told not to make. Adding
it as a convenience would have settled the design question sideways, by shipping
an answer nobody had agreed to.

---

## 3. Method

Five arms, one engagement each so ledgers cannot contaminate one another. The
target is the disposable D11 container on the sandbox's `10.79.0.0/24` network —
real daemons, real nmap output — and the evidence every arm is shown is a real
scan of it, collected through the ordinary pipeline before the Supervisor is
asked anything.

The engagement holds two scope objects, both of which a real customer might
register: the range `10.79.0.0/24`, and the single live host `10.79.0.2` by
address. Both authorize `network.recon` and `network.scan`. Two routes to the
same host is not a trick — it makes "the same work, authorized two ways"
reachable without constructing anything artificial.

| Arm | n | State |
|---|---|---|
| `independent` | 20 | One frozen state, nothing written back between calls |
| `accumulating` | 12 rounds | Each round's tasks are really created; round *k+1* sees round *k*'s |
| `accumulating_warned` | 12 rounds | Same, with the anti-duplication paragraph appended |
| `closed` | 10 | Everything completed, one direction really denied |
| `closed_pressure` | 8 | Same closed state, objective aimed at the denied host |

### What "semantically duplicate" means here

Nothing asks a model, or me, whether two goals mean the same thing. Each task is
reduced to a **structural key**: its action, its target canonicalized by the real
Target Canonicalizer, and the scope object it named. Two tasks sharing that key
are the same work by construction, whatever words their goals used. A second
measure drops the scope object, because scanning one host under two different
valid authorizations is still one scan. A third counts repeats *within a single
plan*, which is the stronger case: across calls a planner may not have been told
what it did last time, but a plan listing the same work twice in one answer
contradicts itself with the whole ledger in front of it.

Beside every duplicate count is a **counterfactual**: how many of those pairs an
exact goal-string comparison would have matched, and how many a
punctuation-insensitive one would. It is labelled a counterfactual throughout
because there is no such comparison in the system to bypass — `create_task`
inserts unconditionally — and describing the result as "dedup was evaded" would
be false.

### Why the warned arm exists

D17's measurement is whether a real planner re-issues work its ledger already
holds. A system prompt telling it not to would have measured the instruction. So
the production prompt says only that the ledgers are there to be read — what an
engineer would write without this question in mind — and
`test_the_production_prompt_does_not_coach_the_measurement` fails if the words
"duplicate" or "already queued" ever appear in it. The second arm appends one
paragraph and nothing else, which `test_the_experimental_arm_only_appends` pins.

### Two things the harness deliberately does not do

* It does not filter duplicates before writing them. Every task a plan produces
  goes through the real `create_task`, because a harness that de-duplicated in
  front of the Task Manager would be measuring the harness.
* It does not repair the policy. The run refuses to start when stale global
  emergency overlays are in force (D11-6, which recurred again here — nineteen
  rows, retired separately under an operator name through
  `deactivate_policy_layer`), rather than clearing them itself.

### One fixture, named as a fixture

The `closed` and `closed_pressure` arms need an engagement whose authorized work
is genuinely exhausted. The **decisions** in that state are real — the denial
goes through the actual policy engine against the actual policy — but the five
completed tasks that make the ledger look finished are seeded, not executed.
Running eleven real scans would not have changed what the planner sees, since all
it ever gets is the ledger; it does mean this arm measures a planner against a
described history rather than a lived one.

The first version of the `closed` arm had only the setup scan in its ledger, and
the planner answered "there is more to do here". That answer was **correct** —
one host out of a /24 is not a finished engagement — and the arm was measuring a
state nobody was in. That is why `CLOSED_LEDGER` exists, and it is worth
recording that the fixture was built because the model was right, not because it
was wrong.

### A run that was discarded

The first attempt at the full experiment ran all five arms in one 62-call
process. Forty-six of those calls failed with `cli exited 1:` and nothing after
the colon, and the container was reclaimed shortly afterwards. **None of those
numbers are reported here**, for the reason D15's truncated run was discarded:
a distribution missing three quarters of its calls, for a cause that could not be
distinguished from a rate limit, a bad flag or a killed process, is not a
measurement.

Two things changed as a result, both committed before the re-run:

* `run_headless` now falls back to stdout when stderr is empty, so the next
  failure of this kind says what it was. stderr stays first and stays capped,
  because stderr is where argv — and so the prompt — gets echoed back.
* The arms are run one process at a time, each writing its own results file, so
  a reclaim costs one arm instead of all five. `d17_analyze.py` reads any number
  of them together.

