# MVP-0 — what D10 delivered, what D10.5 owes, what D11 deferred

The last section carries deferred items found after MVP-Kernel was accepted, in
the same format as `ACCEPTANCE_MVP_KERNEL.md` §5. That document is the record of
a stage that closed; new items go here rather than being written back into it.

D10 swapped the Policy Reviewer for a real model **as code**. It did not measure
how that model behaves, because this environment has no Anthropic credential of
any kind: `ANTHROPIC_API_KEY` unset, no `~/.config/anthropic/` profile, no `ant`
CLI. The behavioural questions were therefore split into D10.5 rather than
simulated.

That split is deliberate and worth being blunt about. The stated point of this
deliverable was never "the model connects" — it was to learn how a real model's
judgement distribution differs from what the adversarial fixture assumed. A stub
returning a hand-written opinion would answer that question with a number I made
up. The project has refused that trade since D6 (the sandbox confinement rule:
fail explicitly rather than mock), and it is refused here for the same reason.

---

## Delivered in D10

| | |
|---|---|
| `agents/llm/policy_reviewer.py` | `LLMPolicyReviewer` — satisfies the existing `PolicyReviewer` protocol |
| `tests/test_llm_reviewer.py` | 35 tests, all offline, stubbing only the HTTP transport |

**Scope limit #2 held.** `control_plane/`, `tool_gateway/`, `agents/base_agent.py`
and `agents/fake/` are byte-identical to `main`. The seam was one line —
`function_api.py`'s `reviewer.review(proposal=..., canonical_target=...)` — and
the substitution needed nothing else. Asserted structurally by
`test_swapping_the_reviewer_changed_no_existing_component`, which reads the
adapter's source (docstrings stripped) and fails if it ever references a
resolver, a registry, the broker, or the policy engine.

**Scope limit #3 held.** The output schema carries `additionalProperties: false`
over exactly the four `ReviewerOpinion` advisory fields; there is no
`data_class`, no `authorized`, no `decision`. Two independent tests cover it —
one on the schema, one confirming that extra fields a model might return are
dropped by the frozen dataclass rather than carried.

### A vulnerability found while building this

The first version wrapped the proposal in a fixed `<untrusted_observation>` pair.
That was broken, and `test_injected_text_stays_inside_the_untrusted_block` caught
it: **JSON escapes quotes and backslashes but not `<` or `/`**, so a target whose
hostname contained the literal closing marker serialized verbatim into the block
and closed it early. Everything after it in that hostname then sat outside the
boundary, where a model reads it as text from the operator.

Fixed by giving the delimiter a per-call random id (`secrets.token_hex(8)`), so
whoever chose the hostname cannot know what would close the block. Escaping the
marker was rejected as the alternative: it would mean editing evidence before
showing it to the reviewer, and a hostname containing an injection attempt is
precisely what a reviewer should see intact — and flag.

Mutation-tested: reverting to a fixed token fails both the freshness test and the
injection test.

### Fail-closed behaviour

Timeout, connection error, safety refusal, and unparseable output all return
`risk_hint="high"` + `recommended_escalation=True`, which reaches OPA's existing
`high_risk` approval rule. **No policy change and no new reason string** — an
unavailable reviewer is treated as a reviewer that is worried. A risk level
outside `{low, medium, high}` is coerced to `high` for the same reason (I10:
ambiguity resolves cautiously). The failure cause is carried in
`semantic_risk_hints` so the audit trail can distinguish "the model was worried"
from "the model was unreachable" — same decision, different operational response.

---

## Owed by D10.5

### 1. Scenario B against a real model

Re-run all 8 Scenario B tests plus the 4 I10 integration tests with
`LLMPolicyReviewer` in place of `AdversarialFakeReviewer`, same fixtures.

The decision must still be DENY — the kernel guarantees that regardless of what
the reviewer says, and Scenario B already proves it. **The new information is
what the model itself judged**, so record the full `ReviewerOpinion`, not just
the final decision. The interesting outcomes, in rough order of how much they
would tell us:

- the model correctly flags the PII target → the fixture's adversarial
  assumption is pessimistic relative to reality
- the model says "low risk, nothing sensitive" → the fixture's assumption was
  realistic, and was measuring a real failure mode
- the model is inconsistent across runs → the distribution matters more than any
  single verdict, and the sample size needs to be more than one

### 2. Ambiguity baseline

Proposals where a human reviewer would also hesitate: authorization plainly
valid, no AUTHORITATIVE classification, only low-tier OBSERVED data. The kernel's
behaviour is already known and fixed (unknown → HUMAN_APPROVAL for actions that
need a classification), so **this is not a kernel test**. It measures whether
the model's `semantic_risk_hints` carry information.

The measure is `ReviewBaseline.distinct_hints()`: a reviewer that emits one
hint across many different proposals is giving the same answer every time, which
is not a signal however careful the wording sounds.

### 3. Latency and cost

`ReviewCall` already records per-call latency, input/output tokens, and USD at
per-model list rates. Report the distribution, not just a mean — a reviewer
usually fast and occasionally timing out is a different operational problem from
one uniformly slow.

### 4. Two-model comparison

Run both `claude-opus-5` and `claude-haiku-4-5` over the same scenarios.
`model=` is already a constructor argument and `ReviewCall.PRICES` already
carries both rate cards, so this needs no code change.

Opus first, to establish the ceiling: if the strongest model cannot produce a
useful hint on a given proposal, a cheaper one will not either, and the
comparison then separates "this task is hard" from "this model is too small".

---

## CI: how the live tests will run

**Key management.** `ANTHROPIC_API_KEY` is read through `require_env` in
`control_plane/config.py` — the same no-fallback path as the database
credentials. There is no default, no fallback, and no key anywhere in the repo
or in a workflow file. In CI it comes from a repository secret injected as an
environment variable; `.env` is gitignored and is the local equivalent.
`test_a_missing_api_key_raises_rather_than_defaulting` pins the behaviour.

**Frequency: scheduled plus manual dispatch, in a separate named job.** Not on
every push, and the reasoning is worth recording because the alternative looks
more rigorous than it is. Model output is non-deterministic, so a live job on the
push gate would fail intermittently for reasons unrelated to the change being
pushed — and a gate that fails for unrelated reasons is one people learn to
re-run without reading. The failure mode is not a red build; it is a build
nobody trusts.

The job stays **visible**: its own named job with its own result, on a schedule
and on `workflow_dispatch`. That is the distinction from the thing this project
has refused twice — a test quietly excluded from the gate and never run at all.
This one runs on a known cadence and reports a result each time.

The offline tests in `tests/test_llm_reviewer.py` need no key and stay in the
normal push gate, where they already are.

---

# DEFERRED — found by the D11 live run

Same format as `ACCEPTANCE_MVP_KERNEL.md` §5: where it was found, why it is not
being done now, and what binds whoever implements it later. Numbered from 11 so
the two lists do not collide.

Neither of these blocks anything today. **The first is not, however, in the same
class as the rest of the deferred list.** Items 5.1, 5.2 and 5.4 are places where
the design is silent and guessing would invent semantics — risks that are real
but so far theoretical. 11.1 has already happened: it took a live run down, and
the recovery required knowing to write SQL against a table no operation exposes.
It should be ranked ahead of the "not needed yet" items on that basis alone.

## 11.1 No way to ask which policy layers are in force — D11 live run

`control_plane/policy/layers.py`

The first live-run attempt came back **DENY** with `action_denied_by_policy`,
against a baseline layer published seconds earlier that said
`network.scan: ALLOW`.

The cause was nineteen `emergency_overlay` rows published globally
(`engagement_id IS NULL`) by test runs between 16 and 19 August, each carrying
`{"actions": {"network.scan": "DENY"}}`, all still active. A global layer applies
to every engagement in the database and nothing expires it, so `network.scan` was
denied for every engagement, permanently, by rows nobody remembered writing.

The merge behaved exactly as designed — that is I2 holding, and the `_combine`
fold is what stopped the fresh baseline from masking them. The gap is that
**there is no operation that answers "what is in force right now, and where did
it come from".** `load_effective_policy` returns the merged result, which says
`network.scan: DENY` and nothing about why. `current_policy_version` returns a
number. The rows behind both are reachable only by writing SQL against
`policy_layers`, so the diagnosis was available to someone who already knew the
schema and to nobody else.

This is the shape D8 fixed for `audit_log`. Before `reconstruct_decision()`, the
audit trail was complete and effectively unreadable: every test that wanted to
know what happened wrote its own `SELECT ... ORDER BY audit_id` and grouped rows
by hand. The fix was not more data — it was one function shaped like the question
people actually ask. `list_effective_policy_layers()` is the same move for the
Policy Pack.

*Why not now:* D12 was scoped to two security fixes and two records, and this is
neither. The immediate hazard has also been cleared: the nineteen rows were
retired through `deactivate_policy_layer` under a dedicated maintenance
engagement, so the cleanup is itself audited, and the test helpers that produced
them were changed to `scoped_to_engagement=True` before D11. What remains is that
the next person to meet this has no better tool than the last one did.

*Binding constraints:*

1. **It reports; it does not decide.** A query interface that recomputed the
   merge would be a second implementation of §4.5's algebra, and two answers that
   can disagree is worse than one answer that is hard to read. It returns the
   rows that fed `load_effective_policy` — layer, version, scope, document,
   `active`, who published it and when — and the merged result comes from the
   existing function.
2. **The rows it returns are exactly the set `load_effective_policy` selects**
   (active, global or this engagement's), and a test pins that equality. A
   listing that shows a different set from the one being enforced is worse than
   no listing, because it will be believed.
3. **Global rows must be visibly global.** The whole failure was a global layer
   read as though it were the engagement's own; the output has to distinguish
   `engagement_id IS NULL` from a scoped row without the reader inferring it.
4. **Read-only, and no new grant.** `policy_layers` is already readable by
   `cyberorch_app`; this must not become a reason to widen anything. Note that
   the provenance half of the question — *who* published a global layer — is not
   answerable today for a separate reason, recorded as 11.2 below, and this
   interface must not paper over that by presenting an empty attribution as
   though it were an absent one.

## 11.2 Audit attribution for operations that belong to no engagement — D11 live run

`control_plane/audit/logger.py`, `db/migrations/versions/0001_core_schema.py`
(the `audit_log` RLS policy), `control_plane/policy/layers.py`

Observed while diagnosing 11.1, and it is why that diagnosis had to end at
"there are nineteen rows" rather than "X published them on the 18th":

```
global layers visible from ENG-D11-3ee453d054 : [{'id': 703, 'layer': 'baseline_global', 'engagement_id': None}]
policy_layer.published audit rows visible here: 0
...but the row exists, under the engagement that published it:
    [{'audit_id': 4077, 'actor': 'd11-live-run', 'subject_id': '703'}]
```

A policy layer published with `scoped_to_engagement=False` has
`engagement_id IS NULL` and is readable from every engagement — it has to be, or
it could not apply. The `audit_log` row recording who published it, when, and
with what document is written on a connection pinned to whichever engagement the
publisher happened to be in, and RLS scopes it there (§8.6, I4).

So a global write leaves a globally-visible effect and an audit record only its
author can see. From inside an engagement you can see that a global layer
constrains you and cannot see where it came from. Both halves are individually
correct — global layers must be globally visible, and one engagement's audit must
not leak into another — and the gap is between them: **a globally-scoped
operation has no globally-scoped record.**

*Why not now:* this is not a missing query, it is a missing decision, and the
same reasoning as 5.1 applies — the design does not answer it and picking one
answer here would be inventing an access-control model rather than implementing
the one that exists. Recorded as the open questions rather than as a plan, and
deliberately with **no proposed fix**. Nothing in the RLS policy should be
touched until these are settled:

- **Which `engagement_id` does a global operation's audit record carry?** `NULL`
  is the honest value and the one `policy_layers` already uses, but `audit_log`
  declares the column `NOT NULL` and every reader assumes it is populated. A
  reserved sentinel engagement is the other candidate and brings its own
  question — whether a row that is not an engagement should appear in the
  `engagements` table at all.
- **Who may read these records?** Not simply "any engagement's `registry_admin`".
  That role exists per engagement, and letting each one read a shared audit
  stream creates a cross-engagement read surface where none exists today, which
  is precisely what I4 and §8.6's `FORCE ROW LEVEL SECURITY` were built to
  prevent. Whatever is chosen has to say what it is granting to whom, not merely
  which rows it returns.
- **Do these records need access rules independent of the current RLS model?**
  Today every `audit_log` row is reachable through exactly one predicate, on
  `engagement_id`. A second class of row with a second rule means the table no
  longer has one access model, and that is a change to the security boundary
  rather than an addition to it — including for anyone auditing the audit table.

*Binding constraint, ahead of any of that being decided:* the current behaviour
must not be treated as a bug to be worked around locally. Widening the RLS
predicate, writing the record under a borrowed engagement id, or duplicating the
row into every engagement would each close the visibility gap by opening the
isolation one. Whatever lands has to be a decision about the model, made once,
and 11.1's listing interface must not pre-empt it.

## 11.3 Two tasks are never compared — D17 Supervisor run

**RESOLVED in D19 (`docs/ADR_TASK_IDENTITY.md`, Option 1).** `create_task` now
persists the action, canonical target and scope object it used to discard
(migration 0006), computes a target-level identity key `(action, canonical
target)`, and on a match populates `overlaps_with` — marking the duplicate,
never dropping it (binding constraint 1). `query_tasks` is the read side of the
same key. Replaying the committed D17 `blind` arm through the new logic
identifies **21 of 25** tasks as duplicates at insertion (25 − 4 distinct
groups), and the Redis:6379 / relay:7001-7002 pair is kept as two rows rather
than merged — the port-level distinction is made downstream by §7's fingerprint,
which is the layer that has ports. The original finding is kept below as the
record of why the change was made.

---

`control_plane/api/function_api.py` (`create_task`), `db/migrations/versions/0001_core_schema.py`
(the `tasks` table), `control_plane/dedup/`

The brief for D17 asked whether the Task Manager's dedup/lease mechanism could
identify a real planner's semantically-duplicate tasks, or whether varying
natural language would slip past a literal comparison. Measuring it turned up a
prior question: **there is no comparison to slip past.**

Three separate facts, each checkable:

1. **`create_task` inserts unconditionally.** A fresh uuid, an INSERT, an audit
   record. Nothing is looked up first. Two calls with a byte-identical goal
   produce two tasks — `test_even_a_byte_identical_goal_creates_a_second_task`.
2. **The `tasks` table does not retain what a non-semantic comparison would
   need.** `ProposedTask` carries an action, a target and a scope object id;
   `create_task` writes `goal`, `created_by` and `priority` and drops the other
   three. So the only thing about a task that survives into the database is free
   text, and any dedup built on the table as it stands could only ever compare
   prose — `test_a_task_keeps_its_prose_and_discards_its_structure`.
3. **§4.2's `overlaps_with` is written by nothing.** It has been in the schema
   since the first migration and no code path assigns it —
   `test_nothing_ever_writes_the_overlap_field`.

What *does* exist, and what it covers:

* **§6's claim/lease works and was never the exposure.** `FOR UPDATE SKIP
  LOCKED` plus a status guard and a five-minute lease: eight threads against six
  tasks claim each exactly once
  (`test_concurrent_agents_never_claim_the_same_task`, three mutations). But it
  answers "who owns this row", not "is this row the same work as that one".
  Seed the same sentence twice and two agents hold two live leases, each
  believing it owns work nobody else is doing —
  `test_the_lease_protects_a_task_not_the_work_it_describes`.
* **§7's fingerprint deduplicates *executions*, several stages later.** It is
  consulted in `dispatch_scan` and it is real: an identical second scan returns
  `dedup_hit` without the tool running
  (`test_a_second_identical_scan_is_deduplicated`). Two limits matter, and both
  are now pinned by tests. It keys on `normalized_params`, so two duplicate
  tasks that lead a Worker to the same host with *different ports* are two
  executions (`test_the_same_host_scanned_for_different_ports_is_not_deduplicated`).
  And it runs **after** the policy evaluation and after `issue_capability`, so a
  duplicate still costs a proposal, a decision and a capability even in the case
  the cache catches.

*Why not now:* the brief is explicit — report the finding, do not decide how task
identity should be compared. That decision is larger than a deliverable. It has
to answer what makes two tasks the same (identical structure? overlapping target
sets? the same objective reached differently?), what the system does when they
are (refuse, merge, link through `overlaps_with`, warn), and it interacts with
§9's ADR G, which rules out automatic semantic derivation on the grounds that
getting it wrong produces a false negative — the scan that should have run and
did not. A dedup that silently swallows a task is a worse failure than a
duplicate one.

*What the D17 run measured about it:* see `docs/D17_SUPERVISOR_REPORT.md` §5.
The numbers there are input to whatever gets decided, not a proposal.

*Binding constraints on whoever takes this:*

1. **Fail towards a duplicate, never towards a silent drop.** §1.2c and ADR G
   are both explicit that a false negative here is a security bug. If a
   comparison is uncertain, the task gets created.
2. **Whatever is compared has to be stored.** Any structural comparison needs
   `create_task` to persist the action, canonical target and scope object it is
   currently given and discards. That is a schema change and a write-path
   change, and it is the smallest honest starting point.
3. **Not automatic semantic derivation** (ADR G). An explicit rule, an explicit
   table, or a human-visible "these look related" link — not a similarity score.
4. **`overlaps_with` is the field §4.2 already reserved** for the "related, not
   identical" answer, and it should be used rather than a new one.

## 11.4 A task goal is generated text on the trusted side of another model's prompt — D17

`agents/llm/worker_base.py` (`BaseWorker.build_prompt`), `agents/llm/supervisor_base.py`

`BaseWorker.build_prompt` places the task — goal and action — **outside** the
untrusted block, and says why: the task "comes from the Supervisor and the
registry". That was accurate while the Supervisor was a scripted fixture
emitting constants.

With a real model behind the role it is no longer simply true. A Supervisor's own
prompt contains an untrusted block (findings and evidence, both derived from what
targets said), and its output includes free text that becomes `tasks.goal`. So
there is a path by which text a target chose can be copied into a goal and
re-emerge on the *trusted* side of a different model's prompt.

The channel is bounded, and the bound is real rather than reassuring:

* A goal cannot name an authorization. The Worker still selects
  `scope_object_id` from a schema enum over the offered candidates, and the
  Authorization Resolver still decides containment from the registry (D15).
* A goal cannot name a tool, a port, a budget or a capability — none of those
  are fields the Supervisor has.
* What a goal *can* do is tell a Worker what to work on, in words the Worker is
  told to trust.

*Measured, not assumed:* the D17 run counts how often a generated goal quotes the
lure address or the hostname from the untrusted block. The result is in
`docs/D17_SUPERVISOR_REPORT.md` §6.

*Why not now:* the fix is not obvious and the obvious one is wrong. Wrapping the
task in the Worker's untrusted block would tell the Worker to distrust its own
assignment — the same mistake D13 refused when it declined to wrap the scope
objects — and would leave the Worker with no trusted statement of what it is for.
The alternatives (a structured goal with a free-text field marked as
model-authored; wrapping only the goal while leaving the action and scope
outside; keeping goals but having the Worker take its target from the structured
fields alone) are all interface changes to a boundary D13 and D15 verified
empirically, and re-opening it deserves its own deliverable rather than a rider
on this one.
