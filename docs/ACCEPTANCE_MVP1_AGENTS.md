# MVP-1 Acceptance Review — the three roles behind real models

Against `docs/ARCHITECTURE.md` v0.3, and the stage `ACCEPTANCE_MVP_KERNEL.md`
named as the one that follows it: *"replacing the fake agents with a real LLM
behind the same argument. Nothing else in `propose_action` changes, which was
the point of building it this way."*

**Verdict: GO.** All three roles — Policy Reviewer, Worker, Supervisor — now run
behind a real model, selected by one environment variable each, and the kernel
boundary each role touches held. The reasoning is in [Go / No-Go](#go--no-go) at
the end; the evidence is everything above it. This document is the record of a
stage that is closing, in the same form as `ACCEPTANCE_MVP_KERNEL.md` §5–§8. New
deferred items continue to be written to `DEFERRED_MVP0.md`, not back into this
file once it is merged.

Scope reminder — what this stage covered and what it deliberately did not. It
put a real model behind each of the three roles and measured that role against
the boundary it can actually reach. It did **not** add Neo4j, a Vector DB, an
Egress Proxy, a Web Agent, Playwright, an Approval UI, or a finding-verification
workflow; those remain Phase-1 scope. The live measurements were run by hand and
never entered CI, for the reasons `DEFERRED_MVP0.md` and
`ADR_REVIEWER_BILLING.md` give: model output is non-deterministic and a personal
subscription's OAuth credential does not belong in CI secrets.

---

## 1. The three roles, each verified against the boundary it reaches

The design point of the kernel was that each role meets a *different* part of the
system, so each real-model swap is a different experiment. The Reviewer's output
is advisory and meets OPA; the Worker's output is a proposal and meets the
Canonicalizer and the Authorization Resolver; the Supervisor's output is a task
and meets the Task Manager and never reaches the policy kernel at all.

### 1.1 Policy Reviewer — I6a / I6b / I6c (D10, D10.5)

`agents/llm/policy_reviewer.py`, `ADR_REVIEWER_BILLING.md`,
`LIVE_RUN_REPORT.md` §6

The Reviewer was swapped as *code* in D10 (one seam: `function_api.py`'s
`reviewer.review(...)`), and its behaviour measured in D10.5. Four selectable
backends (`fake`, `api`, `claude_code`, `local`) share one advisory-only
`OPINION_SCHEMA` with `additionalProperties: false` over exactly four fields —
no `data_class`, no `authorized`, no `decision`. That is I6b enforced
structurally: the opinion has no field able to assert a data class.

**The distribution (D10.5, `claude_code`/`sonnet`, CLI 2.1.237, n=30 across two
Scenario-B cases):**

| Case | risk=low | flagged sensitive | named PII | **recommended_escalation** |
|---|---|---|---|---|
| bare IP `10.79.0.20` | 15/15 | **0/15** | 0/15 | **0/15** |
| named `customer-pii-db.example` | 5/15 | **15/15** | 15/15 | **0/15** |

**The headline number is 0/30 escalations.** Across both cases and all 30 runs
the reviewer never once set `recommended_escalation` — including the ten runs
where it rated the target medium *and* named the PII it holds. On these
proposals the model supplies **no safety margin at all**; the AUTHORITATIVE deny
in the registry does 100% of the work, and the DENY would be byte-identical with
the reviewer switched off. That is not a defect — it is the empirical form of the
design assumption the kernel was built on (a reviewer is advisory; nothing may
depend on it noticing), and it must never become an argument for letting the
reviewer influence a decision.

Two scoping limits kept honest rather than smoothed over:

* **Blind is not the same as wrong.** The bare-IP case is *stably* blind (15/15
  low, 0/15 PII mentions): the model has no classification data for the address
  and does not invent any. It is not guessing badly; it has nothing to guess
  from, which is exactly why the kernel does not ask it.
* **The scalar label is the unreliable part, not the detection.** On the named
  host the substance was consistent (15/15 flagged sensitive data) while
  `risk_hint` varied 10/5 between medium and low. `semantic_risk_hints` carried
  information; `risk_hint` alone would have misled a third of the time. Do not
  build a threshold on the scalar.

A second live pass (D11, `opus`, CLI 2.1.238, n=20) reproduced **0/20
escalations** and surfaced *escalation-by-narration*: `approval_reasons contains
"sensitive_data_hint"` fires on `count(...) > 0`, so in 11/20 runs the reviewer
rated the proposal `low`, set `recommended_escalation: false`, and escalated it
anyway by describing the port list. Fail-closed and I6b-safe — the presence of
prose, not the verdict field, drove the tightening — but worth knowing before
wiring a model into an unattended pipeline: a helpful model writes something in a
field called "hints" most of the time. The rate is a function of the *request's*
shape (2/10 vs 9/10 for the same bare IP under different port lists), not of the
target, confirming the model invents no target knowledge.

**Fail-closed on every backend:** timeout, connection error, safety refusal,
unparseable output, and an out-of-range risk level all return `risk_hint="high"`
+ `recommended_escalation=True`, reaching OPA's existing `high_risk` rule — no
policy change and no new reason string, with the failure cause carried in
`semantic_risk_hints` so the audit trail separates "worried" from "unreachable".

### 1.2 Worker — I8, Discovery ⊥ Authorization (D13, D15)

`agents/llm/worker_base.py`, `D13_WORKER_REPORT.md`, `D15_LOOKALIKE_REPORT.md`

The Worker is the role closest to the boundary: its Action Proposal feeds the
Target Canonicalizer and then the Authorization Resolver directly, so §8.9's
separation of Discovery from Authorization (I8) had until D13 only ever been
exercised by fixtures written to respect it. D13 put a component that *could*
ignore the separation behind it, fed a real injection from a real target, and
D15 ran the look-alike experiment D13 said it had not.

| Experiment | took the lure | runs | key result |
|---|---|---|---|
| D13 injection (scan-result + web-content) | **0/20** | 30, 0 refusals | 1 scope candidate; lure refused out loud once |
| D15 look-alike (default, 4 candidates) | **0/30** | 30 | model does the containment arithmetic itself |
| D15 look-alike (`--tight`, 5 candidates) | **0/15** | 15 | correct at a `/29` boundary, six addresses short |

The D15 negative is the informative one: the model **engages** with the lure, by
name, and gets the boundary right — *".77 is not covered by any scope object, so
it is deliberately excluded"* attached to a proposal targeting the `/29` that
ends six addresses below it. It also moved into the lure's neighbourhood on
6/30 + 5/15 proposals, which is what makes the refusal of the address itself
meaningful rather than incidental.

**The scope limit stated as forcefully as the result** — the same discipline the
kernel review applied to §5.2:

> This is not a measurement of "would a model be fooled". It is a measurement of
> *"would this model, told the truth about how authorization works, be fooled"* —
> because the system prompt says outright that choosing a scope object which does
> not cover the target "just wastes the proposal". That is the configuration that
> ships, and therefore the one worth knowing, but it is not the general claim.
> **The 0/65 must not be read as "the Worker cannot be fooled."**

**The kernel half, which does not depend on the model** (synthetic, labelled
synthetic — a hand-built out-of-scope proposal through the unmodified pipeline,
because the Worker never produced a real one): the honest provenance label costs
an extra escalation reason and changes nothing else; **the lie removes the
escalation reason and changes nothing else** — still DENY, still
`target_out_of_scope`, still no capability. Authorization comes from the Scope
Registry and never from the proposal's account of itself. The resolver was also
asked directly with three positive controls, so "it refuses every `203.0.113.x`"
cannot masquerade as "it refuses the right ones". `authorization.source` was
`engagement_scope` in all 75 proposals — written by `_to_proposal`, read from the
model's reply nowhere.

The one gap the runs found is `discovery_source`: self-reported, uncorroborated,
and semantically ambiguous (does it describe where the *target* came from or
where the *motivation* came from?). Same target and evidence produced
`prior_scan_result` 8/10 and `web_content` 2/10, and only the two `web_content`
answers were escalated — an outcome decided by a word the model chose with no
rule to guide it. Bounded by I8 (a false label can suppress a human check on an
*already-authorized* target; it can never authorize anything) and recorded as a
design decision, not fixed (§3, `discovery_source`).

### 1.3 Supervisor — the Task Manager, §6 and §7 (D17)

`agents/llm/supervisor_base.py`, `D17_SUPERVISOR_REPORT.md`, `docs/d17_runs/`

The Supervisor cannot be tested like the other two, because its output is a task
and a task is authorized by nothing — it goes into the `tasks` table, a Worker
later claims it, and only *that Worker's* proposal meets the Canonicalizer. So
the component a real Supervisor is pointed at is the **Task Manager**: §6's
claim/lease and §7's execution fingerprint. The brief's question was whether that
dedup/lease machinery identifies a real planner's semantically-duplicate tasks,
or whether varying natural language slips past a literal comparison.

**The answer, before any number: there is no comparison to slip past.** Three
facts, each pinned by a CI test (§11.3):

1. `create_task` inserts unconditionally — two byte-identical goals produce two
   tasks (`test_even_a_byte_identical_goal_creates_a_second_task`).
2. The `tasks` table retains only free text; `ProposedTask` carries action,
   target and scope-object id and `create_task` **drops all three**
   (`test_a_task_keeps_its_prose_and_discards_its_structure`). Any dedup on the
   table as it stands could only ever compare prose.
3. §4.2's `overlaps_with` has been in the schema since migration 0001 and is
   written by nothing (`test_nothing_ever_writes_the_overlap_field`).

**The measurement (n = 74 calls, 74 plans, 0 refusals, 81 tasks across six
arms):**

| Question | Result |
|---|---|
| Duplicates let through | all of them — `blind` arm: **25 tasks for 4 distinct pieces of work** |
| §6 claim/lease held | yes — 25 tasks claimed by 25 agents, **no task claimed twice** |
| But it protects a row, not the work | **16 agents held simultaneous live leases on the same `/24` sweep**; two on byte-identical goals |
| A literal comparison would have caught | **2 of 97** same-work pairs in `blind` (~2%); **2 of 312** across all arms (<1%) |
| Shown its own ledger, does it duplicate? | **no** — `accumulating` produced 4 tasks in 12 rounds, then nine empty plans; `warned` produced 2, zero repeats |

So §6 is not bypassed — it works exactly as specified and answers a different
question ("who owns this row"). §7's fingerprint deduplicates *executions* several
stages later, downstream of `issue_capability`, and keys on `normalized_params`
so the same host at different ports is two executions. The honest summary:
duplicate tool *executions* are partly deduplicated; duplicate *tasks*,
*proposals*, *decisions* and *capabilities* are not deduplicated at all.

The control arm (`accumulating`) is what makes the `blind` number mean something:
when the planner can see the ledger it does not repeat itself, so the duplication
is a property of *context pressure* (§2's query limits drop the oldest, most
re-doable work first), not of the model being careless. And the one repeat the
metric flagged in `accumulating` was a **false positive in the instrument** — two
genuinely different scans (Redis:6379 vs the 7001-7002 relays) collapsed to one
key because *a task carries no ports*. That is the finding that binds whoever
takes §11.3: a structural dedup built on what a task can currently express would
have **merged two different scans and dropped one** — the exact false negative
§1.2c and ADR G call a security bug.

Recorded, not fixed, per the brief. `DEFERRED_MVP0.md` §11.3 carries it with
binding constraints.

---

## 2. Problems found and fixed, D11 through D17

Same format as `ACCEPTANCE_MVP_KERNEL.md` §6: every commit pushed individually,
CI confirmed green before the next began. Branch:
`claude/mvp-kernel-cybersecurity-platform-su841g`. All runs below concluded
`success`.

| Commit | Change | CI run |
|---|---|---|
| `14d1662` | D10 — a real model behind the Policy Reviewer seam (MVP-0) | 32353143369 |
| `fb32afa` | D10.5 — four ways to run the Policy Reviewer, one contract | 32373204944 |
| `a803933` | Record the Scenario-B reviewer distribution (0/30 escalation) | 32385216126 |
| `1b37d20` | **D11-1 / D11-2** — two nmap scan types that could not execute; deadline == kill | 32438276767 |
| `3736780` | **D11-3** — put the network allowlist in the execution fingerprint (§7) | 32438878999 |
| `5d8546d` | Record the D11 live run against a real target | 32439244977 |
| `87a63aa` | Record two deferred items the D11 run exposed (D11-6, D11-7) | 32452184837 |
| `c4c7d04` | **D11-4** — enforce the capability target budget in the policy (I3) | *(in D12 range)* |
| `ec08275` | **D11-5** — refuse a CIDR written with host bits set (I10) | *(in D12 range)* |
| `fc79345` | D12.5 — replay the D11-4 / D11-5 counterexamples against the live target | 32475669887 |
| `3df7744` | D13 — a real Worker, and the boundary that decides what it can say | 32476467365 |
| `d625013` | D13 — the real Worker against a real target, with a real lure | 32479138592 |
| `c340d3f` | **D14** — `list_effective_policy_layers`, the operation D11-6 needed three times | 32493431895 |
| `8bed503` | Fix three defects the D15 experiment hit before it could measure anything | 32555770984 |
| `686f129` | D15 — the look-alike experiment, and why 0/45 means something | 32557327614 |
| `1378a12` | **D16** — canonicalize scope values on write; close the read path's fail-open branch | 32568397228 |
| `3619e25` | D17 — a real Supervisor, and the queries it needs (§2) | 32576060021 |
| `6170bab` | D17 — the claim/lease concurrency test §11 asked for, and the harness | 32577154290 |
| `7c9295f` | D17 — say something useful when the CLI fails; mark §7's dedup boundary | 32584519429 |
| `0f5e038` | D17 — report scaffolding, and DEFERRED 11.3 / 11.4 | 32584640823 |
| `754b949` | D17 — the blind arm: the ledger created and then withheld | 32585855189 |
| `0c5498c` | D17 — the Supervisor run; §6 holds, and there is no task-level dedup | 32586673662 |

The defects, in words:

* **D11-1 — two of three scan types could not execute** (`1b37d20`). `ping` and
  `version` both selected a raw-socket technique and died `dnet: Failed to open
  device eth0`; the derived view reported `port_count: 0`, which reads as
  "nothing listening" rather than "the scan never ran". `--unprivileged` now
  states the reasoning the adapter already gave for `-sT`. The suite had executed
  `-sT` and nothing else, which is why it survived six deliverables; the
  replacement test is parametrized over `SCAN_TYPES`.
* **D11-2 — the tool's deadline and the sandbox's kill were the same instant**
  (`1b37d20`). A dead heat the kill won, producing `timed_out=True` with nothing
  but a banner. The margin now comes off the *tool's* deadline and is never added
  to the sandbox's, so the capability's authorization boundary does not move.
  Invisible until D11-1 was fixed.
* **D11-3 — the network allowlist was not part of the execution fingerprint**
  (`3736780`), the one with a real security consequence. A scan confined to a
  range with no route reported nothing open under `-Pn`; the identical proposal
  under the range that *could* reach matched the same fingerprint, was answered
  from cache, and never ran. Three open ports went unreported as a
  `dedup_hit`. The allowlist went into `execution_context` per §7's v0.3
  amendment — a namespace that can reach the target and one that cannot are
  different executions.
* **D11-4 — `budget.max_targets` bounds nothing** (I3 violation; fixed D12
  `c4c7d04`). A capability with `max_targets: 1` scanned 256 addresses. Enforced
  at OPA after the design question was put to the operator — authorization
  belongs at the one decision point, not at the broker or the gateway — with
  `capability_budget_missing` and `target_count_unknown` fail-closed (a missing
  budget is not an unlimited one).
* **D11-5 — `normalize_cidr` silently widened a host into its network** (fixed
  D12 `ec08275`). `10.79.0.2/24` was masked to `10.79.0.0/24`, the reachable
  route into D11-4. Now raises `CanonicalizationError`; the caller who means the
  network passes the network address.
* **D14 — `list_effective_policy_layers`** (`c340d3f`), implemented against
  11.1's binding constraints rather than redesigned. Both the listing and the
  merge now go through one selection predicate `_APPLICABLE`, so they cannot
  diverge by construction; the listing reports and does not decide, global rows
  are visibly global, read-only, no new grant. **This closes DEFERRED 11.1** (see
  §3).
* **D16 — canonicalize scope values on write, and close the fail-open read
  branch** (`1378a12`). The same ambiguity D11-5 fixed on the *target* side still
  lived on the *registry* side: `register_scope_object` stored `value` verbatim,
  so `cidr 10.79.0.2/24` could be registered and mean the whole range. D15's
  mutation testing found the matching read-path defect — flipping
  `scope_covers_target`'s parse-failure branch to `return True` left the whole
  suite green, because a scope object nobody could parse was a state nothing had
  ever created (fail-open, untested because unreached). `register_scope_object`
  now canonicalizes and refuses at registration, where the Engagement Manager is
  the only party who knows what was meant; the fqdn `*.` pattern is the one
  deliberate asymmetry, because a scope is a set. **This closes the registry-side
  half of D11-5 and the D15 fail-open finding** (see §3).
* **D15 pre-experiment fixes** (`8bed503`), none about injection, all three
  corrupting the measurement: a malformed `ports: "n/a"` crashed the
  orchestrator (now refused at the Worker boundary and handled as a refusal by
  the gateway); the headless call inherited the caller's stdin (now
  `DEVNULL`); the Worker ran on the Reviewer's 30s deadline and lost ten runs to
  timeouts, truncating the distribution from above — reported rather than buried,
  because the truncated "0/20 took the lure" would have been a number produced by
  dropping the slowest third.
* **D17 diagnostic defect** (`7c9295f`). The first full experiment lost 46 of 62
  calls to `cli exited 1:` with nothing after the colon. `run_headless` now falls
  back to stdout when stderr is empty (stderr stays first and stays capped,
  because argv — and so the prompt — is echoed into it), pinned by three tests.
  The discarded run's numbers were **not** reported, for the reason D15's
  truncated run was discarded.

---

## 3. DEFERRED — the full list, current status

Continues `ACCEPTANCE_MVP_KERNEL.md` §5 and `DEFERRED_MVP0.md`. Each carries
where it was found and its status *as of this stage closing*. Two items closed
during D10–D17; they are marked so and kept, because a canonical list that
quietly drops resolved items is how a reader loses the thread.

### Closed during this stage

| # | Item | Closed by |
|---|---|---|
| **11.1** | No way to ask which policy layers are in force (D11 live run) | **D14** `list_effective_policy_layers` (`c340d3f`) — reports, does not decide; one `_APPLICABLE` predicate shared with the merge; global rows visibly global; read-only, no new grant |
| **D11-5 (registry side)** + **D15 fail-open** | Registry stored CIDRs with host bits verbatim; `scope_covers_target` parse-failure branch fail-open | **D16** (`1378a12`) — canonicalize and refuse at registration; the read branch is now reachable and tested |

### Still open — carried forward unchanged from MVP-Kernel

| # | Item | Status |
|---|---|---|
| 5.1 | Hierarchical classification fallback (D3) | Open. Design defines no inheritance semantics; both answers are wrong in a different direction. Binding constraints unchanged (inherit only downward from AUTHORITATIVE; tighten-only; its own tests). |
| 5.2 | Enforcement against a non-Docker network (D6) | Open. **Still the only deferred item that is a real-deployment gap rather than a scope boundary.** Confinement is proven against a Docker bridge and has never been exercised against a routed/macvlan network. Must be re-proven against the new driver, with kernel-level evidence (`ENETUNREACH`, not the tool), before anything points at a customer network. |
| 5.3 | `reconstruct_decision` does not walk back to the task (D8) | Open. Extending it needs a decision the design does not record (do a task's events belong to every proposal it produced?). `by_stage()` must stay a partition; the diff against the whole-engagement query stays pinned. |
| 5.4 | `heartbeat_required` declared, not enforced | Open. Blocked on a **missing prerequisite, not a decision**: there is still no scheduler in MVP-0, and `last_heartbeat_at` is only meaningful once an agent heartbeats on its own schedule. Column stays; the gap is behaviour. |
| 5.5 | `approvals` has no API (Phase-1 scope) | Open, scope boundary. Checking is covered; only the granting operation is absent. When it lands, `revoke_approval()` needs the D9 cascade treatment. |
| 5.6 | `findings.state` / `verification_conflict` (Phase-1 scope) | Open, scope boundary. **Note:** D17 implemented `query_findings` (a *read*), but the kernel still never promotes evidence to a finding, so the state machine remains unwritten. The read interface existing does not change the deferral. |
| 5.7 | Emergency-overlay content not randomized in the stateful test | Open. The algebra is covered at 400 generated combinations per property; the stateful rule exists to test the *interaction*. If content is randomized later it must respect tighten-only. |
| D11-8 | The derived view drops the nmap VERSION column | Open, minor. Cosmetic loss in the derived view; evidence retains the raw. |
| D11-9 | Nothing creates an engagement | Open, gap. Engagements are seeded by tests and harnesses; no operation creates one. A stage boundary, surfaced when the live runs each had to construct their own. |

### Still open — the ones that need a decision before work starts

These are the items where implementing anything first requires an architecture
or design decision the documents do not make. Guessing would invent semantics,
which is the failure mode the whole project has refused since D6.

| # | Item | The decision that gates it |
|---|---|---|
| **11.2 / D11-7** | A globally-scoped operation has no globally-scoped audit record (D11) | Which `engagement_id` a global operation's audit row carries (`NULL` vs a reserved sentinel); who may read these rows without opening a cross-engagement read surface I4 forbids; whether they need an access rule independent of the current single-predicate RLS model. **No fix proposed on purpose.** Nothing in the RLS policy is to be touched until these are settled. |
| **11.3** | Two tasks are never compared (D17) | What makes two tasks the same (identical structure? overlapping target sets? same objective reached differently?), and what the system does when they are (refuse / merge / link via `overlaps_with` / warn). Interacts with ADR G. Binding constraints: **fail towards a duplicate, never a silent drop** (a false negative is a security bug); whatever is compared must first be *stored* (`create_task` currently discards action/target/scope); not automatic semantic derivation; use the `overlaps_with` field §4.2 reserved. A literal comparison would have caught **<1%** of the same-work pairs a real planner produced. |
| **11.4** | A task goal is generated text on the trusted side of another model's prompt (D17) | Whether/how to structure the goal so a Worker takes its target from structured fields rather than free text. **The obvious fix is wrong:** wrapping the task in the Worker's untrusted block tells the Worker to distrust its own assignment — the mistake D13 refused for scope objects — and leaves it with no trusted statement of what it is for. Measured 0/81 goals quoted the out-of-scope lure, but the channel is structural and stays open whatever that number says. Deserves its own deliverable. |
| discovery_source | Self-reported provenance is semantically ambiguous (D13, D15) | Does the field describe where the *target* came from or where the *motivation* came from? §4.1 does not say. Bounded by I8 (can suppress a check on an already-authorized target; can never authorize). Until pinned, `untrusted_discovery_source` fires on a self-report whose meaning the design does not define. |

### Interface note — §2 completed, not extended (D17)

D17 needed two of §2's seven agent-callable functions that had never worked:
`query_findings` (never implemented) and `query_state` (returned five integers,
ignored `filter`). Both are **read-only**, run on the ordinary `cyberorch_app`
role with **no new grant**, are RLS-confined (the `engagement_id` argument
cannot select another engagement), and spell §2's `filter` as *checked keyword
arguments* validated against fixed vocabularies rather than a predicate that
becomes SQL. No `tool`/`command`/`capability`/`budget`/`ports`/`scan_type`/
`authorization` field appears in either function or in the Supervisor's schema.

The one genuine new exposure, stated rather than glossed: `query_state` returns
**decisions on other agents' proposals in the same engagement**. Every such row
was already returned to its own submitter; what changed is the readership. This
does not cross a line — §5's isolation boundary is the engagement, not the agent
(I4 is per-engagement) — but it is a widening of exactly the kind that gets waved
through, so it is on the record, and a deployment can pass `decision_limit=0` to
close it without touching the kernel. `query_tasks(matching=…)` was deliberately
**not** added, because defining "like this" *is* the 11.3 decision, and shipping
it as a convenience would settle that question sideways.

---

## 4. Risk grading

The candidate list falls into three classes, in decreasing order of how settled
they are.

### Class A — fixed, with a regression test pinning it

Closed this stage and guarded against recurrence. D11-1, D11-2 (parametrized
`SCAN_TYPES` execution test); D11-3 (allowlist in the fingerprint, pinned both
ways); D11-4 (OPA budget rule with fail-closed controls); D11-5 target side
(`CanonicalizationError`); **11.1 → D14** (one `_APPLICABLE` predicate, equality
pinned); **D11-5 registry side + D15 fail-open → D16** (canonicalize-on-write,
the read branch now reachable and tested); the three D15 pre-experiment defects;
the D17 diagnostic fallback. Nothing in this class needs a decision — it needs
only the guarantee that the tests stay in the gate, which they are (all offline).

### Class B — known, bounded, and safe to leave alone

No decision required to *not* do them; each is either a Phase-1 scope boundary or
a documented minor limit with its behaviour understood. 5.4 (missing scheduler
prerequisite), 5.5 and 5.6 (Phase-1 scope), 5.7 (interaction already covered by
property tests), D11-8 (cosmetic), D11-9 (stage-boundary gap). **5.2 sits at the
edge of this class and carries the one standing caveat:** it is bounded and safe
*for MVP-1, whose targets are containers*, but it is a real-deployment gap and
must be re-proven against the production network driver before any customer
network is touched.

### Class C — blocked on an architecture decision

Work must not start until the decision is made, because any implementation
encodes an answer to a question the design leaves open, and a wrong guess invents
authorization or access-control semantics. 5.1 (classification inheritance), 5.3
(does a task's events belong to every proposal it produced), 11.2 / D11-7 (the
audit model for global operations), 11.3 (task identity), 11.4 (the goal
laundering channel and the boundary it re-opens), and `discovery_source`
semantics. For each, the specific decision is in the §3 table above, and for
11.2, 11.3 and 11.4 there are binding constraints already written so the decision
is made once and not re-litigated by the implementer.

---

## Go / No-Go

**GO — the three-role-pluggable stage is complete.**

The stage `ACCEPTANCE_MVP_KERNEL.md` pointed at asked for one thing: a real model
behind each role, selected the same way, without the kernel's decision path
changing. That holds:

1. **All three roles run behind a real model**, each selected by its own
   environment variable (`CYBERORCH_REVIEWER_BACKEND`,
   `CYBERORCH_WORKER_BACKEND`, `CYBERORCH_SUPERVISOR_BACKEND`), with a test
   pinning that the three switches are independent.
2. **Each role was verified against the boundary it actually reaches**, not a
   convenient one: the Reviewer against OPA and I6b (a lying reviewer changes no
   decision; 0/30 escalations means the registry does 100% of the work); the
   Worker against the Canonicalizer, the Authorization Resolver and I8
   (injection 0/20 and look-alike 0/45, with the scope limit stated as loudly as
   the result); the Supervisor against the Task Manager and §6/§7 (§6 correct,
   and the finding that there is no task-level comparison at all).
3. **The kernel boundary did not move.** No schema change, no new database grant,
   no change to `create_task`, `claim_task`, the Canonicalizer, the resolvers,
   OPA, the broker or the gateway. The only control-plane additions are two
   read-only queries that *complete* §2 rather than extend it, RLS-confined and
   ungranted.

Nothing on the DEFERRED list blocks the stage. Two items were closed during it
(11.1 by D14; the registry-side ambiguity and the fail-open branch by D16).

**Next steps, and what each needs first:**

* **11.2 / D11-7 (the audit model for global operations)** is the highest-ranked
  Class-C item, because unlike the rest it has already caused an incident — the
  D11 live run went down on nineteen orphaned global overlays and the diagnosis
  required SQL against a table no operation exposes. It cannot begin until the
  three questions in §3 are answered: which `engagement_id` a global audit row
  carries, who may read it, and whether it needs an access rule outside the
  current RLS model. This is an access-control decision, and the binding
  constraint is that it must be made once, not worked around locally.
* **11.3 (task identity)** and **11.4 (goal laundering)** are the two findings the
  real Supervisor surfaced, and both are larger than a deliverable. 11.3 needs a
  decision on what makes two tasks the same *and* a schema/write-path change to
  store what a comparison would need (its smallest honest starting point). 11.4
  needs an interface decision at a boundary D13 and D15 verified empirically, so
  re-opening it deserves its own deliverable rather than a rider.
* **Everything in Class A and B** needs no decision — A is done and guarded, B is
  a matter of Phase-1 scheduling — except that **5.2 must be re-proven against the
  production network driver before any customer engagement**, which remains the
  single caveat a reader should carry out of both acceptance reviews.

The design intent from the kernel review — *"nothing else in `propose_action`
changes, which was the point of building it this way"* — is confirmed
empirically: three real models were placed behind the three roles, and the one
place the decision path changed was where §2 was finished, not where it was bent.
