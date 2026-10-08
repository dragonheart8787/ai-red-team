# D61 — Just-in-time capability issuance (D58-8)

**The gap.** `grant_approval` wrote an `approvals` row and issued a 60-second capability, then
returned. Nothing in `control_plane/` or `agents/` dispatched it: an approved proposal was a
capability ageing out of its lease with nothing to use it. D58 found, separately, that a
capability's lease is anchored to the transaction that issues it (3 s TTL + 4 s of waiting = born
expired). One cause under both: **the capability was issued when the decision was made, not when it
was used.**

**The fix.** Issuance moves to the moment of dispatch. `grant_approval` records one fact — *a human
approved this proposal* — and no longer issues anything. A new explicit call,
`dispatch_approved(engagement_id, proposal_id, …)`, re-runs the broker's checks, issues the
capability at that instant, and dispatches immediately, through the same stage functions an ALLOW
uses. Not a scheduler, not a reconciler, and no credential selection (§5).

---

## 1. The state: *approved, awaiting dispatch*

D60's stage column gained two stages (migration `0017`):

```
 received → decided ───────────────→ capability_issued → dispatching → recorded
    │          │                            ↑                │
    │          └→ closed (DENY)             │                └→ closed
    └→ awaiting_approval → approved ────────┘
              │
              └→ closed   (denied by a human: stage_detail 'approval_denied')
```

* **`awaiting_approval`** — the decision was HUMAN_APPROVAL; no human has answered. Before D61 this
  proposal was `closed`, which was true of the *run* and false of the *request*.
* **`approved`** — **awaiting dispatch.** The `approvals` row and the stage commit in one
  transaction; `stage_detail` holds the `approval_id`; **no capability exists**. This is the state
  the brief asks to be externally queryable.

**Queryable the way D60's stages are** — committed state, no code needs to run to read it:

```sql
SELECT proposal_id, stage_detail AS approval_id, stage_updated_at FROM action_proposals
WHERE pipeline_stage = 'approved';
```

and `approved_dispatch.list_approved_awaiting_dispatch(conn, engagement_id, older_than_seconds=None)`
returns, per proposal, who approved it and when, `waiting_seconds`, and `approval_live` (false once
the approval expired or was revoked — a dispatch attempt would then be refused, so the proposal needs
a human, not a retry). `scripts/approvals.py awaiting-dispatch [--older-than N]` is the CLI form.

**What D58-9's reconciler will be able to recognise, with no reconciler written:**

| Situation | What the committed rows say |
|---|---|
| nothing ever triggered the dispatch | `approved`, `stage_updated_at` old, `approval_live` true |
| the approval lapsed while waiting | `approved`, `approval_live` false |
| a dispatch attempt died before its transaction committed | **`approved`, unchanged** — the issue stage rolled back whole (tested: `…failed_before_it_committed_leaves_the_proposal_waiting_and_retryable`) |
| it died after the capability committed | `capability_issued` (D60's stage; see §6 for its residual) |
| it died with the container started | `dispatching` (D60: `reconcile_stale_dispatches` finds it) |

"Attempt failed" and "nothing triggered it" both read as *waiting*, deliberately: no failure counter
was added — that is the ladder (D58-6), which is not this deliverable.

## 2. How the post-approval dispatch works

`dispatch_approved` is a thin builder: it reads the approved proposal back from committed rows (the
proposal, the approval named in `stage_detail`, the facts the decision stage established), builds a
`_Run`, and calls `function_api._drive` — the D60 driver. `_drive` sees stage `approved` with the run
marked as the post-approval one and calls **the same `_issue`**, which takes `approved →
capability_issued` instead of `decided → capability_issued` and passes the broker three extra
things: `approval_id`, the constraints the approval record describes, and `expected_policy_version`.
`_dispatch` and the `dispatch_*` functions are unchanged.

**Checked at the moment of use** (all by the broker, in the issuing transaction, none at the grant):
engagement active, kill switch, **approval valid and unexpired**, scope object still standing and
still allowing the action, and **policy unchanged since the decision**.

* The last is new (`issue_capability(expected_policy_version=…)`, an optional argument that reuses the
  broker's existing `POLICY_CHANGED` check). The decision stage now records the version in force
  *before* the reviewer and OPA ran (`action_proposals.decided_policy_version`), so a policy published
  while they ran makes the recorded version older than the world, never newer. An approval is a human
  saying yes to *that* decision under *that* policy (I9); if the policy moved, the operator re-proposes.
  This is a **choice** — it makes an approval more perishable than the one-hour `valid_until` alone
  would. Left out, nothing is compared, which is right for ALLOW, where decision and issue are moments
  apart.
* A refusal **closes** the proposal with `capability_refused:<reasons>` and the outcome is a DENY — the
  same handling as an ALLOW whose issue is refused. Fail-closed; no side-door retry.
* The approved capability is issued with `Budget(max_duration_seconds=120)` and the proposal's
  requested TTL (default 60), as before — what changed is *when* its lease starts.

**What the caller still supplies.** `sandbox`, `network_allowlist`, `execution_context`, `proxy_*` are
runtime context, not facts about the proposal, and are not stored; the orchestrator passes them at
dispatch as it does to `propose_action`. (The `web.post` body *is* stored with the proposal — it
survived the round trip, `test_the_approval_route_carries_and_describes_the_same_body`.)

**Not a side effect of asking again.** `propose_action` with the same `idempotency_key` on an approved
proposal reports it and does not dispatch (the post-approval stage is driven only when the run is built
by `dispatch_approved`). Calling `dispatch_approved` twice dispatches once: the second finds the stage
moved on and reports the first's run. Two concurrent dispatchers run the tool once (conditional UPDATE).

## 3. Callers and what stayed the same

* `control_plane/web/app.py` `post_approve` and `scripts/approvals.py approve` call the unchanged
  `grant_approval`; their output changed. The console returns `{"approval_id", "proposal_id",
  "approved_scope", "stage": "approved"}` (no `issued`/`capability_id` — nothing was issued). The CLI
  prints that the approval is recorded and the proposal is awaiting dispatch, exit 0 (it used to exit 3
  when "the broker did not issue", a state that can no longer arise at grant time).
* **Unchanged (D24):** the structured §4.7 approval object, `approved_scope`, the audit record
  (`approval.granted`: who, when, scope, proposal), `list_pending_approvals`, `preview_approval`
  (preview and grant still share `approval_fields`, and a test compares them), every refusal
  (unknown scope, not escalated, already approved, already denied, authorization no longer holds).
  Only capability issuance timing changed.
* New: a second approver now loses cleanly (the stage transition is the first statement of the grant);
  a denial closes the proposal (`approval_denied`) and writes its provenance.
* Migration back-fill: a HUMAN_APPROVAL proposal that was pending becomes `awaiting_approval`; an
  already-approved or denied one stays `closed` — the old path issued (or not) at grant time, and
  re-opening it would let an old approval be dispatched. No old approval is resurrected.

## 4. Verification

**4.1 The D58 scenario, on the approval path.** A proposal asks for a 3-second capability; the grant
happens; 4 seconds pass; `dispatch_approved` runs.
(`test_a_three_second_capability_is_not_born_expired_after_a_four_second_wait`)

| | issued at | lease | at dispatch time (+4 s) |
|---|---|---|---|
| **old path** (reproduced by putting issue-at-grant back and calling `dispatch_scan` on that capability) | grant | grant + 3 s | **expired** (`lease_expires_at < now()`, age 4.0 s) → refused `capability_not_live`, 0 sandbox calls, no run |
| **JIT** | dispatch | dispatch + 3 s | **live**: `issued_at − approvals.created_at ≥ 3.9 s` (database clock), `issued_at ≤ run.started_at ≤ lease_expires_at`, the tool ran |

The test also asserts the arithmetic the old path could not survive (`approved_at + 3 s <
run.started_at`). **W1** (D58: issue → dispatch) measured from the database's clocks after a 3 s wait:
`run.started_at − capability.issued_at < 1 s`, `capability.issued_at − approval.created_at ≥ 2.9 s` —
the lease no longer spends the human's wait (`test_the_issue_to_dispatch_window_is_close_to_zero`).

**4.2 End to end — the gap itself.** `test_an_approved_proposal_runs_a_tool_writes_evidence_and_leaves_a_complete_trail`,
through the real entry points (`propose_action` → HUMAN_APPROVAL → `list_pending_approvals` →
`grant_approval` → `list_approved_awaiting_dispatch` → `dispatch_approved`):

1. After the proposal: stage `awaiting_approval`, listed as pending, not as awaiting dispatch.
2. After the grant: stage `approved` with the approval id, **zero capabilities, no `capability.issued`
   event**, listed as awaiting dispatch with approver and `approval_live`.
3. After dispatch: the tool ran once; `tool_runs` `succeeded`/exit 0 on the capability; one `evidence`
   row for that run; stage `recorded`/`succeeded`; the capability carries the `approval_id`, ports 443 and
   scan type `version` as proposed, and `{k: v ≠ host}` equals the §4.7 record's `constraints`.
4. Audit trail, ordered by id across proposal, capability and run: `proposal.submitted` → `policy.decided`
   (reviewer's sensitive-data hint recorded) → `approval.granted` (actor alice) → `capability.issued`
   (payload `approval_id`) → `tool_run.started`; each approval/capability event exactly once.
5. Provenance written from the committed rows: scope_object→proposal *authorized*, proposal→capability
   *issued*, capability→run *executed*, run→evidence *produced*; `provenance_complete`.
6. Nothing waiting afterwards; `assert_coherent` (D60) holds.

`test_the_same_story_with_a_real_container` runs the same chain with the real `DockerSandbox` and the real
nmap image against a host that does not answer: a real container, a real network, a run row and an evidence
row — the point being that the approval path reaches the *real* dispatch, not that the scan found anything.
The first uses `FakeSandbox` for the container; the second does not.

**4.3 One stage-commit logic.** Three independent checks:
*behaviour* — every conditional UPDATE is recorded for an ALLOW and for an approved proposal: after the
decision both take exactly `capability_issued → dispatching → recorded`, each transition won, and the
issuing transition differs in one thing, its source (`decided` vs `approved`); *structure* —
`dispatch_approved`'s source contains no SQL write, no `commit`/`begin`, no `stages.take/advance`, no
`issue_capability`, no `record_audit`, and calls `function_api._drive`; *boundary* — `approved` and
`awaiting_approval` are not in `stages.BEFORE_DISPATCH`, so a hand-written caller cannot reach
`dispatching` from them without being issued first. D60's `assert_coherent` was extended: `approved` ⇒ an
approval row exists and no capability; `awaiting_approval` ⇒ neither; a capability ⇒ the proposal was ALLOWed
*or approved*.

**4.4 Mutation checks** (each reverts one guard; the suite must go red):

| Mutation | Result |
|---|---|
| issue at grant again, as the old `grant_approval` did | 10 tests red (end-to-end, every refusal-at-use test — the grant-time capability masks them — the retry, double-dispatch and re-propose guards) |
| policy version not handed to the broker | `…policy_published_after_the_decision_invalidates_the_approval` red |
| stage transitions unconditional | `…two_dispatchers_at_once_run_the_tool_once` red (two capabilities) |
| HUMAN_APPROVAL closes the proposal (D60 behaviour) | end-to-end red |
| denial no longer closes | `…denied_proposal_is_not_dispatched_and_is_closed` red |

The 3 s/4 s test does not go red under "issue at grant", and could not: that mutation leaves the JIT issue in
place, so the test measures the JIT capability. The old failure is shown instead by §4.1's reproduction.

## 5. ad.collect and the credential path — unchanged by JIT

D58 §5: the HUMAN_APPROVAL path and the credential path are incompatible — an approval names no
`credential_id`, the approved capability is credential-less, and `dispatch_collection` refuses an
`ad.collect` without one (D50 F1, `unbuildable_plan`). **JIT does not change this**, because it moves
*when* the capability is issued, not *what* it carries. Confirmed through the real entry points
(`test_ad_collect_after_approval_is_still_refused_because_the_capability_has_no_credential`): an
escalated `ad.collect` proposal is approved and dispatched; the capability **is** issued (nothing upstream
objects; `credential_id` NULL, `approval_id` set), `dispatch_collection` refuses it before any container
exists (`failure == unbuildable_plan`, no run row, the recording sandbox never constructed). A credential
handed to the *escalated* `propose_action` call is not carried to the approval; nothing stores it.

I did **not** thread a caller-supplied `credential_id` into `dispatch_approved`, though it would be four lines
and would make the test above fail. The approval preview a human sees names no credential, so letting the
dispatcher choose one at use time would spend a credential on an approval that never mentioned it — that is
D58-15's question (who selects the credential, and what a human sees before agreeing), and ACCEPTANCE **5.57**
records it as a candidate there. The pinning test is written so that whoever answers D58-15 fails it for the
right reason and rewrites it.

## 6. What this does not do, and what is left

* **No caller exists in production.** `dispatch_approved` is called by nothing but tests; the orchestrator
  (D58-1..4) will call it. Until then an approved proposal waits at `approved`, now visibly (§1) rather than
  as a dead capability.
* **A crash between the issue and the dispatch** leaves `capability_issued` with a short-lived capability. A
  resumed `dispatch_approved` finds that stage and dispatches the capability it has; an expired one is refused
  (`capability_not_live`, the same refusal §4.1's reproduction shows) rather than re-issued. Safe, wasteful; the approval has been spent on a
  capability nobody used. The window is a stage hand-off (measured < 1 s above), and what to do about it —
  reissue on resume — is the reconciler's (D58-9). Not built.
* **No reconciler, scheduler or failure ladder** (D58-9, D58-1..4, D58-6): the state is *recognisable*, and
  nothing acts on it.
* **The policy-version check is conservative** (§2): any policy layer published for the engagement after the
  decision refuses the dispatch, including ones that only widen. A finer rule ("widening is harmless") is a
  policy decision, left as the broker already treats it for heartbeats.
* **`approved_scope` (`this_task`, `this_resource`) still only records the operator's intent.** Nothing yet
  lets one approval cover a second proposal; each approved proposal is dispatched individually.
* Standing from D60 and untouched: the kill switch does not stop a running container (D44-7 / D58-16);
  ACCEPTANCE 5.54/5.55 (two unexecuted live-run scripts) are unaffected — neither touches the approval path.

## 7. Files

`db/migrations/versions/0017_approval_stages.py` (stages, `decided_policy_version`, back-fill) ·
`control_plane/orchestrator/stages.py` · `control_plane/state/models.py` · `control_plane/capability/broker.py`
(`expected_policy_version`) · `control_plane/api/function_api.py` (`_decide`, `_issue`, `_drive`, `_JitIssue`) ·
`control_plane/api/approved_dispatch.py` (new: `dispatch_approved`, `list_approved_awaiting_dispatch`) ·
`control_plane/api/approvals.py` (`grant_approval`, `deny_approval`, `ApprovalOutcome`) ·
`control_plane/web/app.py`, `scripts/approvals.py` · tests: `tests/test_approved_dispatch.py` (new, 23),
`tests/test_approvals.py`, `tests/test_web_console.py`, `tests/test_web_post_body.py`,
`tests/test_pipeline_stages.py` (coherence rules).
