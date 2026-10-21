# D68 S5 -- Q1 wired into `propose_action`, behind its own switch

Plan: `docs/D68_IMPLEMENTATION_PLAN.md` section 6. Design: `docs/D68_REVIEWER_SEMANTIC_VALIDATION_DESIGN.md`
sections 1.3 (Q1), 4 (data flow and signal). ACCEPTANCE 5.118; 5.120 is the precedent for the fault-injection method.
Claims are tagged [R] read, [E] executed, [D] derived, [N] not established.

**What S5 is:** the validator built in S4 is now asked, once per proposal, when the proposal is its task. Its answer is
stored beside the task relation, audited, and replayed at the approval re-derivation. A second policy switch,
`goal_fit_enforce`, lets the answer ask for a human. **The switch is off everywhere, and the default validator is the
honest fake** (everything `plausible`), so nothing in the repository changes a decision. S8b enables.

## 1. The hard requirement, and how it is met

> The control plane must call the validator inside `try/except Exception`; any unexpected exception, not only the known
> API-level ones, becomes `not_assessed` and never propagates out of `propose_action`. It needs a dedicated fault-injection
> test, in the manner of the 5.120 verification, showing the proposal state stays coherent and can be retried or reclaimed.

* **One call site, one guard.** `control_plane/plan_fit/goal_fit.py`: `_ask` is the only place a validator's `assess` is
  called, `assess_goal_fit` is the only caller of `_ask`, and the call sits in `try ... except Exception`. Everything about
  the validator is touched inside `_ask`: the answer, its `calls` record, its `provenance()`. Not only the call. [R]
  `test_the_validator_is_called_from_one_place_and_inside_except_exception` pins this by AST (one call, one caller, the
  handler names `Exception`, neither a bare `except` nor `BaseException`).
* **What an exception becomes.** `not_assessed` / `failed`, with the exception's **class name** (not its message) in the audit.
  The decision is then made by the policy: switch on -> `plan_check_failed` (a human); switch off -> unchanged.
* **An answer that is not a valid one is the same thing.** `None`, a dict, a string, a number, a tuple, an object that only
  looks like an assessment, an assessment whose attributes raise when read -- and `disabled` / `not_applicable`, which are
  the *system's* to say: a validator that says them would otherwise make its own answer quiet. All `failed` / `invalid_answer`.
* **Not caught, on purpose:** `BaseException` that is not an `Exception` (`KeyboardInterrupt`, `SystemExit`). A process asked
  to stop must stop; the proposal is then left as every interrupted proposal is (below).

### The injection (in the manner of 5.120)

The sandbox is a **trap that raises if it is reached**, so that "an action ran although its plan check failed" is a red test,
not a silent pass. The validator raises when touched. [E]

| injection | what the tests assert | result |
|---|---|---|
| 15 exception types from the validator (`RuntimeError`, `KeyError`, `IndexError` -- the 5.120 one --, `ZeroDivisionError`, `AssertionError`, `ValueError`, `TypeError`, `AttributeError`, `OSError`, `TimeoutError`, `MemoryError`, `RecursionError`, `UnicodeDecodeError`, a class nothing has heard of, a bare `Exception`), switch on | `propose_action` returns; `HUMAN_APPROVAL` with exactly `plan_check_failed`; sandbox calls 0; stored `not_assessed/failed`; audit `error_type` is the class name and the message is **not** in it; `assert_coherent`; stage `awaiting_approval` | pass |
| the same, switch off (4 types) | `ALLOW`, runs once, stage `recorded`, coherent | pass |
| 8 garbage answers (above), switch on | `HUMAN_APPROVAL` / `plan_check_failed`, sandbox 0, audit `invalid_answer`, coherent | pass |
| a `calls` property that raises; a `provenance()` that raises; no `provenance` at all | broken record -> `failed`; broken/absent provenance -> left out of the audit, **the answer stands** | pass |
| a task that cannot be read | `failed` / `task_unreadable`, validator not asked | pass |
| an adapter whose own guard is broken (a `BasePlanFitValidator` subclass that raises `KeyError`) | the control plane's guarantee does not rest on the adapters' promise | pass |
| retry of a decided request whose validator raised | one proposal, validator asked once, one audit event | pass |
| a proposal held by a failed check, then approved | dispatches once, with the reason that was shown; validator not asked again | pass |
| **`BaseException` (not an `Exception`) from the validator** | propagates (as intended); proposal `received`, coherent, no `policy.decided`, no capability, no run, sandbox 0; **a retry under the same key decides and runs it exactly once**; with no retry, the **reconciler's state-only pass** abandons it as `undecided_past_grace` | pass |

The last row is the same shape as the 5.120 trace: uncaught, left at `received`, retried to completion once, reclaimed by the
reconciler, nothing executed. [E]

### A real hole this found (and fixed)

`relation.policy_signal` -- the S3 function both policy callers use, documented as "never raises" -- tested set and dict
membership on stored values. A damaged row holding a **list** (unhashable) as `task_relation` raised `TypeError`. It would
have escaped from the approval re-derivation. Fixed (operands must be strings first) and pinned by a grid over 13^4 junk
combinations (`test_the_replay_never_raises_whatever_a_damaged_row_holds`) and mutation `S5-t`. [E] The S3 claim "never
raises" was false until now.

## 2. What was built

* **Wiring** (`function_api._decide`): the task's goal/action/target are read **by the control plane from the task row**, in
  the same read as P1, only when the validator exists and the relation is `matches_task` -- the proposal's own words
  never reach the validator (a test puts a prompt-injection string in the proposal's `reason` and checks it is in none of the
  five strings). The model call happens with **no transaction held**, after the Reviewer's opinion and before OPA.
* **Stored/audited:** `reviewer_hints["plan_fit"]` gains `goal_fit` and `goal_fit_cause` (JSONB, no migration); the one
  `plan_fit.assessed` event carries both halves, plus `validator_id`, an **input digest** (sha-256 of the five strings -- the
  goal's text is not copied into the audit), the validator's provenance (id, model, backend, prompt hash) and its call record
  (latency, tokens).
* **Not asked** when the proposal is not its task (`no_task`, `differs`, `task_not_live`): `not_applicable`. With no validator
  configured: `disabled`. Both are quiet.
* **Policy:** `goal_fit_enforce` -- same algebra as the first switch (neutral false, OR-merge, boolean-only publication, overlay
  may only say `true`); `ENFORCE_SWITCHES` names both and every place that handles one handles both (a test checks each
  is a field of the layer and the effective policy; `_combine` carries it). Rego, in `approval_reasons` only: `plan_implausible`,
  `plan_unverified`, `plan_check_failed`. `plausible`, `not_assessed/disabled`, `not_assessed/not_applicable` and an absent
  `goal_fit` fire nothing. Anything else present -- `failed`, a missing or odd cause, `unrecognized` -- is a check that did not
  succeed and asks. The reason names are provisional until you review them.
* **Replay:** `policy_signal` judges the two halves apart; an absent `goal_fit` (a row from before S5) stays absent -- it does
  not read as a failed check and refuse every old approval -- and a stored one this code does not know becomes
  `unrecognized`. `approved_dispatch` still never calls a validator (a test says so by AST).
* **Enforced run:** the seam also forces `goal_fit_enforce`, so the CI second run covers it. The modules that may opt out
  through `switch_as_published` were four (the definition and three that test the switch); this stage adds
  `tests/test_plan_fit_goal_fit.py`, and the AST test that pins the list was updated. **This widens the list by one file and is yours to overrule**, as the first two were.
* `agents/llm/plan_fit_base.py`, `agents/fake/fake_plan_fit.py`: an optional `provenance()`.

## 3. The kernel holds

A lying validator (`AdversarialFakePlanFit`: `plausible` for everything) is run over 4 scenarios x 2 task-switch states x
2 goal-switch states: **the decision, approval reasons and deny reasons are identical to having no validator at all**. For
every answer x scenario x switch state, the decision is never lower than without a validator and its reasons are a
superset. At the policy level (`test_plan_fit_policy.py`) the same property runs over 14 goal-fit values x 3 starting
points (allowed, already asking, denied) x 4 switch states: a DENY stays a DENY with its reasons; the signal adds exactly
three reasons and `plausible` is not one of them. [E]

## 4. Verification

* **Local, full suite, Docker up:** normal run **3,844 passed, 0 failed, 24 errors**; run with the switches forced on
  (`CYBERORCH_TEST_TASK_RELATION_ENFORCE=1`) **3,844 passed, 0 failed, 24 errors**. The 24 errors are the same
  browser/bloodhound image tests this machine lacks, as in every earlier stage. (A first attempt had 13 failures and 37 errors
  because the Docker daemon on this machine had stopped; restarting it and rerunning gave the numbers above. Those were not
  code failures.) [E]
* **OPA:** 78/78 (67 + 11 new), formatting clean.
* **New tests:** `tests/test_plan_fit_goal_fit.py` 106; additions to `test_plan_fit_policy.py` (131 total), structure (9), relation.
* **Mutations:** 20 (`scripts/mutations_d68.py`, `D68-S5-a` to `-t`), **all valid**. Two were INVALID at first and were repaired,
  not accepted: S5-g (the answer not stored) and S5-i (the provenance guard narrowed) died of `KeyError` / an escaped
  `AttributeError`, which the runner files under "other" -- the tests now assert (`stored()` and the `decide()` wrapper turn those into
  failed assertions). **S5-i is informative:** narrowing only the provenance guard lets an exception escape from the
  failure handler itself -- the guard is load-bearing, and now tested as such.
  They are: the guard narrowed to `ValueError` (13 target failures); a failure returned as `plausible` (24, **and the trap
  sandbox is reached -- an action runs**); an invalid answer accepted (2); the system's causes accepted from a validator (2);
  the validator asked for a proposal that is not its task (6); the goal taken from the proposal (1); the answer not stored
  (35); the exception message kept in the audit (15); provenance guard narrowed (12); merge/loader/publication/overlay each
  forgetting or loosening the new switch (45 / 1 / 6 / 1); a rule firing with the switch off (5); `plausible` read as a
  failure (9); an unrecognized value quiet (5); an old row read as a failed check (8); the replay dropping the goal half (49) or
  passing an unknown value through (11); the replay raising on a damaged operand (1).
* **CI:** see ACCEPTANCE 5.118 for the run on the tip of this stage.

## 5. Limits

* **No real model was called**, anywhere. What a real model says about real goals, how often `insufficient_context` and
  `implausible` appear, and what enabling the switch would escalate: S6/S7.
* The validator is asked on every decision of a `matches_task` proposal -- one model call of latency per proposal when a real
  backend is configured. Not measured. The call record is in the audit so S7 can.
* With the switch on and **no validator configured**, nothing is escalated (`disabled` is quiet). Enabling `goal_fit_enforce`
  before a validator is configured is a no-op, not an outage; S8b enables both together.
* Enabling the switch through a layer bumps the policy version and voids waiting approvals (as for the first switch).
* A retried `received` proposal asks the validator again (the first answer was never stored): intended; a decided one does not.
