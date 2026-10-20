# D68 S3 -- P1 enforceable: the switch, the rules, the replay, and the enforced CI run

Plan: `docs/D68_IMPLEMENTATION_PLAN.md` section 4. ACCEPTANCE 5.116 (the gap), 5.118 (the stages).
Claims are tagged [R] read, [E] executed, [D] derived, [N] not established.

**What S3 is:** the relation computed in S2 can now change a decision -- behind a policy switch that is
**off everywhere**. Nothing is enabled; S8a does that. With the switch on, a proposal that names no task,
or whose task is not its own, needs a human. The replay at the approval re-derivation exists, and the
suite runs a second time in CI with the switch forced on for every policy input.

## 1. What was built

* **The switch.** `task_relation_enforce` in a policy layer. Neutral element `false`, merged by **OR**,
  so a layer can turn it on and none can turn it off. Only a real boolean is accepted at publication; the
  reader treats anything but `true` as off (a string "false" is truthy); an emergency overlay may only say
  `true`. No migration: the overlay's schema `CHECK` forbids `scope_allow` and `ALLOW`, and neither is touched.
* **The input and the rules.** `build_policy_input(plan_fit=...)` adds a top-level `plan_fit` only when a
  signal exists. In `authz.rego`, `approval_reasons` alone reads it: `proposal_without_task` for `no_task`,
  `proposal_outside_task` for anything present that is not `matches_task` or `no_task` -- a task that
  differs or is not live, a value from another vocabulary, a damaged object. `matches_task` and an absent
  signal fire nothing. The reason names are provisional until you review them.
* **The replay.** `evaluate_policy` takes `plan_fit` as a **required** argument. The decision stage passes
  what it just computed; `approved_dispatch._rederive` passes what the decision stored
  (`reviewer_hints["plan_fit"]`); both through `relation.policy_signal`, which gives a stored value this code
  knows back unchanged and anything else as `unrecognized` (outside the plan). An absent key stays absent.
  The re-derivation never reads `tasks` and never looks at the rebuilt proposal for the signal.
* **The CI step.** After the normal run, the whole suite runs again with
  `CYBERORCH_TEST_TASK_RELATION_ENFORCE=1`, then an assertion step requires zero failures, zero errors, zero
  skips and a non-empty result file. Both steps are `if: always()`. The comments in the workflow say it is
  not to be relaxed, skipped or made advisory.

## 2. The hard acceptance: the enforced run

| run | result |
|---|---|
| normal, CI, `90ab94a` | green |
| **enforced, CI, `90ab94a`** | **failed** -- the same three tests as locally (below) |
| enforced, local, `90ab94a` | 3 failed, 3,543 passed, 24 errors (images this machine lacks, identical to the baseline's 24) |
| enforced, local, `b038ff9` | **0 failed, 3,547 passed**, the same 24 image errors |
| both runs, CI, `b038ff9` | see the last section |

It worked as designed: it found three things the author had not, and none of them was an M-class site of S1.

1. **A misclassified caller.** `test_the_approval_path_takes_the_same_transitions_through_the_same_functions`
   proposes through `test_approved_dispatch._proposal`, a helper S1 had classified K2 (a HUMAN_APPROVAL
   fixture) -- and uses it once for an ALLOW. Under enforcement the ALLOW became HUMAN_APPROVAL and the test
   went red. It now carries a task. The classification (design note section 12) was right for 33 of its 34
   users and wrong for one; the run found the one.
2. **Two tests of the switch itself.** "With the switch off, the relation changes nothing" (S2's shadow test)
   and "approved while it was off, dispatched with it on" cannot say what they mean while every policy input is
   forced on. **This is a decision I took and you may overrule:** they opt out of the seam through a named fixture,
   `switch_as_published`, and `tests/test_plan_fit_structure.py` pins the exact modules that may use it (four,
   one of them the definition). I did not make the seam skip, did not loosen the assertion step, and did not
   relax any caller's class. If you read "hard acceptance" as "no test may opt out", the alternative is to
   delete those two tests' switch-off halves, which would lose the thing they pin.

## 3. Verification

* **OPA:** 67/67 (58 + 9 new): each relation with the switch on and off; an absent signal; the five unreadable
  forms; a DENY never outranked; the signal adds to other reasons and never replaces them; the formatting
  check passes.
* **Python:** `tests/test_plan_fit_policy.py` (the switch's algebra and loading, and **a property over the real
  policy**: every signal x switch state x starting point (allowed, already asking, denied) is at least as strict
  as the same without the signal, adds only its two reasons, keeps every DENY and its reasons, and
  `matches_task` is identical to no signal); `tests/test_plan_fit_replay.py` (10: the cases design 11.3
  asked for, with proposals that *have* tasks and rows from before the signal existed);
  `tests/test_plan_fit_structure.py` (7: one place builds the input, both callers pass `plan_fit` and take it
  from `policy_signal`, the re-derivation reads no task, nothing that ships reads the test variable, the seam
  is on exactly when asked, who may opt out). 3,571 tests collected.
* **Mutations:** 15 for S3 (`scripts/mutations_d68.py`), all valid -- the merge forgets the switch; the
  loader's combining drops it; a truthy value turns it on; a non-boolean accepted; an overlay may say false;
  the replay removed; **recomputed from the rebuilt proposal**; **read from the task's status now**; an
  absent signal invented; an unreadable one taken as a match; the rules firing with the switch off; a damaged
  signal read as fine; `matches_task` asking for a human; the input dropping the signal; `evaluate_policy` not
  forwarding it. One was INVALID at first (a `KeyError` filed as "other") and the test was repaired to assert.
* **What the replay mutations show, stated plainly:** removing the replay altogether (no signal at the
  re-derivation) is *lenient*, not wounding -- nothing extra appears, so no behaviour test goes red and only
  the structure test sees it. The wounding forms are the two **recomputes** (from the rebuilt proposal: every
  task-carrying approval refused; from the task's status: refused when its task finished while it waited),
  and the behaviour tests catch both. So the structure test is what keeps the replay from being deleted, and
  the replay tests are what keep it from being replaced by a recompute.

## 4. What S3 found

1. **`_combine` in `layers.py`** folds the rows of one layer name field by field -- a second merge routine.
   The first run of the loading test showed the switch dropped there: published, read back, `false`. A new
   field is dropped by the routine nobody remembers; a test and a mutation now pin it.
2. **An OPA pitfall, in a rule I wrote.** `not input.plan_fit.task_relation in {...}` does not fire when the
   operand is undefined -- exactly the damaged-object case it had to catch. Found by the test for a damaged
   signal, replaced by a helper rule (commented), and the operator form is called out in the rego.
3. **Enabling voids the waiting approvals, twice over.** Publishing the switch as a layer bumps the policy
   version, which already voids an approval waiting for dispatch (`policy_changed`, existing test). If the
   version were not enough, a stored `no_task` now produces a reason the approver was never shown, and the
   re-derivation refuses with `new_approval_reasons` (tested). So turning enforcement on **requires
   re-approval of anything waiting**; this is the intended behaviour, and the operator should know it before
   S8a. The replay's job is the other direction: switch on at both the decision and the dispatch.
4. S2's record: proposals decided from S2 on carry `plan_fit`; before it, none -- and both dispatch.

## 5. How the switch would be turned on (S8a; nothing here does it)

Global, immediate, all engagements: `python scripts/manage_global_policy.py publish --layer
emergency_overlay --version N --document '{"task_relation_enforce": true}' --actor <person>` (asks for a
person; an overlay can only say `true`). For new engagements only: the same in a `baseline_global` layer
(frozen into an engagement at its creation, D54). For one engagement: an engagement layer through
`publish_policy_layer`. **Not run against the shared database in this stage** [N]: a global overlay applies to
every engagement; the tests use an engagement layer and in-memory policies.

## 6. Limits

* Nothing is on. The first real measurement of what enforcement would escalate is S6/S7; DP-13's question
  (a task on a network, a proposal for one host inside it) is still unanswered by data and S8a is gated on it.
* The seam covers the proposals that go through `function_api.build_policy_input`, which is every real
  decision (propose and re-derive). Tests that call the engine directly with their own inputs are not
  affected, by construction; they are the policy's own tests (OPA, the property test).
