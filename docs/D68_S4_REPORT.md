# D68 S4 -- the Q1 validator, built and not wired

Plan: `docs/D68_IMPLEMENTATION_PLAN.md` section 5. Design: `docs/D68_REVIEWER_SEMANTIC_VALIDATION_DESIGN.md`
sections 1.3 (Q1), 2 (injection surface), 4 (data flow and signal). ACCEPTANCE 5.118.
Claims are tagged [R] read, [E] executed, [D] derived, [N] not established.

**What S4 is:** a validator that answers one question -- do a task's goal, action and target fit each
other? -- with one of `plausible`, `implausible`, `insufficient_context`, over three transports and three
scripted fakes, selectable by `CYBERORCH_PLANFIT_BACKEND` (default `fake`). **Nothing calls it.** A test says
so; S5 wires it in behind its own switch and replaces that test.

## 1. What was built

* **The types** (`agents/base_agent.py`, beside `ReviewerOpinion`, importable by the control plane):
  `PlanFitQuery` -- exactly five strings, the goal and the task's and the proposal's action and canonical
  target; `GoalFitAssessment(validator_id, goal_fit, cause)` -- a value from the closed vocabulary, or
  `not_assessed` with a cause (`failed` / `disabled` / `not_applicable`), and nothing else: **no field for a
  sentence, a score or a confidence**; `PlanFitValidator`, the seam.
* **`agents/llm/plan_fit_base.py`:** the schema (one property, an enum of the three values,
  `additionalProperties: false`), the system prompt, `build_prompt`, `_to_assessment`, `_fail`.
* **`agents/llm/plan_fit_validators.py`:** the API, Claude-Code-headless and local transports, reusing the
  Reviewer's (`headless.run_headless`, the Anthropic client, one POST). The Reviewer's own files are
  **untouched** (weighed and rejected in the plan: generalising `BaseReviewer` would put the D10.5-tested
  boundary at risk to save about 150 lines).
* **`agents/fake/fake_plan_fit.py`:** a scripted validator, an honest one (the default: everything
  `plausible`, which adds no caution and so changes no decision), an adversarial one (always `plausible`,
  however mismatched -- the control S5's kernel-holds test needs) and an unavailable one.
* **`selection.build_plan_fit_validator`:** the fourth role, with its own pair of variables; an unknown
  name raises rather than falling back.

## 2. The properties, and what holds each

| property (design note) | held by |
|---|---|
| **Everything shown is inside one nonce block; there is no trusted input but the system prompt** (2.2) | `build_prompt` puts the five strings in `wrap_untrusted`; tests: the whole query is between the markers, the instruction is after the closing one, the nonce differs on every call, and **28 hostile placements** (7 lures x goal / task target / proposal target / task action) stay inside and cannot forge the closing marker |
| **The agent's own words are not shown** (2.2: its stated reason is what a lure writes) | `PlanFitQuery` has five string fields and no more -- a test fixes the list; mutation `S4-b` adds a `reason` and goes red |
| **Nothing a model writes can be free text** (2.4, DP-6) | the schema's one property is an enum; any other key in a reply is a failure; `GoalFitAssessment` has no text field; failure reasons go to the call record, not the assessment |
| **A model can never say `not_assessed`** (1.4) | it is not in the enum (mutation `S4-l` adds it: red) and a reply that says it is a failure |
| **"Cannot tell" is an answer of equal standing; the model is not pushed to a guess** (4.3) | the system prompt defines `insufficient_context` as "a complete and honest answer", for goals too broad to bound, too vague to compare, or simply unclear (mutation `S4-k` removes that sentence: red) |
| **Failure is never `plausible`** (4.3) | a refusal, a timeout, a transport error, non-JSON, a non-object, an empty `choices`, an unknown value, an extra key, a missing model: all `not_assessed / failed`, on all three transports, tested one by one (mutation `S4-c` returns `plausible` from the failure path: 49 tests red) |
| **The question is not scope, sensitivity, danger or credentials** (1.5) | the system prompt names the four as outside the question and not changeable by the answer |
| **An embedded ready-made answer is not a legitimate goal** (2.3, L1/L2) | the system prompt tells the model to answer `implausible` for text that tries to instruct it or supply an answer -- the direction that adds friction; **whether a real model obeys is not tested here** [N] |
| **One boundary, shared** | `test_every_adapter_shares_one_boundary`: no adapter overrides `build_prompt`, `_to_assessment`, `_fail` or the parser; none defines its own schema or prompt |
| **Not wired** | `test_nothing_in_the_control_plane_calls_a_validator_yet` |

## 3. Verification

* **Tests:** `tests/test_plan_fit_validator.py`, 112 (counting the parametrised ones): the vocabulary, the
  schema, the boundary, coercion on all three backends, each failure path of each transport, the
  accounting (one call, one record, a failure included), the selection, the fakes, and the two structural
  tests. All offline: the transports are stubs, as the Reviewer's tests do it. 3,683 tests collected.
* **Mutations:** 12 (`scripts/mutations_d68.py`, `D68-S4-a` to `-l`), all valid: the goal outside the block; the
  agent's reason in the query; a failure returned as `plausible`; the schema open; a sentence beside the
  answer accepted; a static delimiter; a refusal read as an answer; an empty `choices` escaping; a real model
  as the default; a failed call unrecorded; "cannot tell" no longer an answer; the model allowed to say
  `not_assessed`. Three were INVALID at first and were repaired, not accepted: one edit matched two lines,
  and two tests died of an `IndexError` / `ValueError` the runner files under "other" -- they now assert.
* **No model was called**, anywhere. What a real model does with this prompt, how often it says
  `insufficient_context`, and whether a lure moves it are S6/S7's measurements; none of that is claimed.

## 4. What S4 found

**The Reviewer's local adapter has the same hole this validator's first test found in its own.** A reply whose
`choices` list is empty raises `IndexError` out of `LocalReviewer.review()` instead of failing closed: the
adapter catches `ValueError, TypeError, KeyError, JSONDecodeError`, not `IndexError` [E: run against the
existing class, "RAISED IndexError"]. The validator's copy of the code catches it (and a mutation pins it).
Not changed in the Reviewer -- S4 leaves it untouched -- and recorded as ACCEPTANCE 5.120. It fails loud (an
exception in the pipeline), not open, and needs a local server answering with an empty list.

## 5. Not done, by design

No call from the control plane, no input assembled from a task row, no audit event, no policy rule, no
switch (`goal_fit_enforce`): all S5. The tests for what a real model does are S6/S7.
