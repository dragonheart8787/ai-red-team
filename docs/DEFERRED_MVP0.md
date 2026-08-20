# MVP-0 — what D10 delivered, and what D10.5 still owes

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
