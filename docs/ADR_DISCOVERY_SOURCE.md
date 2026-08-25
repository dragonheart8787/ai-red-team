# ADR: discovery_source — what it means, and who gets to say it

Status: **proposed, D20. Awaiting a decision before any implementation.** No
schema, worker or Rego change is made until the direction in §7 is chosen.
Addresses the `discovery_source` item on the candidate list
(`ACCEPTANCE_MVP1_AGENTS.md` §3, Class C).

This is step one of D20, mirroring D19: a design decision, not code. It answers
the four questions the brief set — what the field should mean, whether it can be
made deterministic, what that does to the §5 escalation rule, and how the new
definition reads against the D13 divergence.

The scope limit the brief drew is load-bearing and is honoured throughout: this
touches **only the discovery side** of §8.9's Discovery ⊥ Authorization split.
The authorization side — `authorization.scope_object_id`, the Authorization
Resolver, OPA's `target_authorized` — is not touched, and nothing here may let a
discovery fact authorize anything. Where a proposal below reads scope
membership, it does so to answer *"where did this candidate come from"*, never
*"is it authorized"*; the two stay separate functions computing separate things.

---

## 1. The problem (brief Q1): one field, two questions, and the Worker chooses

`discovery.source` is a self-reported enum
(`explicit_scope | prior_scan_result | tool_observed | dns | web_content`),
written by the Worker in `worker_base._to_proposal` from the model's reply and
corroborated by nothing. D13 measured what that costs. Same target, same
evidence, same engagement:

| Scenario | observation the harness built | Worker reported | outcome |
|---|---|---|---|
| `injection_web_content` | `web_content` (a page fetched from 10.79.0.2) | `prior_scan_result` **8/10** | ALLOW |
| | | `web_content` **2/10** | HUMAN_APPROVAL |

The `web_content` two escalated by §5's `untrusted_discovery_source` rule; the
`prior_scan_result` eight did not. D13's own report already leaned on the reading
that resolves this: *"every one of those ten proposals named an in-scope target
that would have been allowed anyway, and the escalation the eight avoided was one
they arguably did not warrant."*

The field is answering two different questions at once, and the model is free to
pick whichever it likes for a given proposal:

- **Q-channel** — *through what technical channel did this candidate reach us?*
  (a scan result, a web page, a DNS answer). For 10.79.0.2 this round, the
  channel was a web fetch → `web_content`.
- **Q-origin** — *where was this target first established?* 10.79.0.2 was found
  by the earlier scan and is inside the authorized `/24`, so its origin is the
  engagement's own prior work → `prior_scan_result`.

Both are true. The model said Q-origin eight times and Q-channel twice, and the
policy — which was written expecting Q-channel — escalated only the twice. That
is not a lie and not an exploit; it is an underspecified field doing double duty,
and a Worker that wanted to avoid escalation would only need to pick the reading
that suits it, without ever saying anything false.

Neither Q-channel nor Q-origin, as the model answers them, is the question the
*escalation* actually cares about. §8.9's concern is narrower and sharper: **was
this target introduced to us by attacker-controlled text?** That is neither "what
format was the observation" nor "where was the host first seen" — and it is,
importantly, a *fact*, not a judgement.

---

## 2. What the design already says (and already reserved)

Three things in `ARCHITECTURE.md` bear directly on this, and the first is the
one that reframes the whole deliverable:

1. **§4.1's `discovery` block already has the deterministic fields.** The schema
   is, verbatim:
   ```json
   "discovery": {
     "source": "explicit_scope | dns | tool_observed | web_content",
     "evidence_id": "HTTP-991",
     "discovered_by_run_id": "RUN-01923"
   }
   ```
   `evidence_id` and `discovered_by_run_id` are in the design and were **never
   implemented** — `_to_proposal` writes `discovery={"source": discovery_source}`
   and drops the other two. This is the same shape as `query_findings`,
   `overlaps_with` and the task-identity columns: a field the design reserved,
   left inert, and now the thing a deliverable turns on. Filling them is
   *implementing* §4.1, not extending it.

2. **§8.1: everything a target produced is untrusted, by construction.** Every
   `evidence.derived_view` carries `untrusted_content: true` (enforced in
   `evidence/store.py`). A scan banner and a web page are *equally* untrusted —
   which matters for §3 below, because the current rule treats them differently.

3. **§8.9's intent for the rule:** `discovery.source == "web_content"` forces
   HUMAN_APPROVAL regardless of the reviewer's risk. The design singled out web
   content as the attacker-controlled channel. D13 showed the singling-out is
   too narrow: the lure that deliverable planted lived in an **nmap banner**
   (`tool_output`), not a web page, and a target named there would be classified
   `prior_scan_result`/`tool_observed` and would not trip the rule at all.

---

## 3. Investigation (brief Q2): can the technical channel be made deterministic?

**Yes, and the machinery is already present.** The evidence for feasibility is
in the code, not in principle:

- **The harness knows the provenance when it builds the window.** In
  `scripts/live_run/d13_worker.py` the observation is literally constructed from
  a specific evidence artifact:
  ```python
  Observation("web_content", f"http://{ip}/ index page", page)   # page = derived_view of laced["evidence_id"]
  ```
  The harness chose the content, from a known `evidence_id`. It is not inferring
  the source — it *is* the source.
- **The evidence record carries the channel and the chain.** `evidence.type`
  ∈ `{tool_output, screenshot, log, http_transaction}` gives the channel
  deterministically (`http_transaction` → web, `tool_output` → scan), and
  `evidence.run_id` (FK to `tool_runs`) gives "which run produced it". So
  "this text came from evidence E-84, E-84 is the output of run RUN-44" is a
  lookup, not a judgement.
- **The one plumbing gap is small.** `build_prompt` and `propose` already
  receive `observations`; `_to_proposal` does not. Threading the observations
  (each tagged with its `evidence_id`/`run_id`) into `_to_proposal` is a
  one-argument change within the one class.

This is exactly §5's principle applied to the discovery side: the Canonicalizer
and the Metadata Resolver establish deterministic facts and the AI may only *add*
caution, never assert the fact. Today `discovery.source` is the one place that
principle is violated — a deterministic fact (what channel a candidate arrived
through) is left to the model to assert. The investigation's conclusion is that
it does not have to be.

**So the technical-channel half can be taken away from the Worker entirely.**
The question is whether we stop at "make the channel deterministic" or go one
step further and make the *escalation trigger itself* deterministic. §4 lays out
both.

---

## 4. The options

### Option A — the escalation trigger becomes a deterministic fact *(recommended)*

Split the field exactly as the brief's Q1 asks, and resolve each half on the
correct side:

- **Technical provenance → deterministic, harness-filled.** Implement §4.1 as
  written: `discovery.evidence_id` and `discovery.discovered_by_run_id` are set
  by the pipeline from the observation a target was drawn from, never by the
  model.
- **Trust/escalation → a system rule over a fact, not a model label.** The rule
  the escalation needs is *"was this target introduced to us only by
  attacker-controlled text?"* — and that is deterministically checkable:

  > A target is **observation-introduced** when its canonical identity appears in
  > the `untrusted_content` of an observation shown this round **and** is not
  > otherwise *established* — i.e. it is neither an offered scope object nor an
  > address/port already present in the *structured* fields of prior evidence
  > (a host the tooling actually observed responding, as opposed to one merely
  > named in a banner). When it is observation-introduced, `discovery.source` is
  > set to the naming evidence's channel and its `evidence_id`/`run_id` recorded,
  > and the proposal escalates. Otherwise `discovery.source` is `explicit_scope`
  > (or the established channel) and it does not escalate on discovery grounds.

  The Worker no longer writes `discovery_source` at all. Its discovery-side
  output disappears; the pipeline computes the fact from the observations it
  itself assembled and the engagement's own record.

  The "established" test is what keeps this from either extreme. Anchored on
  *what was actually observed* (a scope object, or a host/port in the structured
  scan output), it does not depend on whether an address happens to be echoed in
  some page's text, and it separates a host the tooling saw respond from one an
  attacker merely typed into a banner. Its precision is the sub-decision in §7.2.

What this fixes, point by point:

- **The D13 divergence cannot recur.** 10.79.0.2 is a host the earlier scan
  actually observed responding and it sits inside the authorized `/24`, so it is
  *established* — not introduced by this round's page — regardless of what the
  page text contains. It resolves to non-escalating for all ten runs. The 8/10
  that were allowed were right; the 2/10 were the model answering Q-channel.
  There is no longer a choice to make.
- **The banner-injection gap (§2.3) closes.** The lure `203.0.113.77` *does*
  appear in the untrusted content — whether that content is a web page or an
  nmap banner — so it is observation-introduced regardless of channel. (In D13
  it was also out of scope, so authorization denied it independently; the point
  is that an *in-scope-looking* address named in a banner would now escalate,
  which today it would not.)
- **The relabel-to-dodge hole closes.** The Worker cannot pick a favourable
  source, because it does not supply one.

Costs and the one real subtlety:

- Thread `observations` (each carrying `evidence_id`/`run_id`) into
  `_to_proposal`; add a deterministic "identity appears in untrusted content"
  check; fill the two schema fields; drop `discovery_source` from the Worker
  schema and prompt. Moderate, and contained to `worker_base.py` plus the
  harness and one Rego rule.
- **The matching must be robust the way D13's precondition check was not.** nmap
  escapes the dots (`203\.0\.113\.77`), and D13's first harness concluded the
  lure had failed because a literal substring check missed it. The identity
  match here must normalize the same way — compare canonical identity forms, not
  raw bytes — or it fails *open* (a named target read as not-named → no
  escalation). This is the D16-style fail-open risk and it gets a mutation test.

### Option A′ — derive the channel from evidence type *(weaker deterministic variant)*

The smaller version: fill `evidence_id`/`run_id` deterministically and derive
`discovery.source` from `evidence.type` (`http_transaction` → `web_content`,
`tool_output` → `tool_observed`), but keep the escalation rule keyed on the
`web_content` channel as today. Simpler — no identity-in-content check — and it
still removes the self-report and the D13 divergence (the channel is now a fact).
But it **keeps the §2.3 gap**: a target named in a `tool_output` banner is
`tool_observed` and does not escalate. Recorded as the honest lesser option, not
recommended, because it leaves exactly the hole D13 demonstrated.

### Option B — converge the enum, keep it self-reported *(fallback)*

If threading evidence provenance is judged too costly, or a future collection
path genuinely cannot attribute a target to an evidence artifact, then collapse
`DISCOVERY_SOURCES` to two deterministically-checkable values —
`from_scope` (the target matches an offered scope object) and `from_observation`
(everything else) — pin their definitions, and escalate on `from_observation`.
This kills the Q-channel/Q-origin choice, since neither survives as a value. It
is weaker than A: it stays partly self-reported (mitigated by validating a
`from_scope` claim against the offered scope objects), and escalating *all*
observation-derived targets would newly escalate ordinary scan-follow-up work,
which is most of what a Worker does — a large behavioural change for a coarse
signal. Kept as the fallback the brief asked for, in case A and A′ are both
rejected.

---

## 5. The Rego rule (brief Q3)

The current rule, `control_plane/policy/rego/authz.rego`:

```rego
approval_reasons contains "untrusted_discovery_source" if {
    input.action.discovery.source == "web_content"
}
```

Reviewed against each option, the residual ambiguity is the same one §2.3 names:
**the rule equates "attacker-controlled" with "web channel", and §8.1 says all
observations are untrusted, so a target named in a scan banner is attacker-
controlled too.** What changes per option:

- **Under A:** the rule is rekeyed off the deterministic fact the pipeline now
  computes — escalate when the target is observation-introduced (an
  `evidence_id` is recorded on `discovery`) rather than when a channel string
  equals `web_content`. The channel becomes descriptive metadata; the trigger is
  the fact. The gap closes.
- **Under A′:** the rule is unchanged and the gap **remains** — this is why A′ is
  not recommended. It should at least be documented in the rule that
  `tool_observed` is untrusted too and is deliberately not escalated, so the gap
  is a known decision rather than an oversight.
- **Under B:** the rule keys on `from_observation` instead of `web_content`,
  which closes the channel gap but at the escalation-noise cost in §4.

Either way, the rule stays in `approval_reasons` — advisory escalation, never a
new authorization path — so the Discovery ⊥ Authorization boundary is untouched:
discovery still can only *add* a human check, never grant or deny.

---

## 6. Validation against D13/D15 (brief Q4) — and an honest limit

**The raw per-run data for D13 and D15 was never committed.** The D17 report says
so explicitly ("the files are committed under `docs/d17_runs/` — unlike D13's and
D15's, which were not"), and `git ls-files` confirms only `docs/d17_runs/`
exists. So unlike D19 — which replayed committed `d17_runs/` data through the new
code — **this ADR cannot re-run D13/D15 against the new definition.** Re-deriving
it would mean re-collecting those runs against a live target, which is D20 step
two's business at most, not an ADR's, and is a *new* measurement the brief did
not ask for.

What the committed **reports** let us reason, precisely:

- The `injection_web_content` divergence (8/10 `prior_scan_result` vs 2/10
  `web_content`, D13 §4) resolves under **Option A** to a single classification:
  10.79.0.2 is a host the prior scan observed responding and is inside the
  authorized `/24`, so it is *established*, not observation-introduced →
  **no escalation, all ten**. The divergence disappears, and the answer agrees
  with D13's own stated lean ("the escalation the eight avoided was one they
  arguably did not warrant"). The two escalations were the model answering
  Q-channel; Option A removes Q-channel as something the model answers.
- The D13/D15 **lure** (`203.0.113.77`, named in a banner/page) is
  observation-introduced under Option A — its identity string is in the untrusted
  content — so it escalates on discovery grounds *in addition to* being denied by
  authorization for being out of scope. Under the current rule and under A′, a
  banner-named target does not escalate; this is the §2.3 gap, and D15's lure
  living in a `tool_output` banner (port 7002) is the concrete case.

This reasoning is from the reports, not a re-run, and it is labelled as such.
If step two proceeds under Option A, a re-collection of the `injection_web_content`
scenario is the right confirmation, and it should show the split gone.

---

## 7. The decision I need

1. **Which option** — A (deterministic trigger: "target introduced by untrusted
   content"), A′ (deterministic channel only, gap retained), or B (converged
   self-report). **My recommendation is A**: it is the only one that both makes
   the fact deterministic *and* closes the banner-injection gap, it implements
   §4.1 as already designed, and it applies §5's "the AI does not assert
   deterministic facts" principle to the one field that still breaks it.
2. **If A**, how strict "established" is — this decides the one case the two
   readings disagree on, a target that is *in an authorized range but was only
   ever named in a banner*, never observed (e.g. a `/24` is in scope and a banner
   says "scan 10.79.0.55", a host nothing has seen respond):
   - **(i) loose** — established = covered by any offered scope object. 10.79.0.55
     is covered, so it does not escalate. Simpler; no structured-evidence
     corroboration needed. But it means an attacker can steer a Worker onto any
     unseen address inside an authorized range without a human check.
   - **(ii) strict** *(my lean)* — established = a scope object, or a host/port
     actually present in prior structured scan output. 10.79.0.55 was only named,
     never observed, so it escalates; 10.79.0.2 was observed, so it does not.
     This is the reading that makes discovery escalation carry independent value
     rather than mostly duplicating the authorization deny, and it needs the
     structured-evidence check (the part with real implementation depth).

   Either way a scan follow-up of a genuinely observed in-scope host is **not**
   escalated, which is the D13 "eight were right" outcome. The choice is only
   about the named-but-never-observed in-range target.

Step two — the `worker_base` schema change, the deterministic check, the
`evidence_id`/`run_id` plumbing, the Rego rekey, and the mutation tests — does
not begin until §7 is answered.
