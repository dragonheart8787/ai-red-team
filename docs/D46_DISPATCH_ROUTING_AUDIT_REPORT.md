# D46 — is D45's routing bug an isolated event, or a pattern?

D45 found `propose_action` calling `dispatch_scan` unconditionally for
`ad.collect` and `code.scan`, silently dropping the extra step each one's own
bespoke dispatch function alone performs. This deliverable checks whether
that gap was a one-off or whether it recurs for `web.get`, `web.post`,
`web.render`, `network.scan`/`network.recon` — and re-verifies, rather than
trusts, D37's own claim to have already driven `web.render` through the real
`propose_action` entry point.

**Headline: the other five actions were never at risk of this specific bug,
verified by code inspection and by reading every commit that ever touched
the dispatch call site — not assumed from a clean test run. D37's own
verification method was genuine, not a bypass, confirmed by reading the
actual test file it produced. Zero new gaps were found.** The routing layer
is now rebuilt so this class of bug is structurally impossible to reintroduce
silently: every adapter declares which dispatch function it needs, and a new
test drives the real routing function for every currently-registered action,
mutation-verified to fail exactly the way D45's own bug would have failed it.

---

## 1. Why the other five actions were never exposed to this bug

`dispatch_scan` (`control_plane/orchestrator/dispatch.py:216`) is not a
per-action branch list — it looks up the adapter for `capability.action`
through `tool_gateway.registry.adapter_for`, a single `MappingProxyType`
dict (`registry.ADAPTERS`), and runs whatever it finds generically:
`build_plan` → `sandbox.run` → `record_evidence`. Structurally, this cannot
route to "the wrong adapter" — the dict either has the right entry or the
action fails closed as `UNKNOWN_ACTION`. Nothing here was ever an if/elif
that a new action could fall through unnoticed.

**`ad.collect` and `code.scan` are the only two actions in this system's
history that have ever needed something *other* than `dispatch_scan`** —
each needs a second, bespoke step (`dispatch_collection`'s Security Graph
write; `dispatch_code_scan`'s control-plane-side git fetch/cleanup) that the
generic path has no place for. `network.scan`/`network.recon`, `web.get`,
`web.post` and `web.render` have never needed anything `dispatch_scan`
doesn't already do — there was never a second correct destination for any of
them to be routed to *instead of*, so "routed to the wrong dispatch
function" was never a possible failure mode for these five, at any point in
this system's history.

This is not an assumption; it is confirmed by reading the actual diff of
every commit that ever touched `propose_action`'s dispatch call site:

| Commit | What changed at the dispatch call site |
|---|---|
| D34 (`c8a9ab3`, adds `web.post`) | Nothing. Still the single, unconditional `dispatch_scan(...)`. The commit's own changes were to `side_effect_floor` (where `writes_data`/`changes_state` get their authority) — no routing logic touched. |
| D35 (`41f71a2`, TLS termination) | `function_api.py` is not in this commit's diff at all. |
| D37 (`edd4ddb`, adds `web.render` end to end) | Still the single, unconditional `dispatch_scan(...)` — gained three new *parameters* (`proxy_url`/`ca_cert_pem`/`proxy_cert_spki`) threaded through to the same one call, not a new branch. The commit's actual bug (below) was in `execution_constraints`, a different function entirely. |

**The pattern the brief suspected — "routing logic silently not updated when
a new action is added" — did not recur for these five, because none of them
were ever additions that changed how many possible dispatch destinations
existed.** `ad.collect` (D42) was the first action ever to need a second
destination, and that is exactly the commit where the gap was introduced
(D42 never added the routing `propose_action` would need; D45 is what found
this three deliverables later).

---

## 2. Which tests actually drive `propose_action`, and which stop short

| Deliverable | Test file | Drives `propose_action`? | What it proves |
|---|---|---|---|
| D31 (`web.get`) | `tests/test_http_get.py` | Yes (3 call sites) | Full pipeline incl. a real `evidence_id`/`tool_run` row — `dispatch_scan` genuinely ran |
| D34 (`web.post`) | `tests/test_web_post.py` | Yes (5 call sites) | Same — `evidence_id="HTTP-post0001"` asserted directly against the real dispatch outcome |
| D35 (TLS proxy) | `tests/test_egress_proxy.py` | No | Tests the proxy itself (host/method/redirect enforcement) at its own layer; never claimed to exercise `propose_action`, and correctly doesn't need to — TLS termination is orthogonal to which dispatch function runs |
| D36 (`web.render` adapter) | `tests/test_browser_adapter.py`, `tests/test_browser_escape.py` | No | Adapter-level (`build_plan`/escape-experiment) tests, the same scope as D42's own adapter-only tests before D45 — correctly labeled as such, not claimed to be end-to-end |
| D37 (`web.render` E2E) | `tests/test_web_render_e2e.py` | Yes (6 call sites) | See §3 |

No test file for any of these five actions ever called `dispatch_scan`
directly the way D42's/D44's own suites called `dispatch_collection`/
`dispatch_code_scan` — but as §1 establishes, that distinction carries no
risk here, because `dispatch_scan` was always both the only and the correct
destination regardless of which layer a given test happened to exercise.

---

## 3. D37's own claim, re-verified rather than trusted

D37's report claims web.render was driven "through the real pipeline entry
point." Read `tests/test_web_render_e2e.py` directly rather than trusting the
claim:

```python
from control_plane.api.function_api import execution_constraints, propose_action
...
outcome = propose_action(
    conn, engagement_id=engagement_id, proposal=proposal, reviewer=reviewer,
    policy=policy, agent_id=..., sandbox=sandbox, network_allowlist=[...],
    ...
)
```

This is a genuine call to the real, unmodified `propose_action` — not a
hand-assembled substitute. The file's own docstring is explicit about what
is and is not covered: *"a stub sandbox records exactly what dispatch would
run, so the whole chain ... is exercised on every machine. The companion
container run (`tests/scenarios/test_scenario_web_render.py`) proves the
same path with a real browser in CI."* This is an honest, correctly-labeled
scope statement, not an overclaim — it names its own stub and points to the
real-container companion test rather than implying the stub alone is the
full story.

**D37's verification method was reliable for what D37 was actually
checking**, and this deliverable's own examination confirms it: the test
asserts a real `evidence_id`, a real `derived_view`, and (in a second test in
the same file) exercises the fifth injection experiment's authorization
half — proving `dispatch_scan` genuinely ran and genuinely wrote evidence,
not merely that OPA returned ALLOW. **What D37 could not have caught, and
never claimed to check, is the class of bug D45 found** — because at the
time D37 ran, and at every point up to D45, `dispatch_scan` was the only
dispatch function that existed for `web.render` to be routed to. A test
cannot catch "routed to the wrong function" when there has only ever been
one function to route to. This is not a flaw in D37's method; it is a
statement about what question was and was not being asked at the time.

**Conclusion: D37's claim holds, and re-checking it changed nothing about
its own conclusion.** What changed is a more precise understanding of *why*
it could never have found D45's bug — not because it was insufficiently
careful, but because the bug it would need to find did not yet exist to be
found.

---

## 4. One adjacent path checked and found out of scope

`control_plane/api/approvals.py`'s `grant_approval` (the §4.7 human-approval
path) issues a capability but never calls any dispatch function at all —
confirmed by an exhaustive `grep` across the repository: `dispatch_scan(`,
`dispatch_collection(` and `dispatch_code_scan(` are called from exactly one
production call site (`function_api._dispatch_for_action`) and nowhere else,
including `approvals.py`. This is a different, already-documented stage of
the capability lifecycle (approve → issue), not a second routing path this
deliverable's fix needs to cover — there is no dispatch decision to get
wrong here because no dispatch happens on this path at all. Noted for
completeness, not treated as a gap.

---

## 5. The fix: a declaration, not a guess

D45's own fix (`_dispatch_for_action`) was already correct, but it was a
hand-written `if capability.action == ad_collector.ACTION: ... elif
capability.action == semgrep.ACTION: ...` — exactly the shape that let the
original bug exist: a third action needing its own dispatch function would
only be caught if whoever added it also remembered to add a branch to this
one file, which its own adapter module never has to import or know about.

**D46 replaces the branch with a declaration each adapter makes about
itself.** Every adapter registered in `registry.ADAPTERS` now declares
`NEEDS_DISPATCH` — one of `"dispatch_scan"`, `"dispatch_collection"` or
`"dispatch_code_scan"` — as a required constant, following the exact
precedent `nmap.py` already set for `WRITES_DATA`/`CHANGES_STATE`/
`REQUIRES_PROXY` ("an adapter that simply omitted the constants would raise
on the authorization path, which is not a failure mode any adapter should
be able to introduce by being written incompletely"). `_dispatch_for_action`
now does nothing but look this declaration up and call the named function,
handing it only the keyword arguments its own signature accepts (the same
`inspect.signature` introspection `dispatch.py`'s own `_build_plan_params`
already uses for the identical reason). There is no per-action branch left
in `propose_action`'s own code for a future action to be missing from.

No business logic changed. `dispatch_scan`, `dispatch_collection` and
`dispatch_code_scan` are byte-for-byte unchanged; only how `_dispatch_for_
action` chooses among them moved from a hardcoded lookup to a declared one.

---

## 6. The structural test, and its mutation verification

`tests/test_dispatch_routing.py` (new) parametrizes over every entry in
`registry.ADAPTERS` — the same exhaustive source of truth `dispatch_scan`
itself reads — and asserts two things per action:

1. Its adapter declares `NEEDS_DISPATCH`, naming a real dispatch function.
2. Driving the real `_dispatch_for_action` (with every real dispatch
   function replaced by a recording stub, no database or sandbox needed)
   reaches *exactly* the function the adapter declared, and no other.

**Mutation-verified, not merely believed.** `_dispatch_for_action`'s routing
decision was temporarily reverted to the pre-D45 shape — unconditionally
`_DISPATCH_FUNCTIONS["dispatch_scan"]`, ignoring `capability.action`
entirely — and the suite re-run:

```
tests/test_dispatch_routing.py::test_every_registered_action_routes_to_its_declared_dispatch_function[ad.collect] FAILED
tests/test_dispatch_routing.py::test_every_registered_action_routes_to_its_declared_dispatch_function[code.scan] FAILED
tests/test_dispatch_routing.py::test_every_registered_action_routes_to_its_declared_dispatch_function[network.recon] PASSED
tests/test_dispatch_routing.py::test_every_registered_action_routes_to_its_declared_dispatch_function[network.scan] PASSED
tests/test_dispatch_routing.py::test_every_registered_action_routes_to_its_declared_dispatch_function[web.get] PASSED
tests/test_dispatch_routing.py::test_every_registered_action_routes_to_its_declared_dispatch_function[web.post] PASSED
tests/test_dispatch_routing.py::test_every_registered_action_routes_to_its_declared_dispatch_function[web.render] PASSED
```

Exactly the asymmetry §1 predicts: `ad.collect` and `code.scan` fail (the
two actions the mutation actually breaks), the other five pass (`dispatch_
scan` genuinely is correct for them, mutation or not) — the precise failure
message read `action 'code.scan' ... declares NEEDS_DISPATCH=
'dispatch_code_scan', but _dispatch_for_action actually reached 'SENTINEL-
dispatch_scan'`. The fix was then restored and the full suite (see §7)
re-confirmed green before committing. This is the same manual-mutation-then-
record convention `tests/test_graph_queries_structure.py` already
established for D42-6's own structural guarantee.

A future action that forgets to declare `NEEDS_DISPATCH` fails
`test_every_adapter_declares_its_dispatch_requirement` immediately (a clear,
named assertion) rather than surfacing three deliverables later as a live
run's silent gap — the exact escalation D45 itself needed to find this
class of bug the first time.

---

## 7. Verification summary

| Check | Result |
|---|---|
| `network.scan`/`network.recon` routing | Always correct — `dispatch_scan` is the only destination that has ever existed for them |
| `web.get` routing | Always correct, same reason; `test_http_get.py` drives `propose_action` and confirms real dispatch |
| `web.post` routing | Always correct, same reason; `test_web_post.py` drives `propose_action` and confirms real dispatch |
| `web.render` routing | Always correct, same reason; D37's own `test_web_render_e2e.py` claim re-verified genuine |
| `ad.collect`/`code.scan` routing | The D45 bug, already fixed; D46 rebuilds the fix as a declaration rather than a hand-written branch |
| New routing gaps found | None |
| `grant_approval` (human-approval path) | Out of scope — issues a capability but dispatches nothing; no routing decision exists there to audit |
| New structural test | `tests/test_dispatch_routing.py`, 15 cases, all passing |
| Mutation verification | Reverting to the pre-D45 routing shape fails exactly `ad.collect`/`code.scan`, passes the other five — captured above |
| Full local test suite | 924 passed (909 + 15 new), after the refactor |
| No business logic changed | Confirmed — `dispatch_scan`/`dispatch_collection`/`dispatch_code_scan` bodies are untouched |

---

## 8. Files touched

* `tool_gateway/adapters/nmap.py`, `http_get.py`, `http_post.py`,
  `browser.py`, `ad_collector.py`, `semgrep.py` — each gained `NEEDS_DISPATCH`.
* `control_plane/api/function_api.py` — `_dispatch_for_action` rebuilt as a
  declaration-driven lookup (`_DISPATCH_FUNCTIONS` + `inspect.signature`
  kwarg filtering) instead of a hand-written `if`/`elif`; removed the
  now-unused direct `ad_collector`/`semgrep` imports.
* `tests/test_dispatch_routing.py` — new, this report's structural guarantee.
