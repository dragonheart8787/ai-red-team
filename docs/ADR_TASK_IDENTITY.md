# ADR: Task identity — what makes two tasks the same work

Status: **accepted, D19 — Option 1 (target-level identity + `overlaps_with`,
never drop).** The §6 granularity question was decided in favour of
distinguishing Redis/relay at execution time (§7), not at the task layer. Step
two (schema, `create_task`, `query_tasks`, validation) is built against Option 1.
Closes `DEFERRED_MVP0.md` §11.3.

This is step one of D19: a design decision, not code. It proposes what
structured fields a task must carry to support a *safe* identity comparison,
lays out the options with their trade-offs, and answers the one question the
brief singled out — what the system does when two tasks are judged the same.
Nothing in `create_task`, the `tasks` schema, or `ProposedTask` changes until
this is agreed.

---

## 1. The problem, stated against the D17 data

D17 showed `create_task` inserts unconditionally: the `blind` arm produced **25
tasks for 4 distinct pieces of work**, all created, and 16 workers then held
live leases on the same `/24` sweep. `ProposedTask` carries `action`, `target`
and `scope_object_id`; `create_task` writes only `goal`, `created_by` and
`priority` and drops the other three. So the only thing about a task that
survives into the database is free text (§11.3, `test_a_task_keeps_its_prose_
and_discards_its_structure`).

The brief is explicit that the fix is **not** a smarter string or
semantic-similarity algorithm over the goal text. It is to give the task enough
*structure* to compare. That is right, and the reason is in the D17 data itself.

### 1.1 The counter-example that constrains everything

D17's own measurement instrument produced one false positive: it collapsed two
genuinely different scans into one key. Here are those two tasks, read back from
`docs/d17_runs/d17_accumulating.json`, with every field they carry:

| | goal (free text) | action | target | scope_object_id |
|---|---|---|---|---|
| A | *"…focused service/NSE scan of Redis on 10.79.0.2**:6379**…"* | `network.scan` | `{ip, 10.79.0.2}` | `SCOPE-2909733755` |
| B | *"…focused service/version scan of the unidentified TCP services on 10.79.0.2 **ports 7001-7002**…"* | `network.scan` | `{ip, 10.79.0.2}` | `SCOPE-2909733755` |

**Every structured field is identical.** The port distinction — `:6379` versus
`7001-7002`, which is the entire reason these are different work — exists *only*
in the goal string. The Supervisor's output schema (`plan_schema`) has no port,
no service and no scan parameter: `target_value` is "an address, a CIDR, a
hostname or a URL", `additionalProperties: false`, and D17 held that line
deliberately, because a Supervisor that specifies ports is a Supervisor that
dispatches rather than plans.

This is the finding that decides the shape of the answer:

> Reusing exactly the fields `ProposedTask` already carries (`action`, `target`,
> `scope_object_id`) — the fields the brief says to persist — **cannot on its
> own tell A and B apart**, because those fields are equal for A and B. The only
> signal that separates them is either the goal free text (which the brief and
> ADR G both forbid comparing) or a port/service granularity the task does not
> currently carry at any layer the Supervisor is allowed to fill.

So the real decision is not "which comparison function". It is: **at what
granularity is a task identified, and is the Supervisor permitted to express
that granularity?** Everything below follows from that.

### 1.2 The constraints that bind any answer (from §11.3 and the design doc)

1. **Fail toward a duplicate, never toward a silent drop** (§1.2c, §9 ADR G).
   A false negative — the scan that should have run and did not — is a security
   bug, not a performance one. This is the constraint the Redis/relay case is a
   live instance of: a comparison too coarse to tell A from B, if it *drops* on
   a match, deletes a real scan.
2. **Whatever is compared has to be stored.** Any structural comparison needs
   `create_task` to persist the `action`, canonical target and scope object it
   currently discards. That is the smallest honest starting point and it is a
   schema + write-path change.
3. **Not automatic semantic derivation** (ADR G). An explicit, deterministic
   rule over structured fields — not a similarity score over prose.
4. **`overlaps_with` is the field §4.2 already reserved** for the "related, not
   identical" answer.

One consistency note against the design doc, surfaced rather than glossed:
§4.2's persisted Task JSON lists `goal`, `parent_task_id`, `overlaps_with` and
does **not** list `action`/`target`/`scope_object_id`. Persisting those three is
therefore an *extension* of §4.2's shape — but it is the extension §11.3's
binding constraint 2 already sanctioned, and it reuses `ProposedTask`'s existing
fields rather than inventing a parallel scheme. Flagged here so the schema
change is a decision on the record, not a quiet drift.

---

## 2. What a task must persist (agreed regardless of option)

Both options below start from the same write-path change, which is constraint 2:

`create_task` stops discarding `ProposedTask.action`, `ProposedTask.target` and
`ProposedTask.scope_object_id`. The target is stored **canonicalized** by the
real Target Canonicalizer (the same `normalize_target` the resolver uses), so
`10.79.0.0/24` and any other spelling of that network collapse to one value and
the stored identity does not depend on how the model wrote it. A target that
will not canonicalize is stored as-is with a flag, and is treated as *never
matching* anything — a task nobody can reduce is a task no dedup could safely
compare, and it must not silently match (that would be a fail-open drop).

New columns on `tasks`: `action TEXT`, `canonical_target TEXT`,
`scope_object_id TEXT`, and a computed `identity_key TEXT` (§3 defines it).
`ProposedTask` is unchanged — it already carries all three; only `create_task`
and the table change.

This alone is not a dedup. It is the precondition for one, and it is where the
two options diverge.

---

## 3. The identity key, and the two options

### The choice in one sentence

Either the task stays **host/target-level** (the granularity it can express
today) and duplicates are *marked, never dropped* — or the task is **widened to
carry sub-host (service/port) granularity** so an exact match can be told apart
from A/B and safely refused. The first respects the plan/dispatch boundary D17
held; the second reopens it.

### Option 1 — target-level identity, `overlaps_with`, never drop *(recommended)*

**Identity key:** `(action, canonical_target)`. Scope object is persisted but
**not** part of the key — the same host scanned under two different valid scope
objects is the same work, and scope is an authorization fact, not a
work-identity one (this is D17's `work_key`, the measure the harness already
used).

**On a match:** the new task is **still created**, and its `overlaps_with` is
populated with the ids of the existing queued/active tasks that share its
identity key (and those tasks' `overlaps_with` is updated symmetrically). A
match is a *signal to a reader*, never a refusal.

**How it handles the Redis/relay case:** A and B share `(network.scan,
ip:10.79.0.2)`, so at the task layer they are flagged as **overlapping** — and
both are created. Neither is dropped. They then flow to two separate proposals
and, at dispatch, to §7's execution fingerprint, which keys on
`normalized_params` and *does* carry ports: A fingerprints on `:6379`, B on
`7001-7002`, so **both scans run** and neither is deduplicated away
(`test_the_same_host_scanned_for_different_ports_is_not_deduplicated` already
pins this). The port-level distinction is made at the one layer that actually
has ports.

**What this buys, and what it does not.** It makes the `blind` arm's pile-up
*visible*: 16 tasks on one sweep would each carry an `overlaps_with` the
Supervisor's `query_tasks` (and a human) can see and act on, where today they
are invisible. It never risks dropping a real scan. It does **not** by itself
prevent the duplicate *proposal / decision / capability* — only §7 stops the
redundant *tool run*. That cost is cheap and fully audited; the alternative
(dropping) trades it for the risk of deleting work, which constraint 1 forbids.

**The honest cost against the brief's wording.** Under Option 1 the task-layer
comparison calls A and B "overlapping", i.e. *same target-level work* — it does
**not** report them as "different work" at the task layer. The brief's step-2
check ("Redis vs 7001-7002 判斷成不同工作") is satisfied *at execution time by
§7*, not at the task layer, because the task layer has no ports to judge on.
If the requirement is that the **task-layer** comparison itself distinguish
them, that is Option 2 and its cost is below. This is the single point I need a
decision on (§6).

### Option 2 — endpoint-level identity via an enriched target, allow refuse-on-exact-match

**Identity key:** `(action, canonical_target)` where the target may now be a
*service endpoint* — `10.79.0.2:6379` versus `10.79.0.2:7001-7002` — so A and B
carry different targets and are distinguished at the task layer. With a precise
key, an **exact** structural match (same action, same endpoint, same
everything) may be safely refused/skipped rather than merely marked, because it
is provably the same work.

**What it requires.** The Supervisor's `plan_schema` must permit a port/service
in the target. That is a widening of the schema D17 deliberately closed
(`additionalProperties: false`, no tool parameters), and it moves the line
between "planning" (what to look at) and "dispatch" (how to scan it): a target
of "the Redis service at :6379" is arguably still a target, but "ports
7001-7002, version scan" starts to read as tool configuration. It also adds a
structured, model-authored field on the *trusted* side of the boundary (§11.4's
concern), and it **degrades to Option 1 anyway** for the many tasks that name no
port ("enumerate services across the /24") — so Option 2 does not replace
Option 1's `overlaps_with` fallback, it sits on top of it and needs both paths.

**What it buys.** It can actually *prevent* the duplicate proposal/decision/
capability for exact endpoint matches, not just flag it — and it satisfies the
brief's "judged different work at the task layer" literally.

### Option 3 — compare the goal text *(rejected, named to close it)*

A string or embedding similarity over `goal`. Rejected by the brief explicitly
and by ADR G: automatic semantic derivation whose errors are false negatives is
the exact thing §1.2c calls a security bug. D17 measured that a literal goal
comparison catches <1% of real same-work pairs, and a fuzzier one buys recall by
buying false merges — the Redis/relay collapse, now with no structured field to
appeal to. Not pursued.

---

## 4. The resolution question — drop vs `overlaps_with`

The brief asks this directly and asks for a reasoned lean, not a coin flip.

**Recommendation: `overlaps_with` (mark, still create). Do not refuse or skip —
under Option 1 never, under Option 2 only on a byte-identical structured match,
and even there I would prefer marking.** The reasoning:

1. **Constraint 1 is asymmetric and decisive.** Dropping a task that turns out
   not to be a duplicate deletes a scan that should have run — a security bug.
   Marking a task that turns out to be a genuine duplicate costs one proposal,
   one policy evaluation and one capability — cheap, bounded and fully audited.
   The costs are not symmetric, so the default is not neutral.
2. **§7 already saves the expensive, dangerous part safely.** The redundant
   *tool execution* — the thing that actually touches the target — is
   deduplicated downstream by the execution fingerprint, which has the port
   granularity the task lacks. Dropping at the task layer would save only the
   proposal/decision/capability, which are cheap, while taking on the drop risk
   the fingerprint layer specifically avoids by keying on `normalized_params`.
   Putting a second, coarser dedup in front of it is a second place to get a
   false negative, against ADR G's "one explicit exact rule, no clever
   derivation" posture.
3. **The blind-arm harm is invisibility, and marking is the actual fix for it.**
   D17's damage was 16 workers each believing they owned unique work. `drop`
   hides the redundancy by deleting it; `overlaps_with` surfaces it to the
   Supervisor and to a human, which is what lets a *smarter* Supervisor (or an
   operator) choose not to act — without the kernel ever refusing work it cannot
   prove is redundant.
4. **It is the field §4.2 reserved for exactly this** — "related, not
   identical" — and it has never been written, so nothing regresses.

The one caveat: `overlaps_with` does not *reduce* duplicate proposals; it makes
them accountable. If the platform later wants to actually suppress duplicate
proposals, that is a separate decision that needs Option 2's precise key first,
and it should be a deliberate follow-on, not smuggled in as a drop here.

---

## 5. `query_tasks` — scoped to this decision

D17 declined to add `query_tasks(matching=…)` because "matching" was undefined,
and defining it *was* the task-identity decision. This ADR defines it, so the
function can now exist without settling anything sideways:

`query_tasks(engagement_id, action, target) -> tasks[]` returns the queued/
active tasks in the engagement whose **identity key** (§3, the *decided* one —
`(action, canonical_target)`) matches the given action and canonicalized target.
No free-text argument, no similarity parameter, no dimension beyond the identity
key this ADR defines. Read-only, on the ordinary `cyberorch_app` role with **no
new grant**, RLS-confined exactly like `query_state` and `query_findings` (the
`engagement_id` argument labels the connection's scope and cannot select another
engagement). It is the read side of the same key `create_task` writes, so a
Supervisor can ask "is this already queued?" before planning, and gets the same
answer `create_task` would compute.

---

## 6. The one decision I need before building

**Does the Redis/relay pair have to be distinguished at the *task layer*, or is
distinguishing them at *execution time* (§7) sufficient?**

- If §7 is sufficient → **Option 1** (target-level identity + `overlaps_with`).
  No schema widening, respects the plan/dispatch boundary, satisfies every
  binding constraint, and the two scans still both run. The step-2 validation
  then checks that the 25 blind-arm tasks yield **21 overlap-flagged
  duplicates** (25 − 4 distinct target-level keys) and that A and B are both
  created and both reach distinct fingerprints — i.e. *not merged*, which is the
  property that matters — while sharing a task-layer overlap flag.
- If the task-layer comparison itself must call A and B different → **Option 2**,
  and I need agreement to widen `plan_schema` to carry a service endpoint, with
  §11.4's trusted-side-text concern noted as the cost.

**My recommendation is Option 1.** It is the reading consistent with the role
boundary the whole D10–D17 stage established (the Supervisor plans; the Worker
and the execution layer own ports), it satisfies constraint 1 by construction,
and it reframes D17's own false positive correctly: the coarse task-level key
calling A and B "overlapping" is *harmless* precisely because nothing is
dropped, and the true distinction is preserved where the port information
actually lives.

---

## 7. Step two, once a granularity is chosen (for reference, not yet done)

1. **Schema + write path.** New `tasks` columns; `create_task` canonicalizes and
   persists action/target/scope, computes the identity key, and on a match
   populates `overlaps_with` symmetrically (still inserting). `ProposedTask`
   unchanged.
2. **`query_tasks`** as in §5, scoped to the decided identity key.
3. **Validation on committed D17 data** (`docs/d17_runs/`, no new measurement):
   replay the `blind` arm's 25 tasks through the new logic and assert **21**
   are flagged as overlapping an existing task (25 − 4 distinct keys); replay
   A and B from the `accumulating` arm and assert **both are created and neither
   is dropped** (Option 1) — or, under Option 2, that they receive **different**
   identity keys and are not merged.
4. **Mutation tests, D16-style.** Remove or invert one leg of the identity
   comparison (drop `action` from the key; skip canonicalization so a raw
   spelling silently fails to match; let an un-canonicalizable target match
   instead of never-match) and assert a test goes red for each — so the
   comparison cannot fail open on a missing field or a type slip.

Step two does not begin until §6 is answered.
