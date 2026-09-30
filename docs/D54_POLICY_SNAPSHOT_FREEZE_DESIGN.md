# D54 — Policy Snapshot freeze (ACCEPTANCE 5.20): design note

**Status: design only for 5.20 -- nothing here is built. Update (D54 follow-up): the two prerequisites this note found were taken ahead of the freeze and are done -- 5.35 (customer scoping; the shared predicate now feeds all three readers) and 5.36 (migration 0013 narrowed the runtime role's grants). Sections 1, 3 and 5 are written as the state before that work; the notes marked *since done* say what changed.** This answers the four
questions D54 asked and ends with the decisions that are yours. Every fact below was read in
the code or **executed against the local test database** (an ephemeral database of
`ENG-TEST`/`ENG-X-*` engagements; the experiment layers were deactivated afterwards);
inference is labelled as such.

## 0. What §4.5 asked for, and what exists

§4.5 (v0.2): `Effective Policy = Baseline Global Snapshot (frozen when the engagement is
created) ∩ Emergency Overlay (published any time, only tightens, global, immediate) ∩ Customer ∩
Engagement`. The reason for the split is written in the section: the customer signed against one
baseline and a later global publish must not silently rewrite it, but a discovered bypass must
still be closable at once — that is the overlay's job.

Today (verified):

* `load_effective_policy` selects every `active` layer with `engagement_id IS NULL OR
  engagement_id = :eid` and folds them (`layers.py:261`, `_APPLICABLE`). It never reads
  `engagements.policy_snapshot_version`; `test_load_effective_policy_does_not_read_the_snapshot`
  pins that.
* A later `baseline_global` publish therefore applies to **every open engagement at once**, and
  it moves each one's `current_policy_version`, so outstanding capabilities are revoked at the
  next heartbeat (executed: engagement A's version went 82597 → 82599 when a baseline was
  published *from engagement B*).
* **A later baseline can also widen.** `resolve_action` is DENY-dominant but an `ALLOW` beats
  `INHERIT` and all-`INHERIT` is DENY (`merge.py:198`). Executed: with no layer mentioning an
  action, `action_decision` is `DENY`; a newly published layer with `actions: {a: ALLOW}` makes it
  `ALLOW` for an already-open engagement. Only `emergency_overlay` has a tighten-only `CHECK`
  (`policy_layers.emergency_overlay_can_only_tighten`); `baseline_global` has none.
  So the retroactivity §4.5 wanted to prevent runs in **both** directions today, not only the
  tightening one.

## 1. Does the freeze split `_APPLICABLE` into two rules?

**It changes the predicate, and it does not need two rules — but there is a bigger finding first.**

**Finding: there are already three copies of the predicate, not one.** *(Since done: `current_policy_version` now reads the shared predicate, with a structural test. The freeze's clause is one more line in that single place.)* The D14 guarantee is that
enforcement and the listing share `_APPLICABLE`. Verified true for those two
(`load_effective_policy`, `list_effective_policy_layers`). But `broker.current_policy_version`
(`broker.py:231`) hand-writes the same `WHERE active IS TRUE AND (engagement_id IS NULL OR
engagement_id = :eid)` in its own SQL; `layers.py`'s docstring says the loader "selects the same
set `current_policy_version` counts", which is true of the *values* and enforced by nothing.
`test_policy_layers.py` pins listing = merge; I found no test that pins the version's basis to either. A
freeze changes the predicate in one place and would leave the version — and so which capabilities
get revoked — describing a different set. That is the D14 failure, in the third place.

**Proposed shape.** Keep one fragment, parameterised by the engagement's own row:

```sql
FROM policy_layers pl
LEFT JOIN engagements e ON e.engagement_id = :eid
WHERE pl.active IS TRUE
  AND (pl.engagement_id IS NULL OR pl.engagement_id = :eid)
  AND (pl.layer <> 'baseline_global'
       OR e.baseline_frozen_through IS NULL
       OR pl.id <= e.baseline_frozen_through)
```

One statement, one extra clause that applies to one layer category. All three consumers use it:
the loader, the listing and `current_policy_version` (which moves out of `broker.py`'s private SQL
onto the shared helper). That is "one fact, one authority" preserved, rather than the two-rule split
the D39 note feared. `baseline_frozen_through` is `NULL` for an engagement that has no freeze, which
makes the clause a no-op for it (see §4).

**How the divergence stays impossible — new tests, in this order of strength:**

1. *Structural.* A source scan: the only `SELECT … FROM policy_layers` in `control_plane/` is the
   shared helper. Adding a fourth private copy fails the build (the equivalent of the
   `keys_read` / carry check D53 built for constraints). Mutation: re-inline the predicate in
   `broker.py` → red.
2. *Same-statement spy* (extends D14's `test_the_listing_returns_exactly_the_rows_the_merge_consumed`).
   Over a scenario matrix — {unfrozen legacy, frozen} × {baseline published after, overlay after,
   engagement layer after, a frozen-in row deactivated, a not-frozen-in row deactivated} — assert
   `ids(listing) == ids(rows the loader's statement returned)` **and**
   `current_policy_version == max(ids(listing))`. The third equality is the new one.
3. *Model-based oracle.* An independent ~30-line Python model of §4.5's formula over an event
   history (create / publish / deactivate), compared with `load_effective_policy` under Hypothesis
   (the stateful suite already uses it). The oracle is written from the section text, not from the
   SQL, so it can disagree with the SQL.
4. *Fail-open guard.* A frozen engagement never has *fewer* baseline `data_deny` / `scope_deny`
   entries than the rows that existed at its creation. A boundary bug that drops a baseline is a
   dropped deny — the fail-open direction — so it is tested as its own property.

## 2. A new, tighter baseline: immune, or does it penetrate?

**Recommendation: full immunity. Only an `emergency_overlay` reaches a frozen baseline.**

* *Against the alternative.* "Penetrate only if tighter" needs a decision procedure for
  tighter. The algebra has none: the baseline has no tighten-only constraint, a single document
  can tighten one field and widen another (`data_deny` up, `actions` ALLOW added), and §0 shows
  widening is real. Building "accept the tightening parts" means validating a baseline document as
  though it were an overlay — reimplementing `validate_emergency_overlay` under another name — and
  making `baseline_global` a **second retroactive channel** without the `CHECK` the first one has.
* *Against §4.5 / D16.* §4.5 introduces the overlay precisely so retroactive change has one
  separately stored, separately reviewed, schema-limited channel ("只能新增 deny 規則，schema 上直接
  不允許 allow 欄位"). D16 put the `CHECK` on that channel because the danger is a retroactive path
  that can relax. Letting a baseline penetrate when it happens to tighten weakens the only reason the
  overlay is separate.
* *The cost, stated.* An operator who wants a fleet-wide tightening must publish it as an overlay
  (which already validates and refuses any ALLOW). Mitigation, report-only (D14's "reports, does not
  decide"): the listing gains a `frozen_out` section — baseline rows newer than this engagement's
  boundary that are **not** applied — so "why does engagement X not have the new deny" is answerable
  without SQL. No auto-promotion of a baseline into an overlay.
* *What legitimate widening uses instead.* The `engagement` layer is unfrozen and may `ALLOW`; it is
  per-engagement and audited (D11-7). A frozen engagement that needs a new action gets an engagement
  layer, not a global one.

## 3. Copy the content, or store a version and look back?

**Checked, not assumed.** `policy_layers` supports lookback by id: ids are `BIGSERIAL`
(monotone), rows are only inserted and soft-deactivated, `created_at` exists, `version` is
publisher-supplied and unique per (layer, version, engagement, customer). "Baseline rows that
existed at creation" is `id <= boundary`. Three things limit that:

| Fact (executed unless marked) | Consequence |
|---|---|
| `cyberorch_app` holds `UPDATE` and `DELETE` on `policy_layers`: `UPDATE … SET document='{}'` and `DELETE` both returned rowcount 1. The blanket `GRANT … ON ALL TABLES` (migration 0001) was revoked only for the append-only tables. Production code does only `INSERT` and `SET active = FALSE` (`layers.py:124,193`). | A version pointer inherits **mutable history**: editing or deleting a frozen-in row silently changes what the engagement is frozen to. Unlike `evidence`/`audit_log`, nothing at the privilege level prevents it. |
| `active` records only the *current* state; there is no `deactivated_at`. | "Active at creation" is not recoverable; the pointer can say "existed then and active now". |
| `customer` layers are not customer-scoped (§7, finding 5.35). | "The customer layers" is not a well-defined set to snapshot today. |

**Option V — boundary pointer, plus make the rows immutable.** Store one number on the
engagement; `REVOKE UPDATE, DELETE ON policy_layers FROM cyberorch_app; GRANT UPDATE (active)
ON policy_layers TO cyberorch_app` (a column-level grant; the only production writes are `INSERT`
and `active`; the one test that sets `active = TRUE` is covered). Content is not duplicated, so it
cannot drift from the source rows.

**Option S — copy the documents at creation** into an insert-only table. Immune to later edits by
construction, but it is a second representation of the same fact that must be reconciled with
`active` (a deactivation must still lift a copied row, or a bad baseline can never be retired for open
engagements), needs a join in the loader, the listing and the version, and a migration of a new
table with RLS and grants. More surface, more places to disagree — the property D14 spent an
entire deliverable removing.

**Recommendation: V, with the grants.** *(Since done: the grants are migration 0013 -- `policy_layers`: INSERT/SELECT + `UPDATE (active)`; `engagements`: SELECT + `UPDATE (status, kill_switch_engaged, updated_at)`. The freeze's boundary column will be covered by that column list by construction: the runtime role cannot write it.)* The consistency risk in V (mutable rows) is closed by a
two-line privilege change that also fixes the same gap for its own sake; the consistency risk in S
(copy vs source) has no equivalent fix. Both are judged as D14 judged them: prefer reporting the
rows the merge used over a recomputed copy of them.

The engagement row needs the same treatment: `cyberorch_app` can `UPDATE` any column of
`engagements` (D39 removed only `INSERT`/`DELETE`). A boundary that the runtime role can set to
`NULL` is a freeze it can lift. The two `UPDATE engagements` statements (`engagement.py:243,367`)
touch `kill_switch_engaged`, `status`, `updated_at`; a column-level grant to exactly those closes it,
with a D39-style test asserting `InsufficientPrivilege` for the boundary column.

## 4. `create_engagement`: store a number, or take a snapshot?

**Store a number.** Verified smaller and lower-risk: `create_engagement` already reads
`current_policy_version` (the maximum applicable id) before inserting. Because ids are global and
monotone, every baseline row visible at that moment has `id <=` it, and every row published later has
a larger id, so the existing value *is* the boundary — the change is one new column and writing it
(plus the audit payload).

* **Use a new nullable column, `baseline_frozen_through BIGINT`, not `policy_snapshot_version`.**
  `policy_snapshot_version` is `NOT NULL INTEGER` and pre-D39 callers wrote the literal `1`;
  a legacy `1` is indistinguishable from a real version 1, and reading it as a boundary would
  **drop every baseline row with id > 1 — a mass fail-open**. `NULL` means "no freeze recorded" and
  the predicate treats it as live, exactly today's behaviour. This is D30/D11-7's rule (absence means
  *unknown*, never *none*; do not back-fill a plausible reconstruction). Executed: this database holds
  0 engagements with the literal 1, so nothing legacy exists here to migrate — but the design must not
  depend on that.
* **No backfill.** An existing engagement stays live until it is recreated. If you want an operator
  operation to opt one in, that is a separate, audited call — not part of this.
* **Known, benign race.** `create_engagement` reads the version and inserts in separate steps; a
  baseline committed in between lands on the "after" side of the boundary. Either side of creation
  is a legitimate reading of "when the engagement was created"; documented, not fixed.
* **Consequence to accept:** a baseline published *after* an engagement is created never reaches it,
  including the first baseline. An engagement created before any baseline exists is frozen with
  none (all actions default DENY until its own layers say otherwise).
* **Test-suite impact (counted).** The tests that publish a DB `baseline_global` after the engagement
  exists (by grep, about five sites across `test_policy_layers.py` and `test_engagement_creation.py`) and two live-run scripts
  (`scripts/live_run/live_run.py`, `d40_three_role.py`) would silently lose their baseline; they need
  to publish first or to assert the freeze deliberately. `test_load_effective_policy_does_not_read_the_snapshot`
  is inverted into the freeze's own test.

## 5. Proposed change, if approved (nothing done)

1. Migration `0015`: `engagements.baseline_frozen_through BIGINT NULL` (the grant changes it listed are
   already 0013; the new column is unwritable by the runtime role without any further grant).
2. `layers.py`: the shared fragment above; `current_policy_version` delegates to it;
   `list_effective_policy_layers` adds `frozen_out`.
3. `engagement.py`: `create_engagement` writes the boundary (from the value it already computes) and
   adds it to the `engagement.created` audit payload.
4. Tests as in §1 (structural, spy matrix, oracle, fail-open guard), the privilege tests, the
   inverted snapshot test, and mutation verification of each: re-inlined predicate, boundary compare
   flipped, `NULL` treated as `0`, `active` filter dropped, grants reverted.
5. Docs: `ARCHITECTURE.md` §4.5 pointer (not rewritten), `ACCEPTANCE` 5.20 closed, the D39 docstring's
   "never built" sentence updated.

Size, judged from the code above: one small migration, ~40 lines in `layers.py`/`broker.py`/
`engagement.py`, about 30 new tests, and edits to ~8 existing test sites and 2 scripts. The risk is
concentrated in one place — a wrong boundary drops a deny — which is why §1's fourth test exists.

## 6. Decisions that are yours

| # | Decision | My default |
|---|---|---|
| 1 | What freezes: baseline only, or also `customer` / `engagement` layers | **Baseline only.** `engagement` layers are the in-flight adjustment channel. `customer` layers are now well-defined (5.35) but §4.5's own text splits the freeze into a baseline snapshot plus a live overlay, so the smaller change is still baseline first; freezing customer layers would be a separate, later step |
| 2 | A newer baseline that *tightens*: immune, or penetrates | **Immune**; only an overlay reaches a frozen engagement (§2) |
| 3 | A frozen-in baseline row is later deactivated: does the engagement follow? | **Follows** (`active` still honoured) — deactivation is deliberate and audited, and a row that can never be retired for open engagements is worse. It is a widening path that D16's `CHECK` does not cover, but since 5.37 it is an operator's act over the `global_policy_admin` connection, not something a runtime credential can do |
| 4 | Pointer (V) or copy (S) | **V**, with the grants in §3 |
| 5 | Legacy engagements | **Stay live** (`NULL`), no backfill |
| 6 | Bundle the privilege hardening (`policy_layers`, `engagements` columns) and the `current_policy_version` de-duplication | **Done ahead of the freeze** (5.36, 5.35). Closing 5.36 found 5.37 -- who may write and retire *global* layers -- and **5.37 is now closed too** (migration 0014, the `global_policy_admin` role). That gives decision 3 a cleaner premise: a frozen-in baseline row can only be retired over that one operator-held connection, not by any engagement's runtime credential, so "the engagement follows a deactivation" now means "an operator decided to retire a baseline" |
| 7 | Fleet tightening ergonomics | **Report-only** `frozen_out`; no auto-promotion |

## 7. Findings this turned up (recorded as candidates, not fixed)

* **5.35 — `customer` policy layers are not customer-scoped.** *(Closed at D54, follow-up.)* `_APPLICABLE` never reads
  `customer_id`. Executed: a `customer` layer published with `customer_id = CUST-ALPHA` was applied to
  an engagement of `CUST-BETA` — including `actions: {a: ALLOW}`, which turned `DENY` into `ALLOW` for
  the other customer's engagement. Fail-safe for denies, cross-customer widening for allows. Not
  reachable in a single-customer deployment.
* **5.36 — the runtime role can rewrite `policy_layers` and any column of `engagements`.** *(Closed at D54, follow-up, migration 0013.)* Above (§3).
  Resolved as part of 5.20 if decision 6 is taken; otherwise it stands as a Class B candidate.

## 8. What this note does not do

It does not build the freeze, add a grant, or change a predicate. It does not decide the `customer`
question. It does not claim the boundary approach is free of the "widening through deactivation" path
— it names it (decision 3) and leaves the choice with you.
