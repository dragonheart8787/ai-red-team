# ADR: classification inheritance — downward restriction only

Status: **proposed, D25. Awaiting a decision before any implementation.** No
schema, Metadata Resolver, or Rego change is made until the direction in §7 is
chosen. Addresses item 5.1 (hierarchical classification inheritance) on the
candidate list (`ACCEPTANCE_MVP1_AGENTS.md` §3).

This is step one of D25: a design decision, not code. It answers the four
questions the brief set — how a parent is defined per scope-object type, how the
conflict case resolves, whether inheritance is computed at query time or
materialized, and how the tests stay separate — and it reports one boundary
finding the brief asked to be told about (§6).

The scope limit the brief drew is load-bearing and is honoured throughout:

> This deliverable touches **only the Metadata Registry's classification
> inheritance** (`data_class` / `resource_class`). It does **not** touch the
> Scope Registry's authorization decision. I8 / D11-4 / D11-5 settled that
> authorization is an *exact* `scope_object_id` match with no hierarchy
> derivation, and that stays exactly as it is. If the implementation turns out
> to entangle the two — in the data model or the query path — stop and report
> rather than share logic for convenience.

§6 is that report. The short version: the two decisions do not entangle, but
they share one piece of pure containment *arithmetic* (is this CIDR inside that
CIDR; is this host under that suffix), and the honest way to reuse it is to
extract it into a neutral primitive that neither owns, rather than have the
metadata path import from `authorization.py`.

---

## 1. The problem (brief context)

Today `resolve_metadata` (`control_plane/canonicalizer/metadata.py`) answers
"what is this resource" by an exact `(identity_type, identity_value)` lookup
against `metadata_registry`, then applying §5 precedence:

- exactly one AUTHORITATIVE row → its `resource_class` / `data_class` become the
  canonical answer, `known = True`;
- no AUTHORITATIVE row → `authority = UNKNOWN`, `known = False`, canonical
  fields empty;
- more than one AUTHORITATIVE row → `authority = CONFLICT`, `known = False`
  (I10, fail closed);
- lower-tier rows (OBSERVED / INFERRED / LLM_HINT) never fill canonical fields;
  they become `observations` (I6b anti-laundering).

The gap: classification is registered against whole ranges, but resolved against
single hosts. An Engagement Manager marks `10.79.0.0/24` AUTHORITATIVE **PII**.
A proposal then targets `10.79.0.42`, a host with no row of its own. Exact
lookup finds nothing → UNKNOWN → the host is treated as unclassified, and a
prerequisite action against it escalates to HUMAN_APPROVAL rather than being
denied on the PII the Engagement Manager already declared for its enclosing
range. The declared restriction on the parent does not reach the child.

The brief's decision — already taken, not reopened here — is to close that gap in
**one direction only**:

- **Downward restriction (DO):** an AUTHORITATIVE, deny-relevant classification
  on a parent reaches an unregistered child. The child is treated as *at least
  as restricted* as the parent.
- **Downward relaxation (DO NOT):** an *absence* of any AUTHORITATIVE mark on a
  parent says nothing about a child. A range no one classified does not make its
  hosts clean. A child with no row stays UNKNOWN → HUMAN_APPROVAL for
  prerequisite actions, exactly as today.

Everything below serves that asymmetry. Inheritance may only ever *tighten*; it
may never manufacture a known-and-permitted answer where there was none. This is
the D3 binding constraint already written into `metadata.py`'s docstring.

---

## 2. Q1 — what "parent" means, per scope-object type

A parent is a *registered AUTHORITATIVE row whose identity strictly contains the
child's identity*, under a containment relation that is defined per identity
type. The identity types are the six in `IDENTITY_TYPES`
(`fqdn`, `ip`, `cidr`, `url`, `repo`, `ad_domain`). Containment is defined only
where it has an unambiguous, arithmetic meaning:

| Child identity | Parent identity | Containment relation | Source of the arithmetic |
|---|---|---|---|
| `ip` | `cidr` | address ∈ network | `ipaddress.ip_address(child) in ip_network(parent)` |
| `cidr` | `cidr` | subnet ⊆ supernet | `ip_network(child).subnet_of(ip_network(parent))` |
| `fqdn` | `fqdn` | suffix match at a label boundary | `child.endswith("." + parent)` — see §2.1 |
| everything else | — | **no inheritance** | §2.2 |

This is deliberately the *same* geometry the Authorization Resolver's
`scope_covers_target` already computes for scope objects — an IP is inside a
CIDR, a subnet is inside a supernet, a host is under a domain — because "is A
geometrically inside B" is one fact about addresses and names, and the system
must not answer it two different ways. §6 is about how that reuse is done without
crossing the authorization boundary.

Note two identity-type asymmetries carried straight over from §4.1.5:

- an `fqdn` child never inherits from a `cidr` parent and vice versa. Resolving a
  name to an address is exactly the step §8.9 / I8 forbids as an authorization
  input, and it is equally forbidden as a classification input. A name and an
  address are different identities even when they point at the same host.
- an `ip` is a leaf on the address side (nothing is *inside* a single host) but
  is a child on the CIDR side. A `/32` written as a `cidr` and a bare `ip` are
  the same host to `subnet_of`/`in`; the arithmetic handles both.

### 2.1 FQDN containment: parent is a proper suffix at a label boundary

`api.pii.customer-a.com` inherits from an AUTHORITATIVE row on
`pii.customer-a.com` (a proper parent domain), and from one on `customer-a.com`,
but **not** from a row on `a.com` unless `a.com` itself is the registered
parent domain of `customer-a.com` — which, by label decomposition, it is not
(the parent of `customer-a.com` is `com`, not `a.com`). Containment is: the
child equals `something` + `"." + parent`, i.e. `parent` is a suffix of `child`
beginning at a dot. `customer-a.com` does **not** end at a label boundary of
`a.com` (`...customer-a.com` — the boundary falls inside the `customer-a`
label), so substring-style suffix matching is refused, exactly as
`fqdn_covered` already refuses it in Rego (`host != trim_prefix(suffix, ".")`
and the leading-dot check).

One decision to make explicit: registry FQDN rows are registered as **bare
domains** (`pii.customer-a.com`), not as `*.` wildcards. The `*.` form is a
*scope-object* construct (§4.1.5, "a target is one host; a scope is a set"); a
metadata row classifies a named thing, not a set expressed as a pattern. So the
inheritance suffix test treats a stored FQDN value `D` as covering child `H`
iff `H == D` (exact, which the existing exact lookup already handles) or
`H.endswith("." + D)`. No wildcard parsing on the metadata side. If we ever want
`*.` metadata rows, that is a separate decision; this ADR does not introduce
them.

### 2.2 url, repo, ad_domain: no inheritance (recommended)

These three are compared verbatim everywhere in the system (`canonicalize_scope_value`
returns them unchanged; `scope_covers_target` requires exact equality). They have
internal structure a human reads as hierarchy — a URL has a path, a repo has an
org, an AD domain has a tree — but the system has **no** canonical containment
arithmetic for any of them, and inventing one here would be exactly the "a value
the system only ever compares for equality" trap that `target.py` already names
and refuses. In particular:

- **url**: is `https://host/admin` a parent of `https://host/admin/users`? Path
  prefix looks obvious but is a minefield (`/admin` vs `/administrator`, trailing
  slashes, query strings, the host-vs-path question). We already normalize paths
  but have never defined path *containment*.
- **repo**: is `github.com/org` a parent of `github.com/org/repo`? Only if we
  decide org-level classification cascades to every repo, which is a policy
  choice, not arithmetic.
- **ad_domain**: `corp.example.com` vs `child.corp.example.com` looks like the
  FQDN case but AD domain trees are not DNS suffix trees in general.

**Recommendation:** these three inherit *nothing* in D25 — a child of one of
these types with no AUTHORITATIVE row of its own stays UNKNOWN. This is the
fail-closed direction: no inheritance means no false *clearing* and also no
false *restriction*; the operator can always register an explicit row. If a real
engagement needs URL-path or repo-org cascade, that is a future ADR with its own
containment definition, not a convenience bolted on here. Defining containment
for a type is a decision that deserves to be made deliberately, once, with tests
— not defaulted into because the code path happened to be open.

---

## 3. Q2 — the conflict case, and why "stricter wins" falls out for free

The case the brief flagged: the child has its **own** AUTHORITATIVE row saying
non-PII (say `resource_class = ["web"]`, `data_class = []`), while an
AUTHORITATIVE **parent** says PII. Two authoritative statements, pulling opposite
ways. The brief leans toward the stricter (union / PII) winning, fail-closed,
aligned with I10, and asks for the reasoning and the alternatives.

The decision rests on a fact about the existing policy that makes most of this
question answer itself. There are **two** deny paths in `authz.rego`:

```rego
deny_reasons contains "forbidden_data" if {          # reads CANONICAL data_class
    some class in canonical_data_class
    class in data_deny
}
deny_reasons contains "forbidden_data_observed" if {  # reads OBSERVATIONS
    some class in observed_data_class
    class in data_deny
}
```

Both are hard DENY. The design comment on the second is explicit: *"tightening is
always permitted, from any source … an LLM_HINT of PII still denies; only an
AUTHORITATIVE row can clear a prerequisite."* An inherited parent classification
emitted **as an observation** therefore gets fail-closed DENY behaviour on a
deny-listed class **without one line of new Rego**, and it gets it *whatever the
child's own canonical row says*, because observations and canonical are unioned
on the deny side and neither can suppress the other.

That is the whole conflict resolution, and it is why the recommended
representation (§4, Option B) is "inheritance is an observation":

- **Parent PII, child's own canonical non-PII (the brief's case):** the child's
  canonical answer stays its own AUTHORITATIVE non-PII row (exact match still
  wins for the canonical field — the child *is* what its own authoritative row
  says it is). The inherited parent PII rides along as an **observation**. If
  `PII ∈ data_deny`, `forbidden_data_observed` fires → DENY. Stricter wins, fail
  closed, and canonical still means "this resource's own exact AUTHORITATIVE
  classification" — untouched. No CONFLICT is raised, because there is no
  contradiction *within the canonical field*: the child's canonical row is the
  sole authoritative statement about the child itself; the parent's statement is
  about the parent, applied downward as a lower-trust signal.
- **Parent PII, child has no row at all:** canonical stays UNKNOWN (`known =
  False`), the inherited PII is an observation, `forbidden_data_observed` denies
  a deny-listed class, and for a non-deny-listed but still-declared class
  `non_authoritative_sensitivity` already raises HUMAN_APPROVAL. The child is
  never silently cleared.

### 3.1 Why *not* fold inheritance into the canonical field

The tempting alternative is to make the inherited parent class part of the
child's canonical `data_class` (a union: child's own ∪ parent's). Rejected, for
two reasons that go to the core invariants:

1. **It would break "canonical = exactly one AUTHORITATIVE row about *this*
   resource."** I6b/I6c and the whole v0.3 fix rest on canonical being a single,
   traceable, authoritative statement with a `classification_source` and
   `classification_version` pointing at one registry row. A unioned field has no
   single source row and no single version. `resolve_metadata` returns
   `classification_source` / `classification_version` today; an inherited-into
   canonical answer could not honestly fill them.
2. **The CONFLICT machinery would misfire.** If inheritance wrote into canonical,
   the parent-PII / child-non-PII case becomes "two authoritative classes in the
   canonical field," which I10 says is CONFLICT → deny with
   `classification_conflict`. That is *also* fail-closed, so it is not wrong for
   safety — but it is wrong for *meaning*: it reports a conflict between two rows
   that do not actually disagree (one is about the /24, one is about the host),
   and it would deny the child even for classes that are not on the deny list,
   turning every inheriting host into a CONFLICT. Keeping inheritance in
   observations reserves CONFLICT for its real meaning: two AUTHORITATIVE rows
   about *the same identity* disagreeing.

### 3.2 Alternative considered: strict union with a distinct "inherited" tier

We could add a fifth classification tier `INHERITED`, ranked between
AUTHORITATIVE and OBSERVED, and teach the resolver and Rego about it. Rejected as
over-engineering for D25: it needs a schema/enum change, a new Rego branch, and a
new precedence rule, and it buys nothing over "emit as observation" for the
deny-side behaviour, which is the behaviour that matters. The observation channel
already carries `authority`, `source`, `resource_class`, `data_class` per
`Observation`; an inherited observation can set `source` to something like
`INHERITED_AUTHORITATIVE` and `authority` to the parent's, so the provenance is
not lost — it is recorded in the observation, not promoted into canonical. If a
future need appears for inheritance to *clear* a prerequisite (it must not, per
the brief), that would be the moment to reconsider — and the answer would still
be no.

**Recommendation: Option B — inheritance is emitted as an observation, never
into the canonical field. `known` is never set True by inheritance.** Stricter
wins and fail-closed both fall out of the existing `forbidden_data_observed`
path; canonical keeps its exact-AUTHORITATIVE-only meaning; CONFLICT keeps its
same-identity meaning.

---

## 4. Q3 — query time vs materialize

Two ways to make the parent's classification reach the child:

- **(A) Query-time computation.** `resolve_metadata`, after its exact lookup,
  runs a second query for AUTHORITATIVE rows whose identity contains the target,
  and folds any it finds into `observations`. Nothing is written.
- **(B) Write-time materialization.** When an AUTHORITATIVE parent row is
  registered, expand it: write derived rows onto known children, or maintain a
  closure table.

**Recommendation: (A), query-time**, for the same reason D14 chose "report,
don't recompute" and the resolvers are pure read functions:

- **Consistency.** A materialized child row goes stale the moment the parent
  changes, is deactivated, or a closer parent is registered. The registry is
  versioned and rows are deactivated, not deleted; a materialized inheritance
  would need its own invalidation to track all of that, and a stale *restriction*
  that outlives its parent is a silent policy drift. Query-time reflects the
  registry's current state by construction.
- **It only ever tightens, so it is cheap to be always-correct.** The second
  query is bounded (a handful of candidate parents per target) and read-only.
- **No new write path, no new grant.** This is a brief requirement and it comes
  free with (A). Materialization would need `registry_admin` (or a new writer) to
  emit derived rows, widening a write surface the whole design works to keep
  narrow. Query-time touches `metadata_registry` read-only under the existing
  `cyberorch_app` RLS-scoped connection — same engagement boundary, no new grant.
- **Provenance stays honest.** The inherited observation names the exact parent
  row it came from at read time; there is no derived row pretending to be a
  primary fact.

The cost is a second query per resolve. Given the resolver already does one
lookup and the candidate-parent set is tiny, this is not a concern at MVP scale;
if it ever becomes one, a materialized cache can be added *behind* the same
function without changing its contract.

---

## 5. Q4 — the separate test set (D3 binding constraint)

D3 requires inheritance to be a **separate code path with separate tests**, and
the inheritance tests must **not** be mixed into the exact-match precedence
tests. Concretely:

- A new test module (e.g. `tests/test_metadata_inheritance.py`), distinct from
  the existing exact-precedence tests (`tests/test_metadata_resolver.py` or
  wherever `resolve_metadata`'s precedence is pinned). The existing precedence
  suite must keep passing **unchanged** — that is the regression guarantee that
  inheritance did not perturb exact resolution.
- The inheritance suite pins, at least: IP-in-CIDR inherits parent PII as an
  observation; CIDR-in-CIDR (subnet) inherits; sibling/non-containment does
  **not** inherit; FQDN suffix inherits at a label boundary and does **not**
  inherit on a non-boundary suffix (`customer-a.com` ⊄ `a.com`); `url`/`repo`/
  `ad_domain` inherit nothing; a child with its own AUTHORITATIVE non-PII plus
  parent PII yields canonical = child's own, observation = parent PII, and (with
  PII on the deny list) a DENY via `forbidden_data_observed`; inheritance never
  sets `known = True`; no AUTHORITATIVE parent → no inheritance (the
  downward-relaxation prohibition).
- One test asserts the **shared containment primitive** (§6) is the *same* one
  `scope_covers_target` uses — the D14-style "verify the shared predicate is
  actually shared," so the two containment answers can never drift apart.

---

## 6. §6 boundary report — the one place the two touch, and how to keep them apart

The brief asked to be told if authorization and classification turn out to
entangle in the data model or the query path. Here is the honest finding.

**At the decision level: they do not entangle.** Authorization stays an exact
`scope_object_id` match (I8 / D11-4). Classification inheritance is a separate
read against `metadata_registry`, keyed on identity containment, feeding only the
`observations` channel. No inheritance result ever becomes an authorization
input, and no scope object is ever consulted to answer "what is this resource."
The two queries hit two different tables and produce two different outputs.

**At the arithmetic level: they share one thing — containment geometry.** The
"is this IP inside that CIDR / is this host under that domain" math already lives
in `authorization.py::scope_covers_target`, bound to the `ScopeObject` and
`CanonicalTarget` types. The metadata ancestor query needs the *same* geometry
between two `metadata_registry` identities. There are three ways to get it, and
only one is clean:

1. **Copy the arithmetic into `metadata.py`.** Rejected — this is precisely the
   "answer one fact two ways" that D15's mutation test punished. Two copies drift;
   one gets a fail-open fix the other misses.
2. **Import `scope_covers_target` from the metadata path and feed it fabricated
   `ScopeObject` / `CanonicalTarget` instances built from metadata rows.**
   Rejected — *this* is the entanglement the brief forbids. It would make the
   classification path depend on the authorization module and dress metadata rows
   up as scope objects and targets, exactly blurring the line v0.3 drew. It also
   couples to those dataclasses' fields for a use that has nothing to do with
   authorization.
3. **Extract the pure geometry into a neutral primitive that neither owns**, e.g.
   `control_plane/canonicalizer/containment.py::identity_contains(parent_type,
   parent_value, child_type, child_value) -> bool`, operating on plain
   `(type, value)` pairs with no `ScopeObject`, no `CanonicalTarget`, no registry
   or authorization concept inside it. `scope_covers_target` is refactored to
   call it (pinned by its existing tests — the refactor must be behaviour-
   preserving, asserted byte-for-byte on the current suite), and the metadata
   ancestor query calls the same function. One implementation of the geometry,
   zero dependency of classification on authorization, and the shared-predicate
   test in §5 keeps them provably identical.

**Recommendation: option 3.** It satisfies D3 constraint-3's "share one canonical
containment logic" *and* the brief's "do not entangle authorization and
classification" at the same time, because what is shared is pure address/name
geometry — a thing that is neither an authorization decision nor a classification
decision — while the two *decisions* stay in their own modules reading their own
tables. If the reviewer prefers to keep the containment inside `authorization.py`
and have metadata import it, that is option 2 and I will not do it without an
explicit call, because it crosses the line this ADR was told to watch.

This is the one item that needs an explicit yes/no before implementation:
**extract a neutral `containment` primitive (option 3), or something else?**

---

## 7. Decision requested

Before any code, schema, or Rego change, please confirm:

1. **Parent definition (§2):** IP∈CIDR, CIDR⊆CIDR, FQDN proper-suffix at a label
   boundary; `url`/`repo`/`ad_domain` inherit nothing in D25. FQDN metadata rows
   are bare domains, no `*.` wildcard on the metadata side.
2. **Conflict / representation (§3, §4-representation):** inheritance is emitted
   as an **observation**, never into canonical; `known` is never set True by
   inheritance; stricter-wins and fail-closed come from the existing
   `forbidden_data_observed` path; CONFLICT keeps its same-identity meaning.
3. **Query time, not materialized (§4):** read-only second query inside
   `resolve_metadata`; no new write path, no new grant.
4. **Separate tests (§5):** new module; existing exact-precedence suite unchanged;
   a shared-predicate test pins the containment reuse.
5. **Boundary (§6):** extract a neutral `containment` primitive (option 3) that
   both `scope_covers_target` and the metadata ancestor query call — refactoring
   `scope_covers_target` behaviour-preservingly to use it.

On approval, D25 step two implements exactly this and nothing beyond it.
