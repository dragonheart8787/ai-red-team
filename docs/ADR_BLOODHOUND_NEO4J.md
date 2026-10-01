# ADR: BloodHound + Neo4j — Phase 1 investigation (D42)

Status: **decided and implemented (D42–D50).** As signed off: D42-1 option C (`ad_domain` authorizes
collecting only), D42-3 option A (Postgres is the sole classification authority), D42-4 (the
provenance/security-graph split unchanged), D42-6 (a bulk-collection shape, `dispatch_collection`),
and **D42-5: Postgres only — Neo4j was not adopted** (`docs/D42_1_D42_6_DESIGN.md`,
`docs/D42_2_CTE_BENCHMARK.md`; `control_plane/provenance/graph.py` says the same). Implementation
and its end-to-end verification are in the status updates below; the classification position of
`ad.collect` is argued in "Status update (ACCEPTANCE 5.48)".

*(Earlier status line, kept as written. It describes the stage this document was written in, not the current state.)*

Status: **investigation only, D42. No code, schema, migration, or Rego change
is made until the decisions in §5 are confirmed.** This is step one of what
the brief itself calls a bigger build than D31 or D34 — the brief's own
instruction is to confirm the foundation before building on it, and this
document is that confirmation pass, not a partial implementation.

**Status update**: D42-1, D42-3, D42-4, and D42-6's direction have been
signed off. D42-2 has been closed with a real measurement rather than the
architectural argument alone — see `docs/D42_2_CTE_BENCHMARK.md` and
`scripts/bench/d42_bloodhound_cte_bench.py`/`docs/d42_bench/`. D42-5
(Neo4j vs. Postgres-only) was decided **Postgres-only** against those numbers (see that
document's "Reading these numbers against D42-5" section and `docs/D42_1_D42_6_DESIGN.md`);
this ADR's §3/§5 predate the measurement and describe the options as they stood.

**Status update (D45/D46)**: §4's design was implemented and then driven
end to end for the first time at D45, which found the real production entry
point (`propose_action`) never actually routed `ad.collect` to
`dispatch_collection` at all — every real call ran the generic
`dispatch_scan` instead, silently dropping the Security Graph write this
section's whole design exists for. Fixed at D45, rebuilt as a structural
guarantee at D46 (`tests/test_dispatch_routing.py`). D45 also found that
real authenticated collection cannot complete against any environment
available to this project, for a reason one layer earlier than expected —
see `docs/D45_AD_COLLECTION_E2E_REPORT.md` §5 — which qualifies §4's design
as verified for its wiring, not yet for a real domain controller in
practice. Full account: `docs/D45_AD_COLLECTION_E2E_REPORT.md` and
`docs/D46_DISPATCH_ROUTING_AUDIT_REPORT.md`.

**Status update (ACCEPTANCE 5.48) -- `ad.collect` and the classification gate.** `ad.collect`
does **not** require a known classification (`authz.rego`'s `requires_known_classification`;
`ad_collector.KNOWN_CLASSIFICATION` is `"exempt: ..."`). Until 5.48 that was a state, not a
decision: D42 decided how a domain enters scope (D42-1) and never asked the §5 question of the
action. The argument, now on the record:

1. **D42-1 option C, §1.5/§1.6.** An `ad_domain` scope authorizes *collecting* and nothing else;
   every entity a run surfaces is a discovery candidate that enters as `OBSERVED`, never
   `AUTHORITATIVE`, and is never itself grounds for a capability (I8).
2. **A collected node carries no classification (§2.3).** Identity (SID, hostname) and structure
   only; classification stays with the Postgres registry, keyed by that identity
   (`tests/test_schema.py::test_security_graph_tables_have_no_classification_columns`). A run
   produces no classified content for the gate to describe -- it produces the discovery
   candidates classification work starts from.
3. **That is `ARCHITECTURE.md` §5 table row 1:** an action whose output is the raw material of
   classification needs none first ("不需要——這正是分類資料的來源之一"). Stated carefully: the row
   names `network.passive_identification`, which exists only as that row (nothing implements
   it; ACCEPTANCE, D32 analysis), so it is the *principle* here and not an implemented
   precedent. The implemented analogue is `network.scan`, exempt for the adjacent reason (a
   banner is a fragment, not a document).

**What this does not argue.** `ad.collect` reads a customer's directory, and user and group
identities are personal data; D32's and D43-3's "does it touch the resource's content" test can
be pointed at it. The exemption rests on points 1-3, and on two other gates the action keeps: it
cannot run without a credential issued for the engagement (`dispatch_collection` refuses
without a `credential_id`, D50-F1) or without an `ad_domain` scope, and nothing it surfaces can
be acted on without its own scope (D42-1). What is **not** gated is a human confirming the
directory's sensitivity before it is read. If a customer's directory must be treated as
sensitive first, that is a classification row for the `ad_domain` and `ad.collect` added to the
rule, with its own tests -- a policy change, not a reading of this exemption.

This is the first tool this project has ever considered whose native output
is a **relationship graph** (`User —MemberOf→ Group —GenericAll→ Computer`)
rather than a classification of, or scan result against, one resource. Every
prior tool — nmap, `web.get`/`web.post`, the browser — produces evidence
*about a target the proposal already named*. BloodHound's value is the
opposite: it is asked about a domain and returns facts about entities nobody
named in the proposal, including entities nobody has ever seen before. That
inversion is the thread running through all four sections below — it is not
four unrelated integration questions, it is the same question (does
*discovering* a graph edge ever imply authorization or trust over what it
names) asked at the scope layer, the storage layer, the access-control layer
and the dispatch layer in turn.

---

## 1. Authorization model — how does an AD domain get into scope?

### 1.1 What `ad_domain` already is, verified against the tree

Exactly what the brief suspected, and confirmed rather than assumed:
`ad_domain` exists **only as a name in enums**, with zero behaviour built on
it anywhere.

| Where it appears | What it does |
|---|---|
| `control_plane/canonicalizer/target.py` `IDENTITY_TYPES` | Listed as a valid `logical_identity.type`. |
| `control_plane/canonicalizer/target.py:285` | `else: # repo, ad_domain — opaque identifiers, compared verbatim` — no parsing, no normalization beyond `.strip()`. |
| `control_plane/canonicalizer/containment.py` `CONTAINMENT_TYPES` | Listed, but falls to the catch-all: `child_type == parent_type and child_value == parent_value` — **exact string equality only**, no containment arithmetic (same bucket as `url`, and D25 §2.2 already refused to invent one: "is an org the parent of its repos... a policy choice, not arithmetic"). |
| `control_plane/canonicalizer/metadata.py` `ANCESTOR_TYPES` | **Absent as a key.** `_inherited_observations` returns `()` immediately for an `ad_domain` identity — it cannot inherit classification from anything, by the same D25 decision that excluded `url`/`repo`. |
| `agents/llm/worker_base.py:75` `TARGET_TYPES` | **Not offered to the Worker at all.** The comment is explicit: *"`repo` and `ad_domain` are omitted because MVP-Kernel's only tool is a network scanner and offering a type no adapter can execute invites a proposal that dies at the Tool Gateway instead of being refused up front."* |
| `db/migrations/versions/0001_core_schema.py:92` | Present in the `identity_type` CHECK constraint on `metadata_registry`, so a row *can* be inserted with this type today — but nothing reads it as anything other than an opaque string. |
| Tool Gateway (`tool_gateway/registry.py` `ADAPTERS`) | No adapter. No action namespace (`ad.*` is mentioned once in `ARCHITECTURE.md` §9 row E as an example of a *possible future* namespace, never implemented). |

So the honest starting position is: **nothing has to be un-done.** `ad_domain`
is a placeholder that was named in the schema and then correctly left inert
everywhere it would have mattered, the same discipline that kept `repo` inert.
This is a green field, not a half-built feature to reconcile with.

### 1.2 The problem underneath the type question: I3 has no notion of "how big is this domain"

Before choosing *how* an AD domain enters scope, one existing mechanism needs
to be named as something that will not survive contact with it unmodified:
**§4.6's I3 (budget must be checked against target size) has no way to size
an `ad_domain` target.**

`CanonicalTarget.address_count` (`control_plane/canonicalizer/target.py`):

```python
if self.logical_identity.type != "cidr":
    return 1
return ipaddress.ip_network(self.logical_identity.value).num_addresses
```

Every non-`cidr` type — including `ad_domain` — reports `address_count == 1`,
always. This is correct for `ip`/`fqdn`/`url` (one name, one address, one
resource — the count *is* one) and it is why D12's original finding (a
capability recording `max_targets: 1` executing against a `cidr` covering 256
addresses) was fixable by teaching the count function to look inside a CIDR
prefix. **An AD domain has no equivalent structural way to know its own
size before it is queried** — a domain with 40 computers and one with 40,000
look identical to `address_count` (both report `1`), because the number of
objects in a domain is not encoded in the identity string the way a network's
size is encoded in its prefix length. A proposal claiming
`max_targets: 1` against an `ad_domain` would sail through the exact check
that caught D12's bug, for a structural reason D12's fix does not reach.

This is not a reason to abandon the idea — it is a reason the scope/target
design (§1.3–1.5) has to answer "what is the budget actually bounding" as
part of the same decision, not as a follow-on detail.

### 1.3 Option A — a new `ad_domain` scope type authorizing the whole domain

A `scope_object` of `type: "ad_domain", value: "corp.example.com"` authorizes
`ad.collect` (or similar) against the whole domain in one grant, matching how
a customer would actually describe their engagement ("you may run BloodHound
against `corp.example.com`").

**What this buys:** matches how the brief frames the core value — BloodHound's
whole point is relationships that *cross* single hosts, and if the Worker had
to hold a separate scope object per computer before it could even ask "what
groups is this computer in," the tool could never ask the question that makes
it worth running. It also matches the plain-language shape of a real
engagement's rules of engagement document.

**What it costs:** §1.2's sizing problem is now a live authorization gap, not
a theoretical one — a single scope object silently spans however many objects
the domain actually contains, and the budget/I3 machinery cannot bound it
until *after* the fact (only the tool's own returned counts would reveal the
domain's real size, which is exactly the untrusted-observation-deciding-its-
own-budget shape §8.1/§8.9 exist to forbid elsewhere).

### 1.4 Option B — no domain-level type; authorize only individual computers via existing `fqdn`/`ip`

BloodHound's collection is *permitted* only over the union of computers
already covered by existing `fqdn`/`ip`/`cidr` scope objects — no new type,
reusing exactly what exists today.

**What this buys:** zero new authorization surface, I3 keeps working exactly
as it does today (each computer sizes to 1, or a CIDR sizes to its prefix),
no new containment/inheritance question.

**What it costs:** this is very likely to make BloodHound close to useless for
its own stated purpose. BloodHound's central technique is discovering a path
that crosses hosts nobody separately authorized — `UserA →(has session on)→
WorkstationB →(admin of)→ ServerC →(GenericAll)→ DomainAdminGroup` — the
value is precisely in the hosts that get pulled into the picture *because*
they appear on a path, not because an Engagement Manager pre-registered each
one. Restricting collection to a pre-enumerated host list answers "what do
these known hosts look like individually" and cannot answer "is there a path
from a low-privilege user to Domain Admin," which is the actual question a
real engagement asks BloodHound. Recorded so the option is not silently
attractive for being the cheapest to build — it may not do the job at all.

### 1.5 Option C (recommended for discussion) — `ad_domain` scope authorizes *collection*, never authorizes *action* against what it discovers

A hybrid: register `ad_domain` as a real scope type, authorizing the
`ad.collect` action class specifically — nothing else. Every entity
BloodHound's collection surfaces (a computer, a user) becomes a **discovery
candidate**, in exactly §8.9's existing sense: it may enter `metadata_registry`
as an `OBSERVED`-tier row (never `AUTHORITATIVE`), and if any *later* Worker
proposal wants to actually act against one of those computers (`network.scan`,
`web.get`, anything with a side effect or a resource cost), that proposal
still needs its **own** `fqdn`/`ip`/`cidr` scope object covering that specific
computer — precisely the same rule §4.1.5 already applies to a DNS-resolved
IP ("the IP being reachable from an in-scope name does not by itself
authorize `network.scan` against it").

This reframes §1.2's sizing problem rather than solving it: the budget
`ad.collect` needs is not "how many objects will this touch" (unknowable in
advance) but something more like "how long may this run" / "how many LDAP
queries may it issue" — a duration and a request-rate ceiling, the same shape
`§4.6` already gives `http.max_requests`/`requests_per_second` as a
tool-owned budget dimension, rather than the target-size-based `max_targets`
nmap and the CIDR types use. The size of the *blast radius of what gets
looked at* stays unbounded by scope-object count, same as an `nmap
network.recon` sweep of a `/16` today — bounded instead by what the operator
is willing to let the collector run *for*, and by the fact that nothing it
finds can be acted on without a fresh, individually-scoped authorization.

This is the option I'd lean toward, because it is the only one of the three
that does not either (a) hand out an unbounded authorization (Option A) or
(b) make the tool unable to do the thing it exists for (Option B) — but it
needs your explicit sign-off (Decision D42-1) because it is a genuinely new
shape of scope object (authorizing a *verb over a set*, not a *target*), and
because "collection is authorized, action is not" is a distinction the Worker
schema and OPA policy do not currently express anywhere and would need to.

### 1.6 The I8 risk, stated concretely against a real BloodHound run

The brief asks directly whether this reruns D11-4/D11-5. Walked through with
an actual BloodHound edge:

> Collection returns `UserA —AdminTo→ WorkstationB`. `WorkstationB` was never
> registered by anyone. `WorkstationB` is a real, existing computer object
> that BloodHound *structurally observed* — LDAP returned it, it is not text
> in a banner someone could have forged the way D13's lure was.

This is a different case from D13's injection (an attacker-controlled string
claiming a relationship) — LDAP query results are the same category of
"structurally observed by the tool" fact D20 already built a deterministic
provenance path for (`Observation.observed_identities`, checked *before* any
content-matching, in `_discovery_provenance`). The mechanism that already
exists is the right shape for this. What does **not** already exist is any
path by which a *graph* of thousands of such observations reaches that
mechanism — D20's `_discovery_provenance` was built for one Worker call
naming one target against a handful of prior `Observation`s, not for a single
tool run structurally asserting the existence of an unbounded number of new
identities in one shot. Whatever Option §1.3–1.5 is chosen, the concrete
requirement I8 places on it is: **every entity a BloodHound run returns must
enter the system the same way a scan-discovered IP does today — as
`OBSERVED`, never `AUTHORITATIVE`, and never itself sufficient grounds for a
capability** — and that needs to be verified with the same kind of
adversarial-fixture-and-real-resolver test D13/D15 already used, not assumed
because the discovery/authorization split holds elsewhere.

> **D54 decision on "established" — read this with the paragraph above; on this one question it
> supersedes the comparison drawn there.** The paragraph above puts LDAP-returned objects in the
> same category as what a scan observes. For *authorization* that changes nothing (Discovery ⊥
> Authorization holds). For D20's *established* it does not hold, and the rule is now decided:
>
> **Decided rule (D54, ACCEPTANCE 5.27).** A node in the Security Graph is evidence
> that a *directory contains a record*; it is not evidence that the host or identity
> it names is alive or reachable, and it is **never by itself "established"** in D20's
> sense. Any harness that fills `Observation.observed_identities` from Security Graph
> rows must include an identity only when a *structural observation* of that same
> identity also exists in this engagement: a tool run whose own network exchange with
> it succeeded (for example an Nmap run that saw the host respond, or an HTTP/browser
> transaction that reached it). The `ad.collect` run itself counts only for the host
> it connected to (the domain controller it bound to), never for the objects it merely
> read from that host. A graph identity with no such observation may reach a Worker
> only as `Observation.content`, where it escalates like any other
> named-but-unobserved target. D20's strict criterion, `_discovery_provenance` and the
> Rego rule are unchanged; this rule constrains what a harness may put in the field.
> It does not decide how a graph `fqdn` and a scanned `ip` for the same machine are
> matched (names are never resolved, §8.9/I8), and it does not replace the end-to-end
> verification 5.28 requires when a harness is first written.
>
> Canonical text: `ACCEPTANCE_MVP1_AGENTS.md` **5.27**; the same wording is in
> `D42_1_D42_6_DESIGN.md` §1.8. The original paragraph above is left unchanged.

---

## 2. Metadata / data model — dividing labor between Neo4j and Postgres

### 2.1 The existing decision this reopens, stated precisely

This is not a green-field storage choice. `ARCHITECTURE.md` §9 row D already
decided this once: *"MVP 用 Postgres edges 表，Phase 2+ 評估 Neo4j... 資料量小
時 Postgres 夠用，先不引入第二個資料庫的維運成本"* — and the condition attached
to revisiting it was explicit: **"如果 Postgres edges 真的撐不住再上"** (only if
Postgres edges genuinely can't handle it). `control_plane/provenance/graph.py`'s
own module docstring repeats the same reasoning verbatim: *"Postgres edges
rather than Neo4j, per §9-D: at MVP volumes a recursive CTE is enough, and a
second datastore is a second thing to operate."*

So the question this section actually needs to answer first is **not** "how
do Neo4j and Postgres divide labor" — it is **"has the condition that was
supposed to gate this actually been met, or are we introducing Neo4j because
BloodHound-the-product ships with one?"** Those are different justifications
and D42 should not conflate them.

### 2.2 Does the requirement come from BloodHound's data, or from BloodHound's own tooling choice?

Worth stating plainly because it changes the shape of the decision: BloodHound
the open-source project bundles Neo4j because **its own GUI** runs live
Cypher queries for interactive attack-path visualization. That is a decision
BloodHound's authors made for BloodHound's UI — it is not a fact about the
data that binds this platform, which does not have to adopt BloodHound's own
frontend at all. This platform could run a BloodHound-family **collector**
(SharpHound or the `bloodhound-python`/Impacket-based collector, either
produces the same edge-list JSON) purely as a Tool Gateway adapter and choose
its own storage independently of what BloodHound's own shipped UI happens to
prefer.

That said, the underlying *query shape* BloodHound exists to answer —
"is there a path from UserA to Domain Admins," a variable-length,
shortest/all-paths graph traversal over a dense, cyclic ACL graph — is
genuinely a different animal from every query the Provenance Graph has ever
needed. Every existing `provenance_edges` use is a **bounded, backward walk
from one known node** (a proposal id, a finding id) a handful of hops deep,
which is exactly what the ADR's own justification says a recursive CTE
handles fine. "Find every path (or the shortest path) from any of 500
low-privilege users to Domain Admins" over a graph with cycles is the first
query shape this project has ever needed that a recursive CTE answers
awkwardly (Postgres *can* express bounded-depth path search with
`WITH RECURSIVE` and a visited-set anti-cycle guard, but a variable-length
shortest-path query across a dense graph is what Cypher — or a purpose-built
graph engine — is designed to make efficient, and a hand-rolled recursive
CTE re-deriving that is a second implementation of graph-traversal semantics
in a language not built for it).

**Reading this honestly: this is the first real evidence since §9-D that the
gating condition might actually be met** — not "Neo4j is trendy" or "the
open-source tool bundles one," but "the specific query BloodHound exists to
answer is graph-shaped in a way a recursive CTE handles worse." That is a
real, if not yet empirically measured, case for revisiting §9-D. It is also
not proven: nobody has yet tried the recursive-CTE version against a
realistically-sized synthetic AD graph and measured whether it is merely
inelegant or actually too slow to be usable. **Decision D42-2**: before
committing to Neo4j, should this investigation include a small measured
comparison (a synthetic domain of a few thousand objects, the same
shortest-path query run as a recursive CTE and as Cypher), or is the
architectural argument above sufficient to proceed without measuring it?

### 2.3 If Neo4j is adopted: three ways to divide the labor, and the consistency risk each carries

Whichever way this goes, the brief is right that this is the same
two-things-that-must-agree risk this project has hit repeatedly (D15's dual
containment implementations, `db/schema.sql` vs the migrations at D33, the
Web Agent report's own D34/D37 findings) — now between two different database
*technologies*, which removes even the option of a single transaction holding
both writes together.

**Option A — Neo4j is authoritative for the graph; Postgres Metadata Registry
is authoritative for classification; the two are cross-referenced by exact
identity and never duplicate a fact.** A BloodHound-discovered computer node
in Neo4j carries only its identity (SID, hostname) — no `data_class`, no
`resource_class`. Anything that needs to know "is this computer classified"
queries Postgres by that same identity, exactly as `resolve_metadata` does
today for any other resource. **Consistency risk:** nothing enforces that a
Neo4j node's identity has ever been *seen* by Postgres — a graph node can
exist with no corresponding registry awareness at all, which is fine (§1.6
says it should be `OBSERVED`, not `AUTHORITATIVE`) as long as every consumer
remembers to ask Postgres rather than trusting anything Neo4j says about
classification. Cheapest option; the risk is entirely "someone reads a
Neo4j property that looks like classification and forgets it isn't one."

**Option B — extend D25's inheritance pattern across the database boundary.**
Neo4j's graph can express "this computer is `MemberOf` this OU" the way
Postgres's `fqdn`/`cidr` containment expresses "this IP is inside this
network." `resolve_metadata`'s `_inherited_observations` could, in principle,
also query Neo4j for ancestors and fold what it finds in as an `OBSERVED`-tier
row, the same downward-tightening-only shape D25 built. **Cost:** this makes
the Metadata Resolver — a function whose entire design principle since D25 §6
is "share the pure geometry, keep the *decision* in one place, never let the
classification path acquire a dependency on a second system for its answer"
— depend on a live Neo4j round-trip for every resolution. D25 §6 rejected an
analogous entanglement (classification importing authorization's function
directly) for exactly the coupling reason this option reintroduces one layer
down, with a slower, less available system as the dependency. Not
recommended without a much narrower, explicitly-scoped version of this idea.

**Option C — Neo4j nodes are opaque graph ids only; identity never lives in
two places.** Neo4j stores BloodHound's SIDs and edges and nothing an
`identity_type`/`identity_value` pair. Any consumer that wants to reason about
"is this SID the same resource as this `fqdn`/`ip` row in Postgres" does the
join explicitly, at query time, using an identity-resolution step this
project would still have to build (SID → hostname is not always 1:1 or
stable, which is its own can of worms BloodHound users already know about).
**Consistency risk is structurally the lowest of the three** — Neo4j never
asserts anything Postgres could disagree with, because Neo4j never asserts a
classification-relevant fact at all — but it defers the actual hard problem
(reconciling AD identity with this platform's identity model) rather than
solving it, and nothing downstream (an OPA rule, a Worker's classification
check) can use a BloodHound fact without that join existing somewhere first.

**Recommendation, tentative:** Option A, for the same reason D25 §6 gives —
one authority per fact, cross-referenced rather than merged. **Decision
D42-3** is which of the three, and it should be made together with D42-1
(the scope model), because Option A only stays safe if §1.5/§1.6's
"discovery is never authoritative" rule is actually enforced at the point
Neo4j data is read back into anything OPA sees.

### 2.4 Provenance Graph vs. Security Knowledge Graph — do they merge?

No, and the existing code already explains why not to. `provenance/graph.py`'s
own docstring draws the line: the Provenance Graph answers *"why do we
believe this"* (`TASK → PROPOSAL → CAPABILITY → RUN → EVIDENCE`, always
Postgres-native ids, always a short backward walk); the Security (Knowledge)
Graph answers *"how do things connect"* (`User → Group → Server → App → DB`,
potentially thousands of nodes, the BloodHound shape). These are different
questions with different shapes today, on purpose, and nothing about adding
BloodHound changes that — it only gives the second graph a real data source
for the first time.

The one place they touch: a BloodHound collection run is itself a `RUN` that
`PRODUCED` `EVIDENCE`, exactly like an nmap run today — that edge belongs in
`provenance_edges` (Postgres) unchanged, recording "this collection happened,
authorized by this scope object, at this time." What is novel is only that
this run's "evidence" is a write into a *second store* (wherever §2.3 lands)
rather than a JSONB blob — the provenance edge should point at that write
(by whatever id the Security Graph assigns the resulting subgraph or batch),
not attempt to duplicate the graph's own contents into Postgres. **This
appears to need no decision** — it is the existing Provenance/Security split
applied consistently — but is listed as **D42-4** in case there is a reason
to treat it differently that this investigation has not surfaced.

---

## 3. Neo4j access control — is there an RLS equivalent?

### 3.1 Researched via web search, not verified hands-on — flagged explicitly

Everything in this section is sourced from Neo4j's own current documentation
and third-party write-ups found by search, **not** confirmed against a
running Neo4j instance in this environment. Given this project's own
standing rule — the D5/D39 lesson that a security boundary assumed to exist
and never actually exercised is indistinguishable from one that does not
exist — nothing here should be treated as load-bearing until it is checked
against a real Neo4j deployment the way D4.5's role separation and D25's
containment refactor were checked against a real Postgres.

**Community Edition**: single default user, no multi-user support, no
role-based access control, no per-database isolation. There is **no Neo4j
equivalent of `FORCE ROW LEVEL SECURITY`** available at all in Community —
every connection sees everything, full stop.

**Enterprise Edition** (commercial, licensed): full RBAC (`CREATE ROLE`,
`GRANT`/`DENY`/`REVOKE`), and two isolation primitives that could map onto I4:

1. **Multi-database** — each tenant gets its own physical database inside one
   Neo4j instance. The strongest isolation available (structurally identical
   to "a separate Postgres database per engagement," which this project has
   never needed because RLS gives the same guarantee inside one database at
   far lower operational cost).
2. **`GRANT READ ... WHERE`** (Neo4j 5.x) — property-value-conditioned read
   privileges, e.g. *"role `tenant_a_role` may read nodes where
   `tenant_id = 'tenant_a'`."* This is the closer analogue to Postgres RLS in
   spirit, but with a load-bearing difference found in the research: **the
   `WHERE` predicate's value is fixed into the role's own definition at grant
   time.** Postgres's `cyberorch_current_engagement()` reads a
   *per-connection* session GUC (`SET LOCAL cyberorch.engagement_id`), so one
   role (`cyberorch_app`) serves every engagement, forever, with the
   engagement selected fresh on each connection. Neo4j's `WHERE`-scoped grant,
   as documented, needs **one role per tenant value** — there is no
   documented mechanism found in this research for a single role's privilege
   to be conditioned on a value supplied at connection time the way a
   Postgres GUC is. If that finding holds up under hands-on testing, it means
   an engagement-scoped Neo4j role would have to be **provisioned as its own
   step inside `create_engagement()`** (a new Cypher `CREATE ROLE` + `GRANT`,
   not just an `INSERT`), and Neo4j roles would accumulate for the lifetime
   of the system the same way engagements themselves do — with no existing
   retirement story, since engagements are retired by status and never
   deleted (§1.2e), and nothing in this research suggests Neo4j roles have an
   equivalently cheap "soft-retire" primitive.

### 3.2 Options

**Option A — Enterprise, one role per engagement (`GRANT READ ... WHERE`).**
Closest in spirit to the Postgres model, but with per-engagement role
provisioning as new state `create_engagement()` (or an ADR-42-specific
sibling operation) would have to manage, and a role-sprawl question with no
answer yet. Requires an Enterprise license.

**Option B — Enterprise, one database per engagement (multi-database).**
Strongest isolation, structurally simplest to reason about (there is no
cross-tenant query to ever get wrong, because there is no shared database to
query across) — but the heaviest operationally: every `create_engagement()`
call provisions a new Neo4j database, every engagement's lifecycle now
manages a second piece of infrastructure state, and whether Neo4j's database
creation/teardown is fast and automatable enough to sit inside a
request-scoped operation the way a Postgres `INSERT` is needs hands-on
verification, not assumption. Also Enterprise-licensed.

**Option C — Community, isolation enforced entirely in the application
layer.** No license cost, but — stated as plainly as the brief asked for —
**this is precisely the "rests on application code choosing not to" shape
D5 closed for the Scope Registry and D39 closed for `engagements`.** Every
Cypher query the control plane ever issues would need to carry its own
`WHERE n.engagement_id = $eid`, by convention, with the database offering
**no backstop** if one call site is written wrong — not "a weaker backstop,"
literally none, since Community has no RLS-equivalent to fall back on even
as defense-in-depth. If this option is chosen anyway (e.g., because the
license cost is a hard blocker), the honest mitigation is a single,
unavoidable choke point — one function, analogous to `engagement_scope()`,
that is the *only* sanctioned way to obtain a Neo4j session, which injects
the engagement filter into every query it runs — but this is enforced by
code review and the absence of any other import path to Neo4j, not by the
database refusing a bypass the way `FORCE ROW LEVEL SECURITY` refuses even
the table owner. **This must be named as an accepted, permanent risk in the
record if chosen, not glossed over as "handled."**

### 3.3 A fourth option this section should not omit: reconsider whether Neo4j is needed at all

Given that **every** access-control option above either costs an Enterprise
license, adds a per-engagement infrastructure-provisioning step with no
retirement story, or reintroduces a category of gap this project has twice
already had to close by name — it is worth stating the option the brief's own
framing (Neo4j as a given) does not explicitly offer: **stay on Postgres**,
inside the RLS boundary that is already built, tested, and has a real track
record (D4.5 through D39), and answer BloodHound's actual query need (§2.2)
with a set of purpose-built recursive CTEs for the small number of graph
questions this platform actually needs answered (shortest path to a named
target class; is there any path at all; list paths under N hops) rather than
a general-purpose Cypher engine. This is less elegant and would not give an
operator ad hoc Cypher access — but it inherits I4 for free, needs no new
role model, no new license, and no new "what happens to this resource when an
engagement is paused/killed/completed" story, because engagements, capability
revocation and audit already all work identically for one more table. **This
should be treated as a real fourth option, not a rejected one** — Decision
D42-5 is explicitly "Neo4j (with one of A/B/C above), or stay on Postgres
with purpose-built recursive CTEs."

---

## 4. Tool Gateway integration

### 4.1 The dispatch shape does not fit, structurally, independent of storage

`dispatch_scan(conn, *, target: str, ...)` (`control_plane/orchestrator/
dispatch.py`) is built around **one proposal, one canonical target, one
`tool_run`, one `evidence` record.** Every existing adapter honours this:
nmap scans the one target string it was given; `web.get`/`web.post` fetch the
one URL; the browser renders the one page. `evidence.derived_view` is a
single JSONB blob designed to be read once by a Worker/Reviewer/Supervisor
prompt (§4.4), and `record_evidence` requires it to be marked
`untrusted_content: true` as a single unit.

BloodHound's collection does not produce "the evidence for one target" — one
collection run against one domain returns an unbounded number of nodes and
edges in one shot. Two consequences, independent of §1–§3's answers:

* **Sizing.** §1.2's problem recurs here in dispatch terms: `dispatch_scan`
  has no notion of "this one run touched N objects" the way `nmap`'s
  `open_ports` count is bounded by the ports requested.
* **Evidence shape.** Putting a BloodHound run's full output into
  `evidence.derived_view` and handing it to a Worker/Supervisor prompt would
  not merely be unwieldy — it would recreate D40/5.21's argv-length crash
  (found for a *handful* of nmap scans) on the very first real run, at a
  scale where the crash would not even need three rounds to accumulate to.
  A graph is not something that belongs inline in a prompt at all; the
  right-sized "evidence" for a Worker to see is a **summary** (counts, a
  short list of the most notable new edges), with the graph itself living
  wherever §2.3 puts it.

### 4.2 Two shapes of integration

**Option A — a BloodHound adapter that fits today's shape as closely as
possible.** One dispatch call = one collection run against the `ad_domain`
scope object (§1.5); `derived_view` holds a bounded summary
(`{"computers_seen": N, "notable_edges": [...]}`, `untrusted_content: true`);
the full graph write happens as a side effect of the same dispatch call,
written to wherever §2 lands, keyed by the `run_id` so the Provenance Graph
edge (§2.4) can point at it. Smallest change to the existing pipeline; the
budget question (§1.5, duration/rate rather than target count) still needs
answering, and "one dispatch, one evidence row, but a second unbounded write
happens on the side" is a real precedent this project has not set before and
should be named as such rather than waved through as "just a new adapter."

**Option B — a distinct "bulk collection" action category**, structurally
separate from `dispatch_scan`'s one-target model, with its own budget shape
(§4.6 already lets each tool define tool-specific dimensions;
`max_collection_duration_seconds` / `max_queries_issued` would be BloodHound's),
its own audit event vocabulary, and its own review path (a Reviewer opinion
on "should this collection run" is a different question from "should this
specific action against this specific target run," and conflating them risks
the same category error I6b/I6c were built to prevent for the existing
prerequisite). Bigger lift — this is genuinely new Tool Gateway surface, not
an extension — but avoids retrofitting a single-target abstraction to
something that was never single-target shaped to begin with.

**Decision D42-6**: which shape, and it should probably be decided *after*
§1.1–§1.5 (the scope/budget model) rather than before, since the dispatch
shape is downstream of what the authorization actually grants.

### 4.3 Credential Vault (§48) — verified: does not exist

Checked directly rather than assumed. The `credentials` table
(`db/migrations/versions/0001_core_schema.py`):

```sql
CREATE TABLE credentials (
    credential_id  TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(engagement_id),
    label          TEXT NOT NULL,
    revoked        BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**No secret material column of any kind** — no password, key, token, or
encrypted blob. This table answers exactly one question, "has credential X
been revoked," for `check_preconditions`/capability renewal (I9) to consult.
It has never been anything else. A repo-wide search for `vault`/`Vault`
returns nothing; every other `secret`/`password` hit in `control_plane`/
`tool_gateway` is a database connection password or a TLS private key
(`engagement_ca.py`, the egress proxy's leaf key) — infrastructure secrets
this platform manages for itself, never a customer domain credential handed
to a tool on the customer's behalf. **§48's Credential Vault was never
built. It remains exactly the Phase-2-deferred item `ARCHITECTURE.md` §10
named it** (bundled with BloodHound+Neo4j and an Attack Graph UI in the same
line), not a gap introduced by this investigation.

One finding worth being precise about because it is easy to get half-right:
`revoke_credential()` (D9) **does** correctly cascade — it flips
`credentials.revoked` and calls `revoke_capabilities_for_credential`, which
revokes every issued capability carrying that `credential_id`. The mechanism
is real, tested, and has been since D9. But a repo-wide check of every
`issue_capability` call site (`control_plane/api/function_api.py`, the only
production caller) shows **`credential_id` is never passed — it is always
`None`.** No tool today authenticates with a stored credential, so nothing
has ever issued a capability *with* one, so `revoke_credential`'s cascade has
zero production mileage despite being fully built and tested — the same
shape of finding as D39's unused `cyberorch_app` grant or D11-10's inert
`consume_request`: a real mechanism, sitting completely unexercised, waiting
for the first caller that needs it. BloodHound would be that first caller.

What this means concretely for D42: **BloodHound is the first tool in this
system that needs the control plane to hand a tool container a secret an
operator supplied.** Nmap needs no credential. `web.get`/`web.post` need none
(a target-embedded basic-auth URL is the closest precedent, and even that has
never been built). The browser needs none. This is new surface, not an
extension of something with a track record, and it needs its own design pass
this document does not attempt to close:

* **At rest**: where does the domain credential live before a proposal ever
  references it — encrypted in Postgres, in a real secrets manager (Vault-the-
  product, cloud KMS), operator-supplied per-run and never persisted at all?
* **In transit to the tool**: it must not pass through the Worker's own
  context the way a proposal or a prompt does — the browser's TLS leaf key
  precedent (`TOOL_CA_PATH`, path-only, never argv, never the environment) is
  the right shape to imitate, not invent from scratch.
* **Revocation's actual reach**: does flipping `credentials.revoked` stop an
  *in-flight* container that already has the secret loaded (a live SharpHound
  process holding a Kerberos ticket), or only prevent *future* capability
  issuance? D9's own docstring calls this "eager... the renewal check remains
  the backstop for anything issued in the same instant" — which was true for
  every existing tool because none of them hold a credential for longer than
  one bounded dispatch call. A credential a running collection process has
  already authenticated with is a materially different revocation problem
  than "stop issuing new capabilities," and this document does not have an
  answer for it.

This is flagged as a design item for a *following* deliverable, not something
D42 should attempt to settle alongside the scope/storage/access-control
questions above — but it must not be silently assumed solved because a
`credentials` table already exists.

---

## 5. Decisions needing your sign-off

| # | Decision | Options on the table | This document's lean |
|---|---|---|---|
| **D42-1** *(its classification consequence is argued in the "Status update (ACCEPTANCE 5.48)" above)* | How does an AD domain enter scope? | (A) `ad_domain` authorizes the whole domain for any action; (B) no new type, per-computer `fqdn`/`ip` only; (C) `ad_domain` authorizes *collection* only, every follow-up action needs its own scope object | (C) |
| **D42-2** | Should the Neo4j-vs-Postgres-CTE question be settled by a measured comparison (synthetic graph, same query, both engines) before committing? | Yes / no, the architectural argument in §2.2 is sufficient | **Closed — measured, see `docs/D42_2_CTE_BENCHMARK.md`** |
| **D42-3** | If Neo4j is adopted, how does classification authority divide? | (A) Neo4j opaque-identity-only, Postgres sole classification authority; (B) extend D25 inheritance across the database boundary; (C) Neo4j fully opaque, join deferred to query time | (A) |
| **D42-4** | Does the Provenance/Security Graph split need any change for BloodHound? | Treat a collection run as one more `RUN --produced--> EVIDENCE` provenance edge, unchanged | No change needed (low-confidence decision point — flagged in case something was missed) |
| **D42-5** | Neo4j at all, or stay on Postgres with purpose-built recursive CTEs for BloodHound's specific query shapes? | Neo4j (pick an access-control option below) / Postgres-only | Explicitly undecided — this is the one this document most wants your read on |
| **D42-5a** | *(only if Neo4j)* Access control model | (A) Enterprise, per-engagement `GRANT READ...WHERE` role; (B) Enterprise, per-engagement database; (C) Community, application-layer-only isolation with a named, accepted risk | Leaning A or B if Neo4j is chosen at all; C only with eyes open |
| **D42-6** | Tool Gateway integration shape | (A) BloodHound adapter fitted to today's one-target dispatch shape, bounded summary in `derived_view`; (B) new "bulk collection" action category with its own budget/audit/review shape | Leaning B, but this should follow D42-1 rather than precede it |

**Not a decision for this document, but not to be silently assumed away:**
the Credential Vault gap (§4.3) is real and blocks BloodHound regardless of
how D42-1 through D42-6 resolve — it needs its own investigation-then-design
pass, the same shape as this one, before implementation starts.

---

## 6. What this document does not do

No code, schema, migration, Rego, or test was written or changed. No
Neo4j instance was started or queried — §3's findings are sourced from
current Neo4j documentation and third-party write-ups found by search, not
hands-on verification, and are flagged as such throughout. No performance
measurement was run comparing a recursive CTE against Cypher for the
specific query shapes BloodHound needs (§2.2/D42-2). Nothing about the
existing kernel, Web Agent, or three-role integration stages was touched.
