# ADR: Semgrep — Phase 1 investigation (D43)

Status: **implemented (D43), wired through `propose_action` at D45/D46, private repositories at D44.**
As implemented: D43-1 repo + mutable branch with the resolved commit in the fingerprint, D43-2
subdirectory containment refused, D43-3 `code.*` requires a known classification, D43-4 snippets
redacted before a model reads them (`control_plane/evidence/redaction.py`), D43-5 a control-plane-side
fetch handed in as a read-only mount, D43-6 private repositories deferred and then delivered by the
D44 Vault. The second tool of this family, Gitleaks, is `docs/ADR_GITLEAKS.md` (D55).

*(Earlier status line, kept as written. It describes the stage this document was written in, not the current state.)*

Status: **investigation only, D43. No code, schema, migration, or Rego change
is made until the decisions in §4 are confirmed.** No `semgrep` binary is
invoked, no repository is cloned, and nothing about D42's BloodHound/Security
Graph work is touched.

**Status update (D45/D46)**: implemented and wired at D43 as this document
describes. D45 found that the real production entry point (`propose_action`)
never actually routed `code.scan` to `dispatch_code_scan` — every real call
ran the generic `dispatch_scan` instead, so a real `code.scan` capability
would start its container with nothing mounted at `CONTAINER_REPO_PATH`
(the control-plane-side git fetch this document's §3.2/D43-5 design depends
on would never run) and fail immediately. This was never caught because
every existing test called `dispatch_code_scan` directly, never
`propose_action`. Fixed at D45, rebuilt as a structural guarantee at D46
(`tests/test_dispatch_routing.py`) so a future action cannot silently repeat
it. Full account: `docs/D45_AD_COLLECTION_E2E_REPORT.md` and
`docs/D46_DISPATCH_ROUTING_AUDIT_REPORT.md`.

D42 (BloodHound) was the first tool whose *output* is a shape this platform
had never stored — a relationship graph. Semgrep is the first tool whose
*input* is a shape this platform has never handled — the entire contents of
a git repository, rather than a network address. That inversion runs through
every section below in a form D42 never had to answer, because D42's target
(an AD domain) was still something the tool *reaches over the network*, the
same as every prior tool. Semgrep's target is something the tool must
*possess a copy of* before it can do anything, and that copy is, by
definition, the customer's own first-party source code — trusted as to
truthfulness (nobody is spoofing it), but potentially the single most
sensitive artifact this platform has ever been asked to hold: production
credentials, internal hostnames, and proprietary logic can all sit in a
repository's plain text. Every one of D31/D34/D36/D37/D42's `untrusted_content`
markers exists to answer "should this be believed" — none of them was built
to answer "should this be shown," which is the question this deliverable
actually raises for the first time.

---

## 1. Scope model

### 1.1 What `repo` already is, verified against the tree

Checked the same way D42-1 §1.1 checked `ad_domain`, line for line, against
the current code:

| Where it appears | What it does |
|---|---|
| `control_plane/canonicalizer/target.py` `IDENTITY_TYPES` | Listed as a valid `logical_identity.type`, alongside `ad_domain`. |
| `control_plane/canonicalizer/target.py:285-286` | `else: # repo, ad_domain — opaque identifiers, compared verbatim` — `value = ivalue.strip()`, no other parsing. |
| `control_plane/canonicalizer/target.py:355-361` (`canonicalize_scope_value`) | Same treatment: `if scope_type in ("repo", "ad_domain"): ... return text` — opaque, compared for equality only. |
| `control_plane/canonicalizer/target.py` `address_count` | Returns `1`, same as every non-`cidr` type. |
| `control_plane/canonicalizer/containment.py` `CONTAINMENT_TYPES` | Listed, but falls to the same generic catch-all as `url`/`ad_domain`: exact `child_type == parent_type and child_value == parent_value`, no containment arithmetic. |
| `control_plane/canonicalizer/metadata.py` `ANCESTOR_TYPES` | **Absent as a key**, explicitly, by name, in the docstring above it (D25 §2.2's decision, re-quoted at D42-1 for `ad_domain`) — `repo` cannot inherit classification from anything. |
| `agents/llm/worker_base.py` `TARGET_TYPES` | **Not offered to the Worker.** Current comment: *"`repo` stays omitted for the reason this comment used to give for both: no adapter can execute it... `ad_domain` joined this list at D42-1/D42-6, once `ad.collect` gave it an adapter."* |
| `db/migrations/versions/0001_core_schema.py` | Present in the `scope_registry.type` CHECK constraint since migration 0001. |
| `tool_gateway/registry.py` `ADAPTERS` | No adapter. No `code.*` action exists anywhere in the tree. |
| `docs/ARCHITECTURE.md` | `repo` appears twice (lines 25, 273) as the canonical *example* of a typed scope object ("一個 FQDN 授權跟它背後的 IP 授權是兩件事,一個 repo 授權跟一個 AD domain 授權也是兩件事") — named early, in the same breath as `ad_domain`, but never built. Line 880 already names `code.*` as an anticipated action namespace alongside `web.*`/`ad.*`. Line 673 already names *Semgrep specifically* as the reason `execution_fingerprint` carries a `ruleset_version` field ("Nuclei 新增 CVE template、Semgrep/CodeQL 更新規則後...") — this deliverable is not a surprise the fingerprint design failed to anticipate. |

Conclusion, identical in shape to D42-1's: **`repo` is a placeholder named
everywhere and executable nowhere.** Nothing has to be undone. This is a
green field for behavior, not a half-built feature — the one difference from
`ad_domain` is that `repo` has been sitting in the design's own examples
longer, which changes nothing about what needs building.

### 1.2 Precision: does authorizing a repo authorize a ref?

This is where D42-1 and D43 genuinely diverge, and it is the sharper version
of the question the brief raises. An `ad_domain` scope object names something
that does not have a "which version of it" axis in the way a git repository
does — a domain is queried live, at whatever state it happens to be in.
`github.com/org/repo` has an unbounded number of *contents* depending on
which commit is checked out, and those contents are exactly what Semgrep
scans and exactly what a finding is about.

**Checked directly rather than assumed: `execution_fingerprint` already has
a slot for a rule-set version, and it has never been populated.**
`control_plane/dedup/fingerprint.py`'s signature is:

```python
def execution_fingerprint(
    *, engagement_id, tool, tool_version, normalized_target,
    normalized_params=None, execution_context=None, ruleset_version=None,
) -> str:
```

Every existing call site (`dispatch_scan`, `dispatch_collection`) passes
`ruleset_version=None` implicitly — no adapter has ever populated it. This is
the exact shape of D39's unused `cyberorch_app` grant and D9's unexercised
`revoke_credential` cascade: a real mechanism, present in the schema and the
function signature since before it had a caller, waiting for its first one.
**Semgrep would be that first caller**, and it must actually pass its rule
pack's version — not because this is a new requirement, but because the
design already named the reason (`ARCHITECTURE.md` line 673, quoted above)
and nothing has tested it yet.

That handles *rule* staleness. It does not yet handle *target content*
staleness, which is the real version of the brief's D11-3 concern. D11-3's
exact lesson (`docs/LIVE_RUN_REPORT.md`, the incident record): a scan
confined to `10.88.0.0/24` (no route to the target) succeeded and reported
nothing; the identical proposal under `10.79.0.0/24` (which *could* reach the
target) fingerprinted identically and was served from cache — three open
ports went unreported. The fix: fold the network allowlist into
`execution_context`, on the precedent that "the same target scanned with a
different credential is a different execution."

Applied to Semgrep: **if the commit/ref scanned is not part of the
fingerprint, two scans of a repository whose content has genuinely changed
between them — a customer's fix landing, or an attacker's commit landing —
will fingerprint identically if `normalized_target` is just `"org/repo"`,
and the second, materially different scan will be served `dedup_hit` and
never run.** This is not a hypothetical shaped like D11-3; it is D11-3,
with "which network the container can reach" replaced by "which commit the
container was handed." The same fix shape applies: the resolved commit SHA
belongs in `execution_context`, regardless of how scope precision (below) is
decided, because a dedup cache correctness question is separate from an
authorization-scope question and D11-3 already settled which category this
falls into.

**What scope precision itself should be is the open question**, and it has
three shapes:

- **Option A — scope authorizes the repository, any ref.** `github.com/
  org/repo` is the scope value; the ref/commit is a capability constraint
  (like nmap's `ports`), never a scope dimension. Matches how every other
  scope type already works — a `cidr` scope authorizes the range, not a
  specific host's current state. Cost: an Engagement Manager cannot express
  "scan `main`, never the `experiments/unredacted-secrets` branch" at the
  authorization layer; that has to be enforced elsewhere, and there is no
  elsewhere today.
- **Option B — the scope value pins an exact ref** (`github.com/org/repo@
  <sha>` or `.../repo:<branch>`), so a different branch is a *different*
  scope object requiring its own authorization. Matches `repo`'s existing
  exact-match-only containment (§1.3) exactly — consistent, but a branch
  that moves (an actively-developed `main`) would need the Engagement
  Manager to either re-authorize on every commit (impractical) or pin only
  the branch *name* rather than a commit, which is a weaker pin than the
  syntax suggests.
- **Option C (recommended for discussion) — scope authorizes repo + branch
  name** (`github.com/org/repo:main`), narrower than A, more usable than B's
  literal commit-pinning. `main` moving is expected and does not require
  re-authorization; a scan of `experiments/unredacted-secrets` under a scope
  naming only `main` is refused, the same exact-match refusal `repo`
  already gives any mismatched value. **Whichever of A/B/C is chosen, the
  actual commit SHA resolved at clone time is still a required
  `execution_context` dimension** — that part is not really a fourth
  option, it is D11-3 applied.

### 1.3 Parent/child containment: a monorepo subdirectory

Checked against D25 §2.2's own refusal, quoted directly in
`control_plane/canonicalizer/metadata.py`'s `ANCESTOR_TYPES` docstring:
*"`url`, `repo` and `ad_domain` are absent, and that is a decision rather
than an omission... Guessing one here (is /admin the parent of /admin/users?
is an org the parent of its repos?) would be inventing classification
semantics the design does not record."*

This is exactly the mine the brief asks about, and the answer is the same
one D25 already gave: **no subdirectory-level containment.** A scope object
for `github.com/org/repo` authorizes the repository as one identity, full
stop — the same way a `url` scope authorizes that exact URL and nothing
about its path segments implies a hierarchy. A customer who wants Semgrep to
skip a subdirectory is expressing a **constraint on the scan**, not a
narrower **authorization** — the same category §4.6 already puts nmap's
`ports`/`allowed_ports` in: adapter-owned, budget/capability-shaped, decided
per proposal, never a scope-registry concept. No new containment rule is
needed, and none should be built.

---

## 2. Authorization / classification

### 2.1 Does `code.scan` need a known classification?

`requires_known_classification` (`control_plane/policy/rego/authz.rego`) is
three independent conditions, none of which mention *who owns* the target:

```rego
requires_known_classification if {
	some pattern in {"data.*", "web.get", "web.post", "web.put", "web.delete"}
	pattern_matches(pattern, input.action.action)
}
requires_known_classification if input.action.writes_data == true
requires_known_classification if input.action.changes_state == true
```

A miss does not deny — it forces `unknown_classification_for_action_class`,
a `HUMAN_APPROVAL` reason (I10: the prerequisite is missing, so the action
cannot proceed unattended).

D32 added `web.get` to this set with a specific, narrow test — quoted
directly from `authz.rego`'s own comment: **the trigger is "touches
content" (returns the resource's whole document, the thing `data_class`
describes), not "modifies the target."** An nmap banner is "a fragment
incidental to identifying a service," which is why `network.scan` stays
out.

The brief is right that this cannot be assumed to transfer, and worth
arguing both ways rather than picking the answer that happens to be
convenient:

**Against transferring it as-is:** D32's concern was implicitly about a
target the operator does not own — the classification gate exists so an
Engagement Manager's own judgment about a *third party's* resource (or a
range they registered without fully characterizing it) stands between the
system and content the person invoking it may not have actually vetted.
Registering a `repo` scope object is, by construction, an explicit act by
the resource's own owner authorizing exactly this repository — arguably a
stronger consent signal than authorizing an IP range ever is.

**For transferring it, independently argued:** that distinction is about
*whose fault a leak would be*, not about *whether the system currently knows
enough to make an informed call*. D32's actual test — does the action touch
the resource's whole content — applies to Semgrep more directly than it does
to `web.get`: running Semgrep necessarily means the tool ingests the
repository's entire text, and a finding's evidence is a **verbatim quote**
of that text (§2.2). A repository that happens to contain hardcoded
production credentials is exactly the `resource_class`/`data_class` a human
should confirm is understood *before* an LLM-mediated pipeline starts
reading and summarizing matched snippets — the same reasoning `data.read`
already applies, just for a resource type nobody happened to register a
classification against yet.

**Recommendation: yes**, and specifically as a `code.*` wildcard pattern
(matching `data.*`'s existing style, not a hardcoded `"code.scan"` literal)
— `ARCHITECTURE.md` line 880 already names `code.*` as a namespace, not a
single action, and any future sibling action in it (`code.secrets`,
`code.deps`) would touch content by the identical argument. This needs your
sign-off (**D43-3**) because it is a genuinely independent argument, not an
extension of D32's — the brief was correct not to let this be assumed.

### 2.2 Evidence: derived_view for content that is true but may be sensitive

Checked directly: `record_evidence` (`control_plane/evidence/store.py`)
raises unless `derived_view["untrusted_content"]` is true, and every
adapter (`nmap`, `_http`, `browser`, `ad_collector`) sets it, uniformly, for
the same reason each time — quoting `nmap.py`'s docstring, "nmap parsed the
banner honestly, which says nothing about whether the banner is true."
**That marker encodes one axis: is this content's *claim about reality*
trustworthy.** It has never had to encode a second axis, because nothing
before Semgrep produced evidence that is *simultaneously* known-true (it is
the customer's own code, nobody forged it) and potentially confidential.
Every prior tool's evidence is at most embarrassing if leaked (an open port,
a page's HTML); Semgrep's evidence can be a live credential.

Nothing in `resource_metadata`'s classification tiers reaches this either:
`repo` is excluded from `ANCESTOR_TYPES` (§1.1), so there is no way today
for an Engagement Manager to pre-mark "this whole org's repositories are
sensitive" the way `10.79.0.0/24` can be marked PII and have it apply to
every host inside it. A per-repo `register_metadata` call is still possible
(exact-identity classification always is), but it requires the Engagement
Manager to have already anticipated it — same as any other exact-match
identity.

Semgrep's own JSON output puts the actual matched source line in each
finding (`extra.lines` in its real schema) — this is the specific new risk:
if a derived_view naively includes it, a hardcoded secret a rule correctly
flagged is now sitting inside whatever an LLM Reviewer's prompt context
window, potentially retained by the model provider, purely because the tool
did its job. This is the "raw/derived separation" question in a shape this
platform has not faced: previously, *derived* was always the *safe-to-show*
side and *raw* the untrusted-but-harmless-to-store side. Here, the raw
artifact is the one that must never leak, and derived is where the
exposure risk actually lives if built carelessly.

The closest existing precedent is D42-6's own `ad_collector.derive_view`:
a bounded, prompt-facing summary (counts, a small fixed sample) with the
full detail held only in a side artifact (there, the Security Graph; for
evidence generally, the raw artifact) that is never read into a prompt.
Three ways to apply that shape here, genuinely undecided:

- **Option A — full snippet in `derived_view`, unchanged from nmap/http's
  precedent.** Simplest, and consistent with "the reviewer needs to see
  what triggered a rule to judge a false positive." Cost: the exposure risk
  above, unmitigated — a real secret can end up in a model's context on the
  very first real run.
- **Option B — no snippet at all in `derived_view`.** Only `rule_id`, file
  path, line number, severity, and rule metadata (CWE/OWASP tags) are
  prompt-visible; the snippet lives solely in the raw artifact, audit-only
  per the existing `read_raw_artifact` guard ("never call this to build a
  prompt"). Safest, but a Reviewer judging "is this actually a hardcoded
  password or a test fixture" has nothing to go on and will default to
  `HUMAN_APPROVAL` far more often — plausibly defeating the point of
  automated triage.
- **Option C — a second, parallel marker** (e.g. `contains_first_party_
  content: true`, name TBD) alongside `untrusted_content`, with the snippet
  still present but truncated (mirroring `_http.py`'s own
  `stdout_excerpt`/`stderr_excerpt` truncation precedent) and the marker
  traveling with the data as a machine-readable fact for whatever review or
  export path consumes it later — the D22 principle ("the marker travels
  with the data... never as a consumer's assumption") applied to a
  confidentiality axis instead of a trust axis.

**Leaning C, truncated by default, over A** — full snippets are not
obviously necessary for a first pass, and a short, size-bounded excerpt
gives a Reviewer enough to judge "does this look like a real secret" without
guaranteeing the whole value is captured. This is the one point in this
document I'd most like your read on (**D43-4**) — it trades Reviewer
usefulness against exposure risk in a way this project has not had to
weigh before, and getting it wrong in either direction has a real cost.

---

## 3. Tool Gateway integration

### 3.1 Getting the repository into the sandbox

Checked directly against `tool_gateway/sandbox.py`: two mount mechanisms
exist today, and neither is a bundle-injection facility.

- **`tmpfs`** (D36, for the browser): writable scratch space over an
  otherwise read-only root, `mode=1777`, discarded with the container.
  Outbound-only — a place for the tool to *write*, not a way to hand it
  anything.
- **Read-only bind mounts** (D35, for TLS material): exactly three fixed
  single-file paths (`TOOL_CA_PATH`, the proxy's leaf cert, its leaf key),
  each delivered by writing a host tempfile and bind-mounting it read-only.
  This is the closest existing precedent to "put something into the
  container before it runs" — but it has only ever handled one PEM file at
  a time, by a fixed path constant, never a directory tree.

**There is no existing way to hand a container a repository's worth of
files.** Building one is real, new work either way; the question is where
the clone happens:

- **Option A — clone inside the sandbox.** The command becomes `git clone
  <url> /repo && semgrep --config ... /repo`, reusing `DockerSandbox.run()`
  exactly as-is: `network_allowlist` just names the git host instead of a
  scan target. Zero new sandbox mechanism. Cost: the container running
  Semgrep now needs live network egress *and*, for anything beyond a public
  repo, a git credential materialized inside it — widening the trust
  surface of the one container in this pipeline that is also parsing
  arbitrary source text, at exactly the point this document is most
  worried about confidentiality.
- **Option B (recommended for discussion) — the control plane fetches the
  repository itself** (a narrow, dedicated step, outside any sandbox,
  using whatever credential that step alone holds — trivial for public
  repos, the real Credential Vault question for private ones, §3.2), then
  **injects the resulting tree into the Semgrep container via a new,
  read-only, directory-shaped extension of the existing bind-mount
  mechanism.** The Semgrep container itself never holds a credential and
  never has network egress at all. This is the same logic that already
  drove D34's egress-proxy split and D35/D36's file-not-network credential
  delivery ("a private key should never pass through argv or the
  environment, where the process table would expose it") — applied one
  layer up, to the *content* rather than a credential.

Option B is the bigger lift — a bind-mount-a-directory-tree capability does
not exist and needs its own tests at D35/D36's level of rigor — but it is
the one consistent with everything else this platform has chosen when
handling something it does not want a sandboxed process to be able to leak
or misuse on its own. Flagged as **D43-5**, and recommended to be decided
before implementation starts rather than defaulted to A for being cheaper.

### 3.2 Credential / private repositories

Checked against the same finding D42's ADR made for the Credential Vault
(§48, `ARCHITECTURE.md` §10): it does not exist. A private repository needs
git authentication (a token or SSH key) to clone at all, under either
Option A or B above. This is the identical shape D42-6 already accepted for
`ad.collect`: **buildable and testable against fixture output, no
live/production path until the Vault lands** — not something to route
around with an ad hoc credential-passing shortcut.

**Recommendation: this deliverable's scope is public repositories only**
(**D43-6**), matching D42-6's own precedent exactly. A private-repo path
should wait for the Credential Vault deliverable regardless of how §3.1 is
decided, since Option B's control-plane-side fetch step is exactly where a
vault-issued credential would need to be consulted once one exists — this
phase should leave that seam obviously open rather than build a temporary
answer for it.

---

## 4. Decisions needing your sign-off

| # | Decision | Options on the table | This document's lean |
|---|---|---|---|
| **D43-1** | Repo scope precision — does authorizing a repo pin a ref? | (A) repo only, any ref, ref is a proposal-time constraint; (B) scope pins an exact ref/commit; (C) scope pins repo + mutable branch name | (C) — the resolved commit SHA is a required `execution_context` fingerprint dimension regardless of which is chosen (D11-3) |
| **D43-2** | Monorepo subdirectory containment | Define path-level containment, or refuse it and treat exclusions as an adapter-level constraint | Refuse it — identical to D25 §2.2's `url`/`repo`/`ad_domain` decision, low-friction |
| **D43-3** | Does `code.*` require known classification? | Yes (join `requires_known_classification`'s pattern set as `code.*`) / No | Yes — independently argued from D32's "touches content" test, not inherited from it |
| **D43-4** | Evidence sensitivity handling for matched code snippets | (A) full snippet in derived_view; (B) no snippet, metadata only; (C) truncated snippet + a new confidentiality marker | (C), truncated — the point this document most wants your read on |
| **D43-5** | How the repository reaches the sandbox | (A) `git clone` inside the sandbox container; (B) control-plane-side fetch + a new read-only directory bind-mount | (B), consistent with D34/D35/D36's trust-minimization precedent, but the larger lift |
| **D43-6** | Private repository support | In scope now (needs a credential path) / deferred to Credential Vault | Deferred — matches D42-6's `ad.collect` precedent exactly |

---

## 5. What this document does not do

No code, schema, migration, or Rego was written or changed. No `semgrep`
binary was installed, invoked, or inspected for its actual CLI flags or
exact JSON output schema — `extra.lines` is cited from public knowledge of
Semgrep's output format, not verified against a real run in this
environment, and should be checked before implementation the same way the
D42 ADR flagged its Neo4j research as search-sourced rather than hands-on
verified. No repository, public or private, was cloned. Nothing about D42's
Security Graph, BloodHound adapter, or any prior stage was touched.
