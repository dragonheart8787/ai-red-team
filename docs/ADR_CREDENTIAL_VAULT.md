# ADR: Credential Vault — Phase 1 investigation (D44)

Investigation and design only. No schema, migration, code, or Rego was
written or changed for this document. Every claim below about the current
system was checked against the tree at the time of writing (D43, commit
`ab2849a`), not assumed from the concept brief.

**Status update (D45/D46)**: implemented at D44 as this document describes.
D45 drove a real `revoke_credential()` call genuinely mid-flight during a
real `dispatch_collection` run and found §2.2's exposure-window claim needs
a sharper mechanism than stated: the revoke is not merely "too slow to stop
the container" (below) — it is a complete no-op against that specific run,
because `propose_action`'s entire pipeline runs inside one open database
transaction, and the capability row a concurrent revoke needs to see does
not exist to any other connection until that transaction commits, which
happens only once the container has already finished. This does not change
§2.2's conclusion (the exposure window is accepted, not closed, per D44-7
Option A) — it sharpens the mechanism behind it. Full account:
`docs/D45_AD_COLLECTION_E2E_REPORT.md` §6, and
`docs/ACCEPTANCE_MVP1_AGENTS.md` 5.24's own addendum.

**Addendum (D50)**: §7 records one place where the implemented design does not
meet §2.1 (the secret reaches the tool's argv and is visible in the host
process table), and lays out options with evidence. **No option was adopted**;
it is tracked as ACCEPTANCE 5.26. **Revision (D50-B)**: §8 changes what an
`ad_domain_bind` credential *is* — a secret, an account and an auth mode stored
as one indivisible unit.

## 0. Why this is a different trust boundary than D35, and why that matters

D35 built the only precedent this system has for handing a sandboxed
container secret material at all — a TLS leaf certificate and key for the
egress proxy. It is tempting to treat D44 as "D35 again, for a different
secret," but the two do not share a threat model, and treating them as the
same would produce a design that looks careful and is not.

D35's leaf key goes to a container **this system owns and built**
(`tool_gateway/egress_proxy.py`), running fixed code nobody outside this
codebase controls, whose only job is to terminate one TLS connection to one
host the capability already named. The key's blast radius is bounded by
what that fixed, audited program does with it — which is: present it in a
handshake and nothing else.

D44's credential goes to a container running **the actual tool** —
`bloodhound-python` reading a Worker/Supervisor-directed command line, or
(per §4 below) potentially nothing at all, depending on which of the two
target use cases is in view. Unlike the proxy, this is the exact class of
process §8.3 already calls "compromised or hallucinating": something whose
behavior this system does not fully control once it starts, holding a
credential that is not this system's own infrastructure secret but a real
customer domain password or access token. D35 never had to ask "what can a
compromised holder of this secret do to a third party," because its secret
was never handed to a third-party-facing, semi-trusted process. D44 has no
way to avoid that question.

That difference drives every section below. The file-mount-not-argv
*mechanism* D35 built is worth reusing (§2.1); the *trust conclusion* D35
reached — "a compromised holder of this key can only misuse it for the one
thing this system's own code lets it do" — does not transfer, and §2.2
works out what does transfer in its place.

---

## 1. Credential storage and lifecycle

### 1.1 What exists today, verified

`docs/ADR_BLOODHOUND_NEO4J.md` §4.3 already did this check for D42 and
found: the `credentials` table (`db/migrations/versions/0001_core_schema.py`
lines 197–205) is

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

Re-verified for this document, with two things D42's check did not need to
go further into:

* **`capability_id.credential_id` is fully plumbed as an identifier, never
  as a secret carrier.** `control_plane/capability/broker.py` threads
  `credential_id` through `issue_capability`, `_load_capability`,
  `renew_capability`, and `revoke_capabilities_for_credential` — it is a
  real column on the `Capability` dataclass (line 154), read back out of
  the database on every renewal. `control_plane/orchestrator/engagement.py`
  `revoke_credential` (line 281) flips `credentials.revoked` and cascades
  into `revoke_capabilities_for_credential`, and this cascade is genuinely
  built and tested (D9). **What is missing is not the identifier plumbing —
  it is everything between "a capability names a `credential_id`" and "a
  tool process holds the actual secret bytes."** No function in this
  codebase has ever read a `credential_id` and produced material from it,
  because there has never been any material to produce: the row carries a
  label and a revocation flag and nothing else.
* **The one production call site never passes one.** `control_plane/api/
  function_api.py`'s `issue_capability` call is the only place a real
  capability is issued outside tests, and it never supplies `credential_id`
  — confirmed again for this document, unchanged since D42's check.

Conclusion: **there is nothing to extend.** `§48`'s Credential Vault is not
a partially-built feature with a rough edge; it is an identifier column and
a revocation cascade with zero live callers, waiting for the first one. This
is a from-scratch design for everything except "how does a capability say
which stored credential it means," which is already solved.

### 1.2 Where secret material lives at rest

Two real options, not a spectrum:

**Option A — an encrypted column in Postgres.** Add a `credential_material`
table (or columns on `credentials` itself) holding envelope-encrypted
blobs: a master key held outside the database (an environment variable on
the control-plane host, matching this project's existing "no hardcoded
secret, `.env`-based, generated once" convention — `scripts/init_db.sh`
already does exactly this for the four database role passwords) encrypts a
per-credential data key, which encrypts the actual secret. Decryption
happens application-side, inside the control-plane process, using a
library like `cryptography`'s `Fernet` or AES-GCM directly — the same
dependency this repo already uses for `control_plane/tls/engagement_ca.py`.
RLS on the new table follows the exact `engagement_ca` precedent (§1.3
below decides who else can reach it).

* *For*: zero new infrastructure. This system's entire stack today is
  Postgres + OPA + Docker — no message queue, no service mesh, no existing
  secrets manager anywhere in the tree (a repo-wide search for `vault`/
  `Vault` outside this new document returns nothing). Adding HashiCorp
  Vault, AWS Secrets Manager, or an equivalent means a new service to
  deploy, seal/unseal or IAM-bootstrap, monitor, and back up, for what is
  — at the scale this system runs at today — a handful of credentials per
  engagement. This is the identical shape of argument D42-5 already made
  and you already accepted: *measure/justify the complexity before adding
  a service*, not architect for a scale nobody has hit yet.
* *Against*: the master key's own protection is now this system's problem,
  not a specialized product's. A key in an environment variable on the
  control-plane host is protected by host access control alone — no seal/
  unseal ceremony, no per-secret access policy finer than "the control
  plane process can decrypt everything," no built-in secret-versioning or
  automatic rotation. If the control-plane host is compromised, every
  credential in every engagement decrypts at once — there is no equivalent
  of Vault's per-token, per-lease access scoping to blunt that.

**Option B — an external secrets manager (HashiCorp Vault OSS, cloud KMS +
Secrets Manager).** The control plane never stores plaintext or holds a
master key at all; it authenticates to the external service per-request
and asks it to decrypt (or, for Vault's dynamic-secrets engines, to *mint*
a fresh credential on demand — Vault's AD secrets engine can generate a
short-lived domain-bind credential without this system ever storing the
long-lived one at all, which would answer part of §2.3's "how do you make
a copy short-lived" question at the source rather than downstream of it).

* *For*: purpose-built for exactly this problem — audit logging, seal/
  unseal, per-secret access policy, secret versioning, and (for the AD use
  case specifically) genuine dynamic secret issuance are Vault's actual job,
  not something this document would be inventing a smaller version of.
* *Against*: real new operational surface — a service to run, an unseal
  process (or auto-unseal via a cloud KMS, itself another dependency), and
  a second system whose own compromise or unavailability now gates every
  Vault-dependent tool run. This is the same "operate what actually solves
  a measured problem" question D42-5 answered by *not* adopting Neo4j.

**This document's lean**: **Option A now**, with **B named as the
correct next step once either (a) credential volume/rotation needs exceed
what a hand-rolled envelope scheme comfortably handles, or (b) the AD/
LDAP use case specifically wants dynamic short-lived credentials rather
than a stored long-lived one exposed on every run (§2.3)**. This is
consistent with D42-5's own reasoning applied to a different piece of
infrastructure, not a new argument invented for this document.

### 1.3 Who can write a credential

The existing role model (`scripts/init_db.sh`, and the migrations that grew
it — 0001 `cyberorch_app`, 0002 `registry_admin`, 0007 `global_auditor`,
0008 `ui_reader`) is a strict one-role-one-job ladder:

| Role | What it can touch |
|---|---|
| `cyberorch_app` | Runtime path, RLS-bound, append-only on most tables (0001's blanket grant was narrowed to INSERT+SELECT by every later migration that touches a table) |
| `registry_admin` | Everything `cyberorch_app` can, plus write access to `scope_registry`/`metadata_registry` (0002) and engagement creation + `policy_layers` SELECT (0010) — the "Engagement Manager" |
| `global_auditor` | SELECT on `audit_log` only, across engagements (0007) |
| `ui_reader` | SELECT on a fixed dashboard-safe table list (0008) |

Every one of these splits happened *because* the previous arrangement
bundled unrelated privileges — D39's own finding was that giving
`registry_admin` broad `cyberorch_app`-shaped access and *then* carving out
scope/metadata write was the wrong order; the pattern this codebase has
settled on is a new role per new responsibility, not widening an existing
one's blast radius.

**Option A — extend `registry_admin`.** The Engagement Manager is already
the human/system boundary trusted with what a Worker may target
(`scope_registry`) and what the system believes about a target
(`metadata_registry`) — a credential is arguably one more thing "the
person who sets up an engagement" configures.

* *Against*: this bundles the single most sensitive category of data in
  the system (a real customer password or token) into a role whose
  existing job is authorizing *targets*, not guarding *secrets*. A
  `registry_admin` connection compromise today yields forged scope or
  metadata — bad, escalation-worthy, but not a customer's actual domain
  admin credential in the clear. Extending it changes what "the
  `registry_admin` connection leaked" means qualitatively.

**Option B — a new, dedicated role** (e.g. `credential_admin`).

* *For*: matches every precedent in the table above exactly. Even if in
  practice the same human operates both `registry_admin` and this new
  role, keeping the *database roles* separate means a `registry_admin`
  application-layer bug or SQL-injection-shaped mistake — the kind of thing
  RLS and role separation exist to contain even from this system's own
  code, not only from a customer's Worker — cannot reach credential
  material by construction, the same reasoning that kept `ui_reader` and
  `global_auditor` from ever being folded into `registry_admin` for
  convenience.
* *Against*: one more connection string/role to provision in
  `scripts/init_db.sh`, one more thing to keep in sync across migrations.

**This document's lean**: **Option B**, for consistency with the only
pattern this codebase has ever used for "a new category of sensitive
access arrives" — every prior instance (D2, D7, D8/D39) added a role
rather than widened one, and this is a strictly higher-sensitivity category
than any of them.

---

## 2. Getting a credential into the tool container

### 2.1 What D35 established, what generalizes, what does not

`tool_gateway/sandbox.py`'s `DockerSandbox.run()` already has the primitive
this needs: `source_mounts` (extended in D43 from D35's single-PEM-file
`ca_cert_pem` path to arbitrary host-path → container-path read-only bind
mounts). **The principle "path in argv, secret content only in a mounted
file, never in argv or the environment" generalizes without change** — a
Vault-issued credential file is mounted exactly the way `TOOL_CA_PATH` and
D43's repository/ruleset mounts already are.

**What does not generalize is D35's implicit assumption that the thing
handed to a container never needs to outlive one already-bounded
operation in a way anyone has had to reason about.** D35's leaf lives
"as long as the proxy does" (its own docstring) — one proxy process, one
capability, no renewal-time re-evaluation of whether the leaf should still
be trusted, because a leaked leaf can only impersonate the TLS server side
of one already-authorized connection. A Vault-issued domain credential or
git token has none of that self-limiting property: it authenticates as a
*principal* (a real domain account, a real GitHub identity), not as one
side of one already-scoped connection, so it needs the lease/heartbeat
tie-in D35 never needed.

**The new problem: a mounted file cannot be un-mounted from a running
container.** This is not a D44-specific gap — it is true of every
revocation path this system has ever built. `engage_kill_switch`
(`control_plane/orchestrator/engagement.py` line 231) and
`revoke_credential` both only flip a database row and refuse *future*
capability issuance/renewal (`check_preconditions`, called at issue and
heartbeat time, never mid-dispatch); neither has ever reached into a
running container. `revoke_credential`'s own docstring is explicit about
this: *"Eager, like the kill switch and for the same reason: ... The
renewal check remains the backstop for anything issued in the same
instant."* Every dispatch function (`dispatch_scan`, `dispatch_collection`,
`dispatch_code_scan`) calls `sandbox.run()` as one blocking call bounded
only by `max_duration_seconds`, with no re-check of `capabilities.revoked`
between container start and container exit.

This has never mattered before now because nothing a running container
held was itself worth stealing — an nmap scan revoked mid-flight loses
nothing but its own (already-scoped, already-bounded) output. **D44 is the
first deliverable where "the container keeps running for `max_duration_
seconds` after revocation" means "a real secret sits in a container's
filesystem for `max_duration_seconds` after this system decided that
secret should no longer be trusted."** That is a materially different
severity riding on an unchanged mechanism, and it needs to be named rather
than inherited silently.

Docker *does* support killing a running container by ID
(`tool_gateway/sandbox.py` line 703, already used for the
`max_duration_seconds` timeout enforcement), and every container is
labeled with its `run_id` (line 667) which `tool_runs.run_id` already
correlates to a `capability_id` — so "kill every container whose
`tool_run` carries the just-revoked `credential_id`" is buildable, not
hypothetical. Whether to build it now is Decision D44-7 below.

### 2.2 Blast radius, stated at §8.3's level of precision

§8.3 states its bound as: *a fully compromised Worker can, at most, do
what the union of its currently-valid capabilities allows, for as long as
each capability's TTL allows.* D44 needs the equivalent statement for a
compromised **tool container** holding vault-issued material, which is a
narrower and more concrete claim because a tool container (unlike a
Worker) cannot propose new capabilities — it can only misuse the one
credential it was actually handed, for the one target its capability
already named.

**Stated precisely, for the LDAP/domain-credential case (`ad.collect`,
§4.1):** a compromised `ad.collect` container holding a Vault-issued
credential can, at most, use that credential's real authentication
material (password, or NTLM hash for pass-the-hash) to authenticate as
that domain principal against hosts reachable within the capability's own
`network_allowlist` — which, per D42-1, is a scope this same capability
already had to name — for no longer than `max_duration_seconds`, after
which the sandbox kills the container (or, if D44-7 is adopted, as soon as
the credential is revoked, whichever is sooner). **This system adds no
privilege the credential did not already carry in the real domain**: what
it bounds is *where* the credential can be presented (§8.3's existing
network confinement, unchanged by this deliverable) and *for how long*
(the sandbox timeout, an existing mechanism now carrying new stakes). What
it does **not** bound, and cannot: the credential's plaintext is real bytes
on that container's filesystem for the run's duration — LDAP simple bind
needs the literal password, there is no TLS-leaf-shaped derivative that
lets the container prove possession without holding the value itself
(§2.3 examines what *can* be shortened instead). If the container's
`network_allowlist` includes anything beyond the domain controller itself,
the compromised process could also attempt to relay or exfiltrate the
credential to another reachable host — a risk §8.3's existing per-capability
CIDR scoping already bounds and D44 does not need to re-solve, but which
argues for `ad.collect`'s allowlist staying as narrow as D42-1's own scope
model already pushes it.

**Stated precisely, for the git-token case (`code.scan` private repos,
§4.2):** **there is no equivalent exposure inside a tool container to
analyze**, because — as §4.2 below works out from D43-5's already-decided
architecture — the credential this case needs is consumed entirely
control-plane-side, before any sandbox exists for that dispatch. The
Semgrep container's own blast radius is unchanged by D44: still zero
credential material, still zero network egress, exactly as D43 shipped it.

### 2.3 Lifetime strategy: what can be shortened, and what cannot

D35's leaf key is a genuine *derivative* — a fresh, single-purpose
artifact minted from a long-lived CA key, worth nothing beyond one
TLS handshake to one host for 12 hours. The question for D44 is whether an
equivalent derivative exists for each credential shape, because "mint a
short-lived copy, never hand out the long-lived original" is a strictly
better answer than "hand out the long-lived original with a short mount
window" wherever it is possible at all.

* **NTLM hash / pass-the-hash**: no derivative exists. The hash *is* the
  credential in this authentication scheme; there is nothing cheaper to
  mint from it that still authenticates. The only available lever is
  exposure window (§2.2's `max_duration_seconds` bound) and never
  persisting the hash to the container beyond that one mounted file,
  deleted immediately after `sandbox.run()` returns — the same
  caller-owns-cleanup discipline `control_plane/orchestrator/git_fetch
  .cleanup_repo` already established for D43's fetched repository.
* **Domain password (LDAP simple bind)**: same conclusion as the hash —
  bloodhound-python needs the literal password bytes to bind. **Unless
  Option B of §1.2 is adopted** (a Vault with a real AD/LDAP dynamic-
  secrets engine), in which case the Vault itself could mint a genuinely
  short-lived service-account credential distinct from any operator-
  supplied long-lived one — the one case in this whole document where
  the storage-layer decision (§1.2) and the delivery-layer decision (§2.3)
  are not independent: Option B (external Vault) is the only path to a
  real leaf-shaped derivative for this credential type. Recorded as a
  fact this document surfaces, not a reason to force §1.2 to B — the
  storage decision is about the whole system's dependency footprint,
  not this one lever alone.
* **Git access token (personal access token or GitHub App installation
  token)**: a real derivative *does* exist and is standard practice — a
  GitHub App installation token is already short-lived (1 hour) and can be
  minted on demand from a longer-lived App private key; even a bare PAT
  can be scoped narrowly at issuance time. But per §4.2, this consumption
  happens control-plane-side, not inside a sandbox, so the "how short can
  the copy in the container be" question does not arise for this case at
  all — the relevant question becomes "how short-lived is the token the
  control plane's own `git_fetch.fetch_repo` call uses," a much lower-
  stakes question than anything reaching a sandboxed process.

**Net design for the case that does need a sandbox-delivered copy
(`ad.collect`)**: mint a per-dispatch file (mode `0644`, matching D43's own
correction — `git_fetch.fetch_repo`'s `chmod a+rX` fix, made necessary
because a container's non-root user cannot read a host-default `0700`
temp directory; the same lesson applies here and must not be
independently re-discovered) at the moment `dispatch_collection` builds
its plan, mount it read-only, and delete it in the dispatch function's
`finally` block the same way `git_fetch.cleanup_repo` is always called
regardless of outcome. No new "TTL" field beyond `max_duration_seconds`
is needed — the credential's exposure window is already exactly that
budget, and the design obligation is only to make sure nothing caches or
reuses the on-disk copy across dispatches.

---

## 3. Audit

Every credential lifecycle event needs its own named event, mirroring
D35's `egress_ca.provisioned`/`egress_leaf.minted` exactly:

* `credential.stored` — a new secret is written (actor: the new role from
  §1.3, never `cyberorch_app`).
* `credential.issued_to_run` — a per-dispatch copy was minted and mounted
  for one `tool_run` (parallel to `egress_leaf.minted`, `subject_id` the
  `run_id`).
* `credential.revoked` — **already exists** (`control_plane/orchestrator/
  engagement.py` line 307), unchanged; D44 only needs to confirm its
  payload shape (`{"revoked_capabilities": [...], "capability_count": N}`)
  never needed a secret-bearing field, which it does not.
* `credential.mount_cleanup_failed` — the deferred-cleanup step (§2.3)
  could not remove an on-disk copy; this must be its own alarmable event,
  not silently swallowed, since a cleanup failure means a secret is sitting
  on the control-plane host's disk longer than designed.

**Test requirement, matching the existing pattern exactly**
(`tests/test_engagement_ca.py::test_provisioning_the_ca_is_audited_
without_leaking_the_key`, verified above at lines 210–225): the test must
check for the **actual secret bytes**, not merely the absence of a
suspiciously-named field — `key_body = ca.key_pem.split("\n")[1]; assert
key_body not in payload`. A test that only asserts `"password" not in
payload.keys()` would pass on a payload that embedded the raw secret
under an oddly-named key, which is exactly the gap D30's "the test input
must differ from the default" standard exists to catch in spirit: a check
that cannot fail on the actual mistake it claims to guard against proves
nothing. Every new event above needs this same mutation-shaped test
(construct a payload, confirm the literal credential value is checked
for, not a key name).

---

## 4. Validating the design against both stuck tools

The brief is explicit that this design must not be built for one shape and
assumed to fit the other. Working through both concretely surfaces a real
asymmetry, not a coincidence of implementation detail:

### 4.1 `ad.collect` (D42) — genuinely needs everything above

`tool_gateway/adapters/ad_collector.py`'s `build_plan` (module docstring,
lines 15–29) is explicit about the gap it left open: `bloodhound-python`
needs `-u <user> -p <password>` or `-u <user> --hashes <hash>` to
authenticate an LDAP bind, and **that authentication happens inside the
sandboxed container**, because the LDAP protocol conversation is the
`bloodhound-python` process's own socket-level work — there is no
control-plane-side step that could do this on the container's behalf the
way §4.2 has for git. This is the case §2's entire design (file-mount
delivery, lease-tied lifetime, blast-radius analysis, no available
derivative shorter than the credential itself) exists to serve, and it
needs all of it.

### 4.2 `code.scan` private repositories (D43) — does not need §2 at all

This is the asymmetry worth being explicit about rather than assuming away.
`docs/ADR_SEMGREP.md` §3.1 already decided (**D43-5, Option B**) that the
repository is fetched **control-plane-side, outside any sandbox**, and
handed to the Semgrep container only as an already-fetched, already-
decrypted plaintext directory via a read-only bind mount. The Semgrep
container itself never touches a git remote, never holds a git credential,
and never has network egress at all (`tool_gateway/adapters/semgrep.py`
`REQUIRES_PROXY = False`, confirmed unchanged by this document).

That means a git access token for a private repository is needed by
exactly one caller: `control_plane/orchestrator/git_fetch.fetch_repo`,
called from `dispatch_code_scan`, itself a fully-trusted control-plane
function — the same trust tier as `ensure_engagement_ca`/`mint_leaf_for_
host` (§0's D35 comparison), not the tool-container tier §2 is built for.
**§3.2 of `ADR_SEMGREP.md` already named this seam explicitly**: "Option
B's control-plane-side fetch step is exactly where a vault-issued
credential would need to be consulted once one exists." Verifying that
claim against this document's own design: yes — a Vault client call inside
`fetch_repo` (or a thin wrapper around it) that resolves a `credential_id`
to a token, uses it for exactly one `git clone` subprocess call, and never
persists or returns it, is a straightforward extension of §1's storage
design with **none of §2's mount/lease/blast-radius machinery required**,
because the secret never crosses a sandbox boundary at all.

### 4.3 Does one interface serve both?

Yes, but only if the interface is explicit that it has **two delivery
modes**, not one:

```
vault.material_for(conn, credential_id) -> CredentialMaterial   # control-plane-local use (§4.2)
vault.mount_for_run(conn, credential_id, run_id) -> MountedCredential  # sandbox file-mount (§4.1)
```

Designing a single function that always returns a mounted file path would
force `git_fetch.fetch_repo` to write a token to disk and mount it into
*something* even though nothing sandboxed ever needs to read it — solving
a problem D43-5 deliberately built around. Designing a single function that
always returns raw material in memory would put `ad_collector.build_plan`
back to smuggling a secret through a command string or environment
variable, exactly what §2.1 rules out. The interface has to know which of
the two `credential_type` shapes (`ad_domain_bind` vs. `git_token`, or
whatever the storage schema names them in §1) implies which delivery mode,
the same way `registry.ADAPTERS`/`side_effects_for` already dispatch on an
action's own declared shape rather than a caller's claim about it.

---

## 5. Decisions needing your sign-off

| # | Decision | Options on the table | This document's lean |
|---|---|---|---|
| **D44-1** | At-rest storage for credential material | (A) Encrypted column(s) in Postgres, master key outside the DB; (B) external secrets manager (HashiCorp Vault / cloud KMS) | (A) now, for the same "don't add infra ahead of a measured need" reasoning as D42-5 — (B) named as the correct move if AD dynamic-secret issuance (D44-4) or rotation/volume needs later justify it |
| **D44-2** | Which role may write/read credential material | (A) extend `registry_admin`; (B) a new, dedicated role (`credential_admin`) | (B) — matches every prior role split in this codebase (D2/D7/D8/D39), none of which widened an existing role instead |
| **D44-3** | Credential delivery interface shape | One function returning a mounted file path always, vs. two explicit modes (control-plane-local material, and sandbox file-mount) per §4.3 | Two modes — a single always-mounted interface forces D43's already-decided no-sandbox-credential design backward |
| **D44-4** | Lifetime strategy for a credential with no cheaper derivative (NTLM hash, LDAP password) | (A) accept exposure bounded by `max_duration_seconds`, document as a stated limit (§2.2), matching §8.3's cert-pinning "explicit limit, not a defect" precedent; (B) require Option B of D44-1 (external Vault) specifically to obtain AD dynamic-secret issuance before `ad.collect` may use a real domain credential at all | (A) for this phase, with (B) flagged as the only real fix if the exposure-window risk is judged unacceptable at production scale |
| **D44-5** | Per-dispatch mounted-credential file cleanup | Delete in the dispatch function's own `finally` block (mirrors `git_fetch.cleanup_repo`) | Yes — no alternative considered, this is not a real decision point so much as a requirement to not skip |
| **D44-6** | New audit events | `credential.stored`, `credential.issued_to_run`, `credential.mount_cleanup_failed`, alongside the existing `credential.revoked` | As listed in §3 |
| **D44-7** | Should credential revocation actively kill any currently-running container holding it, rather than only blocking future issuance? | (A) accept the existing eager-DB-flip-only pattern (same as the kill switch and every prior revocation path), document the in-flight exposure window as a named, accepted limit; (B) build active `docker kill` on revocation, keyed by `tool_runs.run_id` ↔ `capability_id` ↔ `credential_id`, confirmed buildable against existing container labeling (`tool_gateway/sandbox.py` line 667) | Leaning (A) for this deliverable's scope, recorded as a DEFERRED candidate (5.2x-style) in `docs/ACCEPTANCE_MVP1_AGENTS.md` rather than silently assumed solved — (B) is real, scoped work but widens this deliverable considerably and is not blocking either D42 or D43 from becoming usable |

---

## 6. What this document does not do

No code, schema, migration, or Rego change. No credential material of any
kind — real, synthetic, or placeholder — was stored, encrypted, or moved
anywhere. No external secrets manager was installed, run, or evaluated
hands-on; §1.2's comparison is sourced from this system's own existing
architecture plus general knowledge of HashiCorp Vault's documented
feature set, not a working deployment. `bloodhound-python`'s actual
`-u`/`-p`/`--hashes` flags remain **unverified against an installed
binary**, exactly as `ad_collector.py`'s own module docstring already
flags — this document did not attempt to close that gap, since no
credential exists yet to test a real bind with regardless. Nothing about
`dispatch_scan`, `dispatch_collection`, or `dispatch_code_scan`'s existing
behavior was changed; this document only traced how each already handles
(or does not need to handle) secret material, to ground §2 and §4.

---

## 7. Addendum (D50) — the secret reaches the tool's argv: options, not a decision

**Status: DISPOSED at the D50 decisions (see §7.11).** No option below was
adopted; the exposure is recorded as `docs/ACCEPTANCE_MVP1_AGENTS.md` 5.26 for
re-evaluation once a real threat model exists, and one *different* question
raised here (§7.8) was adopted and is recorded as a revision in §8. The section
is kept as written when it was a draft — options, evidence and leans — because
5.26 points back to it. It is an addendum, not a rewrite: §§0–6 stand as written
(D44's design was implemented as described and its delivery mechanism was
re-verified byte-for-byte at D50). What this section does is record one place
where the implemented design does not meet a principle §2.1 states, lay out the
ways to close or accept that, and put the same question §0 asked of D35 to each
of them — *is this the same trust boundary as the precedent?* — with evidence,
before anyone builds anything. Evidence is from D50 unless marked otherwise;
every experiment is reproducible with
`scripts/live_run/d50_ad_collector_auth_probe.py` (probes 2, 4, 5) and the
commands quoted inline. Full investigation:
`docs/D50_AD_COLLECTOR_AUTH_GAP_INVESTIGATION.md`.

### 7.1 What is true today

**§2.1 says** the principle "path in argv, secret content only in a mounted
file, never in argv or the environment" *"generalizes without change"*. For
`bloodhound-python` it cannot be applied literally, because the tool has no
option to read its password from a file. D44 resolved that with a shell wrapper
(`sh -c 'exec bloodhound-python … "$(cat /creds/secret)"'`), and
`ad_collector.py`'s docstring called the residue "an honest limit". Measured
while the tool runs (D50 probe 4):

| Observer | Sees the secret? |
|---|---|
| `docker inspect` `Config.Cmd` (the daemon's / control plane's record) | no |
| `tool_runs.normalized_params`, `tool_run.started` audit payload | no (D45/D49 live checks + `dispatch_collection`) |
| `docker top <container>` | **yes** |
| host `ps -eo args` | **yes**, for the whole run (the wrapper `exec`s) |
| the mounted file `/tmp/cyberorch-cred-*` on the host | **yes**, mode `0644`, for the whole run (ADR §4.1's own choice) |

What that changes about the record:

* The principle in §2.1 is met for everything *this system* records and not met
  at the host process table. The adapter docstring limited the exposure to
  "*inside* the container … for the moment it execs" and said §2.2 "already
  prices this in"; both statements understate it (host-wide, run-long), and
  §2.2 does not mention the process table at all. That is a correction owed
  regardless of which option below is chosen.
* **A calibration made at D50 needs qualifying.** D50's report called the
  practical increment small, because the same run already leaves the secret in
  a world-readable file that anyone who can `ps` can also read. That reasoned
  only about *live local observers*. It did not consider that argv, unlike a
  temp file, is routinely **recorded and shipped off-host** by `auditd`
  `execve` rules and EDR/process-telemetry agents, and then persists in places
  the file never does. I have not measured whether any such collector runs on
  a deployment host; it is general knowledge about how those tools work, stated
  as a risk to be assessed, not as a finding.
* The 0644 file is a *separate* exposure and stays under every option except
  §7.5. The container runs as `uid=10002 (collector)` with `CapEff=0`
  (measured), so a `0600` file owned by any other host uid is unreadable to it;
  `0644` is what makes the mount work. Narrowing that (e.g. `chown` to
  10002) needs the control plane to run as root or as that uid, which is not
  generally true — out of scope here unless you want it added.

### 7.2 The yardstick: what the precedents actually did

§0 separated D35 from D44 by asking whose code holds the secret. The same
question needs a finer grain here, because every option below still uses the
D44 mount; what differs is what sits between the mounted file and the tool.

| | Who reads the file | Where the secret lives afterwards | Platform-authored code in the tool's process | Uses the tool's own input channel? |
|---|---|---|---|---|
| **D35** TLS material | the tool, via its own flag (`curl --cacert <path>`) | the tool's memory | none | yes |
| **D34** web.post body | the tool, via its own `--data-binary @-` on stdin | the tool's memory | none | yes |
| **D44 as built** | `sh` (`$(cat …)`), then `exec` | **the tool's argv** | shell glue, *gone after `exec`* | yes (argv) — but populated by platform glue |

The `sandbox.run` contract all of these share is *container-level*: an
internal, gateway-less network confined to the allowlisted CIDR, no capabilities,
read-only root, `no-new-privileges`, pid/memory limits, a kill at
`max_duration_seconds`. None of it depends on what the process image is or how
its `command` is written, and no option below touches any of it. Repo check: no
code identifies a tool by its command line (`grep` for `docker top`, `/proc/…/
cmdline`, `psutil`: nothing); tool identity is `adapter.TOOL`, recorded in
`tool_runs.tool` and the audit payloads.

### 7.3 Option (i) — an in-process launcher

`python3 -c '<fixed script>' <positional args>` reads `/creds/secret`, builds
`sys.argv` in memory, and calls the tool's own entry point.

**What was verified (D50).**
* The entry point is the package's *declared* console script
  (`entry_points.txt`: `bloodhound-python = bloodhound:main`), and the console
  script itself is `sys.exit(main())`. A launcher making the same call is not
  reaching into internals.
* Behavioural equivalence, real image, five cases (no auth flag → usage; an
  argparse error; auth accepted then DNS unreachable; `--help`; a hash-parse
  `ValueError`): **exit code, stdout and stderr identical** to the console
  script, ignoring traceback frame lines (they name `<string>` instead of the
  script path). One requirement surfaced: the launcher must set `sys.argv[0]`,
  or argparse's `prog` — which appears in usage and error text — changes.
* The secret is absent from `docker top` and host `ps` while the tool runs,
  and the tool still selects its authentication branch (probe 5).
* The shell layer disappears, so `$(cat …)`'s newline stripping goes with it;
  every value would reach the tool as a list element, never through a shell.

**Deviation from `sandbox.run`'s execution model, axis by axis.**

| Axis | Now | With a launcher | Verdict |
|---|---|---|---|
| Container guarantees (network, caps, FS, limits, kill) | unchanged by anything in `command` | identical | **no deviation** |
| Privilege of the code that reads the secret | `sh`, uid 10002, CapEff 0 | `python3`, same uid, CapEff 0 | no deviation |
| Process image the audit/`docker top` describes | `bloodhound-python …` | `python3 -c …` | changes; nothing in the repo consumes it |
| What the audit records | the full `command`, glue included | the full `command`, glue (now Python source) included | unchanged in kind — the code that runs is still in the audit verbatim. A launcher *baked into the image* would not have this: the audit would record only its path. Inline is the option that preserves it |
| Is platform code resident in the tool's process? | **no** — `exec` replaces the shell | **yes** — the launcher's frame stays on the stack while `main()` runs | **the one real shift** |
| Reliance on tool internals | the tool's CLI | the tool's CLI **and** its `main` entry point (pinned: `BLOODHOUND_VERSION`, build-time manifest check) | small, and the delivery/acceptance tests in `tests/test_ad_collector_credential_delivery.py` run against the real image in CI, so a break is caught |
| Child processes | n/a | the tool uses `multiprocessing.Pool` for ACL parsing; this image's default start method is `fork`, so workers inherit the parent's command line, which contains no secret (it is read at run time, not embedded). Not exercised end to end: no run has got far enough to start the pool | unverified past the argument that follows from `fork` |

**Is it the same trust boundary as the precedent?** In every respect §0 cares
about — who holds the secret, with what privilege, what a compromised holder
can do — yes: a compromised tool library in the same interpreter can already
read `/creds/secret` and its own argv, so a resident launcher grants nothing
new. What is genuinely new is category, not capability: D34 and D35 both used
the tool's **own** input channel with nothing of the platform's in the tool's
process, and D44's shell wrapper was platform glue that disappeared at `exec`.
A launcher is the first case where platform-authored code stays resident in the
tool's process. That is a fact to decide on, not a reason to refuse it.

**What it does not do:** it leaves the `0644` file (§7.1) untouched. It also
fixes **both** authentication modes (password and hashes), which no option
except (iii) does.

### 7.4 Option (ii) — Kerberos ccache instead of a password

The tool's `-k` mode reads a ticket cache instead of a secret; the secret never
enters the tool container.

**What was verified (D50).** `bloodhound/ad/authentication.py` `load_ccache`
reads the path from the `KRB5CCNAME` environment variable and extracts only a
**TGT**. After that the tool still calls `getKerberosTGS(…, self.kdc, …)` to
obtain service tickets, and impacket's `sendReceive` resolves the KDC
*hostname* with `socket.getaddrinfo` — the system resolver, which D49's `-ns`
does not touch and which cannot resolve AD names in the sandbox (D50 F4,
observed in D49's own run). Two more findings:
`DockerSandbox.run` has no environment parameter (`grep` for `environment=`:
none), so `KRB5CCNAME` would have to be set by a shell prefix in `command`; and
the tool container's uid is 10002, so the ccache file has the same mode
constraint as §7.1.

**Consequences.**
* It is **coupled to F4**, which was deliberately deferred: without a way for
  the tool container to resolve the KDC's name, the Kerberos path cannot get
  service tickets. This option cannot be evaluated, let alone built, before F4.
* Something must mint the ccache from the password. Either the control plane
  does (a new dependency — impacket is not in `pyproject.toml` — and a new
  network path from the control plane to a customer's KDC; D43's control-plane-
  side `git fetch` is the nearest precedent for the control plane contacting a
  third party with a credential), or a *second, fixed-code container* does,
  which is the D35 pattern (§0: a program this system owns) applied to a new
  purpose.
* **It contradicts a sentence in §2.3.** §2.3 says no derivative shorter than
  the credential exists for a domain password or hash. A Kerberos TGT is such a
  derivative (bounded lifetime, password never leaves the minting step). The
  caveat: while valid it, and its session key, act as the principal for
  anything the principal can do, so it shortens the window and removes the
  password from the tool container without shrinking what a leak can do.
* Not verified at all: any part of this against a real KDC. Samba's KDC
  rejects impacket's TGS-REQ for a reason D45 recorded, so this environment
  cannot test it.

### 7.5 Option (iii) — accept it, and correct the record

No mechanism change. State the exposure and bound it.

* **Bound:** host-visible for at most `max_duration_seconds` (600 by default in
  `build_plan`; the budget the capability carries), to whoever can list host
  processes or run `docker top`, and — per §7.1 — to any host-local user via the
  file regardless.
* **Corrections owed under any option:** the `ad_collector.py` docstring
  (scope: host, not container; duration: the run, not "the moment it execs";
  and it must stop citing §2.2 as having priced this in); §2.1's "generalizes
  without change" (false for a tool whose CLI takes secrets only in argv); §2.2
  (add the host process table to what the exposure includes); §2.3 (the
  Kerberos derivative, §7.4).
* This is the only option that needs no code. It is also the only one that
  leaves §2.1's principle knowingly unmet for this tool; whether that is
  acceptable is a threat-model call (single-tenant host with no process
  telemetry vs. shared host or one with `execve` auditing), which this document
  cannot make for you.

### 7.6 Option (iv) — newly found: the tool's own password prompt, fed from stdin

Not in the three the brief listed; found while checking what the tool's CLI
offers. With `-u <user>` and no password, `main()` calls `getpass.getpass()`,
which in a container with no TTY falls back to reading stdin. `DockerSandbox.run`
already has a stdin channel (D34, for `web.post`).

**What was verified (D50).** Real image, real `DockerSandbox.run(stdin=…)`: the
tool passes the prompt and reaches its DNS stage. Fidelity of `getpass` on that
channel, secret + `\n` sent: plain, spaces, shell metacharacters, leading `-`,
unicode, trailing spaces and empty are **intact**; a trailing newline is
stripped; **an embedded newline is silently truncated** (`ab\ncd` → `ab`) —
worse than today, where it survives. The prompt and a `GetPassWarning` land on
stderr and therefore in the evidence excerpt (no secret in them).

**Consequences.**
* It is the **only** option that removes *both* the argv exposure and the host
  file: the secret would exist only in the control plane's memory, the Docker
  attach socket and the tool's memory. Nothing in `docker top`, `ps`,
  `docker inspect`, `/tmp` or the audit payload.
* It **runs into D44's own written contract.** `vault.material_for`'s
  docstring says never to pass its result to `DockerSandbox.run`, and
  `mount_for_run` refuses any type but `ad_domain_bind` precisely so a
  control-plane-only secret never reaches a sandbox (§4.3). Feeding stdin
  needs a third delivery mode (say `stdin_for_run`) or an amendment of that
  contract, and it means the plaintext transits `dispatch_collection`'s memory,
  which today it never does (only a path does).
* **Password mode only.** There is no prompt for `--hashes`; that mode would
  still need argv or a launcher. Two mechanisms instead of one.
* The truncation above needs a guard (refuse a secret containing `\n` at
  store time) or it is a silent-corruption risk.

### 7.7 Side by side

| | (i) launcher | (ii) ccache | (iii) accept + correct | (iv) stdin / getpass |
|---|---|---|---|---|
| Secret out of host `ps` / `docker top` | yes | yes (never in the tool container) | no | yes |
| Secret out of the host `0644` file | no | no (ccache is a file too) | no | **yes** |
| Password mode / hashes mode | both | password → TGT; hashes → `-aesKey`/ticket, untested | both | password only |
| Changes a D44 contract | no | §2.3 sentence; new delivery type | text only | `material_for`'s "never to `sandbox.run`"; third delivery mode |
| Platform code in the tool's process | **yes, resident** | none (a separate minting step) | none | none |
| Code / design size | small | large, needs a second component | none | medium |
| Blocked by anything deferred | no | **F4** | no | no |
| Verified in D50 | equivalence, probe | source reading only | n/a | fidelity, probe |

### 7.8 The second question: where do secret shape and bind identity live?

Independent of §§7.3–7.6, and the one D50 left "D44-level" (F3 items 2 and 3):
`--hashes` needs exactly `LM:NT` (anything else crashes the tool before any DNS,
verified), and nothing binds a stored secret to the *kind* of secret it is or to
the account it belongs to.

**This was a decision, not an oversight.** `store_credential`'s docstring says
the secret is "the one thing this Vault ever encrypts"; the username and the
password-vs-hashes choice are non-secret constraints the proposal supplies,
so that the table's shape stays identical across credential types (§4.3).
Changing it reverses that. The three placements:

| Placement | Mechanism | Cost | Catches |
|---|---|---|---|
| **Adapter** (`build_plan`) | — | — | **nothing**: it never sees the secret, by design |
| **Mount time** (`mount_for_run`) | validate shape just before the file is written; refuse with a named audit event | none to the schema; one more failure mode at dispatch | wrong shape, at the last moment, per run |
| **Store time** (`store_credential`) | validate at write; optionally also store `auth_mode` (and `username`) inside the encrypted JSON | **no migration** — `encrypted_material` is already an encrypted JSON object holding `{"secret": …}`; reverses the "secret only" decision | wrong shape once, at the source; and, if username is stored, ends the Worker-supplied pairing (today a Worker can pair a stored password with any `domain_username` or with `hashes`) |

Store-time-with-binding is the strongest and the only one that changes what the
record *means*; mount-time is the cheapest and keeps §4.3 intact. Either way the
adapter's `domain_username`/`auth_mode` constraints would become redundant or
required-to-match.

### 7.9 Decisions this needs (nothing here is decided)

| # | Decision | Options | Lean — explicitly *not* a decision |
|---|---|---|---|
| **D50-A** | How to treat the argv exposure | (i), (ii), (iii), (iv), or a combination | (i) closes the observers §7.1 lists for both modes with the smallest design change and no contract broken, but leaves the `0644` file, so it only *helps* if the deployment's threat model cares about `ps`/`docker top`/`execve` telemetry but not about local file reads; (iv) is the only one that closes both, at the cost of a contract change and password-only coverage. If the threat model is single-tenant with no process telemetry, (iii) is defensible. This is a threat-model question the code cannot answer |
| **D50-B** | Whether to touch the `0644` file at all | leave / `chown` to uid 10002 when the control plane can / drop it via (iv) | leave, unless D50-A picks (iv) |
| **D50-C** | Where shape/identity binding lives (§7.8) | mount-time / store-time / store-time + bound username | mount-time now (no schema or §4.3 change), store-time-with-binding recorded as the stronger follow-up |
| **D50-D** | Ordering with F4 | (ii) only after F4 | (ii) is not a candidate until F4 is designed |

### 7.10 What this addendum does not do

No code, test, schema or Rego change. The three experiments in §7.3/§7.6 ran in
throwaway containers against `cyberorch/bloodhound:local`; the launcher was
never put in the dispatch path and no stdin secret was ever stored by the
Vault (the probes used synthetic values). Not tested against a real domain
controller: any of (i)–(iv) authenticating successfully (F5 — no authentication
has succeeded anywhere in this project, so the delivery is proven up to the
tool's argument parser and no further); §7.4's Kerberos behaviour; the
`multiprocessing` workers under a launcher; whether the deployment host runs
process-command-line telemetry (§7.1's risk).

### 7.11 Disposition (D50 decisions)

| # | Decision | Outcome |
|---|---|---|
| **D50-A** | How to treat the argv exposure | **No option adopted.** Each has a defect the owner will not take on as a cost (launcher: first platform code resident in the tool's process, and it closes only argv; ccache: bound to F4 and contradicts §2.3; stdin/getpass: breaks `material_for`'s contract and silently truncates a secret containing a newline; accept-and-correct: not adopted as a standing position). Recorded as **ACCEPTANCE 5.26**, to be re-evaluated when a real deployment threat model — e.g. whether hosts carry `execve` auditing or EDR — exists. That is an honest statement that there is not yet enough information to say which cost is worth paying, not a deferral of a known answer |
| **D50-B** | Where secret shape and bind identity live (§7.8) | **Store-time, with the identity bound into `encrypted_material`.** Implemented; see §8 |
| **D50-C** | The `0644` file | **Folded into D50-A / 5.26**, not tracked separately: the same decision space |
| **D50-D** | Ordering with F4 | F1, F3 and D50-B first; task #42/#44/#45 are then assessed **without** waiting for D50-A, because whether a credential can complete an LDAP/NTLM authentication and how visible it is on the host do not block each other. (§7.4's finding stands: the Kerberos option cannot be evaluated before F4.) |

One thing was corrected without deciding anything: the `ad_collector.py`
docstring's statements that the exposure was container-only and momentary, and
that §2.2 priced it in (§7.1), are now accurate. Correcting a false sentence is
not the same as accepting what it described.

---

## 8. Revision (D50-B) — an `ad_domain_bind` credential is one indivisible unit

**Status: implemented at D50-B.** This is a revision of a decision, not a new
feature, and the original decision is stated here as it was.

### 8.1 What is being revised

Until D50-B `store_credential` encrypted **only the secret**. The account name
and the choice between a password and an NT hash were "non-secret capability
constraints" a proposal supplied at run time. That was a deliberate trade-off
made at D44 implementation: it kept `credential_material`'s shape identical
across credential types.

**Where it was recorded, stated honestly:** in `store_credential`'s docstring,
not in this ADR. §1 (including §1.2's choice of an encrypted column) says
nothing about what the encrypted object holds, and the docstring's citation of
§4.3 for the "identical table shape" property does not survive a reading of
§4.3, which is about the two *delivery* modes. So this revises an
implementation-time decision, whose stated rationale leaned on this document
for a sentence it does not contain.

### 8.2 Why it is being revised

The separation was cheap and it was not free. D50 found what it let happen:

* A credential could exist with **no bind identity**. A capability that carried a
  `credential_id` but named no `domain_username` was **silently run
  uncredentialed** — the credential it was issued with ignored — against a tool
  that has no credential-free mode, so the run could only fail. (This was the
  visible symptom of D50 F1.)
* A **Worker-supplied** `domain_username` / `auth_mode` could be paired with any
  stored secret: a stored password with another account's name, or with the
  other authentication mechanism. The pairing was decided by the proposal, not
  by the credential.
* Nothing validated a secret against how it would be used: `--hashes` crashes
  the real tool on anything but `LM:NT` (verified), and no layer that sees the
  secret ever checked.

All three follow from one property: the pieces that make a credential *whole*
lived in different places, so "this is one complete, indivisible credential" was
true only as long as every caller remembered to pass all of it. The revision
puts the account, the auth mode and the secret in the **same encrypted object**,
so that property is guaranteed by the data model, not by caller discipline.

### 8.3 What changed

* `store_credential(…, username=…, auth_mode=…)`: **required** for
  `ad_domain_bind`, refused for `git_token` (whose identity is a repository URL,
  a scope object). Validated at write, where the secret is visible: `auth_mode`
  ∈ {`password`, `hashes`} (pinned equal to the adapter's vocabulary by a test);
  a `hashes` secret must be exactly `LM:NT`; a NUL byte in the username or
  secret, or a secret ending in a newline (which `$(cat …)` would silently strip,
  so the tool would receive a *different* secret than the one stored), is
  refused. Refusals never echo the secret and happen before either `INSERT`.
* `vault.identity_for(conn, credential_id)` returns the non-secret half
  (`username`, `auth_mode`) and never the secret, so the dispatch function learns
  *whose* account a run will use without holding the secret — §4.3's asymmetry
  (`material_for` never to a sandbox; a sandbox secret only as a mounted file) is
  untouched.
* `dispatch_collection` takes the identity from the credential. A capability's
  `domain_username` / `auth_mode` are kept only as **assertions that must match**;
  a mismatch is refused as `UNBUILDABLE_PLAN` before anything is minted or run.
  A capability with no `credential_id` is refused (D50 F1).
* `credential.stored`'s audit payload now also carries `username` and
  `auth_mode` (identity, not secret; the secret bytes remain pinned absent).
* **No migration.** `encrypted_material` was already an encrypted JSON object
  holding `{"secret": …}`; it now holds `{"secret", "username", "auth_mode"}` for
  this type.

### 8.4 Existing data

Checked before implementing, as D16/D30 ask. The only database available to this
work is the development database this branch's tests and live runs use, and it
held **357** `credential_material` rows (surveyed as the database superuser,
because RLS scopes every ordinary role to one engagement — a first survey
through `credential_admin_scope` returned 0, an artifact of asking as a
nonexistent engagement, not a fact): **305 `ad_domain_bind`** — 278 holding only
`{"secret"}` and 27 that cannot be decrypted with the current `VAULT_MASTER_KEY`
(the key in `.env` was regenerated at some point; rotating it makes older rows
unreadable, as `_fernet`'s docstring already warns) — and **52 `git_token`**,
which this revision does not touch. Every row belongs to this branch's own
`ENG-TEST` (test suite), `ENG-D45` (the live runs against a Samba test domain)
or `ENG-D50` (the probes) engagements; **none is deployment or customer data.**
Nothing was modified, backfilled or deleted. The rule, following D30 / D11-7 —
*an honest absence is safer than a plausible reconstruction*:

* **No backfill.** A credential stored before D50-B holds only a secret. The
  account it belongs to cannot be recovered from the secret; inferring `hashes`
  from a hash-shaped string would be a guess and inferring a username is
  impossible. A reconstruction written into a credential record is worse than a
  gap.
* **Absence means *unknown*, never "no identity needed".** `identity_for` and
  `mount_for_run` refuse such a credential with a named reason
  (`predates identity binding`), and `dispatch_collection` therefore refuses any
  capability that carries one — fail-closed, before anything is minted. The
  operator's remedy is the one `store_credential` already documents: rotation is a
  new `credential_id`, and the old one is revoked through the existing cascade.
  There is no update path, and this adds none.

### 8.5 What this does not change

The secret still reaches the tool's argv and the `0644` file (§7, ACCEPTANCE
5.26 — deliberately not addressed here). This revision is about *what a
credential is*, not about how it is delivered.

