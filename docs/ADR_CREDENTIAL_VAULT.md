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
