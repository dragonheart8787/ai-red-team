# D45 — AD Collection end-to-end verification: is the D42/D44 wiring real?

D37's lesson was that "the wiring is in place" and "the wiring actually
works" are different claims, and only an end-to-end run distinguishes them —
`execution_constraints` silently dropping `port`/`path`/`scheme` was invisible
to every hand-wired D31–D36 test and only surfaced once `web.render` was
driven the whole way through `propose_action`. D42 (`ad_domain` scope
authorization) and D44 (Credential Vault `mount_for_run`) each shipped with
green suites, and every one of those suites called `dispatch_collection`
directly. Nothing had ever driven an `ad.collect` proposal through
`propose_action` — the one real production entry point — at all.

**Headline: driving it for real found four real bugs in the wiring itself,
and two structural findings about what the real sandbox and the real
transaction model actually do — one of which means `ad.collect` cannot
complete real domain discovery in *any* environment as currently built, not
only against this deliverable's test target.** None of the six is a security
authorization failure — nothing was ever allowed that should have been
denied — but two of the four bugs would have meant a real `ad.collect`
capability silently ran the wrong container image or never reached the
Security Graph at all, in production, today, had this deliverable not driven
the real path.

---

## 1. Setup

| | |
|---|---|
| Target | Real Samba AD DC (`nowsci/samba-domain`), domain `d45test.local`, container `d45-samba-dc` |
| Why Samba | The only lightweight, non-Windows environment found that gives `bloodhound-python` a genuine LDAP/Kerberos endpoint — see §2 for what this rules in and out |
| Image | `cyberorch/bloodhound:local`, built for the first time this deliverable (`tool_gateway/images/bloodhound.Dockerfile` + `build_bloodhound_image.sh`, new files) |
| Network | `cyberorch-allow-a4d57259082b` (`10.85.0.0/24`, `internal=True`), the same deterministic name `DockerSandbox.ensure_network` would create for this allowlist |
| Domain account | `collector`, a plain low-privilege domain user created for this test — never `Domain Admins` |
| Engagement | `create_engagement()` (D11-9/D39) — not a raw INSERT |
| Scope | `ad_domain d45test.local` -> `ad.collect` only (D42-1 Option C) |
| Credential | Real Vault-stored `ad_domain_bind` credential (`store_credential`/`mount_for_run`, D44) |
| Harness | `scripts/live_run/d45_ad_collection_e2e.py` (new) |

The harness drives the real chain: `create_engagement` -> `register_scope_object`
-> an engagement-scoped policy layer ALLOWing `ad.collect` ->
`credential_admin_scope`/`store_credential` -> a scripted `ProposedAction`
(`HonestFakeReviewer`, since this deliverable verifies the *mechanism*, not
an LLM's judgment) -> `function_api.propose_action` -> Authorization
Resolver -> OPA -> Capability Broker -> `dispatch_collection` -> a real
`cyberorch/bloodhound:local` container against the real Samba DC -> the real
audit trail.

---

## 2. What the environment investigation found, up front

Before any wiring could be tested, the brief's own precondition had to be
answered: is there a lightweight way to get a real LDAP endpoint at all?

**Yes — `nowsci/samba-domain` works, is real (a genuine `samba-tool
domain provision` domain controller with real LDAP/Kerberos/SMB/DNS), and
needed no Windows host.** `bloodhound-python` genuinely reaches it: real DNS
queries, real TCP connections, real Kerberos/NTLM exchanges. But **real
authenticated collection could not be completed against it**, for reasons
that turned out to run one layer deeper than expected — see §4 and §5.
Every one of these reasons is either a documented upstream client-library
limitation or a gap in this project's own sandbox, confirmed by reading
source and reproducing the failure directly, not assumed from a single
stack trace or worked around with a mock standing in for the real thing.

Per the brief's own instruction, this is reported as a hard limit rather
than quietly relaxed: **there is no way, with the environment available
here, to get bloodhound-python to complete a real authenticated collection
and produce real Security Graph data.** §7 below asks explicitly what to do
about the three verification items that depend on real collected data.

---

## 3. Four real bugs, found only by driving the real entry point

Every one of these was invisible to D42's and D44's own test suites because
those suites called `dispatch_collection` directly. `StubSandbox` records
`plan.command` without executing it, and nothing before D45 ever called
`propose_action` for `ad.collect` at all — exactly D37's own lesson,
recurring in a different function.

**1. `ad_collector.py` hardcoded the wrong binary path.** `build_plan` used
`/usr/bin/bloodhound-python`; the real `pip install bloodhound` location is
`/usr/local/bin/bloodhound-python`. Found by querying the real, newly-built
image directly. Fixed: a `BLOODHOUND_PYTHON_PATH` constant, used everywhere
the path was previously hardcoded, plus the one test asserting the exact
command tuple.

**2. `propose_action` never routed `ad.collect` or `code.scan` to their own
dispatch functions.** `dispatch_collection` and `dispatch_code_scan` were
never even imported into `control_plane/api/function_api.py`; step 7
unconditionally called `dispatch_scan`. In production, this meant a real
`ad.collect` capability issued through `propose_action` would run
bloodhound-python but never call `record_batch` — the Security Graph write
D42's entire design exists for would simply never happen — and a real
`code.scan` capability would never call `fetch_repo`, so its container would
start with nothing mounted at `CONTAINER_REPO_PATH` and fail immediately.
This bug has existed since D42/D43 shipped. Fixed: a new `_dispatch_for_action`
routing helper in `function_api.py`, plus the missing imports.

**3. `execution_constraints` dropped every `ad.collect`/`code.scan`-specific
field.** The D30 single derivation shared by `propose_action`'s ALLOW path
and `grant_approval`'s human-approval path only ever produced nmap/web-shaped
constraints (`host`/`ports`/`scan_type`/`port`/`path`/`scheme`). A proposal
naming `domain_username` had it silently dropped before the capability was
even issued — so a credentialed `ad.collect` capability issued through
`propose_action` could never reach `ad_collector.build_plan`'s credentialed
branch, regardless of whether `issue_capability` was given a `credential_id`.
This is a direct structural recurrence of the exact defect class D30 was
built to prevent ("two derivations of one fact, disagreeing exactly when a
human was in the loop") — except here it was one derivation with an
incomplete set of fields, not two derivations. Fixed: four new conditional
pass-through fields (`collection_methods`, `domain_username`, `auth_mode`,
`exclude_paths`), matching the existing `port`/`path`/`scheme` pattern
exactly. `approvals.approval_fields` calls `execution_constraints` directly
rather than re-deriving it, so it picked up the fix automatically — confirmed
by reading the call site, not assumed.

**4. `dispatch_collection` never looked up `adapter.IMAGE`.** `dispatch_scan`
and `dispatch_code_scan` both do `getattr(adapter, "IMAGE", None)` and fall
back to `DockerSandbox`'s shared default only when the adapter names none —
`semgrep.py` sets `IMAGE = "cyberorch/semgrep:local"` for exactly this reason.
`ad_collector.py` had no `IMAGE` constant at all, and `dispatch_collection`
never looked one up — so a caller of `propose_action`/`dispatch_collection`
that did not hand-pick a sandbox got `DockerSandbox`'s `DEFAULT_IMAGE`
(`cyberorch/nmap:local`), a container with no bloodhound-python binary in it
whatsoever. Fixed: `IMAGE = "cyberorch/bloodhound:local"` added to
`ad_collector.py`, and `dispatch_collection`'s sandbox-selection line
rewritten to match `dispatch_scan`'s own `adapter_image = getattr(...)`
pattern exactly.

All four fixes are covered by the existing fixture suites (909 tests,
unchanged pass count) plus this deliverable's own live run. None required
touching OPA policy, RLS, or any authorization decision — every wrong
behavior was downstream of an ALLOW that was already correct.

---

## 4. The real chain, traced end to end

One proposal from a live run of `scripts/live_run/d45_ad_collection_e2e.py`,
read back the same way D40's report reads its own chain:

```
proposal.submitted        actor=d45-scripted-worker
policy_reviewer.opinion   actor=honest-fake-reviewer
policy.decided            ALLOW
capability.issued         subject=CAP-c6928c99cc
tool_run.started          subject=RUN-af380303d537
credential.issued_to_run  subject=RUN-af380303d537
tool_run.failed           subject=RUN-af380303d537
```

Every stage present, nothing missing, once all four bugs above were fixed.
The real command bloodhound-python actually executed, taken from the real
`tool_run.started` audit payload:

```
/bin/sh -c 'exec /usr/local/bin/bloodhound-python -d "$1" -u "$2" "$3" "$(cat "$4")" -c "$5" --zip' \
    sh d45test.local collector -p /creds/secret Group,ACL
```

Confirmed directly against this real run:

* The fixed binary path (`/usr/local/bin/bloodhound-python`) is what
  actually executed.
* The real domain name (`d45test.local`) is what was actually passed.
* The plaintext secret never appears in the command the control plane
  recorded — only `/creds/secret`, the fixed container-side mount point.
* `credential.stored` and `credential.issued_to_run` are both in the
  credential's own audit trail.
* `tool_runs.execution_context` carries this run's real `credential_id`.
* The credential mount file was created and removed by
  `dispatch_collection`'s own `finally` block (already covered by D44's
  cleanup tests; nothing new to add here beyond confirming it fires on a
  real container, not a stub).

The run's own outcome is `FAILED` — expected, and explained precisely in §5,
not glossed over as an unexplained red result.

---

## 5. Why authentication cannot complete — two layers, not one

The module docstring in `tool_gateway/adapters/ad_collector.py` has the full
technical detail; this is the summary.

**Layer 1 — DNS, and this is the one that actually blocks the real path.**
`bloodhound-python`'s first act is an SRV lookup,
`_ldap._tcp.pdc._msdcs.<domain>` — the AD domain-controller locator record,
answerable only by the domain's own DNS server (in practice, the DC itself).
`DockerSandbox.run` passes no `dns` argument to `containers.create`, so the
container gets Docker's own embedded resolver (127.0.0.11), which returns
`SERVFAIL` for that record. Confirmed structural, not a Samba quirk:
querying the identical record directly against the DC's own DNS
(`--dns <dc-ip>`, bypassing `DockerSandbox` entirely) answers correctly — the
record exists and is correct; the sandboxed container simply has no route to
ask for it. **This is not specific to Samba or to this test's target.** A
real customer engagement's `ad.collect` container runs on the identical kind
of internal, gateway-less network, and a real Windows AD domain's locator
records are resolvable only through that domain's own DNS — the identical
`SERVFAIL` would occur against a genuine production target. This is recorded
as `ACCEPTANCE_MVP1_AGENTS.md` **5.25**.

**Layer 2 — LDAP/Kerberos, reachable only if Layer 1 is ever closed.** A raw,
out-of-band container run (bypassing `DockerSandbox`, `--dns` pointed
directly at the DC) does reach the LDAP/Kerberos boundary, and fails there
for two independent, verified reasons that are properties of the client
libraries against Samba's specific server implementation:

1. `ldap3`'s NTLM bind uses the legacy Microsoft "Sicily" LDAP extension.
   Samba's AD DC does not implement it and closes the connection on sight —
   confirmed via `ldap3`'s own extended debug logging, showing the exact
   Sicily discovery request sent and the immediate, zero-byte connection
   close that follows.
2. `impacket`'s Kerberos TGS-REQ (`impacket/krb5/kerberosv5.py`,
   `getKerberosTGS`) never sets the Authenticator's optional `cksum` field.
   Real Microsoft AD KDCs tolerate the omission; Samba's own, stricter KDC
   rejects it with `KRB_AP_ERR_INAPP_CKSUM`. Confirmed by reading the
   library source directly and by reproducing the identical failure both
   with a cleartext password and with a computed NTLM hash (ruling out an
   RC4-vs-AES explanation).

Neither is fixable from this project's side. **Real authenticated collection
against a genuine Windows AD domain remains unverified through any path** —
Layer 1 blocks the real sandbox path before authentication is ever
attempted, and Layer 2 is what an operator would hit next, against this
specific test target, if Layer 1 were ever closed.

---

## 6. Credential revocation, mid-flight — a sharper finding than D44-7 stated

D44-7 (`ACCEPTANCE_MVP1_AGENTS.md` 5.24) documented that a revoked credential
does not stop an in-flight container — the container runs until
`max_duration_seconds` or its own completion. D45 triggered a real
`revoke_credential()` call while a real `dispatch_collection` run was
genuinely in flight (confirmed by wall-clock timing across a background
thread: the revoke call landed at t=0.50s, the dispatch returned at t=1.25s)
and found the actual mechanism is sharper than that framing:

**The revoke call is not merely too slow — it is a complete no-op against
that specific run.** `engagement_scope` wraps `engine.begin()`, and
`propose_action` runs its entire pipeline — OPA, `issue_capability`, and the
fully synchronous, blocking `sandbox.run()` — inside that one transaction.
Postgres's read-committed isolation means the capability row a concurrent
`revoke_credential` call needs to see and flip does not exist to any other
connection until that transaction commits, which happens only once the
container has already finished. The live run's own numbers show this
directly: `revoke_credential`, called mid-flight, returned zero revoked
capabilities, and the capability row read immediately afterward showed
`revoked: False` — even though the run it authorized was, by then, already
complete. The control the harness ran to rule out "`revoke_credential` is
just broken": the identical call, against the identical `credential_id`,
issued again after the pipeline's transaction commits, succeeds immediately
(`revoked_capabilities` names the capability; the row flips to
`revoked: True`).

This does not change D44-7's conclusion (accept the exposure window,
documented explicitly, D44-7 Option A) — it sharpens the mechanism.
Recorded as an addendum to `ACCEPTANCE_MVP1_AGENTS.md` **5.24** rather than a
new item, since it is the same exposure, more precisely characterized, not a
new one.

---

## 7. What could not be verified, and the decision this needs

The brief named three verification items that all depend on a successful
real collection producing real Security Graph data:

* Querying real collected data with `shortest_path` (D42-6's interface),
  confirming the query logic against real-shaped data rather than only the
  synthetic benchmark fixtures D42-2/D42-6 used.
* Re-running the I8 adversarial test (a fabricated high-privilege edge)
  against data a real collection actually produced, rather than only
  hand-built fixture rows.
* The bloodhound-python output translator `parse_graph` currently expects
  this adapter's own placeholder JSON shape (documented in its own
  docstring) rather than bloodhound-python's real, native `--zip`
  per-object-type output — untestable without a real collection to translate.

**None of these could be attempted, because §5's two layers mean no real
collection against any environment available here can succeed.** Per the
brief's own explicit instruction, this is reported as the limit it is,
rather than substituting synthetic data to manufacture a green result. The
brief offered one specific fallback if this happened — verifying only that
the command assembly is correct and a real connection attempt is genuinely
made, without requiring real authentication to succeed — and §3/§4/§5 above
already deliver exactly that, to the fullest extent the environment allows.

The decision this report is asking for: how, if at all, to proceed on the
three items above. Two honest paths, neither chosen unilaterally here:

1. **Leave them blocked** until either a genuine Windows AD test environment
   becomes available, or `DockerSandbox` gains a way to route a container's
   DNS to a target-supplied nameserver (closing 5.25) *and* a non-Samba LDAP
   target is found (Layer 2 is Samba-specific; a real Windows DC would not
   hit it). This is the only path that verifies the real translator against
   real tool output.
2. **Verify `parse_graph` and the query/I8 items against realistically-shaped
   synthetic data**, explicitly labeled as such in whatever record documents
   it — closer to what D42-2/D42-6's benchmarks already did, but not a
   substitute for what real bloodhound-python output would look like, and
   not to be reported as having closed the same gap real data would close.

This report recommends neither over the other; it is the kind of call the
brief was explicit should come back to a decision, not be made silently by
lowering the bar to reach a green run.

---

## 8. Verification summary

| Check | Result |
|---|---|
| Real lightweight AD environment found | Yes — Samba AD DC (`nowsci/samba-domain`) |
| Real image built for `ad.collect` | Yes — `cyberorch/bloodhound:local` (new) |
| `-d`/`-u`/`-p`/`--hashes`/`-c`/`--zip` verified against the real binary | Yes — all confirmed; `--hashes` takes `LM:NTLM`, not a single hash |
| Real proposal driven through the real `propose_action` entry point | Yes |
| Real Authorization Resolver -> OPA -> Capability Broker -> `dispatch_collection` chain | Yes, after fixing bugs 2–4 above |
| Real container executes the real, fixed command against the real DC | Yes |
| Credential file permission model (0644) generalizes to this new image | Yes — confirmed for the non-root `collector` (uid 10002) user |
| Real command never carries the plaintext secret | Confirmed |
| Real audit trail (proposal/reviewer/policy/capability/tool_run/credential) complete | Confirmed |
| Security Graph write against real collected data | **Not reached** — no successful collection to write (§5) |
| `shortest_path`/I8 adversarial re-test against real data | **Blocked** — see §7 |
| Mid-flight `revoke_credential()`, timing and effect | Confirmed, and sharper than 5.24's original framing (§6) |
| Full local test suite | 909 passed, unchanged pass count, after all four fixes |

---

## 9. Files touched

* `tool_gateway/adapters/ad_collector.py` — `BLOODHOUND_PYTHON_PATH`,
  `IMAGE`, corrected module docstring (real flag verification, the DNS
  finding, the two auth-layer failures).
* `tests/test_ad_collector_adapter.py` — updated to assert against the
  `BLOODHOUND_PYTHON_PATH` constant rather than a hardcoded literal.
* `control_plane/api/function_api.py` — `_dispatch_for_action` routing
  helper; `propose_action` gained `credential_id`; `execution_constraints`
  gained the four `ad.collect`/`code.scan` pass-through fields.
* `control_plane/orchestrator/dispatch.py` — `dispatch_collection`'s
  sandbox-selection now looks up `adapter.IMAGE`, matching `dispatch_scan`.
* `tool_gateway/images/bloodhound.Dockerfile`,
  `tool_gateway/images/build_bloodhound_image.sh` — new, the first-ever
  `ad.collect` image.
* `scripts/live_run/d45_ad_collection_e2e.py` — new, this report's harness.
* `docs/ACCEPTANCE_MVP1_AGENTS.md` — **5.25** (new), and an addendum to
  **5.24** sharpening its mechanism.
