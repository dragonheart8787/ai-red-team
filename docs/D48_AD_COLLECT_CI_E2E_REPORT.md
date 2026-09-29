# D48 — closing D47's coverage gap: permanent propose_action E2E tests for ad.collect and code.scan

D47's merge-readiness audit found one real, previously unreported gap: zero
committed, CI-run tests called the real `propose_action` for `ad.collect` or
`code.scan` anywhere in this stage's history. This deliverable closes it —
before the merge, per the instruction not to leave it for later — with two
permanent, CI-committed test files, following `test_web_render_e2e.py`'s own
two-tier precedent (D37).

**Headline: `code.scan` got the straightforward fix — a real, permanent,
propose_action-driven test against real infrastructure that already works
reliably. `ad.collect` got a StubSandbox-tier test only, by design: real
Samba-in-CI was investigated and rejected, not silently skipped, for two
independent reasons — a real Docker Hub reliability risk (confirmed
empirically, not assumed) on top of D45's own already-established fact that
real authentication cannot succeed against Samba regardless of setup time.
Both new files mutation-verify against all four of D45's original bugs to
the extent each bug applies to that action; none is a "ran without raising"
check.**

---

## 1. `ad.collect`: why real Samba stays out of the CI push gate

### 1.1 The setup-time question, investigated directly

Timing a genuine cold pull of `nowsci/samba-domain` (removing the locally
cached image first, to match a fresh CI runner) produced this on the first
attempt:

```
$ docker pull nowsci/samba-domain:latest
Error response from daemon: unknown: failed to resolve reference
"docker.io/nowsci/samba-domain/manifests/latest": 429 Too Many Requests
```

Reproduced identically on a second attempt five seconds later. **This is a
distinct, additional risk from the pure time-cost question the brief
raised**: `nowsci/samba-domain` is a third-party, unauthenticated Docker Hub
pull, subject to Docker Hub's anonymous rate limiting. GitHub Actions
runners share IP ranges across an enormous number of concurrent jobs and are
a well-documented target for exactly this kind of rate limit — unlike every
other image this project's CI already builds (`nmap`, `web-target`,
`egress-proxy`, `browser`, `semgrep`), which are either built from `apt`
packages installed directly on the runner or from Dockerfiles based on
high-traffic, heavily-cached base images (`python:3.12-slim`), not pulled
whole from a low-traffic community repository. Putting `nowsci/samba-domain`
in the per-push gate would mean **every single push carries a chance of a
red CI run for a reason that has nothing to do with the code being
tested** — exactly the kind of noise this project's own CI discipline
(`test.yml`'s "Assert nothing was skipped" step, the standing refusal to
treat a flaky red as acceptable background noise) has consistently guarded
against.

### 1.2 Even without the pull risk, the outcome is already known and static

D45 already established, independently and twice over, that
`bloodhound-python`'s own authentication (Kerberos and NTLM alike) cannot
succeed against Samba's AD DC implementation — `ldap3`'s Sicily-only NTLM
bind, and `impacket`'s Kerberos TGS-REQ never setting the Authenticator
checksum, both confirmed by reading the library source, not by observing one
stack trace. **Neither fact will change from one CI run to the next.** A
real-Samba job, even a reliable one, could never reach the successful-
collection path — it would spend real time (domain provisioning on top of
whatever the pull costs) on every single run to re-confirm a static,
already-fully-documented external-library limitation, not to catch a
regression in this project's own code.

### 1.3 Recommendation

**Do not add real Samba to the CI push gate.** Given §1.2, a periodic
(scheduled, not per-push) job is also not recommended as a strong default —
its expected information gain is low (nothing here changes on a schedule
unless `ldap3`/`impacket`/Samba's own versions drift, which a much less
frequent, manually-triggered check could catch just as well). This matches
the project's own existing precedent of not putting a real-model evaluation
into the automated CI gate (`docs/ACCEPTANCE_MVP1_AGENTS.md`'s treatment of
LLM-backed reviewer runs). `scripts/live_run/d45_ad_collection_e2e.py`
remains the record of the real, non-CI verification and is not superseded
by anything in this deliverable — it is the thing a future, deliberate
re-check (if `ldap3`/`impacket` ever fix these bugs) would re-run.

---

## 2. `tests/test_ad_collection_e2e.py` — what it actually verifies

A `StubSandbox`, but the *class*, not an instance the test hands in.
`dispatch_collection` constructs `DockerSandbox` itself
(`DockerSandbox(image=adapter_image) if adapter_image else DockerSandbox()`)
whenever `propose_action` is called with `sandbox=None` — patching the class
(`monkeypatch.setattr(dispatch_module, "DockerSandbox", _RecordingDockerSandbox)`)
rather than pre-selecting an instance is what lets this test observe *which
image `dispatch_collection` chose on its own*, closing a subtlety D45's own
live-run script actually missed: that script constructed
`DockerSandbox(image=ad_collector.IMAGE)` itself and handed it in directly,
which means D45's own real run never actually exercised the specific
internal fallback line its own fourth bug fix lives in. This file does.

Two tests (credentialed and uncredentialed), each driving the real
`propose_action` -> Authorization Resolver -> OPA -> Capability Broker ->
real `dispatch_collection`, with explicit, mutation-verified assertions for
every one of D45's four bugs:

> **Status, as of D50:** the "uncredentialed" test described here asserted that
> a capability with no `domain_username` ran and wrote three graph nodes. That
> held only because the recording sandbox never executed the command; the real
> bloodhound-python has no credential-free mode (`docs/D50_AD_COLLECTOR_AUTH_GAP_
> INVESTIGATION.md` F1). The test now asserts the opposite -- `propose_action`
> authorizes the proposal and `dispatch_collection` refuses it as
> `UNBUILDABLE_PLAN` before any container is constructed
> (`test_ad_collect_without_a_credential_is_refused_by_dispatch_collection`).
> The four-bug table below concerns the credentialed test and is unchanged.

| Bug (D45) | Assertion | Mutation-verified |
|---|---|---|
| 1. Wrong binary path | `ad_collector.BLOODHOUND_PYTHON_PATH in rendered_command` and the old path is absent | Reverting the constant to `/usr/bin/bloodhound-python` fails the test with the exact wrong string quoted in the diff |
| 2. No `propose_action` routing | Real `security_graph_nodes`/`security_graph_edges` rows exist, matching the stub's fixture counts (`dispatch_scan` cannot write these) | Reverting `_dispatch_for_action` to always call `dispatch_scan` fails with `node_count == 0` — the image and command still looked right (`dispatch_scan` does its own correct `adapter.IMAGE` lookup independently), it is specifically the Security Graph write that exposes the misroute |
| 3. `execution_constraints` dropping fields | `capabilities.constraints` carries `domain_username`/`auth_mode`/`collection_methods` | Reverting the four conditional pass-throughs fails with `KeyError: 'domain_username'` |
| 4. Missing `adapter.IMAGE` lookup | The internally-constructed sandbox's own `.image` equals `ad_collector.IMAGE` | Reverting `dispatch_collection`'s sandbox-selection line to `DockerSandbox()` fails with `None == 'cyberorch/bloodhound:local'` |

Each mutation was applied, confirmed red, and reverted before commit — the
same discipline `tests/test_dispatch_routing.py` (D46) and
`tests/test_graph_queries_structure.py` (D42-6) already established for
this project's structural tests.

---

## 3. `tests/test_code_scan_e2e.py` — what it actually verifies

No stub tier needed: Semgrep against a real git-over-HTTP repository already
works reliably (`tests/test_dispatch_code_scan.py`'s own real-container
suite), so this file drives the real `propose_action` against the real
`cyberorch/semgrep:local` container and the real, in-process `git
http-backend` fixture `tests/test_git_fetch_credential.py` already built
(pure Python, no Docker, no third-party pull — reused directly, confirmed
reusable exactly as the brief asked, not re-implemented).

Two of D45's four bugs apply to `code.scan` at all (the wrong-binary-path
and missing-`IMAGE`-lookup bugs were `ad_collector`/`dispatch_collection`-
specific and never existed for `semgrep`/`dispatch_code_scan` — confirmed in
D46's own audit). Both applicable ones are asserted and mutation-verified:

| Bug (D45) | Assertion | Mutation-verified |
|---|---|---|
| 2. No `propose_action` routing | `tool_runs.execution_context` carries a real `commit_sha` and the real `credential_id` — both populated only by `dispatch_code_scan`'s own `fetch_repo` call, never by `dispatch_scan` | Reverting `_dispatch_for_action` to always call `dispatch_scan` fails both tests with `KeyError: 'commit_sha'` |
| 3. `execution_constraints` dropping `exclude_paths` | `capabilities.constraints["exclude_paths"]` matches what was proposed, and the real Semgrep command recorded in `tool_run.started`'s own audit payload actually carries `--exclude vendor/`/`--exclude node_modules/` | Reverting the `exclude_paths` pass-through fails with `KeyError: 'exclude_paths'` |

The credentialed test additionally proves the full private-repo chain for
real: a real Vault-stored `git_token`, a real Basic-Auth-gated clone, a real
Semgrep run against the cloned tree, and a genuinely successful
`tool_runs.status == "succeeded"` outcome — not merely that the pipeline
didn't raise.

---

## 4. Verification summary

| Check | Result |
|---|---|
| Real Samba-in-CI feasibility investigated | Yes — rejected, with concrete evidence (§1), not silently skipped |
| `ad.collect` propose_action test, permanent, CI-committed | `tests/test_ad_collection_e2e.py`, 2 tests |
| `code.scan` propose_action test, permanent, CI-committed, real infrastructure | `tests/test_code_scan_e2e.py`, 2 tests |
| All four D45 bugs covered by explicit assertions, to the extent each applies | Yes — table in §2/§3 |
| Every assertion mutation-verified (not just "ran without raising") | Yes — each bug's fix reverted, confirmed red, restored |
| `private_git_server` infrastructure reused, not reimplemented | Yes |
| Full local test suite | 928 passed (924 + 4 new) |
| OPA tests | 44/44, unchanged |
| `opa fmt` | clean |

D47's own gap (§1 of `docs/D47_MERGE_READINESS_AUDIT.md`) is closed.
