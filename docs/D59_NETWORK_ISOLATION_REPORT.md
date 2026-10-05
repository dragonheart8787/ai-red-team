# D59 — two engagements, one range, one Docker network (I4 at the network layer)

D58's investigation observed, in passing, that two engagements authorizing the same CIDR were handed
the same Docker bridge and a container of one could ping a container of the other. This deliverable
treats that as the security gap it is: finds the rule that causes it, measures how far it reaches
(it is **not** ping-only), fixes it, and puts a regression suite under it whose verdicts come from
witnesses other than the component under test.

**Headline.**

* **Root cause:** `DockerSandbox.network_name()` hashes the *allowlist alone*, and `ensure_network()`
  is get-or-create on that name. The network is therefore a property of the CIDR, not of the
  engagement. This was a documented design choice (the module docstring says the network is
  "provisioned once and each run attaches to it") that was right for the *assets* on the network and
  wrong for the *tenants*.
* **Reach:** ICMP **and TCP and HTTP**. Measured from a second engagement's tool container on the
  unfixed code: ICMP reply, TCP connect to a port the first engagement's container listened on, and —
  the worst — **an HTTP request through the first engagement's egress proxy to a host only the first
  engagement's grant allowed, served by the target** (the target's own access log shows it). The
  proxy spends *its capability's* grant for any container that can reach it, so a shared tool-side
  network was an authorization bypass, not only a reachability finding. A second, wider instance was
  found on the way: **every engagement's code scans (`code.scan`, `code.secrets`) ran on one fixed
  `/29` for all engagements, by construction rather than by CIDR coincidence.**
* **Fix:** two engagements are never live on one network at once; actions that need no network join
  none. Not "a private network per engagement", which Docker cannot give (§4.1).
* **Exposure window:** the shared-network design dates to D6 (2026-08-18): **48 days** to today for
  tool-vs-tool; the proxy path from D34 (2026-09-23), **12 days**; the code-scan instance from D43
  (2026-09-28), **7 days**. **No instance of two engagements actually live on one network at once was
  found** in the records that survive (§3) — and nothing in the project ever ran two engagements
  concurrently (no resident service exists, ACCEPTANCE 5.51 / D58) — but the property was never
  enforced, so "did not happen" rests on how the project was operated, not on the system.

---

## 1. Root cause: the rule that decides network reuse

`tool_gateway/sandbox.py`:

```python
def network_name(self, allowlist):
    digest = hashlib.sha256("|".join(sorted(allowlist)).encode()).hexdigest()[:12]
    return f"cyberorch-allow-{digest}"

def ensure_network(self, allowlist):          # get-or-create on that name
    ...
    try:    return client.networks.get(name)
    except NotFound: ...create(name=name, internal=True, ipam=<the allowlist as subnet>)
```

`run()` attaches every container to `ensure_network(allowlist)`; `start_egress_proxy()` does the same
for its tool-side and target-side networks. Neither takes an engagement. So the answer to the brief's
first question — *"one network per capability/tool_run, or does the same CIDR reuse one?"* — is:
**the same CIDR reuses one network, for every run of every engagement**, and nothing else participates
in the choice. The D6 module docstring states this on purpose ("created per run … would describe a
range containing only the scanner"); the targets of a lab live on that bridge, so a per-run network
would have nothing to scan.

Two callers made the sharing broader than "same CIDR":

* `NO_EGRESS_ALLOWLIST = ["10.255.255.0/29"]` (`dispatch.py`, D43) is one constant used by **every**
  `dispatch_code_scan`, so all engagements' Semgrep and Gitleaks containers shared one bridge —
  although those tools need no network at all.
* The proxy topology puts the tool on a *tool-side* network whose range is a constant in every harness
  (`WEB_TOOL_CIDR`, `TOOL_CIDR`), so any two engagements doing web actions share it by construction.

## 2. How far the leak reaches (measured, unfixed code)

Real containers, real `DockerSandbox`, one network (`10.60.0.0/24`), engagement A's tool container
alive, then engagement B's tool run:

| Layer | Probe | Result on unfixed code |
|---|---|---|
| ICMP | `ping` from a container on the network to A's container | **reply** |
| TCP | B's real tool run: `ncat -v <A's ip> 4444`, A listening | **connected** |
| HTTP, through A's proxy | B's tool run sends `GET http://<target>/` to A's proxy (`:3128`); the target is granted to A's capability only | **`HTTP/1.1 200 OK`**; the target's own log records `GET / HTTP/1.1 200` |

What this does and does not say, so the severity is not read in either direction:

* A tool container is a *client*; nmap, curl, the browser and bloodhound-python do not listen. The TCP
  row needed something listening, and that something is exactly what a compromised tool container
  (§8.3's threat model) or — routinely — an **egress proxy** is. The HTTP row is therefore the one
  that needs no hostile assumption beyond "B's tool can address an IP on its own network".
* The bypass is of *authorization*, not of the policy engine: B's request never went through B's OPA
  decision, B's capability or B's grant; it was served under A's. That is I4 violated at the network
  layer and I8's spirit (what authorized this request?) with it.
* I did **not** establish that a running scanner can *discover* a neighbour by scanning: an attempted
  `nmap -sT` sweep of the range reported every port `filtered` (a tool-level report, not an
  observation of the neighbour; exactly the kind of verdict D6 teaches not to trust), so discovery is
  recorded as untested, and the TCP row above used the neighbour's known address.
* For two engagements on **different** ranges the networks are different bridges and the kernel
  returns ENETUNREACH (re-verified after the fix, `test_two_engagements_on_different_ranges_…`). The
  gap is specifically *identical* ranges (Docker refuses *overlapping* ranges outright — D58
  experiment E5 — which fails closed, though it was mislabelled `unknown_outcome`; see §4.4).

## 3. Which earlier work could have been affected, and for how long

**Window.** Per mechanism, to today (2026-10-05):

| Mechanism | Introduced | Days exposed |
|---|---|---|
| tool container ↔ tool container on a shared allowlist network | D6, 2026-08-18 (`11a9942`) | 48 |
| tool container → another engagement's egress proxy / grant | D34, 2026-09-23 (`c8a9ab3`) | 12 |
| all engagements' code scans on one `/29` | D43, 2026-09-28 (`8c6eb16`) | 7 |

**Was it ever exercised?** Checked rather than assumed, in three ways, with the limits of each stated.

1. **The live-run scripts** (D11 `live_run.py`, D13, D15, D17, D40, D45, `verify_d12`, the D50 probe)
   run one engagement at a time *within* a process: none uses threads except D45's, whose thread is a
   mid-flight revocation within a single engagement. Several create more than one engagement per
   process (D17's arms, D40's `main_run` then `injection_experiment`), always one after the other. D40
   starts **one** proxy (`CAP-D40-WEB-POOL`) that only the first engagement's web tasks use; the second
   engagement is nmap-only and runs after the first has finished. Their reports name the same network
   (`cyberorch-allow-97e616…`, `10.79.0.0/24`) across *runs*. What the code cannot exclude is an
   operator running two scripts in two shells at once; only check 3 speaks to that. (Read, not re-run.)
2. **The test suite** shares `10.78.0.0/24` and a handful of other ranges across many modules and
   engagements, sequentially (no `xdist`; module-scoped proxy and target fixtures end with their
   module). Two cases *were* shaped like the leak without being a use of it: the web-render scenario's
   module-wide proxy served every test's engagement in turn, and the D40 harness's proxy was started
   before its engagement existed. Both ran one engagement at a time, and **both are exactly the shape
   the new rule refuses**, so they had to change (§4.5) — which is the clearest evidence in the
   repository that the design relied on never running two at once.
3. **The one persistent record available**, this environment's development database (audit trail from
   2026-09-23 to 2026-10-01 plus today's runs): 2018 runs with a recorded `tool_run.started`, 1999 of
   them with a recorded end, across 1817 engagements, **11 allowlists used by more than one
   engagement**, **0 pairs of different-engagement runs with overlapping lifetimes on an identical
   allowlist** (intervals taken from the independently committed `tool_run.started` and terminal audit
   events — `tool_runs.started_at/finished_at` cannot be used, both are `now()` of the *same*
   transaction and are equal). Limits: it covers this environment only and not the D6–D33 period
   (the database was rebuilt); 19 runs have no terminal event (killed) and their extent is unknown; and
   many of the runs use a fake sandbox and never had a container, so the count is an upper bound on
   exposure, not a count of real co-residence. A first version of this query reported 466 overlapping
   pairs; that was an artefact of assuming a 10-minute lifetime for the unfinished runs, and is
   mentioned because it is the kind of number that gets quoted.

**Assessment.** The shared network was *structurally* available for 48 days and, for the proxy and
code-scan cases, 12 and 7. I found **no evidence that it was used or exploited**, and the project's
mode of operation (no resident service, one engagement per process) explains why. That is a statement
about how it was operated, not about the system: nothing prevented it, nothing would have recorded it
(no audit event exists for "two engagements shared a network"), and the first component designed to run
engagements concurrently (D58's orchestrator) would have made it routine. D58 recorded it as X12 and
D58-14; this deliverable resolves both (§6).

## 4. The fix

### 4.1 What cannot be done, verified

"A separate network per engagement" is the obvious reading of the brief, and it is not available on a
Docker bridge: **Docker refuses a second network with the same subnet** — two `--internal --subnet
10.98.0.0/24` networks: `invalid pool request: Pool overlaps with other one on this address space`.
An allowlist *is* the subnet (the tool must be on the segment where the assets are, at their real
addresses), so two engagements cannot each hold a private copy of one range. Naming the network by
engagement would leave the second engagement unable to run at all, and would move every target a lab
had attached by CIDR-hash name.

### 4.2 What was done

Options considered, and why this one:

| Option | Verdict |
|---|---|
| Network per engagement (name includes the engagement) | Impossible for an identical range (above); also strands the lab's targets, which attach by CIDR name. |
| `enable_icc=false` on the bridge | Blocks container↔container — **including tool→target**, which is the whole point of the network. |
| Host-level filtering (iptables / bridge port isolation) | Needs host privilege, races container start, and makes the boundary a rule that can be misconfigured — the thing §8.3 chose a missing route over. |
| **Never two engagements live on one network (this)** | Closes the leak by construction (no co-resident, nothing to reach), needs no host privilege, fails closed, and leaves assets and same-engagement runs alone. |

The rule, in `tool_gateway/sandbox.py`:

* Every container the sandbox creates carries `cyberorch.owner=<engagement_id>` (`""` when the caller
  names none). `run(..., engagement_id=)` and `start_egress_proxy(..., engagement_id=)` take it;
  dispatch always passes it.
* After a container is created and attached — **before it is started** — `_assert_exclusive` lists the
  other owner-labelled containers on every network it joins. One that belongs to a *different* owner
  and is running (or paused/restarting), **or created earlier and about to run**, refuses the newcomer
  with `NetworkInUse` (a `SandboxUnavailable`, so existing handlers still catch it).
* It is not "look, then go". Two engagements arriving together each see the other's *created*
  container; creation time (parsed as a time, ties by id) decides: the later yields, the earlier ignores
  the later (which is about to yield). **Exactly one proceeds.** Mutation-verified both ways (§5).
* Unlabelled containers — a lab's targets — are the range's assets, not tenants, and are not counted.
* **`run(no_network=True)`** (`network_mode='none'`) for actions that need no network: `dispatch_code_scan`
  now uses it. No segment exists to share, and Semgrep/Gitleaks neither need nor get a route
  (`NO_EGRESS_ALLOWLIST` stays as the *record* for the fingerprint and `tool_runs.network_allowlist`,
  so no execution fingerprint changed).
* The egress proxy is held to the same rule on **both** of its networks. It carries one capability's
  grant, so it must not share a segment with another engagement's tool, and while it lives it keeps
  other engagements' tools off the tool-side network.

### 4.3 What the second engagement now sees

`NetworkInUse` — "the network for this allowlist is in use by another engagement; nothing was started".
The message deliberately names no one: it reaches the refused engagement's audit trail. The operator
log (`cyberorch.sandbox`, WARNING) names the blocking container and its owner.

### 4.4 Dispatch: "not started" is not "unknown outcome"

Every `SandboxUnavailable` in dispatch is recorded as `UNKNOWN_OUTCOME` — "may or may not have run, do
not retry" (§8.8). For a refusal made *before the container exists* that is wrong, and the fix would
otherwise have made it a common outcome (two engagements on one range is now ordinary). So the
refusals are a subclass, `NetworkNotAvailable` (`NetworkInUse`, and `NetworkRangeConflict` for Docker's
overlap refusal, which D58's E5 had found mislabelled the same way), and each of the three dispatch
functions catches it **before** the `SandboxUnavailable` handler (an AST test pins the order): the run
is `FAILED`, the proposal is `failed` (retryable), audited as `tool_run.refused` with a stable reason
code, and **no `executed` provenance edge is drawn**. This closes the network-caused part of D58's X4;
the daemon-unreachable-before-start part is untouched.

### 4.5 Callers that had relied on the old behaviour

* `tests/scenarios/test_scenario_web_render.py` — the proxy was module-scoped and served every test's
  engagement. It is now function-scoped and started *for* that test's engagement (target and networks
  stay module-scoped). The test failed under the rule, correctly: dispatch passed the engagement, the
  proxy was an unattributed owner.
* `scripts/live_run/d40_three_role.py` — the proxy was started before the engagement existed; the
  engagement id is now created first and passed to both. (By reading and `ruff`; not re-run, as it
  needs the real model CLI — recorded in 5.50's neighbourhood, not new.)
* Six test doubles that mirror `DockerSandbox.run`'s signature gained the two new keyword arguments;
  `tests/gitleaks_support.run_command`, which mirrors dispatch, passes `no_network=True`.

## 5. Tests (`tests/test_network_isolation.py`, 17)

Verdict sources, none of them the refused run's own report: the **listener's own log** (a connection
that was accepted is recorded by the one who accepted it), the **kernel's** ENETUNREACH through
`probe_egress` (D6), the **target's own access log** (D34), and `docker inspect` / `docker ps` /
`docker network inspect`. Every refusal has a same-engagement positive control in the same file —
without it "was refused" and "could never have connected" are one observation.

| Test | Establishes |
|---|---|
| same engagement shares its network with itself | the legitimate case still works (part 三); control for the rest |
| another engagement refused before its container starts | no B container exists; only A's is on the network; A's listener log shows **no connection**; the message names no one |
| unattributed vs. engagement, both directions | probes/lab scripts are not a way onto an engagement's network |
| sequential engagements | exclusion is while live, not forever; the second takes the same address |
| two engagements starting together ×3 | exactly one runs, one is refused — never both, never neither |
| different ranges, both live | `probe_egress` from B to A: `network_unreachable` (kernel); from A's own range: `reachable` (control) |
| **another engagement cannot spend this engagement's proxy grant** | control: A's tool through A's proxy → 200; B refused; **the target's log still shows exactly one request**; B cannot start a proxy beside A's either |
| no-network runs of different engagements | both run **at once**; `docker inspect`: `NetworkMode none`, attached to `none` only; kernel: "Network is unreachable" |
| overlapping range | typed `NetworkRangeConflict`, still a `SandboxUnavailable` |
| creation key | Docker's trimmed fraction compared as a time, not as text |
| dispatch passes `engagement_id` on all three `sandbox.run` calls; code scans pass `no_network=True`; handler order | structural (AST) |
| network refusal through the real `propose_action` ×2 | proposal and run `failed` (not `unknown_outcome`), `tool_run.refused` audited with reason, **0 `executed` edges**, no engagement id in the payload |

**Mutation verification** (each applied, observed red, reverted; the file diff was checked clean after):
`_assert_exclusive` made a no-op → the refusal test fails; the proxy path's call removed → the
proxy-grant test fails; tie-break removed (a created container always ignored) → the race test fails;
tie-break replaced by symmetric abort → the race test fails. One of these mutations left a real proxy
container behind, which is how the leftover-container behaviour in §7 was found.

## 6. Part 三 — does the tightening block anything that legitimately shares a network?

Looked for any existing need for tool runs to reach one another, and found none by design:

* **Tool ↔ tool, same engagement:** no code path makes one tool run connect to another. Tools are
  clients. The positive control confirms same-owner containers still reach each other if a test makes
  one listen.
* **Tool ↔ its own proxy:** the proxy is started for the engagement whose tools use it → same owner →
  allowed (positive control: A's tool through A's proxy gets 200).
* **Tool/proxy ↔ targets:** targets are unlabelled → assets → not counted, unchanged.
* **Sequential engagements and the live-run lab:** unaffected (exclusion is while live).
* What *does* change: two engagements on one range can no longer run **at the same time**; the second
  gets `NetworkInUse` and, through dispatch, a retryable `failed`. That is the point, and it is a cost
  for the Production Orchestrator (below). The full suite also exposed the two callers in §4.5 that
  were shaped for sharing; nothing else.

## 7. What this does not fix (stated, not hidden)

1. **Same-range engagements serialize.** The orchestrator must treat `NetworkInUse` as "try later",
   not as failure; D58-14 is now decided in direction (exclusion, not per-engagement bridges).
2. **Assets are shared by definition.** Two *customers* whose real networks use the same private range
   would, in a routed deployment, need per-customer routed networks, which is ACCEPTANCE 5.2 (never
   exercised); this fix does not address that and cannot — the network's identity would then have to
   include the owner. It is the same open item, not a new one.
3. **A stale owner-labelled container blocks the network until removed.** A crashed process leaves a
   proxy (or a `running` tool container) that the rule counts. Fail-closed, and the operator log names
   it, but it needs the reconciler D58 already lists (orphan sweep by `cyberorch.run_id` / owner label).
   Observed in this very session: a proxy left by a failed mutation run blocked later runs until removed.
4. **Single Docker daemon.** The check reads one daemon's containers; engagements spread across Docker
   hosts are not covered.
5. **The target-side network is exclusive too** (deliberate: the proxy is a tenant there). A hostile
   *target* reaching the proxy's target-side address (`--bind 0.0.0.0`) was noticed in the code and not
   tested; it is not part of this deliverable and not made worse by it.
6. **Post-fix ICMP was not re-measured between two *co-resident* containers**, because none can now
   exist; for different ranges the evidence is the kernel's ENETUNREACH on TCP, with ICMP covered by
   the same routing argument. The pre-fix ICMP reply is the measurement in §2.
7. **`tests/` and lab scripts that name no engagement** are one owner ("") and may still share a
   network with each other — distinct from every engagement, so never with one. Intentional (probes);
   it means an unattributed run is not isolated *from other unattributed runs*.

## 8. Reproducing

```
.venv/bin/python -m pytest tests/test_network_isolation.py -v      # 17 tests, ~45 s, real containers
```

The pre-fix measurements are three throwaway scripts (listener + ICMP/TCP; proxy-grant bypass; the
audit-trail overlap query) whose method is §2 and §3; they were run against the tree at `ad2c8d5` and
are not committed. To see the leak again, make `_assert_exclusive` return immediately: the refusal,
proxy-grant and race tests go red.
