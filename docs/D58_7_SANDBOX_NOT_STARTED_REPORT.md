# D58-7 — A sandbox that never started is "failed", not "unknown outcome" (D58-7)

**The defect (D58 §3.2 link 4, X4).** `dispatch` caught every `SandboxUnavailable` and recorded it as
`unknown_outcome` — "the tool may or may not have run" (§8.8, I7). That is the right answer for a
failure at or after `container.start()`. It is the wrong one for a failure where the tool *provably
did not run*: Docker could not be reached, the tool image was absent, the confined network could not
be had, the container could not be created. A Docker outage then turned every dispatch in its window
into a proposal only a human could clear — and Docker flaps. (D59 had already fixed the one case it
met, the network refusals, by giving them their own type; this is the same fix for the rest.)

**The adjacent escape (X5).** With a *cached* client and the daemon dead, the SDK raises a raw
`requests.exceptions.ConnectionError`, which is not a `SandboxUnavailable`: it escaped
`propose_action` entirely. Since D60 that leaves the stage `dispatching` with a `running` row (the
reconciler's), which is safe but is an unhandled exception to the caller for what is a typed fact.

## What changed

* `tool_gateway/sandbox.py` — a type, not a message match: **`NotStarted(SandboxUnavailable)`**, with
  `DaemonUnreachable` (`docker_unreachable`), `ImageNotPresent` (`tool_image_missing`) and the existing
  `NetworkNotAvailable` family (now its subclasses). Raised only where "nothing of this run executed"
  is provable: in `run()`, the client / image check / network / `containers.create` — wrapped by one
  context manager that also translates the raw connection error (X5). **Not** wrapped around
  `start()` or after: a connection lost there leaves a run that may have executed.
  `client()` also no longer caches a client that failed its ping (it did: `_client` was assigned
  before `ping()`, so a failed first call left a broken client in place for the next one).
* `control_plane/orchestrator/dispatch.py` — `_execute` handles `NotStarted` where it handled
  `NetworkNotAvailable`: run `failed`, `dispatch_state` `failed`, stage `closed` with the reason as
  detail, audit `tool_run.refused` with reasons `(sandbox_not_started | network_unavailable, <code>)`,
  no run id returned (so no *executed* provenance edge).
* A plain `SandboxUnavailable` — raised by nothing in `run()` any more, but still by any sandbox that
  cannot say where it failed — **stays `unknown_outcome`**. The policy half of D58-7 (retrying
  side-effect-free unknowns) is not touched: D58's recommendation was (B), fix the mislabel and keep
  "never auto-retry" for what is genuinely unknown.

## Verification (`tests/test_sandbox_not_started.py`, 8; `tests/test_network_isolation.py`)

Real Docker SDK against an address with no daemon (`DOCKER_HOST=tcp://127.0.0.1:1`), and against the
real daemon with an image that does not exist — no stub raising what the fix expects.

* daemon unreachable through `propose_action`: `dispatch_state=failed`, stage `closed`/`docker_unreachable`,
  run `failed`, no evidence, **no `tool_run.unknown_outcome`**, `reconcile_stale_dispatches` finds nothing;
  a fresh proposal for the same target runs once the daemon is back;
* X5: a cached client whose daemon is dead raises `DaemonUnreachable` (and through `propose_action`
  records the same), instead of a raw `ConnectionError`; a failed ping is not cached;
* a missing image: `failed`/`tool_image_missing`;
* control: an untyped `SandboxUnavailable` is still `unknown_outcome`/`recorded`;
* `tests/test_dispatch.py::test_an_unavailable_sandbox_yields_unknown_outcome` pinned the mislabel itself (a missing
  image → `unknown_outcome`, with the comment that "nothing distinguishes never launched from launched and lost"). It
  was the one test the full suite turned red; it now uses a sandbox that cannot place its failure (still
  `unknown_outcome`) and a new twin asserts the missing image is `failed`/`tool_image_missing`;
* D59's AST guard now requires the `NotStarted` handler to precede the `SandboxUnavailable` one.

Mutation-verified: dispatch handling only the network family (the pre-fix behaviour) → the daemon,
cached-client and image tests red; daemon errors not translated → both X5 tests red; `client()`
raising an untyped error → three red; every `SandboxUnavailable` treated as not started → the control
and the ordering guard red.

## Not done

* A raw connection error **after** `start()` still propagates (stage `dispatching`, reconciler's);
  retyping it as `SandboxUnavailable` so it is recorded `unknown_outcome` at once is D58-6's ladder.
* `start_egress_proxy` and `probe_egress` raise plain `SandboxUnavailable`; they are not on the
  dispatch path.
* No retry or backoff: a `failed` proposal is retried by whoever schedules (D58-1..4), as for D59.

## Follow-up: the exit D58-7 missed — `container.start()` refused by the daemon

Found while designing the scheduler (D62). A `network.scan` on a single IP with no allowlist builds a one-address
Docker network (`/32`); `containers.create` succeeds, and **`container.start()` raises `APIError` 500 "failed to
set up container networking: no available IPv4 addresses"**. D58-7 had typed everything up to `create` and left
`start()` alone, so the error escaped `propose_action`/`dispatch_approved` raw and left the proposal at
`dispatching` — for a run that provably never executed.

*Where exactly:* `DockerSandbox.run`, the `container.start()` call (after the container exists, before any
process). *Proof it never ran* (inspected after the failure): `Status: created`, `Running: false`, `Pid: 0`,
`StartedAt: 0001-01-01…`.

*Fix:* `DockerSandbox._start_container` — an `APIError` from `start()` becomes `ContainerStartRefused` (a
`NotStarted`, code `container_start_refused`, fixed message) **only if** a following inspection shows exactly that
state; an inspection that fails, or any other state, re-raises the original error and the run stays unplaced. A
dropped connection during `start()` is deliberately not covered. Recorded `failed`, stage `closed`/
`container_start_refused`, audit `tool_run.refused (sandbox_not_started, container_start_refused)`.

*Tests* (`tests/test_sandbox_not_started.py`, +4): real Docker refusal typed; through `propose_action` the proposal
is `failed`/`closed` (the daemon's explanation asserted in the operator log, absent from the audit message),
nothing for the reconciler; the guard types only on proof (running / exited / has-a-PID states re-raise); a failed
inspection re-raises. Mutation-verified: `start()` untyped again → the two real-Docker tests red; proof dropped →
the guard test red; failed inspection typed → the inspection test red.
