# ADR: the network allowlist of the inline dispatch (numbered change D69-NC-2)

Status: decided by the review layer under the owner's standing delegation, 2026-11-27; the owner may
veto. Plan items 161 and 162 record it.

## Background

Read-only investigations of 2026-11-27, each fact with where it is in the code at
`a379e954b486c1ba7396060cdd1692ea05436aa9`:

1. **The dispatch takes the caller's allowlist, or the target itself.**
   `control_plane/orchestrator/dispatch.py:712`: `allowlist = network_allowlist or [target]`. The
   value is written into the `tool_runs` row and the proposal moves to `dispatching` in the same
   committed transaction (`dispatch.py:758-781`), before the sandbox is asked.
2. **Nothing compares the caller's allowlist with the authorized scope object, or the target with
   the allowlist.** `propose_action` passes `network_allowlist` through unchanged
   (`control_plane/api/function_api.py:519`, `:612`, `:1072`, `:366`); `dispatch_scan` checks no
   target against it (only the AD collector's `dns_server` is checked, `dispatch.py:1035-1039`);
   `tool_gateway.sandbox.target_within_allowlist` is called only by `scripts/live_run/live_run.py`
   and the tests; `control_plane/policy/rego/authz.rego` has no rule on an allowlist (authorization
   compares the target with the scope object, `authz.rego:54-85`). §8.3's egress boundary therefore
   rests on each caller.
3. **The harness passes no allowlist.** `harness/loop_adapter.py:214-217` calls `propose_action`
   without `network_allowlist`, so an ip target gets `["<ip>"]`, which the sandbox reads as a
   `/32` (`tool_gateway/sandbox.py:380-391`). A `/32` internal bridge holds no container: D62's
   measurement, `control_plane/scheduler/allowlist.py:3-7` and
   `tests/test_scheduler_allowlist.py:109-132`. Every outcome is a `NotStarted`
   (`NetworkNotAvailable`, `NetworkRangeConflict` or `ContainerStartRefused`, `sandbox.py:251-285`,
   `:566-578`), recorded as not started (`dispatch.py:442-448`, `:334-357`); `propose_action`
   returns `ALLOW` with no run.
4. **An fqdn target is not a CIDR.** `validate_allowlist` raises a plain `ValueError`
   (`sandbox.py:383-387`) at the first line of `DockerSandbox.run` (`sandbox.py:1004`), which is
   neither a `NotStarted` nor a `SandboxUnavailable`, so `_execute` lets it through
   (`dispatch.py:436-441`), and so do `dispatch_scan`, `_dispatch` and `propose_action`. The run
   stays `running` and the proposal `dispatching`; the harness's loop ends with exit 12
   (`harness/loop.py:354-355`), and the stop-event check never sees the proposal
   (`scripts/run_harness.py:171-174`).
5. **A derivation exists, on another path.** `control_plane/scheduler/allowlist.derive_network_allowlist`
   (D62) turns the authorizing scope object into a Docker-acceptable allowlist, or a skip reason; it
   is used only by the scheduler's execution step (`control_plane/scheduler/execute.py:37-67`), for
   approved proposals.

## Decision

The rules apply to a dispatch whose action is in `control_plane.scheduler.vocab.NETWORK_ACTIONS`
(`network.scan`, `network.recon`: the harness's whole action set), and are placed in
`control_plane.api.function_api._dispatch`, the stage both the inline dispatch and the approved
dispatch (`dispatch_approved` through `_drive`) pass through, so that the two share one definition.
In this order:

- **R-a, derive.** `derive_network_allowlist` is called with the action, the type and value of the
  scope object the proposal was authorized by (`action_proposals.authorized_scope_object_id`) and the
  target's type and value. A skip reason means the dispatch is not started, and the outcome's
  `failure` is that reason. A proposal whose authorized scope object cannot be read is not started
  (`authorized_scope_missing`).
- **R-b, the caller's allowlist.** When the caller passes `network_allowlist`, every entry must be a
  CIDR (else `allowlist_invalid`), a subnet of the derived block (else `allowlist_exceeds_scope`),
  and an ip target must lie inside one of them (else `target_outside_allowlist`). When all hold, the
  dispatch uses the caller's list; when the caller passes none, it uses the derived one.
- **R-c, not started.** A refused start calls no sandbox and creates no run: the proposal moves from
  `capability_issued` straight to `closed` with the reason as its detail, the way `_dispatch`'s
  existing `capability_missing` branch does (`function_api.py:1060-1067`); its `dispatch_state` is
  `failed`; one audit event, `tool_run.refused`, names the reason, the caller's allowlist and the
  derived one. The decision stays `ALLOW`, `run_id` and `evidence_id` are `None`, and `failure` is
  the reason.
- **R-d, the sandbox's own refusal.** `DockerSandbox.run` turns `validate_allowlist`'s `ValueError`
  into the base `NotStarted` (`sandbox_not_started`), keeping the message, before any Docker object
  is touched; so a case the rules above do not reach (a caller of `dispatch_scan` directly, or an
  action outside `NETWORK_ACTIONS`) is recorded as not started instead of escaping. No exception
  class and no refusal code is added: the set of `NotStarted` reasons is pinned to migration 0025's
  closed vocabulary (`tests/test_timeout_vs_not_started.py:104-108`,
  `tests/test_refusal_code.py:72-75`, `tests/test_harness_h5a1_result_summary.py:257-265`).
  `validate_allowlist` itself, which still raises `ValueError`, its four assertions
  (`tests/test_sandbox.py:93`, `:98`, `:103`, `tests/test_egress_proxy.py:956`) and
  `remove_network` (`sandbox.py:628`) are unchanged.

The three new reasons, and `authorized_scope_missing`, are added to
`control_plane/scheduler/vocab.py` as `ALLOWLIST_REFUSALS`, apart from `SKIP_REASONS` (which migration
0019's `CHECK` repeats): they are outcomes of the dispatch, not dispositions of the scheduler.

## Alternatives rejected

- **Only the harness passes an allowlist.** Rejected: the boundary would still depend on each
  caller, the fact the change is about; every other caller of `propose_action` would stay as it is.
- **Widening an ip scope object into a block** that can hold a scanner and a target. Rejected: it
  grants more than was authorized, the reason D62's design note gives for not doing it
  (`control_plane/scheduler/allowlist.py:46-50`).
- **A new exception class for R-d** (`AllowlistRefused`, a `NotStarted` and a `ValueError`).
  Withdrawn: its reason would either repeat an existing one (`test_timeout_vs_not_started.py:108`)
  or be outside migration 0025's vocabulary (`test_refusal_code.py:75`), which would need a
  migration and the harness's copy of the vocabulary changed.
- **Applying R-a to every action.** Rejected after the implementer measured the whole suite: 9 test
  files' dispatches (`ad.collect`, `web.*`, and the tests' own synthetic action names) would have
  been refused, because `derive_network_allowlist` knows only network and code actions.

## Consequences

- A network dispatch the rules refuse keeps the decision `ALLOW`: the policy allowed it, and nothing
  ran. So a listed lure still triggers `lure_allowed` in the shadow runner. The harness's
  `result_summary` reads such an outcome as `not_executed` (`harness/result_summary.py:108-118`,
  `:143-144`), its existing class for an allowed action that did not run.
- An ip scope object can no longer be dispatched inline (`scope_narrower_than_sandbox_minimum`), as
  the scheduler already refused it; a test that dispatched against one exercised a path a real
  sandbox cannot run. `tests/test_harness_observations_db.py` moves its ip scopes to the enclosing
  `10.83.0.0/24`, with no assertion changed.
- `scripts/live_run/d15_lookalike.py:277`, which dispatches `203.0.113.200` (authorized by
  `203.0.113.128/25`) with the allowlist `10.79.0.0/24`, would now be refused
  (`allowlist_exceeds_scope`): the allowlist and the authorization disagree, which is the exposure
  this change closes. The script is not changed.

### Known gaps, stated

- **`web.*` and `ad.collect` also have egress**, but their scope objects (for example `ad_domain`) have
  no block to derive, so the caller's allowlist is still not checked for those two kinds of action.
- **Code actions** (`code.scan`, `code.secrets`) join no network; they are outside the rules.
- **A direct caller of `dispatch_scan`** does not pass through `_dispatch` and is not checked by
  R-a to R-c; only R-d's backstop applies to it.
- ipv6 targets and scope objects take D62's `ipv6_not_supported_v0`; a reserved address of the block
  takes `target_is_reserved_address`; the scheduler's path already used D62 and is unaffected.

## Pre-registration

`tests/test_inline_dispatch_allowlist.py`: twelve cases, D1 to D12, and one unit test of R-d, with
the expectation before the repair (D2, D5 and D12 pass, the other nine fail), committed before its
first run.
