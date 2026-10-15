# F1 and F2 of the soak pilots: what was changed, the rule, and every place that lists and then asks (2026-10-15)

## The rule (written in `service._translate`, pinned by `tests/test_reconciler_vanishing.py`)

| the call met | it means | what happens |
|---|---|---|
| `NotFound` (404) for an object whose id we hold, between a list and the call that follows it | that object is **gone** | handled where the call is made: a listing drops it, an action returns `gone` |
| connection refused / reset / timed out; an HTTP 5xx; an SDK error with no HTTP answer; `OSError` | the **daemon is lost** | `docker_lost`, exit 5 |
| an HTTP 4xx that reaches the top of the service | the daemon answered, so it is there; this is a **defect** | `unexpected_error`, exit 1 |

Before, every `DockerException` was `docker_lost`, and `NotFound` is a `DockerException`: a container removed while the
reconciler listed stopped it with "Docker unreachable" (pilot 3; `python -m scripts.soak.experiment_list_race`: 109 of 1,554
listings raised `NotFound`). After, the same experiment's listings do not raise (the tests below), and a daemon that is really
not there still ends the service with exit 5 (a client pointed at a port nothing listens on, through the reconciler's own `serve`;
and, in the soak, a real restart of `dockerd`).

## Every place that lists Docker objects and then calls something on them

| place | what it did | now | test (real Docker, 40 times each) |
|---|---|---|---|
| `observe.list_containers` | SDK `list` = ids, then inspect each; `NotFound` escaped | `ignore_removed=True`: the container is not in the result | `test_gone_a_container_removed_between_the_list_and_the_inspect_...` |
| `observe.list_networks` | `networks.list()` then `network.reload()` | `NotFound` on the reload: the network is skipped | `..._a_network_removed_between_the_list_and_its_inspect_...` |
| `observe.list_networks`, members of a network | `containers.list(filters network)` | `ignore_removed=True` | `..._a_container_attached_to_a_network_that_vanishes_...` |
| `observe.live_mount_sources` | `containers.list(all=True)` then `.attrs` | `ignore_removed=True` (a container that is gone mounts nothing) | `..._mount_sources_..._[observe]` |
| `act_docker.live_mount_sources` (re-read before an unlink) | same | `ignore_removed=True` | `..._mount_sources_..._[act_docker]` |
| `act_docker._remove_network`, "any container on it?" | `containers.list(filters network)` | `ignore_removed=True` (it is not on it any more) | `..._on_a_network_that_vanishes_while_the_network_is_removed_...` |
| `act_docker._remove_container.gone()` | `get`, then `list(filters id)` | `ignore_removed=True` | (the answer is the same either way: gone) |
| `tool_gateway/sandbox._assert_exclusive` | `containers.list(...)` then `other.reload()` | `ignore_removed=True`; `NotFound` on the reload: not on the network | `..._the_sandbox_checks_exclusivity_...` |
| `act_docker._inspected`, `_kill`, `_remove_container`, `_remove_network` (the action's own subject) | `get`/`reload`/`remove` | unchanged: already `NotFound -> gone`, 40-time tests since RT8 (`tests/test_reconciler_races.py`, `..._concurrency.py`) | existing |
| the sandbox's own run (`run`, `start_egress_proxy`: create, start, wait, reload of **its own** container) | -- | unchanged: if someone removes the run's own container, that is the run's unknown outcome (5.74), not a listing race | existing |
| `tests/residue.py` (test infrastructure) | `containers.list(all=True)` | `ignore_removed=True` | -- |

`service._translate` is the only place a `DockerException` becomes an exit code; `scheduler.execute.docker_reachable` only pings.

## F2 (ACCEPTANCE 5.108), confirmed and tested, not changed

`DockerSandbox.ensure_network` does `networks.get`, then on `NotFound` `networks.create`; the loser of a race gets Docker's 409.
It raises `NetworkNotAvailable`, a `NotStarted` ("nothing started, so the outcome is known and the action can be retried",
`reason = network_unavailable`), before any container exists. `tests/test_network_create_race.py`: the type and reason (409 on
a fake that loses the race); through `propose_action` the proposal is `closed / network_unavailable`, the run `failed` with
`refusal_code` and **never** `unknown_outcome`; the same request made again runs; and on a real daemon two creators released
together **40 times**: in all 40 rounds there was a loser, every loser was a `NetworkNotAvailable` (never another exception), and a
retry of every loser got the network. The race is not removed; it is a refusal, as designed.
