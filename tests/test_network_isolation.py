"""Two engagements, one range: network isolation between engagements (D59, I4).

I4 had been checked in the database (RLS) and in the application (engagement
scoping). Nobody had asked the network layer what happens when two engagements
authorize the *same* range -- and the answer, until D59, was that they were
handed the same Docker bridge: the network is named from the allowlist alone.
Measured on the unfixed code, from a second engagement's tool container:

    ICMP to the first engagement's container   -> reply
    TCP connect to a port it listened on       -> connected
    HTTP through the first engagement's egress
    proxy, to a host only that grant allowed   -> 200 (the target's own log shows it)

so the leak was not ping-only, and the last row was an authorization bypass: the
proxy spends *its* capability's grant for whoever can reach it.

What these tests assert is the rule that replaced it -- two engagements are never
live on one network at once -- with every verdict taken from something other than
the component under test: the *listener's own log* (a connection that happened is
recorded by the one who accepted it), the kernel's ENETUNREACH through
``probe_egress`` (D6), the target's own access log (D34), and ``docker inspect``.
A refusal is never established from the refused run's own report.

Each refusal test has a positive control in the same file: the same run, same
network, **same engagement**, does connect. Without it "was refused" and "could
never have connected anyway" would be the same observation. The same-engagement
controls are also the answer to "did the tightening break anything that was
legitimately sharing a network": runs of one engagement, and a run with its own
engagement's proxy, are untouched.

Nothing here is mocked except where stated (the dispatch-outcome tests). Docker
or the images being unavailable fails the test rather than skipping it.
"""

from __future__ import annotations

import ast
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

from control_plane.state.db import engagement_scope
from tool_gateway.sandbox import (
    NO_OWNER,
    OWNER_LABEL,
    DockerSandbox,
    NetworkInUse,
    NetworkNotAvailable,
    NetworkRangeConflict,
    SandboxUnavailable,
    _creation_key,
)

REPO = Path(__file__).resolve().parent.parent

# Ranges nothing else in the suite uses (10.77-10.91 are taken), all with no
# route to anything real.
SHARED = "10.93.0.0/24"
OTHER = "10.94.0.0/24"
TOOL_SIDE = "10.95.0.0/24"
TARGET_SIDE = "10.96.0.0/24"
BIG = "10.97.0.0/16"
INSIDE_BIG = "10.97.1.0/24"
TARGET_IP = "10.96.0.10"
TARGET_PORT = 8080
PORT = 4444

A, B = "ENG-D59-A", "ENG-D59-B"


@pytest.fixture(scope="module")
def box():
    sandbox = DockerSandbox()
    try:
        sandbox.ensure_image()
    except SandboxUnavailable as exc:
        pytest.fail(
            f"sandbox unavailable: {exc}\nThese tests verify the network boundary "
            "between engagements and are not meaningful without a real container.",
            pytrace=False,
        )
    yield sandbox
    for cidr in (SHARED, OTHER, TOOL_SIDE, TARGET_SIDE, BIG, INSIDE_BIG):
        sandbox.remove_network([cidr])


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True).stdout.strip()


def _container_id(run_id: str) -> str:
    return _docker("ps", "-aq", "--filter", f"label=cyberorch.run_id={run_id}")


class Holder:
    """A tool container, owned by an engagement, that stays up and listens.

    It is a real ``sandbox.run`` (so it is labelled, attached and checked exactly
    as production runs are), running ``ncat -l -k -v``: ncat logs every connection
    it accepts to stderr, which is the witness -- the listener's own record of who
    reached it, outside anything the connecting side reports.
    """

    def __init__(self, box: DockerSandbox, cidr: str, owner: str | None, *,
                 no_network: bool = False, seconds: int = 60):
        self.box, self.cidr, self.owner = box, cidr, owner
        self.run_id = f"hold-{uuid.uuid4().hex[:8]}"
        self.result = None
        self.error: BaseException | None = None
        self._kwargs = dict(
            command=["/usr/bin/ncat", "-l", "-k", "-v", "-p", str(PORT)],
            network_allowlist=[cidr], max_duration_seconds=seconds,
            run_id=self.run_id, engagement_id=owner, no_network=no_network,
        )
        self.thread = threading.Thread(target=self._go, daemon=True)

    def _go(self) -> None:
        try:
            self.result = self.box.run(**self._kwargs)
        except BaseException as exc:  # noqa: BLE001 - reported by __enter__
            self.error = exc

    def __enter__(self) -> Holder:
        self.thread.start()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.error is not None:
                raise self.error
            cid = _container_id(self.run_id)
            if cid:
                logs = subprocess.run(["docker", "logs", cid], capture_output=True, text=True)
                if "Listening on" in logs.stdout + logs.stderr:
                    return self
            time.sleep(0.2)
        raise AssertionError("the holder never started listening")

    def __exit__(self, *exc) -> None:
        self.stop()

    def ip(self) -> str:
        net = self.box.network_name([self.cidr])
        return _docker("inspect", "-f",
                       "{{(index .NetworkSettings.Networks \"" + net + "\").IPAddress}}",
                       _container_id(self.run_id))

    def stop(self):
        """Kill it and return what it logged -- every connection it accepted."""
        cid = _container_id(self.run_id)
        if cid:
            _docker("kill", cid)
        self.thread.join(timeout=30)
        return self.result.stderr if self.result is not None else ""


def _connect(box, cidr: str, owner: str | None, ip: str) -> object:
    return box.run(
        command=["/usr/bin/ncat", "-w", "3", "-v", ip, str(PORT)],
        network_allowlist=[cidr], max_duration_seconds=15, engagement_id=owner,
    )


# ---------------------------------------------------------------------------
# 1. TCP: a second engagement cannot join a network the first is running on
# ---------------------------------------------------------------------------

def test_the_same_engagement_still_shares_its_network_with_itself(box):
    """The positive control, and the legitimate case (part 三 of D59): two runs of
    ONE engagement on one network. The second reaches the first, the first logs it.
    If this fails the tightening broke something that was supposed to work -- and
    every refusal below stops meaning anything."""
    with Holder(box, SHARED, A) as held:
        result = _connect(box, SHARED, A, held.ip())
    assert "Connected to" in result.stderr, result.stderr
    assert "Connection from" in held.result.stderr


def test_another_engagement_is_refused_before_its_container_starts(box):
    with Holder(box, SHARED, A) as held:
        ip = held.ip()
        with pytest.raises(NetworkInUse) as refused:
            _connect(box, SHARED, B, ip)
        members = _docker("network", "inspect", "-f",
                          "{{range .Containers}}{{.Name}} {{end}}",
                          box.network_name([SHARED])).split()
        assert len(members) == 1, f"only A's container may be on the network: {members}"
        assert not _docker("ps", "-aq", "--filter", f"label={OWNER_LABEL}={B}"), (
            "B's container still exists"
        )
        logged = held.stop()
    # The witness: the one that would have accepted the connection never saw one.
    assert "Connection from" not in logged, logged
    # The refusal reaches B's audit trail through its message; it must not name A.
    assert A not in str(refused.value) and "ENG-D59" not in str(refused.value)
    assert refused.value.reason == "network_in_use_by_another_engagement"


def test_a_run_that_names_no_engagement_is_kept_apart_from_one_that_does(box):
    """Probes and lab scripts name no engagement; they must not be a way onto an
    engagement's network."""
    with Holder(box, SHARED, A) as held:
        with pytest.raises(NetworkInUse):
            _connect(box, SHARED, None, held.ip())
    with Holder(box, SHARED, None) as held:
        with pytest.raises(NetworkInUse):
            _connect(box, SHARED, A, held.ip())


def test_once_the_first_engagement_is_finished_the_second_may_use_the_network(box):
    """Exclusion is while live, not forever: sequential engagements on one range
    (the lab, and every live-run script) are unaffected."""
    with Holder(box, SHARED, A) as held:
        ip = held.ip()
    # A's container is gone. B takes the network and finds the same address free.
    with Holder(box, SHARED, B) as other:
        assert other.ip() == ip


@pytest.mark.parametrize("round_", range(3))
def test_two_engagements_starting_together_leave_exactly_one_running(box, round_):
    """The check is not 'look, then go'. Two engagements start on one network at
    the same moment: exactly one proceeds and the other is refused, whichever was
    scheduled first -- never both, which would be the leak, and never neither."""
    barrier = threading.Barrier(2)
    outcomes: dict[str, object] = {}

    def attempt(owner: str) -> None:
        barrier.wait()
        try:
            outcomes[owner] = box.run(
                command=["/usr/bin/ncat", "-l", "-p", str(PORT)],
                network_allowlist=[SHARED], max_duration_seconds=2, engagement_id=owner,
            )
        except NetworkInUse as exc:
            outcomes[owner] = exc

    threads = [threading.Thread(target=attempt, args=(o,)) for o in (A, B)]
    [t.start() for t in threads]
    [t.join(timeout=60) for t in threads]
    refused = [o for o, v in outcomes.items() if isinstance(v, NetworkInUse)]
    ran = [o for o, v in outcomes.items() if not isinstance(v, BaseException)]
    assert len(refused) == 1 and len(ran) == 1, outcomes


# ---------------------------------------------------------------------------
# 2. Disjoint ranges: simultaneously live, and the kernel says no route
# ---------------------------------------------------------------------------

def test_two_engagements_on_different_ranges_cannot_reach_each_other(box):
    """Both containers live at once, on separate bridges. The answer is the
    kernel's (D6's probe_egress: ENETUNREACH means no packet was built), not the
    tool's report. The positive control is the same probe, from A's own range."""
    with Holder(box, SHARED, A) as held:
        ip = held.ip()
        with Holder(box, OTHER, B):
            cross = box.probe_egress(
                target=ip, port=PORT, network_allowlist=[OTHER], engagement_id=B,
            )
        own = box.probe_egress(
            target=ip, port=PORT, network_allowlist=[SHARED], engagement_id=A,
        )
    assert cross == "network_unreachable", cross
    assert own == "reachable", own


# ---------------------------------------------------------------------------
# 3. HTTP through the proxy: the grant is not shared with a neighbour
# ---------------------------------------------------------------------------

def _wait_until_serving(name: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        if "Serving HTTP" in logs.stdout + logs.stderr:
            return
        time.sleep(0.2)
    raise AssertionError("the web target never started serving")


def _request_via_proxy() -> str:
    return (f"GET http://{TARGET_IP}:{TARGET_PORT}/ HTTP/1.1\r\n"
            f"Host: {TARGET_IP}:{TARGET_PORT}\r\nConnection: close\r\n\r\n")


@pytest.fixture
def proxy_topology(box):
    """A's capability: a web target, and a proxy granted that one host."""
    name = f"d59-web-{uuid.uuid4().hex[:8]}"
    target_net = box.ensure_network([TARGET_SIDE])
    box.ensure_network([TOOL_SIDE])
    subprocess.run(
        ["docker", "run", "-d", "--name", name, "--network", target_net.name,
         "--ip", TARGET_IP, "cyberorch/web-target:local"],
        check=True, capture_output=True,
    )
    endpoint = None
    try:
        _wait_until_serving(name)
        endpoint = box.start_egress_proxy(
            grant={"capability_id": "CAP-D59-A", "host": TARGET_IP, "port": TARGET_PORT,
                   "methods": ["GET"], "max_requests": 20},
            tool_side=[TOOL_SIDE], target_side=[TARGET_SIDE], engagement_id=A,
        )
        yield endpoint, name
    finally:
        if endpoint is not None:
            box.stop_egress_proxy(endpoint)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def _through_proxy(box, endpoint, owner):
    host, port = endpoint.url.removeprefix("http://").split(":")
    return box.run(
        command=["/usr/bin/ncat", "-w", "5", host, port],
        network_allowlist=[TOOL_SIDE], max_duration_seconds=15, engagement_id=owner,
        stdin=_request_via_proxy(),
    )


def _target_served(name: str) -> list[str]:
    logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
    return [line for line in (logs.stdout + logs.stderr).splitlines() if '"GET ' in line]


def test_another_engagement_cannot_spend_this_engagements_proxy_grant(box, proxy_topology):
    """The authorization bypass the shared network allowed. Engagement B has no
    capability for this host; before the fix its tool simply addressed A's proxy
    and the target served it. The witness is the target's own access log -- the one
    record neither proxy nor tool can write."""
    endpoint, target = proxy_topology

    # Positive control: A's own tool, through A's own proxy, is served.
    reply = _through_proxy(box, endpoint, A)
    assert reply.stdout.startswith("HTTP/1.1 200"), reply.stdout[:200]
    assert len(_target_served(target)) == 1

    with pytest.raises(NetworkInUse):
        _through_proxy(box, endpoint, B)
    assert len(_target_served(target)) == 1, "B's request reached the target"

    # Nor may B stand up a proxy of its own beside A's.
    with pytest.raises(NetworkInUse):
        box.start_egress_proxy(
            grant={"capability_id": "CAP-D59-B", "host": TARGET_IP, "port": TARGET_PORT,
                   "methods": ["GET"], "max_requests": 1},
            tool_side=[TOOL_SIDE], target_side=[TARGET_SIDE], engagement_id=B,
        )
    assert not _docker("ps", "-aq", "--filter", f"label={OWNER_LABEL}={B}")


# ---------------------------------------------------------------------------
# 4. No network at all: nothing to share
# ---------------------------------------------------------------------------

def test_no_network_runs_of_different_engagements_run_together_and_share_nothing(box):
    """Code scans (semgrep, gitleaks) used to run on one fixed /29 for every
    engagement. They need no network, so they now get none: the engagements run
    concurrently, no segment is shared, and the container's own attachment record
    says so."""
    with Holder(box, SHARED, A, no_network=True) as held:
        cid = _container_id(held.run_id)
        mode = _docker("inspect", "-f", "{{.HostConfig.NetworkMode}}", cid)
        attached = _docker("inspect", "-f",
                           "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}", cid)
        assert mode == "none" and attached.split() == ["none"], (mode, attached)
        # B, concurrently: not refused (there is nothing to be in use), and the
        # kernel finds no route to anything -- loopback is all there is.
        other = box.run(
            command=["/usr/bin/ncat", "-w", "2", "-v", "10.255.255.2", str(PORT)],
            network_allowlist=["10.255.255.0/29"], max_duration_seconds=15,
            engagement_id=B, no_network=True,
        )
    assert "Network is unreachable" in other.stderr, other.stderr


# ---------------------------------------------------------------------------
# 5. A range that collides is "not started", and says so
# ---------------------------------------------------------------------------

def test_an_overlapping_range_is_a_typed_refusal_not_a_daemon_fault(box):
    box.ensure_network([BIG])
    with pytest.raises(NetworkRangeConflict) as refused:
        box.ensure_network([INSIDE_BIG])
    assert isinstance(refused.value, NetworkNotAvailable)
    assert isinstance(refused.value, SandboxUnavailable), "existing handlers must still catch it"


def test_creation_order_is_compared_as_a_time_not_as_text():
    """Docker trims trailing zeros from the fraction, so '...13Z' and '...13.1Z'
    do not sort as times. The tie-break between two simultaneous creators rests
    on this."""
    class C:
        def __init__(self, created, cid):
            self.attrs, self.id = {"Created": created}, cid

    earlier = _creation_key(C("2026-10-05T14:11:53Z", "b"))
    later = _creation_key(C("2026-10-05T14:11:53.1Z", "a"))
    assert earlier < later
    assert _creation_key(C("2026-10-05T14:11:53.5Z", "a")) > _creation_key(
        C("2026-10-05T14:11:53.49Z", "a"))
    assert _creation_key(C("2026-10-05T14:11:53.1Z", "a")) < _creation_key(
        C("2026-10-05T14:11:53.1Z", "b")), "equal times fall back to id, so no two tie"
    assert NO_OWNER == ""


# ---------------------------------------------------------------------------
# 6. The wiring: dispatch tells the sandbox who it is working for
# ---------------------------------------------------------------------------

def _dispatch_tree() -> ast.Module:
    return ast.parse((REPO / "control_plane/orchestrator/dispatch.py").read_text())


def test_every_dispatch_sandbox_run_names_its_engagement():
    """The sandbox can keep engagements apart only if told which is which. A
    dispatch path that forgot would run as an unattributed owner and be kept apart
    from everyone -- safe, but it would silently stop being a tenant of anything,
    so this is checked structurally."""
    calls = [n for n in ast.walk(_dispatch_tree())
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "run" and isinstance(n.func.value, ast.Name)
             and n.func.value.id == "sandbox"]
    assert len(calls) == 3, "dispatch_scan, dispatch_collection, dispatch_code_scan"
    for call in calls:
        keywords = {k.arg: k.value for k in call.keywords}
        assert "engagement_id" in keywords, ast.unparse(call)[:80]


def test_code_scans_join_no_network():
    run_calls = [n for n in ast.walk(_dispatch_tree())
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr == "run"
                 and any(k.arg == "source_mounts" for k in n.keywords)
                 and any(k.arg == "network_allowlist" and isinstance(k.value, ast.Name)
                         and k.value.id == "NO_EGRESS_ALLOWLIST" for k in n.keywords)]
    assert len(run_calls) == 1
    flag = {k.arg: k.value for k in run_calls[0].keywords}.get("no_network")
    assert isinstance(flag, ast.Constant) and flag.value is True


def test_the_sandbox_unavailable_handler_is_preceded_by_the_network_one():
    """``NetworkNotAvailable`` is a ``SandboxUnavailable``. A handler for the base
    placed first would catch it and record 'unknown outcome' for a run that never
    started -- the mislabel D59 exists to avoid for this case. Since D60 the handlers
    live in one place, ``_execute``, which all three dispatch functions go through."""
    tree = _dispatch_tree()
    tries = [n for n in ast.walk(tree) if isinstance(n, ast.Try)
             and any(isinstance(h.type, ast.Name) and h.type.id == "SandboxUnavailable"
                     for h in n.handlers)]
    assert len(tries) == 1
    names = [h.type.id for h in tries[0].handlers if isinstance(h.type, ast.Name)]
    assert names.index("NetworkNotAvailable") < names.index("SandboxUnavailable")
    public = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
              and n.name in ("dispatch_scan", "dispatch_collection", "dispatch_code_scan")}
    assert len(public) == 3
    for name, function in public.items():
        called = {c.func.id for c in ast.walk(function)
                  if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
        assert "_execute" in called, f"{name} must run its container through _execute"


class _RefusingSandbox:
    def __init__(self, exc):
        self.exc = exc

    def run(self, **kwargs):
        raise self.exc


@pytest.mark.parametrize("exc", [
    NetworkInUse("the network for this allowlist is in use by another engagement; "
                 "nothing was started"),
    NetworkRangeConflict("the range ['10.0.0.0/24'] overlaps an existing network"),
])
def test_a_network_refusal_is_failed_not_unknown_outcome(engagement_id, registry, exc):
    """Through the real propose_action: nothing started, so the proposal is FAILED
    and retryable, not parked as UNKNOWN_OUTCOME for a human; the run left no
    'executed' edge; and the audit record names no one."""
    from agents.base_agent import ProposedAction
    from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
    from control_plane.api.function_api import propose_action
    from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy

    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value="10.82.0.0/24",
                   allowed_actions=["network.scan"])
    policy = merge_policy(
        PolicyLayer(name="baseline_global", actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"), PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )
    proposal = ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": "ip", "value": "10.82.0.5"}},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"},
    )
    with engagement_scope(engagement_id) as conn:
        outcome = propose_action(
            engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(), policy=policy, agent_id="w",
            sandbox=_RefusingSandbox(exc),
        )
    assert outcome.decision == "ALLOW" and outcome.run_id is None
    assert outcome.failure == exc.reason

    with engagement_scope(engagement_id) as conn:
        state = conn.execute(text("SELECT dispatch_state FROM action_proposals")).scalar_one()
        run = conn.execute(text("SELECT status FROM tool_runs")).scalar_one()
        events = conn.execute(text(
            "SELECT event_type, reasons, payload::text FROM audit_log "
            "WHERE event_type LIKE 'tool_run.%' ORDER BY audit_id")).all()
        edges = conn.execute(text(
            "SELECT count(*) FROM provenance_edges WHERE relation = 'executed'")).scalar_one()
    assert state == "failed" and run == "failed"
    kinds = [e[0] for e in events]
    assert "tool_run.refused" in kinds and "tool_run.unknown_outcome" not in kinds, kinds
    refused = next(e for e in events if e[0] == "tool_run.refused")
    assert exc.reason in refused[1] and "ENG-D59" not in refused[2]
    assert edges == 0
