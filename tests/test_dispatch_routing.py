"""Structural guarantee: every registered action reaches the dispatch
function its own adapter declares (D46).

D45 found ``propose_action`` calling ``dispatch_scan`` unconditionally for
*every* action, including ``ad.collect`` and ``code.scan`` — each of which
needs a different, bespoke dispatch function to perform the extra step
``dispatch_scan`` does not know how to do (the Security Graph write; the
control-plane-side git fetch/cleanup). D42's and D43's own test suites never
caught it because they called ``dispatch_collection``/``dispatch_code_scan``
directly, never ``propose_action`` at all.

D45's own fix was still a hand-written ``if capability.action == ad_collector
.ACTION`` inside ``function_api._dispatch_for_action`` — correct for the two
actions it named, but exactly the shape that let the original bug exist: a
third action needing its own dispatch function is only caught here if
whoever adds it also remembers to add a branch to this one file, which its
own adapter module never has to import or know about. D46 replaces the
if/elif with a declaration each adapter makes about itself
(``NEEDS_DISPATCH``, a required constant, not one an adapter can omit) plus
a lookup table (``function_api._DISPATCH_FUNCTIONS``) that
``_dispatch_for_action`` does nothing but consult. This file is what turns
"forgot to wire a new action's routing" into a red test here, rather than
something only a live end-to-end run (D45's own method) can find.

D46 also re-verified every *existing* action, not only the two D45 found
broken: ``network.scan``/``network.recon`` (nmap), ``web.get``, ``web.post``
and ``web.render`` all share the generic ``dispatch_scan`` path and always
have — confirmed by reading every commit that touched ``function_api.py``'s
dispatch call site (D34's web.post, D37's web.render) and finding the call
was always the single, unconditional ``dispatch_scan(...)`` it needed to be
for those five actions. There was never a second dispatch function for any
of them to be routed to incorrectly, which is also why this file's mutation
check (below) only demonstrates a red result for ``ad.collect``/
``code.scan`` — the other five have no way to fail it.

Mutation-verified, not merely believed: with ``_dispatch_for_action``'s body
temporarily reverted to the pre-D45 shape (unconditionally
``return dispatch_scan(conn, ...)``, ignoring the action entirely — the
exact defect D45 found and this file exists to catch),
``test_every_registered_action_routes_to_its_declared_dispatch_function``
failed for ``ad.collect`` and ``code.scan`` (both routed to ``dispatch_scan``
instead of their own declared function) and passed for every other action
(for which ``dispatch_scan`` genuinely is correct) — exactly the asymmetry
this module docstring's previous paragraph explains. The fix was then
restored and the full suite re-confirmed green before this file was
committed. The exact captured failure is quoted in this deliverable's own
completion report rather than duplicated here, matching
``tests/test_graph_queries_structure.py``'s own convention for recording a
manual mutation check.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

from control_plane.api import function_api
from control_plane.orchestrator.dispatch import (
    dispatch_code_scan,
    dispatch_collection,
    dispatch_scan,
)
from tool_gateway import registry

#: The only three dispatch functions that exist. Not read off
#: ``function_api._DISPATCH_FUNCTIONS`` itself -- that would make this file
#: check the table against a copy of itself. These are the same three
#: ``import``s ``function_api.py`` makes, so a fourth dispatch function
#: nobody imported here cannot silently pass either check below.
_KNOWN_DISPATCH_FUNCTIONS = {
    "dispatch_scan": dispatch_scan,
    "dispatch_collection": dispatch_collection,
    "dispatch_code_scan": dispatch_code_scan,
}

#: One (action, adapter) pair per entry in ``registry.ADAPTERS`` -- the
#: exhaustive, single source of truth for what action namespaces exist. A
#: newly registered action is automatically a new case in every
#: parametrized test below; nothing here has to be told about it separately.
_REGISTERED = sorted(registry.ADAPTERS.items(), key=lambda pair: pair[0])
_IDS = [action for action, _adapter in _REGISTERED]


class _RecordingDispatch:
    """Stands in for a real dispatch function inside this test only.

    Carries the real function's own signature (``__signature__``), so
    ``_dispatch_for_action``'s ``inspect.signature``-based kwarg filtering
    behaves exactly as it would against the function this stands in for --
    what is under test is the routing decision, not whether this stub
    happens to accept whatever it is given.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[dict] = []
        self.__signature__ = inspect.signature(_KNOWN_DISPATCH_FUNCTIONS[name])

    def __call__(self, conn, **kwargs):
        self.calls.append(kwargs)
        return f"SENTINEL-{self.name}"


@pytest.mark.parametrize("action,adapter", _REGISTERED, ids=_IDS)
def test_every_adapter_declares_its_dispatch_requirement(action, adapter):
    """No implicit default. An adapter that omits ``NEEDS_DISPATCH`` fails
    here, before it could ever be silently misrouted at dispatch time -- the
    same discipline ``WRITES_DATA``/``CHANGES_STATE``/``REQUIRES_PROXY``
    already enforce for every adapter (see ``nmap.py``'s own comment on
    those constants: "an adapter that simply omitted the constants would
    raise on the authorization path, which is not a failure mode any
    adapter should be able to introduce by being written incompletely").
    """
    assert hasattr(adapter, "NEEDS_DISPATCH"), (
        f"{adapter.__name__} (serving action {action!r}) does not declare "
        "NEEDS_DISPATCH -- propose_action has no way to know which dispatch "
        "function this action needs"
    )
    assert adapter.NEEDS_DISPATCH in _KNOWN_DISPATCH_FUNCTIONS, (
        f"{adapter.__name__}.NEEDS_DISPATCH == {adapter.NEEDS_DISPATCH!r} "
        f"names no real dispatch function; expected one of "
        f"{sorted(_KNOWN_DISPATCH_FUNCTIONS)}"
    )


@pytest.mark.parametrize("action,adapter", _REGISTERED, ids=_IDS)
def test_every_registered_action_routes_to_its_declared_dispatch_function(
    action, adapter, monkeypatch,
):
    """The cross-check the brief asked for: not "does the adapter say
    something", but "does what actually runs agree with what it says".

    Drives the real ``function_api._dispatch_for_action`` -- the same
    function ``propose_action`` calls -- for every currently-registered
    action, with every real dispatch function replaced by a stub that only
    records that it was reached. No database, no sandbox, no capability
    beyond the one attribute (``.action``) this routing decision reads.
    """
    stubs = {name: _RecordingDispatch(name) for name in _KNOWN_DISPATCH_FUNCTIONS}
    monkeypatch.setattr(function_api, "_DISPATCH_FUNCTIONS", stubs)

    capability = SimpleNamespace(action=action)
    result = function_api._dispatch_for_action(
        conn=object(), engagement_id="ENG-TEST", proposal_id="PROP-TEST",
        capability=capability, target="target", actor="tester",
        sandbox=None, network_allowlist=None, execution_context=None,
        proxy_url=None, ca_cert_pem=None, proxy_cert_spki=None,
    )

    expected = adapter.NEEDS_DISPATCH
    assert result == f"SENTINEL-{expected}", (
        f"action {action!r} (adapter {adapter.__name__}) declares "
        f"NEEDS_DISPATCH={expected!r}, but _dispatch_for_action actually "
        f"reached {result!r}"
    )
    for name, stub in stubs.items():
        if name == expected:
            assert len(stub.calls) == 1, (
                f"expected exactly one call to {name} for action {action!r}, "
                f"got {len(stub.calls)}"
            )
        else:
            assert stub.calls == [], (
                f"{name} was called for action {action!r}, but its adapter "
                f"declares NEEDS_DISPATCH={expected!r} -- two dispatch "
                "functions both ran, or the wrong one did"
            )


def test_dispatch_functions_table_is_exhaustive_over_known_names():
    """``function_api._DISPATCH_FUNCTIONS`` names exactly the three real
    dispatch functions -- not a subset (which would ``KeyError`` for some
    adapter's declared name) and not a superset (a fourth function nothing
    declares would be dead routing table, easy to mistake for reachable).
    """
    assert set(function_api._DISPATCH_FUNCTIONS) == set(_KNOWN_DISPATCH_FUNCTIONS)
    for name, fn in _KNOWN_DISPATCH_FUNCTIONS.items():
        assert function_api._DISPATCH_FUNCTIONS[name] is fn
