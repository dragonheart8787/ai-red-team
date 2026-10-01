"""The mechanical contract every registered tool adapter must meet (D53).

Six integrations rediscovered the same wiring mistakes one CI round at a time.
Each check below is one of them, made a test over ``registry.ADAPTERS`` so the
seventh tool meets it before CI does. The mechanics live in ``adapter_kit`` so a
*scaffolded, not-yet-registered* adapter can run the same checks.

What this file does not do: decide anything about a tool. It cannot tell whether
``WRITES_DATA = False`` is true, only that somebody stated it (a
``NotImplemented`` placeholder is not a ``bool``). See
``docs/NEW_TOOL_ONBOARDING.md`` §1 for the decisions that stay with a person.

Each historical failure a check descends from:

* image not built in CI ........ 8168084 (semgrep, D43), 203d8d6 (bloodhound, D49)
* host-probe ``tool_version`` .. ab2849a (semgrep, D43)
* constraint dropped ........... D37 (web port/path/scheme), D45 (ad.collect, code.scan)
* dispatch mis-routed .......... D45; ``NEEDS_DISPATCH`` itself is D46; that the function
                                 behind the name serves the adapter is D56 (found at D55)
* classification gate skipped .. D56: the action's spelling decides it, and nothing said so
* side-effect profile omitted .. D34 (``test_web_post.py`` also pins the bools)
"""

from __future__ import annotations

import pytest

from control_plane.api.function_api import execution_constraints
from tests import adapter_kit
from tool_gateway import registry

_REGISTERED = sorted(registry.ADAPTERS.items(), key=lambda pair: pair[0])
_IDS = [action for action, _ in _REGISTERED]


@pytest.mark.parametrize("action,adapter", _REGISTERED, ids=_IDS)
def test_every_adapter_meets_the_local_contract(action, adapter):
    problems = adapter_kit.adapter_violations(adapter, action=action)
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("action,adapter", _REGISTERED, ids=_IDS)
def test_every_adapter_is_wired_in_everywhere_a_new_tool_must_be(action, adapter):
    problems = adapter_kit.registration_violations(adapter, action=action)
    assert not problems, "\n".join(problems)


def test_no_two_actions_share_a_tool_name_across_different_modules():
    """``TOOL`` keys evidence prefixes and the fingerprint. Two modules claiming
    one name would make their runs indistinguishable. (``http_get`` and
    ``http_post`` deliberately share ``curl``: same binary, and the fingerprint's
    ``method`` param separates them.)"""
    owners: dict[str, set[str]] = {}
    for _action, adapter in _REGISTERED:
        owners.setdefault(adapter.TOOL, set()).add(adapter.__name__)
    shared = {tool: mods for tool, mods in owners.items() if len(mods) > 1}
    assert set(shared) <= {"curl"}, f"unexpected shared TOOL names: {shared}"


# ---------------------------------------------------------------------------
# Declared exceptions must stay true. An exception that outlives what it
# excuses is a silenced alarm.
# ---------------------------------------------------------------------------

def test_every_carry_exemption_is_still_needed():
    for (action, key), reason in adapter_kit.CARRY_EXEMPTIONS.items():
        adapter = registry.ADAPTERS[action]
        assert key in adapter_kit.keys_read(adapter, "constraints"), (
            f"({action!r}, {key!r}) is exempted but build_plan no longer reads it -- remove it"
        )
        carried = set(execution_constraints({"logical_identity": {}, key: "x"}, "h"))
        assert key not in carried, (
            f"({action!r}, {key!r}) is exempted as not carried, but execution_constraints now "
            f"carries it -- the exemption is stale, remove it"
        )
        assert reason.strip()


def test_every_tool_version_exemption_is_still_needed():
    for action, reason in adapter_kit.TOOL_VERSION_HOST_PROBE_EXEMPTIONS.items():
        adapter = registry.ADAPTERS[action]
        slug = adapter_kit.image_slug(adapter.IMAGE)
        assert (adapter_kit.IMAGES_DIR / f"{slug}.Dockerfile").exists(), (
            f"{action}: exemption but no Dockerfile"
        )
        assert adapter_kit._function_source_uses_host_probe(adapter.tool_version), (
            f"{action}: tool_version() no longer probes the host -- "
            "the exemption is stale, remove it"
        )
        assert reason.strip()


def test_every_multi_action_exemption_is_still_needed():
    for module_name in adapter_kit.MULTI_ACTION_ADAPTERS:
        served = [a for a, m in _REGISTERED if m.__name__ == module_name]
        assert len(served) > 1, f"{module_name} serves {served}: it is no longer multi-action"


# ---------------------------------------------------------------------------
# The checks must be able to fail. A contract test that has never been seen red
# proves nothing (the standing D27/D28 lesson), so each rule is shown to fire on
# a deliberately broken adapter.
# ---------------------------------------------------------------------------

class _Broken:
    """An adapter with every decision undecided and every wiring step missing."""

    __name__ = "broken_adapter"
    TOOL = "broken"
    ACTION = "broken.scan"
    WRITES_DATA = NotImplemented
    CHANGES_STATE = NotImplemented
    REQUIRES_PROXY = NotImplemented
    NEEDS_DISPATCH = "dispatch_nothing"
    IMAGE = "cyberorch/broken:local"

    class AdapterError(Exception):
        pass

    @staticmethod
    def build_plan(*, constraints, target):  # no `budget`
        return None

    @staticmethod
    def tool_version():
        return ""

    @staticmethod
    def derive_view(stdout, stderr):
        return {"untrusted_content": False}


def _as_module(cls):
    import types

    module = types.ModuleType("broken_adapter")
    for name, value in vars(cls).items():
        if not name.startswith("__"):
            setattr(module, name, value)
    return module


@pytest.mark.parametrize("needle", [
    "WRITES_DATA is NotImplemented",
    "CHANGES_STATE is NotImplemented",
    "REQUIRES_PROXY is NotImplemented",
    "NEEDS_DISPATCH 'dispatch_nothing'",
    "KNOWN_CLASSIFICATION is None",
    "AdapterError must be a ValueError subclass",
    "build_plan is missing keyword(s) ['budget']",
    "tool_version() must return a non-empty string",
    "untrusted_content: true",
])
def test_the_local_contract_fires_on_a_broken_adapter(needle):
    problems = adapter_kit.adapter_violations(_as_module(_Broken), action="broken.scan")
    assert any(needle in p for p in problems), problems


def test_the_registration_checks_fire_on_an_unregistered_adapter():
    problems = adapter_kit.registration_violations(_as_module(_Broken), action="broken.scan")
    text = "\n".join(problems)
    assert "registry.ADAPTERS['broken.scan'] is not this adapter" in text
    assert "EVIDENCE_PREFIX has no entry for TOOL 'broken'" in text
    assert "build_broken_image.sh" in text


# ---------------------------------------------------------------------------
# The threat-model gate: a tool added after D53 does not get in without its own
# analysis. It can verify the document exists and was decided, not that it is good.
# ---------------------------------------------------------------------------

def test_the_grandfathered_set_is_frozen():
    """The tools excused from the gate must be exactly the ones that existed at D53.
    Adding a name here is how the gate would be defeated; the test below then makes
    every registered tool outside the set prove it has a decided document."""
    assert adapter_kit.PRE_D53_TOOLS == {
        "nmap", "curl", "chromium", "bloodhound-python", "semgrep",
    }


def _fake_tool(name):
    import types

    module = types.ModuleType(f"fake_{name}")
    module.TOOL = name
    return module


def test_a_new_tool_without_a_document_is_refused(tmp_path):
    problems = adapter_kit.threat_model_violations(_fake_tool("gitleaks"), docs_dir=tmp_path)
    assert problems and "no docs/ADR_GITLEAKS.md" in problems[0]


@pytest.mark.parametrize("status", [
    "**proposed. Awaiting a decision before any implementation.**",
    "Draft -- not reviewed",
    "**investigation, Dnn. No code change.**",
])
def test_a_new_tool_whose_document_is_still_open_is_refused(tmp_path, status):
    (tmp_path / "ADR_GITLEAKS.md").write_text(f"# ADR: gitleaks\n\nStatus: {status}\n")
    problems = adapter_kit.threat_model_violations(_fake_tool("gitleaks"), docs_dir=tmp_path)
    assert problems and "still" in problems[0]


def test_a_new_tool_with_a_decided_document_passes(tmp_path):
    (tmp_path / "ADR_GITLEAKS.md").write_text(
        "# ADR: gitleaks\n\nStatus: **accepted, D60 -- Option A.**\n"
    )
    assert adapter_kit.threat_model_violations(_fake_tool("gitleaks"), docs_dir=tmp_path) == []


def test_a_document_with_no_status_line_is_refused(tmp_path):
    (tmp_path / "ADR_GITLEAKS.md").write_text("# ADR: gitleaks\n\nJust some notes.\n")
    problems = adapter_kit.threat_model_violations(_fake_tool("gitleaks"), docs_dir=tmp_path)
    assert problems and "no 'Status:' line" in problems[0]


def test_a_hyphenated_tool_name_maps_to_an_underscored_file(tmp_path):
    problems = adapter_kit.threat_model_violations(_fake_tool("my-tool"), docs_dir=tmp_path)
    assert "docs/ADR_MY_TOOL.md" in problems[0]


def test_the_existing_tools_are_exempt_and_the_gate_reads_nothing_for_them():
    for _action, adapter in _REGISTERED:
        assert adapter_kit.threat_model_violations(adapter) == []


# ---------------------------------------------------------------------------
# D56 -- NEEDS_DISPATCH is checked by what is behind the name, not the name
# ---------------------------------------------------------------------------
# D53's checks verified that ``NEEDS_DISPATCH`` names a real function that
# ``_DISPATCH_FUNCTIONS`` maps. D55 then routed a second tool to
# ``dispatch_code_scan``, which was hard-wired to Semgrep, and every one of those
# checks stayed green. These tests are what would have failed.

@pytest.mark.parametrize("action,adapter", _REGISTERED, ids=_IDS)
def test_the_function_behind_needs_dispatch_serves_the_adapter(action, adapter):
    problems = adapter_kit.dispatch_violations(adapter, action=action)
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("action,adapter", _REGISTERED, ids=_IDS)
def test_the_probe_really_reaches_the_adapters_own_build_plan(action, adapter):
    """The behavioural check is not vacuous: for every action it can reach, it reaches
    *that adapter's* ``build_plan``. ``ad.collect`` is the declared exception -- its
    function stops at the credential check first, so the static check carries it."""
    reached, audits, error = adapter_kit.probe_dispatch(action)
    assert error is None, error
    if action == "ad.collect":
        assert reached is None
        assert [a["reasons"] for a in audits] == [("unbuildable_plan",)]
    else:
        assert reached == adapter.__name__, (action, reached)
        assert audits == []


def _mutated_dispatch_code_scan(tmp_path, monkeypatch):
    """The real ``dispatch_code_scan`` with D55's fix put back the way it was.

    Built from the tree's own source, so it is the function as it is with exactly one
    change: ``adapter = semgrep`` instead of resolving the adapter from the action.
    """
    import inspect
    import textwrap
    import types

    from control_plane.api import function_api
    from control_plane.orchestrator import dispatch

    source = textwrap.dedent(inspect.getsource(dispatch.dispatch_code_scan))
    fixed = (
        "adapter = registry.adapter_for(capability.action)\n"
        "    if adapter is None or getattr(adapter, \"NEEDS_DISPATCH\", None) "
        "!= \"dispatch_code_scan\":"
    )
    assert source.count(fixed) == 1, "the D55 resolution is not where this test expects it"
    old = source.replace(fixed, "adapter = semgrep\n    if capability.action != adapter.ACTION:")
    path = tmp_path / "old_dispatch_code_scan.py"
    path.write_text(old)
    scratch = dict(vars(dispatch))
    exec(compile(old, str(path), "exec"), scratch)  # noqa: S102 - test-only, our own source
    built = scratch["dispatch_code_scan"]
    # Rebind to the module's *live* globals, so the probe's patches (and every helper
    # the function calls) are the real ones -- the function is otherwise byte-for-byte
    # the tree's own, with its source file on disk for `inspect`.
    old_function = types.FunctionType(
        built.__code__, vars(dispatch), built.__name__, built.__defaults__, built.__closure__,
    )
    old_function.__kwdefaults__ = built.__kwdefaults__
    monkeypatch.setitem(function_api._DISPATCH_FUNCTIONS, "dispatch_code_scan", old_function)


def test_the_d55_case_is_caught_and_the_d53_checks_alone_do_not_catch_it(tmp_path, monkeypatch):
    """dispatch_code_scan hard-wired to Semgrep again. Gitleaks is routed to it."""
    from tool_gateway.adapters import gitleaks, semgrep

    _mutated_dispatch_code_scan(tmp_path, monkeypatch)

    # What D53 checked -- the name resolves, the local contract holds -- is still green:
    assert adapter_kit.adapter_violations(gitleaks, action=gitleaks.ACTION) == []
    assert adapter_kit.adapter_violations(semgrep, action=semgrep.ACTION) == []
    # ...and Semgrep, whom the function *is* bound to, is still fine:
    assert adapter_kit.dispatch_violations(semgrep, action=semgrep.ACTION) == []

    # What D56 checks is red, on both independent grounds:
    problems = adapter_kit.dispatch_violations(gitleaks, action=gitleaks.ACTION)
    text = "\n".join(problems)
    assert "bound to ['semgrep'] by name" in text
    assert "refuses 'code.secrets' as 'no_adapter_for_action'" in text
    assert adapter_kit.registration_violations(gitleaks, action=gitleaks.ACTION), (
        "the wired-in check every tool already runs must go red too"
    )


def test_the_probe_alone_catches_a_function_that_hides_its_binding(monkeypatch):
    """Without the static check: a function that resolves ``semgrep`` dynamically names no
    adapter, and never refuses -- it just runs the wrong tool. Only the probe sees it."""
    import sys

    from control_plane.api import function_api
    from tool_gateway.adapters import gitleaks

    def _hides(conn, *, capability, **_):
        module = sys.modules["tool_gateway.adapters." + "sem" + "grep"]
        module.build_plan(constraints={}, budget={}, target="x#main")

    monkeypatch.setitem(function_api._DISPATCH_FUNCTIONS, "dispatch_code_scan", _hides)
    assert adapter_kit._adapter_modules_bound_by(_hides) == set()
    problems = adapter_kit.dispatch_violations(gitleaks, action=gitleaks.ACTION)
    assert any("ran tool_gateway.adapters.semgrep.build_plan" in p for p in problems), problems


def test_the_static_check_alone_catches_a_binding_the_probe_never_reaches(monkeypatch):
    """Without the probe: an adapter named only on a path the probe does not take."""
    from control_plane.api import function_api
    from control_plane.orchestrator import dispatch
    from tool_gateway.adapters import gitleaks, semgrep

    def _dormant(conn, *, capability, **_):
        adapter = dispatch.registry.adapter_for(capability.action)
        if capability.action == "never.probed":
            adapter = semgrep
        adapter.build_plan(constraints={}, budget={}, target="x#main")

    monkeypatch.setitem(function_api._DISPATCH_FUNCTIONS, "dispatch_code_scan", _dormant)
    problems = adapter_kit.dispatch_violations(gitleaks, action=gitleaks.ACTION)
    assert any("bound to ['semgrep'] by name" in p for p in problems), problems
    assert not any("ran " in p or "refuses" in p for p in problems), "the probe is clean here"


def test_a_binding_hidden_in_a_helper_is_followed(monkeypatch):
    from control_plane.api import function_api
    from control_plane.orchestrator import dispatch
    from tool_gateway.adapters import gitleaks, semgrep

    def _helper():
        return semgrep

    _helper.__module__ = dispatch.__name__
    monkeypatch.setattr(dispatch, "_d56_helper", _helper, raising=False)

    def _via_helper(conn, *, capability, **_):
        _d56_helper().build_plan(constraints={}, budget={}, target="x#main")  # noqa: F821

    _via_helper.__globals__["_d56_helper"] = _helper
    monkeypatch.setitem(function_api._DISPATCH_FUNCTIONS, "dispatch_code_scan", _via_helper)
    assert adapter_kit._adapter_modules_bound_by(_via_helper) == {"semgrep"}
    assert any(
        "bound to ['semgrep']" in p
        for p in adapter_kit.dispatch_violations(gitleaks, action=gitleaks.ACTION)
    )


def test_a_dispatch_function_that_cannot_be_probed_is_reported_not_skipped(monkeypatch):
    from control_plane.api import function_api
    from tool_gateway.adapters import gitleaks

    def _needs_a_database(conn, *, capability, **_):
        raise RuntimeError("needs a real connection")

    monkeypatch.setitem(function_api._DISPATCH_FUNCTIONS, "dispatch_code_scan", _needs_a_database)
    problems = adapter_kit.dispatch_violations(gitleaks, action=gitleaks.ACTION)
    assert any("probing 'dispatch_code_scan' raised RuntimeError" in p for p in problems)


# ---------------------------------------------------------------------------
# D56 -- the action's name is a classification decision, made on the record
# ---------------------------------------------------------------------------

def _classified(action, declared, *, writes=False, changes=False):
    import types

    module = types.ModuleType("fake_classified")
    module.WRITES_DATA, module.CHANGES_STATE = writes, changes
    module.KNOWN_CLASSIFICATION = declared
    return module, action


EXEMPT = "exempt: reads a public banner fragment, not a resource's content"


@pytest.mark.parametrize("action,adapter", _REGISTERED, ids=_IDS)
def test_every_adapter_states_its_classification_position_and_the_rule_agrees(action, adapter):
    assert adapter_kit.adapter_violations(adapter, action=action) == []
    assert adapter_kit.classification_violations(adapter, action=action) == []


def test_the_rule_is_asked_of_opa_not_copied_into_python():
    ask = adapter_kit.rego_requires_known_classification
    assert ask("code.secrets") is True and ask("web.get") is True
    assert ask("secrets.scan") is False and ask("network.scan") is False
    assert ask("secrets.scan", True, False) is True, "a writing action triggers it regardless"
    assert ask("secrets.scan", False, True) is True


def test_an_example_name_used_without_confirming_it_is_caught():
    """The scaffold's old example, ``secrets.scan``, taken at face value: the adapter says
    it needs a classification, and the rule -- which keys on the spelling -- never asks."""
    module, action = _classified("secrets.scan", "required")
    problems = adapter_kit.classification_violations(module, action=action)
    assert len(problems) == 1
    assert "'required' but authz.rego does NOT require" in problems[0]
    assert "silently never applies" in problems[0]
    assert "'secrets.scan'" in problems[0]


def test_the_same_name_confirmed_on_purpose_is_accepted():
    module, action = _classified("secrets.scan", EXEMPT)
    assert adapter_kit.classification_violations(module, action=action) == []


def test_a_name_the_rule_covers_needs_no_exemption_and_forbids_a_false_one():
    module, action = _classified("code.secrets", "required")
    assert adapter_kit.classification_violations(module, action=action) == []
    module, action = _classified("code.secrets", EXEMPT)
    problems = adapter_kit.classification_violations(module, action=action)
    assert problems and "the exemption is not in force" in problems[0]
    assert "because of the action's name" in problems[0]


def test_an_exemption_that_a_writing_tool_cannot_have_is_named_as_such():
    module, action = _classified("secrets.scan", EXEMPT, writes=True)
    problems = adapter_kit.classification_violations(module, action=action)
    assert problems and "because the adapter writes data or changes state" in problems[0]


@pytest.mark.parametrize("declared", [
    NotImplemented, None, "", "REQUIRED", "yes", True, "exempt", "exempt:", "exempt: n/a",
    "exempt: TODO decide",
])
def test_an_undecided_or_ceremonial_answer_is_not_an_answer(declared):
    module, action = _classified("secrets.scan", declared)
    module.NEEDS_DISPATCH = "dispatch_scan"
    problems = adapter_kit.adapter_violations(module, action=action)
    assert any("KNOWN_CLASSIFICATION" in p for p in problems), (declared, problems)
    assert adapter_kit.classification_violations(module, action=action) == [], (
        "an undecided declaration is reported once, by the local contract"
    )


def test_when_opa_cannot_be_run_the_action_is_unconfirmed_not_assumed_fine(monkeypatch):
    module, action = _classified("secrets.scan", EXEMPT)
    adapter_kit.rego_requires_known_classification.cache_clear()
    monkeypatch.setattr(adapter_kit.shutil, "which", lambda name: None)
    try:
        problems = adapter_kit.classification_violations(module, action=action)
    finally:
        adapter_kit.rego_requires_known_classification.cache_clear()
    assert problems and "cannot evaluate authz.rego" in problems[0]


def test_the_classification_check_is_part_of_the_registration_checks(monkeypatch):
    """So it runs for every tool through the wiring test and ``--check``, not only here."""
    from tool_gateway.adapters import gitleaks

    monkeypatch.setattr(gitleaks, "KNOWN_CLASSIFICATION", EXEMPT)
    text = "\n".join(adapter_kit.registration_violations(gitleaks, action=gitleaks.ACTION))
    assert "the exemption is not in force" in text
