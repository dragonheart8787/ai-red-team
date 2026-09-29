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
* dispatch mis-routed .......... D45; ``NEEDS_DISPATCH`` itself is D46
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
