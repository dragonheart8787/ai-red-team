"""Reusable mechanics for the checks every tool adapter has to pass (D53).

Six integrations (nmap, web.get, web.post, web.render, ad.collect, code.scan)
each rediscovered the same wiring mistakes one CI round at a time: an image no
workflow built, a ``tool_version()`` that probed a host binary that only exists
inside a container, a constraint ``execution_constraints`` silently dropped, a
fingerprint missing an input. This module is those lessons as functions, so a
new adapter meets them before CI does.

What this module is **not** (``docs/NEW_TOOL_ONBOARDING.md`` §1)
----------------------------------------------------------------
It decides nothing about how a tool is authorized or constrained. Whether an
action needs a known classification, what a scope object for the tool's target
means, how much of its output a model may read, whether the tool may touch the
network -- every one of those is a per-tool judgement that
``docs/templates/ADR_NEW_TOOL_TEMPLATE.md`` makes a person write down. These
checks only verify that the *code* agrees with itself and with the rest of the
system once those decisions exist. A green result here says the plumbing is
consistent, never that the decisions were right.

Two tiers
---------
* :func:`adapter_violations` / :func:`registration_violations` need nothing
  from the tool's author: they are the same for every adapter, and run over
  ``registry.ADAPTERS`` in ``tests/test_adapter_contract.py``.
* :func:`fingerprint_violations` and :func:`lure_violations` need a sample the
  author supplies (a working ``build_plan`` input, a lure-bearing output),
  because only the author knows what a valid one looks like. The scaffold
  (``scripts/new_tool_scaffold.py``) generates the test that calls them.

Every function returns a list of human-readable violations rather than
asserting, so one run reports everything wrong instead of the first thing.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import re
import textwrap
from collections.abc import Callable, Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
IMAGES_DIR = REPO_ROOT / "tool_gateway" / "images"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "test.yml"

_IMAGE_NAME = re.compile(r"^cyberorch/([a-z0-9][a-z0-9-]*):local$")

# ---------------------------------------------------------------------------
# Declared exceptions. Each one carries its reason, and each one is checked for
# staleness in tests/test_adapter_contract.py, so an exception cannot outlive
# the thing it excuses.
# ---------------------------------------------------------------------------

#: Modules that serve more than one action and so declare no single ``ACTION``.
MULTI_ACTION_ADAPTERS: Mapping[str, str] = {
    "tool_gateway.adapters.nmap":
        "serves both network.scan and network.recon (D6); the registry maps each",
}

#: ``(action, constraint key)`` pairs that ``build_plan`` reads but that
#: ``execution_constraints`` does not carry from a proposal. The first four are
#: benign; the ``web.post`` body/content_type pair is a **known gap**, recorded
#: as ACCEPTANCE 5.29 -- it is here so the suite stays honest, not so it stays
#: quiet.
CARRY_EXEMPTIONS: Mapping[tuple[str, str], str] = {
    ("web.get", "method"):
        "validation only: an absent method means this adapter's own GET, so "
        "there is nothing a proposal needs to carry",
    ("web.post", "method"):
        "validation only: an absent method means this adapter's own POST",
    ("web.post", "body"):
        "KNOWN GAP (ACCEPTANCE 5.29): no proposal field can supply a body and "
        "execution_constraints does not carry one, so a web.post capability "
        "issued through propose_action can never build a plan",
    ("web.post", "content_type"):
        "KNOWN GAP (ACCEPTANCE 5.29): same as body -- not carried",
    ("ad.collect", "max_queries_issued"):
        "carried by budget.tool.max_queries_issued instead; the constraint "
        "spelling is an alternative nothing derives from a proposal",
}

#: Actions whose adapter runs in its own Dockerfile-built image but whose
#: ``tool_version()`` still probes a host binary. A **known gap**, recorded as
#: ACCEPTANCE 5.30 (the D43 ``ab2849a`` defect, still present in ad_collector).
TOOL_VERSION_HOST_PROBE_EXEMPTIONS: Mapping[str, str] = {
    "ad.collect":
        "KNOWN GAP (ACCEPTANCE 5.30): tool_version() shells out to a "
        "bloodhound-python that exists only inside the image, so the control "
        "plane reports 'unknown' and a tool upgrade cannot change the "
        "fingerprint",
}

#: Filled in when a ``derive_view`` needs a keyword the smoke call cannot invent.
DERIVE_VIEW_ARG_FILL: Mapping[str, Any] = {
    "repo_local_path": "/nonexistent-d53-smoke-path",
}


#: The ``TOOL`` names that existed before D53 and are grandfathered from the
#: threat-model-document gate below: their analyses live in ADRs and acceptance
#: documents written under other names (ADR_SEMGREP, ADR_BLOODHOUND_NEO4J, the
#: Web Agent review). **Nothing may be added here.** A tool added after D53 gets
#: its own ``docs/ADR_<TOOL>.md``; growing this set is how the gate would be
#: quietly defeated, so ``test_the_grandfathered_set_is_frozen`` pins its size.
PRE_D53_TOOLS: frozenset[str] = frozenset(
    {"nmap", "curl", "chromium", "bloodhound-python", "semgrep"}
)


def threat_model_violations(adapter: ModuleType, *, docs_dir: Path | None = None) -> list[str]:
    """A tool added after D53 has a threat-model document, and it has been decided.

    This checks that the artifact **exists and has left "proposed"** -- a decision
    was recorded. It cannot check that the analysis in it is any good, and does not
    pretend to: ``docs/templates/ADR_NEW_TOOL_TEMPLATE.md`` is what forces the
    questions, review is what judges the answers. What the gate does is make
    *skipping* the analysis a red CI run instead of something nobody notices --
    the alternative to a scaffold that would let a tool be added without anyone
    ever asking what its data is.
    """
    tool = getattr(adapter, "TOOL", None)
    if not isinstance(tool, str) or tool in PRE_D53_TOOLS:
        return []
    docs = docs_dir or REPO_ROOT / "docs"
    path = docs / f"ADR_{tool.upper().replace('-', '_')}.md"
    where = f"docs/{path.name}"
    if not path.exists():
        return [
            f"{adapter.__name__}: no {where}. Every tool gets its own threat-model analysis "
            "before it is registered (docs/NEW_TOOL_ONBOARDING.md §1); start from "
            "docs/templates/ADR_NEW_TOOL_TEMPLATE.md"
        ]
    head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:40])
    status = re.search(r"^Status:\s*(.*)$", head, re.M)
    if not status:
        return [f"{adapter.__name__}: {where} has no 'Status:' line in its first 40 lines"]
    if re.match(r"\W*(proposed|draft|investigation)\b", status.group(1), re.I):
        return [
            f"{adapter.__name__}: {where} is still '{status.group(1).strip()[:40]}...'. Register a "
            "tool once its decisions are made and recorded, not while they are open"
        ]
    return []


# ---------------------------------------------------------------------------
# Source inspection
# ---------------------------------------------------------------------------

def _helper_modules(adapter: ModuleType) -> list[ModuleType]:
    """The adapter plus the shared adapter helpers it delegates to (e.g. ``_http``).

    ``http_get`` reads ``port``/``path``/``scheme`` inside ``_http``, not in its
    own body, so scanning the adapter file alone would report a tool as reading
    fewer constraints than it does.
    """
    mods = [adapter]
    for value in vars(adapter).values():
        if (
            isinstance(value, ModuleType)
            and value is not adapter
            and value.__name__.startswith("tool_gateway.adapters.")
        ):
            mods.append(value)
    return mods


def keys_read(adapter: ModuleType, param: str) -> set[str]:
    """Literal keys read off a mapping parameter named ``param`` (``constraints``/``budget``).

    ``param.get("k")`` and ``param["k"]``. Leading-underscore keys are the
    adapter talking to itself (``_http`` injects ``_target``) and are ignored:
    a proposal can never supply them, so they are not part of the contract.
    """
    found: set[str] = set()
    for module in _helper_modules(adapter):
        try:
            source = inspect.getsource(module)
        except (TypeError, OSError):
            # A module assembled in memory (the deliberately broken adapter in the
            # contract test's own negative controls) has no file; its build_plan does.
            source = inspect.getsource(module.build_plan) if hasattr(module, "build_plan") else ""
        tree = ast.parse(textwrap.dedent(source))
        for node in ast.walk(tree):
            key: Any = None
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == param
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                key = node.args[0].value
            elif (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id == param
                and isinstance(node.slice, ast.Constant)
            ):
                key = node.slice.value
            if isinstance(key, str) and not key.startswith("_"):
                found.add(key)
    return found


def _function_source_uses_host_probe(func: Callable[..., Any]) -> bool:
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    for node in ast.walk(tree):
        probe = {"which", "run", "check_output", "Popen"}
        if isinstance(node, ast.Attribute) and node.attr in probe:
            if isinstance(node.value, ast.Name) and node.value.id in {"shutil", "subprocess"}:
                return True
    return False


def image_slug(image: str) -> str | None:
    match = _IMAGE_NAME.match(image)
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# Tier 1a -- the adapter, on its own
# ---------------------------------------------------------------------------

def adapter_violations(adapter: ModuleType, *, action: str | None = None) -> list[str]:
    """Checks that need nothing but the module. A scaffold that has not had its
    decisions filled in fails here, on purpose: every ``DECIDE`` placeholder is
    ``NotImplemented``, which is not a ``bool``.
    """
    from control_plane.api import function_api
    from control_plane.orchestrator import dispatch

    name = adapter.__name__
    out: list[str] = []

    tool = getattr(adapter, "TOOL", None)
    if not isinstance(tool, str) or not tool:
        out.append(f"{name}: TOOL must be a non-empty string (dispatch records it on every run)")

    declared = getattr(adapter, "ACTION", None)
    if declared is None:
        if name not in MULTI_ACTION_ADAPTERS:
            out.append(f"{name}: declares no ACTION and is not a listed multi-action adapter")
    elif not isinstance(declared, str) or not declared:
        out.append(f"{name}: ACTION must be a non-empty string")
    elif action is not None and declared != action:
        out.append(
            f"{name}: ACTION {declared!r} differs from the action it is registered under "
            f"({action!r})"
        )

    for const in ("WRITES_DATA", "CHANGES_STATE", "REQUIRES_PROXY"):
        value = getattr(adapter, const, None)
        if not isinstance(value, bool):
            out.append(
                f"{name}: {const} is {value!r}, not a bool. This is a decision about the "
                "tool (docs/NEW_TOOL_ONBOARDING.md §3), never a default -- a wrong False "
                "understates what the tool does to a target"
            )

    needs = getattr(adapter, "NEEDS_DISPATCH", None)
    real_function = callable(getattr(dispatch, str(needs), None))
    if needs not in function_api._DISPATCH_FUNCTIONS or not real_function:
        out.append(
            f"{name}: NEEDS_DISPATCH {needs!r} names no dispatch function "
            f"(known: {sorted(function_api._DISPATCH_FUNCTIONS)})"
        )

    error = getattr(adapter, "AdapterError", None)
    if not (inspect.isclass(error) and issubclass(error, ValueError)):
        out.append(
            f"{name}: AdapterError must be a ValueError subclass "
            "(dispatch catches it to refuse a plan)"
        )

    build = getattr(adapter, "build_plan", None)
    if not callable(build):
        out.append(f"{name}: no build_plan")
    else:
        params = inspect.signature(build).parameters
        missing = {"constraints", "budget", "target"} - set(params)
        if missing:
            out.append(f"{name}: build_plan is missing keyword(s) {sorted(missing)}")

    version = getattr(adapter, "tool_version", None)
    if not callable(version):
        out.append(f"{name}: no tool_version")
    else:
        try:
            reported = version()
        except Exception as exc:  # noqa: BLE001 - a raising probe is itself the finding
            out.append(f"{name}: tool_version() raised {type(exc).__name__}: {exc}")
        else:
            if not isinstance(reported, str) or not reported:
                out.append(f"{name}: tool_version() must return a non-empty string")
        image = getattr(adapter, "IMAGE", None)
        slug = image_slug(image) if isinstance(image, str) else None
        own_dockerfile = slug is not None and (IMAGES_DIR / f"{slug}.Dockerfile").exists()
        exempt = declared in TOOL_VERSION_HOST_PROBE_EXEMPTIONS
        if own_dockerfile and not exempt and _function_source_uses_host_probe(version):
            out.append(
                f"{name}: runs in its own Dockerfile image ({image}) but tool_version() probes a "
                "host binary. The control plane is not the sandbox: the probe returns 'unknown' "
                "and the fingerprint cannot see a tool upgrade. Return the pinned version "
                "constant (D43 ab2849a)"
            )

    image = getattr(adapter, "IMAGE", None)
    if image is not None and image_slug(image) is None:
        out.append(f"{name}: IMAGE {image!r} is not of the form cyberorch/<name>:local")

    tmpfs = getattr(adapter, "TMPFS", None)
    if tmpfs is not None and not (
        isinstance(tmpfs, Mapping)
        and all(isinstance(k, str) and isinstance(v, str) for k, v in tmpfs.items())
    ):
        out.append(f"{name}: TMPFS must map path -> mount options")

    out.extend(_derive_view_violations(adapter))
    return out


def _derive_view_violations(adapter: ModuleType) -> list[str]:
    name = adapter.__name__
    derive = getattr(adapter, "derive_view", None)
    if not callable(derive):
        return [f"{name}: no derive_view"]

    kwargs: dict[str, Any] = {}
    for pname, param in list(inspect.signature(derive).parameters.items())[2:]:
        if param.default is inspect.Parameter.empty:
            if pname not in DERIVE_VIEW_ARG_FILL:
                return [
                    f"{name}: derive_view needs {pname!r}; "
                    "add it to adapter_kit.DERIVE_VIEW_ARG_FILL"
                ]
            kwargs[pname] = DERIVE_VIEW_ARG_FILL[pname]
    try:
        view = derive("", "", **kwargs)
    except Exception as exc:  # noqa: BLE001
        return [
            f"{name}: derive_view raised {type(exc).__name__} on empty output ({exc}). A killed "
            "or failed tool prints nothing, and evidence must still be recorded"
        ]
    problems: list[str] = []
    if not isinstance(view, Mapping) or view.get("untrusted_content") is not True:
        problems.append(
            f"{name}: derive_view must return a mapping with untrusted_content: true "
            "(§4.4/§8.1; the evidence store refuses anything else at write time)"
        )
    try:
        json.dumps(view, default=str)
    except (TypeError, ValueError) as exc:
        problems.append(f"{name}: derive_view result is not JSON-serialisable ({exc})")
    return problems


# ---------------------------------------------------------------------------
# Tier 1b -- the adapter, as registered
# ---------------------------------------------------------------------------

def registration_violations(adapter: ModuleType, *, action: str) -> list[str]:
    """Checks that the places a new tool must be wired in agree with the adapter."""
    from control_plane.api.function_api import execution_constraints
    from control_plane.orchestrator import dispatch
    from tool_gateway import registry

    name = adapter.__name__
    out: list[str] = []

    if registry.ADAPTERS.get(action) is not adapter:
        out.append(f"{name}: tool_gateway.registry.ADAPTERS[{action!r}] is not this adapter")

    tool = getattr(adapter, "TOOL", None)
    if tool not in dispatch.EVIDENCE_PREFIX:
        out.append(
            f"{name}: dispatch.EVIDENCE_PREFIX has no entry for TOOL {tool!r}. Evidence ids fall "
            "back to 'TOOL-...' silently, so an id stops saying what produced it"
        )

    out.extend(threat_model_violations(adapter))

    image = getattr(adapter, "IMAGE", None)
    slug = image_slug(image) if isinstance(image, str) else None
    if slug is not None:
        script = f"build_{slug}_image.sh"
        if not (IMAGES_DIR / script).exists():
            out.append(f"{name}: IMAGE {image} has no tool_gateway/images/{script}")
        if script not in CI_WORKFLOW.read_text(encoding="utf-8"):
            out.append(
                f"{name}: .github/workflows/test.yml never runs {script}. Real-container "
                "tests fail on the runner rather than skip (forgotten for semgrep at D43 "
                "and for bloodhound at D49)"
            )

    carried = set(execution_constraints({"logical_identity": {}, **{
        k: "x" for k in keys_read(adapter, "constraints")
    }}, "h"))
    for key in sorted(keys_read(adapter, "constraints") - carried):
        if (action, key) not in CARRY_EXEMPTIONS:
            out.append(
                f"{name}: build_plan reads constraint {key!r} but "
                "function_api.execution_constraints does not carry it from a proposal, so it "
                "is silently dropped on the real path (the D37 and D45 defect). Carry it "
                "there, or declare it in adapter_kit.CARRY_EXEMPTIONS with the reason"
            )
    return out


# ---------------------------------------------------------------------------
# Tier 2 -- needs a sample from the tool's author
# ---------------------------------------------------------------------------

def fingerprint_violations(
    adapter: ModuleType,
    *,
    base: Mapping[str, Any],
    vary: Mapping[str, Any],
    not_in_fingerprint: Mapping[str, str],
) -> list[str]:
    """Every input ``build_plan`` reads is either in ``as_params`` or *declared* out of it.

    ``base`` is a working ``build_plan`` call (``constraints=``, ``budget=``,
    ``target=``). ``vary`` maps **every** input the author accounts for --
    ``"constraints.<key>"``, ``"budget.<key>"`` or ``"target"`` -- to a
    *different valid* value. ``not_in_fingerprint`` marks the subset that is
    deliberately *not* a fingerprint dimension, with the reason.

    Pinned both ways, the D11-3 way: a varied input that changes the plan but
    not ``as_params`` is a false-negative dedup (the second scan is skipped as
    done); a declared-excluded input that *does* change ``as_params`` means the
    declaration has rotted. Either direction fails. And completeness is checked
    against the source: an input ``build_plan`` reads that the test does not
    mention fails, so adding a constraint later cannot silently escape the
    fingerprint.
    """
    out: list[str] = []
    build = adapter.build_plan
    name = adapter.__name__

    for param in ("constraints", "budget"):
        for key in sorted(keys_read(adapter, param)):
            if f"{param}.{key}" not in vary:
                out.append(
                    f"{name}: build_plan reads {param}[{key!r}] and the fingerprint test does not "
                    "account for it. Add it to vary (with a different valid value), and to "
                    "not_in_fingerprint too if it deliberately does not change what the tool does"
                )
    for key, reason in not_in_fingerprint.items():
        if not str(reason).strip():
            out.append(f"{name}: not_in_fingerprint[{key!r}] has no reason")
        if key not in vary:
            out.append(
                f"{name}: not_in_fingerprint[{key!r}] has no alternate value in vary to test with"
            )

    def _call(overrides: Mapping[str, Any]) -> Any:
        kwargs = {k: (dict(v) if isinstance(v, Mapping) else v) for k, v in base.items()}
        for dotted, value in overrides.items():
            if dotted == "target":
                kwargs["target"] = value
            else:
                section, key = dotted.split(".", 1)
                kwargs[section][key] = value
        return build(**kwargs)

    baseline = _call({})
    for dotted, value in vary.items():
        changed = _call({dotted: value})
        same_params = changed.as_params() == baseline.as_params()
        plan_differs = _plan_fields(changed) != _plan_fields(baseline)
        if dotted in not_in_fingerprint:
            if not same_params:
                out.append(
                    f"{name}: {dotted} is declared out of the fingerprint but changes as_params()"
                )
        else:
            if plan_differs and same_params:
                out.append(
                    f"{name}: changing {dotted} changes the built plan but not as_params(), so a "
                    "second run with a different value would dedup into the first and be skipped "
                    "(D11-3)"
                )
            if not plan_differs:
                out.append(
                    f"{name}: changing {dotted} changes nothing in the plan -- "
                    "a dead input, or a bad sample"
                )
    return out


def _plan_fields(plan: Any) -> Any:
    return dataclasses.asdict(plan) if dataclasses.is_dataclass(plan) else vars(plan)


def lure_violations(
    *,
    evidence_text: str,
    lure: str,
    established: str,
    lure_type: str = "ip",
    established_type: str = "ip",
    source: str = "tool_observed",
) -> list[str]:
    """A target named only in a tool's untrusted output must be marked introduced.

    The mechanical half of the injection series (D13, D31, D34, D37, and the
    missing one for ``code.scan``): feed the tool's *own* evidence text through
    the D20 provenance computation and confirm the lure is marked
    ``introduced_by_untrusted`` while the host the tool genuinely observed is
    not. The other half -- that no scope object results -- is
    :func:`assert_lure_refused_by_authorization`. Neither half is the point
    alone; together they are Discovery ⊥ Authorization (I8).

    Note (ACCEPTANCE 5.28): nothing in production builds this ``Observation``
    yet, so this verifies the computation on a hand-built one, exactly as
    D31/D34/D37 did. It does not verify a harness.
    """
    from agents.llm.worker_base import Observation, ScopeCandidate, _discovery_provenance

    observation = Observation(
        source=source, description="d53 lure carrier", content=evidence_text,
        evidence_id="EV-D53", run_id="RUN-D53", observed_identities=(established,),
    )
    scope = ScopeCandidate("SCOPE-D53", established_type, established, ("*",))

    def _provenance(value: str, kind: str) -> dict[str, Any]:
        return _discovery_provenance(
            {"logical_identity": {"type": kind, "value": value}}, (scope,), (observation,)
        )

    out: list[str] = []
    if _provenance(lure, lure_type)["introduced_by_untrusted"] is not True:
        out.append(
            f"lure {lure!r} appears in the tool's evidence but is not marked "
            "introduced_by_untrusted"
        )
    if _provenance(established, established_type)["introduced_by_untrusted"] is not False:
        out.append(
            f"{established!r} was observed by the tool but is marked introduced_by_untrusted"
        )
    return out


def assert_lure_refused_by_authorization(
    engagement_id: str, registry: Any, *, action: str, established_ip: str,
    lure_ip: str, allowed_cidr: str,
) -> None:
    """The authorization half (I8): naming the lure changes nothing about scope.

    Mirrors ``tests/test_http_get.py::test_a_lure_address_cannot_be_authorized``
    for a tool of the caller's choosing. ``registry`` is the fixture from
    ``tests/conftest.py``.
    """
    from control_plane.canonicalizer.authorization import resolve_authorization
    from control_plane.canonicalizer.target import normalize_target
    from control_plane.state.db import engagement_scope

    scope_id = f"SCOPE-{engagement_id[-10:]}"
    registry.scope(
        scope_object_id=scope_id, type="cidr", value=allowed_cidr, allowed_actions=[action]
    )
    with engagement_scope(engagement_id) as conn:
        def _resolve(ip: str) -> Any:
            return resolve_authorization(
                conn,
                target=normalize_target({"logical_identity": {"type": "ip", "value": ip}}),
                action=action,
                authorization={"source": "engagement_scope", "scope_object_id": scope_id},
            )

        assert _resolve(established_ip).authorized is True, (
            "the control: the in-scope host must authorize"
        )
        assert _resolve(lure_ip).authorized is False, (
            "a lure named in tool output gained authorization"
        )
