"""Four ways to run one Policy Reviewer, held to one contract (D10.5).

D10 built the API-backed reviewer. This adds a Claude Code subscription in
headless mode and a local model server, selectable with one environment
variable. The role, the output schema, the untrusted-observation boundary and
the fail-closed path are identical across all of them — that is the property
these tests exist to defend, because four backends is four chances for one of
them to grow its own idea of the rules.

Everything here is offline. The isolation assertions are about the argv the
adapter constructs, not about what a CLI does with it; the empirical check that
those flags actually deny tools and project context was run by hand with a
matched control and is recorded in docs/ADR_REVIEWER_BILLING.md.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from agents.base_agent import PolicyReviewer, ProposedAction
from agents.llm.claude_code_headless_reviewer import (
    ISOLATION_FLAGS,
    ClaudeCodeHeadlessReviewer,
)
from agents.llm.local_reviewer import MODEL_ENV, LocalReviewer
from agents.llm.reviewer_base import (
    OPINION_SCHEMA,
    SYSTEM_PROMPT,
    UNTRUSTED_TAG,
    BaseReviewer,
)
from agents.llm.selection import (
    BACKEND_ENV,
    BACKENDS,
    ReviewerSelectionError,
    build_reviewer,
)

WELL_FORMED = {
    "risk_hint": "medium",
    "possible_sensitive_data_hint": ["customer records"],
    "semantic_risk_hints": ["hostname suggests a billing service"],
    "recommended_escalation": True,
}


def _proposal(**overrides) -> ProposedAction:
    base = {
        "action": "network.scan",
        "target": {"logical_identity": {"type": "ip", "value": "10.20.0.7"}},
        "authorization": {"source": "engagement_scope", "scope_object_id": "SCOPE-1"},
        "discovery": {"source": "explicit_scope"},
        "reason": "in-scope recon",
    }
    return ProposedAction(**{**base, **overrides})


def _review(reviewer):
    return reviewer.review(proposal=_proposal(), canonical_target="10.20.0.7")


def _cli(stdout="", *, returncode=0, stderr="", raises=None):
    """A stand-in for subprocess.run that records what it was given."""
    calls: list[dict] = []

    def runner(cmd, **kwargs):
        calls.append({"cmd": cmd, **kwargs})
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    runner.calls = calls
    return runner


def _envelope(payload=None, **extra):
    return json.dumps({
        "type": "result",
        "result": payload if payload is not None else WELL_FORMED,
        "usage": {"input_tokens": 900, "output_tokens": 120},
        **extra,
    })


# ---------------------------------------------------------------------------
# One contract across four backends
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("backend", BACKENDS)
def test_every_backend_is_selectable_and_satisfies_the_protocol(backend, monkeypatch):
    """The switch works for all four, which is the whole D10.5 claim."""
    monkeypatch.delenv(BACKEND_ENV, raising=False)
    assert isinstance(build_reviewer(backend), PolicyReviewer)


@pytest.mark.parametrize("backend", BACKENDS)
def test_the_environment_variable_selects_the_backend(backend, monkeypatch):
    monkeypatch.setenv(BACKEND_ENV, backend)
    by_env = type(build_reviewer()).__name__
    monkeypatch.delenv(BACKEND_ENV, raising=False)
    assert by_env == type(build_reviewer(backend)).__name__


def test_the_default_is_the_fake_reviewer(monkeypatch):
    """An unconfigured checkout must not reach a real model.

    CI, a fresh clone, or a test somebody runs without reading the docs all land
    here. Defaulting to a live backend would mean spending money by omission.
    """
    monkeypatch.delenv(BACKEND_ENV, raising=False)
    assert type(build_reviewer()).__name__ == "HonestFakeReviewer"


def test_an_unknown_backend_raises_rather_than_falling_back(monkeypatch):
    """A typo must not silently become the fake reviewer.

    Same failure this project has already been bitten by once: a run that looks
    like it exercised a real model and did not.
    """
    monkeypatch.delenv(BACKEND_ENV, raising=False)
    with pytest.raises(ReviewerSelectionError, match="unknown reviewer backend"):
        build_reviewer("claude-code")  # hyphen, not underscore


def test_the_control_plane_never_imports_the_selector():
    """The pipeline takes a reviewer; it does not choose one.

    If function_api ever imported the selector, the kernel would gain an opinion
    about which model runs, and MVP-Kernel's whole seam argument would weaken.
    """
    for path in Path("control_plane").rglob("*.py"):
        source = path.read_text()
        assert "agents.llm" not in source, f"{path} imports an LLM backend"
        assert "selection" not in source or "agents" not in source


# ---------------------------------------------------------------------------
# The shared boundary is shared, not copied
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cls", [ClaudeCodeHeadlessReviewer, LocalReviewer])
def test_every_adapter_inherits_the_boundary_rather_than_restating_it(cls):
    """§8.1/§8.2 lives in one place.

    A security property in three copies is a security property that will shortly
    exist in two. These are the methods an adapter must not override: the
    delimiter, the coercion rules and the fail-closed path.
    """
    for method in ("build_prompt", "_to_opinion", "_escalate"):
        assert getattr(cls, method) is getattr(BaseReviewer, method), (
            f"{cls.__name__} overrides {method}, which is shared for a reason"
        )


@pytest.mark.parametrize("cls,kwargs", [
    (ClaudeCodeHeadlessReviewer, {}),
    (LocalReviewer, {"model": "llama3"}),
])
def test_every_adapter_wraps_the_proposal_in_a_fresh_nonce(cls, kwargs):
    reviewer = cls(**kwargs)
    prompts = [
        reviewer.build_prompt(proposal=_proposal(), canonical_target="10.20.0.7")
        for _ in range(5)
    ]
    for prompt in prompts:
        assert prompt.startswith(f"<{UNTRUSTED_TAG} id=")
    assert len({p.split("id=")[1].split(">")[0] for p in prompts}) == 5


@pytest.mark.parametrize("cls,kwargs", [
    (ClaudeCodeHeadlessReviewer, {}),
    (LocalReviewer, {"model": "llama3"}),
])
def test_no_adapter_defines_its_own_schema_or_system_prompt(cls, kwargs):
    """Both are inherited by import, so a backend cannot loosen either."""
    import importlib

    module = importlib.import_module(cls.__module__)
    assert module.OPINION_SCHEMA is OPINION_SCHEMA
    assert module.SYSTEM_PROMPT is SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Claude Code headless: isolation
# ---------------------------------------------------------------------------

def test_the_headless_call_is_locked_to_zero_tools():
    """The flag that makes a CLI agent equal in authority to an API call.

    `--tools ""` empties the built-in tool set. Asserted on the argv rather than
    trusted: several of these flags changed name across CLI versions, and a
    stale flag fails open by being silently ignored.
    """
    cmd = ClaudeCodeHeadlessReviewer().build_command("PROMPT")

    assert "--tools" in cmd
    assert cmd[cmd.index("--tools") + 1] == "", "tools must be emptied, not narrowed"
    # Nothing may re-grant them.
    for regranting in ("--allowedTools", "--allowed-tools", "--add-dir",
                       "--dangerously-skip-permissions",
                       "--allow-dangerously-skip-permissions",
                       "--permission-mode", "--mcp-config", "--agents"):
        assert regranting not in cmd, f"{regranting} would widen the lock"


def test_the_headless_call_disables_project_context_and_memory():
    """The reviewer sees one proposal, not this repository.

    Claude Code discovers CLAUDE.md, skills, plugins, hooks and MCP servers from
    its surroundings. All of them are off, and session persistence too — a
    reviewer with memory could have one target influence the review of a later,
    unrelated one.
    """
    cmd = ClaudeCodeHeadlessReviewer().build_command("PROMPT")
    for flag in ("--safe-mode", "--strict-mcp-config", "--disable-slash-commands",
                 "--no-session-persistence"):
        assert flag in cmd
    assert cmd[cmd.index("--setting-sources") + 1] == ""


def test_the_whole_isolation_set_is_present():
    """Asserted as a set so a flag cannot be dropped one at a time."""
    cmd = ClaudeCodeHeadlessReviewer().build_command("PROMPT")

    # The set appears contiguously and in order, so a flag cannot be dropped or
    # have its paired value detached from it.
    start = cmd.index(ISOLATION_FLAGS[0])
    assert tuple(cmd[start:start + len(ISOLATION_FLAGS)]) == ISOLATION_FLAGS
    assert cmd.count("--print") == 1


def test_bare_mode_is_not_used_because_it_would_force_an_api_key():
    """--bare disables more, and defeats the purpose.

    It forces ANTHROPIC_API_KEY auth and never reads OAuth, so it would bill the
    API — the exact cost this adapter exists to avoid. --safe-mode disables the
    same project context while leaving subscription auth working.
    """
    assert "--bare" not in ClaudeCodeHeadlessReviewer().build_command("PROMPT")


def test_each_call_runs_in_a_fresh_empty_directory(tmp_path, monkeypatch):
    """Belt and braces behind --safe-mode: nothing of this repo is in cwd."""
    seen: list[str] = []

    def runner(cmd, **kwargs):
        cwd = kwargs["cwd"]
        seen.append(cwd)
        assert list(Path(cwd).iterdir()) == [], "the working directory must be empty"
        return subprocess.CompletedProcess(cmd, 0, _envelope(), "")

    reviewer = ClaudeCodeHeadlessReviewer(runner=runner)
    _review(reviewer)
    _review(reviewer)

    assert len(set(seen)) == 2, "each call needs its own directory"
    for path in seen:
        assert not Path(path).exists(), "the directory must be removed afterwards"
        assert Path(path).resolve() != Path.cwd().resolve()


def test_the_schema_and_model_are_passed_to_the_cli():
    reviewer = ClaudeCodeHeadlessReviewer(model="sonnet")
    cmd = reviewer.build_command("PROMPT")

    assert json.loads(cmd[cmd.index("--json-schema") + 1]) == OPINION_SCHEMA
    assert cmd[cmd.index("--model") + 1] == "sonnet"
    assert cmd[cmd.index("--output-format") + 1] == "json"
    assert cmd[cmd.index("--system-prompt") + 1] == SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Claude Code headless: parsing and fail-closed
# ---------------------------------------------------------------------------

def test_a_well_formed_envelope_becomes_an_opinion():
    reviewer = ClaudeCodeHeadlessReviewer(runner=_cli(_envelope()))
    opinion = _review(reviewer)

    assert opinion.risk_hint == "medium"
    assert opinion.semantic_risk_hints == ("hostname suggests a billing service",)
    assert reviewer.calls[0].input_tokens == 900


def test_a_result_delivered_as_a_json_string_is_accepted():
    """The CLI may hand back the answer already parsed or as a string."""
    reviewer = ClaudeCodeHeadlessReviewer(
        runner=_cli(_envelope(json.dumps(WELL_FORMED))),
    )
    assert _review(reviewer).risk_hint == "medium"


@pytest.mark.parametrize("runner,expected", [
    (_cli(raises=subprocess.TimeoutExpired("claude", 30)), "timed out"),
    (_cli(raises=FileNotFoundError("claude not installed")), "FileNotFoundError"),
    (_cli("", returncode=1, stderr="not logged in"), "cli exited 1"),
    (_cli("this is not json"), "unparseable"),
    (_cli(_envelope("still not json")), "unparseable"),
    (_cli(json.dumps({"is_error": True, "result": "boom"})), "cli reported an error"),
    (_cli(json.dumps({"subtype": "error", "result": {}})), "cli reported an error"),
])
def test_every_headless_failure_reaches_the_shared_fail_closed_path(runner, expected):
    """Same path as D10's API adapter: an absent opinion is a worried opinion."""
    reviewer = ClaudeCodeHeadlessReviewer(runner=runner)
    opinion = _review(reviewer)

    assert opinion.risk_hint == "high"
    assert opinion.recommended_escalation is True
    assert any(expected in hint for hint in opinion.semantic_risk_hints), (
        opinion.semantic_risk_hints
    )
    assert reviewer.calls[0].failed is True


def test_an_error_envelope_with_exit_zero_still_escalates():
    """A CLI that reports failure in its payload but exits 0 must not pass.

    Worth its own test: returncode is the obvious check and would miss this,
    and a hallucinated opinion that reached OPA would be exactly the input the
    kernel is built to distrust.
    """
    reviewer = ClaudeCodeHeadlessReviewer(
        runner=_cli(json.dumps({"is_error": True, "result": WELL_FORMED})),
    )
    assert _review(reviewer).risk_hint == "high"


def test_stderr_is_truncated_in_the_failure_reason():
    """stderr can echo the prompt back, and the prompt carries hostile text."""
    reviewer = ClaudeCodeHeadlessReviewer(
        runner=_cli("", returncode=1, stderr="X" * 5000),
    )
    hint = _review(reviewer).semantic_risk_hints[0]
    assert len(hint) < 400


# ---------------------------------------------------------------------------
# Local model
# ---------------------------------------------------------------------------

def test_the_local_reviewer_defaults_to_loopback(monkeypatch):
    """"Local" must be a fact, not a claim about intent."""
    monkeypatch.delenv("CYBERORCH_LOCAL_REVIEWER_BASE_URL", raising=False)
    assert LocalReviewer(model="llama3").base_url.startswith("http://127.0.0.1")


def test_the_local_reviewer_sends_the_shared_schema_and_prompt():
    body = LocalReviewer(model="llama3").build_request("PROMPT")

    assert body["response_format"]["json_schema"]["schema"] is OPINION_SCHEMA
    assert body["messages"][0]["content"] is SYSTEM_PROMPT
    assert body["messages"][1]["content"] == "PROMPT"
    assert body["temperature"] == 0


def test_an_unconfigured_local_model_escalates(monkeypatch):
    monkeypatch.delenv(MODEL_ENV, raising=False)
    opinion = _review(LocalReviewer())

    assert opinion.risk_hint == "high"
    assert any(MODEL_ENV in h for h in opinion.semantic_risk_hints)


def _local(payload):
    def transport(_body):
        return {
            "choices": [{"message": {"content": json.dumps(payload)}}],
            "usage": {"prompt_tokens": 800, "completion_tokens": 90},
        }
    return LocalReviewer(model="llama3", transport=transport)


def test_a_conforming_local_reply_becomes_an_opinion():
    opinion = _review(_local(WELL_FORMED))
    assert opinion.risk_hint == "medium"
    assert opinion.reviewer_id == "local-reviewer"


@pytest.mark.parametrize("payload,expected", [
    ({**WELL_FORMED, "data_class": ["public"]}, "outside the contract"),
    ({"risk_hint": "low"}, "omitted required fields"),
    ({**WELL_FORMED, "risk_hint": "catastrophic"}, "not a known level"),
    ({**WELL_FORMED, "semantic_risk_hints": "a string"}, "must be a list"),
    ({**WELL_FORMED, "recommended_escalation": "yes"}, "must be a boolean"),
])
def test_a_local_model_that_ignores_the_contract_escalates(payload, expected):
    """The one real difference between local and hosted, made explicit.

    A hosted backend has the schema enforced server-side. A local server may not
    enforce anything, so the adapter validates and treats a violation as a
    failure — an extra field escalates to a human rather than being quietly
    dropped, because a model ignoring the contract is one whose opinion should
    not be trusted to be advisory-shaped.
    """
    opinion = _review(_local(payload))

    assert opinion.risk_hint == "high"
    assert opinion.recommended_escalation is True
    assert any(expected in h for h in opinion.semantic_risk_hints), (
        opinion.semantic_risk_hints
    )


def test_the_reviewer_headless_call_does_not_inherit_stdin_either():
    """The same fix, on the role that shares the runner (D15).

    Worth asserting separately rather than trusting the shared module: the
    guarantee is that *neither* role's behaviour depends on the calling shell,
    and a test on one of them does not say anything about the other if the
    sharing is ever undone.
    """
    seen = {}

    def runner(command, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(command, 0, json.dumps({"result": {
            "risk_hint": "low", "possible_sensitive_data_hint": [],
            "semantic_risk_hints": [], "recommended_escalation": False,
        }}), "")

    ClaudeCodeHeadlessReviewer(runner=runner).review(
        proposal=_proposal(), canonical_target="10.20.0.7")
    assert seen["stdin"] is subprocess.DEVNULL
