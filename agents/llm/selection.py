"""Choosing which backend runs each agent role (D10.5, D13, D17).

Three roles, three independent environment variables, and the same rule for all
of them: the default is scripted, and every other value reaches a real model.
Holding them apart is what lets one role be a real model while the other two
stay wherever they were — which is the discipline D13 and D17 are built on, one
new source of non-determinism at a time.

Four ways to run the Policy Reviewer, selected by one environment variable:

===================  ====================================================
``fake``             The scripted reviewers. The default, and what CI uses.
``api``              Anthropic API, billed per token (D10).
``claude_code``      The `claude` CLI in headless mode, on a subscription.
``local``            A local OpenAI-compatible server. Nothing leaves the box.
===================  ====================================================

The default is ``fake`` and that is deliberate. Every other value reaches a real
model, and a default that did so would mean an unconfigured checkout — CI, a new
clone, a test somebody runs without reading this file — quietly making network
calls and possibly spending money. Opting in is one variable; opting out after
the fact is a bill.

This module exists so ``function_api.py`` keeps knowing nothing about backends.
The pipeline takes a ``reviewer`` argument and calls ``.review(...)`` on it; the
choice is made by whoever assembles the run. Nothing here is imported by the
control plane, and a test asserts that.

Imports are deferred into each branch on purpose: ``api`` needs the ``anthropic``
package and ``local`` needs nothing, so importing all four eagerly would make an
optional dependency mandatory for everyone.
"""

from __future__ import annotations

import os
from typing import Any

from agents.base_agent import PolicyReviewer

#: Which backend to use. Read at call time, not at import, so a test can set it.
BACKEND_ENV = "CYBERORCH_REVIEWER_BACKEND"

#: Which model, where the backend takes one. Each backend has its own default,
#: because "opus" means something to the CLI and nothing to a local server.
MODEL_ENV = "CYBERORCH_REVIEWER_MODEL"

#: The same two variables for the Worker (D13), separate from the Reviewer's so
#: one role can be a real model while the other stays scripted. That is not a
#: convenience: D13's whole discipline is introducing one source of
#: non-determinism at a time, and a single switch flipping both would make that
#: impossible to hold.
WORKER_BACKEND_ENV = "CYBERORCH_WORKER_BACKEND"
WORKER_MODEL_ENV = "CYBERORCH_WORKER_MODEL"

#: And again for the Supervisor (D17), the third and last role. Three
#: independent switches rather than one, for the reason above: D17's variable is
#: the Supervisor, and it is only the Supervisor if the other two can be held
#: wherever they were.
SUPERVISOR_BACKEND_ENV = "CYBERORCH_SUPERVISOR_BACKEND"
SUPERVISOR_MODEL_ENV = "CYBERORCH_SUPERVISOR_MODEL"

FAKE = "fake"
API = "api"
CLAUDE_CODE = "claude_code"
LOCAL = "local"

BACKENDS = (FAKE, API, CLAUDE_CODE, LOCAL)


class ReviewerSelectionError(ValueError):
    """Raised for an unknown backend name.

    One exception type for all three roles rather than three that would behave
    identically. Kept under its original name so nothing that catches it has to
    change; the message always says which role and which name.
    """


def build_reviewer(
    backend: str | None = None, *, model: str | None = None, **kwargs: Any
) -> PolicyReviewer:
    """Return the configured Policy Reviewer.

    ``backend`` overrides the environment, which is what the manual baseline
    script uses to run the same proposals through several backends in one
    process.

    An unknown name raises rather than falling back to ``fake``. A silent
    fallback would turn a typo into a run that looks like it exercised a real
    model and did not — the same class of mistake as the suite that reported
    "40 passed" while skipping every database test.
    """
    backend = (backend or os.environ.get(BACKEND_ENV) or FAKE).strip().lower()
    model = model or os.environ.get(MODEL_ENV) or None

    if backend == FAKE:
        from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer

        return HonestFakeReviewer(**kwargs)

    if backend == API:
        from agents.llm.policy_reviewer import LLMPolicyReviewer

        return LLMPolicyReviewer(**({"model": model} if model else {}), **kwargs)

    if backend == CLAUDE_CODE:
        from agents.llm.claude_code_headless_reviewer import (
            ClaudeCodeHeadlessReviewer,
        )

        return ClaudeCodeHeadlessReviewer(
            **({"model": model} if model else {}), **kwargs
        )

    if backend == LOCAL:
        from agents.llm.local_reviewer import LocalReviewer

        return LocalReviewer(**({"model": model} if model else {}), **kwargs)

    raise ReviewerSelectionError(
        f"unknown reviewer backend {backend!r}; expected one of {BACKENDS}"
    )


#: Which Workers can be built. Only two so far: the scripted one, and the
#: headless CLI. There is no API-billed Worker because nobody has asked for one
#: and adding a backend nothing exercises is how an unused code path acquires a
#: bug in private.
WORKER_BACKENDS = (FAKE, CLAUDE_CODE)


def build_worker(
    backend: str | None = None, *, model: str | None = None, **kwargs: Any
):
    """Return the configured Worker (D13).

    Defaults to ``fake`` for the reason ``build_reviewer`` does, with one extra
    edge: a Worker reaching a real model does not merely cost money, it decides
    what the system will be asked to *do*. An unconfigured checkout must get the
    scripted one.

    An unknown name raises rather than falling back, so a typo cannot produce a
    run that looks like it exercised a real model and did not.
    """
    backend = (backend or os.environ.get(WORKER_BACKEND_ENV) or FAKE).strip().lower()
    model = model or os.environ.get(WORKER_MODEL_ENV) or None

    if backend == FAKE:
        from agents.fake.fake_worker import FakeWorker

        return FakeWorker(**kwargs)

    if backend == CLAUDE_CODE:
        from agents.llm.claude_code_headless_worker import ClaudeCodeHeadlessWorker

        return ClaudeCodeHeadlessWorker(
            **({"model": model} if model else {}), **kwargs
        )

    raise ReviewerSelectionError(
        f"unknown worker backend {backend!r}; expected one of {WORKER_BACKENDS}"
    )


#: Which Supervisors can be built (D17). The scripted planner and the headless
#: CLI, for the reason ``WORKER_BACKENDS`` gives: a backend nothing exercises is
#: how an unused code path acquires a bug in private.
SUPERVISOR_BACKENDS = (FAKE, CLAUDE_CODE)


def build_supervisor(
    backend: str | None = None, *, model: str | None = None, **kwargs: Any
):
    """Return the configured Supervisor (D17).

    Defaults to ``fake``, and here the default matters most of the three. A
    Reviewer reaching a real model costs money; a Worker reaching one decides
    what the system will be asked to do about a target somebody already named; a
    Supervisor reaching one decides *which targets get looked at at all*. An
    unconfigured checkout must get the scripted planner, which plans nothing
    until it is handed a script.

    An unknown name raises rather than falling back, so a typo cannot produce a
    run that looks like it exercised a real model and did not.
    """
    backend = (backend or os.environ.get(SUPERVISOR_BACKEND_ENV) or FAKE).strip().lower()
    model = model or os.environ.get(SUPERVISOR_MODEL_ENV) or None

    if backend == FAKE:
        from agents.fake.fake_planner import FakePlanner

        # An empty script by default: a fake planner that invented tasks would
        # be a fake with an opinion, and MVP-Kernel's whole point is that the
        # scripted roles have none.
        return FakePlanner(kwargs.pop("script", ()), **kwargs)

    if backend == CLAUDE_CODE:
        from agents.llm.claude_code_headless_supervisor import (
            ClaudeCodeHeadlessSupervisor,
        )

        return ClaudeCodeHeadlessSupervisor(
            **({"model": model} if model else {}), **kwargs
        )

    raise ReviewerSelectionError(
        f"unknown supervisor backend {backend!r}; expected one of "
        f"{SUPERVISOR_BACKENDS}"
    )
