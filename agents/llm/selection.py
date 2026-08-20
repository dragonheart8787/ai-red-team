"""Choosing which Policy Reviewer backend runs (D10.5).

Four ways to run the same role, selected by one environment variable:

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

FAKE = "fake"
API = "api"
CLAUDE_CODE = "claude_code"
LOCAL = "local"

BACKENDS = (FAKE, API, CLAUDE_CODE, LOCAL)


class ReviewerSelectionError(ValueError):
    """Raised for an unknown backend name."""


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
