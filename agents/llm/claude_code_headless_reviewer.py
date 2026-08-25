"""A Policy Reviewer that runs on a Claude Code subscription (D10.5).

Same role, same output contract, different way of paying for it. D10's adapter
bills the Anthropic API per token; this one shells out to the `claude` CLI in
headless mode, so a developer who already pays for Claude Code can run the
reviewer without opening a second billing relationship.

Everything that makes the reviewer safe is inherited, not restated.
:class:`BaseReviewer` owns the nonce-delimited untrusted-observation boundary,
the four-field output schema, the coercion rules and the fail-closed path. This
file adds transport and isolation, and nothing else — which is the point, since
a second copy of the boundary would be a second thing to get wrong.

Isolation, and why each piece is there
--------------------------------------

A CLI agent is a very different object from an API call: by default it has
tools, a working directory, project configuration, and memory. All three have to
be taken away before it can stand in for a stateless reviewer.

``--tools ""``
    Zero tools. Not a restricted set, not a permission mode that would prompt —
    the built-in tool set is emptied. This is the flag that makes a CLI agent
    equivalent in authority to an API call, and
    ``test_the_headless_call_is_locked_to_zero_tools`` pins it.
``--safe-mode``
    Disables CLAUDE.md, skills, plugins, hooks, MCP servers, custom agents and
    output styles, while leaving auth and model selection working. Chosen over
    ``--bare``, which does the same and more but forces ``ANTHROPIC_API_KEY``
    auth — that would defeat the entire purpose of this adapter.
``--setting-sources ''``
    Loads no user, project or local settings files.
``--strict-mcp-config``
    No MCP servers beyond those passed with ``--mcp-config``, and none are.
``--disable-slash-commands``
    No skills.
``--no-session-persistence``
    Nothing written to disk, nothing resumable. A reviewer has no memory between
    proposals by design: each opinion must depend only on the proposal it was
    shown, or a target could influence the review of a later, unrelated one.
An empty temp directory as cwd
    Belt and braces behind ``--safe-mode``. Claude Code discovers context from
    the working directory, and running it inside this repository would put the
    project's own CLAUDE.md and source in front of a component that is supposed
    to see one proposal. The directory is created empty per call and removed
    afterwards.

Network
-------

This runs inside the same container the Tool Gateway confines (§8.3), so the
namespace-level CIDR allowlist from D6 applies unchanged; the reviewer needs
only ``api.anthropic.com``. That is a property of the deployment, not of this
file, and it is worth being precise about the limit: **nothing here enforces
it.** ``tool_gateway/sandbox.py`` enforces network confinement for tool runs,
and its DEFERRED note about Docker-managed subnets applies equally to this path.

Output
------

``--json-schema`` validates the model's reply against the shared
``OPINION_SCHEMA`` — the same contract the API adapter enforces through
``output_config.format``, so both backends are held to the same four fields with
``additionalProperties: false``. ``--output-format json`` wraps the result in an
envelope carrying cost and duration, which is what makes the subscription path
measurable on the same terms as the paid one.
"""

from __future__ import annotations

import subprocess
import time
from typing import Any

from agents.base_agent import ProposedAction, ReviewerOpinion
from agents.llm import headless
from agents.llm.headless import CLI, DEFAULT_MODEL, ISOLATION_FLAGS, HeadlessError
from agents.llm.reviewer_base import (
    OPINION_SCHEMA,
    SYSTEM_PROMPT,
    TIMEOUT_SECONDS,
    BaseReviewer,
    ReviewCall,
)

__all__ = ["CLI", "DEFAULT_MODEL", "ISOLATION_FLAGS", "ClaudeCodeHeadlessReviewer"]


class ClaudeCodeHeadlessReviewer(BaseReviewer):
    """Policy Reviewer over the `claude` CLI in headless mode."""

    def __init__(
        self,
        *,
        reviewer_id: str = "claude-code-headless-reviewer",
        model: str = DEFAULT_MODEL,
        timeout_seconds: float = TIMEOUT_SECONDS,
        executable: str = CLI,
        runner: Any | None = None,
    ) -> None:
        super().__init__()
        self.reviewer_id = reviewer_id
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.executable = executable
        #: Injectable for tests. Production passes None and gets subprocess.run.
        self._runner = runner or subprocess.run

    # -- command -----------------------------------------------------------

    def build_command(self, prompt: str) -> list[str]:
        """The exact argv. Separate so a test can assert on it without a call."""
        return headless.build_command(
            prompt=prompt, system_prompt=SYSTEM_PROMPT, schema=OPINION_SCHEMA,
            model=self.model, executable=self.executable,
        )

    # -- review ------------------------------------------------------------

    def review(
        self, *, proposal: ProposedAction, canonical_target: Any
    ) -> ReviewerOpinion:
        prompt = self.build_prompt(
            proposal=proposal, canonical_target=canonical_target,
        )
        started = time.monotonic()
        try:
            result = headless.run_headless(
                command=self.build_command(prompt),
                timeout_seconds=self.timeout_seconds,
                runner=self._runner,
            )
        except HeadlessError as exc:
            return self._escalate(started, str(exc))

        self.calls.append(ReviewCall(
            latency_seconds=time.monotonic() - started,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            model=self.model,
        ))
        return self._to_opinion(result.payload)
