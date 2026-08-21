"""A Worker that runs on a Claude Code subscription (D13).

Transport and nothing else. :class:`~agents.llm.worker_base.BaseWorker` owns
the schema, the untrusted-observation boundary and the refusal path;
:mod:`agents.llm.headless` owns the isolation set and the subprocess plumbing,
shared with the Policy Reviewer that D10.5 verified empirically.

``--tools ""`` matters more here than it did there. A Reviewer with tools would
be a component that could look things up; a Worker with tools would be a
component that could *act*, and §2's whole premise is that agents reach the
world through the narrow function API and through nothing else. The Worker's
only output is a proposal, and a proposal is a request rather than an action.
"""

from __future__ import annotations

import subprocess
import time
from typing import Any

from agents.base_agent import ProposedAction, ProposedTask
from agents.llm import headless
from agents.llm.headless import CLI, DEFAULT_MODEL, TIMEOUT_SECONDS, HeadlessError
from agents.llm.worker_base import (
    WORKER_SYSTEM_PROMPT,
    BaseWorker,
    Observation,
    ScopeCandidate,
    WorkerCall,
    WorkerRefusal,
    proposal_schema,
)


class ClaudeCodeHeadlessWorker(BaseWorker):
    """Worker over the `claude` CLI in headless mode."""

    def __init__(
        self,
        *,
        agent_id: str = "claude-code-headless-worker",
        model: str = DEFAULT_MODEL,
        timeout_seconds: float = TIMEOUT_SECONDS,
        executable: str = CLI,
        runner: Any | None = None,
    ) -> None:
        super().__init__()
        self.agent_id = agent_id
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.executable = executable
        #: Injectable for tests. Production passes None and gets subprocess.run.
        self._runner = runner or subprocess.run

    def build_command(
        self, prompt: str, *, candidates: tuple[ScopeCandidate, ...]
    ) -> list[str]:
        """The exact argv. Separate so a test can assert on it without a call.

        The schema is built from the candidates, so the enum of selectable scope
        objects is fixed before the model is asked rather than checked after it
        answers. Both happen — see ``BaseWorker._to_proposal`` for why the
        in-process check is not redundant.
        """
        actions = tuple(sorted({a for c in candidates for a in c.allowed_actions}))
        schema = proposal_schema(
            scope_object_ids=tuple(c.scope_object_id for c in candidates),
            actions=actions,
        )
        return headless.build_command(
            prompt=prompt, system_prompt=WORKER_SYSTEM_PROMPT, schema=schema,
            model=self.model, executable=self.executable,
        )

    def propose(
        self, *, task: ProposedTask, candidates: tuple[ScopeCandidate, ...],
        observations: tuple[Observation, ...] = (), task_id: str | None = None,
    ) -> ProposedAction | None:
        if not candidates:
            # Nothing to select from. Refusing is the only honest answer: a
            # proposal naming a scope object that was never offered is exactly
            # what the enum exists to prevent.
            return self._refuse(time.monotonic(), "no scope candidates were offered")

        prompt = self.build_prompt(
            task=task, candidates=candidates, observations=observations,
        )
        started = time.monotonic()
        try:
            result = headless.run_headless(
                command=self.build_command(prompt, candidates=candidates),
                timeout_seconds=self.timeout_seconds,
                runner=self._runner,
            )
        except HeadlessError as exc:
            return self._refuse(started, str(exc))

        try:
            proposal = self._to_proposal(
                result.payload, candidates=candidates, task_id=task_id,
            )
        except WorkerRefusal as exc:
            return self._refuse(started, f"unusable proposal: {exc}")

        self.calls.append(WorkerCall(
            latency_seconds=time.monotonic() - started,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            model=self.model,
        ))
        return proposal
