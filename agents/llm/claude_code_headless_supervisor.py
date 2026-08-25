"""A Supervisor that runs on a Claude Code subscription (D17).

Transport and nothing else. :class:`~agents.llm.supervisor_base.BaseSupervisor`
owns the schema, the untrusted boundary and the refusal path;
:mod:`agents.llm.headless` owns the isolation set and the subprocess plumbing,
shared with the Policy Reviewer D10.5 verified empirically and the Worker D13
added.

``--tools ""`` is doing something slightly different here than in either of the
other two roles. A Reviewer with tools could look things up; a Worker with tools
could act. A Supervisor with tools could *decide what the engagement is* — it is
the role furthest from the policy kernel and therefore the one whose beliefs
about the world are checked the least, so the only material it may reason from
is the material it was handed.
"""

from __future__ import annotations

import subprocess
import time
from typing import Any

from agents.base_agent import ProposedTask
from agents.llm import headless
from agents.llm.headless import (
    CLI,
    DEFAULT_MODEL,
    WORKER_TIMEOUT_SECONDS,
    HeadlessError,
)
from agents.llm.supervisor_base import (
    BaseSupervisor,
    ScopeCandidate,
    StateSummary,
    SupervisorCall,
    SupervisorRefusal,
    plan_schema,
)


class ClaudeCodeHeadlessSupervisor(BaseSupervisor):
    """Supervisor over the `claude` CLI in headless mode."""

    def __init__(
        self,
        *,
        agent_id: str = "claude-code-headless-supervisor",
        model: str = DEFAULT_MODEL,
        timeout_seconds: float = WORKER_TIMEOUT_SECONDS,
        executable: str = CLI,
        warn_about_duplicates: bool = False,
        runner: Any | None = None,
    ) -> None:
        super().__init__(warn_about_duplicates=warn_about_duplicates)
        self.agent_id = agent_id
        self.model = model
        # The Worker's deadline rather than the Reviewer's, and for a stronger
        # version of D15's reason: a planning call is shown the whole ledger
        # plus every finding, so its prompt is the largest of the three roles'
        # and its reply is a list rather than a single object. A cap that
        # truncated the distribution from above would discard exactly the runs
        # where the model deliberated over the ledger — which in a duplication
        # experiment are the runs that carry the answer.
        self.timeout_seconds = timeout_seconds
        self.executable = executable
        #: Injectable for tests. Production passes None and gets subprocess.run.
        self._runner = runner or subprocess.run

    def build_command(
        self, prompt: str, *, candidates: tuple[ScopeCandidate, ...]
    ) -> list[str]:
        """The exact argv. Separate so a test can assert on it without a call."""
        actions = tuple(sorted({a for c in candidates for a in c.allowed_actions}))
        schema = plan_schema(
            scope_object_ids=tuple(c.scope_object_id for c in candidates),
            actions=actions,
        )
        return headless.build_command(
            prompt=prompt, system_prompt=self.system_prompt, schema=schema,
            model=self.model, executable=self.executable,
        )

    def plan(
        self, *, state: StateSummary, candidates: tuple[ScopeCandidate, ...],
    ) -> list[ProposedTask] | None:
        if not candidates:
            # Nothing to select from. Every task must name a scope object, and
            # a plan naming one that was never offered is what the enum exists
            # to prevent — so the honest answer is no plan.
            return self._refuse(time.monotonic(), "no scope candidates were offered")

        prompt = self.build_prompt(state=state, candidates=candidates)
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
            tasks = self._to_tasks(result.payload, candidates=candidates)
        except SupervisorRefusal as exc:
            return self._refuse(started, f"unusable plan: {exc}")

        self.calls.append(SupervisorCall(
            latency_seconds=time.monotonic() - started,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            model=self.model,
            task_count=len(tasks),
            status_assessment=str(result.payload.get("status_assessment") or ""),
            assessment_note=str(result.payload.get("assessment_note") or ""),
        ))
        return tasks
