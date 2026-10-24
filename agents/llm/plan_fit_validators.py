"""The three ways to run a plan-fit validator (D68 Q1, S4): API, Claude Code headless, local.

Transport and nothing else. The boundary, the schema, the system prompt, the coercion and the
fail-closed path are :mod:`agents.llm.plan_fit_base`'s and are not restated here; the transports
are the Reviewer's (``headless.run_headless``, the Anthropic client, one HTTP POST), reused as they
are. The Reviewer's adapters are untouched.

Nothing calls these yet. S5 wires the validator into ``propose_action`` behind its own switch.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any

from agents.base_agent import GoalFitAssessment, PlanFitQuery
from agents.failure_kind import REFUSAL, UNCLASSIFIED, classify_failure
from agents.llm import headless
from agents.llm.headless import CLI, DEFAULT_MODEL, HeadlessError
from agents.llm.local_reviewer import DEFAULT_BASE_URL, LOCAL_TIMEOUT_SECONDS
from agents.llm.plan_fit_base import (
    MAX_TOKENS,
    PLAN_FIT_SCHEMA,
    SYSTEM_PROMPT,
    TIMEOUT_SECONDS,
    BasePlanFitValidator,
)
from control_plane.config import require_env

__all__ = [
    "API_MODEL", "BASE_URL_ENV", "MODEL_ENV", "ClaudeCodeHeadlessPlanFitValidator",
    "LLMPlanFitValidator", "LocalPlanFitValidator",
]

#: The Reviewer's default, for the same reason: the ceiling is the number worth establishing first.
API_MODEL = "claude-opus-5"

#: The local server for this role, its own variables: the validator and the Reviewer are two roles
#: and may be two models, so neither borrows the other's setting.
MODEL_ENV = "CYBERORCH_LOCAL_PLANFIT_MODEL"
BASE_URL_ENV = "CYBERORCH_LOCAL_PLANFIT_BASE_URL"


class LLMPlanFitValidator(BasePlanFitValidator):
    """A plan-fit validator backed by the Anthropic API."""

    def __init__(
        self, *, validator_id: str = "llm-plan-fit-validator", model: str = API_MODEL,
        client: Any | None = None, max_tokens: int = MAX_TOKENS,
        timeout_seconds: float = TIMEOUT_SECONDS,
    ) -> None:
        super().__init__()
        self.validator_id = validator_id
        self.model = model
        self.max_tokens = max_tokens
        self.timeout_seconds = timeout_seconds
        self._client = client

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        api_key = require_env(
            "ANTHROPIC_API_KEY",
            hint="The live plan-fit validator needs it. Export it, or put it in the gitignored "
                 ".env. It is never read from a default.",
        )
        import anthropic

        self._client = anthropic.Anthropic(api_key=api_key, timeout=self.timeout_seconds)
        return self._client

    def request(self, prompt: str) -> dict[str, Any]:
        """The arguments of the call. Separate so a test can assert on them offline."""
        return {
            "model": self.model, "max_tokens": self.max_tokens, "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
            "output_config": {"format": {"type": "json_schema", "schema": PLAN_FIT_SCHEMA}},
        }

    def assess(self, *, query: PlanFitQuery) -> GoalFitAssessment:
        started = time.monotonic()
        try:
            response = self._get_client().messages.create(
                **self.request(self.build_prompt(query=query)))
        except Exception as exc:  # noqa: BLE001 - every failure is "no answer"
            return self._fail(started, f"{type(exc).__name__}: {exc}",
                              kind=classify_failure(exception=exc))
        usage = getattr(response, "usage", None)
        tokens = {"input_tokens": getattr(usage, "input_tokens", 0) or 0,
                  "output_tokens": getattr(usage, "output_tokens", 0) or 0}
        if getattr(response, "stop_reason", None) == "refusal":
            return self._fail(started, "model refused to answer", kind=REFUSAL, **tokens)
        try:
            payload = self._parse_json_object(self._text_block(response))
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return self._fail(started, f"unparseable reply: {exc}", kind=UNCLASSIFIED, **tokens)
        return self._to_assessment(
            started, payload, **tokens,
            cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0)

    @staticmethod
    def _text_block(response: Any) -> str:
        for block in getattr(response, "content", None) or ():
            if getattr(block, "type", None) == "text":
                return block.text
        raise ValueError("no text block in the reply")


class ClaudeCodeHeadlessPlanFitValidator(BasePlanFitValidator):
    """A plan-fit validator over the `claude` CLI in headless mode (isolation as the Reviewer's)."""

    def __init__(
        self, *, validator_id: str = "claude-code-headless-plan-fit-validator",
        model: str = DEFAULT_MODEL, timeout_seconds: float = TIMEOUT_SECONDS,
        executable: str = CLI, runner: Any | None = None,
    ) -> None:
        super().__init__()
        self.validator_id = validator_id
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.executable = executable
        self._runner = runner or subprocess.run

    def build_command(self, prompt: str) -> list[str]:
        return headless.build_command(
            prompt=prompt, system_prompt=SYSTEM_PROMPT, schema=PLAN_FIT_SCHEMA,
            model=self.model, executable=self.executable)

    def assess(self, *, query: PlanFitQuery) -> GoalFitAssessment:
        prompt = self.build_prompt(query=query)
        started = time.monotonic()
        try:
            result = headless.run_headless(
                command=self.build_command(prompt), timeout_seconds=self.timeout_seconds,
                runner=self._runner)
        except HeadlessError as exc:
            return self._fail(started, str(exc), kind=classify_failure(
                stop_reason=exc.stop_reason, api_error_status=exc.api_error_status,
                timed_out=exc.timed_out))
        return self._to_assessment(
            started, result.payload, input_tokens=result.input_tokens,
            output_tokens=result.output_tokens)


class LocalPlanFitValidator(BasePlanFitValidator):
    """A plan-fit validator over a local OpenAI-compatible server."""

    def __init__(
        self, *, validator_id: str = "local-plan-fit-validator", model: str | None = None,
        base_url: str | None = None, timeout_seconds: float = LOCAL_TIMEOUT_SECONDS,
        transport: Any | None = None,
    ) -> None:
        super().__init__()
        self.validator_id = validator_id
        self.model = model or os.environ.get(MODEL_ENV, "")
        self.base_url = (base_url or os.environ.get(BASE_URL_ENV) or DEFAULT_BASE_URL).rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._transport = transport

    def build_request(self, prompt: str) -> dict[str, Any]:
        return {
            "model": self.model, "max_tokens": MAX_TOKENS, "temperature": 0,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": prompt}],
            "response_format": {"type": "json_schema", "json_schema": {
                "name": "plan_fit", "strict": True, "schema": PLAN_FIT_SCHEMA}},
        }

    def assess(self, *, query: PlanFitQuery) -> GoalFitAssessment:
        started = time.monotonic()
        if not self.model:
            return self._fail(started, f"no local model configured; set {MODEL_ENV}")
        prompt = self.build_prompt(query=query)
        try:
            envelope = self._post(self.build_request(prompt))
            payload = self._parse_json_object(envelope["choices"][0]["message"]["content"])
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            return self._fail(started, f"{type(exc).__name__}: {exc}",
                              kind=classify_failure(exception=exc))
        except (ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError) as exc:
            return self._fail(started, f"unparseable reply: {exc}")
        usage = envelope.get("usage") or {}
        return self._to_assessment(
            started, payload, input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0))

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        if self._transport is not None:
            return self._transport(body)
        request = urllib.request.Request(  # noqa: S310 - scheme is our own default
            f"{self.base_url}/chat/completions", data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:  # noqa: S310
            return json.loads(response.read().decode())
