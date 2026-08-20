"""A Policy Reviewer running against a local model server (D10.5).

The fourth way to pay for the same role: nothing leaves the machine and nothing
is billed. Useful when the target data should not reach a third party at all,
which for a security-testing platform is a real constraint rather than a
preference — a proposal carries customer hostnames.

Speaks the OpenAI-compatible ``/v1/chat/completions`` shape, because Ollama,
vLLM, llama.cpp's server and LM Studio all expose it. That is a wire format, not
a provider: no OpenAI service is contacted and no OpenAI credential is used. The
base URL points at localhost by default and must be set explicitly to point
anywhere else.

Everything safety-relevant is inherited from :class:`BaseReviewer` — the
nonce-delimited boundary, the schema, the coercion rules, the fail-closed path.

One difference from the hosted adapters is worth stating rather than hiding.
Hosted backends enforce the output schema server-side; a local server may or may
not, depending on which one it is and how it was started. So this adapter asks
for JSON and then validates what came back against ``OPINION_SCHEMA`` itself,
and treats a violation as a failure — reaching the same fail-closed path as a
timeout. A local model that ignores the schema therefore escalates to a human
rather than having its extra fields quietly dropped.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from agents.base_agent import ProposedAction, ReviewerOpinion
from agents.llm.reviewer_base import (
    MAX_TOKENS,
    OPINION_SCHEMA,
    RISK_LEVELS,
    SYSTEM_PROMPT,
    BaseReviewer,
    ReviewCall,
)

#: Ollama's default. Overridable, but the default stays on loopback: an adapter
#: whose default reached off-box would make "local" a claim rather than a fact.
DEFAULT_BASE_URL = "http://127.0.0.1:11434/v1"

#: No default that silently works. Which local model is running is a deployment
#: fact, and guessing one produces a confusing 404 rather than a clear error.
MODEL_ENV = "CYBERORCH_LOCAL_REVIEWER_MODEL"
BASE_URL_ENV = "CYBERORCH_LOCAL_REVIEWER_BASE_URL"

#: Local models are slower, and a laptop under load is slower still. Generous
#: rather than unbounded: the fail-closed path is a worse outcome than waiting,
#: but an unbounded wait would stall the pipeline instead of escalating.
LOCAL_TIMEOUT_SECONDS = 120.0


class LocalReviewer(BaseReviewer):
    """Policy Reviewer over a local OpenAI-compatible server."""

    def __init__(
        self,
        *,
        reviewer_id: str = "local-reviewer",
        model: str | None = None,
        base_url: str | None = None,
        timeout_seconds: float = LOCAL_TIMEOUT_SECONDS,
        transport: Any | None = None,
    ) -> None:
        super().__init__()
        self.reviewer_id = reviewer_id
        self.model = model or os.environ.get(MODEL_ENV, "")
        self.base_url = (
            base_url or os.environ.get(BASE_URL_ENV) or DEFAULT_BASE_URL
        ).rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._transport = transport

    # -- request -----------------------------------------------------------

    def build_request(self, prompt: str) -> dict[str, Any]:
        """The request body. Separate so a test can assert on it offline."""
        return {
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            # Honoured by vLLM and recent Ollama; ignored by others, which is
            # why the reply is validated locally regardless.
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "reviewer_opinion",
                    "strict": True,
                    "schema": OPINION_SCHEMA,
                },
            },
        }

    # -- review ------------------------------------------------------------

    def review(
        self, *, proposal: ProposedAction, canonical_target: Any
    ) -> ReviewerOpinion:
        started = time.monotonic()
        if not self.model:
            return self._escalate(
                started,
                f"no local model configured; set {MODEL_ENV}",
            )

        prompt = self.build_prompt(
            proposal=proposal, canonical_target=canonical_target,
        )
        try:
            envelope = self._post(self.build_request(prompt))
            payload = self._parse_json_object(self._content(envelope))
            self._validate(payload)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            return self._escalate(started, f"{type(exc).__name__}: {exc}")
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            return self._escalate(started, f"unparseable reply: {exc}")

        usage = envelope.get("usage") or {}
        self.calls.append(ReviewCall(
            latency_seconds=time.monotonic() - started,
            input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0),
            model=self.model,
        ))
        return self._to_opinion(payload)

    # -- helpers -----------------------------------------------------------

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        if self._transport is not None:
            return self._transport(body)

        request = urllib.request.Request(  # noqa: S310 - scheme is our own default
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(  # noqa: S310
            request, timeout=self.timeout_seconds,
        ) as response:
            return json.loads(response.read().decode())

    @staticmethod
    def _content(envelope: dict[str, Any]) -> str:
        return envelope["choices"][0]["message"]["content"]

    @staticmethod
    def _validate(payload: dict[str, Any]) -> None:
        """Hold a local model to the same contract a hosted one is held to.

        Deliberately not a general JSON Schema implementation — it checks the
        properties OPINION_SCHEMA actually declares, which is a fixed and small
        set. A dependency on a schema library to validate four fields would be
        more moving parts guarding less.

        Extra keys are rejected rather than dropped. On the hosted path the
        service already refused them; here nothing did, so an unexpected field
        means the model ignored the contract, and a model ignoring the contract
        is one whose opinion should not be trusted to be advisory-shaped.
        """
        allowed = set(OPINION_SCHEMA["properties"])
        extra = set(payload) - allowed
        if extra:
            raise ValueError(f"reply carried fields outside the contract: {sorted(extra)}")
        missing = set(OPINION_SCHEMA["required"]) - set(payload)
        if missing:
            raise ValueError(f"reply omitted required fields: {sorted(missing)}")
        if payload["risk_hint"] not in RISK_LEVELS:
            raise ValueError(f"risk_hint {payload['risk_hint']!r} is not a known level")
        for name in ("possible_sensitive_data_hint", "semantic_risk_hints"):
            if not isinstance(payload[name], list):
                raise ValueError(f"{name} must be a list")
        if not isinstance(payload["recommended_escalation"], bool):
            raise ValueError("recommended_escalation must be a boolean")
