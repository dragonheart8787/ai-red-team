"""The first real model in the system: a live Policy Reviewer (§5, MVP-0).

This replaces exactly one component. ``propose_action`` calls
``reviewer.review(proposal=..., canonical_target=...)`` on one line and does not
care what is behind it; the Planner and Worker stay scripted, so if behaviour
changes after this lands, the Reviewer is the only thing that could have caused
it.

What a reviewer can and cannot do is settled by the return type, not by this
prompt. :class:`ReviewerOpinion` has no field that names a canonical data class,
no field that asserts authorization, and no path to either registry — the
control plane runs as ``cyberorch_app``, which holds SELECT and nothing more on
both. So the strongest thing a compromised or confused model here can achieve is
to ask for a human. That guarantee predates this file and is tested by Scenario
B; nothing here is allowed to widen it.

Two consequences shape the code below.

**The proposal is untrusted input** (§8.1, §8.2). A hostname, a path, a banner —
all of it is either attacker-controlled or attacker-influenceable, and it is
being pasted into a prompt. It goes inside a delimited block that the system
prompt describes as observations to be classified, never as instructions to be
followed. That does not make injection impossible; it makes a successful
injection worth nothing, because the model's entire output surface is advisory.

**A failed review escalates rather than passing.** The model is a network call:
it can time out, rate-limit, or refuse. Letting the exception propagate would
abort the pipeline — safe, but it reads as a crash. Returning a cheerful default
would be a fail-open. So every failure path returns an opinion carrying
``risk_hint="high"`` and ``recommended_escalation=True``, which OPA already
turns into HUMAN_APPROVAL through its existing ``high_risk`` rule. No policy
change and no new reason string: an unavailable reviewer is treated as a
reviewer that is worried.
"""

from __future__ import annotations

import json
import time
from typing import Any

from agents.base_agent import ProposedAction, ReviewerOpinion
from agents.llm.reviewer_base import (
    MAX_TOKENS,
    OPINION_SCHEMA,
    RISK_LEVELS,
    SYSTEM_PROMPT,
    TIMEOUT_SECONDS,
    UNTRUSTED_TAG,
    BaseReviewer,
    ReviewCall,
)
from control_plane.config import require_env

__all__ = [
    "MAX_TOKENS", "MODEL", "OPINION_SCHEMA", "RISK_LEVELS", "SYSTEM_PROMPT",
    "TIMEOUT_SECONDS", "UNTRUSTED_TAG", "LLMPolicyReviewer", "ReviewCall",
]

#: Default. Chosen for the baseline rather than for production economics: if the
#: most capable model cannot produce a useful semantic_risk_hint on a given
#: proposal, a cheaper one will not either, so the ceiling is the number worth
#: establishing first. ``model=`` is a constructor argument precisely so the same
#: scenarios can be re-run against a cheaper model and compared.
MODEL = "claude-opus-5"


class LLMPolicyReviewer(BaseReviewer):
    """A Policy Reviewer backed by a real model.

    Satisfies :class:`agents.base_agent.PolicyReviewer` structurally, which is
    the whole integration: no caller changes, because the seam was designed for
    this substitution and the return type is unchanged.
    """

    def __init__(
        self,
        *,
        reviewer_id: str = "llm-policy-reviewer",
        model: str = MODEL,
        client: Any | None = None,
        max_tokens: int = MAX_TOKENS,
        timeout_seconds: float = TIMEOUT_SECONDS,
    ) -> None:
        self.reviewer_id = reviewer_id
        self.model = model
        self.max_tokens = max_tokens
        self.timeout_seconds = timeout_seconds
        super().__init__()
        self._client = client

    # -- client ------------------------------------------------------------

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        import anthropic

        # Through require_env, so a missing key raises with an instruction
        # rather than falling back to something that happens to work. The key is
        # never defaulted and never written to the repository; see
        # control_plane/config.py for why that rule has no exceptions.
        api_key = require_env(
            "ANTHROPIC_API_KEY",
            hint="The live Policy Reviewer needs it. Export it, or put it in "
                 "the gitignored .env. It is never read from a default.",
        )
        self._client = anthropic.Anthropic(
            api_key=api_key, timeout=self.timeout_seconds,
        )
        return self._client

    # -- review ------------------------------------------------------------

    def review(
        self, *, proposal: ProposedAction, canonical_target: Any
    ) -> ReviewerOpinion:
        started = time.monotonic()
        try:
            response = self._get_client().messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": self.build_prompt(
                        proposal=proposal, canonical_target=canonical_target,
                    ),
                }],
                output_config={
                    "format": {"type": "json_schema", "schema": OPINION_SCHEMA},
                },
            )
        except Exception as exc:  # noqa: BLE001 - every failure escalates
            return self._escalate(started, f"{type(exc).__name__}: {exc}")

        latency = time.monotonic() - started
        usage = getattr(response, "usage", None)

        # A safety decline is not an opinion. Treated like any other failure:
        # the reviewer did not answer, so a human should.
        if getattr(response, "stop_reason", None) == "refusal":
            return self._escalate(started, "model refused to answer", usage=usage)

        try:
            payload = self._parse_json_object(self._text_block(response))
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return self._escalate(started, f"unparseable reply: {exc}", usage=usage)

        self.calls.append(ReviewCall(
            latency_seconds=latency,
            input_tokens=getattr(usage, "input_tokens", 0) or 0,
            output_tokens=getattr(usage, "output_tokens", 0) or 0,
            cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            model=self.model,
        ))
        return self._to_opinion(payload)

    @staticmethod
    def _text_block(response: Any) -> str:
        """The reply's text, which for this transport is a content block.

        The only shape difference between backends: the API returns structured
        content blocks, a CLI returns bytes. Parsing and coercion are shared.
        """
        for block in getattr(response, "content", None) or ():
            if getattr(block, "type", None) == "text":
                return block.text
        raise ValueError("no text block in the reply")
