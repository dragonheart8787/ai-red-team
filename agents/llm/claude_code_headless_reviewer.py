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

import json
import shutil
import subprocess
import tempfile
import time
from typing import Any

from agents.base_agent import ProposedAction, ReviewerOpinion
from agents.llm.reviewer_base import (
    OPINION_SCHEMA,
    SYSTEM_PROMPT,
    TIMEOUT_SECONDS,
    BaseReviewer,
    ReviewCall,
)

#: Alias rather than a pinned id: the CLI resolves 'opus'/'sonnet' to whatever
#: the subscription currently serves, and pinning here would silently diverge
#: from what the user is actually paying for.
DEFAULT_MODEL = "opus"

CLI = "claude"

#: The isolation flags, as one list so a test can assert on the whole set rather
#: than on whichever ones somebody remembered to check. Verified against
#: `claude --help` on 2.1.237 rather than recalled — several of these changed
#: name across versions, and a stale flag fails open by being ignored.
ISOLATION_FLAGS: tuple[str, ...] = (
    "--tools", "",                  # zero tools
    "--safe-mode",                  # no CLAUDE.md, skills, plugins, hooks, MCP
    "--setting-sources", "",        # no settings files
    "--strict-mcp-config",          # no ambient MCP servers
    "--disable-slash-commands",     # no skills
    "--no-session-persistence",     # no memory between proposals
)


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
        return [
            self.executable,
            "--print", prompt,
            "--model", self.model,
            "--system-prompt", SYSTEM_PROMPT,
            "--output-format", "json",
            "--json-schema", json.dumps(OPINION_SCHEMA),
            *ISOLATION_FLAGS,
        ]

    # -- review ------------------------------------------------------------

    def review(
        self, *, proposal: ProposedAction, canonical_target: Any
    ) -> ReviewerOpinion:
        prompt = self.build_prompt(
            proposal=proposal, canonical_target=canonical_target,
        )
        started = time.monotonic()

        # Fresh and empty every call. Claude Code reads context from cwd, and a
        # reviewer that could see this repository would be reviewing proposals
        # with the project's own documentation in its context.
        workdir = tempfile.mkdtemp(prefix="reviewer-")
        try:
            completed = self._runner(
                self.build_command(prompt),
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self._escalate(started, f"timed out after {self.timeout_seconds}s")
        except (OSError, ValueError) as exc:
            return self._escalate(started, f"{type(exc).__name__}: {exc}")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        if completed.returncode != 0:
            # stderr is truncated: it can carry the prompt back, and the prompt
            # contains attacker-influenced text that would then land in an audit
            # payload unbounded.
            detail = (completed.stderr or "").strip()[:200]
            return self._escalate(
                started, f"cli exited {completed.returncode}: {detail}",
            )

        try:
            envelope = self._parse_json_object(completed.stdout)
            payload = self._unwrap(envelope)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return self._escalate(started, f"unparseable reply: {exc}")

        self.calls.append(ReviewCall(
            latency_seconds=time.monotonic() - started,
            input_tokens=self._usage(envelope, "input_tokens"),
            output_tokens=self._usage(envelope, "output_tokens"),
            model=self.model,
        ))
        return self._to_opinion(payload)

    # -- helpers -----------------------------------------------------------

    def _unwrap(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Pull the opinion out of the CLI's result envelope.

        ``--output-format json`` returns metadata around the model's answer, and
        the answer itself may arrive either already parsed or as a JSON string
        in ``result``. Both are accepted; anything else escalates rather than
        being guessed at.

        An envelope reporting an error is treated as a failure even though the
        process exited zero — a CLI that says ``is_error`` and returns 0 would
        otherwise pass a hallucinated opinion straight through.
        """
        if envelope.get("is_error") or envelope.get("subtype") == "error":
            raise ValueError(f"cli reported an error: {str(envelope)[:200]}")

        result = envelope.get("result", envelope)
        if isinstance(result, str):
            result = self._parse_json_object(result)
        if not isinstance(result, dict):
            raise ValueError(f"expected an object, got {type(result).__name__}")
        return result

    @staticmethod
    def _usage(envelope: dict[str, Any], field: str) -> int:
        usage = envelope.get("usage")
        if isinstance(usage, dict):
            try:
                return int(usage.get(field, 0) or 0)
            except (TypeError, ValueError):
                return 0
        return 0
