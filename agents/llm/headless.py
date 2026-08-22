"""Running the `claude` CLI as a stateless model call (D10.5, shared at D13).

D10.5 established this for the Policy Reviewer and verified it empirically with
a matched control: a canary file and a CLAUDE.md that a context-reading agent
would have picked up, and did not. D13 adds a second role that runs the same
way, so the isolation set and the subprocess plumbing move here instead of
being copied — the same reasoning as ``untrusted.py``.

Isolation, and why each piece is there
--------------------------------------

A CLI agent is a very different object from an API call: by default it has
tools, a working directory, project configuration, and memory. All of that has
to be taken away before it can stand in for a stateless model call.

``--tools ""``
    Zero tools. Not a restricted set, not a permission mode that would prompt —
    the built-in tool set is emptied. This is the flag that makes a CLI agent
    equivalent in authority to an API call.
``--safe-mode``
    Disables CLAUDE.md, skills, plugins, hooks, MCP servers, custom agents and
    output styles, while leaving auth and model selection working. Chosen over
    ``--bare``, which does the same and more but forces ``ANTHROPIC_API_KEY``
    auth — that would defeat the entire purpose of a subscription backend.
``--setting-sources ''``
    Loads no user, project or local settings files.
``--strict-mcp-config``
    No MCP servers beyond those passed with ``--mcp-config``, and none are.
``--disable-slash-commands``
    No skills.
``--no-session-persistence``
    Nothing written to disk, nothing resumable. Neither role may have memory
    between calls: each answer must depend only on what it was shown, or one
    target could influence the handling of a later, unrelated one.
An empty temp directory as cwd
    Belt and braces behind ``--safe-mode``. Claude Code discovers context from
    the working directory, and running it inside this repository would put the
    project's own CLAUDE.md and source in front of a component that is supposed
    to see one request. Created empty per call and removed afterwards.

Zero tools matters more for a Worker than for a Reviewer. A Reviewer with tools
would be a component that could look things up; a Worker with tools would be a
component that could *act*, and every boundary in §2 exists because agents reach
the world through the narrow function API and through nothing else.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any

CLI = "claude"

#: Alias rather than a pinned id: the CLI resolves 'opus'/'sonnet' to whatever
#: the subscription currently serves, and pinning here would silently diverge
#: from what the user is actually paying for.
DEFAULT_MODEL = "opus"

#: One review is one short request: a single proposal in, four advisory fields
#: out. Shared so "slow" means the same number for every backend of that role.
TIMEOUT_SECONDS = 30.0

#: A Worker's request is not short, and D15 is where that stopped being an
#: opinion. Shown a task, four scope objects and a whole scan's evidence, the
#: Worker ran to a median of 26s against the Reviewer's 11s — and **a third of
#: a 30-run experiment timed out**, with the surviving latencies bunched against
#: the cap at 28–29.5s.
#:
#: That is worse than slow. The Worker's fail-closed path is "no proposal", so
#: the system silently did nothing on ten runs in thirty; and because the cap
#: truncated the distribution from above, the runs it discarded were exactly the
#: ones where the model deliberated longest — which in an injection experiment
#: are the runs most likely to be the interesting ones. A measurement that drops
#: its slowest third is not measuring what it claims to.
WORKER_TIMEOUT_SECONDS = 120.0

#: The isolation flags, as one list so a test can assert on the whole set rather
#: than on whichever ones somebody remembered to check. Verified against
#: `claude --help` rather than recalled — several of these changed name across
#: versions, and a stale flag fails open by being ignored.
ISOLATION_FLAGS: tuple[str, ...] = (
    "--tools", "",                  # zero tools
    "--safe-mode",                  # no CLAUDE.md, skills, plugins, hooks, MCP
    "--setting-sources", "",        # no settings files
    "--strict-mcp-config",          # no ambient MCP servers
    "--disable-slash-commands",     # no skills
    "--no-session-persistence",     # no memory between calls
)


class HeadlessError(RuntimeError):
    """The CLI could not be made to produce a usable reply.

    Carries the reason rather than a partial answer. Every caller turns this
    into its own role's fail-closed outcome — a worried opinion for the
    Reviewer, no proposal at all for the Worker — and neither may guess.
    """


def build_command(
    *, prompt: str, system_prompt: str, schema: dict[str, Any], model: str,
    executable: str = CLI,
) -> list[str]:
    """The exact argv. Separate so a test can assert on it without a call."""
    return [
        executable,
        "--print", prompt,
        "--model", model,
        "--system-prompt", system_prompt,
        "--output-format", "json",
        "--json-schema", json.dumps(schema),
        *ISOLATION_FLAGS,
    ]


@dataclass(frozen=True)
class HeadlessResult:
    payload: dict[str, Any]
    input_tokens: int
    output_tokens: int


def run_headless(
    *, command: list[str], timeout_seconds: float, runner: Any,
) -> HeadlessResult:
    """Run one isolated CLI call and return the model's object.

    Raises :class:`HeadlessError` for every failure mode — timeout, non-zero
    exit, unparseable stdout, an envelope reporting an error despite exit 0 —
    so a caller cannot accidentally handle one and forget another.
    """
    # Fresh and empty every call.
    workdir = tempfile.mkdtemp(prefix="cyberorch-headless-")
    try:
        completed = runner(
            command, cwd=workdir, capture_output=True, text=True,
            # Closed, not inherited. The CLI reads stdin for piped input and
            # waits several seconds before giving up, so whether a headless
            # call works at all depended on what the *calling shell* happened
            # to have attached — the same command succeeded from one context
            # and failed with "no stdin data received in 3s" from another. A
            # model call that behaves differently depending on how the harness
            # around it was invoked is a call whose results cannot be compared
            # between runs.
            stdin=subprocess.DEVNULL,
            timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HeadlessError(f"timed out after {timeout_seconds}s") from exc
    except (OSError, ValueError) as exc:
        raise HeadlessError(f"{type(exc).__name__}: {exc}") from exc
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if completed.returncode != 0:
        # stderr is truncated: it can carry the prompt back, and the prompt
        # contains attacker-influenced text that would then land in an audit
        # payload unbounded.
        detail = (completed.stderr or "").strip()[:200]
        raise HeadlessError(f"cli exited {completed.returncode}: {detail}")

    try:
        envelope = parse_json_object(completed.stdout)
        payload = unwrap(envelope)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HeadlessError(f"unparseable reply: {exc}") from exc

    return HeadlessResult(
        payload=payload,
        input_tokens=usage(envelope, "input_tokens"),
        output_tokens=usage(envelope, "output_tokens"),
    )


def parse_json_object(raw: str) -> dict[str, Any]:
    """Parse a reply that should be one JSON object.

    Nothing is salvaged from a malformed reply. Digging a JSON object out of
    surrounding prose would mean guessing which part was the answer, and a
    guessed answer is worse than an absent one: the absent one fails closed.
    """
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError(f"expected an object, got {type(parsed).__name__}")
    return parsed


def unwrap(envelope: dict[str, Any]) -> dict[str, Any]:
    """Pull the answer out of the CLI's result envelope.

    ``--output-format json`` returns metadata around the model's answer, and the
    answer itself may arrive either already parsed or as a JSON string in
    ``result``. Both are accepted; anything else raises rather than being
    guessed at.

    An envelope reporting an error is treated as a failure even though the
    process exited zero — a CLI that says ``is_error`` and returns 0 would
    otherwise pass a hallucinated answer straight through.
    """
    if envelope.get("is_error") or envelope.get("subtype") == "error":
        raise ValueError(f"cli reported an error: {str(envelope)[:200]}")

    result = envelope.get("result", envelope)
    if isinstance(result, str):
        result = parse_json_object(result)
    if not isinstance(result, dict):
        raise ValueError(f"expected an object, got {type(result).__name__}")
    return result


def usage(envelope: dict[str, Any], field: str) -> int:
    block = envelope.get("usage")
    if isinstance(block, dict):
        try:
            return int(block.get(field, 0) or 0)
        except (TypeError, ValueError):
            return 0
    return 0
