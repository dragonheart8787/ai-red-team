"""Why a plan-fit validator call did not answer: the kind of failure (D68 DP-15).

Three kinds, and the difference matters to what the control plane does about a *class*:

* ``refusal`` -- the service's safety classifier stopped the turn (``stop_reason: refusal``). It is
  a property of what was asked, which is what the per-class exit rule is about
  (``docs/D68_S7_CODE_SECRETS_FAILURE.md``).
* ``transport`` -- the call never reached an answer for a reason that is not about what was asked:
  a timeout, a connection error, a 5xx, an authentication or usage/rate-limit error. It says
  nothing about the class. The exit rule does not count it (a service outage must not suspend a
  class), and the check still fails closed: ``not_assessed / failed`` asks a person, as always.
* ``unclassified`` -- every other failure: an unparseable or out-of-contract reply, a client
  error (4xx other than the above), an exception nobody has named. It is **counted** by the exit
  rule on purpose: what cannot be shown to be infrastructure is treated as the class's own, so a
  class that keeps failing in a way nobody anticipated still gets taken out rather than sending a
  person every proposal for good (design note 2.6, point 1).

This module is pure: it reads a status, a stop reason, a flag or an exception, never the *text* of
a message, and never a goal or a target. What decides the kind is what the service or the
transport said, not what was asked, so wording cannot choose ``transport``.
"""

from __future__ import annotations

import socket
import subprocess
import urllib.error
from typing import Any

REFUSAL = "refusal"
TRANSPORT = "transport"
UNCLASSIFIED = "unclassified"
FAILURE_KINDS = (REFUSAL, TRANSPORT, UNCLASSIFIED)

#: HTTP statuses that are about the service or the caller's standing, not about the question:
#: server errors, a request timeout, authentication, permission, and rate or usage limits
_TRANSPORT_STATUS = frozenset({401, 402, 403, 408, 429})

#: exception classes by name, so that the optional ``anthropic`` package need not be imported
_TRANSPORT_NAMES = frozenset({
    "APIConnectionError", "APITimeoutError", "AuthenticationError", "PermissionDeniedError",
    "RateLimitError", "InternalServerError", "OverloadedError", "ServiceUnavailableError",
})

_TRANSPORT_TYPES: tuple[type[BaseException], ...] = (
    TimeoutError, ConnectionError, socket.timeout, subprocess.TimeoutExpired,
    urllib.error.URLError,
)


def status_is_transport(status: Any) -> bool:
    """A status code that belongs to the service or the caller's standing."""
    return (isinstance(status, int) and not isinstance(status, bool)
            and (500 <= status <= 599 or status in _TRANSPORT_STATUS))


def classify_failure(
    *, stop_reason: Any = None, api_error_status: Any = None, timed_out: bool = False,
    exception: BaseException | None = None,
) -> str:
    """The kind of one failed call, from what the service or the transport said.

    Order matters: a refusal is a refusal whatever else the envelope holds; a timeout, a status
    or a transport exception is ``transport``; anything left is ``unclassified``.
    """
    if stop_reason == "refusal":
        return REFUSAL
    if timed_out or status_is_transport(api_error_status):
        return TRANSPORT
    if exception is not None:
        if getattr(exception, "stop_reason", None) == "refusal":
            return REFUSAL
        if getattr(exception, "timed_out", False):
            return TRANSPORT
        statuses = (getattr(exception, "api_error_status", None),
                    getattr(exception, "status_code", None), getattr(exception, "code", None))
        if any(status_is_transport(s) for s in statuses):
            return TRANSPORT
        if isinstance(exception, urllib.error.HTTPError):
            return UNCLASSIFIED           # a 4xx the server chose to send is not an outage
        if isinstance(exception, _TRANSPORT_TYPES):
            return TRANSPORT
        if type(exception).__name__ in _TRANSPORT_NAMES:
            return TRANSPORT
    return UNCLASSIFIED
