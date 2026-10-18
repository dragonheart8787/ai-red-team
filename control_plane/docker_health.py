"""Is Docker lost, or did it answer? One classification, used by every service that has to say so.

The scheduler and the reconciler each end with an exit code that names a cause, and "Docker went
away" is one of the causes. Twice the two services disagreed with the daemon about it: the
reconciler called a container that vanished while it listed "Docker unreachable" (ACCEPTANCE 5.107),
and the scheduler called a daemon that died under a dispatch "unexpected error" (5.109). Both were
the same mistake -- each service classified Docker's exceptions on its own -- so the classification
is here, once, and a structure test (``tests/test_docker_health_structure.py``) keeps the services
from writing their own.

* ``GONE`` -- ``NotFound`` (404) for an object whose id we hold. Handled where the call is made
  (a listing drops it, an action says ``gone``); if it reaches the top of a service it is a defect.
* ``LOST`` -- the daemon cannot be spoken to or is sick: connection refused, reset, aborted or
  timed out (``requests`` errors and the builtin connection errors), a socket that is not there,
  an SDK error that carries no HTTP answer, an HTTP answer of 5xx. A service ends with
  ``docker_lost``, exit 5.
* ``ANSWERED`` -- an HTTP answer of 4xx other than 404: the daemon is there and this is a defect.
* ``None`` -- not Docker's business: a database error, a bug, a file-system error of the host.

The class of an exception is its own; when it has none, its ``__cause__`` / ``__context__`` chain
is looked through, because libraries wrap (``requests`` around ``urllib3`` around
``FileNotFoundError``). Host file-system errors (``FileNotFoundError``, ``PermissionError``,
``NotADirectoryError``) are not Docker's, unless they are inside a Docker error's chain.
"""

from __future__ import annotations

import requests
from docker.errors import APIError, DockerException, NotFound

LOST = "lost"
GONE = "gone"
ANSWERED = "answered"

_HOST_FILE_ERRORS = (FileNotFoundError, PermissionError, NotADirectoryError)


def _own_class(exc: BaseException) -> str | None:
    if isinstance(exc, NotFound):
        return GONE
    if isinstance(exc, APIError):
        status = exc.status_code
        return LOST if status is None or status >= 500 else ANSWERED
    if isinstance(exc, requests.exceptions.RequestException):
        return LOST
    if isinstance(exc, DockerException):
        return LOST                       # the SDK's own errors that carry no HTTP answer
    if isinstance(exc, _HOST_FILE_ERRORS):
        return None
    if isinstance(exc, OSError):          # builtin ConnectionError, TimeoutError, a bare socket
        return LOST
    return None


def classify(exc: BaseException) -> str | None:
    """``LOST``, ``GONE``, ``ANSWERED`` or ``None`` (not Docker's)."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        found = _own_class(current)
        if found is not None:
            return found
        current = current.__cause__ or current.__context__
    return None


def is_lost(exc: BaseException) -> bool:
    return classify(exc) == LOST
