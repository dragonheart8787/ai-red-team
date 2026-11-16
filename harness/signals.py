"""D69 H5a2 (a9): the stop flag, and a handler that sets it. No signal is registered here.

A signal handler must do almost nothing, so the harness's handler does one thing: it sets a flag.
The loop looks at the flag only at *safe points* -- before a round starts, between engagements and
before a claim -- and never between a task's ``work``, ``propose`` and ``complete``. A flag set in
the middle of a task is seen after that task has been completed, and only then does the loop stop.

This stage provides the flag, the handler and :func:`install`, which takes the function that
registers a handler as an argument (``signal.signal``, in the stage that sends a real signal). It
does not call ``signal.signal`` itself and imports no ``signal`` module, so nothing here can change
how a process handles a signal.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from typing import Any, Protocol


class StopFlag(Protocol):
    """What the loop asks of a stop flag: only whether it is set."""

    def is_set(self) -> bool: ...


class SignalFlag:
    """A stop flag: a thin wrapper around :class:`threading.Event`."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def set(self) -> None:
        self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set()


def handler_for(flag: SignalFlag) -> Callable[..., None]:
    """A handler with the signature of a signal handler that sets ``flag`` and does nothing else."""

    def handler(*_args: Any) -> None:
        flag.set()

    return handler


def install(
    register: Callable[[int, Callable[..., None]], Any],
    flag: SignalFlag,
    signal_numbers: Iterable[int],
) -> None:
    """Register :func:`handler_for` ``flag`` for each of ``signal_numbers`` with ``register``."""
    handler = handler_for(flag)
    for number in signal_numbers:
        register(number, handler)
