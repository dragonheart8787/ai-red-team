"""D69 H5a2 (a7): the enrolment list the loop reads, as a one-method interface.

The loop works on the engagements a person has enrolled. It reads the list once per round, so
an engagement enrolled between two rounds is picked up by the next one (and gets its start-up
check before it is visited, see :mod:`harness.loop`). How the list is stored is not this
package's business: the real reader is an adapter of a later stage, and
``tests/harness_fakes.py`` has an in-memory one.

The order is the order the reader returns; the loop visits the engagements in it.
"""

from __future__ import annotations

from typing import Protocol


class EnrolmentReader(Protocol):
    """Reads the enrolled engagements, in order."""

    def enrolled(self) -> tuple[str, ...]: ...
