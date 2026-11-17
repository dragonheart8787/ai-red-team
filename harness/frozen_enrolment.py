"""D69 H5c2 repair: the engagements the loop visits are the ones the banner named.

The banner (``harness/banner.py``) states a *start-up* list of engagements and the switches of
exactly those. The enrolment reader (``harness/enrolment_db.py``) answers from the database every
time it is asked, and the loop asks once per round, so an engagement enrolled after the start would
be visited from the next round although the banner never listed it and never checked its switches.

:class:`FrozenEnrolment` closes that gap without touching the loop or the adapter. It is built with
the list the banner was made from (one read, taken once by the entry script) and with the current
reader, and :meth:`enrolled` returns the start-up engagements **that are still enrolled now**, in
the start-up order:

* an engagement enrolled after the start is never returned (the operator sees it by restarting and
  reading the banner);
* an engagement withdrawn after the start is not returned from the next round (the loop reads the
  list once per round, so the round in progress is unaffected);
* an engagement of the start-up list that was withdrawn and enrolled again is returned again: it is
  on the banner.

It only reads: it asks the current reader and holds no SQL, no write and no connection of its own.
"""

from __future__ import annotations

from collections.abc import Sequence

from harness.enrolment import EnrolmentReader


class FrozenEnrolment:
    """The start-up engagements that are still enrolled, in the order they had at the start."""

    def __init__(self, at_start: Sequence[str], current: EnrolmentReader) -> None:
        self._at_start: tuple[str, ...] = tuple(at_start)
        self._current = current

    def enrolled(self) -> tuple[str, ...]:
        now = tuple(self._current.enrolled())
        return tuple(engagement_id for engagement_id in self._at_start if engagement_id in now)
