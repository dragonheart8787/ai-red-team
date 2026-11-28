"""S8's dry-run reading (plan item 164), for ``scripts/analyse_shadow.py``'s ``REGISTERED_READING``
during the dry run only.

**This is not the owner's reading rule.** It decides nothing about the shadow's results: it counts
the records and their lines and names the stop event the records' footers carry, so that the dry
run can show that one look is made, written down in the ledger and shown. The owner's reading is
registered separately, before the shadow's real run.
"""

from __future__ import annotations

from collections.abc import Sequence


def read(records: Sequence) -> str:
    """``"<records> record(s), <lines> line(s), stop_event=<name, or none>"``.

    ``records`` are ``analyse_shadow.ShadowRecord`` values; their lines include the header. The stop
    event is the footer's ``stop_event`` of each record that has one, in the records' order, joined
    by ``,``; ``none`` when no footer names one.
    """
    lines = sum(len(record.lines) for record in records)
    events = [line.get("stop_event") for record in records for line in record.lines
              if line is not None and line.get("line") == "footer" and line.get("stop_event")]
    return (f"{len(records)} record(s), {lines} line(s), "
            f"stop_event={','.join(str(event) for event in events) or 'none'}")
