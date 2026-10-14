"""What an action's result can be: one closed vocabulary for the three act modules (D64 §1.7).

``done`` means carried out **and verified** by an observation independent of the call's own reply;
it is the only outcome that reaches the audit hook. Every other outcome says why not, in a fixed
code -- never in the text of an exception, which can carry ids, paths or document content.
"""

from __future__ import annotations

from dataclasses import dataclass

from control_plane.reconciler.model import Action

DONE = "done"                                   # carried out **and** verified
DRY_RUN = "dry_run"                             # would have been carried out
LOST_RACE = "lost_race"                         # the compare-and-set matched no row
SKIPPED_OFF = "skipped_deletions_off"           # a deletion, and the flag is off
GONE = "already_gone"                           # the object was not there to act on
CHANGED = "changed_since_plan"                  # it is no longer what the plan saw
FAILED = "failed"
OUTCOMES = (DONE, DRY_RUN, LOST_RACE, SKIPPED_OFF, GONE, CHANGED, FAILED)

#: the fixed reasons a ``failed`` or ``changed_since_plan`` result carries
NOT_CHANGED_AFTER_UPDATE = "not_changed_after_update"
STILL_RUNNING_AFTER_KILL = "still_running_after_kill"
NOT_GONE_AFTER_REMOVAL = "not_gone_after_removal"
IN_USE = "in_use"
DAEMON_ERROR = "daemon_error"
DB_ERROR = "db_error"
FILE_ERROR = "file_error"
INVALID_ACTION = "invalid_action"
NOT_RUNNING = "not_running"
LABELS_CHANGED = "labels_changed"
NOT_AT_REST = "not_at_rest"
NOT_OURS = "not_ours"
TOO_YOUNG = "too_young"
MOUNTED = "mounted"
NOT_A_REGULAR_FILE = "not_a_regular_file"
FOREIGN_OWNER = "foreign_owner"
#: the audit record that had to come first (a transition's own, an irreversible act's intent) could
#: not be written, so nothing was changed / no call was made
AUDIT_FAILED = "audit_failed"
#: a container whose run ended in ``unknown_outcome`` is removed only after its inspect output and
#: logs were kept (``evidence.py``); they could not be, so it was not removed
EVIDENCE_NOT_SAVED = "evidence_not_saved"
DETAIL_CODES = (NOT_CHANGED_AFTER_UPDATE, STILL_RUNNING_AFTER_KILL, NOT_GONE_AFTER_REMOVAL, IN_USE,
                DAEMON_ERROR, DB_ERROR, FILE_ERROR, INVALID_ACTION, NOT_RUNNING, LABELS_CHANGED,
                NOT_AT_REST, NOT_OURS, TOO_YOUNG, MOUNTED, NOT_A_REGULAR_FILE, FOREIGN_OWNER,
                AUDIT_FAILED, EVIDENCE_NOT_SAVED)


@dataclass(frozen=True)
class Result:
    action: Action
    outcome: str
    detail: str | None = None
    #: the action's own audit record was written in the transaction that made the change, so the
    #: service must not write it a second time (proposal transitions only)
    audited: bool = False
