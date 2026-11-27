"""The scheduler's closed vocabularies (D62). Every code that can reach an audit payload, the
``scheduler_state`` table, or an operator's screen is listed here, and nowhere else.

``scheduler_state``'s ``CHECK`` constraints (migration 0019) repeat the disposition and reason
codes; ``tests/test_scheduler_roles.py`` fails if the two lists drift.
"""

from __future__ import annotations

# --- audit events: exactly what v0 emits ---------------------------------------------------------
STARTED = "scheduler.started"
STOPPED = "scheduler.stopped"
START_REFUSED = "scheduler.start_refused"
ENROLLED = "scheduler.enrolled"        # written by the operator CLI, not the service
WITHDRAWN = "scheduler.withdrawn"      # written by the operator CLI, not the service
DISPATCHED = "scheduler.dispatched"    # "the scheduler decided to attempt a dispatch" -- not "ran"
DEFERRED = "scheduler.deferred"
RESUMED = "scheduler.resumed"
SKIPPED = "scheduler.skipped"

EVENTS = (STARTED, STOPPED, START_REFUSED, ENROLLED, WITHDRAWN, DISPATCHED, DEFERRED, RESUMED,
          SKIPPED)

# --- reason codes --------------------------------------------------------------------------------
APPROVED_AND_IDLE = "approved_and_idle"

DEFER_REASONS = ("engagement_paused", "engagement_killed", "engagement_not_active")

ACTION_NOT_SUPPORTED = "action_not_supported_v0"
SCOPE_TYPE_NO_RANGE = "scope_type_has_no_network_range"
SCOPE_TOO_NARROW = "scope_narrower_than_sandbox_minimum"
TARGET_RESERVED = "target_is_reserved_address"
IPV6_UNSUPPORTED = "ipv6_not_supported_v0"
SKIP_REASONS = (ACTION_NOT_SUPPORTED, SCOPE_TYPE_NO_RANGE, SCOPE_TOO_NARROW, TARGET_RESERVED,
                IPV6_UNSUPPORTED)

#: D69-NC-2 (``docs/ADR_INLINE_DISPATCH_ALLOWLIST.md``): why ``function_api._dispatch`` did not
#: start a network dispatch whose allowlist the caller passed. Outcomes of the dispatch (the
#: proposal's ``stage_detail`` and ``ActionOutcome.failure``), not dispositions of the scheduler, so
#: they are apart from ``SKIP_REASONS``, which migration 0019's ``CHECK`` repeats. A skip reason of
#: ``derive_network_allowlist`` is used as it is.
ALLOWLIST_INVALID = "allowlist_invalid"                      # an entry is not a CIDR
ALLOWLIST_EXCEEDS_SCOPE = "allowlist_exceeds_scope"          # an entry is not inside the scope
TARGET_OUTSIDE_ALLOWLIST = "target_outside_allowlist"        # the ip target is in no entry
AUTHORIZED_SCOPE_MISSING = "authorized_scope_missing"        # no scope object to derive from
ALLOWLIST_REFUSALS = (ALLOWLIST_INVALID, ALLOWLIST_EXCEEDS_SCOPE, TARGET_OUTSIDE_ALLOWLIST,
                      AUTHORIZED_SCOPE_MISSING)

STOP_SIGNAL = "signal"
STOP_LOCK_LOST = "lock_lost"
STOP_DB_LOST = "db_lost"
STOP_DOCKER_LOST = "docker_lost"
STOP_AUDIT_FAILED = "audit_failed"
STOP_NOT_ADVANCED = "dispatch_did_not_advance"
STOP_UNEXPECTED = "unexpected_error"
STOP_REASONS = (STOP_SIGNAL, STOP_LOCK_LOST, STOP_DB_LOST, STOP_DOCKER_LOST, STOP_AUDIT_FAILED,
                STOP_NOT_ADVANCED, STOP_UNEXPECTED)

LOCK_HELD = "lock_held"

# --- scheduler_state dispositions ----------------------------------------------------------------
SERVED, DEFERRED_STATE = "served", "deferred"
SKIPPED_STATE, DISPATCH_DECIDED = "skipped", "dispatch_decided"
DISPOSITIONS = (SERVED, DEFERRED_STATE, SKIPPED_STATE, DISPATCH_DECIDED)

# --- what v0 dispatches: explicit names, no wildcard ---------------------------------------------
#: A wildcard would widen v0 silently when an action is added (ACCEPTANCE 5.9 recorded the same
#: hazard for scope patterns). ``action_class`` comes from the ``scheduler_proposals`` view, which
#: maps any name that is not a registered action to ``'other'``.
SUPPORTED_ACTIONS = ("network.scan", "network.recon", "code.scan", "code.secrets")
NETWORK_ACTIONS = ("network.scan", "network.recon")
CODE_ACTIONS = ("code.scan", "code.secrets")

# --- exit codes ----------------------------------------------------------------------------------
EXIT_OK = 0
EXIT_UNEXPECTED = 1
EXIT_LOCK_HELD = 2
EXIT_AUDIT_FAILED = 3
EXIT_DB_LOST = 4
EXIT_DOCKER_LOST = 5
EXIT_LOCK_LOST = 6
EXIT_NOT_ADVANCED = 7

EXIT_CODE_OF_STOP = {
    STOP_SIGNAL: EXIT_OK,
    STOP_UNEXPECTED: EXIT_UNEXPECTED,
    STOP_AUDIT_FAILED: EXIT_AUDIT_FAILED,
    STOP_DB_LOST: EXIT_DB_LOST,
    STOP_DOCKER_LOST: EXIT_DOCKER_LOST,
    STOP_LOCK_LOST: EXIT_LOCK_LOST,
    STOP_NOT_ADVANCED: EXIT_NOT_ADVANCED,
}
