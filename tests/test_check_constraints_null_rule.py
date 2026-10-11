"""A CHECK passes on NULL, so a closed-code CHECK must exclude NULL or say why NULL is a state.

The rule, found the hard way at D62: ``reason_code IN (...)`` is NULL, not false, for a NULL
``reason_code``, and a CHECK accepts NULL. The first ``scheduler_state`` combination check
therefore accepted "skipped, no reason" until each branch said ``reason_code IS NOT NULL``
(migration 0019).

**General rule.** A column that holds a closed vocabulary is declared ``NOT NULL``; or, when NULL
is a real state ("no decision yet", "not verified yet", "served: no reason"), that is stated, and
any row shape in which a code *must* be present is enforced by a further CHECK that excludes NULL
explicitly.

This test enumerates every CHECK in ``public`` that mentions a nullable column and requires it to
be listed below with the reason NULL is acceptable. A new CHECK on a nullable column fails until
someone reads this docstring and writes the reason down -- the same device as the grant matrix of
the scheduler roles.
"""

from __future__ import annotations

from sqlalchemy import text

from control_plane.state.db import get_engine

#: (table, constraint) -> why a NULL in a nullable column it mentions is acceptable.
NULL_IS_A_STATE = {
    ("action_proposals", "action_proposals_decision_check"):
        "NULL until the decision stage: a `received` proposal has no decision yet. Every later "
        "stage is tied to a non-NULL decision by action_proposals_decision_past_received (0021).",
    ("action_proposals", "action_proposals_decision_past_received"):
        "the stage rule itself: `decision IS NOT NULL OR pipeline_stage = 'received'` -- NULL is "
        "legal at `received` and at no other stage (tested in test_migrations_roundtrip and "
        "test_action_proposals_decision_stage).",
    ("findings", "findings_verifier_state_check"):
        "NULL = not verified yet; the verifier states are the closed set once it has run.",
    ("scheduler_state", "scheduler_state_reason_code_check"):
        "NULL for a `served` row (no reason); scheduler_state_check1 requires a code, and "
        "excludes NULL explicitly, for every other disposition (tested in test_scheduler_roles).",
    ("scheduler_state", "scheduler_state_check1"):
        "tests NULL explicitly in every branch (`IS NULL` for served, `IS NOT NULL` otherwise).",
    ("scheduler_state", "scheduler_state_check"):
        "proposal_id is tested `IS NULL` / `IS NOT NULL` explicitly against kind.",
    ("scheduler_enrollment", "scheduler_enrollment_check"):
        "`(withdrawn_at IS NULL) = (withdrawn_by IS NULL)`: NULL-exact by construction.",
    ("audit_log", "audit_scope_consistent"):
        "engagement_id is tested `IS NULL` / `IS NOT NULL` explicitly against scope.",
}


def _checks_on_nullable_columns() -> dict[tuple[str, str], str]:
    with get_engine().connect() as conn:
        rows = conn.execute(text("""
            SELECT r.relname, c.conname, pg_get_constraintdef(c.oid)
            FROM pg_constraint c JOIN pg_class r ON r.oid = c.conrelid
            WHERE c.contype = 'c' AND r.relnamespace = 'public'::regnamespace
              AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.conrelid
                          AND a.attnum = ANY (c.conkey) AND NOT a.attnotnull)
            ORDER BY 1, 2""")).all()
    return {(t, n): d for t, n, d in rows}


def test_every_check_on_a_nullable_column_is_listed_with_its_reason(db_available):
    found = _checks_on_nullable_columns()
    unlisted = sorted(set(found) - set(NULL_IS_A_STATE))
    stale = sorted(set(NULL_IS_A_STATE) - set(found))
    assert not unlisted and not stale, (
        f"CHECKs on nullable columns not in NULL_IS_A_STATE: {unlisted}; listed but gone: "
        f"{stale}. A CHECK accepts NULL; read this module's docstring.")


def test_scheduler_state_excludes_null_wherever_a_code_is_required(db_available):
    """Exercised for real in tests/test_scheduler_roles.py (a skipped, deferred or decided row
    with a NULL reason is refused); here the constraint text is pinned, so dropping the explicit
    exclusion is visible without a database write."""
    definition = _checks_on_nullable_columns()[("scheduler_state", "scheduler_state_check1")]
    assert definition.count("reason_code IS NOT NULL") == 3
    assert "reason_code IS NULL" in definition                      # the `served` branch
