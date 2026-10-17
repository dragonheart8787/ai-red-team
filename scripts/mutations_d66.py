# ruff: noqa: E501  -- the edits quote source lines verbatim; they must match exactly
"""The mutations of D66-F3 (ACCEPTANCE 5.109), as runnable checks (see ``mutation_check.py``).

``python scripts/mutations_d66.py --list`` names them. The shared classification of "is Docker lost"
(``control_plane/docker_health.py``) and the two services that use it: each mutation breaks one rule
of it, or lets a service classify on its own, and a named test must be red.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutation_check import Edit, Mutation, main  # noqa: E402

HEALTH = "control_plane/docker_health.py"
SCHEDULER = "control_plane/scheduler/service.py"
RECONCILER = "control_plane/reconciler/service.py"
TESTS = ("tests/test_docker_health.py", "tests/test_docker_health_structure.py")
STRUCTURE = ("tests/test_docker_health_structure.py",)
TABLE = ("tests/test_docker_health.py",)

CATALOGUE = [
    Mutation("D66-F3-a", "the scheduler no longer asks the shared classification (back to F3: exit 1)",
             TESTS,
             edits=(Edit(SCHEDULER, "    if docker_health.is_lost(exc):\n        return StopService(vocab.STOP_DOCKER_LOST)\n",
                         "    if False:\n        return StopService(vocab.STOP_DOCKER_LOST)\n"),),
             targets=("test_the_scheduler_exits_5_not_1_for_a_daemon_that_is_gone",
                      "test_a_daemon_that_dies_under_a_dispatch_in_flight_stops_the_scheduler_with_exit_5",
                      "test_each_service_imports_the_shared_classification_and_calls_it_in_translate")),
    Mutation("D66-F3-b", "the reconciler no longer asks the shared classification",
             TESTS,
             edits=(Edit(RECONCILER, "    if docker_health.is_lost(exc):\n        return StopService(emit.STOP_DOCKER_LOST)\n",
                         "    if False:\n        return StopService(emit.STOP_DOCKER_LOST)\n"),),
             targets=("test_the_scheduler_and_the_reconciler_give_the_same_answer",
                      "test_each_service_imports_the_shared_classification_and_calls_it_in_translate")),
    Mutation("D66-F3-c", "a builtin connection error (an OSError) is not a lost daemon",
             TABLE,
             edits=(Edit(HEALTH, "    if isinstance(exc, OSError):          # builtin ConnectionError, TimeoutError, a bare socket\n        return LOST\n",
                         "    if isinstance(exc, OSError):\n        return None\n"),),
             targets=("test_the_classification",)),
    Mutation("D66-F3-d", "an HTTP 5xx from the daemon is an answer, not a lost daemon",
             TABLE,
             edits=(Edit(HEALTH, "return LOST if status is None or status >= 500 else ANSWERED",
                         "return LOST if status is None else ANSWERED"),),
             targets=("test_the_classification",)),
    Mutation("D66-F3-e", "the cause chain is not looked through (requests around urllib3 around FileNotFoundError)",
             TABLE,
             edits=(Edit(HEALTH, "        current = current.__cause__ or current.__context__\n",
                         "        current = None\n"),),
             targets=("test_the_classification",)),
    Mutation("D66-F3-f", "a container that vanished (NotFound) is a lost daemon again (back to F1)",
             TABLE,
             edits=(Edit(HEALTH, "    if isinstance(exc, NotFound):\n        return GONE\n",
                         "    if isinstance(exc, NotFound):\n        return LOST\n"),),
             targets=("test_the_classification",)),
    Mutation("D66-F3-g", "a host file-system error outside a Docker error is called Docker's",
             TABLE,
             edits=(Edit(HEALTH, "    if isinstance(exc, _HOST_FILE_ERRORS):\n        return None\n",
                         "    if isinstance(exc, _HOST_FILE_ERRORS):\n        return LOST\n"),),
             targets=("test_the_classification",)),
    Mutation("D66-F3-h", "the scheduler imports Docker's exceptions to classify on its own",
             STRUCTURE,
             edits=(Edit(SCHEDULER, "from control_plane import docker_health\n",
                         "from control_plane import docker_health\nfrom docker.errors import APIError  # noqa: F401\n"),),
             targets=("test_no_service_imports_docker_or_requests_or_names_a_docker_exception",)),
    Mutation("D66-F3-i", "the reconciler imports requests to classify on its own",
             STRUCTURE,
             edits=(Edit(RECONCILER, "from control_plane import docker_health\n",
                         "from control_plane import docker_health\nimport requests  # noqa: F401\n"),),
             targets=("test_no_service_imports_docker_or_requests_or_names_a_docker_exception",)),
    # ---- enrollments in the residue check, and the characters the operator CLI accepts (5.109)
    Mutation("D66-E-a", "the end of a test no longer withdraws what the test enrolled",
             ("tests/test_residue_check.py", "tests/test_residue_wiring.py"),
             edits=(Edit("tests/residue.py", "    new = live_enrollments() - before\n    done = withdraw_enrollments(new)\n",
                         "    new = live_enrollments() - before\n    done = 0\n"),),
             targets=("test_the_end_of_a_test_withdraws_what_it_enrolled_and_nothing_that_was_live_before",
                      "test_a_test_that_enrolls_an_engagement_has_it_withdrawn_when_it_ends")),
    Mutation("D66-E-b", "the end of a test withdraws every live enrollment, including ones that were there before it",
             ("tests/test_residue_check.py",),
             edits=(Edit("tests/residue.py", "    new = live_enrollments() - before\n    done = withdraw_enrollments(new)\n",
                         "    new = live_enrollments()\n    done = withdraw_enrollments(new)\n"),),
             targets=("test_the_end_of_a_test_withdraws_what_it_enrolled_and_nothing_that_was_live_before",)),
    Mutation("D66-E-c", "the session end does not look at enrollments",
             ("tests/test_residue_check.py", "tests/test_residue_wiring.py"),
             edits=(Edit("tests/residue.py", "        enrollments=sorted(live_enrollments() - before.enrollments))\n",
                         "        enrollments=[])\n"),),
             targets=("test_an_enrollment_made_after_the_snapshot_is_residue_and_one_before_it_is_not",
                      "test_a_session_that_leaves_a_scheduler_enrollment_behind_fails")),
    Mutation("D66-E-d", "the snapshot does not record the enrollments that were live before the session",
             ("tests/test_residue_check.py",),
             edits=(Edit("tests/residue.py", "        enrollments=live_enrollments(),\n        layers=",
                         "        enrollments=frozenset(),\n        layers="),),
             targets=("test_an_enrollment_made_after_the_snapshot_is_residue_and_one_before_it_is_not",)),
    Mutation("D66-E-e", "the CLI does not check --by or the engagement id before the confirmation",
             ("tests/test_scheduler_cli.py",),
             edits=(Edit("scripts/manage_scheduler_enrollment.py", "        if not emit.is_plain_id(value):\n            print(f\"refused:",
                         "        if False:\n            print(f\"refused:"),),
             targets=("test_a_name_that_is_not_a_plain_identifier_is_refused_before_anything_is_asked",
                      "test_an_engagement_id_that_is_not_a_plain_identifier_is_refused_the_same_way")),
    Mutation("D66-E-f", "the rule matches a prefix (a name with a newline or a semicolon after a good start passes)",
             ("tests/test_scheduler_cli.py",),
             edits=(Edit("control_plane/scheduler/emit.py", "bool(_ID.fullmatch(value))", "bool(_ID.match(value))"),),
             targets=("test_a_name_that_is_not_a_plain_identifier_is_refused_before_anything_is_asked",)),
    Mutation("D66-E-g", "the listing prints an odd stored name as it is",
             ("tests/test_scheduler_cli.py",),
             edits=(Edit("scripts/manage_scheduler_enrollment.py", "    return value if emit.is_plain_id(value) else repr(value)\n",
                         "    return value\n"),),
             targets=("test_the_listing_shows_an_old_row_with_an_odd_name_quoted",)),
    # ---- the denial's provenance on an autocommit connection (5.110)
    Mutation("D66-P-a", "the denial records its provenance without a savepoint",
             ("tests/test_deny_provenance_connection.py",),
             edits=(Edit("control_plane/api/approvals.py",
                         "        with conn.begin_nested():\n            graph.record_provenance(conn, engagement_id=engagement_id, proposal_id=proposal_id)\n",
                         "        if True:\n            graph.record_provenance(conn, engagement_id=engagement_id, proposal_id=proposal_id)\n"),),
             targets=("test_a_denial_on_an_autocommit_connection_closes_the_proposal_without_provenance_and_logs",)),
    Mutation("D66-P-b", "a failed provenance takes the denial with it (the error is not caught)",
             ("tests/test_deny_provenance_connection.py",),
             edits=(Edit("control_plane/api/approvals.py", "    except SQLAlchemyError:\n        logger.error(\"provenance for denied",
                         "    except ZeroDivisionError:\n        logger.error(\"provenance for denied"),),
             targets=("test_a_denial_on_an_autocommit_connection_closes_the_proposal_without_provenance_and_logs",)),
]

if __name__ == "__main__":
    main({m.id: m for m in CATALOGUE})
