"""D69 H5a1 (a1): the loop's stop reasons and their exit codes (``harness/exit_codes.py``).

The table is the one in plan items 47 and 58: 0 to 6 keep the scheduler's meanings, 7 is not used,
the harness's own start at 10. Nothing here touches a database, a process or the control plane.
"""

from __future__ import annotations

import pytest

from harness import exit_codes as x
from harness.exit_codes import StopReason, cleans_up_unclaimed, exit_code

#: Written out again here, on purpose: the module's own table is what is being checked.
EXPECTED = {
    StopReason.SIGNAL_OR_ONCE: 0,
    StopReason.UNEXPECTED: 1,
    StopReason.LOCK_HELD: 2,
    StopReason.AUDIT_FAILED: 3,
    StopReason.DB_LOST: 4,
    StopReason.DOCKER_UNREACHABLE: 5,
    StopReason.LOCK_LOST: 6,
    StopReason.STARTUP_REFUSED: 10,
    StopReason.FOREIGN_TASK: 11,
    StopReason.FAULT_OUTSIDE_LIST: 12,
    StopReason.CAP_REACHED: 13,
    StopReason.NO_PROGRESS: 14,
}


@pytest.mark.parametrize("reason,code", list(EXPECTED.items()), ids=lambda v: str(v))
def test_each_stop_reason_has_the_code_the_table_gives_it(reason, code):
    assert exit_code(reason) == code


def test_every_stop_reason_has_a_code_and_the_table_has_nothing_else():
    assert set(x.EXIT_CODE) == set(StopReason) == set(EXPECTED)
    for reason in StopReason:
        assert isinstance(exit_code(reason), int)


def test_the_table_is_injective_no_two_reasons_share_a_code():
    codes = [exit_code(reason) for reason in StopReason]
    assert len(set(codes)) == len(codes), codes


def test_code_1_and_code_12_are_different_codes_for_different_reasons():
    assert exit_code(StopReason.UNEXPECTED) == 1
    assert exit_code(StopReason.FAULT_OUTSIDE_LIST) == 12
    assert exit_code(StopReason.UNEXPECTED) != exit_code(StopReason.FAULT_OUTSIDE_LIST)


def test_code_7_is_reserved_and_no_stop_reason_is_mapped_to_it():
    assert 7 in x.RESERVED_CODES
    assert 7 not in {exit_code(reason) for reason in StopReason}
    assert x.RESERVED_CODES.isdisjoint(x.EXIT_CODE.values())


def test_the_named_constants_are_the_numbers_of_the_table():
    assert (x.EXIT_OK, x.EXIT_UNEXPECTED, x.EXIT_LOCK_HELD, x.EXIT_AUDIT_FAILED, x.EXIT_DB_LOST,
            x.EXIT_DOCKER_LOST, x.EXIT_LOCK_LOST) == (0, 1, 2, 3, 4, 5, 6)
    assert (x.EXIT_STARTUP_REFUSED, x.EXIT_FOREIGN_TASK, x.EXIT_FAULT_OUTSIDE_LIST,
            x.EXIT_CAP_REACHED, x.EXIT_NO_PROGRESS) == (10, 11, 12, 13, 14)


def test_cleans_up_unclaimed_is_true_for_exactly_four_reasons():
    cleaning = {reason for reason in StopReason if cleans_up_unclaimed(reason)}
    assert cleaning == {
        StopReason.SIGNAL_OR_ONCE,      # code 0: a signal, or --once done
        StopReason.STARTUP_REFUSED,     # code 10
        StopReason.CAP_REACHED,         # code 13
        StopReason.NO_PROGRESS,         # code 14
    }
    # ... and the faults and the lost things are not among them.
    for reason in (StopReason.UNEXPECTED, StopReason.FOREIGN_TASK, StopReason.FAULT_OUTSIDE_LIST,
                   StopReason.LOCK_HELD, StopReason.AUDIT_FAILED, StopReason.DB_LOST,
                   StopReason.DOCKER_UNREACHABLE, StopReason.LOCK_LOST):
        assert cleans_up_unclaimed(reason) is False


@pytest.mark.parametrize("not_a_reason", [0, 12, "cap_reached", None, StopReason])
def test_a_value_that_is_not_a_stop_reason_is_refused(not_a_reason):
    with pytest.raises(ValueError):
        exit_code(not_a_reason)
    with pytest.raises(ValueError):
        cleans_up_unclaimed(not_a_reason)
