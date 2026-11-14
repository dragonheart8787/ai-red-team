"""D69 H5a1 (a3): the idempotency key of a task and an attempt (``harness/idempotency.py``).

``propose_action`` without a key gives every call a fresh one; the harness gives it
``h5:<task_id>:<attempt>`` so that the same task and attempt is the same key (plan item 47, 3.5).
No database, no clock: a pure function.
"""

from __future__ import annotations

import pytest

from harness.idempotency import derive_key


def test_the_key_is_h5_task_id_attempt():
    assert derive_key("TASK-0a1b2c3d4e", 1) == "h5:TASK-0a1b2c3d4e:1"
    assert derive_key("TASK-0a1b2c3d4e", 7) == "h5:TASK-0a1b2c3d4e:7"


def test_attempt_1_is_the_first_key_h5_task_1():
    task = "TASK-ffffffffff"
    assert derive_key(task, 1) == f"h5:{task}:1"


def test_the_same_input_gives_the_same_key_every_time():
    keys = {derive_key("TASK-1111111111", 1) for _ in range(50)}
    assert keys == {"h5:TASK-1111111111:1"}
    again = {derive_key("TASK-1111111111", 3) for _ in range(50)}
    assert again == {"h5:TASK-1111111111:3"}


def test_different_tasks_have_different_keys():
    keys = [derive_key(f"TASK-{i:010d}", 1) for i in range(30)]
    assert len(set(keys)) == len(keys)
    assert derive_key("TASK-aaaaaaaaaa", 1) != derive_key("TASK-bbbbbbbbbb", 1)


def test_different_attempts_have_different_keys():
    keys = [derive_key("TASK-aaaaaaaaaa", attempt) for attempt in range(1, 12)]
    assert len(set(keys)) == len(keys)


@pytest.mark.parametrize("task_id", ["", None, 5, b"TASK-x", ["TASK-x"], "TASK:x", "a:b:c", ":"])
def test_a_task_id_that_is_not_a_non_empty_string_without_a_colon_is_refused(task_id):
    with pytest.raises(ValueError):
        derive_key(task_id, 1)


@pytest.mark.parametrize("attempt", [0, -1, -100, True, False, 1.0, 2.5, "1", None, [1]])
def test_an_attempt_that_is_not_an_int_of_at_least_one_is_refused(attempt):
    with pytest.raises(ValueError):
        derive_key("TASK-aaaaaaaaaa", attempt)


def test_two_colons_in_the_key_come_only_from_the_format():
    assert derive_key("TASK-aaaaaaaaaa", 4).count(":") == 2
