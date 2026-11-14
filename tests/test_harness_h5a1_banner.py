"""D69 H5a1 (a6): the start-up banner (``harness/banner.py``).

A pure formatter of a dict of facts: eleven fields, no more and no fewer, one line each in a fixed
order. Nothing is read from a database, the environment or a file.
"""

from __future__ import annotations

import copy

import pytest

from harness import banner
from harness.banner import format_banner

FIELDS = (
    "database", "migration_head", "switches", "action_set", "engagements", "role_models",
    "cli_version", "prompt_digests", "window_limit", "caps", "lock_key",
)

FACTS = {
    "database": {"host": "db.example", "name": "cyberorch", "role": "cyberorch_app"},
    "migration_head": "0030",
    "switches": {"task_relation_enforce": True, "goal_fit_enforce": False},
    "action_set": ["network.scan", "network.recon"],
    "engagements": ["ENG-A", "ENG-B"],
    "role_models": {"worker": "model-w", "supervisor": "model-s", "reviewer": "model-r"},
    "cli_version": "2.0.0",
    "prompt_digests": {"supervisor": "sha256:aaaa", "worker": "sha256:bbbb"},
    "window_limit": 200,
    "caps": {"max_rounds": 10, "max_model_calls": 100, "no_progress_limit": 3},
    "lock_key": "0x0D69_5C4E_D000_0001",
}

EXPECTED_LINES = [
    "database: host=db.example name=cyberorch role=cyberorch_app",
    "migration_head: 0030",
    "switches: task_relation_enforce=true goal_fit_enforce=false",
    "action_set: network.scan, network.recon",
    "engagements: ENG-A, ENG-B",
    "role_models: reviewer=model-r, supervisor=model-s, worker=model-w",
    "cli_version: 2.0.0",
    "prompt_digests: supervisor=sha256:aaaa worker=sha256:bbbb",
    "window_limit: 200",
    "caps: max_rounds=10 max_model_calls=100 no_progress_limit=3",
    "lock_key: 0x0D69_5C4E_D000_0001",
]


def facts(**changes):
    out = copy.deepcopy(FACTS)
    out.update(changes)
    return out


def test_the_required_fields_are_exactly_the_eleven_specified_in_order():
    assert banner.REQUIRED_FIELDS == FIELDS


def test_the_banner_is_exactly_these_lines():
    assert format_banner(FACTS).split("\n") == EXPECTED_LINES


def test_every_required_field_has_its_own_line_in_the_fixed_order():
    lines = format_banner(FACTS).split("\n")
    assert len(lines) == len(FIELDS)
    for field_name, line in zip(FIELDS, lines, strict=True):
        assert line.startswith(f"{field_name}: "), (field_name, line)


@pytest.mark.parametrize("missing", FIELDS)
def test_a_missing_field_is_refused(missing):
    incomplete = {k: v for k, v in FACTS.items() if k != missing}
    with pytest.raises(ValueError):
        format_banner(incomplete)


@pytest.mark.parametrize("sub", [
    ("database", "host"), ("database", "name"), ("database", "role"),
    ("switches", "task_relation_enforce"), ("switches", "goal_fit_enforce"),
    ("prompt_digests", "supervisor"), ("prompt_digests", "worker"),
    ("caps", "max_rounds"), ("caps", "max_model_calls"), ("caps", "no_progress_limit"),
])
def test_a_missing_part_of_a_field_is_refused(sub):
    outer, inner = sub
    changed = copy.deepcopy(FACTS)
    del changed[outer][inner]
    with pytest.raises(ValueError):
        format_banner(changed)


@pytest.mark.parametrize("extra", ["database_url", "password", "token", "env", "notes"])
def test_an_extra_field_is_refused_and_its_value_is_never_printed(extra):
    secret = "hunter2-SECRET-VALUE"
    with pytest.raises(ValueError) as refused:
        format_banner({**FACTS, extra: secret})
    assert secret not in str(refused.value)
    assert extra in str(refused.value)           # the field is named, the value is not


@pytest.mark.parametrize("outer", ["database", "switches", "prompt_digests", "caps"])
def test_an_extra_part_inside_a_field_is_refused_too(outer):
    changed = copy.deepcopy(FACTS)
    changed[outer]["password"] = "hunter2-SECRET-VALUE"
    with pytest.raises(ValueError) as refused:
        format_banner(changed)
    assert "hunter2-SECRET-VALUE" not in str(refused.value)


def test_the_output_is_deterministic_and_the_mapping_order_does_not_matter():
    first = format_banner(FACTS)
    assert all(format_banner(copy.deepcopy(FACTS)) == first for _ in range(20))
    reordered = facts(role_models={"reviewer": "model-r", "worker": "model-w",
                                   "supervisor": "model-s"})
    assert format_banner(reordered) == first


def test_the_output_has_nothing_but_the_eleven_lines():
    text = format_banner(FACTS)
    assert text.count("\n") == len(FIELDS) - 1
    for secret_like in ("password", "token", "url", "env"):
        assert secret_like not in text


def test_caps_not_set_is_accepted_for_each_cap():
    caps = {"max_rounds": "not set", "max_model_calls": "not set", "no_progress_limit": "not set"}
    lines = format_banner(facts(caps=caps)).split("\n")
    assert lines[9] == "caps: max_rounds=not set max_model_calls=not set no_progress_limit=not set"
    mixed = {"max_rounds": 5, "max_model_calls": "not set", "no_progress_limit": 2}
    assert format_banner(facts(caps=mixed)).split("\n")[9] \
        == "caps: max_rounds=5 max_model_calls=not set no_progress_limit=2"


@pytest.mark.parametrize("bad", [-1, 0, True, False, 1.5, "none", "Not Set", "3", None, []])
def test_a_cap_that_is_not_a_positive_int_or_not_set_is_refused(bad):
    for key in ("max_rounds", "max_model_calls", "no_progress_limit"):
        caps = {"max_rounds": 1, "max_model_calls": 1, "no_progress_limit": 1, key: bad}
        with pytest.raises(ValueError):
            format_banner(facts(caps=caps))


@pytest.mark.parametrize("bad", [-5, 0, True, 2.5, "200", None])
def test_a_window_limit_that_is_not_a_positive_int_is_refused(bad):
    with pytest.raises(ValueError):
        format_banner(facts(window_limit=bad))


@pytest.mark.parametrize("bad", ["true", 1, 0, None, "yes"])
def test_a_switch_that_is_not_a_bool_is_refused(bad):
    with pytest.raises(ValueError):
        format_banner(facts(switches={"task_relation_enforce": bad, "goal_fit_enforce": True}))
    with pytest.raises(ValueError):
        format_banner(facts(switches={"task_relation_enforce": True, "goal_fit_enforce": bad}))


@pytest.mark.parametrize("good", ["0x0D695C4ED0000001", "0x0D69_5C4E_D000_0001", "0xabc", "0x0"])
def test_a_lock_key_in_hexadecimal_is_accepted(good):
    assert format_banner(facts(lock_key=good)).split("\n")[10] == f"lock_key: {good}"


@pytest.mark.parametrize("bad", ["", "0x", "0xZZ", "D695C4E", "0x_1", "0x1_", "0x1__2", 5, None])
def test_a_lock_key_that_is_not_0x_and_hexadecimal_is_refused(bad):
    with pytest.raises(ValueError):
        format_banner(facts(lock_key=bad))


@pytest.mark.parametrize("name", ["migration_head", "cli_version"])
def test_the_plain_text_fields_must_be_non_empty_strings(name):
    for bad in ("", None, 5, ["0030"]):
        with pytest.raises(ValueError):
            format_banner(facts(**{name: bad}))


def test_the_lists_must_be_lists_of_strings_and_a_bare_string_is_not_a_list():
    for name in ("action_set", "engagements"):
        for bad in ("network.scan", None, 5, [5], [""], {"network.scan"}):
            with pytest.raises(ValueError):
                format_banner(facts(**{name: bad}))


def test_an_empty_list_or_mapping_prints_none_and_lists_keep_their_order():
    lines = format_banner(facts(engagements=[], role_models={})).split("\n")
    assert lines[4] == "engagements: (none)"
    assert lines[5] == "role_models: (none)"
    swapped = format_banner(facts(action_set=["network.recon", "network.scan"])).split("\n")
    assert swapped[3] == "action_set: network.recon, network.scan"


def test_facts_that_are_not_a_mapping_are_refused():
    for bad in (None, [], "database", 5):
        with pytest.raises(ValueError):
            format_banner(bad)
