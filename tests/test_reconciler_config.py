"""The reconciler's thresholds come from configuration, all of them, and it refuses to start without
(D64-3, D64-5).

* a missing key is refused, by name, for every key; so is an empty one;
* an unusable value (not a whole number, not positive, below the least the code implies) is refused,
  by name; all the problems are listed at once, not the first;
* nothing in the module has a default: the loader is shown to read every value from its argument;
* the recommended values in ``.env.example`` are a valid configuration, and each key there is
  documented with its derivation -- the configuration is not a number someone has to guess.
"""

from __future__ import annotations

import ast
import dataclasses
import re
from pathlib import Path

import pytest

from control_plane.policy.ceiling import MAX_DURATION_CEILING_SECONDS
from control_plane.reconciler import config
from control_plane.reconciler.config import ConfigError, Thresholds, load

REPO = Path(__file__).resolve().parents[1]
VALID = {
    "RECONCILER_STAGE_GRACE_S": "3600", "RECONCILER_LEASE_GRACE_S": "30",
    "RECONCILER_APPROVAL_GRACE_S": "30", "RECONCILER_B_CAP_S": "1800",
    "RECONCILER_P_PROXY_S": "915", "RECONCILER_Q_PROXY_S": "300",
    "RECONCILER_KILL_MARGIN_S": "60", "RECONCILER_MAX_CLOCK_SKEW_S": "5",
    "RECONCILER_RETENTION_S": "86400",
    "RECONCILER_NETWORK_IDLE_S": "3600", "RECONCILER_NETWORK_SWEEP_PERIOD_S": "86400",
    "RECONCILER_VERIFY_WAIT_S": "10", "RECONCILER_SUMMARY_PERIOD_S": "3600",
    "RECONCILER_RETRY_AFTER_FAILURE_S": "1800", "RECONCILER_MAX_PAGES": "20",
    "RECONCILER_MAX_ACTIONS_PER_PASS": "500", "RECONCILER_BACKOFF_MAX_S": "900",
    "RECONCILER_NETWORK_CONFLICT_WINDOW_S": "86400",
    "RECONCILER_NETWORK_CONFLICT_MIN_IDLE_S": "3600",
    "RECONCILER_NETWORK_CONFLICT_DAILY_CAP": "3",
}


def test_the_valid_set_covers_every_key_there_is():
    assert set(VALID) == set(config.KEYS)
    assert len(config.KEYS) == len(dataclasses.fields(Thresholds))


def test_a_complete_valid_configuration_loads_into_a_frozen_value():
    th = load(VALID)
    assert th.stage_grace_s == 3600 and th.b_cap_s == 1800 and th.p_proxy_s == 915
    with pytest.raises(dataclasses.FrozenInstanceError):
        th.b_cap_s = 1                                              # type: ignore[misc]


@pytest.mark.parametrize("key", config.KEYS)
def test_a_missing_key_is_refused_and_named(key):
    env = {k: v for k, v in VALID.items() if k != key}
    with pytest.raises(ConfigError) as refused:
        load(env)
    assert [p for p in refused.value.problems if p.startswith(key)], refused.value.problems
    assert len(refused.value.problems) == 1


@pytest.mark.parametrize("key", config.KEYS)
@pytest.mark.parametrize("bad", ["", "   ", "abc", "12s", "1.5", "-5", "0", "+5", "1e3", "0x10",
                                 "１２３"])
def test_an_unusable_value_is_refused_and_named(key, bad):
    try:
        load({**VALID, key: bad})
    except ConfigError as refused:
        assert [p for p in refused.problems if p.startswith(key)], (bad, refused.problems)
        return
    except Exception as exc:                                         # noqa: BLE001
        pytest.fail(f"{bad!r} was not refused by ConfigError: {type(exc).__name__}")
    pytest.fail(f"{bad!r} was accepted for {key}")


def test_with_nothing_set_every_key_is_listed_not_just_the_first():
    with pytest.raises(ConfigError) as refused:
        load({})
    named = {p.split(":")[0] for p in refused.value.problems}
    assert named == set(config.KEYS)
    assert "missing" in refused.value.problems[0]


def test_unrelated_environment_is_ignored_and_extra_reconciler_keys_do_not_help():
    assert load({**VALID, "PATH": "/bin", "RECONCILER_NOT_A_KEY": "1"}) == load(VALID)


def test_nothing_is_defaulted_the_loader_reads_each_value_from_its_argument():
    seen = []

    class Env(dict):
        def get(self, key, default=None):
            seen.append(key)
            return super().get(key, default)

    load(Env(VALID))
    assert sorted(seen) == sorted(config.KEYS)
    # and the module has no numeric literal that could be a value: the only ones are the call counts
    # and timeouts the minimums are built from, which are named constants
    tree = ast.parse((REPO / "control_plane/reconciler/config.py").read_text())
    named = {n.targets[0].id for n in ast.walk(tree) if isinstance(n, ast.Assign)
             and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Constant)}
    assert named == {"PREFIX", "DOCKER_CALLS_BEFORE_PROXY", "PROXY_READINESS_S",
                     "DOCKER_CALLS_AFTER_PROXY", "DECISION_STAGE_FLOOR_S",
                     "SKEW_FRACTION_OF_MARGIN"}
    in_functions = [node.value for func in ast.walk(tree) if isinstance(func, ast.FunctionDef)
                    for node in ast.walk(func)
                    if isinstance(node, ast.Constant) and isinstance(node.value, int)
                    and not isinstance(node.value, bool)]
    assert set(in_functions) <= {0, 1, 2}, in_functions     # counting, never a threshold


# --- the least the code implies ---------------------------------------------------------------

def test_the_minimums_are_what_the_code_says():
    m = config.minimums()
    assert m["b_cap_s"] == MAX_DURATION_CEILING_SECONDS
    assert m["p_proxy_s"] == 15 * 60 + 15 == 915
    assert m["q_proxy_s"] == 5 * 60 == 300
    assert m["stage_grace_s"] == 300
    from docker.constants import DEFAULT_TIMEOUT_SECONDS
    assert config.DOCKER_CALL_TIMEOUT_S == DEFAULT_TIMEOUT_SECONDS == 60


@pytest.mark.parametrize("key, least", [
    ("RECONCILER_B_CAP_S", MAX_DURATION_CEILING_SECONDS), ("RECONCILER_P_PROXY_S", 915),
    ("RECONCILER_Q_PROXY_S", 300), ("RECONCILER_STAGE_GRACE_S", 300)])
def test_a_value_below_what_the_code_implies_is_refused_and_the_least_is_accepted(key, least):
    with pytest.raises(ConfigError) as refused:
        load({**VALID, key: str(least - 1)})
    assert [p for p in refused.value.problems if p.startswith(key) and "least" in p]
    assert load({**VALID, key: str(least)})


# --- the derived bounds ---------------------------------------------------------------------------

def test_the_derived_bounds_are_functions_of_the_configured_terms_only():
    th = load(VALID)
    assert th.budget_s(120) == 120 and th.budget_s(10 ** 9) == 1800
    assert th.unknown_after_s(120) == 120 + 915 + 300
    assert th.unknown_after_s(10 ** 9) == 1800 + 915 + 300
    assert th.kill_after_s(120) == 180 and th.kill_after_s(10 ** 9) == 1860
    assert th.proxy_overdue_after_s(120) == 180 + 915
    assert th.file_age_s() == 1800 + 915 + 300
    assert load({**VALID, "RECONCILER_B_CAP_S": "2000"}).file_age_s() == 2000 + 915 + 300


# --- the documented example ------------------------------------------------------------------

def _example() -> dict[str, str]:
    values = {}
    for line in (REPO / ".env.example").read_text().splitlines():
        match = re.fullmatch(r"(RECONCILER_(?!READER)[A-Z_]+)=(\S+)", line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


def test_env_example_lists_every_key_with_the_recommended_values_and_they_load():
    assert set(_example()) == set(config.KEYS)
    assert load(_example()) == load(VALID)


def test_env_example_explains_each_key():
    text = (REPO / ".env.example").read_text()
    for key in config.KEYS:
        position = text.index(f"\n{key}=")
        comment = text[:position].rsplit("\n\n", 1)[-1]
        assert comment.lstrip().startswith("#") and len(comment) > 40, key


# --- the network-conflict keys (migration 0025) ----------------------------------------------

def test_the_conflict_window_is_at_most_what_the_database_function_accepts():
    over = {**VALID, "RECONCILER_NETWORK_CONFLICT_WINDOW_S": str(31 * 86400 + 1)}
    with pytest.raises(ConfigError) as caught:
        config.load(over)
    assert any("NETWORK_CONFLICT_WINDOW_S" in p and "most the database" in p
               for p in caught.value.problems)
    assert config.load({**VALID, "RECONCILER_NETWORK_CONFLICT_WINDOW_S": str(31 * 86400)})


def test_the_minimum_idle_time_is_never_below_b_cap_plus_p_plus_q():
    least = 1800 + 915 + 300
    with pytest.raises(ConfigError) as caught:
        config.load({**VALID, "RECONCILER_NETWORK_CONFLICT_MIN_IDLE_S": str(least - 1)})
    assert any("NETWORK_CONFLICT_MIN_IDLE_S" in p and str(least) in p
               for p in caught.value.problems)
    assert config.load({**VALID, "RECONCILER_NETWORK_CONFLICT_MIN_IDLE_S": str(least)})
    # the floor follows the configured terms, not constants: a larger B_CAP raises it
    with pytest.raises(ConfigError):
        config.load({**VALID, "RECONCILER_B_CAP_S": "3000",
                     "RECONCILER_NETWORK_CONFLICT_MIN_IDLE_S": "3600"})


@pytest.mark.parametrize("key", ["RECONCILER_NETWORK_CONFLICT_WINDOW_S",
                                 "RECONCILER_NETWORK_CONFLICT_MIN_IDLE_S",
                                 "RECONCILER_NETWORK_CONFLICT_DAILY_CAP"])
@pytest.mark.parametrize("value", [None, "", "0", "-1", "1.5", "three"])
def test_each_conflict_key_is_required_and_a_positive_whole_number(key, value):
    env = {k: v for k, v in VALID.items() if k != key}
    if value is not None:
        env[key] = value
    with pytest.raises(ConfigError) as caught:
        config.load(env)
    assert any(key in p for p in caught.value.problems)
