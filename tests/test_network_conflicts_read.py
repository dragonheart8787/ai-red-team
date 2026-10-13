"""``reconciler_network_conflicts(p_window_s)``: which networks blocked refused runs, in integers
(migration 0025; D64-N1; ACCEPTANCE 5.90).

The function answers one question for the plan: *of the sandbox networks this database has run on,
which ones overlap the range of a run the sandbox refused for that reason, how often, when last, and
is anything still running on them?* It must answer it **without ever returning a range** -- a
CIDR is
the one thing that must not cross to the plan side -- so the network is named by the number its name
suffix spells, and every column is an integer.

Each scenario builds its own ranges (a random ``fdxx:...::/64`` no earlier test used) and looks only
at the rows for its own blockers, so a development database full of earlier runs cannot colour it.
"""

from __future__ import annotations

import random
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from control_plane.state.db import (
    RECONCILER_FN_OWNER_ROLE,
    RECONCILER_READER_ROLE,
    engagement_scope,
    get_engine,
    reconciler_reader_scope,
)
from tool_gateway.sandbox import DockerSandbox

CONFLICT = "network_range_conflicts_with_another_network"
NO_BLOCKER = -1
DAY = 86_400
COLUMNS = ["blocking_hash_n", "conflicts_n", "last_conflict_us", "last_used_us", "live_runs_n",
           "db_now_us"]
used_prefixes: set[tuple[int, int]] = set()


def fresh_base() -> str:
    """A /64 nobody used: 40 random bits under ``fd00::/8`` (unique local addresses). IPv6, because
    the development database keeps every run of every earlier session and an IPv4 range drawn at
    random would, sooner or later, overlap an earlier scenario's rows (4 for 3, in the one run that
    showed it); ``10.0.0.0/8`` is also in the history for real, and is a blocker for all of 10.x."""
    return "fd{:02x}:{:x}:{:x}:{:x}".format(*(random.getrandbits(n) for n in (8, 16, 16, 16)))


def fresh_block() -> tuple[str, str, str]:
    """(blocker /64, a refused /125 inside it, a second refused /125 inside it)."""
    base = fresh_base()
    return f"{base}::/64", f"{base}::8/125", f"{base}::10/125"


def hash_n(*allowlist: str) -> int:
    """The number the sandbox's own naming spells for this allowlist."""
    return int(DockerSandbox().network_name(list(allowlist)).rsplit("-", 1)[1], 16)


def add_run(eid: str, allowlist: list[str], *, status: str = "succeeded",
            refused: bool = False, created_ago_s: float = 0, finished_ago_s: float | None = None):
    rid = f"RUN-{uuid.uuid4().hex[:12]}"
    refused_or_over = refused or status not in ("queued", "dispatching", "running")
    finished = created_ago_s if finished_ago_s is None else finished_ago_s
    with engagement_scope(eid) as conn:
        conn.execute(text("""
            INSERT INTO tool_runs (run_id, engagement_id, tool, tool_version, normalized_target,
                execution_fingerprint, status, network_allowlist, refusal_code, created_at,
                finished_at)
            VALUES (:r, :e, 'nmap', '1', 't', :fp, :s, CAST(:al AS text[]), :c,
                    now() - make_interval(secs => :ca),
                    CASE WHEN :done THEN now() - make_interval(secs => :fa) END)"""),
            {"r": rid, "e": eid, "fp": f"fp-{rid}", "s": "failed" if refused else status,
             "al": "{" + ",".join(f'"{a}"' for a in allowlist) + "}",
             "c": CONFLICT if refused else None, "ca": created_ago_s, "done": refused_or_over,
             "fa": finished})
    return rid


def conflicts(window_s: int = DAY) -> dict[int, dict]:
    with reconciler_reader_scope() as conn:
        result = conn.execute(text("SELECT * FROM reconciler_network_conflicts(:w)"),
                              {"w": window_s})
        assert list(result.keys()) == COLUMNS
        return {row[0]: dict(zip(COLUMNS, row, strict=True)) for row in result}


# ---------------------------------------------------------------------------------------------
# a range is never returned
# ---------------------------------------------------------------------------------------------

def test_every_column_is_an_integer_in_the_catalog_and_in_what_comes_back(engagement_id):
    with engagement_scope("ENG-NONE") as conn:
        (result, args) = conn.execute(text(
            "SELECT pg_get_function_result(p.oid), pg_get_function_arguments(p.oid) "
            "FROM pg_proc p WHERE p.proname = 'reconciler_network_conflicts'")).one()
    types = [part.strip().split(" ", 1)[1] for part in
             result.removeprefix("TABLE(").removesuffix(")").split(",")]
    assert types == ["bigint", "integer", "bigint", "bigint", "integer", "bigint"], result
    assert args == "p_window_s integer"
    blocker, refused, _ = fresh_block()
    add_run(engagement_id, [blocker])
    add_run(engagement_id, [refused], refused=True)
    rows = conflicts()
    assert rows
    assert all(type(v) is int for row in rows.values() for v in row.values()), rows


def test_no_text_or_array_or_range_column_exists_in_the_functions_result(db_available):
    with engagement_scope("ENG-NONE") as conn:
        result = conn.execute(text(
            "SELECT pg_get_function_result(p.oid) FROM pg_proc p "
            "WHERE p.proname = 'reconciler_network_conflicts'")).scalar_one()
    assert not any(word in result for word in ("text", "[]", "inet", "cidr", "json", "varchar"))


# ---------------------------------------------------------------------------------------------
# the number is the sandbox's own
# ---------------------------------------------------------------------------------------------

#: (the allowlist that ran, the range that was refused and overlaps it), as suffixes of a fresh /64
HASH_CASES = [
    (["::/64"], "::8/125"),
    (["::40/122", "::80/121"], "::40/124"),
    (["::80/121", "::40/122"], "::40/124"),                # the same set, the other order
    (["::/126", "::4/126", "::8/125", "::10/124"], "::10/126"),
    (["::c8/126"], "::c8/125"),
]


@pytest.mark.parametrize("suffixes, refused_suffix", HASH_CASES)
def test_the_blocking_number_is_what_the_sandbox_would_name_the_network(
        engagement_id, suffixes, refused_suffix):
    """E22-1 as a test: the hash computed in SQL (``sha256`` over the sorted allowlist joined with
    ``|``, first 12 hex digits, as a number) against ``DockerSandbox.network_name``."""
    base = fresh_base()
    inside = [f"{base}{suffix}" for suffix in suffixes]
    add_run(engagement_id, inside)
    add_run(engagement_id, [f"{base}{refused_suffix}"], refused=True)
    assert hash_n(*inside) in conflicts()
    assert hash_n(*reversed(inside)) == hash_n(*inside)         # the order does not matter


# ---------------------------------------------------------------------------------------------
# what is counted
# ---------------------------------------------------------------------------------------------

def test_a_refusal_names_the_overlapping_allowlist_that_has_run_and_nothing_else(engagement_id):
    blocker, refused, _ = fresh_block()
    elsewhere, _, _ = fresh_block()
    add_run(engagement_id, [blocker], created_ago_s=600)
    add_run(engagement_id, [elsewhere], created_ago_s=600)         # runs, but overlaps nothing
    add_run(engagement_id, [refused], refused=True, finished_ago_s=5)
    rows = conflicts()
    row = rows[hash_n(blocker)]
    assert (row["conflicts_n"], row["live_runs_n"]) == (1, 0)
    assert row["last_conflict_us"] > row["last_used_us"] > 0
    assert row["db_now_us"] >= row["last_conflict_us"]
    assert hash_n(elsewhere) not in rows
    assert hash_n(refused) not in rows                           # a refused range never ran


def test_refusals_are_counted_and_the_latest_wins(engagement_id):
    blocker, one, two = fresh_block()
    add_run(engagement_id, [blocker], created_ago_s=900)
    add_run(engagement_id, [one], refused=True, finished_ago_s=300)
    add_run(engagement_id, [one], refused=True, finished_ago_s=200)
    add_run(engagement_id, [two], refused=True, finished_ago_s=10)
    row = conflicts()[hash_n(blocker)]
    assert row["conflicts_n"] == 3
    assert 9 * 1_000_000 <= row["db_now_us"] - row["last_conflict_us"] <= 60 * 1_000_000


def test_runs_that_are_not_over_are_counted_apart_from_those_that_are(engagement_id):
    blocker, refused, _ = fresh_block()
    for status in ("succeeded", "failed", "unknown_outcome", "queued", "dispatching", "running"):
        add_run(engagement_id, [blocker], status=status, created_ago_s=500)
    add_run(engagement_id, [refused], refused=True, finished_ago_s=5)
    assert conflicts()[hash_n(blocker)]["live_runs_n"] == 3


def test_the_last_use_is_the_newest_run_on_that_allowlist(engagement_id):
    blocker, refused, _ = fresh_block()
    add_run(engagement_id, [blocker], created_ago_s=7000)
    add_run(engagement_id, [blocker], created_ago_s=100)
    add_run(engagement_id, [refused], refused=True, finished_ago_s=5)
    row = conflicts()[hash_n(blocker)]
    assert 90 * 1_000_000 <= row["db_now_us"] - row["last_used_us"] <= 200 * 1_000_000


def test_engagements_are_not_a_boundary_the_database_has_one_history(engagement_factory):
    (one, _), (two, _) = engagement_factory(), engagement_factory()
    blocker, refused, _ = fresh_block()
    add_run(one, [blocker], created_ago_s=500)
    add_run(two, [refused], refused=True, finished_ago_s=5)
    assert conflicts()[hash_n(blocker)]["conflicts_n"] == 1


@pytest.mark.parametrize("window_s, seen", [(DAY // 2, False), (3 * DAY, True)])
def test_a_refusal_outside_the_window_does_not_count(engagement_id, window_s, seen):
    blocker, refused, _ = fresh_block()
    add_run(engagement_id, [blocker], created_ago_s=2 * DAY + 100)
    add_run(engagement_id, [refused], refused=True, finished_ago_s=2 * DAY)
    assert (hash_n(blocker) in conflicts(window_s)) is seen


def test_a_blocker_is_found_by_any_of_its_cidrs_and_in_either_direction(engagement_id):
    blocker, refused, _ = fresh_block()
    second = f"{fresh_base()}::/64"
    add_run(engagement_id, [second, blocker], created_ago_s=500)    # overlaps by its 2nd element
    add_run(engagement_id, [refused], refused=True, finished_ago_s=5)
    assert hash_n(second, blocker) in conflicts()
    # and the other way round: the run that ran is the small range, the refused one the large
    base = fresh_base()
    inner = f"{base}::40/125"
    add_run(engagement_id, [inner], created_ago_s=500)
    add_run(engagement_id, [f"{base}::/64"], refused=True, finished_ago_s=5)
    assert hash_n(inner) in conflicts()


def test_an_allowlist_equal_to_the_refused_one_is_not_its_own_blocker(engagement_id):
    """The network of that very name would have been reused, not refused: same set, other order."""
    blocker, refused, _ = fresh_block()
    add_run(engagement_id, [blocker, refused], created_ago_s=500)
    add_run(engagement_id, [refused, blocker], refused=True, finished_ago_s=5)
    assert hash_n(blocker, refused) not in conflicts()


# ---------------------------------------------------------------------------------------------
# refusals nothing of ours explains
# ---------------------------------------------------------------------------------------------

def test_a_refusal_with_no_blocker_among_the_allowlists_run_here_is_counted_apart(engagement_id):
    before = conflicts().get(NO_BLOCKER, {}).get("conflicts_n", 0)
    _, alone, other = fresh_block()
    add_run(engagement_id, [alone], refused=True, finished_ago_s=5)
    add_run(engagement_id, [other], refused=True, finished_ago_s=4)
    row = conflicts().get(NO_BLOCKER)
    assert row is not None, "refusals with no blocker are not counted"
    assert row["conflicts_n"] == before + 2
    assert (row["last_used_us"], row["live_runs_n"]) == (0, 0)
    assert hash_n(alone) not in conflicts()


def test_a_refused_range_never_ran_so_it_cannot_block_another_refusal(engagement_id):
    """Two refusals whose ranges overlap each other and nothing that ran: neither is a blocker of
    the other -- a refused range has no network -- and both are foreign."""
    before = conflicts().get(NO_BLOCKER, {}).get("conflicts_n", 0)
    _, wide, narrow = fresh_block()
    inside = wide.replace("/125", "/126")                        # inside `wide`
    add_run(engagement_id, [wide], refused=True, finished_ago_s=5)
    add_run(engagement_id, [inside], refused=True, finished_ago_s=4)
    rows = conflicts()
    assert hash_n(wide) not in rows and hash_n(inside) not in rows
    assert rows[NO_BLOCKER]["conflicts_n"] == before + 2


def test_a_refusal_that_has_a_blocker_is_not_also_counted_as_foreign(engagement_id):
    before = conflicts().get(NO_BLOCKER, {}).get("conflicts_n", 0)
    blocker, refused, _ = fresh_block()
    add_run(engagement_id, [blocker], created_ago_s=500)
    add_run(engagement_id, [refused], refused=True, finished_ago_s=5)
    assert conflicts().get(NO_BLOCKER, {}).get("conflicts_n", 0) == before


def test_refusals_of_other_kinds_are_not_conflicts(engagement_id):
    blocker, refused, _ = fresh_block()
    add_run(engagement_id, [blocker], created_ago_s=500)
    rid = add_run(engagement_id, [refused], refused=True, finished_ago_s=5)
    with engagement_scope(engagement_id) as conn:
        conn.execute(text("UPDATE tool_runs SET refusal_code = 'docker_unreachable' "
                          "WHERE run_id = :r"), {"r": rid})
    assert hash_n(blocker) not in conflicts()


# ---------------------------------------------------------------------------------------------
# a bad row must not blind it; a bad argument is refused
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("garbage", ["not a cidr", "10.0.0.0/33", "999.1.1.1/24", "", "::g/64"])
def test_a_malformed_element_in_the_history_is_skipped_not_raised_on(engagement_id, garbage):
    blocker, refused, _ = fresh_block()
    add_run(engagement_id, [blocker, garbage], created_ago_s=500)
    add_run(engagement_id, [garbage], created_ago_s=500)
    add_run(engagement_id, [refused, garbage], refused=True, finished_ago_s=5)
    raised, rows = None, {}
    try:
        rows = conflicts()
    except Exception as exc:                                  # noqa: BLE001
        raised = type(exc).__name__
    assert raised is None, f"one malformed row blinded the function: {raised}"
    assert hash_n(blocker, garbage) in rows


@pytest.mark.parametrize("window", [None, 0, -1, 31 * DAY + 1, 2 ** 31 - 1])
def test_a_window_outside_one_second_to_thirty_one_days_is_refused_with_a_fixed_text(window):
    with pytest.raises(DBAPIError) as caught:
        conflicts(window)
    assert "argument refused" in str(caught.value.orig)


@pytest.mark.parametrize("window", [1, 31 * DAY])
def test_the_ends_of_the_window_range_are_accepted(window):
    conflicts(window)


def test_a_window_with_no_refusal_in_it_costs_nothing_and_returns_nothing():
    """Seconds after nothing was refused: the gate returns before the aggregate on ``tool_runs``."""
    import time
    time.sleep(1.2)
    assert conflicts(1) == {}


def test_the_aggregate_sits_behind_a_gate_and_an_index_serves_it(db_available):
    with engagement_scope("ENG-NONE") as conn:
        source = conn.execute(text(
            "SELECT prosrc FROM pg_proc WHERE proname = 'reconciler_network_conflicts'")
        ).scalar_one()
        index = conn.execute(text(
            "SELECT indexdef FROM pg_indexes WHERE indexname = 'tool_runs_refused'")).scalar_one()
    gate = source.find("IF NOT EXISTS")
    assert 0 <= gate < source.find("WITH refused"), "the aggregate is not behind a gate"
    assert "RETURN;" in source.split("WITH refused")[0]
    assert "WHERE (refusal_code IS NOT NULL)" in index and "finished_at" in index


# ---------------------------------------------------------------------------------------------
# who may call it
# ---------------------------------------------------------------------------------------------

def test_only_the_reader_and_the_owner_may_execute_it(db_available):
    with get_engine().connect() as conn:
        grantees = set(conn.execute(text(
            "SELECT r.rolname FROM pg_roles r "
            "WHERE has_function_privilege(r.rolname, "
            "'reconciler_network_conflicts(integer)', 'EXECUTE') AND NOT r.rolsuper")).scalars())
    assert grantees == {RECONCILER_READER_ROLE, RECONCILER_FN_OWNER_ROLE}, grantees
