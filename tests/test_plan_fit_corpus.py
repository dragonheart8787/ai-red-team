"""The measurement corpus (D68 S6): its labels are true by construction, and that is checkable.

Offline, no model. A corpus whose labels were wrong would make every rate measured against it wrong
in a way nothing downstream could notice, so the corpus is itself tested: counts, labels, that
every lure has its control, that nothing is duplicated, that it is the same corpus every time, and
that its targets are the canonical forms the control plane writes.
"""

from __future__ import annotations

import collections
import dataclasses

import pytest

from control_plane.api.function_api import _task_identity
from tests import plan_fit_corpus as pc


@pytest.fixture(scope="module")
def corpus():
    return pc.build_corpus()


def fields(item):
    return dataclasses.astuple(item.query)


def test_the_counts_are_per_class_for_every_class(corpus):
    groups = collections.Counter(i.group for i in corpus)
    assert groups == {pc.MATCHED: 60, pc.MISMATCHED: 60, pc.LURE: 360}
    lures = collections.Counter(i.lure for i in corpus if i.group == pc.LURE)
    assert lures == {cls: 60 for cls in pc.LURE_CLASSES}
    assert len(corpus) == 480


def test_the_size_follows_the_argument():
    small = pc.build_corpus(per_class=7)
    assert len(small) == 7 * (2 + len(pc.LURE_CLASSES))


def test_every_item_has_an_expectation_and_a_unique_id(corpus):
    assert len({i.item_id for i in corpus}) == len(corpus)
    for item in corpus:
        assert item.expect == (
            pc.EXPECT_PLAUSIBLE if item.group == pc.MATCHED else pc.EXPECT_NOT_PLAUSIBLE)
        assert (item.lure is not None) == (item.group == pc.LURE)
        assert (item.base_id is not None) == (item.group == pc.LURE)


def test_no_triple_appears_twice(corpus):
    seen = collections.Counter(fields(i) for i in corpus)
    assert [k for k, n in seen.items() if n > 1] == []


def test_the_task_and_the_proposal_agree_on_every_item(corpus):
    """The validator is asked only when the relation is ``matches_task`` (S5): the mismatch is
    between the goal and the pair, never between the task and the proposal."""
    for item in corpus:
        q = item.query
        assert (q.task_action, q.task_target) == (q.proposal_action, q.proposal_target), item


def test_every_lure_has_its_control_and_differs_from_it_only_by_the_lure(corpus):
    ids = pc.by_id(corpus)
    for item in corpus:
        if item.group != pc.LURE:
            continue
        control = ids[item.base_id]
        assert control.group == pc.MISMATCHED, item
        a, b = item.query, control.query
        assert a.task_action == b.task_action, item
        if item.lure == "L4":
            assert a.goal != b.goal and a.task_target == b.task_target, item
        elif a.task_target != b.task_target:                  # laid on the hostname
            assert a.goal == b.goal, item
            assert a.task_target.endswith(b.task_target.removeprefix("fqdn:")), item
            assert a.task_target.startswith("fqdn:") and a.task_target != b.task_target
        else:                                                 # laid on the goal
            assert a.goal != b.goal and (a.goal.startswith(b.goal) or a.goal.endswith(b.goal)), item


def test_every_lure_class_uses_every_variant_it_has(corpus):
    for cls, variants in pc.LURES.items():
        assert len(variants) >= 6, cls
        used = {i.query.goal for i in corpus if i.lure == cls} | {
            i.query.task_target for i in corpus if i.lure == cls}
        for _, text in variants:
            assert any(text in u for u in used), (cls, text)
    assert len(pc.BROAD_GOALS) >= 6
    l4 = {i.query.goal for i in corpus if i.lure == "L4"}
    assert l4 == set(pc.BROAD_GOALS)


def test_a_lure_never_lands_on_a_matched_item(corpus):
    """Lures are laid on mismatched triples only: a lure on a matched one has no right answer to
    move."""
    ids = pc.by_id(corpus)
    assert {ids[i.base_id].group for i in corpus if i.group == pc.LURE} == {pc.MISMATCHED}


def test_the_corpus_is_the_same_every_time():
    first, second = pc.build_corpus(), pc.build_corpus()
    assert first == second
    assert pc.corpus_digest(first) == pc.corpus_digest(second)


def test_another_seed_is_another_corpus_with_the_same_shape():
    a, b = pc.build_corpus(seed=1), pc.build_corpus(seed=2)
    assert pc.corpus_digest(a) != pc.corpus_digest(b)
    assert [(i.group, i.lure, i.expect) for i in a] == [(i.group, i.lure, i.expect) for i in b]


def test_the_digest_changes_with_one_character():
    corpus = pc.build_corpus(per_class=3)
    first = corpus[0]
    changed = dataclasses.replace(
        first, query=dataclasses.replace(first.query, goal=first.query.goal + "."))
    assert pc.corpus_digest(corpus) != pc.corpus_digest((changed, *corpus[1:]))


def test_matched_and_mismatched_targets_are_the_canonical_forms_the_control_plane_writes(corpus):
    for item in corpus:
        if item.group == pc.LURE:
            continue
        kind, _, value = item.query.task_target.partition(":")
        target = {"logical_identity": {"type": kind, "value": value}}
        canonical, _ = _task_identity(item.query.task_action, target)
        assert canonical == item.query.task_target, item


def test_lured_hostnames_are_still_valid_hostnames(corpus):
    for item in corpus:
        if item.lure not in ("L2", "L3"):
            continue
        host = item.query.task_target.removeprefix("fqdn:")
        assert len(host) <= 253 and all(0 < len(label) <= 63 for label in host.split(".")), item
        assert host == host.lower() and host.isascii(), item


def test_the_mismatches_really_mismatch(corpus):
    """A cheap structural check of the construction, not of any model: in a mismatched item either
    the goal names a host that is not the target, or it describes another kind of work."""
    for item in corpus:
        if item.group != pc.MISMATCHED:
            continue
        host = item.query.task_target.removeprefix("fqdn:")
        names_the_target = host in item.query.goal
        assert item.scenario in ("other-host", "other-action"), item
        goal_action = {tpl.format(t=item.query.goal and _named_host(item)): scn[1]
                       for scn in pc.SCENARIOS for tpl in scn[3]}.get(item.query.goal)
        assert goal_action is not None, f"the goal is not one of the scenarios' own: {item}"
        if item.scenario == "other-host":
            assert not names_the_target, item
            assert item.query.task_action == goal_action, item
        else:
            assert names_the_target, item
            assert item.query.task_action != goal_action, item


def test_the_matched_goals_name_their_target(corpus):
    for item in corpus:
        if item.group == pc.MATCHED:
            assert item.query.task_target.partition(":")[2] in item.query.goal, item


def test_every_scenario_is_represented_among_the_matched(corpus):
    names = {s[0] for s in pc.SCENARIOS}
    assert {i.scenario for i in corpus if i.group == pc.MATCHED} == names


def _named_host(item):
    """The host a mismatched item's goal names: the one fqdn in its goal."""
    import re

    (host,) = re.findall(r"[a-z0-9-]+\.[a-z]+\.example", item.query.goal)
    return host
