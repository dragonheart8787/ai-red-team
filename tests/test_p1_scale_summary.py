"""The reasons a proposal differs from its task (D68 P1 scale runs): the classification is a pure
function of the two canonical identities, so it is tested as a table."""

from __future__ import annotations

import json

import pytest

from scripts.live_run import summarise_p1_scale as s


@pytest.mark.parametrize("task,proposal,relation,expected", [
    ("cidr:10.79.0.0/24", "cidr:10.79.0.0/24", "matches_task", "matches"),
    ("ip:10.79.0.2", "ip:10.79.0.2", "matches_task", "matches"),
    # the DP-13 case: a network task, a proposal for one host inside it
    ("cidr:10.79.0.128/26", "ip:10.79.0.130", "differs_from_task",
     "network task narrowed to one host inside it"),
    ("cidr:10.79.0.128/26", "ip:10.79.0.10", "differs_from_task",
     "network task proposed as a host outside it"),
    # a network task narrowed to a smaller network
    ("cidr:10.79.0.0/24", "cidr:10.79.0.64/26", "differs_from_task",
     "network task narrowed to a smaller network inside it"),
    ("cidr:10.79.0.64/26", "cidr:10.79.0.128/26", "differs_from_task",
     "network task proposed as a different network"),
    # a task whose network lost its prefix: /32 of the network address, proposal is the network
    ("cidr:10.79.0.64/32", "cidr:10.79.0.64/26", "differs_from_task",
     "task target lost its prefix (/32); proposal is the network it meant"),
    ("cidr:10.79.0.64/32", "cidr:10.79.0.128/26", "differs_from_task",
     "network task proposed as a different network"),
    ("ip:10.85.0.5", "url:http://10.85.0.5/", "differs_from_task",
     "same host, task as ip and proposal as url"),
    ("ip:10.85.0.5", "url:http://10.99.0.5/", "differs_from_task", "other"),
    ("fqdn:a.example", "fqdn:b.example", "differs_from_task", "other"),
    ("cidr:not-a-network", "ip:10.0.0.1", "differs_from_task", "other"),
])
def test_why_a_proposal_differs_from_its_task(task, proposal, relation, expected):
    assert s.classify(task, proposal, relation) == expected


def test_a_match_is_a_match_whatever_the_identities_look_like():
    assert s.classify("cidr:x", "ip:y", "matches_task") == "matches"


def test_the_engagements_of_a_stratum_are_read_from_its_run_records(tmp_path):
    (tmp_path / "run_1.json").write_text(json.dumps({"main_run": {"engagement_id": "ENG-A"}}))
    (tmp_path / "run_2.json").write_text(json.dumps({"main_run": {"engagement_id": "ENG-B"}}))
    (tmp_path / "run_3.json").write_text(json.dumps({"main_run": {}}))      # a run with none
    (tmp_path / "other.json").write_text(json.dumps({"main_run": {"engagement_id": "ENG-C"}}))
    assert s.engagements(tmp_path) == ["ENG-A", "ENG-B"]


def test_a_match_by_the_containment_rule_is_told_from_an_identical_match():
    assert s.classify("cidr:10.0.0.0/24", "ip:10.0.0.5", "matches_task",
                      "subset_of_task_range").startswith("matched by the containment rule")
    assert s.classify("cidr:10.0.0.0/24", "cidr:10.0.0.0/24", "matches_task", None) == "matches"
