"""ad_collector.build_plan's command shape (D44, D49, D50).

Structural, adapter-only tests — no Vault, no sandbox, no real
bloodhound-python. What is under test is that ``build_plan`` builds the
right *shape* of command for each case, and that the shape it builds never
contains a secret value (there is none at plan-build time to leak — the whole
point of D44's design is that this function never sees one), only a reference
to where the sandbox will mount one later.

D50 F1: there is no uncredentialed plan any more. The real bloodhound-python
has no credential-free mode (it prints usage and exits 1 without a username),
and this file's former "original uncredentialed command" test pinned exactly
that dead command as correct — under a structural test that could never
execute it. Every case below therefore names a ``domain_username``, and the
missing-identity cases are refusals.

D50 F3: the username and the secret are attached to their flag
(``--username=$2``, ``$3=$(cat ...)``), never a flag followed by a separate
token, because the real argparse rejects a separate-token value beginning with
``-``. What a real container does with that shape is asserted separately, in
``tests/test_ad_collector_credential_delivery.py``; this file only pins the
shape.
"""

from __future__ import annotations

import pytest

from tool_gateway.adapters import ad_collector

TARGET = "corp.example.com"
USER = "svc-account"


def _build(constraints):
    return ad_collector.build_plan(
        constraints=constraints, budget={"max_duration_seconds": 60}, target=TARGET,
    )


def _creds(**extra):
    return {"collection_methods": ["Group"], "domain_username": USER, **extra}


# ---------------------------------------------------------------------------
# D50 F1 -- no bind identity, no plan
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("constraints", [
    pytest.param({"collection_methods": ["Group", "ACL"]}, id="absent"),
    pytest.param({"domain_username": ""}, id="empty"),
    pytest.param({"domain_username": "   "}, id="blank"),
    pytest.param({"domain_username": None}, id="none"),
    pytest.param({"domain_username": 42}, id="not-a-string"),
])
def test_a_plan_without_a_bind_identity_is_refused(constraints):
    """The former uncredentialed command (bare ``-d <domain> -c <methods>
    --zip``) is gone: the real tool exits 1 printing usage for it, so building
    it could only produce a run that cannot succeed.
    """
    with pytest.raises(ad_collector.AdapterError, match="domain_username"):
        _build(constraints)


def test_the_refusal_says_why_so_an_operator_can_act_on_it():
    with pytest.raises(ad_collector.AdapterError) as excinfo:
        _build({"collection_methods": ["Group"]})
    assert "credential-free mode" in str(excinfo.value)


def test_every_plan_carries_its_bind_identity_and_fingerprints_it():
    plan = _build(_creds())
    assert plan.domain_username == USER
    assert plan.auth_mode == "password"
    params = plan.as_params()
    assert params["domain_username"] == USER
    assert params["auth_mode"] == "password"


# ---------------------------------------------------------------------------
# The credentialed shell wrapper (D44) in its attached form (D50 F3)
# ---------------------------------------------------------------------------

def test_domain_username_builds_a_shell_wrapper_reading_the_mounted_secret():
    plan = _build(_creds())
    assert plan.command[0:2] == ("/bin/sh", "-c")
    script = plan.command[2]
    assert "cat" in script
    # The container path is a runtime positional argument to the script
    # ($4), not baked into the script text itself -- and it, the flag name,
    # and the username are the only things this command carries. No secret
    # value exists at plan-build time for there to be one to leak.
    assert plan.command[3:] == (
        "sh", TARGET, USER, "--password", ad_collector.CONTAINER_CRED_PATH, "Group",
    )


def test_auth_mode_hashes_selects_the_hashes_flag():
    plan = _build(_creds(auth_mode="hashes"))
    assert plan.auth_mode == "hashes"
    assert plan.command[3:] == (
        "sh", TARGET, USER, "--hashes", ad_collector.CONTAINER_CRED_PATH, "Group",
    )


def test_username_and_secret_are_attached_to_their_flags_not_separate_tokens():
    """D50 F3. ``-p -abc123`` (separate token) is rejected by the real
    argparse; ``--password=-abc123`` is not. The script text must therefore
    glue value to flag, for the secret *and* the username (a Worker-supplied
    ``-alice`` fails the same way).
    """
    script = _build(_creds()).command[2]
    assert '"--username=$2"' in script
    assert '"$3=$(cat "$4")"' in script
    # No bare short flags left that would take a separate-token value.
    assert ' -u ' not in script
    assert ' -p ' not in script


def test_the_flag_name_is_chosen_from_the_closed_vocabulary_never_a_caller_string():
    for mode, flag in (("password", "--password"), ("hashes", "--hashes")):
        assert _build(_creds(auth_mode=mode)).command[6] == flag


def test_an_unknown_auth_mode_is_refused_as_unbuildable():
    with pytest.raises(ad_collector.AdapterError, match="kerberoast"):
        _build(_creds(auth_mode="kerberoast"))


def test_a_username_that_looks_like_a_flag_stays_one_positional_value():
    """It reaches the script only as ``$2`` (a positional argument), so it can
    neither alter the script text nor, with the attached form, be read by the
    tool as a flag of its own.
    """
    plan = _build(_creds(domain_username="-ns"))
    assert plan.command[5] == "-ns"
    assert "-ns" not in plan.command[2]


# ---------------------------------------------------------------------------
# D49 -- dns_server, on the (only) credentialed shape
# ---------------------------------------------------------------------------

def test_dns_server_absent_leaves_the_command_and_params_untouched():
    plan = _build(_creds())
    assert plan.dns_server is None
    assert "-ns" not in plan.command[2]
    assert plan.command[3:] == (
        "sh", TARGET, USER, "--password", ad_collector.CONTAINER_CRED_PATH, "Group",
    )
    assert "dns_server" not in plan.as_params()


def test_dns_server_adds_the_ns_flag_to_the_credentialed_shell_wrapper():
    plan = _build(_creds(dns_server="10.0.0.5"))
    assert plan.dns_server == "10.0.0.5"
    script = plan.command[2]
    assert '-ns "$6"' in script
    # The nameserver is a positional shell argument ($6), never
    # string-interpolated into the script text -- same injection-avoidance
    # discipline as every other value here (module docstring).
    assert plan.command[3:] == (
        "sh", TARGET, USER, "--password", ad_collector.CONTAINER_CRED_PATH,
        "Group", "10.0.0.5",
    )
    assert plan.as_params()["dns_server"] == "10.0.0.5"


def test_dns_server_must_be_a_valid_ip_not_a_hostname():
    with pytest.raises(ad_collector.AdapterError, match=r"dc1\.corp\.example\.com"):
        _build(_creds(dns_server="dc1.corp.example.com"))


def test_dns_server_rejects_garbage():
    with pytest.raises(ad_collector.AdapterError, match="not-an-ip"):
        _build(_creds(dns_server="not-an-ip"))
