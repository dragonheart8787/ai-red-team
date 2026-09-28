"""ad_collector.build_plan's credentialed command shape (D44).

Structural, adapter-only tests — no Vault, no sandbox, no real
bloodhound-python. What is under test is that ``build_plan`` builds the
right *shape* of command for each case, and that the shape it builds for a
credentialed capability never contains a secret value (there is none at
plan-build time to leak — the whole point of D44's design is that this
function never sees one), only a reference to where the sandbox will mount
one later.
"""

from __future__ import annotations

from tool_gateway.adapters import ad_collector

TARGET = "corp.example.com"


def _build(constraints):
    return ad_collector.build_plan(
        constraints=constraints, budget={"max_duration_seconds": 60}, target=TARGET,
    )


def test_no_domain_username_builds_the_original_uncredentialed_command():
    plan = _build({"collection_methods": ["Group", "ACL"]})
    assert plan.domain_username is None
    assert plan.auth_mode is None
    assert plan.command == (
        ad_collector.BLOODHOUND_PYTHON_PATH, "-d", TARGET, "-c", "Group,ACL", "--zip",
    )
    assert "domain_username" not in plan.as_params()
    assert "auth_mode" not in plan.as_params()


def test_domain_username_builds_a_shell_wrapper_reading_the_mounted_secret():
    plan = _build({"collection_methods": ["Group"], "domain_username": "svc-account"})
    assert plan.domain_username == "svc-account"
    assert plan.auth_mode == "password"
    assert plan.command[0:2] == ("/bin/sh", "-c")
    script = plan.command[2]
    assert "cat" in script
    # The container path is a runtime positional argument to the script
    # ($4), not baked into the script text itself -- and it, the bind flag,
    # and the username are the only things this command carries. No secret
    # value exists at plan-build time for there to be one to leak.
    assert plan.command[3:] == (
        "sh", TARGET, "svc-account", "-p", ad_collector.CONTAINER_CRED_PATH, "Group",
    )
    params = plan.as_params()
    assert params["domain_username"] == "svc-account"
    assert params["auth_mode"] == "password"


def test_auth_mode_hashes_selects_the_hashes_flag():
    plan = _build({
        "collection_methods": ["Group"], "domain_username": "svc-account",
        "auth_mode": "hashes",
    })
    assert plan.auth_mode == "hashes"
    assert plan.command[3:] == (
        "sh", TARGET, "svc-account", "--hashes", ad_collector.CONTAINER_CRED_PATH, "Group",
    )


def test_an_unknown_auth_mode_is_refused_as_unbuildable():
    try:
        _build({"domain_username": "svc-account", "auth_mode": "kerberoast"})
        raise AssertionError("an unknown auth_mode must be refused")
    except ad_collector.AdapterError as exc:
        assert "kerberoast" in str(exc)


def test_dns_server_absent_leaves_the_command_and_params_untouched():
    plan = _build({"collection_methods": ["Group"]})
    assert plan.dns_server is None
    assert plan.command == (
        ad_collector.BLOODHOUND_PYTHON_PATH, "-d", TARGET, "-c", "Group", "--zip",
    )
    assert "dns_server" not in plan.as_params()


def test_dns_server_adds_the_ns_flag_to_the_uncredentialed_command():
    plan = _build({"collection_methods": ["Group"], "dns_server": "10.0.0.5"})
    assert plan.dns_server == "10.0.0.5"
    # -ns/value slot in before the trailing --zip, matching bloodhound-python's
    # own flag ordering -- not appended after --zip, which some CLIs reject.
    assert plan.command == (
        ad_collector.BLOODHOUND_PYTHON_PATH, "-d", TARGET, "-c", "Group",
        "-ns", "10.0.0.5", "--zip",
    )
    assert plan.as_params()["dns_server"] == "10.0.0.5"


def test_dns_server_adds_the_ns_flag_to_the_credentialed_shell_wrapper():
    plan = _build({
        "collection_methods": ["Group"], "domain_username": "svc-account",
        "dns_server": "10.0.0.5",
    })
    script = plan.command[2]
    assert '-ns "$6"' in script
    # The nameserver is a positional shell argument ($6), never
    # string-interpolated into the script text -- same injection-avoidance
    # discipline as every other value here (module docstring).
    assert plan.command[3:] == (
        "sh", TARGET, "svc-account", "-p", ad_collector.CONTAINER_CRED_PATH,
        "Group", "10.0.0.5",
    )


def test_dns_server_credentialed_without_dns_server_has_no_ns_flag_or_slot():
    plan = _build({"collection_methods": ["Group"], "domain_username": "svc-account"})
    script = plan.command[2]
    assert "-ns" not in script
    assert plan.command[3:] == (
        "sh", TARGET, "svc-account", "-p", ad_collector.CONTAINER_CRED_PATH, "Group",
    )


def test_dns_server_must_be_a_valid_ip_not_a_hostname():
    try:
        _build({"collection_methods": ["Group"], "dns_server": "dc1.corp.example.com"})
        raise AssertionError("a hostname dns_server must be refused")
    except ad_collector.AdapterError as exc:
        assert "dc1.corp.example.com" in str(exc)


def test_dns_server_rejects_garbage():
    try:
        _build({"collection_methods": ["Group"], "dns_server": "not-an-ip"})
        raise AssertionError("a malformed dns_server must be refused")
    except ad_collector.AdapterError as exc:
        assert "not-an-ip" in str(exc)
