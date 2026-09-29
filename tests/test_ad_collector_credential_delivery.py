"""What a real container receives from the D44 credential mount (D50 F3).

Until D50 no test asserted this. ``test_dispatch_collection.py`` and the D48
E2E test run under ``StubSandbox``, which records ``plan.command`` without
executing it, and their only claim about the secret is negative (it is *absent*
from the records). D45/D49's live runs showed the real tool *accepting* the
arguments, but never that the secret arrived intact, and never a secret that
argparse would refuse. Two real-container tiers close that, both through the
real vault (``store_credential`` / ``mount_for_run``), the real
``ad_collector.build_plan`` command, and the real ``DockerSandbox``:

* **Delivery** -- only the ``bloodhound-python`` binary is replaced (by a stub
  that prints its argv as JSON), so what is asserted is exactly what the tool's
  process would be handed: the mounted secret, byte for byte, in the attached
  form, for shell metacharacters, whitespace, unicode, a leading ``-`` and a
  hashes-mode value.
* **Acceptance** -- the *real* binary, given a password or username that begins
  with ``-``. With the pre-D50 separate-token form (``-p -abc123``) the real
  argparse fails with "expected one argument"; with the attached form
  (``--password=-abc123``) it proceeds to the DNS stage.

Nothing is mocked in the ways that matter and no domain controller is involved:
the real tool is pointed at an address inside the sandbox network where
nothing answers, so it stops at the DNS query, which is far enough to prove it
accepted its arguments. Like ``tests/test_sandbox.py`` these fail rather than
skip when the image is missing -- a green run that never started the container
would show nothing about what the container receives.
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from pathlib import Path

import pytest

from control_plane.state.db import credential_admin_scope, engagement_scope
from control_plane.vault.vault import VaultError, identity_for, mount_for_run, store_credential
from tool_gateway.adapters import ad_collector
from tool_gateway.sandbox import DockerSandbox, SandboxUnavailable

CIDR = "10.96.0.0/24"
DNS_SERVER = "10.96.0.53"  # inside the sandbox network; nothing listens there
TARGET = "corp.example.com"
LM_NT = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
ACTOR = "test-harness"

_ARGV_STUB = "#!/usr/local/bin/python3\nimport sys, json\nprint(json.dumps(sys.argv[1:]))\n"


@pytest.fixture(scope="module")
def sandbox():
    box = DockerSandbox(image=ad_collector.IMAGE)
    try:
        box.ensure_image()
    except SandboxUnavailable as exc:
        pytest.fail(
            f"sandbox unavailable: {exc}\n"
            "These tests verify what a real container receives from the "
            "credential mount and are not meaningful without one -- build "
            "cyberorch/bloodhound:local "
            "(tool_gateway/images/build_bloodhound_image.sh) and ensure the "
            "Docker daemon is running.",
            pytrace=False,
        )
    box.ensure_network([CIDR])
    yield box
    box.remove_network([CIDR])


@pytest.fixture
def argv_stub():
    with tempfile.TemporaryDirectory(prefix="cyberorch-argv-stub-") as tmp:
        stub = Path(tmp) / "bloodhound-python"
        stub.write_text(_ARGV_STUB)
        stub.chmod(0o755)
        yield str(stub)


def _run(sandbox, engagement_id, *, secret, auth_mode="password", username="alice",
         extra_mounts=None, **constraints):
    """Store ``secret`` (with its identity) in the vault, mount it for one run,
    and execute the real ``build_plan`` command in the real sandbox. The
    username and mode handed to ``build_plan`` are read back from the
    credential, exactly as ``dispatch_collection`` does (D50-B) -- not passed
    in separately. Returns ``(plan, result)``.
    """
    credential_id = f"CRED-{uuid.uuid4().hex[:8]}"
    with credential_admin_scope(engagement_id) as conn:
        store_credential(
            conn, engagement_id=engagement_id, credential_id=credential_id,
            label="svc", credential_type="ad_domain_bind", secret=secret, actor=ACTOR,
            username=username, auth_mode=auth_mode,
        )
    run_id = f"RUN-{uuid.uuid4().hex[:8]}"
    with engagement_scope(engagement_id) as conn:
        identity = identity_for(conn, credential_id)
        mounted = mount_for_run(
            conn, credential_id=credential_id, run_id=run_id,
            engagement_id=engagement_id, actor=ACTOR,
        )
    try:
        plan = ad_collector.build_plan(
            constraints={
                "collection_methods": ["Group"], "domain_username": identity.username,
                "auth_mode": identity.auth_mode, **constraints,
            },
            budget={"max_duration_seconds": 30}, target=TARGET,
        )
        result = sandbox.run(
            command=plan.command, network_allowlist=[CIDR], max_duration_seconds=30,
            run_id=run_id,
            source_mounts={
                mounted.host_path: ad_collector.CONTAINER_CRED_PATH, **(extra_mounts or {}),
            },
        )
    finally:
        os.remove(mounted.host_path)
    return plan, result


def _delivered_argv(result) -> list[str]:
    assert result.exit_code == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


# ---------------------------------------------------------------------------
# Tier 1 -- delivery: the process is handed exactly the mounted secret
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("secret", [
    pytest.param("Passw0rd!", id="plain"),
    pytest.param("a b  c", id="spaces"),
    pytest.param("$HOME $(id) `id` \"q\" 'q' \\ ; | & * ?", id="shell-metacharacters"),
    pytest.param("-abc123", id="leading-dash"),
    pytest.param("--hashes", id="looks-like-a-flag"),
    pytest.param("пароль密码🔑", id="unicode"),
    pytest.param("trailing  ", id="trailing-spaces"),
    pytest.param("ab\ncd", id="embedded-newline"),
])
def test_the_password_reaches_the_tool_byte_for_byte(sandbox, engagement_id, argv_stub, secret):
    _, result = _run(
        sandbox, engagement_id, secret=secret,
        extra_mounts={argv_stub: ad_collector.BLOODHOUND_PYTHON_PATH},
    )
    assert _delivered_argv(result) == [
        "-d", TARGET, "--username=alice", f"--password={secret}", "-c", "Group", "--zip",
    ]


def test_a_hashes_secret_reaches_the_tool_in_the_attached_form(
    sandbox, engagement_id, argv_stub,
):
    _, result = _run(
        sandbox, engagement_id, secret=LM_NT, auth_mode="hashes",
        extra_mounts={argv_stub: ad_collector.BLOODHOUND_PYTHON_PATH},
    )
    assert _delivered_argv(result) == [
        "-d", TARGET, "--username=alice", f"--hashes={LM_NT}", "-c", "Group", "--zip",
    ]


def test_a_username_that_looks_like_a_flag_reaches_the_tool_as_a_value(
    sandbox, engagement_id, argv_stub,
):
    _, result = _run(
        sandbox, engagement_id, secret="x", username="-ns",
        extra_mounts={argv_stub: ad_collector.BLOODHOUND_PYTHON_PATH},
    )
    assert _delivered_argv(result) == [
        "-d", TARGET, "--username=-ns", "--password=x", "-c", "Group", "--zip",
    ]


def test_a_secret_the_shell_would_alter_never_gets_this_far(engagement_id):
    """``$(cat ...)`` drops trailing newlines, so a secret ending in one would
    be delivered as a *different* secret than the one stored -- the silent
    stored/sent difference this file exists to make visible (D50 F3-4). Since
    D50-B the vault refuses to store such a secret, so every secret that can
    reach the tests above is one that arrives byte for byte.
    """
    with credential_admin_scope(engagement_id) as conn:
        with pytest.raises(VaultError, match="newline"):
            store_credential(
                conn, engagement_id=engagement_id, credential_id="CRED-nl",
                label="svc", credential_type="ad_domain_bind", secret="abc\n",
                actor=ACTOR, username="alice", auth_mode="password",
            )


def test_the_dns_server_flag_survives_next_to_the_attached_arguments(
    sandbox, engagement_id, argv_stub,
):
    _, result = _run(
        sandbox, engagement_id, secret="x", dns_server=DNS_SERVER,
        extra_mounts={argv_stub: ad_collector.BLOODHOUND_PYTHON_PATH},
    )
    assert _delivered_argv(result) == [
        "-d", TARGET, "--username=alice", "--password=x", "-c", "Group",
        "-ns", DNS_SERVER, "--zip",
    ]


# ---------------------------------------------------------------------------
# Tier 2 -- acceptance: the REAL tool's argument parser takes the attached form
# ---------------------------------------------------------------------------

def _reached_the_dns_stage(result) -> bool:
    """The real tool got past argument parsing and authentication-branch
    selection and tried to look up the domain controller (which nothing here
    answers, so it dies in dnspython)."""
    combined = result.stdout + result.stderr
    return "expected one argument" not in combined and "dns.resolver" in combined


@pytest.mark.parametrize(("label", "secret", "auth_mode", "username"), [
    pytest.param("password beginning with '-'", "-abc123", "password", "alice",
                 id="dash-password"),
    pytest.param("password that is literally a flag name", "--hashes", "password", "alice",
                 id="flag-name-password"),
    pytest.param("username beginning with '-'", "x", "password", "-alice",
                 id="dash-username"),
    pytest.param("LM:NT hash", LM_NT, "hashes", "alice", id="hashes"),
])
def test_the_real_tool_accepts_the_attached_form(
    sandbox, engagement_id, label, secret, auth_mode, username,
):
    _, result = _run(
        sandbox, engagement_id, secret=secret, auth_mode=auth_mode, username=username,
        dns_server=DNS_SERVER,
    )
    assert _reached_the_dns_stage(result), (
        f"the real tool did not accept {label}; exit={result.exit_code}\n"
        f"{result.stdout[-400:]}\n{result.stderr[-600:]}"
    )


def test_the_pre_d50_separate_token_form_is_rejected_by_the_real_tool(sandbox):
    """Why the attached form exists, pinned against the real binary so it is not
    folklore: with a separate-token value the real argparse refuses anything
    that begins with ``-``. If a future bloodhound accepts this, the test goes
    red and the attached form's stated reason needs revisiting.
    """
    result = sandbox.run(
        command=[ad_collector.BLOODHOUND_PYTHON_PATH, "-d", TARGET, "-u", "alice",
                 "-p", "-abc123", "-c", "Group", "-ns", DNS_SERVER],
        network_allowlist=[CIDR], max_duration_seconds=30,
    )
    assert result.exit_code == 2
    assert "expected one argument" in result.stderr
    assert "dns.resolver" not in result.stderr
