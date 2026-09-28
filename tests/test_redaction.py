"""D43-4: pattern-aware redaction of first-party source snippets.

D30's own lesson applies directly here: a test whose input is something the
redaction would leave alone regardless cannot tell "the pattern fired" from
"there was nothing to catch" — every positive case below uses a value that
would appear in full, verbatim, in the output if the specific pattern under
test did not exist, which the negative-control asserts before each redacted
assertion is trusted.
"""

from __future__ import annotations

from control_plane.evidence.redaction import MAX_LINE_LENGTH, redact_snippet


def test_aws_access_key_id_is_redacted_but_the_assignment_survives():
    secret = "AKIAIOSFODNN7EXAMPLE"
    line = f'AWS_KEY = "{secret}"'
    result = redact_snippet(line)
    assert secret not in result.text
    assert "AWS_KEY" in result.text
    assert "[REDACTED:aws-access-key-id]" in result.text
    assert "aws-access-key-id" in result.patterns_matched


def test_generic_password_assignment_is_redacted_but_the_variable_name_survives():
    secret = "hunter2_super_secret"
    line = f'password = "{secret}"'
    result = redact_snippet(line)
    assert secret not in result.text
    assert "password" in result.text
    assert "[REDACTED:credential]" in result.text
    assert "credential-assignment" in result.patterns_matched


def test_a_token_shaped_variable_is_also_caught_by_the_generic_rule():
    secret = "sk_live_abcdef0123456789"
    line = f'api_key = "{secret}"'
    result = redact_snippet(line)
    assert secret not in result.text
    assert "api_key" in result.text


def test_private_key_block_is_fully_redacted():
    secret_body = "MIIEpQIBAAKCAQEA1234567890abcdefFAKEKEYMATERIALFAKEKEYMATERIAL"
    block = f"-----BEGIN RSA PRIVATE KEY-----\n{secret_body}\n-----END RSA PRIVATE KEY-----"
    result = redact_snippet(block)
    assert secret_body not in result.text
    assert "[REDACTED:private-key-block]" in result.text


def test_jwt_like_token_is_redacted():
    fake_jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    line = f"Authorization: {fake_jwt}"
    result = redact_snippet(line)
    assert fake_jwt not in result.text
    assert "[REDACTED:jwt-like-token]" in result.text


def test_credential_in_connection_string_is_redacted_but_host_and_db_survive():
    line = "DATABASE_URL = postgresql://dbuser:sup3rSecr3t@db.internal.corp:5432/prod"
    result = redact_snippet(line)
    assert "sup3rSecr3t" not in result.text
    assert "dbuser" not in result.text
    assert "db.internal.corp:5432/prod" in result.text, (
        "redaction must be surgical -- the host/port/database are not secret "
        "and a Reviewer needs them to judge the finding"
    )


def test_an_unrecognized_long_secret_is_still_bounded_by_the_length_cap():
    """The backstop D43-4 asked for: a secret-shaped value that matches none
    of the named patterns (an odd variable name, no known prefix) must not
    survive in full purely because nothing recognized its shape.
    """
    mystery_secret = "Z" * 300
    line = f"weird_var = '{mystery_secret}'"
    result = redact_snippet(line)
    assert mystery_secret not in result.text
    assert "length-cap" in result.patterns_matched
    assert len(result.text.splitlines()[0]) <= MAX_LINE_LENGTH + 40


def test_ordinary_code_with_nothing_sensitive_is_left_alone():
    """Redaction must be surgical, not wholesale -- the other half of D43-4's
    "looks safe but actually useless" concern: this suite would also fail its
    purpose if it redacted code that was never sensitive to begin with.
    """
    line = "def run_command(user_input):\n    subprocess.run(user_input, shell=True)"
    result = redact_snippet(line)
    assert result.text == line
    assert result.patterns_matched == ()


def test_multiple_secrets_on_different_lines_are_each_redacted():
    text = (
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'password = "hunter2_super_secret"\n'
        "def safe_function():\n"
        "    return 42\n"
    )
    result = redact_snippet(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in result.text
    assert "hunter2_super_secret" not in result.text
    assert "def safe_function():" in result.text
    assert "return 42" in result.text
