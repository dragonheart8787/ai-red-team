"""Redaction of first-party source snippets (D43-4).

``untrusted_content`` (§4.4, enforced by ``record_evidence``) answers one
question: is this content's claim about reality trustworthy. It says nothing
about whether the content is safe to show in full, because nothing before
Semgrep produced evidence that is simultaneously *true* (the customer's own
code, nobody forged it) and *confidential* (it can contain a live credential).
That second question is what this module answers, and it is a genuinely
different axis: a value can be untrusted-and-not-sensitive (an nmap banner),
trusted-and-sensitive (a hardcoded API key in the customer's own repository),
or any other combination — the two facts do not imply each other, which is
why this is a separate mechanism rather than a second meaning bolted onto
``untrusted_content``.

Pattern-based, not length-based, by design (D43-4's explicit requirement):
truncating at N characters catches a long secret and misses a short one
(``password = "hunter2"`` survives any truncation limit that would still
leave the surrounding code readable). Every pattern below replaces only the
secret-shaped *value*, never the whole line, so a Reviewer keeps the
variable name and structure needed to judge whether a finding is a real
credential or a test fixture — the "looks safe but is actually useless"
failure mode named alongside "looks safe but actually leaks". The length cap
in :func:`redact_snippet` is a backstop for a secret-shaped value none of the
named patterns recognizes, not the primary mechanism.

None of this is a claim that every possible secret shape is caught — it
cannot be, the same way no finite blocklist ever fully closes this class of
problem. It is a claim that a known set of common shapes (AWS keys, URL
credentials, bearer tokens, PEM private key blocks, and generic
password/token/secret assignments) is removed before anything reaches a
model's context, and that nothing downstream can assume a plain-length
truncation was the whole defence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Every value redacted by name is replaced with ``[REDACTED:<label>]`` (a
#: whole-match replacement) or has only its value replaced while its
#: surrounding assignment survives (a group-preserving replacement) — see
#: each pattern's own comment for which.
_WHOLE_MATCH_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # AWS access key IDs have a fixed, recognizable shape independent of
    # variable name -- these appear in code as bare literals as often as
    # they appear assigned to an obviously-named variable.
    ("aws-access-key-id", re.compile(r"AKIA[0-9A-Z]{16}")),
    # PEM-formatted private key material. DOTALL: the body is the whole
    # point, and a partial redaction of just the header line would leave the
    # actual key bytes on the following lines untouched.
    ("private-key-block", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    )),
    # A three-part base64url token is recognizable as JWT-shaped on its own,
    # whatever it is assigned to (a header, a variable, a raw literal).
    ("jwt-like-token", re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    )),
    ("bearer-token", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}=*")),
    # scheme://user:password@host -- redact the whole authority-with-
    # credentials prefix, since the username half is itself often sensitive
    # (a real account name) and the port/host after '@' is not secret.
    ("credential-in-url", re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:@/]+:[^\s@/]+@")),
)

#: Group-preserving: `name = "value"` -> `name = "[REDACTED:credential]"`.
#: The variable name and quoting survive; only the literal value is masked.
#: This is deliberately the broadest, least specific pattern (any variable
#: whose *name* looks credential-shaped, holding any quoted literal of
#: plausible secret length) -- it is the backstop for the common case none
#: of the whole-match patterns above are specific enough to catch on their
#: own, e.g. `password = "hunter2_super_secret"`.
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\b
    (\s*[:=]\s*)
    (["'])
    ([^"']{4,})
    (["'])
    """
)

#: Backstop for a secret-shaped value none of the named patterns recognize.
#: Not the primary mechanism -- see the module docstring -- but a single
#: unrecognized long token must still not reach a model's context window in
#: full merely for lacking a name.
MAX_LINE_LENGTH = 160


@dataclass(frozen=True)
class RedactedSnippet:
    text: str
    patterns_matched: tuple[str, ...]


def redact_snippet(text: str) -> RedactedSnippet:
    """Redact known secret shapes in ``text``, then cap any remaining line length.

    Returns the redacted text and the set of named patterns that fired, so a
    caller (or a test) can distinguish "nothing sensitive-shaped was found"
    from "found and handled" without re-deriving it from the text alone.
    """
    matched: list[str] = []

    def _whole_match(label: str):
        def _replace(m: re.Match[str]) -> str:
            matched.append(label)
            return f"[REDACTED:{label}]"
        return _replace

    def _credential_assignment(m: re.Match[str]) -> str:
        matched.append("credential-assignment")
        name, sep, q1, _value, q2 = m.groups()
        return f"{name}{sep}{q1}[REDACTED:credential]{q2}"

    redacted = text
    for label, pattern in _WHOLE_MATCH_PATTERNS:
        redacted = pattern.sub(_whole_match(label), redacted)
    redacted = _CREDENTIAL_ASSIGNMENT.sub(_credential_assignment, redacted)

    capped_lines = []
    for line in redacted.split("\n"):
        if len(line) > MAX_LINE_LENGTH:
            matched.append("length-cap")
            omitted = len(line) - MAX_LINE_LENGTH
            line = line[:MAX_LINE_LENGTH] + f"...[{omitted} more chars redacted]"
        capped_lines.append(line)

    return RedactedSnippet(text="\n".join(capped_lines), patterns_matched=tuple(matched))
