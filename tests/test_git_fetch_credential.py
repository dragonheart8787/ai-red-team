"""git_fetch.fetch_repo's auth_token wiring (D44 §4.2), against a real HTTP server.

Real git, real HTTP, real Basic-Auth enforcement — no mocked transport —
because a stubbed 401 would only prove this test author believes a wrong
credential fails, not that `fetch_repo`'s header actually reaches a server
that checks it. There is no real GitHub account reachable from this
environment, so the server here is a minimal one this file builds itself:
``git http-backend`` (git's own reference smart-HTTP CGI implementation,
the same program a real git host runs behind), invoked per request from a
plain ``http.server`` handler that gates every request behind a hand-rolled
HTTP Basic Auth check first. Smart HTTP, not the simpler "dumb" static-file
protocol, because `fetch_repo` always clones with ``--depth 1``, and git's
dumb-HTTP transport does not support shallow clones at all (confirmed by
this file's own first draft failing with exactly that error) — smart HTTP
is the actual protocol `fetch_repo` speaks against any real git host, so it
is the one this fixture must speak too.

What this proves, end to end, is exactly the seam `docs/
ADR_CREDENTIAL_VAULT.md` §4.2 names: a repository that requires
authentication cannot be cloned at all without a token, real Vault-stored
material decrypts to the same token a legitimate clone needs, and a wrong
token is rejected the same way a real git host would reject one — all
without ever touching a sandbox, matching D43-5's own architecture.
"""

from __future__ import annotations

import base64
import http.server
import os
import subprocess
import threading
import urllib.parse
import uuid

import pytest

from control_plane.orchestrator.git_fetch import GitFetchError, cleanup_repo, fetch_repo
from control_plane.state.db import credential_admin_scope, engagement_scope
from control_plane.vault.vault import material_for, store_credential

REAL_TOKEN = "ghp_synthetic_fake_token_for_real_http_test"  # noqa: S105


def _run_git(*args: str, cwd: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout.strip()


def _init_bare_repo(tmp_path) -> str:
    """A real bare repo at ``<tmp_path>/repo.git``, servable by git http-backend."""
    work = tmp_path / "work"
    bare = tmp_path / "repo.git"
    work.mkdir()
    _run_git("init", "-b", "main", cwd=str(work))
    (work / "app.py").write_text("print('hello')\n")
    _run_git("add", "app.py", cwd=str(work))
    _run_git(
        "-c", "user.email=test@example.com", "-c", "user.name=Test",
        "commit", "-m", "initial commit", cwd=str(work),
    )
    _run_git("clone", "--bare", str(work), str(bare), cwd=str(tmp_path))
    return str(bare)


def _make_authed_backend_handler(*, project_root: str, expected_token: str):
    expected_header = "Basic " + base64.b64encode(
        f"x-access-token:{expected_token}".encode()
    ).decode()

    class _AuthedGitBackendHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep test output quiet
            pass

        def _check_auth(self) -> bool:
            if self.headers.get("Authorization") != expected_header:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="git"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return False
            return True

        def _run_backend(self) -> None:
            # git's own reference smart-HTTP CGI implementation -- the same
            # program a real git host's web server invokes. This handler's
            # only job is the auth gate above and translating CGI's
            # header-blob-then-body output into a real HTTP response.
            parsed = urllib.parse.urlsplit(self.path)
            content_length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(content_length) if content_length else b""
            env = {
                **os.environ,
                "GIT_PROJECT_ROOT": project_root,
                "GIT_HTTP_EXPORT_ALL": "1",
                "PATH_INFO": urllib.parse.unquote(parsed.path),
                "QUERY_STRING": parsed.query,
                "REQUEST_METHOD": self.command,
                "SERVER_PROTOCOL": "HTTP/1.1",
                "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                "CONTENT_LENGTH": str(content_length),
                "REMOTE_ADDR": self.client_address[0],
            }
            proc = subprocess.run(
                ["git", "http-backend"], env=env, input=body, capture_output=True,
            )
            header_blob, _, out_body = proc.stdout.partition(b"\r\n\r\n")
            if not out_body and b"\n\n" in proc.stdout:
                header_blob, _, out_body = proc.stdout.partition(b"\n\n")
            status_code = 200
            headers = []
            for line in header_blob.decode(errors="replace").splitlines():
                if not line.strip() or ":" not in line:
                    continue
                key, _, value = line.partition(":")
                key, value = key.strip(), value.strip()
                if key.lower() == "status":
                    status_code = int(value.split()[0])
                else:
                    headers.append((key, value))
            self.send_response(status_code)
            for key, value in headers:
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(out_body)))
            self.end_headers()
            self.wfile.write(out_body)

        def do_GET(self):  # noqa: N802 - http.server's own naming convention
            if self._check_auth():
                self._run_backend()

        def do_POST(self):  # noqa: N802
            if self._check_auth():
                self._run_backend()

    return _AuthedGitBackendHandler


@pytest.fixture
def private_git_server(tmp_path):
    """A real HTTP server, on a real port, requiring a real Basic Auth header."""
    _init_bare_repo(tmp_path)
    handler = _make_authed_backend_handler(
        project_root=str(tmp_path), expected_token=REAL_TOKEN,
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/repo.git"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_cloning_without_a_token_is_refused_by_the_real_server(private_git_server):
    with pytest.raises(GitFetchError):
        fetch_repo(private_git_server, "main")


def test_cloning_with_the_wrong_token_is_refused_by_the_real_server(private_git_server):
    with pytest.raises(GitFetchError):
        fetch_repo(private_git_server, "main", auth_token="wrong-token-entirely")


def test_a_correct_token_authenticates_a_real_clone(private_git_server):
    fetched = fetch_repo(private_git_server, "main", auth_token=REAL_TOKEN)
    try:
        assert fetched.commit_sha
        assert fetched.branch == "main"
    finally:
        cleanup_repo(fetched.local_path)


def test_a_real_vault_credential_authenticates_a_real_clone(private_git_server, engagement_id):
    """The full seam, end to end: store -> material_for -> fetch_repo."""
    credential_id = f"CRED-{uuid.uuid4().hex[:10]}"
    with credential_admin_scope(engagement_id) as conn:
        store_credential(
            conn, engagement_id=engagement_id, credential_id=credential_id,
            label="git PAT", credential_type="git_token", secret=REAL_TOKEN,
            actor="test-harness",
        )
    with engagement_scope(engagement_id) as conn:
        material = material_for(conn, credential_id)

    assert material.credential_type == "git_token"
    fetched = fetch_repo(private_git_server, "main", auth_token=material.fields["secret"])
    try:
        assert fetched.commit_sha
    finally:
        cleanup_repo(fetched.local_path)


def test_the_token_never_appears_in_a_failed_clones_error_message(private_git_server):
    """Redaction at the boundary: a git clone failure must not smuggle the
    token into whatever GitFetchError reports, regardless of whether the
    underlying git error happened to echo it.
    """
    try:
        fetch_repo(private_git_server, "main", auth_token="wrong-token-entirely")
        raise AssertionError("expected the wrong token to be refused")
    except GitFetchError as exc:
        assert "wrong-token-entirely" not in str(exc)
