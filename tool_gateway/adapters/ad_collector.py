"""AD collector adapter — bulk graph collection, not single-target scanning (§4.6, D42-6).

``bloodhound-python`` (the Impacket-based, pure-Python BloodHound collector)
rather than SharpHound: it runs in the existing Linux sandbox with no new
base image and no Windows host, the same reasoning §8.3 already applies to
every other tool here (D42-1/D42-6 design doc §2.1/§4).

This is the first adapter whose action authorizes *collection over a set*
rather than an action against one target (D42-1 Option C): the capability
names an ``ad_domain`` identity, and everything this run discovers is a
**discovery candidate**, never itself authorization for anything (§1.6/§1.9
of the design doc) — nothing in this module writes ``metadata_registry``,
and nothing here can.

Credential handling (D44, `docs/ADR_CREDENTIAL_VAULT.md` §4.1).
``build_plan`` requires a ``domain_username`` constraint and builds a small
shell wrapper that reads the LDAP bind secret from a file at
``CONTAINER_CRED_PATH`` at *run* time — ``dispatch_collection`` is the caller
that actually mints and mounts that file, via
``control_plane.vault.vault.mount_for_run``. (The wrapper does not keep the
secret out of argv; see the honest limit below.) Since D50-B the
``domain_username`` and ``auth_mode`` this function sees are the ones **bound
into the credential** (``dispatch_collection`` reads them from the vault and
puts them in ``constraints``; a proposal's own claim is only an assertion that
must match) -- this adapter still just requires them to be present, and does
not know or care where they came from.

**There is no uncredentialed mode, and this adapter no longer builds one
(D50 F1).** Until D50 a capability with no ``domain_username`` got a bare
``bloodhound-python -d <domain> -c <methods> --zip``. That was a D42
interim path ("no live/production path until the Vault lands") that D44 never
retired, and it cannot work: the real ``bloodhound==1.9.0`` requires a username
in every authentication branch of its ``main()`` and, given none, prints its
usage text and exits 1 before it builds the object that does any DNS or LDAP
(D50, `docs/D50_AD_COLLECTOR_AUTH_GAP_INVESTIGATION.md` §1, ten credential
shapes tried against the real binary). Every fixture test that passed through
that branch did so under ``StubSandbox``, which never executes the command.
``build_plan`` therefore refuses it, and ``dispatch_collection`` turns that
refusal into ``UNBUILDABLE_PLAN`` before any container starts.

**Attached-form arguments (D50 F3).** The username and the secret are passed as
``--username=<v>`` / ``--password=<v>`` (or ``--hashes=<v>``), never as a flag
followed by a separate token. With the separate-token form, argparse refuses
any value that begins with ``-`` (``-p -abc123`` fails with "expected one
argument"), and both values are operator/Worker-supplied. Verified against the
real binary: the attached forms are accepted for every such value.

**This is an honest limit, not a claimed clean solution.**
``bloodhound-python`` has no "read the password from a file" flag of its
own, so the wrapper still has to substitute the secret into the real
process's argv via shell command substitution (``"$(cat ...)"``) when it
execs. What D35's file-mount principle buys here is that the secret never
appears in *this system's own* records — not in the plan's ``command`` (what
``tool_run.started`` audits), not in the capability's ``normalized_params``,
not on the command line the control plane ever constructs or logs. What it
cannot buy, because the tool's own CLI does not offer it, is keeping the
secret out of that process's argv: **for the whole run** (the wrapper
``exec``s, so the tool *is* the process), and visible **on the host**, not only
inside the container — measured at D50 in ``docker top`` and in the host's own
``ps``. (An earlier version of this paragraph limited it to "inside the
container … for the moment it execs" and said ADR §2.2 already priced it in;
neither was accurate — §2.2 does not mention the process table.) The secret
also sits in a ``0644`` host file for the same window. Whether to close either
is an open, deliberately deferred question: ``docs/ACCEPTANCE_MVP1_AGENTS.md``
5.26 and ``docs/ADR_CREDENTIAL_VAULT.md`` §7.

**Flag verification (D45): closed for real, not re-derived from documentation.**
``-d``/``-c``/``-u``/``-p``/``--hashes``/``--zip`` were all checked against a
real `pip install bloodhound==1.9.0` and a real `bloodhound-python --help`,
then exercised against a real Samba AD DC via `tool_gateway/images/
bloodhound.Dockerfile` (built for the first time in D45 — no image existed
before it). This is also how D45 found and fixed a real bug this module
carried since D42: the binary lives at ``/usr/local/bin/bloodhound-python``
(pip's own install location), not ``/usr/bin/bloodhound-python``, which
every prior test passed under because `StubSandbox` records `plan.command`
without ever executing it. ``--hashes`` takes ``LM:NTLM`` (both halves,
colon-separated), not a single hash value — whoever stores an
``ad_domain_bind`` credential with ``auth_mode="hashes"`` must store it
already in that joined form; this module does not reshape it.

**What D45 could not verify, and why, recorded precisely rather than
glossed over:** a full authenticated collection was attempted against a
real Samba Active Directory Domain Controller (`nowsci/samba-domain`, the
only lightweight non-Windows AD-compatible option found), driven through
the real, unmodified production path (`propose_action` ->
`dispatch_collection` -> `DockerSandbox.run` -> this adapter's real,
fixed-binary-path command). That real run surfaces a real blocker one step
*earlier* than the LDAP/Kerberos layer: `DockerSandbox.run` passes no `dns`
option to `containers.create` at all, so the container gets Docker's own
embedded resolver (127.0.0.11), which returns `SERVFAIL` for the AD-specific
locator record `bloodhound-python` needs first
(`_ldap._tcp.pdc._msdcs.<domain>`, an SRV record type nothing but the
domain's own DNS server -- here, the DC itself -- knows how to answer).
Confirmed structural, not a Samba quirk: querying the same record directly
against the DC's own DNS (`--dns <dc-ip>`, bypassing `DockerSandbox`
entirely) answers correctly, so the record exists and is correct; the sandbox
container simply has no path to ask the DC for it. This is not specific to
this test's Samba surrogate -- **the same sandbox network model (an
internal, gateway-less Docker network with no `dns=` override) would face
the identical `SERVFAIL` against a genuine Windows AD domain**, since a real
deployment's DC is exactly the DNS server bloodhound-python needs and
exactly what `DockerSandbox` currently has no way to point a container at.
This adapter's own design (`build_plan`'s docstring above: "DNS/DC location
is the collector binary's own business at run time, not this module's")
assumed ambient container DNS would simply resolve the domain; D45 is what
found that assumption false for this sandbox's actual network model, not
only for this test's specific target.

Separately, and only reachable if the DNS gap above is ever closed: a raw,
out-of-band container run (bypassing `DockerSandbox`, with an explicit `--dns`
override pointing at the DC) does reach the LDAP/Kerberos layer, and fails
there for two independent, verified reasons that are properties of the
client libraries against *this specific server implementation*, not of
anything this adapter builds: (1) `ldap3`'s NTLM bind uses the legacy
Microsoft "Sicily" LDAP extension, which Samba's AD DC does not implement and
closes the connection on sight; (2) `impacket`'s Kerberos TGS-REQ
(`impacket/krb5/kerberosv5.py`, `getKerberosTGS`) never sets the
Authenticator's optional `cksum` field, which real Microsoft AD KDCs
tolerate but Samba's own, stricter KDC rejects with `KRB_AP_ERR_INAPP_CKSUM`.
Both were confirmed by reading the library source after reproducing each
failure directly, not assumed from a single stack trace, and neither is
fixable from this adapter's side. Real authenticated collection against a
genuine Windows AD domain remains unverified through *any* path -- the DNS
gap blocks the real sandbox path before authentication is ever attempted,
and that gap is real, not a mock standing in for it.

**D49 closes the DNS gap above -- and the fix is smaller than D45's own
framing implied.** D45 said "`DockerSandbox` currently has no way to point a
container at" a nameserver, which reads as "`DockerSandbox` needs a `dns=`
parameter." Verified fresh rather than assumed: it does not. Reading
`bloodhound.ad.domain.AD.__init__` directly shows `-ns` already makes
`dnspython` replace its resolver's nameserver list outright
(`dnsresolver.nameservers = [nameserver]`), which sends the DNS query
straight to that IP over a real socket -- bypassing the container's system
resolver (and therefore Docker's embedded one) entirely, no `containers.
create(dns=...)` involved. `sandbox.py`'s own docstring already establishes
that the container's network namespace has a real route to every address
inside the allowlisted CIDR ("Docker attaches no default gateway to an
internal network, so the container's namespace has a route to the
allowlisted range and to nothing else") -- and a real AD domain's DC (the
address this constraint would actually carry) is, in the case this project
can act on, inside that same CIDR by construction, since D42-1's own scope
model already ties `ad.collect`'s authorization to the domain's own
network. So a `dns_server` constraint naming an address the sandbox's
network can already route to was sufficient, with `DockerSandbox` itself
untouched. What D49 *did* have to add is the piece D45 had not yet asked
the question of: whether an operator-supplied `dns_server` needed its own
authorization check at all (it does -- `dispatch_collection`'s own
docstring covers the reasoning), since nothing before D49 had ever
considered a DNS server as something a compromised or misconfigured
capability could try to point outside its own authorized range.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from control_plane.graph.store import GraphEdge, GraphNode

TOOL = "bloodhound-python"
ACTION = "ad.collect"

#: This tool ships its own image, the same as semgrep's (D43) and for the
#: same reason -- bloodhound-python is not present in the shared
#: cyberorch/nmap:local image dispatch_scan's callers default to. Read by
#: dispatch_collection via getattr(adapter, "IMAGE", None), mirroring
#: dispatch_scan's and dispatch_code_scan's own lookup exactly. **Missing
#: until D45**: dispatch_collection built and read every other adapter
#: attribute (TOOL, ACTION, REQUIRES_PROXY) but never looked one up for the
#: image, so a caller of propose_action/dispatch_collection that did not
#: hand-pick a sandbox got DockerSandbox's DEFAULT_IMAGE
#: (cyberorch/nmap:local) -- a container with no bloodhound-python binary in
#: it at all. Found only because D45 insisted on driving a real dispatch
#: rather than the StubSandbox every prior ad.collect test supplied.
IMAGE = "cyberorch/bloodhound:local"

#: Must equal ``BLOODHOUND_VERSION`` in tool_gateway/images/bloodhound.Dockerfile
#: and in build_bloodhound_image.sh (a test compares all three). The tool is
#: installed inside the image, not on the control-plane host that computes the
#: fingerprint, so there is no host binary whose presence says anything about what
#: actually runs -- see ``tool_version``.
BLOODHOUND_VERSION = "1.9.0"

#: A collection run issues LDAP reads and writes nothing to the domain it
#: queries — the same D31/D34 reasoning nmap's port scan and web.get give,
#: applied to LDAP instead of TCP/HTTP: nothing in the command this adapter
#: builds has a write verb of any kind.
WRITES_DATA = False
CHANGES_STATE = False

#: Whether this action needs a known data classification before it runs (D56). This is a
#: fact about the action's *name* in control_plane/policy/rego/authz.rego
#: (requires_known_classification), stated here so that it is a decision and not a
#: coincidence of spelling; tests/adapter_kit.classification_violations compares the two.
#: not argued: see ACCEPTANCE 5.48.
KNOWN_CLASSIFICATION = (
    'exempt: no argument is recorded either way -- ad.collect was left outside the rule '
    'at D42 and stands as it was (ACCEPTANCE 5.48)'
)

#: LDAP goes through the sandbox's raw namespace, the same as nmap's TCP —
#: there is no application-layer HTTP here for the §8.3 egress proxy to
#: read, so routing through it would add a hop that inspects nothing.
REQUIRES_PROXY = False

#: Which dispatch function (`control_plane.orchestrator.dispatch`) this
#: action's capability must be routed to from `propose_action` (D46).
#: **This is the exact fact D45 found `propose_action` getting wrong**: the
#: real production entry point called the generic `dispatch_scan` for
#: `ad.collect` unconditionally, for as long as this action has existed,
#: because nothing declared -- anywhere -- that it needed something else.
#: `dispatch_collection` is the one dispatch function that actually performs
#: this action's second, bespoke step (the Security Graph write); routing
#: anywhere else silently drops it. See nmap.py's own copy of this constant
#: for why every adapter, not only this one, declares it explicitly.
NEEDS_DISPATCH = "dispatch_collection"

TOOL_STOP_GRACE_SECONDS = 5

#: Verified against a real `pip install bloodhound` inside the image this
#: adapter actually runs in (D45) -- **not** `/usr/bin/bloodhound-python`,
#: which this module wrongly assumed before D45 actually built and ran
#: `tool_gateway/images/bloodhound.Dockerfile` for the first time. Every
#: prior test passed with the wrong path because `StubSandbox` never
#: executes `plan.command`, only records it -- exactly the class of gap a
#: real container run exists to catch.
BLOODHOUND_PYTHON_PATH = "/usr/local/bin/bloodhound-python"

#: bloodhound-python's own collection-method vocabulary (``-c``). Kept
#: closed rather than passed through verbatim, matching every other
#: adapter's refusal to let a constraint become an arbitrary argv escape
#: hatch (nmap's SCAN_TYPES, http's fixed METHOD).
COLLECTION_METHODS = frozenset({
    "Group", "LocalAdmin", "Session", "Trusts", "ACL", "ObjectProps",
    "RDP", "DCOM", "Container", "All",
})

_DOMAIN_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

#: Where the sandbox mounts a per-dispatch credential file (D44,
#: ``control_plane.vault.vault.mount_for_run``'s ``host_path``, mapped here
#: by the caller -- ``dispatch_collection`` -- into ``source_mounts``). Every
#: plan this adapter builds reads it (there is no uncredentialed command, D50).
CONTAINER_CRED_PATH = "/creds/secret"

#: bloodhound-python's two mutually exclusive bind mechanisms. Kept closed
#: like ``COLLECTION_METHODS``, for the same reason: a constraint should
#: select among known shapes, not become an arbitrary flag passthrough.
AUTH_MODES = frozenset({"password", "hashes"})


class AdapterError(ValueError):
    """The capability cannot be turned into a collection run."""


@dataclass(frozen=True)
class AdCollectPlan:
    """What will actually be executed, before it is executed."""

    command: tuple[str, ...]
    target: str
    collection_methods: tuple[str, ...]
    max_duration_seconds: int
    max_queries_issued: int | None
    #: Non-secret. Every plan carries a bind identity (D50 F1 removed the
    #: uncredentialed plan), so these are required, not optional.
    domain_username: str
    auth_mode: str
    #: A concrete IP, never a hostname (D49) -- passed straight to
    #: bloodhound-python's own ``-ns`` flag. ``dispatch_collection`` is the
    #: one place with both this value and ``network_allowlist`` in hand, so
    #: it -- not this adapter -- is what refuses a value outside the
    #: authorized range; this field only carries what the capability named.
    dns_server: str | None = None

    def as_params(self) -> dict[str, Any]:
        """Normalized parameters for the §7 execution fingerprint.

        ``domain_username``/``auth_mode`` are included -- a different bind
        account or a switch from password to pass-the-hash is a different
        execution (§7 v0.3's own reasoning, "the same target scanned with a
        different credential is a different execution") -- but the secret
        value itself never reaches this adapter, so there is nothing here
        for a fingerprint to leak even in principle. ``dns_server`` is
        included for the identical reason: a different nameserver can
        resolve a different domain controller for the same domain name, so
        it is part of what makes one run the same execution as another, not
        a detail the fingerprint can ignore.
        """
        params: dict[str, Any] = {
            "target": self.target,
            "collection_methods": list(self.collection_methods),
            "domain_username": self.domain_username,
            "auth_mode": self.auth_mode,
        }
        if self.dns_server is not None:
            params["dns_server"] = self.dns_server
        return params


def tool_version() -> str:
    """The pinned bloodhound-python version, for the fingerprint (§7).

    Not a host subprocess check. This tool runs from a Dockerfile-built image
    (``BLOODHOUND_VERSION``), not from an export of the host's own installed binary
    the way nmap's image is, so the control plane -- a different machine from the
    sandbox -- has no reason to have it, and probing for it returned ``"unknown"``
    in every deployment. A fingerprint that cannot see a tool upgrade skips a
    re-collection the upgrade should have triggered (ACCEPTANCE 5.30; the defect
    D43 fixed for Semgrep at ``ab2849a``, and the precedent followed here:
    semgrep.py and browser.py return a pinned constant for the identical reason).
    """
    return f"bloodhound-python-{BLOODHOUND_VERSION}"


def tool_deadline(max_duration_seconds: int) -> int:
    """When the collector is asked to stop, given when the sandbox will kill it.

    Same D11-derived reasoning as every other adapter's grace margin
    (nmap.py, _http.py): ask before the sandbox kills, so a well-behaved
    run's partial output survives rather than being destroyed mid-write.
    """
    return max(1, max_duration_seconds - TOOL_STOP_GRACE_SECONDS)


def validate_collection_methods(spec: Sequence[str] | None) -> tuple[str, ...]:
    if not spec:
        return ("Group", "LocalAdmin", "Session", "ACL")
    unknown = set(spec) - COLLECTION_METHODS
    if unknown:
        raise AdapterError(
            f"unsupported collection method(s) {sorted(unknown)}; expected a "
            f"subset of {sorted(COLLECTION_METHODS)}"
        )
    return tuple(spec)


def validate_auth_mode(spec: str | None) -> str:
    mode = spec or "password"
    if mode not in AUTH_MODES:
        raise AdapterError(
            f"unsupported auth_mode {mode!r}; expected one of {sorted(AUTH_MODES)}"
        )
    return mode


def build_plan(
    *, constraints: Mapping[str, Any], budget: Mapping[str, Any], target: str,
) -> AdCollectPlan:
    """Turn a capability into a collection command.

    ``target`` is the ``ad_domain`` identity's value — a domain name, opaque
    per D42-1 §1.1, compared verbatim. This adapter does not *discover* a
    domain controller address on its own initiative — that is exactly the
    kind of discovery-vs-authorization line §8.9/I8 draws elsewhere — but it
    can be *told* one via the ``dns_server`` constraint (D49): when present,
    it is passed straight to bloodhound-python's own ``-ns`` flag, which
    bypasses the container's system resolver entirely and queries that
    server directly (verified by reading ``bloodhound.ad.domain.AD.
    __init__``: ``dnsresolver.nameservers = [nameserver]`` replaces
    ``dnspython``'s default resolver configuration outright, not merely a
    hint layered on top of it). Whether that value is authorized to be
    queried at all — is it inside the capability's own ``network_allowlist``
    — is not this function's call; ``dispatch_collection`` is the one place
    that holds both the constraint and the allowlist, so it is what refuses
    a ``dns_server`` outside the authorized range, before any container
    starts (see its own docstring).
    """
    if not target:
        raise AdapterError("no target")
    if not _DOMAIN_LABEL.match(target.split(".", 1)[0]):
        raise AdapterError(f"invalid ad_domain target {target!r}")

    max_duration = int(budget.get("max_duration_seconds", 600))
    if max_duration <= 0:
        raise AdapterError("max_duration_seconds must be positive")

    tool_budget = budget.get("tool") or {}
    max_queries = constraints.get("max_queries_issued") or tool_budget.get("max_queries_issued")
    max_queries = int(max_queries) if max_queries is not None else None

    methods = validate_collection_methods(constraints.get("collection_methods"))

    # max_queries_issued is recorded on the plan for observability and audit
    # (as_params/dispatch payload) but is not mapped to a CLI flag here:
    # bloodhound-python is not confirmed to have a native per-run query-count
    # cap (see module docstring on unverified flags), and inventing one would
    # be asserting tool behaviour nobody has checked. max_duration_seconds,
    # enforced by the sandbox kill exactly like every other adapter, is the
    # bound this adapter actually enforces today.

    dns_server = constraints.get("dns_server")
    if dns_server is not None:
        try:
            ipaddress.ip_address(dns_server)
        except ValueError as exc:
            raise AdapterError(
                f"dns_server {dns_server!r} is not a valid IP address"
            ) from exc

    # No credential-free plan exists (module docstring, D50 F1): the real tool
    # exits with its usage text unless it is given a username, so building
    # one would only produce a run that cannot succeed. Refused here, in the
    # constraint-shape layer; dispatch_collection reports it as
    # UNBUILDABLE_PLAN, before any container starts.
    domain_username = constraints.get("domain_username")
    if not isinstance(domain_username, str) or not domain_username.strip():
        raise AdapterError(
            "ad.collect requires a domain_username constraint: the real "
            "bloodhound-python has no credential-free mode (it prints usage "
            "and exits 1 without one), so a capability without a bind "
            "identity cannot be run"
        )
    auth_mode = validate_auth_mode(constraints.get("auth_mode"))
    auth_flag = "--password" if auth_mode == "password" else "--hashes"

    # D35's file-mount principle, generalized (D44, module docstring): the
    # secret is read from CONTAINER_CRED_PATH at run time, never placed in this
    # command -- what dispatch_collection audits and records as `plan.command`
    # never contains it. Every value arrives as a positional shell argument
    # ($1..$6), never string-interpolated into the script text, so none of
    # them can alter the script; that holds for non-secret values too (dns_server
    # is not secret, and is a validated IP besides).
    #
    # D50 F3: username and secret are attached to their flag ("--username=$2",
    # "--password=$(cat ...)") rather than following it as a separate token,
    # because argparse refuses a separate-token value that begins with "-"
    # (module docstring). $3 is the flag *name* only, chosen from the closed
    # AUTH_MODES vocabulary above, never a caller-supplied string.
    dns_flag = ' -ns "$6"' if dns_server is not None else ""
    command = [
        "/bin/sh", "-c",
        f'exec {BLOODHOUND_PYTHON_PATH} -d "$1" "--username=$2" '
        f'"$3=$(cat "$4")" -c "$5"{dns_flag} --zip',
        "sh", target, domain_username, auth_flag, CONTAINER_CRED_PATH,
        ",".join(methods),
    ]
    if dns_server is not None:
        command.append(dns_server)

    return AdCollectPlan(
        command=tuple(command), target=target, collection_methods=methods,
        max_duration_seconds=max_duration, max_queries_issued=max_queries,
        domain_username=domain_username, auth_mode=auth_mode,
        dns_server=dns_server,
    )


def derive_view(stdout: str, stderr: str, *, notable_edge_limit: int = 20) -> dict[str, Any]:
    """Build the §4.4 derived view — the bounded, prompt-facing summary.

    Deliberately not the full graph. A BloodHound-shaped graph put inline in
    a prompt would recreate D40/5.21's argv-length crash at a much larger
    scale (design doc §2.1/§4.1 of the ADR) — the full parse lives in
    :func:`parse_graph`, whose output goes to ``control_plane.graph.store
    .record_batch`` as a side effect of dispatch, never into a prompt.
    """
    try:
        nodes, edges = parse_graph(stdout)
    except (ValueError, KeyError):
        nodes, edges = [], []

    by_kind: dict[str, int] = {}
    for n in nodes:
        by_kind[n.kind] = by_kind.get(n.kind, 0) + 1

    return {
        "untrusted_content": True,
        "computers_seen": by_kind.get("computer", 0),
        "users_seen": by_kind.get("user", 0),
        "groups_seen": by_kind.get("group", 0),
        "edge_count": len(edges),
        "notable_edges": [
            {"src": e.src.identity_value, "dst": e.dst.identity_value, "edge_type": e.edge_type}
            for e in edges[:notable_edge_limit]
        ],
        "stdout_excerpt": stdout[:2000],
        "stderr_excerpt": stderr[:2000],
    }


def parse_graph(stdout: str) -> tuple[list[GraphNode], list[GraphEdge]]:
    """The full, unbounded parse — every discovered node and edge.

    Consumes a JSON object of this adapter's own definition:
    ``{"nodes": [{"identity_type", "identity_value", "kind"}, ...],
      "edges": [{"src", "dst", "edge_type"}, ...]}`` where each edge's
    ``src``/``dst`` is an ``identity_value`` from ``nodes``.

    **This is not bloodhound-python's native output shape.** The real tool
    (with ``--zip``) emits a zip of per-object-type JSON files
    (``users.json``, ``computers.json``, ``groups.json``, ...), each with
    its own ``Aces``/``Members``/``Sessions`` arrays. Translating that into
    the shape above is unverified against a real collection — there has
    been no credential to produce one with (§4.3) — and is left as explicit
    follow-on work, not silently assumed solved. What this function does is
    fully tested against fixture data in the shape above, so
    ``dispatch_collection`` → ``record_batch`` → ``queries.py`` is exercised
    end to end; only the translation from the real tool's own output format
    into this one remains open.
    """
    doc = json.loads(stdout)
    nodes = [
        GraphNode(
            identity_type=n["identity_type"], identity_value=n["identity_value"], kind=n["kind"],
        )
        for n in doc.get("nodes", [])
    ]
    by_value = {n.identity_value: n for n in nodes}
    edges = []
    for e in doc.get("edges", []):
        src = by_value.get(e["src"])
        dst = by_value.get(e["dst"])
        if src is None or dst is None:
            raise ValueError(f"edge references a node not in this batch: {e}")
        edges.append(GraphEdge(src=src, dst=dst, edge_type=e["edge_type"]))
    return nodes, edges
