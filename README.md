# ai-red-team

**Policy-Aware Multi-Agent Cybersecurity Orchestration Platform — MVP-Kernel**

Design of record: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (v0.3). Every module in
this repo traces back to a section of that document; no architectural decision is
introduced here that is not in the document.

## What this stage is

MVP-Kernel (§10) — **zero real LLMs**. The planner, worker and policy reviewer are
scripted fakes, and the reviewer is *adversarial*: it deliberately reports
`risk=low, sensitive_data=[]` for targets the Authoritative Metadata Registry marks
`PII` at `AUTHORITATIVE` authority. The point is to prove the kernel holds when the
AI lies (I6b — Attribute Non-Escalation), before spending anything on a real model.

The two scenarios that define "done" (§10):

- **Scenario A** — authorized target walks the whole pipeline to evidence + audit trail.
- **Scenario B** — an `AUTHORITATIVE` deny classification produces `DENY` even though the
  adversarial reviewer says the target is harmless, **and no network action occurs**.

## Layout (§3)

```
control_plane/
  api/            FastAPI routers — the only surface agents may call
  orchestrator/   task lifecycle state machine
  canonicalizer/  target.py + authorization.py + metadata.py (two separate resolvers)
  registry/       scope_registry.py (typed scope objects) + metadata_registry.py
  policy/         engine.py (OPA client) + merge.py (constraint algebra) + rego/
  capability/     lease/heartbeat with re-authorization on every renewal
  dedup/          exact-match fingerprint dedup + manual supersedes table
  state/          SQLAlchemy models + engagement-scoped repository layer
  evidence/       raw immutable + derived LLM-safe view
  provenance/     provenance_edges
  audit/          append-only writer (INSERT-only role)
  events/         Postgres LISTEN/NOTIFY
agents/fake/      fake_planner / fake_worker / adversarial_fake_reviewer
tool_gateway/     registry.py + sandbox.py (Docker + CIDR allowlist) + adapters/
db/               alembic migrations (the schema's only description), roles.sql
policy_tests/     opa test suites (constraint algebra + adversarial fixtures)
tests/stateful/   Hypothesis RuleBasedStateMachine over event sequences
```

Deliberately **not** here (§10 "明確不要做"): real LLMs, Neo4j, vector DB, egress
proxy, multi-provider routing, Web Agent, Playwright, approval UI.

## Database roles (§8.6, §5)

| Role | Used by | Can do |
|---|---|---|
| `migration_owner` | alembic | owns every table; runs DDL |
| `cyberorch_app` | everything at runtime | read/write state; **read-only** on both registries |
| `registry_admin` | Engagement Manager only | `cyberorch_app` plus writes to `scope_registry` and `metadata_registry` |

None of the three is a superuser and none carries `BYPASSRLS`, so RLS applies
to all of them. `registry_admin` is a writer, not an administrator: it is
confined to one engagement exactly like `cyberorch_app`, and holds no `DELETE`
anywhere — registry rows are retired with `active = FALSE` so the audit trail
keeps something to point at.

The split exists because §5 calls the two registries the highest value attack
surface in the system: whoever can write them can authorize themselves, or
reclassify a customer database as a static site. With one role, that guarantee
rested on application code choosing not to issue the write.

## Tool sandbox (§8.3)

Tools run in a container attached to a Docker network created `internal` with
the engagement's allowlisted CIDR as its subnet. An internal network gets no
default gateway, so the namespace has a route to the allowlist and to nothing
else: traffic anywhere else fails in the kernel with `ENETUNREACH` before a
packet is built. The container drops every capability, so it cannot add the
route back.

Two things worth knowing before trusting a green test run:

- **A scanner's own report cannot tell you the boundary held.** Under `-Pn`,
  nmap describes a target it has no route to as "host up, port filtered" —
  identical to a firewall in front of a reachable host. Confinement is checked
  with `DockerSandbox.probe_egress`, which asks the kernel.
- **`ENETUNREACH` and `EHOSTUNREACH` are not the same result.** "Network is
  unreachable" means nothing left the namespace; "No route to host" means
  traffic left and the host did not answer. Both read as "no route" in English,
  and conflating them makes a confinement test pass whenever the target is
  simply absent.

The tool image is built from the host's own nmap install
(`make sandbox-image`) rather than pulled, so it works without a registry and
is pinned to what the operator installed.

## Requirements

Python 3.12, PostgreSQL 16, OPA 1.x (Rego v1), Docker, and `nmap` + `ncat` on
the host (for `make sandbox-image`).

## Setup

```bash
make setup     # venv + dev dependencies
make db        # create roles + database, run alembic migrations
make test      # pytest (unit, scenarios, stateful) + opa test
```
