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
db/               alembic migrations, roles.sql, schema.sql
policy_tests/     opa test suites (constraint algebra + adversarial fixtures)
tests/stateful/   Hypothesis RuleBasedStateMachine over event sequences
```

Deliberately **not** here (§10 "明確不要做"): real LLMs, Neo4j, vector DB, egress
proxy, multi-provider routing, Web Agent, Playwright, approval UI.

## Requirements

Python 3.12, PostgreSQL 16, OPA 1.x (Rego v1), Docker.

## Setup

```bash
make setup     # venv + dev dependencies
make db        # create roles + database, run alembic migrations
make test      # pytest (unit, scenarios, stateful) + opa test
```
