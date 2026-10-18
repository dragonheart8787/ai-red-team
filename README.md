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
| `global_auditor` | audit queries | reads `scope = 'global'` audit rows, nothing else |
| `ui_reader` | the web console | `SELECT` only (D29) |
| `credential_admin` | the credential vault | `credential_material` and `credentials`, nothing else |
| `global_policy_admin` | `scripts/manage_global_policy.py` (an operator) | the only writer of global policy layers (5.37) |
| `scheduler_reader` | the scheduler's decision side | three `engagements` columns, a closed-vocabulary view of proposals, the enrollment list and its own state; no content, no audit log (D62) |
| `scheduler_admin` | `scripts/manage_scheduler_enrollment.py` (an operator) | writes the enrollment list, reads nothing else (D62) |
| `scheduler_state_writer` | the scheduler | writes its closed-vocabulary state table, nothing else (D62) |

None of them is a superuser and none carries `BYPASSRLS`, so RLS applies
to all of them. `registry_admin` is a writer, not an administrator: it is
confined to one engagement exactly like `cyberorch_app`, and holds no `DELETE`
anywhere — registry rows are retired with `active = FALSE` so the audit trail
keeps something to point at. (`db/roles.sql` is the authority for the list;
the table above was three rows long until the D63 audit.)

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

### The deadline helper is not in git

Every tool container runs `cyberorch-deadline` as PID 1 (D65-A: it ends the container when the run's
deadline passes, so a tool does not outlive a control plane that died). Its **binaries are built, not
committed** -- `tool_gateway/deadline/bin/` is git-ignored -- and **a checkout does not have them**. Without
them the sandbox refuses every run (`deadline_helper_missing`) and the tests that start a real sandbox
(`tests/test_deadline_sandbox.py`, the reconciler's real-Docker tests, the live drills) fail.

```bash
./tool_gateway/deadline/build.sh --check   # an x86_64 Linux host; offline, from the vendored source
```

The build uses the pinned Rust toolchain (`toolchain.sh` downloads exactly the tarballs listed in
`TOOLCHAIN.sha256` and checks each sha256 before unpacking), is reproducible, and `--check` compares the
result with the committed `tool_gateway/deadline/SHA256SUMS`; the sandbox compares it again before **every**
run. CI does the same in its own job (`deadline-helper`) and hands the binary to the test job as an artifact.
Where the file must live, and why, is in `tool_gateway/deadline/README.md`.

### The reconciler (D64)

`scripts/run_reconciler.py --mode dry-run|state-only [--once] [--interval 60]` finds what a crash or a lapse
left behind. There is no default mode. `dry-run` changes nothing and writes no audit record. `state-only`
moves stuck proposals to a terminal stage (each by one compare-and-set, each audited) and **does not kill,
remove or delete anything**: those are five switches, each **off by default** -- no environment variable,
configuration key or default turns one on, and nothing that ships starts the reconciler with one. A person turns
one on from the command line, for one run, by typing back a phrase at a terminal (`--enable kill`,
`--enable container`, `--enable proxy`; `network` and `file` are refused in this version). "Off" is a default,
not a state of the world: the drills (`scripts/drill_reconciler_*.py`) and the soak (`docs/D66_SOAK.md`) turn
the first three on -- the first drill only after a dry run had shown that every object in the plan was one it
had made, the others limited to their own engagements (`--engagement`) -- and nothing else has ever been run
with one. `--enable container` also needs `--evidence-dir DIR` -- a directory of yours, mode 0700 -- because a
container whose run ended in an unknown outcome is removed only after its `docker inspect` output and logs are
written there (in a 0700 subdirectory per engagement) and their SHA-256 are in the audit trail. Those files are
**raw data**, not redacted, as sensitive as the engagement; the service refuses to start if it cannot write one
there, and nothing prunes them. The thresholds come from the `RECONCILER_*` keys in
`.env.example`; with one missing it refuses to start. The reconciler needs the database at migration head
(`make db` creates its two roles and runs every migration) and its own login role `reconciler_reader`, which
can execute two read functions and nothing else. `docs/D64_RECONCILER_DESIGN.md` is the design;
`docs/D64_PREDELETION_COMPLETION.md` is what was built and measured, round by round.
`docs/D66_SOAK.md` is the method of the long run under faults (`scripts/soak/`), and `docs/D66_SOAK_PILOT_2026-10-15.md` what its pilots found.
