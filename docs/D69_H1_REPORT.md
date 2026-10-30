# D69 H1 -- pre-checks report (reading only)

**This is H1's deliverable and nothing else.** H1 is the documents-only stage of
`docs/D69_IMPLEMENTATION_PLAN.md`: it reads, records what reading can settle, and authorizes no
implementation. Nothing was run against a database, a daemon, a model or nmap for this report; no
scan of any kind was performed. Written 2026-10-31 by the review layer under the owner's standing
delegation; the owner may veto any line.

Tags: **[R]** read in code or a document, with the line quoted; **[E]** executed by me in this
session; **[D]** derived, not observed; **[N]** not established, with the reason given. Items 1 to 5
are the plan's own H1 list. Items 6 to 10 were added by the owner's instruction of 2026-10-31 and
exist to answer the plan's corrections A to D of the same date.

**Still open, and not closed by this report:** P-1 and P-2 are the owner's, and H1 was to *obtain*
them. P-1 (a) stands on the reading recorded in item 1 below but has had no explicit owner
confirmation. P-2 is recorded in the plan as unconfirmed, and H2 does not start before the owner
confirms or vetoes it. H1 ending does not start H2.

---

## 1. The harness's database role and its grants **[R]**

One blanket grant, then a revoke for three append-only tables:

```
db/migrations/versions/0001_core_schema.py
410:    op.execute("GRANT USAGE ON SCHEMA public TO cyberorch_app;")
411:    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
412:               "TO cyberorch_app;")
413:    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cyberorch_app;")
415:    for table in APPEND_ONLY:
416:        op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM cyberorch_app;")
417:        op.execute(f"GRANT INSERT, SELECT ON {table} TO cyberorch_app;")
```

and the list that revoke applies to:

```
db/migrations/versions/0001_core_schema.py
39:APPEND_ONLY = ["evidence", "audit_log", "provenance_edges"]
```

**The four tables H3 and H5 read.** `tool_runs`, `action_proposals` and `capabilities` are not in
`APPEND_ONLY`, so `cyberorch_app` keeps SELECT/INSERT/UPDATE/DELETE on them from line 411.
`evidence` **is** in `APPEND_ONLY`: `cyberorch_app` has INSERT and SELECT on it and no UPDATE,
DELETE or TRUNCATE. SELECT -- all H3 needs -- is present on all four **[R]**.

**The five functions' write paths, against those grants [R/D].** The grants are read above; which
statement each function issues is read below; that the two fit is the derivation.

* `create_task` -- INSERT on `tasks`, then UPDATE on `tasks` for the overlap back-reference
  [R: `control_plane/api/function_api.py:199-206` `INSERT INTO tasks (...)`, and `:215-222`
  `UPDATE tasks SET overlaps_with = array_append(...)`]. `tasks` is not append-only: within grant.
* `claim_task` -- UPDATE on `tasks` [R: `control_plane/api/function_api.py:244-253`
  `UPDATE tasks SET status = 'claimed', owner_agent_id = :agent, ...`]: within grant.
* `complete_task` -- UPDATE on `tasks` [R: `control_plane/api/function_api.py:272-273`
  `"UPDATE tasks SET status = 'completed', result_summary = :s, "`]: within grant.
* `propose_action` -- INSERT and UPDATE on `action_proposals` through the stage machinery, INSERT on
  `tool_runs` and `evidence` through dispatch, INSERT on `capabilities` at the broker. All are
  INSERT or UPDATE on non-append-only tables except `evidence`, which is INSERT only and is only
  ever inserted [R: `control_plane/evidence/store.py` writes the artifact and the row is inserted,
  never updated -- "Nothing here ever opens an existing artifact for writing."
  `control_plane/evidence/store.py:44`]: within grant.
* `load_effective_policy` -- SELECT on `policy_layers` [R: `control_plane/policy/layers.py:638-640`
  takes a `Connection` and merges stored layers]: within grant.

Every audit write goes through `record_audit`, which uses the `cyberorch_app` engine on its own
short transaction [R: `control_plane/state/db.py:373-375` "Uses the ``cyberorch_app`` engine, which
holds INSERT and SELECT on audit_log and nothing else"]. `audit_log` is append-only and only
inserted: within grant.

**Not found, so not claimed [N]:** no migration grants or revokes anything to `cyberorch_app` for
`tool_runs`, `evidence`, `action_proposals` or `capabilities` individually -- a `git grep` for
`cyberorch_app` across `db/migrations/versions/*.py` filtered to those four table names returns
nothing, so line 411's blanket grant is the only source. The two later column-level grants that do
name these tables are for a different role: `GRANT SELECT (decision) ON {s}.action_proposals TO
{OWNER};` with `OWNER = "reconciler_fn_owner"` [R: `db/migrations/versions/0026_reconciler_has_decision.py:112`
and `db/migrations/versions/0025_tool_run_refusal_code.py:68`].

## 2. The evidence store's directory and file modes, and the expected user

**Modes are not set by this code [R].** The root and the per-engagement shard are created with no
`mode=` argument, and the artifact is created with a plain exclusive open; there is no `chmod`,
`chown` or `umask` call anywhere in the module:

```
control_plane/evidence/store.py
30:DEFAULT_STORE = Path(os.environ.get("EVIDENCE_STORE", "evidence_store"))
33:def store_root() -> Path:
34:    root = Path(os.environ.get("EVIDENCE_STORE", str(DEFAULT_STORE)))
35:    root.mkdir(parents=True, exist_ok=True)
36:    return root
47:    directory = store_root() / engagement_id / digest[:2]
48:    directory.mkdir(parents=True, exist_ok=True)
49:    path = directory / f"{digest}.bin"
55:            with open(path, "xb") as handle:
```

So the permissions an artifact and its directories end up with are whatever the running process's
umask gives, at a root taken from `EVIDENCE_STORE` or the relative default `evidence_store`
**[R for the absence of any mode argument; D for "therefore the umask decides"]**.

**The expected deployment user is [N].** No user, group or uid is named in
`control_plane/evidence/store.py`, and the plan's own H1 item 2 already anticipated this: the modes
of an *existing* store cannot be read without looking at a store, which this report does not do.
What the harness needs is narrower than that and is answered: the rule chosen in D69-3a reads
`evidence.derived_view` from the database, not the artifact, so **the harness does not need to read
the store's files at all** for v0 [R: `control_plane/api/function_api.py:1182-1185`
"Return the derived view only. / §4.4: the raw artifact never enters an LLM context."]. Whether the
harness *may* read the raw artifact stays **[N]** and stays unnecessary.

## 3. `network.scan` with an fqdn target, from `_decide` to `build_plan`

**The code path accepts it [R].** Nothing between the decision stage and the adapter restricts the
identity type. `normalize_target` has a branch per type and an fqdn is normalized, not refused
[R: `control_plane/canonicalizer/target.py:275-276` `if itype == "fqdn": / value = normalize_fqdn(ivalue)`],
and the nmap adapter's `build_plan` takes the target as an opaque string with one emptiness check
and no type check at all:

```
tool_gateway/adapters/nmap.py
167:def build_plan(
171:    target: str,
186:    if not target:
187:        raise AdapterError("no target")
```

**What nmap then does with a name is [N].** The command always carries `-n`
[R: `tool_gateway/adapters/nmap.py:203` `command.append("-n")`], which asks nmap not to resolve;
what a run does with a hostname under `-n` is runtime behaviour, and running nmap is outside this
report's authorization. This is exactly the division the plan's H1 item 3 wrote down: reading
settles the path, not the run.

## 4. A CIDR's scan report under `-Pn` -- **[N]**, as the plan expected

Reading cannot settle it, for two reasons, both checked:

* No manual page is installed. `/usr/share/man/man1/nmap*` does not exist (`ls` reports "No such
  file or directory"); `/usr/share/doc/nmap` holds only `changelog.Debian.gz`, `copyright` and
  `style`. The binary is present at `/usr/bin/nmap` **[E: existence checks only; nmap was not
  executed]**.
* No stored stdout of a `-Pn` CIDR run exists in the repository to read instead -- the finding the
  plan already carries [R: plan section 11 risk 3, "No stored CIDR `-Pn` stdout"].

**The v0 rule does not depend on the answer**, which is why this stays open: for connect and
version scans -- the ones that add `-Pn` -- the builder adds no host identity from `hosts` at all
[R: plan section 4, "The rule (design D69-3a FINAL, inherited, not changed)"]. The item is kept
only so the approval cost of that rule can be interpreted later.

## 5. An observed string carrying a port, under the `url` type **[R]**

`normalize_url` splits the port out, drops it from the canonical form when it is the scheme's
default, and keeps it when it is not:

```
control_plane/canonicalizer/target.py
227:def normalize_url(value: str) -> tuple[str, int | None, str | None]:
228:    """Return (canonical url, port, path)."""
243:    try:
244:        port = parts.port
245:    except ValueError as exc:
246:        raise CanonicalizationError(f"invalid port in url {value!r}: {exc}") from exc
247:    if port == _DEFAULT_PORTS[scheme]:
248:        port = None
251:    netloc = host_repr if port is None else f"{host_repr}:{port}"
252:    canonical = urlunsplit((scheme, netloc, path or "/", "", ""))
253:    return canonical, port or _DEFAULT_PORTS[scheme], path
```

and `normalize_target`'s url branch takes both back, preferring an explicitly supplied port over
the one parsed from the string [R: `control_plane/canonicalizer/target.py:281-284`
`elif itype == "url": / value, url_port, url_path = normalize_url(ivalue) / port = port if port is not None else url_port`].

So: `http://10.79.0.2:80/x` canonicalizes with the port **absent** from the identity value (80 is
http's default) while `http://10.79.0.2:8080/x` keeps `:8080` in it; an unparseable port is a
`CanonicalizationError`, not a best guess. **Consequence for H3 [D]:** a `host:port` string is
never a bare-identity match against an nmap `hosts` entry, which agrees with the D69-3a rule that
ports and host:port forms are never put in `observed_identities`.

## 6. `complete_task`'s preconditions, and whether anything requeues a claimed task

**There are no preconditions. [R]** The whole function:

```
control_plane/api/function_api.py
268:def complete_task(
269:    conn: Connection, *, engagement_id: str, task_id: str, result_summary: str, actor: str
270: ) -> None:
271:    conn.execute(
272:        text("UPDATE tasks SET status = 'completed', result_summary = :s, "
273:             "updated_at = now() WHERE task_id = :tid"),
274:        {"tid": task_id, "s": result_summary},
275:    )
276:    record_audit(
277:        engagement_id=engagement_id, actor=actor, event_type="task.completed",
278:        subject_type="task", subject_id=task_id, payload={"result": result_summary},
279:    )
```

* **`status` is not checked.** The `WHERE` clause is `task_id = :tid` alone: a `queued` task, an
  already-`completed` task or a task claimed by someone else is moved to `completed` just the same.
* **`owner_agent_id` is not checked, and `actor` is not compared to it.** `actor` only reaches the
  audit record; it is not in the `UPDATE`.
* **`engagement_id` is not in the statement either.** It reaches only `record_audit`. The row is
  still protected from another engagement by row-level security on the connection -- the same
  mechanism recorded for the P1 foreign-task reading (ACCEPTANCE 5.119) -- but within one
  engagement nothing scopes the write.
* **Calling it for a task this process did not claim therefore succeeds and overwrites**
  `status` and `result_summary`, and writes a `task.completed` audit record attributing the change
  to whatever `actor` string the caller passed **[R for each clause above; D for the composite
  "succeeds and overwrites"]**.

**Nothing returns a claimed task to `queued`. [R]** A `git grep` over non-test Python for
`SET status = 'queued'`, `def requeue`, `def release_task` and `def unclaim` finds exactly one
`'queued'` occurrence, and it is the *selection* inside `claim_task`, not a write of that value:

```
control_plane/api/function_api.py
248:                WHERE status = 'queued' AND engagement_id = :eid
```

This matches what the plan already carries as a registration item -- no code requeues a `claimed`
task whose lease lapsed (plan section 14, item 5) -- and extends it: there is no deliberate release
either, not only no lease sweeper.

**Consequence, which is the reason this item was added [R/D].** `claim_task` takes no `task_id` and
no creator filter [R: `control_plane/api/function_api.py:235` `def claim_task(conn: Connection, *, engagement_id: str, agent_id: str) -> str | None:`],
ordering by `priority DESC, created_at ASC` [R: `:250`]. A restarted harness on a used engagement
will therefore be handed the oldest queued task -- including one left by its previous run -- and
has no way to put it back, while `complete_task` would let it close a task it never claimed. The
plan's "never claimed again" wording is not implementable as written; corrections A and B of
2026-10-31 are the response.

## 7. Where the Worker's prompt puts `task.goal` **[R]**

In the **trusted** half, outside the untrusted block, with only observations inside it:

```
agents/llm/worker_base.py
631:        header = {
632:            "task": {"goal": task.goal, "action": task.action},
633:            "authorized_scope_objects": [c.as_dict() for c in candidates],
634:        }
635:        trusted = (
636:            "Task and authorized scope, from the engagement's own records:\n"
637:            + json.dumps(header, indent=2, sort_keys=True, default=str)
638:        )
645:        body = json.dumps(
646:            [
647:                {"source": o.source, "description": o.description,
648:                 "content": o.content}
649:                for o in observations
650:            ],
```

and the module says so deliberately [R: `agents/llm/worker_base.py:621-624` "A Worker is handed two
different kinds of thing: the task and the scope objects, which come from the Supervisor and the
registry, and observations, which came from targets. Only the second goes inside the block."].

**The Worker sees no task ledger and no other task's text [R].** The header holds exactly two keys,
`task` (goal and action only) and `authorized_scope_objects`; there is no `task_ledger`, no
`decisions`, no `findings` and no second task anywhere in `build_prompt`.

**Consequence [D].** A goal string written by a Supervisor that had untrusted evidence in its own
prompt arrives at the Worker inside the region the Worker is told to rely on. That is risk D of the
plan's 2026-10-31 additions; it is recorded, not fixed, because changing either prompt is a numbered
change with its own pinned test and a re-run of anything measured against the old wording.

## 8. What today's `complete_task` callers write as `result_summary`, and where it surfaces

**Four non-test call sites [R]** (`git grep "complete_task("` over `*.py`, excluding the definition
and `tests/`):

* `scripts/live_run/d40_three_role.py:387` -- a fixed string: `result_summary="worker declined to propose an action",`
* `scripts/live_run/d40_three_role.py:454` + `:459` -- built from closed-vocabulary outcome fields
  and ids: `result_summary = f"{outcome.decision}: {list(outcome.deny_reasons)}"`, and on the ALLOW
  branch `f"ALLOW; evidence {outcome.evidence_id}; finding {finding_id}"` [R: same file, `:450-452`].
  `decision` is one of the fixed decisions and `deny_reasons` are kernel-generated constants
  [R: `agents/llm/supervisor_base.py:147-148`, the same characterization for the decision ledger:
  "every field is either canonical (the target), drawn from a fixed set (the action, the decision)
  or a kernel-generated constant (the reasons)"].
* `scripts/live_run/live_run.py:190` -- `result_summary=f"live scan {outcome.decision}",`: the
  decision alone.
* `scripts/live_run/d17_supervisor.py:632` -- `result_summary=result,` where `result` comes from a
  hand-written table in the script: `CLOSED_LEDGER` [R: `scripts/live_run/d17_supervisor.py:583-591`,
  e.g. `"one live host: 10.79.0.2; the remaining 253 addresses did not respond"`]. **This one is free
  prose**, written by a person to stand in for what a worker would have said -- not a closed
  vocabulary, though also not taken from tool output or a model at run time.

**So no current caller copies tool or model text into `result_summary` [R].** The field that could
carry it, `ActionOutcome.failure`, is not used by any of the four. That is practice, not a rule:
nothing in `complete_task` constrains the string (item 6 above).

**Where it surfaces: the Supervisor's trusted header [R].** `TaskRecord` carries it
[R: `agents/llm/supervisor_base.py:128` `result_summary: str | None = None`], `as_dict` exports it
[R: `:138` `"result_summary": self.result_summary,`], and `build_prompt` puts the whole task ledger
in the trusted half [R: `agents/llm/supervisor_base.py:445-449`, `"task_ledger": [t.as_dict() for t in state.tasks],`].

**Consequence [D].** `result_summary` is a writable text field that returns to a model inside a
region marked trustworthy, so what may be put in it is a decision, not an implementation detail.
That is correction C of 2026-10-31.

## 9. Creating an engagement per run: the existing patterns **[R]**

**Every existing harness makes a fresh engagement with a unique id.** The id is minted per run:

* `scripts/live_run/d40_three_role.py:477` `engagement_id = engagement_id or uid("ENG-D40-MAIN")`,
  `:671` `engagement_id = uid("ENG-D40-INJECT")`, with
  `:171-172` `def uid(prefix: str) -> str: / return f"{prefix}-{uuid.uuid4().hex[:10]}"`.
* `scripts/soak/world.py:63` `eid = f"ENG-SOAK-{stamp}-{index}"`, one per engagement in the run,
  from a timestamp stamp at `:45`.
* The same shape in `scripts/live_run/live_run.py:104`, `d13_worker.py:107`, `d15_lookalike.py:125`,
  `d17_supervisor.py:162`, `d45_ad_collection_e2e.py:285`, `verify_d12.py:275`,
  `d50_ad_collector_auth_probe.py:140`, and in `scripts/dp15_record_mode.py:737` /
  `scripts/dp15_stage1_run.py:419`.

**The steps and the roles, read and listed (not designed):**

1. A **baseline policy must already be published**, or creation is refused: `create_engagement`
   raises `NoBaselinePublished` rather than freezing an empty baseline [R:
   `control_plane/orchestrator/engagement.py:157-160` "**Created with none, it is refused**
   (:class:`NoBaselinePublished`) rather than frozen at an empty baseline where every action
   silently defaults to DENY."]. In the soak this is `ensure_test_baseline()`
   [R: `scripts/soak/world.py:47`].
2. **`create_engagement` on a `registry_admin_scope(engagement_id)` connection** -- the Engagement
   Manager's role, asserted in the function [R: `control_plane/orchestrator/engagement.py:127-129`
   "``conn`` must be a ``registry_admin_scope(engagement_id)`` connection --/ checked here", and
   `:162` `assert_registry_admin(conn)`]. Pattern in use:
   `scripts/live_run/d40_three_role.py:220-224` `with registry_admin_scope(engagement_id) as conn: / create_engagement(...)`.
3. **Scope objects are registered separately, on the same connection and the same role** -- not
   folded into creation [R: `control_plane/orchestrator/engagement.py:135-138` "No scope object is
   registered here, and none is required."; `control_plane/registry/scope_registry.py:100-103`
   "Register a scope object. Engagement Manager only (§5). / Requires a :func:`registry_admin_scope`
   connection."].
4. **An engagement policy layer** where the run needs one [R: `scripts/soak/world.py:65`
   `sup.publish_engagement_policy(eid)`].
5. **Enrolment, where a service must pick the engagement up** -- the scheduler's own list, written by
   the operator's script [R: `scripts/soak/world.py:68` `sup.enroll(eid, by="soak-harness")`]. The
   harness's own list is P-3 and is not this one.

**Not designed here [N]:** whether the harness creates its own engagement, and who runs step 1, are
not settled by this report. Correction B of 2026-10-31 says only that v0's engagement is the
harness's alone, with no other task creator; the operator steps above are what H6 will have to
write down.

## 10. `DockerSandbox()`'s default image **[R]**

```
tool_gateway/sandbox.py
149:DEFAULT_IMAGE = "cyberorch/nmap:local"
477:@dataclass
478:class DockerSandbox:
479:    """Runs one command in a network-confined container."""
481:    image: str = DEFAULT_IMAGE
```

So `DockerSandbox()` with no arguments runs `cyberorch/nmap:local`. The constant is a module-level
literal: it reads no environment variable and there is no settings file behind it, so "where it is
set" is that one line **[R]**. CI builds that tag as its own step ("Build the sandbox tool image"),
and the adapter-specific override path is the `image=adapter_image` argument the dispatch functions
pass [R: `control_plane/orchestrator/dispatch.py:844-845`].

**Consequence [D].** A harness process that reaches `propose_action`'s ALLOW path without passing a
sandbox gets a real container from this image, so the image must exist wherever the harness runs --
the fact the plan's H5 note of 2026-10-29 already records.

---

## What this report does not do

It authorizes nothing. It closes none of P-1 to P-8. It changes no code, no test, no script and no
other document; the only other file touched in the same commit is
`docs/D69_IMPLEMENTATION_PLAN.md`, by addition only. H2 does not start on the strength of this
report: P-2 needs the owner first.
