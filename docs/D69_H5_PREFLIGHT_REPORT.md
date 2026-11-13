# D69 H5 preflight report

[2026-11-14 review layer, under the owner's standing delegation; the owner may veto] **This is a preflight report. It states facts read from the repository and chooses nothing.** It authorizes no
implementation and changes no file other than itself and the appended lines of `docs/D69_IMPLEMENTATION_PLAN.md`. Facts are tagged [R] (read: the original text is quoted with its file and line numbers),
[D] (derived: reasoned from what was read, with the reasoning stated) or [N] (not found, not read, or not measurable without connecting to a database or a container). **Nothing here was run against a database,
a container, a model or nmap**; no service was started. Every item that would need a live database to settle is [N]. Line numbers refer to the files at commit `8e582da`.

Every quotation below was extracted from the file by a program that reads the line range (a function by its name, a block by its first and last line), not retyped; the number before each `|` is the line number in the file.
A shell command, where one is quoted, is followed by its complete output.

The question list is the owner's task of 2026-11-14, items A to H: A pause and kill state; B `NetworkInUse`; C the 5.120 state; D the `scheduler_enrollment` template; E task functions and vocabulary; F how the scheduler's
signal handling and exit codes are tested; G the idempotency key; H advisory locks. Each section ends with one line, **Effect on H5**, which states which piece or proposal question the facts touch and does not choose an option.

The file name was free: `ls docs/D69_H5_PREFLIGHT_REPORT.md` reported no such file before this one was written, and `git log --all -- docs/D69_H5_PREFLIGHT_REPORT.md` and `git grep D69_H5_PREFLIGHT` returned nothing.

## A. Pause and kill state

### A.1 How the scheduler decides `engagement_paused` and `engagement_killed` [R]

The decision lives in `control_plane/scheduler/decide.py`: `Observation.servable` (line 60) and `Observation.defer_reason` (line 64), fed by `observe(engagement_id: str) -> Observation` (line 113), `servable_now(engagement_id: str) -> bool` (line 202) and `observe_status(engagement_id: str) -> str | None` (line 207).

`control_plane/scheduler/decide.py:59-69`

```text
   59 |     @property
   60 |     def servable(self) -> bool:
   61 |         return self.exists and self.status == ACTIVE and not self.kill_switch_engaged
   62 | 
   63 |     @property
   64 |     def defer_reason(self) -> str:
   65 |         if self.kill_switch_engaged:
   66 |             return "engagement_killed"
   67 |         if self.status == PAUSED:
   68 |             return "engagement_paused"
   69 |         return "engagement_not_active"
```

`control_plane/scheduler/decide.py:113-121`

```text
  113 | def observe(engagement_id: str) -> Observation:
  114 |     """Everything the decision needs about one engagement, in one read-only transaction."""
  115 |     with scheduler_reader_scope(engagement_id) as conn:
  116 |         engagement = conn.execute(
  117 |             text("SELECT status, kill_switch_engaged FROM engagements "
  118 |                  "WHERE engagement_id = :e"), {"e": engagement_id},
  119 |         ).one_or_none()
  120 |         if engagement is None:
  121 |             return Observation(engagement_id=engagement_id, exists=False)
```

`control_plane/scheduler/decide.py:202-216`

```text
  202 | def servable_now(engagement_id: str) -> bool:
  203 |     """Re-read immediately before a dispatch, so 'paused' is caught as a deferral, not a refusal."""
  204 |     return observe_status(engagement_id) == ACTIVE
  205 | 
  206 | 
  207 | def observe_status(engagement_id: str) -> str | None:
  208 |     """'active' only if the engagement exists, is active and its kill switch is not engaged."""
  209 |     with scheduler_reader_scope(engagement_id) as conn:
  210 |         row: Any = conn.execute(
  211 |             text("SELECT status, kill_switch_engaged FROM engagements WHERE engagement_id = :e"),
  212 |             {"e": engagement_id},
  213 |         ).one_or_none()
  214 |     if row is None or row[1]:
  215 |         return None if row is None else "killed"
  216 |     return row[0]
```

The connection role is `scheduler_reader`, through `scheduler_reader_scope(engagement_id)`; the engagement is bound with `set_config('cyberorch.engagement_id', ...)` in `_scoped`:

`control_plane/state/db.py:492-502`

```text
  492 | @contextmanager
  493 | def scheduler_reader_scope(engagement_id: str) -> Iterator[Connection]:
  494 |     """A read transaction bound to one engagement, as ``scheduler_reader`` (D62).
  495 | 
  496 |     The scheduling decision's only window onto an engagement: the columns and the view the role was
  497 |     granted, filtered by the same ``engagement_isolation`` policy as every other role. It cannot
  498 |     write, and it holds no grant on the content tables, so code that is handed this connection
  499 |     cannot read what it must not decide on.
  500 |     """
  501 |     with _scoped(get_scheduler_reader_engine(), engagement_id) as conn:
  502 |         yield conn
```

`control_plane/state/db.py:343-352`

```text
  343 | @contextmanager
  344 | def _scoped(engine: Engine, engagement_id: str) -> Iterator[Connection]:
  345 |     if not engagement_id:
  346 |         raise ValueError("engagement_id is required: RLS fails closed without it")
  347 |     with engine.begin() as conn:
  348 |         conn.execute(
  349 |             text("SELECT set_config('cyberorch.engagement_id', :eid, true)"),
  350 |             {"eid": engagement_id},
  351 |         )
  352 |         yield conn
```

The scheduler re-reads immediately before each dispatch:

`control_plane/scheduler/service.py:173-178`

```text
  173 |         for candidate in plan.candidates:
  174 |             self._assert_lock()
  175 |             # Re-read the engagement right before acting, so a pause or kill that landed since the
  176 |             # observation is a deferral on the next tick, not a refusal that closes the proposal.
  177 |             if not decide.servable_now(engagement_id):
  178 |                 break
```

[D] Two reads of the same two columns (`status`, `kill_switch_engaged`), once per observation and once before each candidate; the codes returned are the three of `DEFER_REASONS`; a killed engagement reports `engagement_killed` even when its `status` is also `killed`, because the kill switch is tested first.

### A.2 What `pause_engagement`, `resume_engagement` and `engage_kill_switch` write [R]

`control_plane/orchestrator/engagement.py:59-65`

```text
   59 | ACTIVE = "active"
   60 | PAUSED = "paused"
   61 | COMPLETED = "completed"
   62 | KILLED = "killed"
   63 | 
   64 | PAUSE_REASON = "engagement_paused"
   65 | COMPLETION_REASON = "engagement_completed"
```

`control_plane/orchestrator/engagement.py:222-241`

```text
  222 | def pause_engagement(
  223 |     conn: Connection, *, engagement_id: str, actor: str, reason: str
  224 | ) -> EngagementState:
  225 |     """Stop new work and revoke what is running.
  226 | 
  227 |     Capabilities are revoked rather than left to lapse. A paused engagement
  228 |     whose in-flight scans continue until their leases expire is not paused; it
  229 |     is paused-ish for up to one lease.
  230 |     """
  231 |     _set_status(conn, engagement_id, PAUSED)
  232 |     revoked = revoke_all_for_engagement(
  233 |         conn, engagement_id=engagement_id, reason=PAUSE_REASON, actor=actor,
  234 |     )
  235 |     record_audit(
  236 |         engagement_id=engagement_id, actor=actor, event_type="engagement.paused",
  237 |         subject_type="engagement", subject_id=engagement_id, decision="DENY",
  238 |         reasons=(reason,),
  239 |         payload={"revoked_capabilities": revoked, "capability_count": len(revoked)},
  240 |     )
  241 |     return EngagementState(engagement_id, PAUSED, False, tuple(revoked))
```

`control_plane/orchestrator/engagement.py:244-276`

```text
  244 | def resume_engagement(
  245 |     conn: Connection, *, engagement_id: str, actor: str, reason: str
  246 | ) -> EngagementState:
  247 |     """Return an engagement to active.
  248 | 
  249 |     Resuming does not restore the capabilities the pause revoked, and must not:
  250 |     I9 makes revocation terminal, so work continues by obtaining new
  251 |     authorization rather than by reviving old. Refused outright once the kill
  252 |     switch has been engaged — that is not a pause.
  253 |     """
  254 |     current = get_engagement(conn, engagement_id)
  255 |     if current is None:
  256 |         raise ValueError(f"unknown engagement {engagement_id!r}")
  257 |     if current.kill_switch_engaged:
  258 |         record_audit(
  259 |             engagement_id=engagement_id, actor=actor,
  260 |             event_type="engagement.resume_refused", subject_type="engagement",
  261 |             subject_id=engagement_id, decision="DENY", reasons=(KILL_SWITCH,),
  262 |             payload={"reason": reason},
  263 |         )
  264 |         raise ValueError(
  265 |             "cannot resume an engagement whose kill switch is engaged; "
  266 |             "the kill switch is not a pause"
  267 |         )
  268 | 
  269 |     _set_status(conn, engagement_id, ACTIVE)
  270 |     record_audit(
  271 |         engagement_id=engagement_id, actor=actor, event_type="engagement.resumed",
  272 |         subject_type="engagement", subject_id=engagement_id, decision="ALLOW",
  273 |         reasons=(reason,),
  274 |         payload={"note": "capabilities revoked by the pause are not restored (I9)"},
  275 |     )
  276 |     return EngagementState(engagement_id, ACTIVE, False)
```

`control_plane/orchestrator/engagement.py:279-310`

```text
  279 | def engage_kill_switch(
  280 |     conn: Connection, *, engagement_id: str, actor: str, reason: str
  281 | ) -> EngagementState:
  282 |     """Stop everything, now, and do not allow it to be undone (§1.2e).
  283 | 
  284 |     Deliberately one-way. A kill switch that can be flicked back is a pause
  285 |     with an alarming name, and the situation it exists for — something is
  286 |     wrong and nobody yet knows how wrong — is exactly the situation in which
  287 |     restarting should require a deliberate, separate act rather than the same
  288 |     operator toggling the same flag back.
  289 |     """
  290 |     conn.execute(
  291 |         text("UPDATE engagements SET kill_switch_engaged = TRUE, status = :killed, "
  292 |              "updated_at = now() WHERE engagement_id = :eid"),
  293 |         {"eid": engagement_id, "killed": KILLED},
  294 |     )
  295 |     revoked = revoke_all_for_engagement(
  296 |         conn, engagement_id=engagement_id, reason=KILL_SWITCH, actor=actor,
  297 |     )
  298 |     record_audit(
  299 |         engagement_id=engagement_id, actor=actor,
  300 |         event_type="engagement.kill_switch_engaged", subject_type="engagement",
  301 |         subject_id=engagement_id, decision="DENY", reasons=(KILL_SWITCH, reason),
  302 |         payload={
  303 |             "revoked_capabilities": revoked,
  304 |             "capability_count": len(revoked),
  305 |             # §1.2(e): with a container sandbox, revocation plus namespace
  306 |             # teardown stops in-flight work rather than waiting for it.
  307 |             "note": "irreversible; in-flight capabilities revoked immediately",
  308 |         },
  309 |     )
  310 |     return EngagementState(engagement_id, KILLED, True, tuple(revoked))
```

`control_plane/orchestrator/engagement.py:413-418`

```text
  413 | def _set_status(conn: Connection, engagement_id: str, status: str) -> None:
  414 |     conn.execute(
  415 |         text("UPDATE engagements SET status = :s, updated_at = now() "
  416 |              "WHERE engagement_id = :eid"),
  417 |         {"eid": engagement_id, "s": status},
  418 |     )
```

`control_plane/capability/broker.py:675-701`

```text
  675 | def revoke_all_for_engagement(
  676 |     conn: Connection, *, engagement_id: str, reason: str, actor: str
  677 | ) -> list[str]:
  678 |     """Revoke every live capability in an engagement.
  679 | 
  680 |     §1.3.2 asks for a revocation cascade: when a credential is pulled or the
  681 |     kill switch trips, capabilities already issued must stop, not merely fail
  682 |     their next heartbeat. Renewal is the backstop; this is the immediate path.
  683 |     """
  684 |     rows = conn.execute(
  685 |         text("""
  686 |             UPDATE capabilities
  687 |             SET revoked = TRUE, revoked_reason = :reason, revoked_at = now()
  688 |             WHERE engagement_id = :eid AND revoked IS FALSE
  689 |             RETURNING capability_id
  690 |         """),
  691 |         {"eid": engagement_id, "reason": reason},
  692 |     ).scalars().all()
  693 | 
  694 |     for capability_id in rows:
  695 |         record_audit(
  696 |             engagement_id=engagement_id, actor=actor,
  697 |             event_type="capability.revoked", subject_type="capability",
  698 |             subject_id=capability_id, decision="DENY", reasons=(reason,),
  699 |             payload={"cascade": True},
  700 |         )
  701 |     return list(rows)
```

The `engagements` table and its status vocabulary:

`db/migrations/versions/0001_core_schema.py:44-53`

```text
   44 | CREATE TABLE engagements (
   45 |     engagement_id            TEXT PRIMARY KEY,
   46 |     customer_id              TEXT NOT NULL,
   47 |     status                   TEXT NOT NULL DEFAULT 'active'
   48 |                              CHECK (status IN ('active','paused','completed','killed')),
   49 |     kill_switch_engaged      BOOLEAN NOT NULL DEFAULT FALSE,
   50 |     policy_snapshot_version  INTEGER NOT NULL,
   51 |     created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
   52 |     updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
   53 | );
```

[D] Tables and columns written: `engagements.status` and `updated_at` (pause, resume); `engagements.kill_switch_engaged` set TRUE, `status` set to `'killed'` and `updated_at` (kill switch, one-way: `resume_engagement` refuses once it is set); `capabilities.revoked`, `revoked_reason`, `revoked_at` for every live capability of the engagement (pause and kill); `audit_log` rows through `record_audit` (`engagement.paused`, `engagement.resumed`, `engagement.resume_refused`, `engagement.kill_switch_engaged`, and one `capability.revoked` per capability). No function of the three writes `tasks`, `action_proposals` or `scheduler_*` tables.

Callers outside the definitions and the tests:

`$ git grep -n -E 'pause_engagement\(|engage_kill_switch\(|resume_engagement\(' -- scripts control_plane harness agents | grep -v 'def '`

```text
(no output)
```

[R] The command lists no caller: in `control_plane/`, `scripts/`, `harness/` and `agents/` the three functions are defined and not called. [N] Which operator tool, if any, calls them in a deployment is not in the repository (their callers are tests).

### A.3 Whether `cyberorch_app` can read the columns [R] [D] [N]

`db/migrations/versions/0001_core_schema.py:18-32`

```text
   18 | ENGAGEMENT_SCOPED = [
   19 |     "engagements",
   20 |     "scope_registry",
   21 |     "metadata_registry",
   22 |     "tasks",
   23 |     "action_proposals",
   24 |     "credentials",
   25 |     "capabilities",
   26 |     "approvals",
   27 |     "tool_runs",
   28 |     "evidence",
   29 |     "findings",
   30 |     "provenance_edges",
   31 |     "audit_log",
   32 | ]
```

`db/migrations/versions/0001_core_schema.py:410-417`

```text
  410 |     op.execute("GRANT USAGE ON SCHEMA public TO cyberorch_app;")
  411 |     op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
  412 |                "TO cyberorch_app;")
  413 |     op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cyberorch_app;")
  414 | 
  415 |     for table in APPEND_ONLY:
  416 |         op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM cyberorch_app;")
  417 |         op.execute(f"GRANT INSERT, SELECT ON {table} TO cyberorch_app;")
```

`db/migrations/versions/0001_core_schema.py:382-394`

```text
  382 |     for table in ENGAGEMENT_SCOPED:
  383 |         key = "engagement_id"
  384 |         op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
  385 |         # Without FORCE, the table owner bypasses every policy below and the
  386 |         # tests would still pass while production leaked. §8.6 exists because of
  387 |         # exactly this half-done case.
  388 |         op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
  389 |         op.execute(f"""
  390 | CREATE POLICY engagement_isolation ON {table}
  391 |     FOR ALL TO PUBLIC
  392 |     USING ({key} = cyberorch_current_engagement())
  393 |     WITH CHECK ({key} = cyberorch_current_engagement());
  394 | """)
```

`db/migrations/versions/0013_narrow_policy_and_engagement_grants.py:19-23`

```text
   19 | * ``engagements`` -- the four lifecycle operations (pause, resume, kill, complete) write
   20 |   ``status``, ``kill_switch_engaged`` and ``updated_at`` and nothing else. So: SELECT stays,
   21 |   UPDATE narrows to those three columns. ``customer_id`` (which decides which customer-scoped
   22 |   policy applies, 5.35) and ``policy_snapshot_version`` (the pointer 5.20's freeze would read)
   23 |   are no longer writable by the runtime role.
```

`db/migrations/versions/0013_narrow_policy_and_engagement_grants.py:43-48`

```text
   43 |     op.execute("REVOKE UPDATE, DELETE ON policy_layers FROM cyberorch_app;")
   44 |     op.execute("GRANT UPDATE (active) ON policy_layers TO cyberorch_app;")
   45 |     op.execute("REVOKE UPDATE ON engagements FROM cyberorch_app;")
   46 |     op.execute(
   47 |         "GRANT UPDATE (status, kill_switch_engaged, updated_at) "
   48 |         "ON engagements TO cyberorch_app;"
```

`db/migrations/versions/0019_scheduler.py:169-170`

```text
  169 |     op.execute("GRANT SELECT (engagement_id, status, kill_switch_engaged) ON engagements "
  170 |                "TO scheduler_reader;")
```

[R] Migration 0001 grants SELECT, INSERT, UPDATE and DELETE on every table that existed (`engagements` among them) to `cyberorch_app`; 0013 narrows only UPDATE on `engagements` (its docstring: "SELECT stays"); `engagements` is under `FORCE ROW LEVEL SECURITY` with the `engagement_isolation` policy, so a connection sees the row only with `cyberorch.engagement_id` set to that engagement (`engagement_scope`, `control_plane/state/db.py:356`). [R] `get_engagement(conn, engagement_id)` (`control_plane/orchestrator/engagement.py:108`) is the existing read of both columns on any connection and returns `EngagementState`, whose `accepts_work` is `status == ACTIVE and not kill_switch_engaged`:

`control_plane/orchestrator/engagement.py:108-119`

```text
  108 | def get_engagement(conn: Connection, engagement_id: str) -> EngagementState | None:
  109 |     row = conn.execute(
  110 |         text("SELECT engagement_id, status, kill_switch_engaged FROM engagements "
  111 |              "WHERE engagement_id = :eid"),
  112 |         {"eid": engagement_id},
  113 |     ).mappings().one_or_none()
  114 |     if row is None:
  115 |         return None
  116 |     return EngagementState(
  117 |         engagement_id=row["engagement_id"], status=row["status"],
  118 |         kill_switch_engaged=row["kill_switch_engaged"],
  119 |     )
```

`control_plane/orchestrator/engagement.py:96-105`

```text
   96 | @dataclass(frozen=True)
   97 | class EngagementState:
   98 |     engagement_id: str
   99 |     status: str
  100 |     kill_switch_engaged: bool
  101 |     revoked_capabilities: tuple[str, ...] = ()
  102 | 
  103 |     @property
  104 |     def accepts_work(self) -> bool:
  105 |         return self.status == ACTIVE and not self.kill_switch_engaged
```

[D] The pipeline itself performs this same `SELECT status, kill_switch_engaged FROM engagements` on the `cyberorch_app` connection (A.4), so the read works for that role. [N] The effective privileges in any running database were not queried (no connection was made); the statement above is from the migrations.

### A.4 Where `propose_action` checks the state [R]

A search for any reference to engagement state in the pipeline's files:

`$ git grep -n -E 'kill_switch|accepts_work|KILL_SWITCH|engagement_not_active|get_engagement|ENGAGEMENT_NOT|status != |\"active\"' -- control_plane/api control_plane/capability control_plane/orchestrator/dispatch.py control_plane/orchestrator/stages.py`

```text
control_plane/capability/broker.py:90:ENGAGEMENT_NOT_ACTIVE = "engagement_not_active"
control_plane/capability/broker.py:91:KILL_SWITCH = "kill_switch_engaged"
control_plane/capability/broker.py:300:    if not row["active"]:
control_plane/capability/broker.py:334:        text("SELECT status, kill_switch_engaged FROM engagements "
control_plane/capability/broker.py:342:        reasons.append(ENGAGEMENT_NOT_ACTIVE)
control_plane/capability/broker.py:344:        if engagement["kill_switch_engaged"]:
control_plane/capability/broker.py:345:            reasons.append(KILL_SWITCH)
control_plane/capability/broker.py:346:        if engagement["status"] != "active":
control_plane/capability/broker.py:347:            reasons.append(ENGAGEMENT_NOT_ACTIVE)
control_plane/orchestrator/dispatch.py:388:        text("SELECT status, kill_switch_engaged FROM engagements WHERE engagement_id = :e"),
control_plane/orchestrator/dispatch.py:391:    if engagement is None or engagement[1] or engagement[0] != "active":
control_plane/orchestrator/dispatch.py:392:        return None, DispatchOutcome(False, None, QUEUED, reason="engagement_not_active")
```

[R] The pipeline file `function_api.py` has no match: the stage-0 insert, `_decide` and `_drive` never read the engagement's status or kill switch. The two places that do are the broker's precondition check and the dispatch stage's fresh read.

`control_plane/capability/broker.py:333-347`

```text
  333 |     engagement = conn.execute(
  334 |         text("SELECT status, kill_switch_engaged FROM engagements "
  335 |              "WHERE engagement_id = :eid"),
  336 |         {"eid": engagement_id},
  337 |     ).mappings().one_or_none()
  338 | 
  339 |     if engagement is None:
  340 |         # RLS also lands here for another engagement's id: it does not exist
  341 |         # from in here, and that is the correct answer either way.
  342 |         reasons.append(ENGAGEMENT_NOT_ACTIVE)
  343 |     else:
  344 |         if engagement["kill_switch_engaged"]:
  345 |             reasons.append(KILL_SWITCH)
  346 |         if engagement["status"] != "active":
  347 |             reasons.append(ENGAGEMENT_NOT_ACTIVE)
```

`control_plane/api/function_api.py:1006-1009`

```text
 1006 |             # check_preconditions runs here, in this stage and not at the start of the
 1007 |             # pipeline: the engagement's status, the kill switch, the credential, the scope
 1008 |             # object and the approval are asked *now*, however long ago the decision was made.
 1009 |             issued = issue_capability(
```

`control_plane/api/function_api.py:1031-1046`

```text
 1031 |             if not issued.issued:
 1032 |                 stages.take(
 1033 |                     conn, proposal_id, expected=stages.CAPABILITY_ISSUED, new=stages.CLOSED,
 1034 |                     detail="capability_refused:" + ",".join(issued.reasons),
 1035 |                 )
 1036 |     except stages.StageConflict:
 1037 |         return _RELOAD
 1038 |     if not issued.issued:
 1039 |         # The policy said yes and the broker said no. Both are recorded; the
 1040 |         # disagreement is the interesting part and must not be flattened.
 1041 |         _record_provenance(run, proposal_id)
 1042 |         return ActionOutcome(
 1043 |             decision=DENY, deny_reasons=tuple(issued.reasons),
 1044 |             failure="capability_refused",
 1045 |             **{k: v for k, v in _common(run, proposal_id).items() if k != "deny_reasons"},
 1046 |         )
```

`control_plane/orchestrator/dispatch.py:375-393`

```text
  375 | def _fresh_capability(conn: Connection, engagement_id: str, capability):
  376 |     """The capability as it is *now*, or a refusal (D60).
  377 | 
  378 |     The one the caller holds was read in an earlier stage, and a stage that committed is exactly
  379 |     what lets a kill switch, a pause or a revocation reach it: the capability row is visible to
  380 |     ``revoke_all_for_engagement`` the moment its stage commits. So the dispatch stage starts by
  381 |     asking again -- of the capability, and of the engagement it belongs to -- rather than trusting
  382 |     what it was handed. Returns ``(capability, None)`` or ``(None, DispatchOutcome)``.
  383 |     """
  384 |     fresh = get_capability(conn, capability.capability_id)
  385 |     if fresh is None or fresh.revoked or not fresh.is_live():
  386 |         return None, DispatchOutcome(False, None, QUEUED, reason="capability_not_live")
  387 |     engagement = conn.execute(
  388 |         text("SELECT status, kill_switch_engaged FROM engagements WHERE engagement_id = :e"),
  389 |         {"e": engagement_id},
  390 |     ).one_or_none()
  391 |     if engagement is None or engagement[1] or engagement[0] != "active":
  392 |         return None, DispatchOutcome(False, None, QUEUED, reason="engagement_not_active")
  393 |     return fresh, None
```

`control_plane/orchestrator/dispatch.py:396-404`

```text
  396 | def _close_early(conn: Connection, proposal_id: str, outcome: DispatchOutcome) -> None:
  397 |     """A dispatch that ended before a run row existed ends the pipeline, with its reason."""
  398 |     detail = outcome.reason or "closed"
  399 |     if outcome.reason == "dedup_hit" and outcome.run_id:
  400 |         detail = f"dedup_hit:{outcome.run_id}"
  401 |     if outcome.reason == "not_claimable":
  402 |         return  # someone else owns this dispatch; its stage is theirs to move
  403 |     stages.advance(conn, proposal_id, expected=stages.BEFORE_DISPATCH,
  404 |                    new=stages.CLOSED, detail=detail)
```

Call sites of `_fresh_capability`, with the function that contains each:

* `control_plane/orchestrator/dispatch.py:375` in `_fresh_capability`: `def _fresh_capability(conn: Connection, engagement_id: str, capability):`
* `control_plane/orchestrator/dispatch.py:631` in `_scan_start`: `capability, refusal = _fresh_capability(conn, engagement_id, capability)`
* `control_plane/orchestrator/dispatch.py:940` in `_collection_start`: `capability, refusal = _fresh_capability(conn, engagement_id, capability)`
* `control_plane/orchestrator/dispatch.py:1320` in `_code_scan_start`: `capability, refusal = _fresh_capability(conn, engagement_id, capability)`

[D] An engagement paused or killed after the proposal row is committed is seen (1) at the issue stage by `check_preconditions`: the proposal moves to `closed` with detail `capability_refused:<reasons>` and `propose_action` returns an `ActionOutcome` with `decision` DENY and `failure="capability_refused"` (returned, not raised), the reasons including `kill_switch_engaged` or `engagement_not_active`; (2) at the dispatch stage by `_fresh_capability`, which returns `DispatchOutcome(False, None, QUEUED, reason="engagement_not_active")`. Between the proposal row and the issue stage nothing reads the state. [N] How `_close_early` records the second refusal in `action_proposals` and the audit trail was read above; its effect on a real database was not observed.

**Effect on H5.** The harness has no code that reads engagement state today; the existing reads are the scheduler's (`scheduler_reader`, `decide.py`), `get_engagement` on any connection, and the pipeline's two checks, so the loop's own pause/kill read (H5-5, H5c) has a function to call and its choice of connection role is open; the stages before the issue stage do not read the state, which bears on the SIGTERM and ALLOW question (proposal 3.4) and on the loop's claim and complete on those paths.

## B. `NetworkInUse`

### B.1 Definition [R]

`tool_gateway/sandbox.py:214-219`

```text
  214 | class SandboxUnavailable(RuntimeError):
  215 |     """Docker is not usable, or the tool image is missing.
  216 | 
  217 |     Raised rather than degraded into a skip or a simulated run. A sandbox that
  218 |     silently does not sandbox is worse than one that refuses to start.
  219 |     """
```

`tool_gateway/sandbox.py:222-236`

```text
  222 | class NotStarted(SandboxUnavailable):
  223 |     """The sandbox failed *before any container of this run was started* (D58-7).
  224 | 
  225 |     A subclass so every existing ``except SandboxUnavailable`` still catches it, and a separate
  226 |     type because callers must be able to tell it apart: nothing of the run executed, so the outcome
  227 |     is **known** (failed, not run) and the action can be tried again -- unlike a failure at or after
  228 |     ``start()``, where the tool may or may not have run (``UNKNOWN_OUTCOME``, §8.8). A plain
  229 |     :class:`SandboxUnavailable` makes no such claim and is still recorded as unknown.
  230 | 
  231 |     Raised only at points where that is provable: the daemon cannot be reached, the tool image is
  232 |     absent, the confined network cannot be had, or the container could not be *created*. Never from
  233 |     ``start()`` onwards. ``reason`` is a stable code; the message never names another engagement.
  234 |     """
  235 | 
  236 |     reason = "sandbox_not_started"
```

`tool_gateway/sandbox.py:265-272`

```text
  265 | class NetworkNotAvailable(NotStarted):
  266 |     """The sandbox refused *before any container existed* because of the network.
  267 | 
  268 |     Nothing started, so unlike a failure at or after ``start()`` the outcome is known and the
  269 |     action can be retried later.
  270 |     """
  271 | 
  272 |     reason = "network_unavailable"
```

`tool_gateway/sandbox.py:275-278`

```text
  275 | class NetworkInUse(NetworkNotAvailable):
  276 |     """Another engagement has a live container on a network this one would join (D59)."""
  277 | 
  278 |     reason = "network_in_use_by_another_engagement"
```

`tool_gateway/sandbox.py:281-284`

```text
  281 | class NetworkRangeConflict(NetworkNotAvailable):
  282 |     """Docker refused the network because its range overlaps an existing one."""
  283 | 
  284 |     reason = "network_range_conflicts_with_another_network"
```

### B.2 Where it is raised [R]

Every occurrence of the name in Python files in the whole repository (`git grep` over the tracked tree, including `tool_gateway/`):

`$ git grep -n 'NetworkInUse' -- '*.py'`

```text
tests/test_network_isolation.py:53:    NetworkInUse,
tests/test_network_isolation.py:186:        with pytest.raises(NetworkInUse) as refused:
tests/test_network_isolation.py:207:        with pytest.raises(NetworkInUse):
tests/test_network_isolation.py:210:        with pytest.raises(NetworkInUse):
tests/test_network_isolation.py:239:        except NetworkInUse as exc:
tests/test_network_isolation.py:245:    refused = [o for o, v in outcomes.items() if isinstance(v, NetworkInUse)]
tests/test_network_isolation.py:342:    with pytest.raises(NetworkInUse):
tests/test_network_isolation.py:347:    with pytest.raises(NetworkInUse):
tests/test_network_isolation.py:478:    NetworkInUse("the network for this allowlist is in use by another engagement; "
tool_gateway/sandbox.py:58:the newcomer with :class:`NetworkInUse`, before it starts. Containers without
tool_gateway/sandbox.py:275:class NetworkInUse(NetworkNotAvailable):
tool_gateway/sandbox.py:617:                raise NetworkInUse(
tool_gateway/sandbox.py:662:        :class:`NetworkInUse` if another engagement has a live container on
tool_gateway/sandbox.py:945:        network this run would join, :class:`NetworkInUse` is raised before this
```

`tool_gateway/sandbox.py:580-620`

```text
  580 |     def _assert_exclusive(self, container, network_names: Sequence[str], owner: str) -> None:
  581 |         """Refuse to start ``container`` beside another engagement's (D59).
  582 | 
  583 |         Called after the container is created and attached, before it is started,
  584 |         so nothing of this run has executed when it is refused. Two callers can
  585 |         reach this at the same moment, so it must not be "look, then go": each
  586 |         sees the other's created container. The rule that decides it is creation
  587 |         order -- a container yields only to a live container of another owner that
  588 |         is running, or that was created before it. The later of two simultaneous
  589 |         creators therefore always sees the earlier one and refuses, while the
  590 |         earlier ignores the later (which is about to refuse) and proceeds; exactly
  591 |         one wins and the loser has not started.
  592 |         """
  593 |         client = self.client()
  594 |         mine = _creation_key(container)
  595 |         for network_name in network_names:
  596 |             for other in client.containers.list(
  597 |                 all=True, filters={"label": OWNER_LABEL, "network": network_name},
  598 |                 ignore_removed=True,
  599 |             ):
  600 |                 if other.id == container.id:
  601 |                     continue
  602 |                 try:
  603 |                     other.reload()
  604 |                 except NotFound:         # removed since it was listed: it is not on the network
  605 |                     continue
  606 |                 other_owner = (other.labels or {}).get(OWNER_LABEL, NO_OWNER)
  607 |                 if other_owner == owner or other.status not in _LIVE_STATES:
  608 |                     continue
  609 |                 if other.status == "created" and _creation_key(other) > mine:
  610 |                     continue
  611 |                 # The operator needs to know who; the message (which reaches the
  612 |                 # refused engagement's audit trail) must not say.
  613 |                 logger.warning(
  614 |                     "network %s refused for owner %r: container %s of owner %r is %s on it",
  615 |                     network_name, owner, other.short_id, other_owner, other.status,
  616 |                 )
  617 |                 raise NetworkInUse(
  618 |                     "the network for this allowlist is in use by another engagement; "
  619 |                     "nothing was started"
  620 |                 )
```

`_assert_exclusive` is called at `tool_gateway/sandbox.py:742` inside `start_egress_proxy`:

`tool_gateway/sandbox.py:739-745`

```text
  739 |         )
  740 |         try:
  741 |             target_network.connect(container)
  742 |             self._assert_exclusive(
  743 |                 container, [tool_network.name, target_network.name],
  744 |                 engagement_id or NO_OWNER,
  745 |             )
```

`_assert_exclusive` is called at `tool_gateway/sandbox.py:1061` inside `run`:

`tool_gateway/sandbox.py:1058-1064`

```text
 1058 |                 )
 1059 |             if network is not None:
 1060 |                 # Before start: a refused run has executed nothing.
 1061 |                 self._assert_exclusive(container, [network.name], owner)
 1062 |             # Attached before start, not after: a container that runs to
 1063 |             # completion between start() and attach() leaves the write with
 1064 |             # nowhere to go, and the tool waits on a stdin that never closes
```

`tool_gateway/sandbox.py:658-664`

```text
  658 |         ``engagement_id`` names who the proxy works for (D59). The proxy
  659 |         carries one capability's grant and listens on the tool-side network, so
  660 |         any container that can reach it can spend that grant; it is therefore
  661 |         held to the same rule as a tool run -- refused with
  662 |         :class:`NetworkInUse` if another engagement has a live container on
  663 |         either network -- and, as a tenant of the tool-side network itself,
  664 |         keeps other engagements' tool containers off it for as long as it lives.
```

`tool_gateway/sandbox.py:943-948`

```text
  943 |         ``engagement_id`` is who the run is for (D59), recorded on the container
  944 |         as ``OWNER_LABEL``. If a container of a *different* owner is live on the
  945 |         network this run would join, :class:`NetworkInUse` is raised before this
  946 |         run's container starts. Omitting it is allowed (probes, lab scripts) and
  947 |         makes the run an owner of its own -- distinct from every engagement, so
  948 |         it is kept apart from them too; production dispatch always passes it.
```

Callers of `start_egress_proxy` (the other place the exception can reach a caller directly):

`$ git grep -n 'start_egress_proxy' -- control_plane agents harness tool_gateway scripts`

```text
scripts/drill_reconciler_docker.py:328:    box.start_egress_proxy(
scripts/live_run/d40_three_role.py:825:        proxy_endpoint = nmap_sandbox.start_egress_proxy(
tool_gateway/sandbox.py:188:    :meth:`DockerSandbox.start_egress_proxy` runs the proxy as the host uid
tool_gateway/sandbox.py:631:    def start_egress_proxy(
```

### B.3 How `propose_action` and dispatch handle it [R]

`control_plane/orchestrator/dispatch.py:289-295`

```text
  289 | #: The sandbox refused before any container existed because the network is held
  290 | #: by another engagement, or its range collides with another network (D59).
  291 | #: Distinct from UNKNOWN_OUTCOME on purpose: nothing started, so the outcome is
  292 | #: *known* and the same proposal can be tried again once the network is free.
  293 | #: Recording it as unknown (what every ``SandboxUnavailable`` gets) would park a
  294 | #: proposal for a human over something the system can simply retry.
  295 | NETWORK_UNAVAILABLE = "network_unavailable"
```

`control_plane/orchestrator/dispatch.py:316-324`

```text
  316 | REFUSAL_CODES = (
  317 |     "sandbox_not_started", "docker_unreachable", "tool_image_missing", "container_start_refused",
  318 |     "network_unavailable", "network_in_use_by_another_engagement",
  319 |     "network_range_conflicts_with_another_network", "tool_command_not_executable",
  320 |     "deadline_helper_unavailable", "deadline_helper_unsupported_architecture",
  321 |     "deadline_helper_unpinned", "deadline_helper_unreadable", "deadline_helper_missing",
  322 |     "deadline_helper_hash_mismatch", "deadline_helper_not_executable",
  323 |     "deadline_helper_path_in_use",
  324 | )
```

`control_plane/orchestrator/dispatch.py:334-357`

```text
  334 | def _refused_before_start(
  335 |     conn: Connection, *, engagement_id: str, actor: str, run_id: str,
  336 |     proposal_id: str, exc: NotStarted,
  337 | ) -> DispatchOutcome:
  338 |     """Record a run the sandbox declined to start, before any container existed (D59, D58-7).
  339 | 
  340 |     The audit payload carries the sandbox's message and the stable code, which
  341 |     by construction name no other engagement; who holds the network is in the
  342 |     operator log, not in this engagement's trail.
  343 |     """
  344 |     # The code is state, written by the statement that fails the run, in this transaction (0025).
  345 |     _finish_run(conn, run_id, FAILED, exit_code=None, refusal_code=refusal_code_of(exc))
  346 |     _set_state(conn, proposal_id, FAILED)
  347 |     record_audit(
  348 |         engagement_id=engagement_id, actor=actor,
  349 |         event_type="tool_run.refused", subject_type="tool_run", subject_id=run_id,
  350 |         decision=DENY_DECISION,
  351 |         reasons=(NETWORK_UNAVAILABLE if isinstance(exc, NetworkNotAvailable)
  352 |                  else SANDBOX_NOT_STARTED, exc.reason),
  353 |         payload={"error": str(exc)},
  354 |     )
  355 |     # run_id is not returned: nothing executed, so propose_action must not draw
  356 |     # an "executed" provenance edge for it.
  357 |     return DispatchOutcome(False, None, FAILED, reason=exc.reason)
```

`control_plane/orchestrator/dispatch.py:431-456`

```text
  431 | def _execute(
  432 |     sandbox_run, *, engagement_id: str, proposal_id: str, actor: str, run_id: str,
  433 | ) -> SandboxResult | DispatchOutcome:
  434 |     """Stage 3b: the container. No database connection is held while it runs.
  435 | 
  436 |     A refusal the sandbox made *before* a container existed, and a failure of the sandbox itself,
  437 |     are each recorded here in their own short transaction and returned as the outcome. Anything
  438 |     else propagates with the stage still ``dispatching`` -- which is what the reconciler reads.
  439 |     """
  440 |     try:
  441 |         return sandbox_run()
  442 |     except NotStarted as exc:
  443 |         try:
  444 |             with engagement_scope(engagement_id) as conn:
  445 |                 # First statement: win the stage, or write nothing (audit-after-win, stages.py).
  446 |                 stages.take(conn, proposal_id, expected=stages.DISPATCHING,
  447 |                             new=stages.CLOSED, detail=exc.reason)
  448 |                 return _refused_before_start(
  449 |                     conn, engagement_id=engagement_id, actor=actor, run_id=run_id,
  450 |                     proposal_id=proposal_id, exc=exc,
  451 |                 )
  452 |         except stages.StageConflict:
  453 |             logger.error("run %s was refused before it started (%s) but proposal %s had already "
  454 |                          "been moved; nothing recorded", run_id, exc.reason, proposal_id)
  455 |             return DispatchOutcome(False, None, UNKNOWN_OUTCOME, reason=STAGE_MOVED)
  456 |     except SandboxUnavailable as exc:
```

`control_plane/api/function_api.py:1069-1081`

```text
 1069 |     outcome = _dispatch_for_action(
 1070 |         engagement_id=eid, proposal_id=proposal_id, capability=capability,
 1071 |         target=run.target.logical_identity.value, actor=run.actor, sandbox=run.sandbox,
 1072 |         network_allowlist=run.network_allowlist, execution_context=run.execution_context,
 1073 |         proxy_url=run.proxy_url, ca_cert_pem=run.ca_cert_pem,
 1074 |         proxy_cert_spki=run.proxy_cert_spki,
 1075 |     )
 1076 |     _record_provenance(run, proposal_id)
 1077 |     return ActionOutcome(
 1078 |         decision=ALLOW, capability_id=capability.capability_id, run_id=outcome.run_id,
 1079 |         evidence_id=outcome.evidence_id, failure=outcome.reason,
 1080 |         **_common(run, proposal_id),
 1081 |     )
```

[D] `NetworkInUse` is a `NotStarted` and so a `SandboxUnavailable`. Inside `propose_action` it is raised by the sandbox's `run` (the `_assert_exclusive` call sites) and caught by `dispatch._execute`'s `except NotStarted` before it can leave: the run row and the proposal are recorded as `failed` and `closed` with the sandbox's reason `network_in_use_by_another_engagement`, a `tool_run.refused` audit event is written, and `propose_action` returns an `ActionOutcome` with `decision=ALLOW` and `failure="network_in_use_by_another_engagement"` (`run_id` and `evidence_id` empty). It is converted to an outcome; it is not swallowed (a record and an audit event are written) and it is not raised to the harness. The proxy start (`start_egress_proxy`) is not called by `propose_action`, which takes `proxy_url` as an argument; the only callers are two scripts, so a harness that starts no proxy does not meet that raise path.

[R] Tests that name the reason string:

`$ git grep -n 'network_in_use_by_another_engagement' -- tests control_plane`

```text
control_plane/orchestrator/dispatch.py:318:    "network_unavailable", "network_in_use_by_another_engagement",
tests/test_network_isolation.py:200:    assert refused.value.reason == "network_in_use_by_another_engagement"
```

[N] No test in that output drives `NetworkInUse` through `propose_action` and reads `ActionOutcome.failure`; the one test line is a sandbox-level assertion. The behaviour in B.3 is from reading `dispatch.py` and `function_api.py`, not from an observed run.

**Effect on H5.** Under the closed fault list (design D69-5a) an outcome with a `failure` string is "a returned outcome", recorded and the task completed; `NetworkInUse` inside `propose_action` arrives as that outcome and not as an exception, so it is not a stop-the-service fault by itself (plan risk 6, `L1385`-`L1387`, calls this H5's open point); the harness's own start of a proxy, if H5 ever has one, is not in the plan.

## C. The 5.120 state

### C.1 ACCEPTANCE 5.120, the whole row [R]

`docs/ACCEPTANCE_MVP1_AGENTS.md:853`

```text
  853 | | **5.120** | **`LocalReviewer.review()` lets an empty `choices` list escape as an `IndexError` instead of failing closed** | **Open, Class B -- found by D68 S4, not changed.** `agents/llm/local_reviewer.py` catches `URLError`/`OSError`/`TimeoutError` and `ValueError`/`TypeError`/`KeyError`/`JSONDecodeError` around the call and the parse; `envelope["choices"][0]` on `{"choices": []}` raises `IndexError`, which none of them is [E: run against the class with a stub transport -- the exception propagates out of `review()`]. *Effect:* a local server that answers with an empty list makes the pipeline raise at the reviewer step instead of escalating (`risk_hint="high"`). It fails loud, not open, and needs a local backend (`CYBERORCH_REVIEWER_BACKEND=local`) that is, per ADR_REVIEWER_BILLING, verified only against a stub. *Traced through the real call chain (2026-10-21, real database; no model):* `propose_action` -> `_drive` (`function_api.py:672`) -> `_decide` (`:740`, `run.reviewer.review(...)` with **no `try`** around it, here or above) -> `LocalReviewer.review` -> `_content`: the `IndexError` is **not caught by any upper layer** and leaves `propose_action` as an exception to its caller. What it leaves behind: one proposal at `received`, no decision, no capability, no run, no evidence, three audit events (`engagement.created`, `scope_object.registered`, `proposal.submitted`), a sandbox that was never called (a sandbox rigged to raise if reached: 0 calls), and a state that `assert_coherent` accepts. A retry under the same idempotency key with a healthy reviewer **resumes and completes it once** (ALLOW, one capability, one run); one nobody retries is **abandoned** by the reconciler in `state-only` (`abandon / undecided_past_grace`, outcome `done`, still no capability or run). Nothing can proceed from `received`: the schema refuses any later stage without a decision (`action_proposals_decision_past_received`), the scheduler selects only `approved`, and OPA was never reached. *So it is not the designed degrade and it is not a bypass:* the Reviewer adapters that catch everything (API, Claude Code) turn a failure into `risk_hint="high"` and a human is asked; this one halts the call instead -- no human is asked, the proposal waits, then is abandoned -- which is exactly what the pipeline already does for **any** uncaught exception at the reviewer (`test_a_fault_at_any_boundary_leaves_coherent_state_and_a_retry_completes_it_once[the reviewer]`, which injects one and requires `received`, coherence and a retry that completes it once). The cost is operational (the caller must handle the exception it already must handle for a database error; the soak's worker would log it as `worker.unexpected`), not a safety property. *Not fixed here:* the Reviewer's files are deliberately untouched by D68. The plan-fit validator's copy of the same code catches `IndexError` and a mutation pins it. *If fixed:* add `IndexError` to the except clause and one test beside `test_a_local_model_that_ignores_the_contract_escalates`. |
```

### C.2 The existing tests that pin the state [R] [N]

The row itself cites `test_a_fault_at_any_boundary_leaves_coherent_state_and_a_retry_completes_it_once[the reviewer]`. The parameter list and the test:

`tests/test_pipeline_stages.py:454-455`

```text
  454 | def _boom(*_a, **_k):
  455 |     raise RuntimeError("injected fault")
```

`tests/test_pipeline_stages.py:458-459`

```text
  458 | def _fault_in_reviewer(world, monkeypatch):
  459 |     return {"reviewer": CountingReviewer(hook=lambda: _boom())}
```

`tests/test_pipeline_stages.py:494-502`

```text
  494 | FAULTS = [
  495 |     # name, injector, stage the proposal must be left in
  496 |     ("the reviewer", _fault_in_reviewer, stages.RECEIVED),
  497 |     ("the decision commit", _fault_before_the_decision_commits, stages.RECEIVED),
  498 |     ("just after the capability insert", _fault_after_the_broker_inserted, stages.DECIDED),
  499 |     ("before the run row commits", _fault_before_the_run_row_commits,
  500 |      stages.CAPABILITY_ISSUED),
  501 |     ("the container", _fault_in_the_container, stages.DISPATCHING),
  502 | ]
```

`tests/test_pipeline_stages.py:505-537`

```text
  505 | @pytest.mark.parametrize("name,inject,expected_stage", FAULTS, ids=[f[0] for f in FAULTS])
  506 | def test_a_fault_at_any_boundary_leaves_coherent_state_and_a_retry_completes_it_once(
  507 |     world, monkeypatch, name, inject, expected_stage,
  508 | ):
  509 |     with monkeypatch.context() as patched:
  510 |         extra = inject(world, patched)
  511 |         with pytest.raises(RuntimeError, match="injected fault"):
  512 |             go(world, **extra)
  513 |         left = snapshot(world["engagement_id"])
  514 |     p = only(left)
  515 |     assert p["stage"] == expected_stage, (name, p)
  516 |     assert_coherent(left)
  517 | 
  518 |     if expected_stage == stages.DISPATCHING:
  519 |         # The container may have run. A retry does not run it again.
  520 |         sandbox = FakeSandbox()
  521 |         outcome = go(world, sandbox=sandbox)
  522 |         assert sandbox.calls == 0
  523 |         assert outcome.failure == "dispatch_in_progress_or_unknown_outcome"
  524 |         assert only(snapshot(world["engagement_id"]))["stage"] == stages.DISPATCHING
  525 |         return
  526 | 
  527 |     sandbox = FakeSandbox()
  528 |     outcome = go(world, sandbox=sandbox)
  529 |     assert outcome.decision == "ALLOW" and outcome.run_id and outcome.evidence_id
  530 |     done = snapshot(world["engagement_id"])
  531 |     assert_coherent(done)
  532 |     assert only(done)["stage"] == stages.RECORDED
  533 |     # Once each, however many attempts: one proposal, one capability, one run, one container.
  534 |     assert done["capabilities"] == 1 and done["runs"] == ["succeeded"]
  535 |     assert sandbox.calls == 1
  536 |     assert done["audit"].get("policy.decided", 0) == 1 if name != "the reviewer" else True
  537 |     assert done["audit"].get("tool_run.started") == 1
```

The state's coherence rule (first lines) and the snapshot it reads:

`tests/test_pipeline_stages.py:170-178`

```text
  170 | def assert_coherent(snap: dict) -> None:
  171 |     """The rules no committed state may break, whatever failed and wherever.
  172 | 
  173 |     No stage ever commits something "partly right": a later stage's rows imply an earlier stage's.
  174 |     """
  175 |     for p in snap["proposals"]:
  176 |         stage = p["stage"]
  177 |         if stage not in stages.UNDECIDED_STAGES:
  178 |             assert p["decision"] is not None, f"stage {stage} with no recorded decision: {p}"
```

`tests/test_pipeline_stages.py:138-140`

```text
  138 | def snapshot(engagement_id: str) -> dict:
  139 |     with engagement_scope(engagement_id) as conn:
  140 |         proposals = [dict(r) for r in conn.execute(text(
```

The second test the same row's trace corresponds to (an interruption that is not an `Exception`; `5.120's trace` is named in its docstring):

`tests/test_plan_fit_goal_fit.py:12-18`

```text
   12 | * **fault injection** (the hard requirement of S5) -- a validator that raises an *unexpected*
   13 |   exception of any kind, returns garbage, or has a broken record, does not interrupt
   14 |   ``propose_action``: the answer becomes ``not_assessed`` / ``failed``, the proposal is decided, and
   15 |   the state is coherent. The injection is the one used to verify ACCEPTANCE 5.120: a sandbox that
   16 |   raises if it is reached, and a validator that raises when touched.
   17 | * **an interruption that is not an ``Exception``** -- left coherent at ``received``; a retry
   18 |   completes it once; the reconciler abandons it. The same shape as 5.120's trace.
```

`tests/test_plan_fit_goal_fit.py:579-603`

```text
  579 | def test_an_interruption_leaves_a_received_proposal_and_a_retry_completes_it_once(world):
  580 |     """Deliberately *not* caught (a process asked to stop must stop). The state is the same as the
  581 |     5.120 trace: the proposal is ``received``, coherent, nothing ran, and a retry under the same key
  582 |     decides it and runs it exactly once."""
  583 |     key = f"key-{uuid.uuid4().hex[:8]}"
  584 |     proposal = with_task(world, _proposal(world))
  585 |     trap = TrapSandbox()
  586 |     with pytest.raises(Stop):
  587 |         decide(world, Raising(Stop()), proposal=proposal, task="given", key=key, sandbox=trap)
  588 |     left = snapshot(world["engagement_id"])
  589 |     assert only(left)["stage"] == stages.RECEIVED
  590 |     assert_coherent(left)
  591 |     assert left["audit"].get("policy.decided", 0) == 0 and trap.calls == 0
  592 |     assert left["capabilities"] == 0 and left["runs"] == []
  593 | 
  594 |     sandbox, healthy = FakeSandbox(), ScriptedPlanFit("plausible")
  595 |     out = decide(world, healthy, proposal=proposal, task="given", key=key, sandbox=sandbox,
  596 |                  goal=False)
  597 |     assert out.decision == "ALLOW" and out.executed
  598 |     done = snapshot(world["engagement_id"])
  599 |     assert_coherent(done)
  600 |     assert only(done)["stage"] == stages.RECORDED
  601 |     assert done["capabilities"] == 1 and done["runs"] == ["succeeded"] and sandbox.calls == 1
  602 |     assert done["audit"].get("policy.decided") == 1
  603 |     assert len(audited(world, out.proposal_id)) == 1
```

[R] Also `tests/test_plan_fit_goal_fit.py:606` `test_the_reconciler_abandons_what_the_interruption_left` (nobody retries; the reconciler's state-only pass abandons it). [N] `git grep -n IndexError -- tests` finds one line (`tests/test_plan_fit_goal_fit.py:355`, a validator test); no test injects the row's own trigger, an empty `choices` list at `LocalReviewer`, so what is pinned is the state left by **any** exception at the reviewer step, and not the `IndexError` itself.

### C.3 What `action_proposals` and the audit trail hold in that state [R] [D]

`db/migrations/versions/0001_core_schema.py:161-187`

```text
  161 | CREATE TABLE action_proposals (
  162 |     proposal_id                   TEXT PRIMARY KEY,
  163 |     engagement_id                 TEXT NOT NULL REFERENCES engagements(engagement_id),
  164 |     task_id                       TEXT REFERENCES tasks(task_id),
  165 |     agent_id                      TEXT NOT NULL,
  166 |     request_idempotency_key       TEXT NOT NULL,
  167 |     dispatch_state                TEXT NOT NULL DEFAULT 'queued' CHECK (dispatch_state IN
  168 |                                       ('queued','dispatching','running','succeeded',
  169 |                                        'failed','unknown_outcome')),
  170 |     action                        TEXT NOT NULL,
  171 |     target                        JSONB NOT NULL,
  172 |     "authorization"               JSONB NOT NULL,
  173 |     discovery                     JSONB NOT NULL,
  174 |     resources                     TEXT[] NOT NULL DEFAULT '{}',
  175 |     expected_data                 TEXT[] NOT NULL DEFAULT '{}',
  176 |     possible_sensitive_data_hint  TEXT[] NOT NULL DEFAULT '{}',
  177 |     writes_data                   BOOLEAN NOT NULL DEFAULT FALSE,
  178 |     changes_state                 BOOLEAN NOT NULL DEFAULT FALSE,
  179 |     risk_hint                     TEXT,
  180 |     reason                        TEXT,
  181 |     requested_capability_ttl_seconds INTEGER,
  182 |     decision                      TEXT CHECK (decision IN
  183 |                                       ('ALLOW','DENY','HUMAN_APPROVAL')),
  184 |     decision_reasons              TEXT[] NOT NULL DEFAULT '{}',
  185 |     created_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),
  186 |     updated_at                    TIMESTAMPTZ NOT NULL DEFAULT now()
  187 | );
```

`db/migrations/versions/0016_pipeline_stage.py:46`

```text
   46 |             ADD COLUMN pipeline_stage TEXT NOT NULL DEFAULT 'received',
```

`db/migrations/versions/0021_decision_past_received.py:45-51`

```text
   45 | NAME = "action_proposals_decision_past_received"
   46 | 
   47 | 
   48 | def upgrade() -> None:
   49 |     op.execute(f"""
   50 |         ALTER TABLE action_proposals ADD CONSTRAINT {NAME}
   51 |             CHECK (decision IS NOT NULL OR pipeline_stage = 'received');
```

`db/migrations/versions/0022_abandoned_stage.py:96`

```text
   96 |             CHECK (decision IS NOT NULL OR pipeline_stage IN ('received', 'abandoned'));
```

`control_plane/api/function_api.py:1491-1502`

```text
 1491 |     inserted = conn.execute(
 1492 |         text("""
 1493 |             INSERT INTO action_proposals (proposal_id, engagement_id, task_id,
 1494 |                 agent_id, request_idempotency_key, action, target, "authorization",
 1495 |                 discovery, resources, expected_data, writes_data, changes_state,
 1496 |                 reason, requested_capability_ttl_seconds)
 1497 |             VALUES (:pid, :eid, :tid, :agent, :key, :action, CAST(:target AS jsonb),
 1498 |                     CAST(:auth AS jsonb), CAST(:disc AS jsonb), :resources,
 1499 |                     :expected, :writes, :changes, :reason, :ttl)
 1500 |             ON CONFLICT (engagement_id, request_idempotency_key) DO NOTHING
 1501 |             RETURNING proposal_id
 1502 |         """),
```

`control_plane/api/function_api.py:627-641`

```text
  627 |         if inserted:
  628 |             # Attributed to the agent, unlike everything after it, which the
  629 |             # orchestrator does. "Which agent asked for this" is otherwise only in the
  630 |             # proposal row, and the audit trail should stand on its own.
  631 |             record_audit(
  632 |                 engagement_id=engagement_id, actor=agent_id, event_type="proposal.submitted",
  633 |                 subject_type="action_proposal", subject_id=proposal_id,
  634 |                 payload={
  635 |                     "action": proposal.action,
  636 |                     "target": target.normalized,
  637 |                     "authorization": dict(proposal.authorization),
  638 |                     "discovery": dict(proposal.discovery),
  639 |                     "task_id": proposal.task_id,
  640 |                 },
  641 |             )
```

The assertions of the interruption test on the left-over state:

`tests/test_plan_fit_goal_fit.py:588-592`

```text
  588 |     left = snapshot(world["engagement_id"])
  589 |     assert only(left)["stage"] == stages.RECEIVED
  590 |     assert_coherent(left)
  591 |     assert left["audit"].get("policy.decided", 0) == 0 and trap.calls == 0
  592 |     assert left["capabilities"] == 0 and left["runs"] == []
```

[D] `action_proposals`: one row with `pipeline_stage='received'`, `decision` NULL and `decision_reasons` empty (the CHECK allows a NULL decision only at `received` or `abandoned`), `dispatch_state='queued'`, `task_id` and `request_idempotency_key` as given at the insert, `provenance_complete` false. Audit: `proposal.submitted` (actor the agent; payload `action`, `target`, `authorization`, `discovery`, `task_id`); no `policy.decided` (`left["audit"].get("policy.decided", 0) == 0`), no capability, no run, no evidence. The row's own list of three events adds `engagement.created` and `scope_object.registered`, which come from the test's setup and not from the pipeline. [D] For a harness that claimed a task before the call, the `tasks` row stays `claimed` (`task.claimed` audited) because nothing in the interrupted call completes it. [N] The exact field values of `engagement.created` and `scope_object.registered` were not read.

**Effect on H5.** Design test 5 (`propose_action` raising) compares this state; the facts above are what that comparison has to hold: a `received` proposal that carries the task id and the key, no decision, no capability or run, one `proposal.submitted` event, and a `claimed` task if the loop does not complete it. A retry under the same key resumes it (G), which is the behaviour the start-up check (proposal 3.5) makes unreachable for a restart.

## D. The `scheduler_enrollment` template

### D.1 Migration 0019: the table, role grants, policies and trigger [R]

`db/migrations/versions/0019_scheduler.py:6-24`

```text
    6 | Three roles (created by ``db/roles.sql``), each with one job and a short grant list:
    7 | 
    8 | * ``scheduler_admin`` -- writes ``scheduler_enrollment``, the list of engagements the scheduler
    9 |   may touch (D58-1/A). Used by an operator's CLI, never by the service. Reads nothing else.
   10 | * ``scheduler_reader`` -- reads the scheduling decision's inputs, and **only** those: the
   11 |   enrollment list; ``engagements.engagement_id/status/kill_switch_engaged``; the view
   12 |   ``scheduler_proposals``; ``scheduler_state``. It has **no grant** on ``action_proposals``
   13 |   itself, on ``audit_log``, ``tasks``, ``capabilities``, ``tool_runs``, ``approvals``,
   14 |   ``evidence`` or ``credential_material``.
   15 | * ``scheduler_state_writer`` -- writes ``scheduler_state``, and nothing else.
   16 | 
   17 | ``cyberorch_app`` gets **no** grant on either new table: the pipeline's own role cannot read or
   18 | write the enrollment list or the scheduler's state.
   19 | 
   20 | * ``scheduler_enrollment`` -- global (no engagement GUC: the reader must list ids to know which
   21 |   engagement to open), so its row-level security is written per role rather than per
   22 |   engagement. ``engagement_id`` references ``engagements`` -- referential-integrity checks
   23 |   bypass row security, so a nonexistent id is refused by the database. Append-only history; a
   24 |   trigger forbids everything but withdrawing a live enrollment.
```

`db/migrations/versions/0019_scheduler.py:65-117`

```text
   65 |     # ------------------------------------------------------------------ enrollment
   66 |     op.execute("""
   67 |         CREATE TABLE scheduler_enrollment (
   68 |             enrollment_id  BIGSERIAL PRIMARY KEY,
   69 |             engagement_id  TEXT NOT NULL REFERENCES engagements(engagement_id),
   70 |             enrolled_by    TEXT NOT NULL CHECK (enrolled_by <> ''),
   71 |             enrolled_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
   72 |             withdrawn_by   TEXT,
   73 |             withdrawn_at   TIMESTAMPTZ,
   74 |             CHECK ((withdrawn_at IS NULL) = (withdrawn_by IS NULL))
   75 |         );
   76 |     """)
   77 |     op.execute("CREATE UNIQUE INDEX scheduler_enrollment_live ON scheduler_enrollment "
   78 |                "(engagement_id) WHERE withdrawn_at IS NULL;")
   79 |     op.execute("ALTER TABLE scheduler_enrollment ENABLE ROW LEVEL SECURITY;")
   80 |     op.execute("ALTER TABLE scheduler_enrollment FORCE ROW LEVEL SECURITY;")
   81 |     op.execute("""
   82 |         CREATE POLICY scheduler_admin_all ON scheduler_enrollment
   83 |             FOR ALL TO scheduler_admin USING (true) WITH CHECK (true);
   84 |     """)
   85 |     op.execute("""
   86 |         CREATE POLICY scheduler_reader_select ON scheduler_enrollment
   87 |             FOR SELECT TO scheduler_reader USING (true);
   88 |     """)
   89 |     op.execute("""
   90 |         CREATE FUNCTION scheduler_enrollment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
   91 |         BEGIN
   92 |             IF NEW.enrollment_id IS DISTINCT FROM OLD.enrollment_id
   93 |                OR NEW.engagement_id IS DISTINCT FROM OLD.engagement_id
   94 |                OR NEW.enrolled_by   IS DISTINCT FROM OLD.enrolled_by
   95 |                OR NEW.enrolled_at   IS DISTINCT FROM OLD.enrolled_at THEN
   96 |                 RAISE EXCEPTION 'an enrollment is fixed when it is written (id %)',
   97 |                     OLD.enrollment_id USING ERRCODE = 'integrity_constraint_violation';
   98 |             END IF;
   99 |             IF OLD.withdrawn_at IS NOT NULL
  100 |                AND (NEW.withdrawn_at IS DISTINCT FROM OLD.withdrawn_at
  101 |                     OR NEW.withdrawn_by IS DISTINCT FROM OLD.withdrawn_by) THEN
  102 |                 RAISE EXCEPTION 'a withdrawn enrollment stays withdrawn (id %)',
  103 |                     OLD.enrollment_id USING ERRCODE = 'integrity_constraint_violation';
  104 |             END IF;
  105 |             RETURN NEW;
  106 |         END $$;
  107 |     """)
  108 |     op.execute("CREATE TRIGGER scheduler_enrollment_guard BEFORE UPDATE ON scheduler_enrollment "
  109 |                "FOR EACH ROW EXECUTE FUNCTION scheduler_enrollment_guard();")
  110 |     op.execute("GRANT USAGE ON SCHEMA public TO scheduler_admin, scheduler_reader, "
  111 |                "scheduler_state_writer;")
  112 |     op.execute("GRANT SELECT, INSERT ON scheduler_enrollment TO scheduler_admin;")
  113 |     op.execute("GRANT UPDATE (withdrawn_by, withdrawn_at) ON scheduler_enrollment "
  114 |                "TO scheduler_admin;")
  115 |     op.execute("GRANT USAGE ON SEQUENCE scheduler_enrollment_enrollment_id_seq "
  116 |                "TO scheduler_admin;")
  117 |     op.execute("GRANT SELECT ON scheduler_enrollment TO scheduler_reader;")
```

`db/migrations/versions/0019_scheduler.py:181-189`

```text
  181 | def downgrade() -> None:
  182 |     op.execute("DROP VIEW IF EXISTS scheduler_proposals;")
  183 |     op.execute("REVOKE SELECT (engagement_id, status, kill_switch_engaged) ON engagements "
  184 |                "FROM scheduler_reader;")
  185 |     op.execute("DROP TABLE IF EXISTS scheduler_state;")
  186 |     op.execute("ALTER TABLE action_proposals DROP CONSTRAINT IF EXISTS "
  187 |                "action_proposals_id_engagement;")
  188 |     op.execute("DROP TABLE IF EXISTS scheduler_enrollment;")
  189 |     op.execute("DROP FUNCTION IF EXISTS scheduler_enrollment_guard();")
```

### D.2 Where `scheduler_admin` and `scheduler_reader` are created [R]

The roles are created by `db/roles.sql`, not by a migration; the migration's docstring says so ("created by ``db/roles.sql``"):

`db/roles.sql:79-87`

```text
   79 |     IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scheduler_reader') THEN
   80 |         CREATE ROLE scheduler_reader LOGIN;
   81 |     END IF;
   82 |     IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scheduler_admin') THEN
   83 |         CREATE ROLE scheduler_admin LOGIN;
   84 |     END IF;
   85 |     IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scheduler_state_writer') THEN
   86 |         CREATE ROLE scheduler_state_writer LOGIN;
   87 |     END IF;
```

`db/roles.sql:155-178`

```text
  155 | -- The scheduler's three roles (D62, D58-1/3). Three jobs, three roles, none of them cyberorch_app:
  156 | --
  157 | --   scheduler_reader       reads the scheduling decision's inputs and nothing else: the enrollment
  158 | --                          list, three columns of engagements, five columns of a closed-vocabulary
  159 | --                          view of action_proposals, and the scheduler's own state table. No
  160 | --                          INSERT anywhere; no grant on tasks, capabilities, tool_runs, evidence,
  161 | --                          approvals, audit_log or credential_material. Still subject to the
  162 | --                          engagement_isolation policy: with no engagement bound it sees no
  163 | --                          engagement's rows.
  164 | --   scheduler_admin        writes the enrollment list (the operator's CLI, never the service) and
  165 | --                          reads nothing else.
  166 | --   scheduler_state_writer writes scheduler_state, a table whose every column is an id, a
  167 | --                          timestamp or a CHECK-closed code, and nothing else.
  168 | -- NOBYPASSRLS like every other role here: their reach is defined by grants and policies in
  169 | -- migration 0019, not by trusting a service to stay in its lane.
  170 | ALTER ROLE scheduler_reader
  171 |     WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION
  172 |     PASSWORD :'scheduler_reader_password';
  173 | ALTER ROLE scheduler_admin
  174 |     WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION
  175 |     PASSWORD :'scheduler_admin_password';
  176 | ALTER ROLE scheduler_state_writer
  177 |     WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION
  178 |     PASSWORD :'scheduler_state_writer_password';
```

Who runs `db/roles.sql`:

`$ git grep -n -E 'roles.sql|alembic|psql|SCHEDULER_(READER|ADMIN|STATE_WRITER)' -- scripts/init_db.sh`

```text
scripts/init_db.sh:6:#   migration_owner  owns every table and runs alembic
scripts/init_db.sh:55:# exists (it runs `.venv/bin/alembic`) and a system Python has no reason to
scripts/init_db.sh:69:: "${SCHEDULER_READER_PASSWORD:=$(gen_password)}"
scripts/init_db.sh:70:: "${SCHEDULER_ADMIN_PASSWORD:=$(gen_password)}"
scripts/init_db.sh:71:: "${SCHEDULER_STATE_WRITER_PASSWORD:=$(gen_password)}"
scripts/init_db.sh:75:# Run psql as the superuser. Arguments are passed through verbatim.
scripts/init_db.sh:76:super_psql() {
scripts/init_db.sh:78:        psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -p "$DB_PORT" -U "$PGSUPER" \
scripts/init_db.sh:84:        su "$PGSUPER" -c "psql -v ON_ERROR_STOP=1 ${quoted[*]}"
scripts/init_db.sh:89:super_psql_db() {
scripts/init_db.sh:91:        psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -p "$DB_PORT" -U "$PGSUPER" \
scripts/init_db.sh:97:        su "$PGSUPER" -c "psql -v ON_ERROR_STOP=1 -d $DB_NAME ${quoted[*]}"
scripts/init_db.sh:102:super_psql \
scripts/init_db.sh:110:    -v "scheduler_reader_password=$SCHEDULER_READER_PASSWORD" \
scripts/init_db.sh:111:    -v "scheduler_admin_password=$SCHEDULER_ADMIN_PASSWORD" \
scripts/init_db.sh:112:    -v "scheduler_state_writer_password=$SCHEDULER_STATE_WRITER_PASSWORD" \
scripts/init_db.sh:114:    -f "$root/db/roles.sql" >/dev/null
scripts/init_db.sh:117:if ! super_psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" | grep -q 1; then
scripts/init_db.sh:118:    super_psql -c "CREATE DATABASE $DB_NAME OWNER migration_owner" >/dev/null
scripts/init_db.sh:124:super_psql_db -c "REVOKE CREATE ON SCHEMA public FROM PUBLIC" >/dev/null
scripts/init_db.sh:125:super_psql_db -c "GRANT CREATE, USAGE ON SCHEMA public TO migration_owner" >/dev/null
scripts/init_db.sh:138:SCHEDULER_READER_PASSWORD=${SCHEDULER_READER_PASSWORD}
scripts/init_db.sh:139:SCHEDULER_ADMIN_PASSWORD=${SCHEDULER_ADMIN_PASSWORD}
scripts/init_db.sh:140:SCHEDULER_STATE_WRITER_PASSWORD=${SCHEDULER_STATE_WRITER_PASSWORD}
scripts/init_db.sh:150:SCHEDULER_READER_DATABASE_URL=postgresql+psycopg://scheduler_reader:${SCHEDULER_READER_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}
scripts/init_db.sh:151:SCHEDULER_ADMIN_DATABASE_URL=postgresql+psycopg://scheduler_admin:${SCHEDULER_ADMIN_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}
scripts/init_db.sh:152:SCHEDULER_STATE_WRITER_DATABASE_URL=postgresql+psycopg://scheduler_state_writer:${SCHEDULER_STATE_WRITER_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}
scripts/init_db.sh:159:"$root/.venv/bin/alembic" -c "$root/alembic.ini" upgrade head
```

`scripts/init_db.sh:1-30`

```text
    1 | #!/usr/bin/env bash
    2 | # Bootstrap the database for local development / CI.
    3 | #
    4 | # Four connections, four privilege levels (§8.6, §5):
    5 | #   superuser        creates roles and the database, then steps out
    6 | #   migration_owner  owns every table and runs alembic
    7 | #   cyberorch_app    the runtime role — owns nothing, cannot bypass RLS
    8 | #   registry_admin   the Engagement Manager — cyberorch_app plus write access
    9 | #                    to scope_registry and metadata_registry, nothing else
   10 | #   credential_admin the Credential Vault's write path (D44) — a separate
   11 | #                    role, not registry_admin widened; write access to
   12 | #                    credential_material and credentials, nothing else
   13 | #   global_policy_admin the only writer of global policy layers (5.37, D54) —
   14 | #                    an operator's CLI role, never a service's
   15 | #   scheduler_reader / scheduler_admin / scheduler_state_writer  the scheduler's
   16 | #                    three narrow roles (D62): read its decision inputs, write the
   17 | #                    enrollment list (operator CLI), write its closed-vocabulary state
   18 | #   reconciler_reader the reconciler's plan side (D64): EXECUTE on two read functions, nothing else
   19 | #
   20 | # Passwords are never hardcoded here. They are taken from the environment, or
   21 | # from a gitignored .env, or generated randomly on first run and written to
   22 | # .env. A checked-in default password is a credential in the repository even
   23 | # when it is "only for development", and it survives in the history after
   24 | # anyone deletes it.
   25 | #
   26 | # Two ways to reach the superuser, because CI and a workstation differ:
   27 | #   PGSUPER_MODE=peer  (default) su to the OS postgres user over the local socket
   28 | #   PGSUPER_MODE=tcp             connect as PGSUPER over TCP, e.g. a CI service
   29 | #                                container
   30 | # CI runs this same script rather than an equivalent-looking sequence of steps:
```

[D] `scripts/init_db.sh` is the operator step that runs `db/roles.sql` with the three passwords and writes the three connection strings to the environment file; the grants on tables come from migrations (0019). A role the loop needs that is not in `db/roles.sql` does not exist until that file is changed and the script re-run [N] (whether any deployment ran it with a later `roles.sql` was not checked).

### D.3 The tests that name `scheduler_enrollment` [R]

`tests/test_migrations_roundtrip.py`, each line with its context:

`tests/test_migrations_roundtrip.py:24-30`

```text
   24 |   constraints, policies, indexes, triggers, functions and grants are **identical** to the first
   25 |   head;
   26 | * 0016-0020 are really undone by their downgrades (the scheduler's tables, the stage column);
   27 | * after **every** migration step, up or down, ``scheduler_state`` and ``scheduler_enrollment`` (when
   28 |   they exist) have ``FORCE ROW LEVEL SECURITY`` on -- the table owner is bound by the policies;
   29 | * 0020 switches ``FORCE`` off for one statement to rewrite rows (the owner is otherwise blind to
   30 |   them) and back on: that pair is shown to be **atomic** -- a failure between them rolls both back,
```

`tests/test_migrations_roundtrip.py:125-132`

```text
  125 |     def force_rls(self) -> dict[str, bool]:
  126 |         """``relforcerowsecurity`` of the scheduler's tables that exist at the current revision."""
  127 |         with self.engine.begin() as conn:
  128 |             return {r[0]: r[1] for r in conn.execute(text(
  129 |                 "SELECT relname, relforcerowsecurity FROM pg_class "
  130 |                 "WHERE relnamespace = CAST(:s AS regnamespace) "
  131 |                 "AND relname IN ('scheduler_state', 'scheduler_enrollment')"), {"s": self.name})}
  132 | 
```

`tests/test_migrations_roundtrip.py:212-217`

```text
  212 |     assert scratch.revision() is None
  213 |     scratch.alembic("upgrade", "head")
  214 |     assert scratch.revision() == _head() == ScriptDirectory.from_config(
  215 |         Config(str(scratch.ini))).get_current_head()      # the copy has every revision
  216 |     assert {"scheduler_enrollment", "scheduler_state", "approvals", "action_proposals"} <= \
  217 |         scratch.tables()
```

`tests/test_migrations_roundtrip.py:226-229`

```text
  226 |     scratch.alembic("downgrade", "0015")
  227 |     assert scratch.revision() == "0015"
  228 |     assert not ({"scheduler_enrollment", "scheduler_state"} & scratch.tables())
  229 |     proposals = scratch.columns("action_proposals")
```

`tests/test_migrations_roundtrip.py:270-275`

```text
  270 | 
  271 | 
  272 | SCHEDULER_TABLES = {"scheduler_state", "scheduler_enrollment"}
  273 | 
  274 | 
  275 | def _revisions_from(first: str) -> list[str]:
```

`tests/test_migrations_roundtrip.py:752-758`

```text
  752 |     added = {line.split(": ", 1)[1].split("  [")[0].strip()
  753 |              for line in snapshot_diff(s22, s23) if line.startswith("+ new")}
  754 |     assert {f"function:{f}" for f in READER_FUNCTIONS} <= added, added
  755 |     assert {f"policy:{t}.reconciler_owner_select" for t in (
  756 |         "action_proposals", "capabilities", "approvals", "engagements", "scheduler_enrollment",
  757 |         "tool_runs")} <= added, added
  758 |     assert {f"index:{n}" for n in (
```

`tests/test_migrations_rls_writes.py`:

`$ git grep -n 'scheduler' -- tests/test_migrations_rls_writes.py`

```text
tests/test_migrations_rls_writes.py:46:    ("0020_scheduler_state_narrow.py", "upgrade"): {"scheduler_state"},
```

`tests/test_migrations_rls_writes.py:43-52`

```text
   43 | EXPECTED = {
   44 |     ("0017_approval_stages.py", "upgrade"): {"action_proposals", "approvals", "audit_log"},
   45 |     ("0017_approval_stages.py", "downgrade"): {"action_proposals"},
   46 |     ("0020_scheduler_state_narrow.py", "upgrade"): {"scheduler_state"},
   47 |     ("0022_abandoned_stage.py", "downgrade"): {"action_proposals"},
   48 |     # D68 DP-15: gives the reasons of suspensions cleared during development a value, FORCE off
   49 |     ("0028_goal_fit_clear_reason.py", "upgrade"): {"goal_fit_suspensions"},
   50 |     # D68 DP-15: gives the failed calls recorded before kinds existed the kind 'unclassified'
   51 |     ("0029_goal_fit_failure_kind.py", "upgrade"): {"goal_fit_calls"},
   52 | }
```

[R] The name `scheduler_enrollment` does not occur in `tests/test_migrations_rls_writes.py`; the only scheduler entry there is the data statement of `0020_scheduler_state_narrow.py`. [D] That test lists migrations whose upgrade or downgrade contains a data statement (`UPDATE`, `INSERT INTO`, `DELETE FROM`, `TRUNCATE`); a migration that only creates a table has no entry, which is why 0019 has none.

The grant test of the three roles and of `cyberorch_app`:

`tests/test_scheduler_roles.py:34-54`

```text
   34 | READER, ADMIN, WRITER = "scheduler_reader", "scheduler_admin", "scheduler_state_writer"
   35 | 
   36 | #: role -> relation -> privilege -> "ALL" or the columns granted. The complete grant list.
   37 | GRANTS = {
   38 |     READER: {
   39 |         "engagements": {"SELECT": ["engagement_id", "status", "kill_switch_engaged"]},
   40 |         "scheduler_enrollment": {"SELECT": "ALL"},
   41 |         "scheduler_proposals": {"SELECT": "ALL"},
   42 |         "scheduler_state": {"SELECT": "ALL"},
   43 |     },
   44 |     ADMIN: {
   45 |         "scheduler_enrollment": {"SELECT": "ALL", "INSERT": "ALL",
   46 |                                  "UPDATE": ["withdrawn_by", "withdrawn_at"]},
   47 |     },
   48 |     WRITER: {
   49 |         "scheduler_state": {"SELECT": "ALL", "INSERT": "ALL",
   50 |                             "UPDATE": ["disposition", "reason_code", "since"]},
   51 |     },
   52 | }
   53 | 
   54 | VIEW_COLUMNS = ["proposal_id", "engagement_id", "pipeline_stage", "stage_updated_at",
```

`tests/test_scheduler_roles.py:85-93`

```text
   85 | @pytest.mark.parametrize("role", [READER, ADMIN, WRITER])
   86 | def test_each_role_has_exactly_the_grants_listed_and_nothing_else(db_available, role):
   87 |     assert _matrix(role) == GRANTS[role]
   88 | 
   89 | 
   90 | def test_the_pipelines_own_role_has_no_grant_on_the_schedulers_tables(db_available):
   91 |     app = _matrix("cyberorch_app")
   92 |     assert "scheduler_enrollment" not in app and "scheduler_state" not in app
   93 |     assert "scheduler_proposals" not in app
```

Every other line of `tests/test_scheduler_roles.py` that names the table or the admin scope:

`$ git grep -n -E 'scheduler_enrollment|scheduler_admin' -- tests/test_scheduler_roles.py`

```text
tests/test_scheduler_roles.py:26:    scheduler_admin_scope,
tests/test_scheduler_roles.py:34:READER, ADMIN, WRITER = "scheduler_reader", "scheduler_admin", "scheduler_state_writer"
tests/test_scheduler_roles.py:40:        "scheduler_enrollment": {"SELECT": "ALL"},
tests/test_scheduler_roles.py:45:        "scheduler_enrollment": {"SELECT": "ALL", "INSERT": "ALL",
tests/test_scheduler_roles.py:92:    assert "scheduler_enrollment" not in app and "scheduler_state" not in app
tests/test_scheduler_roles.py:135:        assert conn.execute(text("SELECT count(*) FROM scheduler_enrollment")).scalar_one() >= 0
tests/test_scheduler_roles.py:210:    "INSERT INTO scheduler_enrollment (engagement_id, enrolled_by) VALUES ('x', 'y')",
tests/test_scheduler_roles.py:211:    "UPDATE scheduler_enrollment SET withdrawn_at = now()",
tests/test_scheduler_roles.py:228:        with scheduler_admin_scope() as conn:
tests/test_scheduler_roles.py:229:            conn.execute(text("INSERT INTO scheduler_enrollment (engagement_id, enrolled_by) "
tests/test_scheduler_roles.py:233:            with scheduler_admin_scope() as conn:
tests/test_scheduler_roles.py:241:            with scheduler_admin_scope() as conn:
tests/test_scheduler_roles.py:242:                conn.execute(text("UPDATE scheduler_enrollment SET enrolled_by = 'someone-else' "
tests/test_scheduler_roles.py:249:        with scheduler_admin_scope() as conn:
tests/test_scheduler_roles.py:250:            conn.execute(text("UPDATE scheduler_enrollment SET withdrawn_at = NULL, "
```

The other files that name the table:

`$ git grep -n -l 'scheduler_enrollment' -- . ':!docs'`

```text
README.md
control_plane/scheduler/decide.py
control_plane/state/db.py
db/migrations/versions/0019_scheduler.py
db/migrations/versions/0023_reconciler_reader.py
db/migrations/versions/0024_reconciler_paging.py
db/migrations/versions/0027_goal_fit_classes.py
scripts/manage_scheduler_enrollment.py
scripts/mutations_d62_d63.py
scripts/mutations_d66.py
scripts/run_scheduler.py
tests/residue.py
tests/scheduler_support.py
tests/test_check_constraints_null_rule.py
tests/test_migrations_roundtrip.py
tests/test_reconciler_reader.py
tests/test_residue_wiring.py
tests/test_scheduler_cli.py
tests/test_scheduler_roles.py
tests/test_scheduler_structure.py
```

`$ git grep -n 'scheduler_enrollment' -- db/migrations/versions/0023_reconciler_reader.py db/migrations/versions/0024_reconciler_paging.py`

```text
db/migrations/versions/0023_reconciler_reader.py:78:    "scheduler_enrollment": ("engagement_id", "withdrawn_at"),
db/migrations/versions/0023_reconciler_reader.py:159:                   EXISTS (SELECT 1 FROM {s}.scheduler_enrollment se
db/migrations/versions/0023_reconciler_reader.py:220:    if table == "scheduler_enrollment":
db/migrations/versions/0024_reconciler_paging.py:102:                   EXISTS (SELECT 1 FROM {s}.scheduler_enrollment se
```

### D.4 `control_plane/state/db.py`: the scheduler's role wiring [R]

Every line of the file that names a scheduler role, URL, engine or scope:

`$ git grep -n -i 'scheduler' -- control_plane/state/db.py`

```text
control_plane/state/db.py:29:_SCHEDULER_READER_ENGINE: Engine | None = None
control_plane/state/db.py:31:_SCHEDULER_ADMIN_ENGINE: Engine | None = None
control_plane/state/db.py:32:_SCHEDULER_STATE_WRITER_ENGINE: Engine | None = None
control_plane/state/db.py:99:def scheduler_reader_url() -> str:
control_plane/state/db.py:100:    """The scheduler's read connection string (D62): ``scheduler_reader``, decision inputs only."""
control_plane/state/db.py:102:        "SCHEDULER_READER_DATABASE_URL",
control_plane/state/db.py:103:        hint="Run scripts/init_db.sh, or export SCHEDULER_READER_DATABASE_URL "
control_plane/state/db.py:104:             "for the scheduler_reader role.",
control_plane/state/db.py:117:def scheduler_admin_url() -> str:
control_plane/state/db.py:120:        "SCHEDULER_ADMIN_DATABASE_URL",
control_plane/state/db.py:121:        hint="Run scripts/init_db.sh, or export SCHEDULER_ADMIN_DATABASE_URL "
control_plane/state/db.py:122:             "for the scheduler_admin role.",
control_plane/state/db.py:126:def scheduler_state_writer_url() -> str:
control_plane/state/db.py:127:    """The scheduler's state writer connection string (D62). Writes ``scheduler_state`` only."""
control_plane/state/db.py:129:        "SCHEDULER_STATE_WRITER_DATABASE_URL",
control_plane/state/db.py:130:        hint="Run scripts/init_db.sh, or export SCHEDULER_STATE_WRITER_DATABASE_URL "
control_plane/state/db.py:131:             "for the scheduler_state_writer role.",
control_plane/state/db.py:203:def get_scheduler_reader_engine() -> Engine:
control_plane/state/db.py:204:    """Pool for ``scheduler_reader`` (D62): the scheduling decision's inputs, SELECT only."""
control_plane/state/db.py:205:    global _SCHEDULER_READER_ENGINE
control_plane/state/db.py:206:    if _SCHEDULER_READER_ENGINE is None:
control_plane/state/db.py:207:        _SCHEDULER_READER_ENGINE = create_engine(
control_plane/state/db.py:208:            scheduler_reader_url(), pool_pre_ping=True, future=True
control_plane/state/db.py:210:    return _SCHEDULER_READER_ENGINE
control_plane/state/db.py:213:def get_scheduler_admin_engine() -> Engine:
control_plane/state/db.py:215:    global _SCHEDULER_ADMIN_ENGINE
control_plane/state/db.py:216:    if _SCHEDULER_ADMIN_ENGINE is None:
control_plane/state/db.py:217:        _SCHEDULER_ADMIN_ENGINE = create_engine(
control_plane/state/db.py:218:            scheduler_admin_url(), pool_pre_ping=True, future=True
control_plane/state/db.py:220:    return _SCHEDULER_ADMIN_ENGINE
control_plane/state/db.py:223:def get_scheduler_state_writer_engine() -> Engine:
control_plane/state/db.py:224:    """Pool for ``scheduler_state_writer`` (D62): ``scheduler_state`` and nothing else."""
control_plane/state/db.py:225:    global _SCHEDULER_STATE_WRITER_ENGINE
control_plane/state/db.py:226:    if _SCHEDULER_STATE_WRITER_ENGINE is None:
control_plane/state/db.py:227:        _SCHEDULER_STATE_WRITER_ENGINE = create_engine(
control_plane/state/db.py:228:            scheduler_state_writer_url(), pool_pre_ping=True, future=True
control_plane/state/db.py:230:    return _SCHEDULER_STATE_WRITER_ENGINE
control_plane/state/db.py:252:    global _SCHEDULER_READER_ENGINE, _SCHEDULER_ADMIN_ENGINE, _SCHEDULER_STATE_WRITER_ENGINE
control_plane/state/db.py:256:                   _GLOBAL_POLICY_ADMIN_ENGINE, _SCHEDULER_READER_ENGINE,
control_plane/state/db.py:257:                   _SCHEDULER_ADMIN_ENGINE, _SCHEDULER_STATE_WRITER_ENGINE,
control_plane/state/db.py:267:    _SCHEDULER_READER_ENGINE = None
control_plane/state/db.py:268:    _SCHEDULER_ADMIN_ENGINE = None
control_plane/state/db.py:269:    _SCHEDULER_STATE_WRITER_ENGINE = None
control_plane/state/db.py:278:SCHEDULER_READER_ROLE = "scheduler_reader"
control_plane/state/db.py:279:SCHEDULER_ADMIN_ROLE = "scheduler_admin"
control_plane/state/db.py:280:SCHEDULER_STATE_WRITER_ROLE = "scheduler_state_writer"
control_plane/state/db.py:332:def assert_scheduler_admin(conn: Connection) -> None:
control_plane/state/db.py:333:    """Refuse an enrollment write on a connection that is not scheduler_admin (D62)."""
control_plane/state/db.py:335:    if role != SCHEDULER_ADMIN_ROLE:
control_plane/state/db.py:337:            f"changing the scheduler's enrollment requires the {SCHEDULER_ADMIN_ROLE} "
control_plane/state/db.py:339:            "use scripts/manage_scheduler_enrollment.py."
control_plane/state/db.py:493:def scheduler_reader_scope(engagement_id: str) -> Iterator[Connection]:
control_plane/state/db.py:494:    """A read transaction bound to one engagement, as ``scheduler_reader`` (D62).
control_plane/state/db.py:501:    with _scoped(get_scheduler_reader_engine(), engagement_id) as conn:
control_plane/state/db.py:506:def scheduler_reader_enrollment_scope() -> Iterator[Connection]:
control_plane/state/db.py:507:    """The enrollment list, as ``scheduler_reader``, no engagement bound (D62).
control_plane/state/db.py:509:    ``scheduler_enrollment`` is global by design -- the reader has to list ids to know which
control_plane/state/db.py:513:    with get_scheduler_reader_engine().begin() as conn:
control_plane/state/db.py:532:def scheduler_state_writer_scope(engagement_id: str) -> Iterator[Connection]:
control_plane/state/db.py:533:    """A write transaction on ``scheduler_state`` for one engagement (D62); nothing else."""
control_plane/state/db.py:534:    with _scoped(get_scheduler_state_writer_engine(), engagement_id) as conn:
control_plane/state/db.py:539:def scheduler_admin_scope() -> Iterator[Connection]:
control_plane/state/db.py:541:    with get_scheduler_admin_engine().begin() as conn:
control_plane/state/db.py:549:    the scheduler's. The caller owns it and closes it."""
control_plane/state/db.py:561:def open_scheduler_lock_connection() -> Connection:
control_plane/state/db.py:571:        scheduler_reader_url(), poolclass=NullPool, future=True,
```

`control_plane/state/db.py:99-105`

```text
   99 | def scheduler_reader_url() -> str:
  100 |     """The scheduler's read connection string (D62): ``scheduler_reader``, decision inputs only."""
  101 |     return require_env(
  102 |         "SCHEDULER_READER_DATABASE_URL",
  103 |         hint="Run scripts/init_db.sh, or export SCHEDULER_READER_DATABASE_URL "
  104 |              "for the scheduler_reader role.",
  105 |     )
```

`control_plane/state/db.py:117-123`

```text
  117 | def scheduler_admin_url() -> str:
  118 |     """The enrollment writer's connection string (D62). Read only by the operator CLI."""
  119 |     return require_env(
  120 |         "SCHEDULER_ADMIN_DATABASE_URL",
  121 |         hint="Run scripts/init_db.sh, or export SCHEDULER_ADMIN_DATABASE_URL "
  122 |              "for the scheduler_admin role.",
  123 |     )
```

`control_plane/state/db.py:203-210`

```text
  203 | def get_scheduler_reader_engine() -> Engine:
  204 |     """Pool for ``scheduler_reader`` (D62): the scheduling decision's inputs, SELECT only."""
  205 |     global _SCHEDULER_READER_ENGINE
  206 |     if _SCHEDULER_READER_ENGINE is None:
  207 |         _SCHEDULER_READER_ENGINE = create_engine(
  208 |             scheduler_reader_url(), pool_pre_ping=True, future=True
  209 |         )
  210 |     return _SCHEDULER_READER_ENGINE
```

`control_plane/state/db.py:213-220`

```text
  213 | def get_scheduler_admin_engine() -> Engine:
  214 |     """Engine for the enrollment writer (D62). Operator CLI only."""
  215 |     global _SCHEDULER_ADMIN_ENGINE
  216 |     if _SCHEDULER_ADMIN_ENGINE is None:
  217 |         _SCHEDULER_ADMIN_ENGINE = create_engine(
  218 |             scheduler_admin_url(), pool_pre_ping=True, future=True
  219 |         )
  220 |     return _SCHEDULER_ADMIN_ENGINE
```

`control_plane/state/db.py:332-340`

```text
  332 | def assert_scheduler_admin(conn: Connection) -> None:
  333 |     """Refuse an enrollment write on a connection that is not scheduler_admin (D62)."""
  334 |     role = conn.execute(text("SELECT current_user")).scalar_one()
  335 |     if role != SCHEDULER_ADMIN_ROLE:
  336 |         raise PermissionError(
  337 |             f"changing the scheduler's enrollment requires the {SCHEDULER_ADMIN_ROLE} "
  338 |             f"connection (D62); this connection is {role!r}. It is an operator's action: "
  339 |             "use scripts/manage_scheduler_enrollment.py."
  340 |         )
```

`control_plane/state/db.py:505-514`

```text
  505 | @contextmanager
  506 | def scheduler_reader_enrollment_scope() -> Iterator[Connection]:
  507 |     """The enrollment list, as ``scheduler_reader``, no engagement bound (D62).
  508 | 
  509 |     ``scheduler_enrollment`` is global by design -- the reader has to list ids to know which
  510 |     engagement to open -- and is the only thing readable without one. Every engagement table still
  511 |     returns nothing on this connection.
  512 |     """
  513 |     with get_scheduler_reader_engine().begin() as conn:
  514 |         yield conn
```

`control_plane/state/db.py:538-542`

```text
  538 | @contextmanager
  539 | def scheduler_admin_scope() -> Iterator[Connection]:
  540 |     """The enrollment writer's transaction (D62). The operator CLI only; a test scans for that."""
  541 |     with get_scheduler_admin_engine().begin() as conn:
  542 |         yield conn
```

`control_plane/state/db.py:561-576`

```text
  561 | def open_scheduler_lock_connection() -> Connection:
  562 |     """One dedicated, unpooled, autocommit connection for the singleton lock (D62, D58-2).
  563 | 
  564 |     Its own engine and no pool: the advisory lock belongs to *this* session, so the session must
  565 |     not be shared, recycled or pre-pinged away. TCP keepalives make a vanished server noticed in
  566 |     seconds. The caller owns it and closes it.
  567 |     """
  568 |     from sqlalchemy.pool import NullPool
  569 | 
  570 |     engine = create_engine(
  571 |         scheduler_reader_url(), poolclass=NullPool, future=True,
  572 |         isolation_level="AUTOCOMMIT",
  573 |         connect_args={"keepalives": 1, "keepalives_idle": 5, "keepalives_interval": 2,
  574 |                       "keepalives_count": 3},
  575 |     )
  576 |     return engine.connect()
```

`control_plane/state/db.py:278-280`

```text
  278 | SCHEDULER_READER_ROLE = "scheduler_reader"
  279 | SCHEDULER_ADMIN_ROLE = "scheduler_admin"
  280 | SCHEDULER_STATE_WRITER_ROLE = "scheduler_state_writer"
```

### D.5 The operator CLI after which the enrolment CLI would be patterned [R]

`scripts/manage_scheduler_enrollment.py:1-30`

```text
    1 | """Enroll or withdraw an engagement from the scheduler -- an operator's action (D62, D58-1/A).
    2 | 
    3 |     python scripts/manage_scheduler_enrollment.py list
    4 |     python scripts/manage_scheduler_enrollment.py enroll   ENG-... --by alice
    5 |     python scripts/manage_scheduler_enrollment.py withdraw ENG-... --by alice
    6 | 
    7 | The scheduler touches only engagements listed here: an engagement nobody enrolled is never read,
    8 | never dispatched. This is the only code that writes the list, over the ``scheduler_admin``
    9 | connection, which nothing else may open (a test scans for that); neither ``cyberorch_app`` nor the
   10 | scheduler's own roles can write it. It asks for a person: without ``--yes`` it prints what will
   11 | happen and waits for the word on a terminal, and refuses when there is none. ``--yes`` exists for
   12 | scripted provisioning and is the caller's statement that a person already decided.
   13 | 
   14 | Every change writes a ``scope='global'`` audit record (``scheduler.enrolled`` / ``.withdrawn``).
   15 | Exit status: 0 done, 1 refused, 2 not confirmed.
   16 | """
   17 | 
   18 | from __future__ import annotations
   19 | 
   20 | import argparse
   21 | import sys
   22 | from pathlib import Path
   23 | 
   24 | REPO_ROOT = Path(__file__).resolve().parents[1]
   25 | sys.path.insert(0, str(REPO_ROOT))
   26 | 
   27 | from sqlalchemy import text  # noqa: E402
   28 | from sqlalchemy.exc import IntegrityError  # noqa: E402
   29 | 
   30 | from control_plane.config import load_dotenv  # noqa: E402
```

Its tests (names only):

`$ git grep -n 'def test_' -- tests/test_scheduler_cli.py`

```text
tests/test_scheduler_cli.py:39:def test_the_enrollment_script_will_not_act_without_a_person_to_confirm(engagement_id):
tests/test_scheduler_cli.py:45:def test_enroll_and_withdraw_are_audited_on_the_global_trail(engagement_id):
tests/test_scheduler_cli.py:71:def test_enrolling_an_engagement_that_does_not_exist_is_refused_by_the_database():
tests/test_scheduler_cli.py:76:def test_an_enrollment_whose_audit_record_cannot_be_written_is_not_made(engagement_id):
tests/test_scheduler_cli.py:84:def test_awaiting_dispatch_says_why_a_skipped_proposal_has_not_run(engagement_id, registry):
tests/test_scheduler_cli.py:134:def test_a_name_that_is_not_a_plain_identifier_is_refused_before_anything_is_asked(
tests/test_scheduler_cli.py:148:def test_the_rule_itself_refuses_what_an_argument_vector_cannot_carry():
tests/test_scheduler_cli.py:153:def test_an_engagement_id_that_is_not_a_plain_identifier_is_refused_the_same_way():
tests/test_scheduler_cli.py:160:def test_a_plain_identifier_is_accepted_and_is_what_the_audit_trail_and_the_table_hold(
tests/test_scheduler_cli.py:179:def test_the_listing_shows_an_old_row_with_an_odd_name_quoted(engagement_id):
```

**Effect on H5.** For H5b: a global table with per-role policies, an admin writer role and a reader role are created in `db/roles.sql` (an operator step) and granted in a migration, with a guard trigger and a unique live-row index; `cyberorch_app` has no grant on the scheduler's tables by test (`test_the_pipelines_own_role_has_no_grant_on_the_schedulers_tables`) and the scheduler's roles are wired in `control_plane/state/db.py` by URL, engine, role constant, assert function and scope; `tests/test_migrations_roundtrip.py` names the table at the lines above and `tests/test_migrations_rls_writes.py` does not, so edits to the former and the files in `db.py` and `roles.sql` are what the pattern implies for a new table (the proposal's H5b authorization list). Which role the loop connects as for the new table (proposal D.3 and plan P-1) is not settled by these facts.

## E. `claim_task`, `complete_task`, `engage_kill_switch`, and the task vocabulary

### E.1 Signatures and returns [R]

`control_plane/api/function_api.py:167-169`

```text
  167 | def create_task(
  168 |     conn: Connection, *, engagement_id: str, task: ProposedTask, created_by: str
  169 | ) -> str:
```

`control_plane/api/function_api.py:235-265`

```text
  235 | def claim_task(conn: Connection, *, engagement_id: str, agent_id: str) -> str | None:
  236 |     """Claim one queued task (§6).
  237 | 
  238 |     ``FOR UPDATE SKIP LOCKED`` plus a lease, so two workers cannot take the
  239 |     same task and a worker that dies does not strand it.
  240 |     """
  241 |     task_id = conn.execute(
  242 |         text("""
  243 |             UPDATE tasks
  244 |             SET status = 'claimed', owner_agent_id = :agent,
  245 |                 lease_expires_at = now() + interval '5 minutes', updated_at = now()
  246 |             WHERE task_id = (
  247 |                 SELECT task_id FROM tasks
  248 |                 WHERE status = 'queued' AND engagement_id = :eid
  249 |                 ORDER BY priority DESC, created_at ASC
  250 |                 FOR UPDATE SKIP LOCKED LIMIT 1
  251 |             )
  252 |             RETURNING task_id
  253 |         """),
  254 |         {"agent": agent_id, "eid": engagement_id},
  255 |     ).scalar_one_or_none()
  256 |     if task_id is not None:
  257 |         # Which agent took which task, and when. Without this the audit trail
  258 |         # attributes everything downstream to the orchestrator, and the agent
  259 |         # that actually did the work appears nowhere.
  260 |         record_audit(
  261 |             engagement_id=engagement_id, actor=agent_id, event_type="task.claimed",
  262 |             subject_type="task", subject_id=task_id,
  263 |             payload={"lease_seconds": 300},
  264 |         )
  265 |     return task_id
```

`control_plane/api/function_api.py:268-279`

```text
  268 | def complete_task(
  269 |     conn: Connection, *, engagement_id: str, task_id: str, result_summary: str, actor: str
  270 | ) -> None:
  271 |     conn.execute(
  272 |         text("UPDATE tasks SET status = 'completed', result_summary = :s, "
  273 |              "updated_at = now() WHERE task_id = :tid"),
  274 |         {"tid": task_id, "s": result_summary},
  275 |     )
  276 |     record_audit(
  277 |         engagement_id=engagement_id, actor=actor, event_type="task.completed",
  278 |         subject_type="task", subject_id=task_id, payload={"result": result_summary},
  279 |     )
```

`control_plane/orchestrator/engagement.py:279-281`

```text
  279 | def engage_kill_switch(
  280 |     conn: Connection, *, engagement_id: str, actor: str, reason: str
  281 | ) -> EngagementState:
```

`control_plane/orchestrator/engagement.py:310`

```text
  310 |     return EngagementState(engagement_id, KILLED, True, tuple(revoked))
```

### E.2 The task vocabulary and the table [R]

`control_plane/api/function_api.py:1322-1328`

```text
 1322 | #: §4.2's status vocabulary. Checked against rather than interpolated: the
 1323 | #: status filter is the one place a caller supplies something that reaches a
 1324 | #: WHERE clause, and an allowlist is what keeps it a filter rather than an
 1325 | #: opening.
 1326 | TASK_STATUSES = (
 1327 |     "queued", "claimed", "running", "completed", "failed", "cancelled",
 1328 | )
```

`control_plane/api/function_api.py:137`

```text
  137 | _LIVE_TASK_STATUSES = ("queued", "claimed", "running")
```

`db/migrations/versions/0001_core_schema.py:134-149`

```text
  134 | CREATE TABLE tasks (
  135 |     task_id           TEXT PRIMARY KEY,
  136 |     engagement_id     TEXT NOT NULL REFERENCES engagements(engagement_id),
  137 |     goal              TEXT NOT NULL,
  138 |     status            TEXT NOT NULL DEFAULT 'queued' CHECK (status IN
  139 |                           ('queued','claimed','running','completed','failed','cancelled')),
  140 |     owner_agent_id    TEXT,
  141 |     lease_expires_at  TIMESTAMPTZ,
  142 |     created_by        TEXT NOT NULL,
  143 |     parent_task_id    TEXT REFERENCES tasks(task_id),
  144 |     overlaps_with     TEXT[] NOT NULL DEFAULT '{}',
  145 |     priority          INTEGER NOT NULL DEFAULT 0,
  146 |     result_summary    TEXT,
  147 |     created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  148 |     updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
  149 | );
```

`db/migrations/versions/0006_task_identity.py:41-45`

```text
   41 |         ALTER TABLE tasks
   42 |             ADD COLUMN action           TEXT,
   43 |             ADD COLUMN canonical_target TEXT,
   44 |             ADD COLUMN scope_object_id  TEXT,
   45 |             ADD COLUMN identity_key     TEXT
```

Every statement in the code base that writes `tasks`:

`$ git grep -n -E 'UPDATE tasks|INSERT INTO tasks' -- control_plane scripts harness agents tool_gateway`

```text
control_plane/api/function_api.py:201:            INSERT INTO tasks (task_id, engagement_id, goal, created_by, priority,
control_plane/api/function_api.py:219:                UPDATE tasks
control_plane/api/function_api.py:243:            UPDATE tasks
control_plane/api/function_api.py:272:        text("UPDATE tasks SET status = 'completed', result_summary = :s, "
scripts/live_run/d17_supervisor.py:653:            text("UPDATE tasks SET status = 'completed', "
scripts/live_run/d17_supervisor.py:785:                "UPDATE tasks SET status = 'completed', result_summary = "
```

Triggers or functions on `tasks` in any migration, and every reader of `lease_expires_at` in the pipeline and the state queries:

`$ git grep -n -i -E 'trigger' -- db/migrations | grep -i tasks`

```text
(no output)
```

`$ git grep -n 'lease_expires_at' -- control_plane/api control_plane/state`

```text
control_plane/api/function_api.py:245:                lease_expires_at = now() + interval '5 minutes', updated_at = now()
control_plane/api/function_api.py:1252:                   lease_expires_at, created_at
control_plane/state/models.py:100:    _ts("lease_expires_at"),
control_plane/state/models.py:200:    _ts("issued_at"), _ts("lease_expires_at", nullable=False),
```

### E.3 What `complete_task` does to a `queued` task [R] [D]

[R] The statement in `complete_task` is `UPDATE tasks SET status = 'completed', result_summary = :s, updated_at = now() WHERE task_id = :tid` (line 272): it has no status predicate, no owner predicate and no lease predicate; the function neither checks the row count nor returns a value; the audit event `task.completed` is written in every case. The migrations create no trigger on `tasks` (the grep above) and the CHECK allows `completed` from any status. [D] Called on a `queued` task it sets `status='completed'` and `result_summary`, leaves `owner_agent_id` and `lease_expires_at` NULL, and writes `task.completed`; no claim is needed first. Called with an id the connection's engagement does not own, row-level security hides the row, no row changes, and the audit event is still written for the `engagement_id` argument. [N] This was read from the SQL and not executed.

[R] `claim_task`'s docstring says a lease means "a worker that dies does not strand it", but its own `WHERE` selects only `status = 'queued'`, and the grep for `lease_expires_at` above shows the column written by `claim_task`; no statement returns a `claimed` task to `queued` or reclaims an expired lease. `claim_task` takes no `task_id`: it claims the next `queued` task of the engagement by `priority DESC, created_at ASC`.

**Effect on H5.** Completing the loop's own never-claimed tasks (the 2026-11-14 residue decision) is possible with the existing function without a prior claim, and no existing operator tool clears a live task; the loop cannot name which task `claim_task` will return; `TASK_STATUSES` has `cancelled`, which `complete_task` cannot write; the closed vocabulary of `result_summary` (plan `L316`-`L324`) is the loop's, since the function stores any string.

## F. How the scheduler's signal handling and exit codes are tested

### F.1 The code [R]

`scripts/run_scheduler.py:33-47`

```text
   33 | def main(argv: list[str] | None = None) -> int:
   34 |     parser = argparse.ArgumentParser(description=__doc__,
   35 |                                      formatter_class=argparse.RawDescriptionHelpFormatter)
   36 |     parser.add_argument("--interval", type=float, default=5.0, help="seconds between ticks")
   37 |     parser.add_argument("--once", action="store_true", help="run one tick and exit")
   38 |     args = parser.parse_args(argv)
   39 |     load_dotenv()
   40 | 
   41 |     stop = threading.Event()
   42 |     for sig in (signal.SIGINT, signal.SIGTERM):
   43 |         signal.signal(sig, lambda *_: stop.set())
   44 |     code = Scheduler().run(interval=args.interval, max_ticks=1 if args.once else None,
   45 |                            stop_event=stop)
   46 |     print(f"scheduler stopped (exit {code})", file=sys.stderr)
   47 |     return code
```

`control_plane/scheduler/service.py:125-142`

```text
  125 |     def run(self, *, interval: float = 5.0, max_ticks: int | None = None,
  126 |             stop_event: threading.Event | None = None) -> int:
  127 |         """Serve until stopped; returns the process exit code."""
  128 |         stop_event = stop_event or threading.Event()
  129 |         try:
  130 |             self.start()
  131 |             ticks = 0
  132 |             while not stop_event.is_set() and (max_ticks is None or ticks < max_ticks):
  133 |                 self.tick()
  134 |                 ticks += 1
  135 |                 if max_ticks is None or ticks < max_ticks:
  136 |                     stop_event.wait(interval)
  137 |         except BaseException as exc:  # noqa: BLE001
  138 |             stop = _translate(exc)
  139 |             self.stop(stop.reason)
  140 |             return stop.exit_code
  141 |         self.stop(vocab.STOP_SIGNAL)
  142 |         return vocab.EXIT_OK
```

`control_plane/scheduler/vocab.py:63-80`

```text
   63 | EXIT_OK = 0
   64 | EXIT_UNEXPECTED = 1
   65 | EXIT_LOCK_HELD = 2
   66 | EXIT_AUDIT_FAILED = 3
   67 | EXIT_DB_LOST = 4
   68 | EXIT_DOCKER_LOST = 5
   69 | EXIT_LOCK_LOST = 6
   70 | EXIT_NOT_ADVANCED = 7
   71 | 
   72 | EXIT_CODE_OF_STOP = {
   73 |     STOP_SIGNAL: EXIT_OK,
   74 |     STOP_UNEXPECTED: EXIT_UNEXPECTED,
   75 |     STOP_AUDIT_FAILED: EXIT_AUDIT_FAILED,
   76 |     STOP_DB_LOST: EXIT_DB_LOST,
   77 |     STOP_DOCKER_LOST: EXIT_DOCKER_LOST,
   78 |     STOP_LOCK_LOST: EXIT_LOCK_LOST,
   79 |     STOP_NOT_ADVANCED: EXIT_NOT_ADVANCED,
   80 | }
```

### F.2 The signal handling [R]

`$ git grep -n -E 'SIGTERM|SIGINT|signal\.signal' -- scripts/run_scheduler.py control_plane/scheduler tests/test_scheduler_actions.py tests/test_scheduler_allowlist.py tests/test_scheduler_cli.py tests/test_scheduler_e2e.py tests/test_scheduler_policy_change.py tests/test_scheduler_roles.py tests/test_scheduler_service.py tests/test_scheduler_skips.py tests/test_scheduler_structure.py tests/scheduler_support.py`

```text
scripts/run_scheduler.py:42:    for sig in (signal.SIGINT, signal.SIGTERM):
scripts/run_scheduler.py:43:        signal.signal(sig, lambda *_: stop.set())
```

`$ git grep -n 'run_scheduler' -- tests`

```text
(no output)
```

`$ git grep -n 'stop_event' -- tests control_plane/scheduler scripts/run_scheduler.py`

```text
control_plane/scheduler/service.py:126:            stop_event: threading.Event | None = None) -> int:
control_plane/scheduler/service.py:128:        stop_event = stop_event or threading.Event()
control_plane/scheduler/service.py:132:            while not stop_event.is_set() and (max_ticks is None or ticks < max_ticks):
control_plane/scheduler/service.py:136:                    stop_event.wait(interval)
scripts/run_scheduler.py:45:                           stop_event=stop)
tests/test_reconciler_vanishing.py:124:    assert r.serve(interval=1, max_passes=1, stop_event=threading.Event()) == 5
```

[R] The handler (`signal.signal` for `SIGINT` and `SIGTERM`, setting a `threading.Event`) exists only in `scripts/run_scheduler.py`; no file under `tests/` mentions `run_scheduler`, and the only `stop_event` a test passes is the reconciler's (`tests/test_reconciler_vanishing.py:124`). [D] No test sends a signal to the scheduler or imports its command; the `stop_event` branch of `Scheduler.run` (the loop condition and the `stop_event.wait(interval)` between ticks) is exercised by no scheduler test, and the closing `self.stop(vocab.STOP_SIGNAL); return vocab.EXIT_OK` is reached by tests only through `max_ticks`. `test_a_decision_recorded_before_a_crash_is_counted_at_the_next_start` calls `sched.stop(vocab.STOP_SIGNAL)` directly (line 218), not through a signal.

### F.3 The exit-code table [R]

`$ git grep -n 'def test_' -- tests/test_scheduler_service.py`

```text
tests/test_scheduler_service.py:59:def test_a_second_instance_is_refused_before_it_reads_anything(world):
tests/test_scheduler_service.py:72:def test_the_lock_is_free_again_once_the_first_instance_has_stopped(world):
tests/test_scheduler_service.py:80:def test_a_killed_lock_connection_stops_dispatching(world):
tests/test_scheduler_service.py:104:def test_run_returns_the_lock_lost_exit_code(world):
tests/test_scheduler_service.py:125:def test_if_the_decision_cannot_be_audited_nothing_is_dispatched(world, monkeypatch):
tests/test_scheduler_service.py:157:def test_a_lost_database_connection_stops_the_service_with_its_own_code(world, monkeypatch):
tests/test_scheduler_service.py:167:def test_an_unreachable_docker_stops_the_service_before_the_dispatch(world, monkeypatch):
tests/test_scheduler_service.py:175:def test_an_unexpected_error_stops_the_service(world, monkeypatch):
tests/test_scheduler_service.py:184:def test_a_dispatched_proposal_that_is_still_approved_afterwards_stops_the_service(
tests/test_scheduler_service.py:201:def test_a_decision_recorded_before_a_crash_is_counted_at_the_next_start(world):
```

`$ git grep -n -E 'EXIT_[A-Z_]+' -- tests`

```text
tests/test_docker_health.py:119:    assert vocab.EXIT_DOCKER_LOST == 5
tests/test_docker_health.py:135:    assert Scheduler(sandbox=sandbox).run(interval=0, max_ticks=3) == vocab.EXIT_DOCKER_LOST == 5
tests/test_docker_health_structure.py:76:        if "STOP_DOCKER_LOST" in text or "EXIT_DOCKER_LOST" in text:
tests/test_dp15_enable_stage1.py:272:    assert run(tmp_path) == st.EXIT_OK
tests/test_dp15_enable_stage1.py:291:    assert run(tmp_path) == st.EXIT_REFUSED
tests/test_dp15_enable_stage1.py:307:    assert run(tmp_path) == st.EXIT_REFUSED
tests/test_dp15_enable_stage1.py:319:    assert run(tmp_path) == st.EXIT_REFUSED
tests/test_dp15_enable_stage1.py:333:    assert run(tmp_path) == st.EXIT_REFUSED
tests/test_dp15_enable_stage1.py:343:    assert st.main(["--wordings-dir", str(tmp_path), "--classes", cls]) == st.EXIT_USAGE
tests/test_dp15_enable_stage1.py:349:    assert st.main(["--wordings-dir", str(tmp_path), "--execute", "--seed", "1"]) == st.EXIT_USAGE
tests/test_dp15_enable_stage1.py:368:    assert run(tmp_path) == st.EXIT_OK
tests/test_dp15_enable_stage1.py:407:        assert code in (st.EXIT_OK, st.EXIT_REFUSED)       # refused only if that database is dirty
tests/test_dp15_enable_stage1.py:409:        assert code == st.EXIT_REFUSED and leg_b.endswith("REFUSED")   # any other database
tests/test_dp15_enable_stage1.py:495:    assert run(tmp_path) == st.EXIT_REFUSED
tests/test_dp15_enable_stage1.py:507:    assert run(tmp_path) == st.EXIT_REFUSED
tests/test_dp15_enable_stage1.py:525:    assert run(tmp_path) == st.EXIT_REFUSED
tests/test_dp15_enable_stage1.py:546:    assert run(tmp_path) == st.EXIT_OK
tests/test_dp15_enable_stage1.py:583:    assert run(tmp_path) == st.EXIT_OK
tests/test_dp15_enable_stage1.py:598:    assert run(tmp_path) == st.EXIT_REFUSED
tests/test_dp15_enable_stage1.py:610:    assert run(tmp_path) == st.EXIT_REFUSED
tests/test_dp15_enable_stage1.py:612:    assert run(tmp_path, "--leg-b-database", "elsewhere") == st.EXIT_OK
tests/test_dp15_enable_stage1.py:624:    assert run(tmp_path) == st.EXIT_REFUSED
tests/test_dp15_record_mode.py:342:    assert done.returncode == rm.EXIT_PRECONDITION, done.stderr
tests/test_dp15_record_mode.py:352:    assert rm.main([]) == rm.EXIT_PRECONDITION
tests/test_dp15_record_mode.py:382:    assert rm.main(flags) == rm.EXIT_USAGE
tests/test_dp15_record_mode.py:863:    assert rm.execute(run_args(), rm.build_plan()) == rm.EXIT_PRECONDITION
tests/test_dp15_record_mode.py:874:    assert rm.execute(run_args(), rm.build_plan()) == rm.EXIT_PRECONDITION
tests/test_dp15_record_mode.py:879:    assert rm.execute(run_args(allow_nonempty=True), rm.build_plan()) == rm.EXIT_PRECONDITION
tests/test_dp15_record_mode.py:889:    assert rm.execute(run_args(), rm.build_plan()) == rm.EXIT_PRECONDITION
tests/test_dp15_record_mode.py:903:    assert rm.execute(run_args(allow_nonempty=allow), rm.build_plan()) == rm.EXIT_PRECONDITION
tests/test_dp15_record_mode.py:925:    assert rm.execute(run_args(), rm.build_plan()) == rm.EXIT_USAGE
tests/test_dp15_stage1_analysis.py:274:    assert an.look(path) == an.EXIT_OK
tests/test_dp15_stage1_analysis.py:284:    assert an.look(path) == an.EXIT_OK
tests/test_dp15_stage1_analysis.py:286:    assert an.look(path) == an.EXIT_USAGE
tests/test_dp15_stage1_analysis.py:289:    assert an.look(path, reason="   ") == an.EXIT_USAGE                  # a blank reason is none
tests/test_dp15_stage1_analysis.py:291:    assert an.look(path, reason="the analysis script had a typo in its table") == an.EXIT_OK
tests/test_dp15_stage1_analysis.py:304:    assert an.look(path, reason="the record was rewritten") == an.EXIT_OK
tests/test_dp15_stage1_analysis.py:309:    assert an.look(tmp_path / "missing.jsonl") == an.EXIT_USAGE
tests/test_dp15_stage1_analysis.py:312:    assert an.look(bad) == an.EXIT_USAGE
tests/test_dp15_stage1_analysis.py:319:    assert an.main(["--record", str(path)]) == an.EXIT_OK
tests/test_dp15_stage1_analysis.py:320:    assert an.main(["--record", str(path)]) == an.EXIT_USAGE
tests/test_dp15_stage1_analysis.py:321:    assert an.main(["--record", str(path), "--reason", "again"]) == an.EXIT_OK
tests/test_dp15_stage1_run.py:85:    assert out.stopped is None and out.exit_code == run.EXIT_OK
tests/test_dp15_stage1_run.py:129:    assert out.exit_code == run.EXIT_STOPPED
tests/test_dp15_stage1_run.py:149:    assert out.stopped == "the cost cap (US$2.00) was reached" and out.exit_code == run.EXIT_STOPPED
tests/test_dp15_stage1_run.py:273:    assert code == run.EXIT_OK and len(calls) == 190 and end["stopped"] is None
tests/test_dp15_stage1_run.py:297:    assert "look 1 of this record" in text and "C1: MET" in text and code == run.EXIT_OK
tests/test_dp15_stage1_run.py:315:    assert code == run.EXIT_STOPPED
tests/test_dp15_stage1_run.py:330:    assert code == run.EXIT_STOPPED and world.begun == 0
tests/test_dp15_stage1_run.py:336:    assert code == run.EXIT_OK
tests/test_dp15_stage1_run.py:405:        return run.EXIT_OK
tests/test_dp15_stage1_run.py:420:    assert cli("--yes") == run.EXIT_OK
tests/test_dp15_stage1_run.py:434:    assert cli("--yes") == run.EXIT_REFUSED
tests/test_dp15_stage1_run.py:443:    assert cli("--yes") == run.EXIT_REFUSED
tests/test_dp15_stage1_run.py:450:    assert cli("--yes") == run.EXIT_REFUSED
tests/test_dp15_stage1_run.py:457:    assert cli("--yes") == run.EXIT_REFUSED
tests/test_dp15_stage1_run.py:464:    assert cli("--yes", flag, value) == run.EXIT_REFUSED
tests/test_dp15_stage1_run.py:475:    assert cli("--yes", "--concurrency", "3") == run.EXIT_REFUSED
tests/test_dp15_stage1_run.py:481:    assert cli("--yes") == run.EXIT_REFUSED
tests/test_dp15_stage1_run.py:489:    assert cli("--yes") == run.EXIT_REFUSED
tests/test_dp15_stage1_run.py:496:    assert cli() == run.EXIT_USAGE
tests/test_dp15_stage1_run.py:515:    assert code == run.EXIT_OK
tests/test_dp15_stage1_run.py:525:    assert an.look(record) == an.EXIT_USAGE                      # a second look needs a reason
tests/test_dp15_stage1_run.py:694:    assert cli("--yes") == run.EXIT_REFUSED
tests/test_dp15_stage1_run.py:703:    assert cli("--yes") == run.EXIT_REFUSED
tests/test_plan_fit_classes.py:86:    assert c.ADMIT_WINDOW == c.EXIT_WINDOW
tests/test_reconciler_evidence.py:712:    from control_plane.reconciler.service import EXIT_CONFIG_REFUSED, StopService
tests/test_reconciler_evidence.py:719:    assert stopped.value.exit_code == EXIT_CONFIG_REFUSED == 8
tests/test_reconciler_flags.py:41:EXIT_REFUSED = 7
tests/test_reconciler_flags.py:310:    assert done.returncode == EXIT_REFUSED, (done.returncode, done.stderr)
tests/test_reconciler_flags.py:329:    assert done.returncode == EXIT_REFUSED, (done.returncode, done.stderr)
tests/test_reconciler_flags.py:338:    assert done.returncode == EXIT_REFUSED, done.stderr
tests/test_reconciler_flags.py:348:    assert status == EXIT_REFUSED, shown
tests/test_reconciler_service.py:256:        assert r.serve(max_passes=1) == service.EXIT_LOCK_HELD == 2
tests/test_reconciler_service.py:274:    assert r.serve(max_passes=3, interval=0) == service.EXIT_AUDIT_FAILED == 3
tests/test_reconciler_service.py:304:    (OperationalError("SELECT 1", {}, Exception("connection lost")), service.EXIT_DB_LOST),
tests/test_reconciler_service.py:305:    (DockerException("daemon gone"), service.EXIT_DOCKER_LOST),
tests/test_reconciler_service.py:306:    (ConnectionError("socket closed"), service.EXIT_DOCKER_LOST),
tests/test_reconciler_service.py:307:    (RuntimeError("something nobody planned for"), service.EXIT_UNEXPECTED),
tests/test_reconciler_service.py:324:    assert r.serve(max_passes=1) == service.EXIT_UNEXPECTED
tests/test_reconciler_service.py:329:    codes = {"ok": service.EXIT_OK, "unexpected": service.EXIT_UNEXPECTED,
tests/test_reconciler_service.py:330:             "lock_held": service.EXIT_LOCK_HELD, "audit": service.EXIT_AUDIT_FAILED,
tests/test_reconciler_service.py:331:             "db": service.EXIT_DB_LOST, "docker": service.EXIT_DOCKER_LOST,
tests/test_reconciler_service.py:332:             "lock_lost": service.EXIT_LOCK_LOST, "config": service.EXIT_CONFIG_REFUSED}
tests/test_reconciler_service.py:334:    assert (service.EXIT_OK, service.EXIT_UNEXPECTED, service.EXIT_LOCK_HELD,
tests/test_reconciler_service.py:335:            service.EXIT_AUDIT_FAILED, service.EXIT_DB_LOST, service.EXIT_DOCKER_LOST,
tests/test_reconciler_service.py:336:            service.EXIT_LOCK_LOST) == (
tests/test_reconciler_service.py:337:        scheduler_vocab.EXIT_OK, scheduler_vocab.EXIT_UNEXPECTED, scheduler_vocab.EXIT_LOCK_HELD,
tests/test_reconciler_service.py:338:        scheduler_vocab.EXIT_AUDIT_FAILED, scheduler_vocab.EXIT_DB_LOST,
tests/test_reconciler_service.py:339:        scheduler_vocab.EXIT_DOCKER_LOST, scheduler_vocab.EXIT_LOCK_LOST)
tests/test_reconciler_service.py:340:    assert set(service.EXIT_CODE_OF_STOP) == set(emit.STOP_REASONS)
tests/test_reconciler_service.py:613:    assert done.returncode == service.EXIT_CONFIG_REFUSED == 8
tests/test_scheduler_policy_change.py:59:    assert exit_code == vocab.EXIT_OK                   # the service carries on, it does not stop
tests/test_scheduler_policy_change.py:100:    assert code == vocab.EXIT_OK
tests/test_scheduler_service.py:64:        assert code == vocab.EXIT_LOCK_HELD
tests/test_scheduler_service.py:76:    assert Scheduler(sandbox=sandbox).run(interval=0, max_ticks=1) == vocab.EXIT_OK
tests/test_scheduler_service.py:97:        assert stop.value.exit_code == vocab.EXIT_LOCK_LOST
tests/test_scheduler_service.py:117:    assert sched.run(interval=0, max_ticks=3) == vocab.EXIT_LOCK_LOST
tests/test_scheduler_service.py:136:    assert Scheduler(sandbox=sandbox).run(interval=0, max_ticks=3) == vocab.EXIT_AUDIT_FAILED
tests/test_scheduler_service.py:163:    assert Scheduler(sandbox=sandbox).run(interval=0, max_ticks=2) == vocab.EXIT_DB_LOST
tests/test_scheduler_service.py:170:    assert Scheduler(sandbox=sandbox).run(interval=0, max_ticks=2) == vocab.EXIT_DOCKER_LOST
tests/test_scheduler_service.py:181:    assert code == vocab.EXIT_UNEXPECTED
tests/test_scheduler_service.py:192:    assert Scheduler(sandbox=sandbox).run(interval=0, max_ticks=3) == vocab.EXIT_NOT_ADVANCED
tests/test_scheduler_skips.py:87:    assert exit_code == vocab.EXIT_OK          # twelve ticks, each of which found the proposal
tests/test_scheduler_skips.py:125:    assert sched.run(interval=0, max_ticks=6) == vocab.EXIT_OK
tests/test_scheduler_skips.py:175:    assert sched.run(interval=0, max_ticks=6) == vocab.EXIT_OK       # skipped, not a stop
```

`$ git grep -n 'EXIT_CODE_OF_STOP' -- tests control_plane scripts`

```text
control_plane/reconciler/service.py:81:EXIT_CODE_OF_STOP = {
control_plane/reconciler/service.py:94:        self.exit_code = exit_code if exit_code is not None else EXIT_CODE_OF_STOP.get(
control_plane/scheduler/service.py:37:        self.exit_code = exit_code if exit_code is not None else vocab.EXIT_CODE_OF_STOP.get(
control_plane/scheduler/vocab.py:72:EXIT_CODE_OF_STOP = {
tests/test_reconciler_service.py:340:    assert set(service.EXIT_CODE_OF_STOP) == set(emit.STOP_REASONS)
```

`tests/test_reconciler_service.py:340`

```text
  340 |     assert set(service.EXIT_CODE_OF_STOP) == set(emit.STOP_REASONS)
```

[R] Each scheduler exit code is asserted by a test that provokes its own cause: `EXIT_LOCK_HELD` (`test_a_second_instance_is_refused_before_it_reads_anything`), `EXIT_OK` (`test_the_lock_is_free_again_once_the_first_instance_has_stopped`), `EXIT_LOCK_LOST`, `EXIT_AUDIT_FAILED`, `EXIT_DB_LOST`, `EXIT_DOCKER_LOST` (here and in `tests/test_docker_health.py:135`), `EXIT_UNEXPECTED`, `EXIT_NOT_ADVANCED`, at the lines of the second command above. The table `EXIT_CODE_OF_STOP` is referenced by no test of the scheduler (the third command lists only its definition and use in `control_plane/scheduler`); the equivalent table of the reconciler is compared with its stop reasons by `tests/test_reconciler_service.py:340`. Nothing tests that the scheduler's seven codes are distinct from each other or that the `main` function returns the value `run` returned.

**Effect on H5.** The scheduler's signal path and exit-code table are tested only by cause, in process, through `Scheduler.run(max_ticks=...)`; a harness test of SIGTERM or of a distinct-code table has no scheduler test to copy and would be the first (design test 9 and the proposal's a1 and a9 pieces).

## G. `propose_action` and `request_idempotency_key`

### G.1 The code [R]

`control_plane/api/function_api.py:555-561`

```text
  555 |     **Retrying is safe.** ``idempotency_key`` names the request: a second call with the same key
  556 |     does not create a second proposal. It finds the first, reads its stage, and carries on from the
  557 |     next stage -- never repeating one that committed (no second decision, no second capability, no
  558 |     second dispatch). With no key every call is a new proposal, as before. A key reused for a
  559 |     *different* action or target is refused. A resumed call needs the same arguments it was first
  560 |     given; a proposal found at ``dispatching`` is not re-dispatched (the container may be running
  561 |     or may have run: that is ``unknown_outcome``, the reconciler's, §8.8).
```

`control_plane/api/function_api.py:622-666`

```text
  622 |     # --- Stage 0: the proposal row, committed -------------------------------
  623 |     key = idempotency_key or f"idem-{proposal_id}"
  624 |     with engagement_scope(engagement_id) as conn:
  625 |         inserted = _persist_proposal(conn, engagement_id, proposal_id, proposal, target,
  626 |                                      agent_id, key)
  627 |         if inserted:
  628 |             # Attributed to the agent, unlike everything after it, which the
  629 |             # orchestrator does. "Which agent asked for this" is otherwise only in the
  630 |             # proposal row, and the audit trail should stand on its own.
  631 |             record_audit(
  632 |                 engagement_id=engagement_id, actor=agent_id, event_type="proposal.submitted",
  633 |                 subject_type="action_proposal", subject_id=proposal_id,
  634 |                 payload={
  635 |                     "action": proposal.action,
  636 |                     "target": target.normalized,
  637 |                     "authorization": dict(proposal.authorization),
  638 |                     "discovery": dict(proposal.discovery),
  639 |                     "task_id": proposal.task_id,
  640 |                 },
  641 |             )
  642 |         else:
  643 |             existing = conn.execute(
  644 |                 text("SELECT proposal_id, action, target ->> 'normalized' AS normalized "
  645 |                      "FROM action_proposals "
  646 |                      "WHERE engagement_id = :e AND request_idempotency_key = :k"),
  647 |                 {"e": engagement_id, "k": key},
  648 |             ).mappings().one()
  649 |     if not inserted:
  650 |         proposal_id = existing["proposal_id"]
  651 |         if existing["action"] != proposal.action or existing["normalized"] != target.normalized:
  652 |             # The key names a request; a different request under it is a bug in the caller, and
  653 |             # silently resuming the first would run something nobody asked for under this name.
  654 |             record_audit(
  655 |                 engagement_id=engagement_id, actor=actor,
  656 |                 event_type="proposal.rejected", subject_type="action_proposal",
  657 |                 subject_id=proposal_id, decision=DENY,
  658 |                 reasons=("idempotency_key_reused_with_a_different_request",),
  659 |                 payload={"action": proposal.action, "target": target.normalized},
  660 |             )
  661 |             return ActionOutcome(
  662 |                 decision=DENY, proposal_id=proposal_id,
  663 |                 deny_reasons=("idempotency_key_reused_with_a_different_request",),
  664 |                 failure="idempotency key names a different action or target",
  665 |             )
  666 |     return _drive(run, proposal_id)
```

`control_plane/api/function_api.py:1479-1535`

```text
 1479 | def _persist_proposal(
 1480 |     conn: Connection, engagement_id: str, proposal_id: str,
 1481 |     proposal: ProposedAction, target, agent_id: str, idempotency_key: str,
 1482 | ) -> bool:
 1483 |     """Insert the proposal; False if one with this idempotency key already exists (D60).
 1484 | 
 1485 |     ``ON CONFLICT DO NOTHING`` on the table's own unique index (engagement, key), so two callers
 1486 |     that race with the same key cannot both create a proposal -- the loser gets False and resumes
 1487 |     the winner's.
 1488 |     """
 1489 |     import json
 1490 | 
 1491 |     inserted = conn.execute(
 1492 |         text("""
 1493 |             INSERT INTO action_proposals (proposal_id, engagement_id, task_id,
 1494 |                 agent_id, request_idempotency_key, action, target, "authorization",
 1495 |                 discovery, resources, expected_data, writes_data, changes_state,
 1496 |                 reason, requested_capability_ttl_seconds)
 1497 |             VALUES (:pid, :eid, :tid, :agent, :key, :action, CAST(:target AS jsonb),
 1498 |                     CAST(:auth AS jsonb), CAST(:disc AS jsonb), :resources,
 1499 |                     :expected, :writes, :changes, :reason, :ttl)
 1500 |             ON CONFLICT (engagement_id, request_idempotency_key) DO NOTHING
 1501 |             RETURNING proposal_id
 1502 |         """),
 1503 |         {
 1504 |             "pid": proposal_id, "eid": engagement_id, "tid": proposal.task_id,
 1505 |             "agent": agent_id, "key": idempotency_key, "action": proposal.action,
 1506 |             # D30: the canonical target *plus* the execution parameters it does
 1507 |             # not carry. `CanonicalTarget.as_dict()` describes what the target
 1508 |             # *is* -- logical_identity, port, path, normalized -- because that is
 1509 |             # what authorization and the §7 fingerprint are about. It has no
 1510 |             # `ports` or `scan_type`, since those say how to run the tool rather
 1511 |             # than what is being targeted.
 1512 |             #
 1513 |             # Storing only the canonical form silently dropped them, and the two
 1514 |             # paths that later need them diverged: `propose_action` still had the
 1515 |             # in-memory proposal and honoured the request, while `grant_approval`
 1516 |             # -- which may run minutes later in another process, holding only this
 1517 |             # row -- found the keys missing and fell through to the defaults. A
 1518 |             # proposal asking for ports 443 came back from human approval as a
 1519 |             # capability for port 8080.
 1520 |             #
 1521 |             # Canonical values are applied last, so they stay authoritative for
 1522 |             # every key they define; the agent's extras survive alongside them.
 1523 |             "target": json.dumps(
 1524 |                 {**dict(proposal.target), **target.as_dict()}, default=str
 1525 |             ),
 1526 |             "auth": json.dumps(dict(proposal.authorization), default=str),
 1527 |             "disc": json.dumps(dict(proposal.discovery), default=str),
 1528 |             "resources": list(proposal.resources),
 1529 |             "expected": list(proposal.expected_data),
 1530 |             "writes": proposal.writes_data, "changes": proposal.changes_state,
 1531 |             "reason": proposal.reason,
 1532 |             "ttl": proposal.requested_capability_ttl_seconds,
 1533 |         },
 1534 |     ).scalar_one_or_none()
 1535 |     return inserted is not None
```

`db/migrations/versions/0001_core_schema.py:166`

```text
  166 |     request_idempotency_key       TEXT NOT NULL,
```

`db/migrations/versions/0001_core_schema.py:188-189`

```text
  188 | CREATE UNIQUE INDEX action_proposals_idempotency ON action_proposals
  189 |     (engagement_id, request_idempotency_key);
```

`control_plane/state/models.py:121`

```text
  121 |     Column("request_idempotency_key", Text, nullable=False),
```

### G.2 Behaviour on a second call with the same key [R] [D]

[R] The column is `action_proposals.request_idempotency_key`, `TEXT NOT NULL`, unique together with `engagement_id`. The default when no key is given is `f"idem-{proposal_id}"` (line 623), a fresh `proposal_id` per call, so a call with no key is always a new proposal. [R] With the same key and the **same action and the same normalized target**, `_persist_proposal` returns False (`ON CONFLICT ... DO NOTHING`), the existing row is read, `proposal_id` is replaced by the existing one, and `_drive` carries the proposal on from the stage it is in (`received` is decided, `decided` is issued, `capability_issued` is dispatched; at `awaiting_approval`, `approved`, `dispatching`, `recorded`, `closed` and `abandoned` it only reports the outcome from the rows). A proposal found at `dispatching` is not re-dispatched. [R] With the same key and a **different action or normalized target**, the call writes a `proposal.rejected` audit event with reason `idempotency_key_reused_with_a_different_request` and returns an `ActionOutcome` with `decision=DENY`, `deny_reasons` that reason and `failure="idempotency key names a different action or target"`; no new proposal is created. [D] The comparison covers only `action` and `target.normalized`; a different `task_id`, `agent_id` or reason under the same key is not compared and the existing row is kept. [D] Two concurrent callers with one key leave one proposal (the unique index decides). [D] The key has no length or format rule beyond `TEXT`.

The tests that pin it (bodies as quoted):

`tests/test_pipeline_stages.py:612-627`

```text
  612 | def test_a_retry_after_the_decision_does_not_decide_again(world, monkeypatch):
  613 |     """Stage 1 committed, stage 2 failed. The retry must not repeat stage 1 -- no second
  614 |     reviewer call, no second ``policy.decided``."""
  615 |     reviewer = CountingReviewer()
  616 |     with monkeypatch.context() as patched:
  617 |         patched.setattr(function_api, "issue_capability", _boom)
  618 |         with pytest.raises(RuntimeError):
  619 |             go(world, reviewer=reviewer)
  620 |     assert only(snapshot(world["engagement_id"]))["stage"] == stages.DECIDED
  621 | 
  622 |     go(world, reviewer=reviewer)
  623 |     snap = snapshot(world["engagement_id"])
  624 |     assert reviewer.calls == 1
  625 |     assert snap["audit"].get("policy.decided") == 1
  626 |     assert snap["audit"].get("policy_reviewer.opinion") == 1
  627 |     assert only(snap)["stage"] == stages.RECORDED and snap["capabilities"] == 1
```

`tests/test_pipeline_stages.py:630-635`

```text
  630 | def test_a_key_reused_for_a_different_request_is_refused_not_resumed(world):
  631 |     go(world)
  632 |     other = go(world, target="10.82.0.77")
  633 |     assert other.decision == "DENY"
  634 |     assert other.deny_reasons == ("idempotency_key_reused_with_a_different_request",)
  635 |     assert len(snapshot(world["engagement_id"])["proposals"]) == 1
```

`tests/test_pipeline_stages.py:638-641`

```text
  638 | def test_calls_without_a_key_are_independent_proposals(world):
  639 |     go(world, key=None)
  640 |     go(world, key=None)
  641 |     assert len(snapshot(world["engagement_id"])["proposals"]) == 2
```

`tests/test_pipeline_stages.py:644-670`

```text
  644 | def test_two_callers_with_one_key_leave_one_of_everything(world):
  645 |     """The two race: both find no proposal, or one inserts and the other resumes mid-stage.
  646 |     Whichever way it falls, one stage-transition wins each stage and the rest repeat nothing."""
  647 |     barrier = threading.Barrier(2)
  648 |     sandbox = FakeSandbox(during=lambda _k: time.sleep(0.3))
  649 |     results: list = []
  650 |     errors: list = []
  651 | 
  652 |     def caller():
  653 |         try:
  654 |             barrier.wait()
  655 |             results.append(go(world, sandbox=sandbox))
  656 |         except BaseException as exc:  # noqa: BLE001
  657 |             errors.append(exc)
  658 | 
  659 |     threads = [threading.Thread(target=caller) for _ in range(2)]
  660 |     [t.start() for t in threads]
  661 |     [t.join(timeout=120) for t in threads]
  662 |     assert not errors, errors
  663 |     assert len(results) == 2
  664 |     snap = snapshot(world["engagement_id"])
  665 |     assert_coherent(snap)
  666 |     assert len(snap["proposals"]) == 1
  667 |     assert snap["audit"].get("policy.decided") == 1
  668 |     assert snap["capabilities"] == 1
  669 |     assert snap["runs"] == ["succeeded"] and sandbox.calls == 1
  670 |     assert snap["audit"].get("tool_run.started") == 1
```

[R] The existing live script that calls `propose_action` passes no key (ACCEPTANCE 5.54: "The harness passes no `idempotency_key`, so each call is an independent proposal"); `task_id` is a field of `ProposedAction` and is stored in `action_proposals.task_id` by the insert quoted in C.3.

**Effect on H5.** The key is per engagement and compared only on action and target: a key of the form chosen for H5 would resume the earlier proposal for the same task and attempt and refuse a key reused for different work (H5-6, H5-26, proposal 3.5); the stored value is read from `action_proposals.request_idempotency_key`.

## H. Advisory locks

### H.1 Every use in the repository [R]

`$ git grep -n -E 'pg_try_advisory|pg_advisory|advisory_lock' -- . ':!docs'`

```text
control_plane/reconciler/lock.py:49:        got = bool(self._conn.execute(text("SELECT pg_try_advisory_lock(:k)"),
control_plane/scheduler/lock.py:5:lease to tune. A second instance's ``pg_try_advisory_lock`` returns false and it exits before
control_plane/scheduler/lock.py:48:        got = bool(self._conn.execute(text("SELECT pg_try_advisory_lock(:k)"),
scripts/mutations_d62_d63.py:81:                    '        got = bool(self._conn.execute(text("SELECT pg_try_advisory_lock(:k)"),\n'
```

`$ git grep -n -i 'advisory' -- harness`

```text
(no output)
```

`$ git grep -n -E 'def open_[a-z_]*lock_connection' -- .`

```text
control_plane/state/db.py:545:def open_reconciler_lock_connection() -> Connection:
control_plane/state/db.py:561:def open_scheduler_lock_connection() -> Connection:
```

[R] The first command lists the scheduler's lock (`control_plane/scheduler/lock.py`), the reconciler's (`control_plane/reconciler/lock.py`) and a mutation text that rewrites the scheduler's line (`scripts/mutations_d62_d63.py`); the second command, over `harness/`, prints nothing: **the harness package uses no advisory lock**; the third shows the two functions that open a lock connection.

### H.2 The scheduler's lock: acquire, release, watch [R]

`control_plane/scheduler/lock.py:1-82`

```text
    1 | """The singleton guard: one scheduler at a time (D62, D58-2).
    2 | 
    3 | A Postgres *session* advisory lock on a dedicated connection. The server releases a session lock
    4 | when the session ends, so it cannot outlive a dead process: no table to clean, no heartbeat row, no
    5 | lease to tune. A second instance's ``pg_try_advisory_lock`` returns false and it exits before
    6 | reading anything.
    7 | 
    8 | "Lost connection = lost lock = stop dispatching." The lock is checked on the same session before and
    9 | after every dispatch (a dispatch can run for the whole ``max_duration_seconds`` of a container),
   10 | and a watchdog thread checks it every ``interval`` seconds meanwhile. It cannot stop a container
   11 | already running -- nothing in v0 can (D44-7/D58-16) -- it sets ``lost`` so that no further dispatch
   12 | starts. It guards against accidents; it is not an authorization mechanism (another role can take the
   13 | same key, which only prevents the scheduler from starting).
   14 | """
   15 | 
   16 | from __future__ import annotations
   17 | 
   18 | import threading
   19 | from collections.abc import Callable
   20 | 
   21 | from sqlalchemy import Connection, text
   22 | 
   23 | from control_plane.state.db import open_scheduler_lock_connection
   24 | 
   25 | #: The advisory-lock key. Fixed, so every instance contends for the same one.
   26 | LOCK_KEY = 0x0D62_5C4E_D000_0001
   27 | 
   28 | _HELD = text("""
   29 |     SELECT EXISTS (
   30 |         SELECT 1 FROM pg_locks
   31 |         WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
   32 |           AND ((classid::bigint << 32) | objid::bigint) = :k)
   33 | """)
   34 | 
   35 | 
   36 | class SingletonLock:
   37 |     def __init__(self, connect: Callable[[], Connection] = open_scheduler_lock_connection):
   38 |         self._connect = connect
   39 |         self._conn: Connection | None = None
   40 |         self._mutex = threading.Lock()
   41 |         self.lost = threading.Event()
   42 |         self._watchdog: threading.Thread | None = None
   43 |         self._stop = threading.Event()
   44 | 
   45 |     def acquire(self) -> bool:
   46 |         """Take the lock; False if another instance holds it."""
   47 |         self._conn = self._connect()
   48 |         got = bool(self._conn.execute(text("SELECT pg_try_advisory_lock(:k)"),
   49 |                                       {"k": LOCK_KEY}).scalar_one())
   50 |         if not got:
   51 |             self.close()
   52 |         return got
   53 | 
   54 |     def held(self) -> bool:
   55 |         """Whether this session still holds the lock. An error is 'lost', and stays lost."""
   56 |         if self.lost.is_set() or self._conn is None:
   57 |             return False
   58 |         try:
   59 |             with self._mutex:
   60 |                 ok = bool(self._conn.execute(_HELD, {"k": LOCK_KEY}).scalar_one())
   61 |         except Exception:  # noqa: BLE001 - any failure of the lock session is "lost"
   62 |             ok = False
   63 |         if not ok:
   64 |             self.lost.set()
   65 |         return ok
   66 | 
   67 |     def start_watchdog(self, interval: float = 2.0) -> None:
   68 |         def watch() -> None:
   69 |             while not self._stop.wait(interval):
   70 |                 if not self.held():
   71 |                     return
   72 |         self._watchdog = threading.Thread(target=watch, name="scheduler-lock-watchdog", daemon=True)
   73 |         self._watchdog.start()
   74 | 
   75 |     def close(self) -> None:
   76 |         self._stop.set()
   77 |         conn, self._conn = self._conn, None
   78 |         if conn is not None:
   79 |             try:
   80 |                 conn.close()
   81 |             except Exception:  # noqa: BLE001 - closing a dead session is not an error
   82 |                 pass
```

`control_plane/state/db.py:561-576`

```text
  561 | def open_scheduler_lock_connection() -> Connection:
  562 |     """One dedicated, unpooled, autocommit connection for the singleton lock (D62, D58-2).
  563 | 
  564 |     Its own engine and no pool: the advisory lock belongs to *this* session, so the session must
  565 |     not be shared, recycled or pre-pinged away. TCP keepalives make a vanished server noticed in
  566 |     seconds. The caller owns it and closes it.
  567 |     """
  568 |     from sqlalchemy.pool import NullPool
  569 | 
  570 |     engine = create_engine(
  571 |         scheduler_reader_url(), poolclass=NullPool, future=True,
  572 |         isolation_level="AUTOCOMMIT",
  573 |         connect_args={"keepalives": 1, "keepalives_idle": 5, "keepalives_interval": 2,
  574 |                       "keepalives_count": 3},
  575 |     )
  576 |     return engine.connect()
```

`control_plane/state/db.py:545-558`

```text
  545 | def open_reconciler_lock_connection() -> Connection:
  546 |     """The reconciler's singleton-lock session (D64-10): unpooled, autocommit, TCP keepalives, as
  547 |     ``reconciler_reader`` -- a login role that holds no table privilege, which is all an advisory
  548 |     lock needs. Its own key (``control_plane/reconciler/lock.py``), so it can be held together with
  549 |     the scheduler's. The caller owns it and closes it."""
  550 |     from sqlalchemy.pool import NullPool
  551 | 
  552 |     engine = create_engine(
  553 |         reconciler_reader_url(), poolclass=NullPool, future=True,
  554 |         isolation_level="AUTOCOMMIT",
  555 |         connect_args={"keepalives": 1, "keepalives_idle": 5, "keepalives_interval": 2,
  556 |                       "keepalives_count": 3},
  557 |     )
  558 |     return engine.connect()
```

How the service uses it:

`$ git grep -n -E 'lock' -- control_plane/scheduler/service.py`

```text
control_plane/scheduler/service.py:1:"""The scheduler loop (D62): wires ``decide``, ``execute``, ``emit``, ``state`` and the lock.
control_plane/scheduler/service.py:9:* a lost database connection, an unreachable Docker, a lost lock or any unexpected exception stops
control_plane/scheduler/service.py:28:from control_plane.scheduler.lock import SingletonLock
control_plane/scheduler/service.py:32:    """The service must stop: ``reason`` is one of ``vocab.STOP_REASONS`` (or ``lock_held``)."""
control_plane/scheduler/service.py:67:    def __init__(self, *, sandbox=None, lock: SingletonLock | None = None,
control_plane/scheduler/service.py:70:        self.lock = lock or SingletonLock()
control_plane/scheduler/service.py:78:        """Take the lock, observe the enrolled engagements, record ``scheduler.started``."""
control_plane/scheduler/service.py:80:            got = self.lock.acquire()
control_plane/scheduler/service.py:92:            self.lock.start_watchdog(self.watchdog_interval)
control_plane/scheduler/service.py:108:            self.lock.close()
control_plane/scheduler/service.py:123:        self.lock.close()
control_plane/scheduler/service.py:149:            self._assert_lock()
control_plane/scheduler/service.py:156:    def _assert_lock(self) -> None:
control_plane/scheduler/service.py:157:        if not self.lock.held():
control_plane/scheduler/service.py:174:            self._assert_lock()
control_plane/scheduler/service.py:225:        self._assert_lock()
```

`control_plane/scheduler/service.py:77-110`

```text
   77 |     def start(self) -> None:
   78 |         """Take the lock, observe the enrolled engagements, record ``scheduler.started``."""
   79 |         try:
   80 |             got = self.lock.acquire()
   81 |         except Exception as exc:  # noqa: BLE001
   82 |             raise _translate(exc) from exc
   83 |         if not got:
   84 |             try:
   85 |                 emit.emit(vocab.START_REFUSED, {"instance_id": self.instance_id,
   86 |                                                 "reason_code": vocab.LOCK_HELD},
   87 |                           subject_type="scheduler", subject_id=self.instance_id)
   88 |             except Exception:  # noqa: BLE001 - refusing to start needs no further record
   89 |                 pass
   90 |             raise StopService(vocab.LOCK_HELD, vocab.EXIT_LOCK_HELD)
   91 |         try:
   92 |             self.lock.start_watchdog(self.watchdog_interval)
   93 |             enrolled = decide.read_enrollment()
   94 |             seen = [decide.observe(e) for e in enrolled]
   95 |             emit.emit(vocab.STARTED, {
   96 |                 "instance_id": self.instance_id,
   97 |                 "enrolled": enrolled,
   98 |                 "missing": [o.engagement_id for o in seen if not o.exists],
   99 |                 "dispatching": {o.engagement_id: o.dispatching for o in seen if o.exists},
  100 |                 "capability_issued": {o.engagement_id: o.capability_issued
  101 |                                       for o in seen if o.exists},
  102 |                 "approved_waiting": {o.engagement_id: len(o.waiting) for o in seen if o.exists},
  103 |                 "approved_redispatch": {
  104 |                     o.engagement_id: len({w.proposal_id for w in o.waiting} & o.decided)
  105 |                     for o in seen if o.exists},
  106 |             }, subject_type="scheduler", subject_id=self.instance_id)
  107 |         except BaseException as exc:
  108 |             self.lock.close()
  109 |             raise _translate(exc) from exc
  110 |         self.started = True
```

`control_plane/scheduler/service.py:112-123`

```text
  112 |     def stop(self, reason: str) -> None:
  113 |         """Record ``scheduler.stopped`` (best effort: the audit may be what failed); let go."""
  114 |         if self._stopped:
  115 |             return
  116 |         self._stopped = True
  117 |         if self.started and reason in vocab.STOP_REASONS:
  118 |             try:
  119 |                 emit.emit(vocab.STOPPED, {"instance_id": self.instance_id, "reason_code": reason},
  120 |                           subject_type="scheduler", subject_id=self.instance_id)
  121 |             except Exception:  # noqa: BLE001 - an unclean stop reads as started-without-stopped
  122 |                 pass
  123 |         self.lock.close()
```

The reconciler's key, which must be holdable together with the scheduler's:

`control_plane/reconciler/lock.py:25-27`

```text
   25 | #: The advisory-lock key. Fixed, so every instance contends for the same one -- and not the
   26 | #: scheduler's (0x0D62_5C4E_D000_0001): the two must be holdable together.
   27 | LOCK_KEY = 0x0D64_5EC0_0000_0001
```

The tests of the locks:

`$ git grep -n 'LOCK_KEY' -- tests`

```text
tests/test_reconciler_lock.py:17:from control_plane.reconciler.lock import LOCK_KEY, SingletonLock
tests/test_reconciler_lock.py:18:from control_plane.scheduler.lock import LOCK_KEY as SCHEDULER_KEY
tests/test_reconciler_lock.py:24:    assert LOCK_KEY != SCHEDULER_KEY
tests/test_reconciler_lock.py:25:    assert 0 < LOCK_KEY < 2 ** 63 and 0 < SCHEDULER_KEY < 2 ** 63
```

`tests/test_scheduler_service.py:59-69`

```text
   59 | def test_a_second_instance_is_refused_before_it_reads_anything(world):
   60 |     sandbox = RecordingSandbox()
   61 |     with sup.running(sandbox):
   62 |         second = Scheduler(sandbox=sandbox, lock=SingletonLock())
   63 |         code = second.run(interval=0, max_ticks=3)
   64 |         assert code == vocab.EXIT_LOCK_HELD
   65 |         assert sandbox.calls == 0
   66 |         assert not second.started
   67 |         assert _global_events("scheduler.start_refused")[0]["payload"] == {
   68 |             "instance_id": second.instance_id, "reason_code": vocab.LOCK_HELD}
   69 |     assert _stage(world)[0] == stages.APPROVED
```

`tests/test_scheduler_service.py:80-101`

```text
   80 | def test_a_killed_lock_connection_stops_dispatching(world):
   81 |     """Lost connection = lost lock = stop. Terminate the lock's own backend; nothing dispatches."""
   82 |     sandbox = RecordingSandbox()
   83 |     sched = Scheduler(sandbox=sandbox, watchdog_interval=0.1)
   84 |     sched.start()
   85 |     try:
   86 |         with sched.lock._mutex:
   87 |             pid = sched.lock._conn.execute(text("SELECT pg_backend_pid()")).scalar_one()
   88 |         from control_plane.state.db import open_scheduler_lock_connection
   89 |         killer = open_scheduler_lock_connection()
   90 |         try:
   91 |             assert killer.execute(text("SELECT pg_terminate_backend(:p)"), {"p": pid}).scalar_one()
   92 |         finally:
   93 |             killer.close()
   94 |         with pytest.raises(StopService) as stop:
   95 |             sched.tick()
   96 |         assert stop.value.reason == vocab.STOP_LOCK_LOST
   97 |         assert stop.value.exit_code == vocab.EXIT_LOCK_LOST
   98 |     finally:
   99 |         sched.stop(vocab.STOP_LOCK_LOST)
  100 |     assert sandbox.calls == 0 and _stage(world)[0] == stages.APPROVED
  101 |     assert sup.audit(world["engagement_id"], "scheduler.dispatched") == []
```

`tests/test_scheduler_service.py:104-118`

```text
  104 | def test_run_returns_the_lock_lost_exit_code(world):
  105 |     sandbox = RecordingSandbox()
  106 |     sched = Scheduler(sandbox=sandbox, watchdog_interval=0.1)
  107 | 
  108 |     ticks = []
  109 |     real_tick = sched.tick
  110 | 
  111 |     def tick_after_losing_the_lock():
  112 |         ticks.append(1)
  113 |         sched.lock._conn.close()            # the session ends; the server drops the lock
  114 |         return real_tick()
  115 | 
  116 |     sched.tick = tick_after_losing_the_lock
  117 |     assert sched.run(interval=0, max_ticks=3) == vocab.EXIT_LOCK_LOST
  118 |     assert sandbox.calls == 0 and len(ticks) == 1
```

[D] Acquire: `pg_try_advisory_lock(key)` on a dedicated autocommit, unpooled connection with TCP keepalives (a **session** lock, released by the server when the session ends); a second instance's call returns false and `acquire` closes its connection. Hold check: a `pg_locks` query on the same session, any error counted as lost; the check runs before and after each dispatch (service `_assert_lock`) and in a watchdog thread every `interval` seconds; loss sets an event and the scheduler stops dispatching with exit code 6, it cannot stop a container already running (module docstring). Release: `close()` closes the connection. The connection's role is the one in the connection string passed: `scheduler_reader` for the scheduler, `reconciler_reader` for the reconciler ("a login role that holds no table privilege, which is all an advisory lock needs", `db.py` docstring above). [R] The two existing keys are `0x0D62_5C4E_D000_0001` (scheduler) and `0x0D64_5EC0_0000_0001` (reconciler); `tests/test_reconciler_lock.py:24` asserts they differ; no existing function opens a lock connection for any other role.

**Effect on H5.** The harness has no lock and no lock-connection opener today; a lock class parameterised only by a connection opener and a key exists twice (scheduler, reconciler) and a third key and a third opener would be new code and a new database role or an existing role's login (proposal 3.6, H5-7), and the lock's loss path ends in an exit code that the scheduler's tests exercise by killing the lock connection.

## Consolidated [N]

* A (A.2): which operator tool calls `pause_engagement`, `resume_engagement` and `engage_kill_switch` in a deployment (the repository's callers are tests).
* A (A.3): the effective privileges of `cyberorch_app` on `engagements` in any running database (no connection was made); the migrations were read instead.
* A (A.4): the recorded effect of `_close_early` after the dispatch stage's fresh read on a real database.
* B (B.3): no test drives `NetworkInUse` through `propose_action` and reads `ActionOutcome.failure`; the handling is from reading the code.
* C (C.2, C.3): no test injects the row's own trigger (`IndexError` at `LocalReviewer`); the fields of `engagement.created` and `scope_object.registered` were not read.
* D (D.2): whether any deployment ran `scripts/init_db.sh` with a later `db/roles.sql`.
* E (E.3): `complete_task` on a `queued` task was read from the SQL and not executed.

## What this report does not do

It chooses no option of the proposal's section 3, authorizes no stage, and writes nothing to the database. Where a fact bears on a decision the owner or the review layer has taken or will take, the **Effect on H5** line says which piece or question it touches and stops there.
