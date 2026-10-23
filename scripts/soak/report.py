"""The soak's report: what was injected, how long recovery took, what held, what trended (D66)."""

from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict

from scripts.soak import checks, heartbeat, lib, logscan


def slope_per_hour(points: list[tuple[float, float]]) -> float | None:
    """Least-squares slope of ``points`` (seconds, value), per hour; ``None`` under three points."""
    if len(points) < 3:
        return None
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True)) / den * 3600


def _spread(values: list[float]) -> str:
    if not values:
        return "-"
    return f"{min(values):.0f} / {statistics.median(values):.0f} / {max(values):.0f}"


def trends(samples: list[dict]) -> list[dict]:
    """Per process incarnation (a pid): memory, descriptors, connections to Postgres."""
    by_pid: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for s in samples:
        for name, stats in (s.get("procs") or {}).items():
            if stats:
                by_pid[(name, stats["pid"])].append({"ts": s["ts"], **stats})
    out = []
    for (name, pid), rows in sorted(by_pid.items(), key=lambda kv: kv[1][0]["ts"]):
        t0 = rows[0]["ts"]
        rss = [(r["ts"] - t0, r["rss_kb"]) for r in rows]
        out.append({
            "process": name, "pid": pid, "samples": len(rows),
            "minutes": round((rows[-1]["ts"] - rows[0]["ts"]) / 60, 1),
            "rss_first_mb": round(rows[0]["rss_kb"] / 1024, 1),
            "rss_last_mb": round(rows[-1]["rss_kb"] / 1024, 1),
            "rss_max_mb": round(max(r["rss_kb"] for r in rows) / 1024, 1),
            "rss_slope_mb_per_h": (round(s / 1024, 2) if (s := slope_per_hour(rss)) is not None
                                   else None),
            "fds_min_max": [min(r["fds"] for r in rows), max(r["fds"] for r in rows)],
            "pg_connections_min_max": [min(r["pg_connections"] for r in rows),
                                       max(r["pg_connections"] for r in rows)],
            "threads_min_max": [min(r["threads"] for r in rows), max(r["threads"] for r in rows)],
        })
    return out


def write(conductor, final_results, teardown) -> None:
    run_dir = conductor.run_dir
    journal = conductor.journal.read()
    ended = lib.now()
    eids = conductor.eids

    faults = conductor.faults_done
    by_kind: dict[str, list[dict]] = defaultdict(list)
    for fault in faults:
        by_kind[fault["kind"]].append(fault)

    lines = ["# Soak report (D66)\n",
             f"* run: `{run_dir}`",
             f"* started {lib.stamp(conductor.started)}, ended {lib.stamp(ended)} "
             f"({(ended - conductor.started) / 3600:.2f} h; the traffic and the faults ran "
             f"{conductor.args.hours} h, then the drain)",
             f"* seed `{conductor.args.seed}`, engagements {len(eids)}, worker threads "
             f"{conductor.args.threads}, mean gap {conductor.args.mean_gap} s, run budget "
             f"{conductor.args.budget} s",
             f"* host: boot id `{heartbeat.boot_id()}`, "
             f"kernel `{heartbeat.host_identity()['kernel']}`; heartbeat file "
             f"`{heartbeat.FILE}` every {heartbeat.PERIOD_S:.0f} s",
             f"* outcome: **{'FINDING - stopped' if conductor.findings else 'no finding'}**\n"]

    lines.append("## Findings\n")
    if conductor.findings:
        for f in conductor.findings:
            lines.append(f"* `{f['kind']}` -- {f['detail']}")
    else:
        lines.append("none")

    lines.append("\n## Faults injected\n")
    lines.append("| fault | times | recovered (s): min / median / max | not recovered | "
                 "action (s) |")
    lines.append("|---|---|---|---|---|")
    for kind in faults_kinds():
        rows = by_kind.get(kind, [])
        rec = [r["recovered_s"] for r in rows if r.get("recovered_s") is not None]
        miss = [r for r in rows if r.get("recovered_s") is None]
        act = [r["action_s"] for r in rows if r.get("action_s") is not None]
        lines.append(f"| {kind} | {len(rows)} | {_spread(rec)} | {len(miss)} | {_spread(act)} |")
    lines.append("\nEach injection (recovery = the slowest of: all three services alive with "
                 "the database and Docker reachable; a reconciler pass after the fault; an ALLOW "
                 "proposal created after the fault recorded as succeeded; a HUMAN_APPROVAL "
                 "proposal dispatched by the scheduler and recorded after the fault):\n")
    lines.append("| at | fault | detail | services up | reconciler pass | ALLOW recorded | "
                 "scheduler dispatched | recovered |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for f in faults:
        r = f.get("recovery_s") or {}
        detail = {k: v for k, v in f.items() if k in ("pid", "container", "hold_s", "detail",
                                                      "error", "killed_hard", "unpause")}
        lines.append(f"| {f['began_at']} | {f['kind']} | {json.dumps(detail)[:90]} | "
                     f"{r.get('services_up')} | {r.get('reconciler_pass')} | "
                     f"{r.get('allow_recorded')} | {r.get('scheduler_dispatched')} | "
                     f"{f.get('recovered_s')} |")

    lines.append("\n## Were all six kinds of fault injected?\n")
    lines.append("| fault | applied | applied and effective | could not be applied |")
    lines.append("|---|---|---|---|")
    for kind in faults_kinds():
        rows = by_kind.get(kind, [])
        effective = [r for r in rows if r.get("ok", True) is not False]
        lines.append(f"| {kind} | {len(rows)} | {len(effective)} | {len(rows) - len(effective)} |")
    not_done = [k for k in faults_kinds() if not any(
        r.get("ok", True) is not False for r in by_kind.get(k, []))]
    lines.append("\n" + (f"**Kinds never effectively injected: {not_done}.**" if not_done else
                         "Every kind was injected at least once and took effect."))

    lines.append("\n## Services\n")
    lines.append("| service | starts | exits (cause: count) |")
    lines.append("|---|---|---|")
    for name, svc in conductor.sup.services.items():
        causes = Counter(e["cause"] for e in svc.exits)
        lines.append(f"| {name} | {svc.starts} | {dict(causes)} |")
    lines.append("\n`explained_by_*` is a service that stopped itself with its documented exit "
                 "code after the fault named, and was started again by this program: **neither "
                 "service reconnects**, a supervisor is part of the design.")

    lines.append("\n## Invariants\n")
    lines.append("| check | runs | failed | last detail |")
    lines.append("|---|---|---|---|")
    names: dict[str, list[dict]] = defaultdict(list)
    for r in conductor.check_results:
        names[r["name"]].append(r)
    for name, rows in names.items():
        failed = sum(1 for r in rows if not r["ok"])
        lines.append(f"| {name} | {len(rows)} | {failed} | {rows[-1]['detail'][:200]} |")

    lines += _check_counts(conductor)
    not_enforced = [r for r in journal if r["kind"] == "smoke.not_enforced"]
    if not_enforced:
        lines.append(f"\n**Smoke run: {len(not_enforced)} failed result(s) of "
                     f"`{not_enforced[0]['check']}` were recorded and not enforced** (see "
                     "`checks.SMOKE_NOT_ENFORCED`: the reconciler's timers, B + P + Q about 21 "
                     "minutes, cannot be compressed, so exited tool containers outlive a smoke "
                     "run). Last: " + not_enforced[-1]["detail"][:200])
    lines += _caps_section(conductor)

    lines.append("\n## Traffic\n")
    try:
        arr = checks._quote(eids)
        stages = lib.psql("SELECT pipeline_stage || ' / ' || coalesce(stage_detail, ''), count(*) "
                          "FROM action_proposals WHERE engagement_id = ANY(" + arr +
                          ") GROUP BY 1 ORDER BY 2 DESC")
        runs = lib.psql("SELECT status, count(*) FROM tool_runs WHERE engagement_id = ANY(" + arr +
                        ") GROUP BY 1 ORDER BY 2 DESC")
        events = lib.psql("SELECT event_type, count(*) FROM audit_log WHERE engagement_id = ANY(" +
                          arr + ") GROUP BY 1 ORDER BY 1")
        lines.append("proposals by `stage / detail`: " + ", ".join(f"{s} {n}" for s, n in stages))
        lines.append("\nruns by status: " + ", ".join(f"{s} {n}" for s, n in runs))
        lines.append("\naudit events: " + ", ".join(f"{s} {n}" for s, n in events))
    except Exception as exc:  # noqa: BLE001
        lines.append(f"(could not read the database: {exc})")
    retries = Counter(r["kind"] for r in journal if r["kind"].startswith("worker."))
    lines.append(f"\nworker: {dict(retries)}")
    actions = Counter((r.get("action"), r.get("outcome")) for r in journal
                      if r["kind"] == "reconciler.action")
    lines.append("\nreconciler actions (kind, outcome): " + ", ".join(
        f"{k[0]}/{k[1]} {n}" for k, n in sorted(actions.items(), key=str)))
    passes = sum(1 for r in journal if r["kind"] == "reconciler.pass")
    lines.append(f"\nreconciler passes seen: {passes}")

    lines.append("\n## Memory and connections (per process incarnation)\n")
    lines.append("| process | pid | minutes | RSS first / last / max (MB) | RSS slope (MB/h) | "
                 "fds min-max | pg connections min-max | threads min-max |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for t in trends(conductor.samples):
        lines.append(f"| {t['process']} | {t['pid']} | {t['minutes']} | {t['rss_first_mb']} / "
                     f"{t['rss_last_mb']} / {t['rss_max_mb']} | {t['rss_slope_mb_per_h']} | "
                     f"{t['fds_min_max']} | {t['pg_connections_min_max']} | "
                     f"{t['threads_min_max']} |")
    pg = [s["pg"] for s in conductor.samples if s.get("pg")]
    if pg:
        totals = [p["total"] for p in pg]
        lines.append(f"\ndatabase backends (all roles): min {min(totals)}, median "
                     f"{statistics.median(totals):.0f}, max {max(totals)}, last {totals[-1]}; "
                     f"longest idle-in-transaction "
                     f"{max(p['idle_in_transaction_max_age_s'] for p in pg)} s")

    lines.append("\n## The hourly sample points\n")
    lines.append("| hour | at | proposals | runs | audit rows | DB MB | RSS MB: scheduler / "
                 "reconciler / worker / conductor | RSS MB: dockerd / containerd / postgres | "
                 "containers | networks | backends | run dir MB | disk free MB | faults so far |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    lines += [_hourly_row(p) for p in conductor.hourly_points]

    lines.append("\n## Host residue over time (window floors, 15 min windows)\n")
    dk = [s for s in conductor.samples if s.get("docker")]
    window = conductor.args.check_every * 60
    for label, pick in (
            ("containers", lambda s: sum(s["docker"]["tools"].values())
             + sum(s["docker"]["proxies"].values())),
            ("exited tool containers", lambda s: s["docker"]["tools"]["exited"]),
            ("proxies", lambda s: sum(s["docker"]["proxies"].values())),
            ("sandbox networks", lambda s: s["docker"]["networks"]),
            ("temp credential/TLS files", lambda s: s["docker"]["files"]),
            ("evidence files", lambda s: s["docker"]["evidence_files"])):
        pts = [(s["ts"], float(pick(s))) for s in dk]
        lines.append(f"* {label}: floors {checks.window_floors(pts, window)}, max "
                     f"{max((p[1] for p in pts), default=0):.0f}, last "
                     f"{pts[-1][1] if pts else '-'}")

    groups = logscan.scan(run_dir, journal)
    classes = json.dumps(logscan.summary(groups))
    lines += ["\n## Logs, classified after the run\n",
              "Every warning and error of the services' logs, the Docker daemon's log and the "
              "Postgres log between the first and the last event of the run, normalised and "
              f"grouped (`scripts/soak/logscan.py`; classes: {classes}). `explained` means "
              "*every* occurrence lies inside a fault's window, which says when and not why; "
              "`known (N)` is a group that matches a pattern registered in `logscan.KNOWN`, "
              "with the ACCEPTANCE item N that records it.\n"]
    lines += logscan.render(groups)
    if logscan.SKIPPED:
        lines.append("\n**Log sources that could not be read, and so are not in the table above:** "
                     + "; ".join(sorted(set(logscan.SKIPPED))))
    lines.append("\n## Observed, and not covered by any check\n")
    lines += not_covered(conductor, journal, groups)

    lines.append("\n## What needed a person\n")
    needed = [f for f in conductor.findings
              if f["kind"] in ("dependencies_down", "no_recovery", "crash_loop",
                               "unexplained_exit", "fault_failed")]
    if needed:
        for f in needed:
            lines.append(f"* `{f['kind']}`: {f['detail']}")
    else:
        lines.append("no recovery needed a person: every service that stopped was started again "
                     "by the supervisor, every fault recovered inside the bound.")
    lines.append(f"\nteardown: {json.dumps(teardown)}")

    (run_dir / "report.md").write_text("\n".join(lines) + "\n")
    summary = {"findings": conductor.findings, "faults": faults, "checks": conductor.check_results,
               "trends": trends(conductor.samples), "teardown": teardown}
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=1, default=str))


def _check_counts(conductor) -> list[str]:
    out = ["\n## How many times each check ran\n",
           "A check with no execution -- or one executed and never given enough to judge (a series "
           "shorter than its windows) -- has verified nothing, and is a failure "
           "(`check_never_ran`).\n",
           "| check | executions | judged | verdict |", "|---|---|---|---|"]
    args = getattr(conductor, "args", None)
    p1, q1 = (bool(getattr(args, "p1_enforce", False)), bool(getattr(args, "q1_enforce", False)))
    missing = checks.never_ran(conductor.check_results, expect_drain=not conductor.halted,
                               p1=p1, q1=q1)
    for name, runs, judged in checks.execution_counts(conductor.check_results, p1=p1, q1=q1):
        failed = [m for m in missing if m.startswith(name + ":")]
        if failed:
            verdict = f"**FAILED: {failed[0]}**"
        elif name == checks.DRAIN_CHECK and not runs:
            verdict = "not expected: the run stopped before the drain"
        else:
            verdict = "ok"
        shown = "n/a (listed)" if name in checks.NOT_JUDGED_BY_DESIGN else judged
        out.append(f"| {name} | {runs} | {shown} | {verdict} |")
    return out


def _caps_section(conductor) -> list[str]:
    doc = conductor.caps_document
    source = (doc or {}).get("source", "the defaults of the development machine (not measured)")
    out = ["\n## The caps of this environment\n", f"source: **{source}**\n"]
    if doc:
        out.append("measured: `" + json.dumps(doc["measured"], sort_keys=True) + "`\n")
    out.append("caps used: `" + json.dumps(conductor.caps, sort_keys=True) + "`")
    return out


def _docker_events(run_dir) -> list[dict]:
    path = run_dir / "docker_events.jsonl"
    out = []
    for line in (path.read_text().splitlines() if path.exists() else []):
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def not_covered(conductor, journal: list[dict], groups: list[logscan.Group]) -> list[str]:
    """What the run showed that no invariant asks about. Listed, never judged: a person reads it.

    Each item says what was looked at, so that an empty one is an answer and not an omission."""
    out: list[str] = []
    odd = [g for g in groups if g.klass in ("not_explained", "untimed")]
    out.append(f"* **Log groups not explained by a fault window:** {len(odd)} "
               f"({sum(len(g.entries) for g in odd)} lines) -- the rows marked `not_explained` or "
               "`untimed` above, with raw samples.")
    known = [g for g in groups if g.klass == "known"]
    out.append("* **Log groups that match a registered known pattern:** " + (
        "; ".join(f"{len(g.entries)} lines of `{g.shape[:70]}` ({g.known.ref})" for g in known)
        if known else "none") + ".")
    bad = [r for r in journal if r["kind"] == "reconciler.action" and r.get("outcome") != "done"]
    by_outcome = Counter((r.get("action"), r.get("outcome"), r.get("reason")) for r in bad)
    out.append("* **Reconciler actions whose outcome was not `done`:** " + (
        ", ".join(f"{k[0]}/{k[1]}/{k[2]} x{n}" for k, n in sorted(by_outcome.items(), key=str))
        if by_outcome else "none"))
    passes = [r for r in journal if r["kind"] == "reconciler.pass"]
    capped = [r for r in passes if r.get("limited") or r.get("held_back") or r.get("truncated")]
    out.append(f"* **Reconciler passes that were limited, held back or truncated:** "
               f"{len(capped)} of {len(passes)}")
    dies = [r for r in _docker_events(conductor.run_dir)
            if r.get("action") == "die" and not r.get("proxy")]
    codes = Counter(str(r.get("exit_code")) for r in dies)
    out.append(f"* **Exit codes of tool containers that died** ({len(dies)}): " + (
        ", ".join(f"{c} x{n}" for c, n in sorted(codes.items())) or "none") +
        " (0 = the tool ended; 137 = killed, 143 = stopped: by the reconciler, a fault or the "
        "daemon's restart)")
    pairs = zip(conductor.samples, conductor.samples[1:], strict=False)
    gaps = [b["ts"] - a["ts"] for a, b in pairs]
    if gaps:
        median = statistics.median(gaps)
        long_gaps = [g for g in gaps if g > 3 * max(median, 1.0)]
        out.append(f"* **Sampler gaps** (one-minute samples; median {median:.0f} s): "
                   f"{len(long_gaps)} longer than three times that, longest {max(gaps):.0f} s")
    slow = []
    by_kind: dict[str, list[dict]] = defaultdict(list)
    for fault in conductor.faults_done:
        by_kind[fault["kind"]].append(fault)
    for kind, rows in by_kind.items():
        times = [r["recovered_s"] for r in rows if r.get("recovered_s") is not None]
        if len(times) >= 3:
            median = statistics.median(times)
            slow += [f"{kind} {t:.0f} s (median {median:.0f})" for t in times if t > 2 * median]
    out.append("* **Recoveries slower than twice their kind's median:** " + (
        "; ".join(slow) if slow else "none"))
    errors = Counter(r.get("type") for r in journal if r["kind"] == "approver.error")
    out.append("* **Approver:** " + ", ".join(
        f"{k} {sum(1 for r in journal if r['kind'] == k)}" for k in
        ("approver.granted", "approver.denied", "approver.refused", "approver.error")) +
        (f"; errors by type {dict(errors)}" if errors else ""))
    try:
        arr = checks._quote(conductor.eids)
        refused = lib.psql("SELECT coalesce(refusal_code, '-'), status, count(*) FROM tool_runs "
                           "WHERE engagement_id = ANY(" + arr + ") GROUP BY 1, 2 ORDER BY 3 DESC")
        out.append("* **Runs by refusal code and status:** " + ", ".join(
            f"{c}/{s} {n}" for c, s, n in refused))
        provenance = lib.psql(
            "SELECT count(*) FILTER (WHERE pipeline_stage = 'closed' AND stage_detail = "
            "'approval_denied'), count(*) FILTER (WHERE pipeline_stage = 'closed' AND stage_detail "
            "= 'approval_denied' AND NOT EXISTS (SELECT 1 FROM provenance_edges e WHERE "
            "e.from_id = action_proposals.proposal_id OR e.to_id = "
            "action_proposals.proposal_id)) FROM action_proposals WHERE engagement_id = ANY("
            + arr + ")")
        out.append(f"* **Denied proposals, and how many of them have no provenance:** "
                   f"{provenance[0][0]} / {provenance[0][1]} (the approver of this harness denies "
                   "through an autocommit connection, on which `deny_approval`'s savepoint cannot "
                   "be taken: see D66_SOAK.md, \"Known before the run\")")
    except Exception as exc:  # noqa: BLE001
        out.append(f"* (could not read the database: {exc})")
    return out


def _mb(kb: int) -> int:
    return round(kb / 1024)


def _hourly_row(p: dict) -> str:
    s, db, host = p["sample"], p.get("db", {}), p["host"]
    procs = s.get("procs") or {}
    rss = " / ".join(str(_mb((procs.get(n) or {}).get("rss_kb", 0)))
                     for n in ("scheduler", "reconciler", "worker", "conductor"))
    daemons = " / ".join(str(_mb(host[n]["rss_kb"])) for n in ("dockerd", "containerd", "postgres"))
    dk = s.get("docker") or {}
    containers = (sum((dk.get("tools") or {}).values()) + sum((dk.get("proxies") or {}).values())
                  if dk else "-")
    rows = [db.get(t, {}).get("rows") for t in ("action_proposals", "tool_runs", "audit_log")]
    size = ("-" if "error" in db else
            round(sum(v.get("mb", 0) for v in db.values()), 1))
    return (f"| {p['hour']} | {p['at']} | {rows[0]} | {rows[1]} | {rows[2]} | {size} | {rss} | "
            f"{daemons} | {containers} | {dk.get('networks', '-')} | "
            f"{(s.get('pg') or {}).get('total', '-')} | {host['run_dir_mb']} | "
            f"{host['disk_free_mb']} | {sum(p['faults_so_far'].values())} |")


def faults_kinds() -> tuple[str, ...]:
    from scripts.soak import faults
    return faults.KINDS
