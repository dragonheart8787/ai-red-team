"""The post-hoc log classification of a soak (D66, ``scripts/soak/logscan.py``) can tell a line
inside a fault's window from one outside it, and keeps what has no timestamp apart.

No database, no Docker: the logs are written by the test, in the formats the real ones have.
"""

from __future__ import annotations

import json
import time
from calendar import timegm
from pathlib import Path

from scripts.soak import logscan

T0 = float(timegm(time.strptime("2026-10-16 03:00:00", "%Y-%m-%d %H:%M:%S")))


def at(seconds: float, *, pg: bool = False) -> str:
    t = time.gmtime(T0 + seconds)
    return (time.strftime("%Y-%m-%d %H:%M:%S", t) + ".123 UTC" if pg
            else time.strftime("%Y-%m-%dT%H:%M:%S", t) + ".123456789Z")


def journal(*faults: tuple[str, float, float | None]) -> list[dict]:
    out = [{"kind": "soak.setup", "ts": T0}, {"kind": "soak.teardown", "ts": T0 + 7200}]
    for kind, begin, recovered in faults:
        out.append({"kind": "fault.begin", "fault": kind, "ts": T0 + begin})
        if recovered is not None:
            out.append({"kind": "fault.recovery", "fault": kind, "ts": T0 + recovered})
    return out


TERMINATING = "terminating connection due to administrator command"


def postgres_log(tmp: Path, *lines: str) -> Path:
    path = tmp / "pg.log"
    path.write_text("\n".join(lines) + "\n")
    return path


def test_normalise_removes_what_differs_between_two_lines_of_one_shape():
    a = logscan.normalise("run RUN-abc123 on 10.1.2.3:80 took 41 ms id 83f22c0eef818666fd9d")
    b = logscan.normalise("run RUN-ff00ee on 10.9.9.9:81 took 7 ms id 0123456789abcdef0123")
    assert a == b


def test_a_postgres_error_continued_by_detail_is_one_entry_and_the_old_ones_are_dropped(tmp_path):
    path = postgres_log(
        tmp_path,
        f"{at(-900, pg=True)} [1] app@db ERROR:  before the run",
        f"{at(10, pg=True)} [2] app@db ERROR:  duplicate key value violates unique constraint",
        f"{at(10, pg=True)} [2] app@db DETAIL:  Key (a)=(1) already exists.",
        f"{at(10, pg=True)} [2] app@db STATEMENT:  INSERT INTO t VALUES (1)",
        f"{at(11, pg=True)} [3] app@db LOG:  checkpoint complete",
        f"{at(12, pg=True)} [4] app@db LOG:  could not receive data from client: Connection reset",
    )
    entries = logscan.read_postgres([path], T0, T0 + 100)
    assert [e.level for e in entries] == ["ERROR", "LOG"]
    assert "already exists" in entries[0].message and "INSERT" not in entries[0].message
    assert entries[1].message.startswith("app: could not receive data")


def test_the_dockerd_log_keeps_warnings_and_errors_inside_the_run_only(tmp_path):
    path = tmp_path / "dockerd.log"
    path.write_text("\n".join([
        f'time="{at(-5)}" level=error msg="before the run"',
        f'time="{at(5)}" level=info msg="shim disconnected"',
        f'time="{at(6)}" level=warning msg="error locating sandbox id abcdef0123456789: gone"',
        f'time="{at(7)}" level=error msg="Handler for POST failed: \\"x\\"" module=api',
        "panic: runtime error: invalid memory address",
    ]) + "\n")
    entries = logscan.read_dockerd(path, T0, T0 + 100)
    assert [(e.level, e.ts is None) for e in entries] == [
        ("warning", False), ("error", False), ("unparsed", True)]


def test_service_logs_keep_error_lines_and_actions_that_were_not_done(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "scheduler.log").write_text("scheduler stopped (exit 1)\nall is well\n")
    (logs / "reconciler.log").write_text("\n".join([
        json.dumps({"kind": "remove_container", "outcome": "done", "reason_code": "x"}),
        json.dumps({"kind": "remove_container", "outcome": "failed", "reason_code": "x"}),
        json.dumps({"summary": {}, "outcomes": {}}),
        "Type exactly:  enable container kill",
    ]) + "\n")
    entries = logscan.read_service_logs(logs)
    assert sorted((e.source, e.level) for e in entries) == [
        ("reconciler", "action"), ("scheduler", "log")]
    assert all(e.ts is None for e in entries)


def test_a_group_wholly_inside_a_window_is_explained_and_one_line_outside_is_not(tmp_path):
    path = postgres_log(
        tmp_path,
        f"{at(100, pg=True)} [1] app@db FATAL:  {TERMINATING}",
        f"{at(101, pg=True)} [2] app@db FATAL:  {TERMINATING}",
        f"{at(3000, pg=True)} [3] app@db ERROR:  deadlock detected",
        f"{at(130, pg=True)} [4] app@db ERROR:  deadlock detected",
    )
    events = journal(("postgres_restart", 95, 120))
    groups = logscan.group(logscan.read_postgres([path], T0, T0 + 7200),
                           logscan.fault_windows(events))
    by_shape = {g.shape: g for g in groups}
    terminating = next(g for g in groups if "terminating" in g.shape)
    deadlock = by_shape[next(s for s in by_shape if "deadlock" in s)]
    assert terminating.klass == "explained" and terminating.kinds == {"postgres_restart": 2}
    assert deadlock.klass == "not_explained" and (deadlock.inside, deadlock.outside) == (1, 1)


def test_the_window_runs_from_the_fault_to_its_recovery_plus_the_grace_and_opens_when_unrecovered():
    windows = logscan.fault_windows(journal(("docker_restart", 100, 150), ("kill9_scheduler", 500,
                                                                           None)))
    (s1, e1, k1), (s2, e2, k2) = windows
    assert (k1, k2) == ("docker_restart", "kill9_scheduler")
    assert s1 < T0 + 100 < T0 + 150 < e1 == T0 + 150 + logscan.GRACE_S
    assert e2 == T0 + 500 + logscan.OPEN_WINDOW_S + logscan.GRACE_S


def test_a_line_with_no_timestamp_is_untimed_never_explained():
    entry = logscan.Entry("scheduler", "log", "scheduler stopped (exit 1)")
    groups = logscan.group([entry], logscan.fault_windows(journal(("kill9_scheduler", 0, 100))))
    assert [g.klass for g in groups] == ["untimed"]


def test_scan_reads_all_three_sources_and_the_summary_counts_the_classes(tmp_path):
    run = tmp_path / "run"
    (run / "logs").mkdir(parents=True)
    (run / "logs" / "worker.log").write_text("Traceback (most recent call last):\n")
    dockerd = tmp_path / "dockerd.log"
    dockerd.write_text(f'time="{at(100)}" level=error msg="boom"\n')
    pg = postgres_log(tmp_path, f"{at(3000, pg=True)} [1] app@db ERROR:  boom")
    groups = logscan.scan(run, journal(("docker_restart", 95, 120)), dockerd=dockerd,
                          postgres_glob=str(pg).lstrip("/"))
    assert logscan.summary(groups) == {"untimed": {"groups": 1, "lines": 1},
                                       "explained": {"groups": 1, "lines": 1},
                                       "not_explained": {"groups": 1, "lines": 1}}
    text = "\n".join(logscan.render(groups))
    assert "not_explained" in text and "Samples of what is not explained" in text
