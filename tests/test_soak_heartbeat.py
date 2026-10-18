"""The soak's heartbeat (D66, ``scripts/soak/heartbeat.py``): a run that stopped is told from one
that ended, and a machine that restarted under it from a conductor that died."""

from __future__ import annotations

import json
import os

from scripts.soak import heartbeat

BOOT_A, BOOT_B = "boot-a", "boot-b"


def beat_at(run_dir, ts, boot=BOOT_A):
    record = heartbeat.write(run_dir, phase="running")
    record.update(ts=ts, boot_id=boot)
    (run_dir / heartbeat.FILE).write_text(json.dumps(record))


def test_the_file_is_replaced_whole_and_names_the_boot_and_the_process(tmp_path):
    first = heartbeat.write(tmp_path, phase="running", faults_done=1)
    second = heartbeat.write(tmp_path, phase="draining", faults_done=2)
    assert heartbeat.read(tmp_path)["phase"] == "draining"
    assert second["ts"] >= first["ts"] and second["pid"] == os.getpid()
    assert second["boot_id"] == heartbeat.boot_id() and second["kernel"]
    assert not list(tmp_path.glob("*.tmp"))


def test_a_run_with_a_teardown_in_its_journal_is_clean(tmp_path):
    beat_at(tmp_path, 1000.0)
    (tmp_path / "events.jsonl").write_text(json.dumps({"kind": "soak.teardown"}) + "\n")
    assert heartbeat.verdict(tmp_path, now=99999.0, current_boot=BOOT_B)["verdict"] == "clean"


def test_a_fresh_heartbeat_of_this_boot_is_running(tmp_path):
    beat_at(tmp_path, 1000.0)
    got = heartbeat.verdict(tmp_path, now=1020.0, current_boot=BOOT_A, current_uptime_s=5000.0)
    assert got["verdict"] == "running"


def test_a_stale_heartbeat_of_this_boot_is_a_conductor_that_died(tmp_path):
    beat_at(tmp_path, 1000.0)
    got = heartbeat.verdict(tmp_path, now=1000.0 + 10 * heartbeat.PERIOD_S, current_boot=BOOT_A,
                            current_uptime_s=50000.0)
    assert got["verdict"] == "interrupted"


def test_another_boot_id_is_a_host_restart_however_fresh_the_file_looks(tmp_path):
    beat_at(tmp_path, 1000.0, boot=BOOT_A)
    got = heartbeat.verdict(tmp_path, now=1010.0, current_boot=BOOT_B, current_uptime_s=3000.0)
    assert got["verdict"] == "interrupted_host_restart"


def test_a_host_up_for_less_time_than_the_heartbeat_is_old_is_a_restart_even_with_one_boot_id(
        tmp_path):
    beat_at(tmp_path, 1000.0, boot=BOOT_A)
    got = heartbeat.verdict(tmp_path, now=1000.0 + 3600, current_boot=BOOT_A, current_uptime_s=60.0)
    assert got["verdict"] == "interrupted_host_restart"


def test_no_file_is_said_so(tmp_path):
    assert heartbeat.verdict(tmp_path)["verdict"] == "no_heartbeat"


def test_the_command_exits_3_for_anything_but_clean_or_running(tmp_path, capsys):
    assert heartbeat.main([str(tmp_path)]) == 3
    assert "no_heartbeat" in capsys.readouterr().out
