"""The soak's heartbeat file, and how a run that stopped is told from one that ended (D66).

    python -m scripts.soak.heartbeat RUN_DIR      # the verdict; exit 0 clean/running, 3 otherwise

The conductor rewrites ``RUN_DIR/heartbeat.json`` every ``PERIOD_S`` (30) seconds, atomically and
flushed to disk: the moment it was written, the conductor's pid, the host's boot id and kernel,
the host's uptime, the phase of the run and when the last sample was taken. It exists because a
run can stop with nothing in its own journal -- the machine under it restarted, was replaced or
was paused -- and then the last thing a person can learn is *when the last sign of life was* and
*which boot of which machine it belonged to*. A run found in that state is marked
**interrupted**; it is never resumed, joined to another run or counted as one.

The verdicts (``verdict``):

* ``clean``                      the journal has ``soak.teardown``: it ended by itself
* ``running``                    no teardown, the heartbeat is fresh and is of this boot
* ``interrupted_host_restart``   no teardown and the boot id now differs from the heartbeat's
                                 (or the host has been up less long than the heartbeat is old)
* ``interrupted``                no teardown, the same boot, the heartbeat stale: the conductor died
* ``no_heartbeat``               no heartbeat file at all
"""

from __future__ import annotations

import json
import os
import platform
import sys
import time
from pathlib import Path

PERIOD_S = 30.0
#: a heartbeat older than this many periods is stale
STALE_PERIODS = 3
FILE = "heartbeat.json"


def boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return "unknown"


def host_uptime_s() -> float | None:
    try:
        return float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def host_identity() -> dict:
    return {"boot_id": boot_id(), "kernel": platform.release(), "host_uptime_s": host_uptime_s()}


def write(run_dir: Path, *, phase: str, **extra) -> dict:
    """Replace the heartbeat file: write a sibling, flush it to disk, rename it over the old one."""
    record = {"ts": round(time.time(), 3), "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "pid": os.getpid(), "phase": phase, **host_identity(), **extra}
    target = Path(run_dir) / FILE
    scratch = target.with_suffix(".tmp")
    fd = os.open(scratch, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (json.dumps(record, sort_keys=True, default=str) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(scratch, target)
    return record


def read(run_dir: Path) -> dict | None:
    try:
        return json.loads((Path(run_dir) / FILE).read_text())
    except (OSError, ValueError):
        return None


def _ended(run_dir: Path) -> bool:
    journal = Path(run_dir) / "events.jsonl"
    try:
        return any('"kind": "soak.teardown"' in line for line in journal.read_text().splitlines())
    except OSError:
        return False


def verdict(run_dir: Path, *, now: float | None = None, current_boot: str | None = None,
            current_uptime_s: float | None = None) -> dict:
    now = time.time() if now is None else now
    current_boot = boot_id() if current_boot is None else current_boot
    uptime = host_uptime_s() if current_uptime_s is None else current_uptime_s
    beat = read(run_dir)
    if _ended(run_dir):
        return {"verdict": "clean", "heartbeat": beat}
    if beat is None:
        return {"verdict": "no_heartbeat", "heartbeat": None}
    age = now - float(beat["ts"])
    out = {"heartbeat": beat, "heartbeat_age_s": round(age, 1)}
    if beat.get("boot_id") != current_boot or (uptime is not None and uptime + 5 < age):
        return {"verdict": "interrupted_host_restart", **out}
    if age > STALE_PERIODS * PERIOD_S:
        return {"verdict": "interrupted", **out}
    return {"verdict": "running", **out}


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print(__doc__.splitlines()[0], file=sys.stderr)
        return 2
    result = verdict(Path(args[0]))
    print(json.dumps(result, indent=1, default=str))
    return 0 if result["verdict"] in ("clean", "running") else 3


if __name__ == "__main__":
    raise SystemExit(main())
