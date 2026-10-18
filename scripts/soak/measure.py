"""Measure the machine a soak runs on, and set its caps from what was measured (D66).

    python -m scripts.soak.measure --dir RUN_DIR [--out caps.json]

The caps of ``conductor.CAPS`` were fixed for the development machine. A runner is another machine,
so before a run on one the machine is measured -- memory, cores, free disk, the descriptor limit,
what Postgres allows, what the idle Docker daemon and Postgres weigh -- and the caps are derived by
the rules below, **never above the default**, and written with the measurements to ``caps.json``,
which the conductor reads (``--caps-file``), puts in its journal and prints in the report as *the
caps of this environment, measured*. The rules are fixed here, in code, before any run; a cap
derived this way is a statement about the environment, not something chosen to make a run pass.

| cap | rule |
|---|---|
| ``rss_mb`` scheduler, reconciler | the default, or 5 % of the machine's memory if that is less |
| ``rss_mb`` worker, conductor | the default, or 8 % of the machine's memory if that is less |
| ``fds`` | the default, or half of the soft descriptor limit if that is less |
| ``pg_connections_per_process`` | the default, or a quarter of Postgres' ``max_connections`` |
| ``pg_backends_total`` | the default, or 80 % of ``max_connections`` less the reserved ones |
| ``containers_total`` | the default, or 25 per core if that is less |
| ``networks`` | the default (a Docker address pool is the limit, and is not measured) |
| ``run_dir_mb`` | the default, or 25 % of the disk free at the start if that is less |
| ``events_file_mb`` | the default, or half of ``run_dir_mb`` if that is less |
| ``disk_free_mb_min`` | the default, or 5 % of the disk's size if that is less, never below 512 |
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import time
from pathlib import Path

DEFAULT_CAPS = {
    "rss_mb": {"scheduler": 512, "reconciler": 512, "worker": 1024, "conductor": 1024},
    "fds": 1024,
    "pg_connections_per_process": 20,
    "pg_backends_total": 80,
    "containers_total": 150,
    "networks": 20,
    "run_dir_mb": 2048,
    "events_file_mb": 512,
    "disk_free_mb_min": 2048,
}


def derive_caps(measured: dict, defaults: dict | None = None) -> dict:
    """The caps for a machine with these measurements. Pure."""
    caps = copy.deepcopy(DEFAULT_CAPS if defaults is None else defaults)
    mem = measured.get("mem_total_mb")
    if mem:
        for name in ("scheduler", "reconciler"):
            caps["rss_mb"][name] = min(caps["rss_mb"][name], int(0.05 * mem))
        for name in ("worker", "conductor"):
            caps["rss_mb"][name] = min(caps["rss_mb"][name], int(0.08 * mem))
    if measured.get("nofile_soft"):
        caps["fds"] = min(caps["fds"], int(measured["nofile_soft"] // 2))
    maxc = measured.get("pg_max_connections")
    if maxc:
        reserved = measured.get("pg_superuser_reserved", 3)
        caps["pg_connections_per_process"] = min(caps["pg_connections_per_process"], int(maxc // 4))
        caps["pg_backends_total"] = min(caps["pg_backends_total"], int(0.8 * (maxc - reserved)))
    if measured.get("cores"):
        caps["containers_total"] = min(caps["containers_total"], 25 * int(measured["cores"]))
    if measured.get("disk_free_mb"):
        caps["run_dir_mb"] = min(caps["run_dir_mb"], int(0.25 * measured["disk_free_mb"]))
    caps["events_file_mb"] = min(caps["events_file_mb"], max(1, caps["run_dir_mb"] // 2))
    if measured.get("disk_total_mb"):
        caps["disk_free_mb_min"] = min(caps["disk_free_mb_min"],
                                       max(512, int(0.05 * measured["disk_total_mb"])))
    return caps


def _meminfo_mb(key: str) -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith(key + ":"):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def measure() -> dict:
    import resource

    from scripts.soak import lib

    usage = shutil.disk_usage("/")
    soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    out: dict = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cores": os.cpu_count(),
        "mem_total_mb": _meminfo_mb("MemTotal"),
        "mem_available_mb": _meminfo_mb("MemAvailable"),
        "disk_total_mb": usage.total // 2**20,
        "disk_free_mb": usage.free // 2**20,
        "nofile_soft": soft if soft != resource.RLIM_INFINITY else None,
        "load_1m": os.getloadavg()[0],
        "idle_rss_mb": {name: lib.rss_of_named(name) for name in ("dockerd", "containerd",
                                                                   "postgres")},
    }
    try:
        out["pg_max_connections"] = int(lib.psql("SHOW max_connections")[0][0])
        out["pg_superuser_reserved"] = int(lib.psql("SHOW superuser_reserved_connections")[0][0])
    except Exception as exc:  # noqa: BLE001 -- said in the file, and the default stays
        out["pg_error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
    try:
        client = lib.docker_client()
        try:
            info = client.info()
        finally:
            client.close()
        out["docker"] = {"server": info.get("ServerVersion"), "ncpu": info.get("NCPU"),
                         "mem_total_mb": (info.get("MemTotal") or 0) // 2**20,
                         "storage_driver": info.get("Driver")}
    except Exception as exc:  # noqa: BLE001
        out["docker_error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    args.dir.mkdir(parents=True, exist_ok=True)
    measured = measure()
    document = {"source": f"measured on this machine at {measured['at']}", "measured": measured,
                "defaults": DEFAULT_CAPS, "caps": derive_caps(measured)}
    (args.out or args.dir / "caps.json").write_text(json.dumps(document, indent=1))
    print(json.dumps(document["caps"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
