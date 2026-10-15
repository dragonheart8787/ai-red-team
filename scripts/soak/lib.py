"""Shared pieces of the soak harness (D66): the event journal, the process and Docker readings.

Nothing here is part of the product. It reads ``/proc``, Docker and Postgres from the outside, the
way an operator would, and writes one line per thing that happened to ``events.jsonl``.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

OWNER_LABEL = "cyberorch.owner"
RUN_LABEL = "cyberorch.run_id"
PROXY_LABEL = "cyberorch.egress_proxy"
NETWORK_PREFIX = "cyberorch-allow-"
FILE_PREFIXES = ("cyberorch-cred-", "cyberorch-tls-")


def now() -> float:
    return time.time()


def stamp(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now() if ts is None else ts))


class Journal:
    """Append-only JSON lines, safe to write from several threads (and processes: one ``write``
    call per line on an ``O_APPEND`` file is not interleaved)."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, kind: str, **data) -> dict:
        record = {"ts": round(now(), 3), "at": stamp(), "kind": kind, **data}
        line = json.dumps(record, sort_keys=True, default=str) + "\n"
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line.encode())
            finally:
                os.close(fd)
        return record

    def read(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text().splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue                         # a line cut short by a kill
        return out


def load_env() -> None:
    import sys
    sys.path.insert(0, str(REPO_ROOT))
    from control_plane.config import load_dotenv
    load_dotenv()


# ---------------------------------------------------------------------------------------------
# processes, from /proc
# ---------------------------------------------------------------------------------------------

def proc_stats(pid: int) -> dict | None:
    """Resident memory (kB), file descriptors, threads, and TCP connections to Postgres. ``None``
    for a process that is gone."""
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        rss = threads = 0
        state = "?"
        for line in status.splitlines():
            if line.startswith("VmRSS:"):
                rss = int(line.split()[1])
            elif line.startswith("Threads:"):
                threads = int(line.split()[1])
            elif line.startswith("State:"):
                state = line.split()[1]
        fds = os.listdir(f"/proc/{pid}/fd")
        inodes = set()
        for fd in fds:
            try:
                target = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if target.startswith("socket:["):
                inodes.add(target[8:-1])
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    if state == "Z":
        return None
    return {"rss_kb": rss, "fds": len(fds), "threads": threads, "state": state,
            "pg_connections": _tcp_to_port(inodes, 5432)}


def _tcp_to_port(inodes: set[str], port: int) -> int:
    count = 0
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(table).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            remote, state, inode = parts[2], parts[3], parts[9]
            if state == "01" and inode in inodes and int(remote.rsplit(":", 1)[1], 16) == port:
                count += 1
    return count


def alive(pid: int | None) -> bool:
    return bool(pid) and proc_stats(pid) is not None


# ---------------------------------------------------------------------------------------------
# Postgres, as the superuser (pg_stat_activity shows other roles' state only to one)
# ---------------------------------------------------------------------------------------------

def psql(statement: str, *, timeout: float = 30.0) -> list[list[str]]:
    done = subprocess.run(
        ["su", "postgres", "-c", f"psql -d cyberorch -At -F '|' -v ON_ERROR_STOP=1 -c "
                                  f"\"{statement}\""],
        capture_output=True, text=True, timeout=timeout)
    if done.returncode != 0:
        raise RuntimeError(f"psql failed: {done.stderr.strip()[-300:]}")
    return [line.split("|") for line in done.stdout.splitlines() if line]


def pg_connections() -> dict:
    """Backends of this database by role and state, and the idle-in-transaction ones by age."""
    rows = psql("SELECT coalesce(usename, ''), coalesce(state, ''), count(*), "
                "coalesce(max(extract(epoch FROM now() - xact_start))::int, 0) "
                "FROM pg_stat_activity WHERE datname = 'cyberorch' AND pid <> pg_backend_pid() "
                "GROUP BY 1, 2")
    by_role: dict[str, int] = {}
    idle_in_transaction_s = 0
    for role, state, count, age in rows:
        by_role[role] = by_role.get(role, 0) + int(count)
        if state.startswith("idle in transaction"):
            idle_in_transaction_s = max(idle_in_transaction_s, int(age))
    return {"by_role": by_role, "total": sum(by_role.values()),
            "idle_in_transaction_max_age_s": idle_in_transaction_s}


def db_reachable() -> bool:
    try:
        psql("SELECT 1", timeout=10)
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------------------------

def docker_client(timeout: int = 20):
    import docker
    return docker.from_env(timeout=timeout)


def docker_reachable() -> bool:
    try:
        docker_client(5).ping()
        return True
    except Exception:  # noqa: BLE001
        return False


def docker_counts(client, tmp_dir: str, evidence_dir: Path | None) -> dict:
    """What the host holds that the product made: containers by kind and state, sandbox
    networks, credential/TLS files in the temp directory, evidence files."""
    tools = {"running": 0, "paused": 0, "exited": 0, "other": 0}
    proxies = {"running": 0, "paused": 0, "exited": 0, "other": 0}
    for container in client.containers.list(all=True, filters={"label": OWNER_LABEL}):
        labels = container.labels or {}
        bucket = proxies if PROXY_LABEL in labels else tools
        status = container.status
        bucket[status if status in bucket else "other"] += 1
    networks = [n.name for n in client.networks.list() if n.name.startswith(NETWORK_PREFIX)]
    files = sorted(name for name in os.listdir(tmp_dir) if name.startswith(FILE_PREFIXES))
    evidence = 0
    if evidence_dir is not None and evidence_dir.exists():
        evidence = sum(1 for p in evidence_dir.rglob("*") if p.is_file())
    return {"tools": tools, "proxies": proxies, "networks": len(networks), "files": len(files),
            "evidence_files": evidence}
