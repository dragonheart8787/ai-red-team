"""Post-hoc classification of every log a soak produced (D66).

    python -m scripts.soak.logscan RUN_DIR [--out FILE]

The checks of a soak ask questions fixed in advance; this asks the logs what *they* contain, after
the run, so that what nobody thought to check for is at least seen. Sources:

* the services' own logs (``RUN_DIR/logs/*.log``) -- no timestamps; every line that names an error
  is kept, and every reconciler action whose outcome is not ``done``;
* the Docker daemon's log (``/tmp/dockerd.log``, where the soak's fault injector sends it) --
  warnings and errors from the soak's start to its end;
* the Postgres server log (``/var/log/postgresql/*.log``) -- ``WARNING``, ``ERROR``, ``FATAL``,
  ``PANIC`` and the ``LOG`` lines that report a connection lost, from the soak's start to its end.

A line is **normalised** (ids, numbers, hashes, addresses replaced) and grouped with the others of
the same source, level and shape. A group is then put in exactly one class:

* ``explained`` -- every occurrence lies inside the window of a fault (from its start to its
  recovery, plus ``GRACE_S``) or of the run's shutdown. The fault kinds that cover it are named.
  This says *when*, not *why*: a line inside a window is not thereby understood, only expected to
  be near a fault.
* ``not_explained`` -- at least one occurrence outside every window. Listed with its first and last
  time, its count inside and outside windows, and samples.
* ``untimed`` -- the source has no timestamps (the services' logs). Listed; not placed.

Nothing here judges a run or stops one. The report prints the groups, and a person reads them.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from calendar import timegm
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

#: how long after a fault's recovery a line is still attributed to it
GRACE_S = 60.0
#: a fault with no recorded recovery is taken to last this long
OPEN_WINDOW_S = 600.0
DOCKERD_LOG = Path("/tmp/dockerd.log")
POSTGRES_LOGS = "/var/log/postgresql/*.log"

_ERRORISH = re.compile(r"traceback|exception|error|fatal|panic|refused|failed|cannot|could not|"
                       r"unable|denied|stopped \(exit|timed? ?out|exited|killed|lost", re.I)
_PG_HEAD = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\.\d+)? UTC \[(\d+)\] "
                      r"(?:(\S+?)@(\S+) )?(DEBUG\d?|INFO|NOTICE|WARNING|ERROR|LOG|FATAL|PANIC|"
                      r"DETAIL|HINT|STATEMENT|CONTEXT|QUERY):\s+(.*)$")
_PG_KEEP_LOG = re.compile(r"unexpected EOF|could not receive data|connection to client lost|"
                          r"terminated by signal|was terminated|could not send data|"
                          r"too frequently|deadlock|canceling|temporary file", re.I)
_DOCKERD = re.compile(r'^time="(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z" level=(\w+) '
                      r'msg="((?:[^"\\]|\\.)*)"(.*)$')

_NORMALISE = [
    (re.compile(r"\b[0-9a-f]{12,64}\b"), "<hex>"),
    (re.compile(r"\b(?:PROP|RUN|ENG|CAP|APP|EV)-[A-Za-z0-9-]+"), "<id>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), "<uuid>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/\d+)?\b"), "<ip>"),
    (re.compile(r"\b\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?Z?\b"), "<time>"),
    (re.compile(r"/tmp/[^\s\"']+"), "<tmp>"),
    (re.compile(r"\b\d+(?:\.\d+)?\b"), "<n>"),
]


#: sources that could not be read in this process (so that a report never reads as "nothing there")
SKIPPED: list[str] = []


def normalise(text: str) -> str:
    for pattern, token in _NORMALISE:
        text = pattern.sub(token, text)
    return re.sub(r"\s+", " ", text).strip()[:240]


@dataclass
class Entry:
    source: str
    level: str
    message: str
    ts: float | None = None               # None: the source has no timestamps
    raw: str = ""
    in_window: bool = False


@dataclass
class Group:
    source: str
    level: str
    shape: str
    entries: list[Entry] = field(default_factory=list)
    inside: int = 0
    outside: int = 0
    kinds: dict[str, int] = field(default_factory=dict)

    @property
    def klass(self) -> str:
        if all(e.ts is None for e in self.entries):
            return "untimed"
        return "explained" if self.outside == 0 and self.inside else "not_explained"


def _utc(text: str) -> float:
    return float(timegm(time.strptime(text, "%Y-%m-%d %H:%M:%S" if " " in text
                                 else "%Y-%m-%dT%H:%M:%S")))


# -- the sources --------------------------------------------------------------------------------

def read_postgres(paths: list[Path], since: float, until: float) -> list[Entry]:
    out: list[Entry] = []
    for path in paths:
        current: Entry | None = None
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError as exc:
            SKIPPED.append(f"{path}: {exc.strerror}")
            continue
        for line in lines:
            head = _PG_HEAD.match(line)
            if not head:
                continue
            stamp, _pid, role, _db, level, message = head.groups()
            ts = _utc(stamp)
            if level in ("DETAIL", "HINT", "STATEMENT", "CONTEXT", "QUERY"):
                if current is not None and level in ("DETAIL", "HINT"):
                    current.message += f" [{level.lower()}: {message}]"
                continue
            current = None
            if ts < since or ts > until:
                continue
            keep = level in ("WARNING", "ERROR", "FATAL", "PANIC") or (
                level == "LOG" and _PG_KEEP_LOG.search(message))
            if not keep:
                continue
            current = Entry("postgres", level, (f"{role}: " if role else "") + message, ts, line)
            out.append(current)
    return out


def read_dockerd(path: Path, since: float, until: float) -> list[Entry]:
    out: list[Entry] = []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError as exc:
        SKIPPED.append(f"{path}: {exc.strerror}")
        return out
    last_ts: float | None = None
    for line in lines:
        m = _DOCKERD.match(line)
        if not m:
            # panics and stack traces have no level and no time of their own: they belong to the
            # line before them, and are read only if that one was inside the run
            if _ERRORISH.search(line) and last_ts is not None and since <= last_ts <= until:
                out.append(Entry("dockerd", "unparsed", line.strip()[:240], last_ts, line))
            continue
        stamp, level, message, _rest = m.groups()
        ts = _utc(stamp)
        last_ts = ts
        if ts < since or ts > until or level not in ("warning", "error", "fatal", "panic"):
            continue
        out.append(Entry("dockerd", level, message, ts, line))
    return out


def read_service_logs(log_dir: Path) -> list[Entry]:
    out: list[Entry] = []
    for path in sorted(log_dir.glob("*.log")):
        name = path.stem
        for raw in path.read_text(errors="replace").splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    record = json.loads(line)
                except ValueError:
                    record = None
                if isinstance(record, dict):
                    outcome = record.get("outcome")
                    if outcome is not None and outcome != "done":
                        out.append(Entry(name, "action", f"{record.get('kind')} -> {outcome} "
                                         f"({record.get('reason_code')})", None, line))
                    continue
            if _ERRORISH.search(line):
                out.append(Entry(name, "log", line[:240], None, raw))
    return out


# -- windows and groups -------------------------------------------------------------------------

def fault_windows(journal: list[dict]) -> list[tuple[float, float, str]]:
    """``(start, end, kind)`` per fault: the start of the fault to its recovery (or
    ``OPEN_WINDOW_S``) plus ``GRACE_S``."""
    recoveries = [r for r in journal if r.get("kind") == "fault.recovery"]
    out = []
    for begin in (r for r in journal if r.get("kind") == "fault.begin"):
        start = float(begin["ts"])
        after = [r for r in recoveries if r.get("fault") == begin.get("fault")
                 and float(r["ts"]) >= start]
        end = (float(after[0]["ts"]) if after else start + OPEN_WINDOW_S) + GRACE_S
        out.append((start - 5.0, end, str(begin.get("fault"))))
    # the end of a run stops its services and closes their connections: a window of its own
    for end_event in (r for r in journal if r.get("kind") == "soak.teardown"):
        at = float(end_event["ts"])
        out.append((at - 90.0, at + GRACE_S, "shutdown"))
    return out


def group(entries: list[Entry], windows: list[tuple[float, float, str]]) -> list[Group]:
    groups: dict[tuple[str, str, str], Group] = {}
    for entry in entries:
        key = (entry.source, entry.level, normalise(entry.message))
        g = groups.setdefault(key, Group(*key))
        g.entries.append(entry)
        if entry.ts is None:
            continue
        kinds = {kind for start, end, kind in windows if start <= entry.ts <= end}
        if kinds:
            entry.in_window = True
            g.inside += 1
            for kind in kinds:
                g.kinds[kind] = g.kinds.get(kind, 0) + 1
        else:
            g.outside += 1
    return sorted(groups.values(), key=lambda g: (g.klass, -len(g.entries)))


def scan(run_dir: Path, journal: list[dict], *, dockerd: Path = DOCKERD_LOG,
         postgres_glob: str = POSTGRES_LOGS) -> list[Group]:
    times = [float(r["ts"]) for r in journal if "ts" in r]
    since = min(times, default=0.0)
    until = max(times, default=0.0) + 120.0
    entries = read_service_logs(run_dir / "logs")
    entries += read_dockerd(dockerd, since, until)
    entries += read_postgres([Path(p) for p in sorted(Path("/").glob(postgres_glob.lstrip("/")))],
                             since, until)
    return group(entries, fault_windows(journal))


# -- the text -----------------------------------------------------------------------------------

def _clock(ts: float | None) -> str:
    return "-" if ts is None else time.strftime("%H:%M:%S", time.gmtime(ts))


def render(groups: list[Group], *, samples: int = 2) -> list[str]:
    lines = ["| class | source | level | count | inside / outside windows | fault kinds | "
             "first - last | shape |", "|---|---|---|---|---|---|---|---|"]
    for g in groups:
        times = sorted(e.ts for e in g.entries if e.ts is not None)
        span = f"{_clock(times[0])} - {_clock(times[-1])}" if times else "-"
        inside = f"{g.inside} / {g.outside}" if times else "-"
        kinds = ", ".join(f"{k} {n}" for k, n in sorted(g.kinds.items())) or "-"
        lines.append(f"| {g.klass} | {g.source} | {g.level} | {len(g.entries)} | {inside} | "
                     f"{kinds} | {span} | `{g.shape.replace('|', '/')[:150]}` |")
    unexplained = [g for g in groups if g.klass != "explained"]
    if unexplained:
        lines.append("\nSamples of what is not explained (raw lines):\n")
        for g in unexplained:
            outside = [e for e in g.entries if not e.in_window]
            for e in outside[:samples]:
                lines.append(f"* `{g.source}/{g.level}` {e.raw.strip()[:300]}")
    return lines


def summary(groups: list[Group]) -> dict:
    by_class: dict[str, dict[str, int]] = defaultdict(lambda: {"groups": 0, "lines": 0})
    for g in groups:
        by_class[g.klass]["groups"] += 1
        by_class[g.klass]["lines"] += len(g.entries)
    return dict(by_class)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    journal = []
    for line in (args.run_dir / "events.jsonl").read_text().splitlines():
        try:
            journal.append(json.loads(line))
        except ValueError:
            pass
    groups = scan(args.run_dir, journal)
    text = "\n".join([f"classes: {json.dumps(summary(groups))}\n", *render(groups)]) + "\n"
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
