"""Experiment (D66 pilot): the reconciler's container listing while containers come and go.

    python -m scripts.soak.experiment_list_race        # one minute; needs python:3.12-slim

One thread creates, starts and removes a labelled container about three times a second -- what a
dispatching control plane does -- while this one calls the reconciler's own
``observe.list_containers`` over and over, and every exception is looked at through the reconciler's
own ``service._translate``. It touches no product state: the containers carry the sandbox's two
labels with an owner (``ENG-EXPERIMENT``) that is no engagement, and are removed by the thread.
"""

from __future__ import annotations

import collections
import sys
import threading
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import docker  # noqa: E402

from control_plane.reconciler import observe  # noqa: E402
from control_plane.reconciler.service import _translate  # noqa: E402


def main(seconds: float = 60.0) -> int:
    client = docker.from_env()
    stop = threading.Event()
    made = [0]

    def churn() -> None:
        other = docker.from_env()
        while not stop.is_set():
            container = other.containers.create(
                "python:3.12-slim", command=["true"],
                labels={"cyberorch.run_id": "RUN-EXP-" + uuid.uuid4().hex[:6],
                        "cyberorch.owner": "ENG-EXPERIMENT"})
            container.start()
            time.sleep(0.2)
            container.remove(force=True)
            made[0] += 1

    thread = threading.Thread(target=churn)
    thread.start()
    errors: collections.Counter = collections.Counter()
    first = None
    lists = 0
    end = time.time() + seconds
    while time.time() < end:
        try:
            observe.list_containers(client)
            lists += 1
        except Exception as exc:  # noqa: BLE001 -- what the reconciler would have done with it
            errors[type(exc).__name__] += 1
            if first is None:
                stop_for = _translate(exc)
                first = (type(exc).__name__, str(exc)[:160], stop_for.reason, stop_for.exit_code)
    stop.set()
    thread.join()
    print(f"containers churned {made[0]}; listings that returned {lists}; "
          f"listings that raised {dict(errors)}")
    print(f"the first one: {first}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
