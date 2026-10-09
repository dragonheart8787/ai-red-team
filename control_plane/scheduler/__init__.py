"""The scheduler, v0 (D62, D58-1/2/3/4).

One job: for each *enrolled* engagement, find proposals a human approved that nothing has dispatched
yet and call ``dispatch_approved`` for each, one at a time. Level-triggered: every tick re-derives
what to do from the database. Not here: planning (D58-12), the failure ladder (D58-6), the
reconciler (D58-9), quotas (D58-13), credential selection (D58-15).

The module layout *is* the safety argument -- see ``tests/test_scheduler_structure.py``:

* ``decide``  reads (as ``scheduler_reader``) and decides. It can reach no execution connection.
* ``execute`` derives runtime context and dispatches (as ``cyberorch_app``). It can reach no reader.
* ``emit`` and ``state`` write the scheduler's own audit events and closed-vocabulary state.
* ``service`` wires them together and passes only ids and enum codes between.
"""
