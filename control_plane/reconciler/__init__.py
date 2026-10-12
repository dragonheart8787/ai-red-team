"""The reconciler (D58-9, D64): finds what a crash or a lapse left behind and puts it right.

Two halves, kept apart on purpose (docs/D64_RECONCILER_DESIGN.md §2.2a):

* **plan** -- ``observe.py`` reads (the database through the reader role's two functions, Docker
  with
  read calls, the temporary directory with ``lstat``); ``plan.py`` is a *pure function* from what
  was
  read and the configured thresholds to a list of actions and reports. It holds no connection and
  does nothing.
* **act** (step 6c) -- consumes the list. Not in this package yet.

Every number that decides anything comes from ``config.py`` and nowhere else; with one missing the
reconciler refuses to start. It never resumes, re-runs, re-issues or re-proposes anything (I7).
"""
