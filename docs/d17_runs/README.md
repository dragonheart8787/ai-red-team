# D17 run artifacts

The raw records behind every number in `../D17_SUPERVISOR_REPORT.md`. Committed —
unlike D13's and D15's, which were not — because a report whose figures cannot
be re-derived is a report that has to be believed.

```
python scripts/live_run/d17_analyze.py docs/d17_runs/d17_*.json
```

One file per arm, because the arms were run one process at a time: an earlier
attempt did all five in one 62-call run, lost 46 calls to an unexplained CLI
failure and was then killed by a container reclaim. That run is not here and
none of its numbers are reported.

`d17_blind_taskmanager.txt` is read back from the database rather than from the
harness — twenty-five tasks, twenty-five claims, sixteen agents holding live
leases on the same sweep.

Each record carries what the model returned, the latency, the token counts, the
structural key the task reduces to, and whether the real Authorization Resolver
would have authorized it. No credentials, no raw evidence: the targets are the
disposable lab container on `10.79.0.0/24`.
