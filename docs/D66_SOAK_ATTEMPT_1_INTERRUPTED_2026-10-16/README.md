# Soak attempt 1 -- interrupted (not a result)

Kept: what was observed after the host event, as captured (see `docs/D66_SOAK.md` §6 and ACCEPTANCE
5.110/5.111). Not kept, because the disk that held them was replaced: the run directory with its
journal, its last sample, the services' logs and the Postgres log of the run.

* `after_second_reset.txt` -- the kernel, boot and file birth times of the replacement machine
* `db_after_reset.txt` -- row counts of the database that exists (all 0) and the enrollment list
* `reconciler_dry_run_after_reset.txt` -- `run_reconciler.py --mode dry-run --once` on it (empty plan)
