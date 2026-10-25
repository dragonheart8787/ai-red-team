# D68 DP-15 record mode: the layer, how to publish it, how to take it back

**Nothing in this file has been run against a deployment, and no layer has been published.** The
owner decides whether and when. Claims: [R] read, [E] executed, [D] derived, [N] not established.

## 0. The database the measurement runs in: a clean one

**The measurement is run in a database made for it, and in no other.** The generator
(`scripts/dp15_record_mode.py`) reads the database it is connected to before it does anything, in
a dry run too, and prints its name, its migration revision, the calls already recorded per class
and the effective `goal_fit_enforce` / `task_relation_enforce`. It **refuses to start** (exit 1,
reasons listed, nothing sent) when

* any class in the list -- the layer file's, the three measured and any other the effective policy
  lists -- already has a row in `goal_fit_calls`, or an uncleared row in `goal_fit_suspensions`
  (`--allow-nonempty` lifts these two refusals, for tests only, and prints a warning; it lifts
  nothing else);
* `goal_fit_enforce` is not off in the effective policy -- no flag lifts this;
* the database cannot be read (the guards could not be checked).

Why a database of its own: the registered numbers are "the first 50 judgements per class" of this
measurement, and the plan reads them from the tables. Rows left by anything else -- tests, an
earlier try, a soak -- would be counted as part of the 50 or would hide that the class was already
suspended. The development database of this session is such a database: the dry run there
refuses (`network.scan already has 180 row(s) in goal_fit_calls`) [E]. A second measurement is a
second clean database, not the same one again.

Steps (the database name is the owner's choice; `cyberorch_dp15` is what was tried):

1. **Create it, at head.** `DB_NAME=cyberorch_dp15 bash scripts/init_db.sh` creates the roles
   (idempotent), the database owned by `migration_owner`, and runs `alembic upgrade head`; the head
   is **0030**. **It also rewrites `.env`** so that every connection string names the new database:
   keep the old file first (`cp -p .env .env.keep`), or run the script from a separate checkout.
   The measurement is then run with the `.env` that names the new database -- the generator prints
   that name first, and the owner reads it before typing `SEND`. [E: run on the development
   cluster with the old `.env` kept and put back; the old database was not touched.]
2. **Check it is empty**, as the database superuser (so that row-level security hides nothing):

   ```sql
   SELECT 'revision', version_num FROM alembic_version;
   SELECT 'pending approvals', count(*) FROM action_proposals
     WHERE pipeline_stage = 'awaiting_approval';
   SELECT 'policy layers', count(*) FROM policy_layers;
   SELECT 'goal_fit_calls', count(*) FROM goal_fit_calls;
   SELECT 'goal_fit_suspensions', count(*) FROM goal_fit_suspensions;
   SELECT 'engagements', count(*) FROM engagements;
   ```

   [E] on the database made for this document: revision `0030`, and `0` for each of the other
   five. **Pending approvals must be 0** -- if it is not, stop: publishing a global layer voids
   every approval waiting (section 5).
3. **Put a global baseline in it** (not done here): `create_engagement` refuses to make an
   engagement when no `baseline_global` layer is in force, and the measurement makes one of its
   own. The platform owner publishes the baseline the deployment would run on; for a database that
   exists only for this measurement a neutral one (`{}`, the document `tests/helpers.py` uses) adds
   nothing to the merge. Publish it with `manage_global_policy.py publish --layer baseline_global`
   as in section 3. [N: not executed; no layer was published in the database of step 2.]
4. **Rehearse, then publish the layer of section 1 in that database**, then run the generator.
   A dry run (`PYTHONPATH=. python scripts/dp15_record_mode.py`) exits 0 only when the guards would
   let the run start; its output with this database is `dry_run_output.txt`.

## 1. The layer

`layer_record_mode.json`:

```json
{ "goal_fit_actions": ["code.scan", "code.secrets", "network.scan"] }
```

* **The names** are the tool gateway's own (`tool_gateway/registry.py`, `ADAPTERS`): `code.scan`
  and `code.secrets` are the two `code.*` actions it can run, `network.scan` one of the two nmap
  actions [R]. `network.recon`, `ad.collect` and the `web.*` actions are deliberately not listed;
  `ad.collect` and `network.recon` are the classes S7 found stopped most often.
* **`goal_fit_enforce` is off by being absent.** It is not written `false`: an emergency overlay
  may only turn a switch *on*, and the publication check refuses a document that says `false`
  ("emergency overlay may only turn goal_fit_enforce on") [E: tried]. Absent, the switch is
  whatever the other layers say, which is off everywhere; `task_relation_enforce` is not touched.
* **Why an emergency overlay.** The list only adds checks, so an overlay may carry it, and an
  overlay is the one form that reaches engagements already open and is withdrawn by retiring it
  (ACCEPTANCE 5.124: a baseline layer is frozen into an engagement at its creation and a baseline
  published this way cannot be rolled back for engagements that have it).
* **What it changes**, with the switch off and a validator configured: Q1 is *asked* for those
  three classes and each call is recorded (`goal_fit_calls`); no decision, reason or approval
  changes (tested end to end for three validators, including one that fails every call). With no
  validator configured it changes nothing at all: `not_assessed / disabled`, as now.

## 2. Validate it without publishing (done)

```
python scripts/manage_global_policy.py publish --layer emergency_overlay --version 1 \
    --document-file docs/D68_DP15_RECORD_MODE/layer_record_mode.json --actor <who> --dry-run
```

Every check of a publication runs -- the code's validation, the overlay's tighten-only rule, the
global-admin connection, and the database's own CHECK constraints (by attempting the INSERT in a
savepoint that is rolled back). No row, no audit record, no new policy version. [E] Output on the
development database:

```
DRY RUN: global emergency_overlay v1 as dry-run-check would be accepted.
  document: {"goal_fit_actions": ["code.scan", "code.secrets", "network.scan"]}
Q1 would be asked about 3 action class(es) (when a validator is configured; with goal_fit_enforce off nothing it says changes a decision):
  code.scan       not recorded yet
  code.secrets    not recorded yet
  network.scan    130 judgement(s) and 0 transport failure(s) recorded, not in the list
  goal_fit_enforce in this document: False
Nothing was published, audited or changed.
```

The same document was also accepted as a `baseline_global` layer by the dry run; the overlay is the
form this plan uses. The development database held, before and after, 5,232 layers, 57 of them
active, and its newest layer id was 56,435 (a dry run consumes one value of the id sequence and
nothing else). [E]

## 3. Publish (not executed)

Before: read the pending-approval count (section 5), then list what is in force.

```
python scripts/manage_global_policy.py list
python scripts/manage_global_policy.py publish --layer emergency_overlay \
    --version "$(date +%s)" \
    --document-file docs/D68_DP15_RECORD_MODE/layer_record_mode.json --actor <who>
```

The tool shows the layer and asks for `PUBLISH` on a terminal. It prints `published layer id=<N>`;
**write N down**, it is the rollback handle. `--version` only has to be unused for that layer name
(`policy_layers_identity`); a timestamp is. [R]

After: `python scripts/manage_global_policy.py list` shows the layer, and the effective policy of
any engagement lists the three classes. The measurement script checks that, in the effective policy of an engagement of its own (plan,
rule 12), and refuses to send anything otherwise.

## 4. Roll back (not executed)

```
python scripts/manage_global_policy.py deactivate --layer-id <N> --actor <who>
```

The tool says that retiring an emergency overlay "RELAXES policy" (it lifts the restriction the
overlay stood for; this one restricts nothing), and asks for `DEACTIVATE`. Effects: [D from the
code and tests]

* The three classes are no longer asked about. Proposals of those classes record
  `not_assessed / class_not_enabled` again, which no rule reads.
* **The recorded calls are kept.** `goal_fit_calls`, `goal_fit_suspensions`,
  `goal_fit_outage_suspicions` and `goal_fit_report_views` are append-only tables the roll-back
  does not touch; a roll-back deletes nothing the measurement produced, and a class that was
  suspended stays suspended in the table (re-listing it later would still find it so, until an
  operator clears it with a reason).
* The policy version moves *down* (the highest active layer id), which re-checks every
  outstanding capability at its next heartbeat; waiting approvals are voided by the *publication*
  (the version moves up), not by the roll-back (ACCEPTANCE 5.124; `docs/D68_S8A_REPORT.md`).
* An engagement that ran in record mode keeps its decisions: nothing was decided differently.

## 5. Before publishing: waiting approvals

Publishing a global layer moves the policy version, and **every approval waiting at that moment is
void** (the dispatch refuses it with `policy_version_changed`). In the clean database of section 0
the count is 0 [E, step 2], so a publication there voids nothing. In the development database of
this session it was 6,642 (`pending_approvals.md`; test and harness leftovers), which is one more
reason the measurement does not run there. Nothing was processed in either.
