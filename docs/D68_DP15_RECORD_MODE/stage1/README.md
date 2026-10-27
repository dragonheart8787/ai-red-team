# DP-15 stage 1: files of the run

This directory holds the registered wording file, the files of the one run of stage 1 and its one
analysis. It interprets nothing: what C1 says is in `analysis_output.txt`, and what it means for
`goal_fit_enforce` is the owner's decision (`../ENABLE_DECISION_PLAN.md`, sections 0 and 5.1).

## What was registered, and by which commit

* **Registering commit: `0747cbe30efb49c5eaf64ccfe8c46800269a217a`** ("D68 DP-15 stage 1
  pre-registered"). Stage 1 is registered by the plan, the wording file and the analysis script as
  they are in that commit.
* The three registered files, byte for byte (sha256), the same at the registering commit, at the
  commit the run was made from, and now:

  | file | sha256 |
  |---|---|
  | `docs/D68_DP15_RECORD_MODE/ENABLE_DECISION_PLAN.md` | `1e929fe51d3dbb4beaa976a128c5457da001d37653e1e990bc2056cf0af5e7ae` |
  | `docs/D68_DP15_RECORD_MODE/stage1/network.scan.json` | `932cd7135258caac11df7ba4bccae12a514ea42127e4c5c41e6320d199a456ca` |
  | `scripts/dp15_stage1_analysis.py` | `dceb55eb67339c94a80d6a42aafe6ec2a3412acce2069ed44b69ddd801dcf8f1` |

* **`plan_commit` in the record's header is the HEAD at the time of the run**, not the registering
  commit: `9df70aad26a5a2671a3670f4a28a30fe1a98c2e6`, a descendant of `0747cbe`. The only changes
  between the two are the pre-registration guard of `--execute` and its tests and mutations
  (`scripts/dp15_stage1_run.py`, `scripts/mutations_d68.py`, `tests/test_dp15_stage1_run.py`). The
  guard refused to start unless the working tree was clean, HEAD contained `0747cbe` and the three
  files above had the hashes above; the header records `head`, `registered_sha256`,
  `current_sha256` (equal) and `code_sha256` (the two run scripts, recorded, not compared).

## The run

* 2026-10-27, 01:40:59 to 01:46:38 UTC (5.6 minutes), database `cyberorch_dp15b`, migration 0030,
  empty before the run (every table, `goal_fit_calls` and `goal_fit_suspensions` included). Published
  into it before the run, unmodified: `baseline_live_run_default.json` (sha256 `4aa010cb95911e2d...`)
  as `baseline_global` and `layer_record_mode.json` (sha256 `8f1c7d58a39f4c79...`) as
  `emergency_overlay`. `goal_fit_enforce` and `task_relation_enforce` were off throughout.
* `python scripts/dp15_enable_stage1.py --execute --yes`, 190 calls: Leg A 180 (direct), Leg B 10
  (through `propose_action`). Nothing stopped it early.
* After the run, in `cyberorch_dp15b`: 10 rows in `goal_fit_calls` (Leg B's; Leg A writes none), 0
  rows in `goal_fit_suspensions` and in `goal_fit_outage_suspicions`, 0 pending approvals.
* One thing in the run's printed summary is mislabelled: the line "validator calls recorded in the
  tables: 190" prints the number of finished calls, not the number of table rows (10). The record
  and the analysis are not affected; the summary line is part of `run_log.txt` as printed.

## Files

| file | what it is |
|---|---|
| `network.scan.json` | the registered wording file (60 wordings: 28 real, 32 hand-written) |
| `OUTCOME.md` | the outcome as facts: commits, the analysis output quoted unchanged, the owner's decision, the environment of the run, the databases (added after the run) |
| `dry_run_output.txt` | the dry run at the registering commit |
| `dry_run_output_before_run.txt` | the dry run immediately before the run, against `cyberorch_dp15b` with the layers published |
| `run_log.txt` | everything the run printed: progress counts, the summary, the analysis |
| `record.jsonl` | the item-level record: header, one line per call, footer (sha256 `94489f86385a5cf81ceefbfe31bb1e3c396ca54b13de82ce536e04df255886f6`) |
| `run_header.json` | the first line of `record.jsonl`, indented |
| `analysis_output.txt` | the analysis as printed at the end of the run: the one look |
| `record.jsonl.looks.jsonl` | the ledger of looks: one line, look 1, with the record's sha256 |

## Looking again

The analysis was run once, at the end of the run. A second look at the same record needs a reason
written down (`python scripts/dp15_stage1_analysis.py --record docs/D68_DP15_RECORD_MODE/stage1/record.jsonl
--reason "..."`) and both looks stay in the ledger. The run itself is never repeated or resumed: a
different measurement is a new registration on new data (plan, section 9).
