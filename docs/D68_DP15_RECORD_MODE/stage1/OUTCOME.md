# DP-15 stage 1: outcome

Facts only. Nothing here is an analysis of the result beyond what the one analysis printed, and
nothing proposes a change of input. The files of the run are described in `README.md`.

## Commits

| | commit |
|---|---|
| Registering commit (plan, wording file, analysis script as registered) | `0747cbe30efb49c5eaf64ccfe8c46800269a217a` |
| HEAD the run was made from (`plan_commit` and `head` in the record's header) | `9df70aad26a5a2671a3670f4a28a30fe1a98c2e6` |
| Results commit (the record and the files of the run) | `ccc6b05` |

The plan (`1e929fe5...`), the wording file (`932cd713...`) and the analysis script (`dceb55eb...`) have
the same sha256 in `0747cbe`, in the run's HEAD and in the commit that adds this file; the full
values are in `README.md`.

## C1, as the analysis printed it

The run completed (190 of 190 calls, no stop, no suspension). The analysis ran once, at the end of
the run (look 1 in `record.jsonl.looks.jsonl`). Its output, quoted from `analysis_output.txt` without
change:

```
look 1 of this record
DP-15 stage 1: the one analysis (C1)
record sha256 94489f86385a5cf81ceefbfe31bb1e3c396ca54b13de82ce536e04df255886f6
wording file sha256 932cd7135258caac11df7ba4bccae12a514ea42127e4c5c41e6320d199a456ca; prompt digest 5e2357979fb3; backend claude_code; model alias sonnet; CLI 2.1.311 (Claude Code); refusal fallback CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1; database cyberorch_dp15b (migration 0030); started 2026-10-27T01:41:00Z
plan commit 9df70aad26a5a2671a3670f4a28a30fe1a98c2e6; seed 20261025

C1: NOT MET -- 8 of 60 decided wordings marked; Wilson upper 24.2%, exact upper 24.6%, threshold 15% for both (at 60 decided wordings at most 3 may be marked)

row                        wordings  decided  marked   point  Wilson 95%        exact 95%         
real (model Supervisor)          28       28       3   10.7%  3.7% - 27.2%      2.3% - 28.2%      
hand-written                     32       32       5   15.6%  6.9% - 31.8%      5.3% - 32.8%      
network.scan pooled (C1)         60       60       8   13.3%  6.9% - 24.2%      5.9% - 24.6%      
difference between the two rows: not large (the intervals overlap)
  How to read it (plan 5.3): a label on the report and nothing else. It is not used to resample, drop or reweight a row, to replace the pooled row, to change a threshold or a wording, or to run the stage again. C1 stands on the pooled row.

reported, not thresholds:
  real: marked calls 12 of 84 non-transport calls; transport losses 0
  hand-written: marked calls 17 of 96 non-transport calls; transport losses 0
  pooled: marked calls 29 of 180 non-transport calls; transport losses 0
  call-level marked share, pooled, with a 95% bootstrap interval over wordings: 8.3% - 24.4%
  calls by outcome: failed:refusal 29, plausible 151
  split wordings (their calls disagree): 9; undecided wordings: 0
  Leg B (through propose_action) agrees with Leg A's first repeat: 10 of 10 compared pairs (10 Leg B calls, 0 not compared); no threshold

the run completed; Leg A calls recorded 180
usage: 190 CLI runs; list-price-equivalent cost US$1.48 (not an invoice); tokens in 410, out 9686, cache read 243745, cache creation 329298; models named in the envelopes: claude-haiku-5-5, claude-sonnet-5-5
This verdict says only whether C1 as registered was met. It does not say whether goal_fit_enforce may be turned on.
exit 0
```

## Decision (made by the owner, 2026-10-27)

* **C1 is not met.**
* **Stage 2 and C3 are not carried out.**
* **`goal_fit_enforce` stays off.**
* **Stage 1 is not re-run and not resumed.**
* **Any further measurement is a new pre-registration with new data, and it attaches this result.**

## The environment of the run (recorded at run time)

| | |
|---|---|
| machine | the development machine (a cloud container) |
| date and time | 2026-10-27, 01:40:59 to 01:46:38 UTC; the record's footer gives 337.4 seconds |
| backend / alias / refusal fallback | `claude_code` / `sonnet` / `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1` |
| CLI version | `2.1.311 (Claude Code)` |
| validator prompt digest | `5e2357979fb3` (the digest DP-14 and S7 measured) |
| models named in the CLI's result envelopes | `claude-sonnet-5-5` and `claude-haiku-5-5` (every run names both; the record does not say which of them produced the validator's answer) |
| database | `cyberorch_dp15b`, migration 0030 |
| usage | 190 CLI runs; list-price-equivalent cost US$1.4754 (not an invoice; the plan's estimate was US$1.67, its cap US$2.50); tokens: input 410, output 9686, cache read 243745, cache creation 329298 |

Before the run, a smoke test of the same code path ran 4 real CLI runs in the throwaway database
`cyberorch_smoke` (3 Leg A, 1 Leg B, four temporary wordings that are not in the registered set;
list-price-equivalent cost US$0.0338; its record is not kept in the repository). It printed no
outcome of any call.

## Databases

* The record-mode layer (`layer_record_mode.json`) was published, as a global `emergency_overlay`
  and still active, in three databases: `cyberorch_dp15` (DP-15 run 1, 2026-10-25), `cyberorch_dp15b`
  (this run) and `cyberorch_smoke` (the smoke test). Its baseline (`baseline_live_run_default.json`)
  was published in the same three.
* In the development database `cyberorch` no global layer that lists a class is active; it holds 77
  rows of such overlays, all inactive, made and retired by the test suite.
* After this run, in `cyberorch_dp15b`: 10 rows in `goal_fit_calls` (Leg B's), none in
  `goal_fit_suspensions` or `goal_fit_outage_suspicions`, no pending approval.
