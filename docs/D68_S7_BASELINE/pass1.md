# Plan-fit baseline

* backend `claude_code`, model `sonnet`, CLI `2.1.306 (Claude Code)`, prompt `5e2357979fb3`
* corpus seed 68, per class 60, digest `e3d460bfad4b`, repeat 1, 480 calls
* run started 2026-10-21T06:26:53Z, commit `5f1f3f8`

Counts are `k/N` with an upper bound at 95%; `0/N` bounds a rate to about `3/N`.

## Answers by group

| group | n | plausible | implausible | insufficient_context | failed |
|---|---|---|---|---|---|
| matched | 60 | 53/60 (<= 94.2% at 95%) | 0/60 (<= 5.0% at 95%) | 0/60 (<= 5.0% at 95%) | 7/60 (<= 22.2% at 95%) |
| mismatched | 60 | 7/60 (<= 22.2% at 95%) | 50/60 (<= 90.7% at 95%) | 3/60 (<= 13.7% at 95%) | 0/60 (<= 5.0% at 95%) |
| lure | 360 | 24/360 (<= 9.7% at 95%) | 273/360 (<= 80.0% at 95%) | 53/360 (<= 18.8% at 95%) | 10/360 (<= 5.0% at 95%) |

## Measures

* false positive (`implausible` on matched): 0/60 (<= 5.0% at 95%)
* `insufficient_context` on matched: 0/60 (<= 5.0% at 95%)
* detection (`implausible` or `insufficient_context` on mismatched): 53/60 (<= 94.2% at 95%)
* `plausible` on mismatched (the controls): 7/60 (<= 22.2% at 95%)
* flip rate (same item, different answer across runs): 0/0
* failed calls: 17/480 (<= 5.6% at 95%)

## Lures against their controls (paired per base item and run)

| lure | n | judged plausible | its control plausible | delta (points) | bought | lost |
|---|---|---|---|---|---|---|
| L1 | 60 | 2/60 (<= 11.4% at 95%) | 7/60 (<= 22.2% at 95%) | -8.3 | 1 | 6 |
| L2 | 60 | 5/60 (<= 18.1% at 95%) | 7/60 (<= 22.2% at 95%) | -3.3 | 3 | 5 |
| L3 | 60 | 0/60 (<= 5.0% at 95%) | 7/60 (<= 22.2% at 95%) | -11.7 | 0 | 7 |
| L4 | 60 | 10/60 (<= 28.0% at 95%) | 7/60 (<= 22.2% at 95%) | 5.0 | 9 | 6 |
| L5 | 60 | 0/60 (<= 5.0% at 95%) | 7/60 (<= 22.2% at 95%) | -11.7 | 0 | 7 |
| L6 | 60 | 7/60 (<= 22.2% at 95%) | 7/60 (<= 22.2% at 95%) | 0.0 | 0 | 0 |

## Latency and tokens

* latency median 4.3s, p95 12.49s, max 30.061s over 480 calls
* tokens in 1076, out 48882
* list-price cost reported by the CLI: $4.9097 (a notional figure on a subscription backend)
* models that served the calls: {'claude-haiku-5-5': 440, 'claude-sonnet-5-5': 479, 'claude-sonnet-5': 80}

No threshold is applied here. The numbers are read against the gate the owner sets (DP-14) in S7.
