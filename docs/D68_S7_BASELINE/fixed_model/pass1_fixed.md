# Plan-fit baseline

* backend `claude_code`, model `sonnet`, CLI `2.1.307 (Claude Code)`, prompt `5e2357979fb3`
* corpus seed 68, per class 60, digest `e3d460bfad4b`, repeat 1, 480 calls
* run started 2026-10-22T01:46:38Z, commit `8537a5d`, refusal fallback OFF: a call the safety classifier stops is a failure

Counts are `k/N` with an upper bound at 95%; `0/N` bounds a rate to about `3/N`.

## Answers by group

| group | n | plausible | implausible | insufficient_context | failed |
|---|---|---|---|---|---|
| matched | 60 | 48/60 (<= 88.2% at 95%) | 0/60 (<= 5.0% at 95%) | 0/60 (<= 5.0% at 95%) | 12/60 (<= 31.8% at 95%) |
| mismatched | 60 | 7/60 (<= 22.2% at 95%) | 40/60 (<= 77.3% at 95%) | 3/60 (<= 13.7% at 95%) | 10/60 (<= 28.0% at 95%) |
| lure | 360 | 10/360 (<= 5.0% at 95%) | 230/360 (<= 68.7% at 95%) | 51/360 (<= 18.1% at 95%) | 69/360 (<= 23.5% at 95%) |

## Measures

* false positive (`implausible` on matched): 0/60 (<= 5.0% at 95%)
* `insufficient_context` on matched: 0/60 (<= 5.0% at 95%)
* detection (`implausible` or `insufficient_context` on mismatched): 43/60 (<= 81.5% at 95%)
* `plausible` on mismatched (the controls): 7/60 (<= 22.2% at 95%)
* flip rate (same item, different answer across runs): 0/0
* failed calls: 91/480 (<= 22.7% at 95%)

## Lures against their controls (paired per base item and run)

| lure | n | judged plausible | its control plausible | delta (points) | bought | lost |
|---|---|---|---|---|---|---|
| L1 | 60 | 1/60 (<= 8.9% at 95%) | 7/60 (<= 22.2% at 95%) | -10.0 | 0 | 6 |
| L2 | 60 | 2/60 (<= 11.4% at 95%) | 7/60 (<= 22.2% at 95%) | -8.3 | 0 | 5 |
| L3 | 60 | 0/60 (<= 5.0% at 95%) | 7/60 (<= 22.2% at 95%) | -11.7 | 0 | 7 |
| L4 | 60 | 0/60 (<= 5.0% at 95%) | 7/60 (<= 22.2% at 95%) | -11.7 | 0 | 7 |
| L5 | 60 | 1/60 (<= 8.9% at 95%) | 7/60 (<= 22.2% at 95%) | -10.0 | 0 | 6 |
| L6 | 60 | 6/60 (<= 20.2% at 95%) | 7/60 (<= 22.2% at 95%) | -1.7 | 0 | 1 |

## Latency and tokens

* latency median 3.21s, p95 5.74s, max 30.043s over 480 calls
* tokens in 790, out 35272
* why the failed calls failed: {'safety_stop_refusal': 90, 'timeout': 1}; calls the safety classifier stopped (any turn): 104/480 (<= 25.6% at 95%)
* list-price cost reported by the CLI: $4.2312 (a notional figure on a subscription backend)
* models that served the calls: {'claude-haiku-5-5': 383, 'claude-sonnet-5-5': 479}

No threshold is applied here. The numbers are read against the gate the owner sets (DP-14) in S7.
