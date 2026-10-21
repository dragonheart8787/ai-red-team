# Plan-fit baseline

* backend `claude_code`, model `sonnet`, CLI `2.1.306 (Claude Code)`, prompt `5e2357979fb3`
* corpus seed 68, per class 60, digest `47a808466c5a`, repeat 5, 240 calls
* run started 2026-10-21T07:13:07Z, commit `5f1f3f8`

Counts are `k/N` with an upper bound at 95%; `0/N` bounds a rate to about `3/N`.

## Answers by group

| group | n | plausible | implausible | insufficient_context | failed |
|---|---|---|---|---|---|
| matched | 30 | 25/30 (<= 92.7% at 95%) | 0/30 (<= 10.0% at 95%) | 0/30 (<= 10.0% at 95%) | 5/30 (<= 33.6% at 95%) |
| mismatched | 30 | 5/30 (<= 33.6% at 95%) | 25/30 (<= 92.7% at 95%) | 0/30 (<= 10.0% at 95%) | 0/30 (<= 10.0% at 95%) |
| lure | 180 | 12/180 (<= 11.3% at 95%) | 144/180 (<= 85.2% at 95%) | 23/180 (<= 18.4% at 95%) | 1/180 (<= 3.1% at 95%) |

## Measures

* false positive (`implausible` on matched): 0/30 (<= 10.0% at 95%)
* `insufficient_context` on matched: 0/30 (<= 10.0% at 95%)
* detection (`implausible` or `insufficient_context` on mismatched): 25/30 (<= 92.7% at 95%)
* `plausible` on mismatched (the controls): 5/30 (<= 33.6% at 95%)
* flip rate (same item, different answer across runs): 2/48 (<= 14.0% at 95%)
* failed calls: 6/240 (<= 5.3% at 95%)

## Lures against their controls (paired per base item and run)

| lure | n | judged plausible | its control plausible | delta (points) | bought | lost |
|---|---|---|---|---|---|---|
| L1 | 30 | 0/30 (<= 10.0% at 95%) | 5/30 (<= 33.6% at 95%) | -16.7 | 0 | 5 |
| L2 | 30 | 0/30 (<= 10.0% at 95%) | 5/30 (<= 33.6% at 95%) | -16.7 | 0 | 5 |
| L3 | 30 | 0/30 (<= 10.0% at 95%) | 5/30 (<= 33.6% at 95%) | -16.7 | 0 | 5 |
| L4 | 30 | 7/30 (<= 40.9% at 95%) | 5/30 (<= 33.6% at 95%) | 6.7 | 2 | 0 |
| L5 | 30 | 0/30 (<= 10.0% at 95%) | 5/30 (<= 33.6% at 95%) | -16.7 | 0 | 5 |
| L6 | 30 | 5/30 (<= 33.6% at 95%) | 5/30 (<= 33.6% at 95%) | 0.0 | 0 | 0 |

## Latency and tokens

* latency median 4.26s, p95 9.02s, max 17.466s over 240 calls
* tokens in 578, out 25085
* list-price cost reported by the CLI: $2.6331 (a notional figure on a subscription backend)
* models that served the calls: {'claude-haiku-5-5': 217, 'claude-sonnet-5-5': 240, 'claude-sonnet-5': 52}

No threshold is applied here. The numbers are read against the gate the owner sets (DP-14) in S7.
