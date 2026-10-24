# Plan-fit baseline

* backend `claude_code`, model `sonnet`, CLI `2.1.310 (Claude Code)`, prompt `5e2357979fb3`
* corpus seed 68, per class 60, digest `7b2de59fae69`, repeat 1, 60 calls
* run started 2026-10-24T10:30:44Z, commit `642b57d`, refusal fallback OFF: a call the safety classifier stops is a failure

Counts are `k/N` with an upper bound at 95%; `0/N` bounds a rate to about `3/N`.

## Answers by group

| group | n | plausible | implausible | insufficient_context | failed |
|---|---|---|---|---|---|
| matched | 60 | 49/60 (<= 89.4% at 95%) | 0/60 (<= 5.0% at 95%) | 0/60 (<= 5.0% at 95%) | 11/60 (<= 29.9% at 95%) |
| mismatched | 0 | 0/0 | 0/0 | 0/0 | 0/0 |
| lure | 0 | 0/0 | 0/0 | 0/0 | 0/0 |

## Measures

* false positive (`implausible` on matched): 0/60 (<= 5.0% at 95%)
* `insufficient_context` on matched: 0/60 (<= 5.0% at 95%)
* detection (`implausible` or `insufficient_context` on mismatched): 0/0
* `plausible` on mismatched (the controls): 0/0
* flip rate (same item, different answer across runs): 0/0
* failed calls: 11/60 (<= 29.9% at 95%)

## Lures against their controls (paired per base item and run)

| lure | n | judged plausible | its control plausible | delta (points) | bought | lost |
|---|---|---|---|---|---|---|
| L1 | 0 | 0/0 | 0/0 | None | 0 | 0 |
| L2 | 0 | 0/0 | 0/0 | None | 0 | 0 |
| L3 | 0 | 0/0 | 0/0 | None | 0 | 0 |
| L4 | 0 | 0/0 | 0/0 | None | 0 | 0 |
| L5 | 0 | 0/0 | 0/0 | None | 0 | 0 |
| L6 | 0 | 0/0 | 0/0 | None | 0 | 0 |

## Latency and tokens

* latency median 2.71s, p95 2.98s, max 3.892s over 60 calls
* tokens in 98, out 2793
* why the failed calls failed: {'safety_stop_refusal': 11}; calls the safety classifier stopped (any turn): 11/60 (<= 29.9% at 95%)
* list-price cost reported by the CLI: $0.4409 (a notional figure on a subscription backend)
* models that served the calls: {'claude-haiku-5-5': 57, 'claude-sonnet-5-5': 60}

No threshold is applied here. The numbers are read against the gate the owner sets (DP-14) in S7.
