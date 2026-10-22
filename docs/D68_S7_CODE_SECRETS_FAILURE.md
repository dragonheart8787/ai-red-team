# D68 S7 -- why `code.secrets` failed 65% in the baseline: the wording of the goal, not the action

Raw records: `docs/D68_S7_BASELINE/goal_class_probe/` (`probe.jsonl` has all 80 calls; `probe.json` the table). Tool: `scripts/plan_fit_goal_class_probe.py`. Claims are tagged [R] read, [E] executed, [D] derived, [N] not established.
No threshold is proposed here.

## 1. The question

The fixed-model baseline (`docs/D68_S7_FIXED_MODEL_REPORT.md`) had `code.secrets` as the action class with the highest failure rate: **32 of 49 calls (65.3%)**, while its 7 ordinary (matched) secrets-scan items failed 0 of 7. The question: is that a property of the corpus's construction (noise), or does the validator really fail on secrets-scan work (risk)?

## 2. What the corpus data already said [E]

Read from the 480 stored records, joined to the corpus:

* The 49 `code.secrets` items are 7 matched (secrets-scan goals; **0 failed**), 6 mismatched and the 36 lures built from those 6.
* **All 6 mismatched `code.secrets` items have an Active-Directory goal** ("Collect the Active Directory relationships of ...", "Gather the AD users, groups and trusts of ...", "Enumerate the directory relationships of ..."). They are in the `code.secrets` class because the *proposal's action* is `code.secrets`; the words the model reads are about AD collection. All 6 failed, and 26 of their 36 lures.
* By the wording of the goal over all 480 items: **Active-Directory goals failed 52 of 79 (65.8%), whatever the action** (23 of 43 with another action, 29 of 36 with `code.secrets`); all other goals 37 of 397 (9.3%); `ad.collect` matched items failed 7 of 7. [D: my classification of goals by keyword]

So the `code.secrets` row is the AD-goal failure rate under another label. That is a reading of existing data; it left open whether a *secrets-scan* goal is safe.

## 3. The probe: goal wording and action separated [E]

80 calls with the baseline's validator, model (`sonnet`), prompt and `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1`, 20 items per cell, shuffled; hosts drawn from the corpus's own role and zone lists (including the sensitive-sounding ones); a stopped call recorded as `failed`, none dropped. Cost about $0.76.

| goal wording | task and proposal action | failed / N (upper 95%) | answers |
|---|---|---|---|
| secrets scan | `code.secrets` (matched) | **0 / 20** (<= 15.0%) | 20 plausible |
| secrets scan | `web.get`, `code.scan`, `network.scan` (mismatched) | **1 / 20** (<= 23.6%) | 13 plausible, 6 implausible |
| Active Directory | `code.secrets` (mismatched) | **17 / 20** (<= 94.8%) | 3 implausible |
| Active Directory | `ad.collect` (matched) | **15 / 20** (<= 88.8%) | 5 plausible |

* **The failure follows the goal's wording.** Secrets-scan goals: 1 failure in 40 calls whatever the action (`code.secrets`: 0 of 20). AD goals: 32 failures in 40, whatever the action (with `code.secrets` 17 of 20, with `ad.collect` 15 of 20). Of the 80 calls, 33 were stopped by the safety classifier (`stop_reason: refusal`), 32 of them AD goals.
* The 65% for `code.secrets` in the baseline is a **corpus-construction artifact**: the 6 mismatched base items for that action were all taken from the AD scenario. It says nothing about secrets scanning.

## 4. The judgement

* **Not a risk of Q1 for `code.secrets`.** The evidence is: 0 of 20 matched-style secrets-scan goals failed (and 0 of 7 in the baseline) -- 0 of 27 in all, and 1 of 40 secrets-scan-wording calls of any action. The upper bound on the failure rate of secrets-scan goals in this corpus's style is about 13% (1 of 40) -- a bound, not an estimate.
* **The classifier's trigger is the goal's wording (Active Directory collection / directory enumeration)**, which is the same thing that makes `ad.collect` fail on ordinary work (7 of 7 matched, 15 of 20 here). That class is already recorded as known-high (plan 7.3a).
* **Not established [N]:** that real `code.secrets` goals written by a Supervisor look like these three templates. Real goals mentioning credentials, keys or "secrets" in other words could behave differently; the probe covers three phrasings.
* **A different observation of the same run, not about failures:** a secrets-scan goal against a `code.scan` task was judged `plausible` in 7 of 7 and against `web.get` in 6 of 7 (answered), against `network.scan` `implausible` in 6 of 6. Adjacent actions on the same host read as plausible. This is the corpus label problem of ACCEPTANCE 5.121 seen from the other side (is a code scan a plausible way to serve a secrets-scan goal? arguably yes), and is not a defect found here.

## 5. What this means for S8b (stated, not decided)

When Q1 is enabled, the `code.secrets` failure rate on real goals is to be read against this: it should be near zero (0 of 27 matched-style, 1 of 40 by wording). If it is not, the cause to look for first is **goal wording that the classifier stops** (directory/AD language, encoded text, reconnaissance), not the action class; a high `code.secrets` rate would be a finding to report, not an expected value.
