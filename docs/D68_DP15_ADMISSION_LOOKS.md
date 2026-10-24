# D68 DP-15: what repeated looks do to the admission recommendation

The admission rule (`control_plane/plan_fit/classes.py`) recommends a class when its **last 50
calls** (at least 40 of them) have a Wilson 95% upper bound on the failure rate of at most 15%.
The window rolls with every call, and `scripts/manage_goal_fit_classes.py report` can be run at any
time. That is not a pre-fixed sample: the number of looks is not set in advance, and the more often
the report is read, the more chances a class has to be seen in a good stretch. This note measures
how much. [E]

## Method

For a class whose calls fail independently with a true rate `p`, simulate the calls one at a time
(up to 2,000). After every call, once there are at least 40 in the window, apply the rule exactly
as the code does (`wilson_upper`, `ADMIT_MIN`, `ADMIT_UPPER`, `ADMIT_WINDOW`). Record the first
call at which the class would be recommended. 4,000 trials per row, seed 20261024. "One look" is a
single reading, at call 50. "Any look" is a person who reads the report after every call.

Failures allowed by the rule: with 40 calls in the window, at most 1; with 45 or 50, at most 2.

## Result

Share of trials in which the class is recommended at least once:

| true failure rate | one look at call 50 | any look in the first 100 calls | 200 | 500 | 2,000 |
|---|---|---|---|---|---|
| 10% | 11.3% | 41.9% | 72.5% | 96.9% | 100.0% |
| 15% | 1.4% | 9.8% | 20.4% | 46.3% | 93.0% |
| 20% | 0.15% | 1.2% | 2.9% | 8.3% | 29.2% |
| 25% | 0.0% | 0.1% | 0.3% | 0.7% | 3.1% |
| 30% | 0.0% | 0.0% | 0.0% | 0.05% | 0.18% |

## How to read it

* The 15% bound is not a 95% guarantee once the report is read repeatedly: a class that truly fails
  one call in five is recommended 29% of the time by someone who keeps looking for 2,000 calls,
  against 0.15% for one reading.
* Even one honest reading is strict: a class that truly fails 10% passes only 11% of the time at
  call 50. The rule asks for a good deal of evidence; the weakness is in the repetition, not in a
  single look.
* What bounds the damage is not the statistic. Admission is a person publishing a layer after
  reading the report (nothing admits a class by itself), and once the class is live the exit rule
  takes it out when more than 30% of its last 50 calls fail. That backstop is at 30%, not 15%: a
  class whose true rate is between the two stays in.

## Reproduction

```python
import random, sys
from control_plane.plan_fit.classes import wilson_upper, ADMIT_MIN, ADMIT_UPPER, ADMIT_WINDOW

ok = {n: max(k for k in range(n + 1) if wilson_upper(k, n) <= ADMIT_UPPER)
      for n in range(ADMIT_MIN, ADMIT_WINDOW + 1) if wilson_upper(0, n) <= ADMIT_UPPER}
rng = random.Random(20261024)
TRIALS = 4000
for p in (0.10, 0.15, 0.20, 0.25, 0.30):
    one = 0
    hit = {100: 0, 200: 0, 500: 0, 2000: 0}
    for _ in range(TRIALS):
        buf, failed, first = [], 0, None
        for i in range(1, 2001):
            f = 1 if rng.random() < p else 0
            buf.append(f)
            failed += f
            if len(buf) > ADMIT_WINDOW:
                failed -= buf[len(buf) - 1 - ADMIT_WINDOW]
            n = min(len(buf), ADMIT_WINDOW)
            good = n >= ADMIT_MIN and failed <= ok[n]
            if i == 50 and good:
                one += 1
            if good and first is None:
                first = i
        if first is not None:
            for N in hit:
                if first <= N:
                    hit[N] += 1
    print(p, one / TRIALS, {N: v / TRIALS for N, v in hit.items()})
```

Run from the repository root with `PYTHONPATH=.` (the numbers above come from this logic).
