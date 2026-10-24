# D68 DP-15 record mode: the measurement, pre-registered

Written **before** the script (`scripts/dp15_record_mode.py`) and before any traffic. Nothing here
has been run: no model was called, no layer was published, no `report` was read for these classes.
Claims are tagged [R] read, [E] executed, [D] derived, [N] not established.

## 1. What this is for

Three action classes -- `code.scan`, `code.secrets`, `network.scan` -- are to be put in *record
mode* by an operator: listed in `goal_fit_actions` (`layer_record_mode.json`), with
`goal_fit_enforce` **off**. In that mode Q1 is asked and its outcome recorded, and no decision
changes (`test_a_listed_class_with_goal_fit_enforce_off_is_asked_and_counted_and_decides_as_unlisted`).
The measurement produces, per class, the judgements the admission rule needs
(`control_plane/plan_fit/classes.py`): **at least 40 of the class's last 50 judgements, with a
Wilson 95% upper bound of the failure rate of at most 15%**. It recommends; it admits nothing.
Publishing any list, in record mode or in enforcing mode, is the owner's decision and is not part
of this plan.

## 2. Registered before the run

1. **A judgement** is a Q1 call that ended `answered`, `refusal` or `unclassified`. A `transport`
   failure (timeout, connection, 5xx, authentication or usage) is a call but not a judgement: it
   is recorded, shown, and counted neither as a failure nor as a success (migration 0029).
2. **N = 50 judgements per class**, no more, no fewer, made through the real `propose_action`
   path (`propose_action(..., plan_fit_validator=<the real validator>)`), by a traffic generator,
   after the class is listed. Proposals are issued class by class in an interleaved order, so that
   a bad hour falls on all three and not on one.
3. **Every proposal is new.** Each uses a target host that no earlier proposal in the run used,
   and a task of its own. No proposal is repeated, and **no call is retried**: a proposal whose
   call ended in `transport` is not asked again; a *new* proposal (a new host) takes its place,
   up to 60 proposals for a class. If a class still has fewer than 50 judgements after 60
   proposals, that is its result: its actual count, not a top-up. The run therefore issues at most
   3 x 60 = 180 proposals.
4. **The goal wording is fixed here, and nothing about it changes during the run.** One sentence
   per class, differing only in the host or repository:

   | class | goal | target of the proposal |
   |---|---|---|
   | `network.scan` | `Scan {host} for open ports and the services behind them` | an address `10.77.<a>.<b>`, a different one each time, inside one `/16` scope object |
   | `code.scan` | `Scan the source at {host} for insecure patterns` | a host name `<role><NN>.<zone>.example`, a different one each time, inside the zone's scope object |
   | `code.secrets` | `Scan the repository at {host} for committed secrets` | the same family of host names, none used for any other proposal of the run |

   Host names are built from the *plain* roles of the S7 corpus (`www`, `blog`, `docs`, `status`,
   `shop`, ..., never the sensitive ones such as `payroll-db` or `vault`), a two-digit number and one
   of the six zones, and are the same kind of target the S7 baseline used for these classes.
   These are the sentences of `tests/task_support.py` (`GOALS`), which every existing end-to-end
   test uses, and the S7 baseline's wording family. They are plain: no Active-Directory,
   reconnaissance or credential-collection wording, which S7 showed is what the service's safety
   classifier stops (`docs/D68_S7_CODE_SECRETS_FAILURE.md`). **This is a choice, and it shapes the
   result: the measured rate is the rate for these sentences, not for whatever goals a Supervisor
   will write.** The validator's prompt and the fields it is shown are untouched.
5. **One look.** The run ends when every class has 50 judgements, has been **censored** (rule 8),
   or the run was **aborted** (rule 9). Only then is `scripts/manage_goal_fit_classes.py report`
   run, **once**. It is not run before, not in the middle, and not again to "check". The script
   never runs it and never prints a failure count or rate while it runs. The record of looks
   (migration 0030) will show `looks = 1` for each class; any class that shows more is reported
   as looked at more than once, with the count, and the result is read with
   `docs/D68_DP15_ADMISSION_LOOKS.md` in mind.
6. **The admission rule is unchanged**: window `n >= 40` and Wilson upper bound `<= 15%`, read
   from that one report. `RECOMMEND ADMISSION` is advice.
7. **The configuration is the one DP-14 was measured on**: backend `claude_code`, model `sonnet`,
   `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1`, the CLI version recorded with the result. The
   Reviewer is the scripted honest one and the sandbox a recording fake: **no tool runs and no
   target is touched**; the only model call per proposal is the validator's. The run makes one engagement of its own (CUST-DP15) and
   writes one policy layer scoped to that engagement, allowing the three actions; it publishes no
   global layer, no baseline, and does not read or set either enforcement switch.
8. **Auto-suspension works as always** (more than 30% of the last 50 judgements, at least 30). A
   class suspended during the run is **censored at the judgements it had**: the script stops
   issuing for it, and its result is "censored at n = ...", not admitted, whatever the rest of the
   run shows.
9. **Abort.** If `transport` failures are more than half of the last 30 calls (of any class) the
   script stops issuing, lets the at most two calls in flight finish, prints that it aborted and
   what it had, and exits non-zero. **It does not retry and does not resume.** Whether and how to
   continue is the owner's decision, after reading what happened.
10. **Bounds.** At most 2 calls in flight; at most 180 proposals; a cost cap of **US$3.00**; a
    wall-clock cap of 60 minutes; the validator's own 30 s limit per call. Reaching a cap ends the
    run like an abort. No cap is raised during a run.
11. **Where it runs is recorded and results from different places are not pooled.** The S8b
    smoke attempts showed the same prompts failing in CI at a rate S7 did not see on a
    development machine, with the cause not established
    (`docs/D68_S8B_REPORT.md` sections 8-11); a number from one environment is a number for that
    environment. [N]: nothing here says which environment the measurement runs in.
12. **Starting state.** Before it sends anything the script refuses to start if no real validator is
    configured as in rule 7, or if one of the classes is already suspended; it makes its own
    engagement (which needs a baseline in force: it publishes none) and refuses, having sent
    nothing, if that engagement's *effective policy* does not list all three classes in
    `goal_fit_actions` or has `goal_fit_enforce` on. It prints (as counts only) what the tables
    hold for each class at the start, and the measurement reads the window, which after 50 new
    calls holds only new calls: older calls (the development database holds 130 recorded
    `network.scan` calls from earlier tests) do not enter it.

## 3. What the script prints, and when

* **While running:** a progress line of proposals issued and finished, nothing else. No outcome, no
  failure count, no rate.
* **At the end:** for each class, the proposals issued, the validator calls made, the judgements
  counted toward N, and whether the class was suspended (and at what `n`). Then the exit status:
  0 complete, 3 aborted or capped.
* **Dry run** (the default): the plan, the bounds, the cost estimate and checks of the plan itself
  (50 + 10 spare distinct targets per class, no target repeated, goal sentences as above). It
  needs no database and builds no validator.

## 4. Cost and time (estimates, [D])

* Per call: about **US$0.0088** (S7 fixed-model baseline: $4.23 for 480 calls) -- the earlier
  working figure was $0.008.
* Planned: 3 x 50 = **150 calls = about $1.32** (at $0.008: $1.20). Worst case, 180 calls: about
  **$1.58**. The cap is $3.00, about 2.3 times the worst case.
* Time: median 3.2 s and p95 5.7 s per call (S7 fixed-model). 150 calls at two at a time: about
  4 minutes; 180 at p95: about 9 minutes. The 60-minute cap is for a service that is slow, not for
  this estimate.

## 5. What would change this plan

Nothing, once a run has started. A change before the first run (a goal sentence, N, a cap) is made
in this file, dated, and the script follows it. A change after a run has seen results is a
different measurement and gets its own pre-registration.
