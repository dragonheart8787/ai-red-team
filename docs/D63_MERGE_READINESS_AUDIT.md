# D63 — merge-readiness audit, `origin/main..` D58–D62

Same shape as D47, D51 and D57: nothing assumed from a deliverable number; every claim below was
read from git, the CI history, the tree, or executed. What the audit found is fixed in the same
change and listed in §5.

## 1. What is being merged — from git

| | |
|---|---|
| `origin/main` (after `git fetch`) | `da8261a` "Merge D52-D57 stage…" — the expected commit, **verified** (CI run 138, green) |
| merge base with the branch | `d64b335` (the D57 audit commit, an ancestor of `da8261a`): the branch is strictly ahead of `main`, no divergence |
| branch tip before this audit | `0da35d3` (16 commits ahead of `main`) |
| diff against `main` before this audit | 90 files, +11 400 / −783 (39 added, 51 modified); five new migrations, `0016`–`0020` |

**The real scope is D58 through D62 — and the numbering is not one-to-one.** Read from the 16 commits:

| Group | Commits |
|---|---|
| D58 — the production-orchestrator investigation (ADR, no code) | `ad2c8d5` |
| D59 — two engagements never live on one Docker network (D58-14) | `885e772` |
| D60 — `propose_action` as stages that each commit (D58-5) | `5ba970d`; `e08b008` (5.54, 5.55 recorded) |
| D61 — just-in-time capability issuance for approved proposals (D58-8) | `8e20c78`; `0c53ac0` (same item: the approval re-derivation) |
| D58-7 — a sandbox that never started is `failed`, not `unknown_outcome` | `adc4632` (**its commit title says "D62"; it is D58-7**); `57f6e91` (follow-up: a `start()` the daemon refused); `e076a90` (relabels the report) |
| D62 — the scheduler (D58-1/2/3/4): design | `6ff0860`, `bb6b7a4`, `c433500`, `d128e06` |
| D62 — the scheduler: build | `c802007`; `0da35d3` (single-IP scopes skipped, not widened; migration `0020`) |
| a CI fix | `e8d6192` (a test that needed an image CI does not build) |

Not in this range, although a reader might expect it from the numbers: D42–D57 (already in `main`).
Of the eighteen D58 decision points, **eight are built here** (D58-1, -2, -3, -4, -5, -7, -8, -14); the
rest are not — see §3.3, which is the index a reader should use.

## 2. CI, every commit

CI runs on each **push**; commits pushed together share the run of the pushed head. All 16 are covered:

| Commit | Run | Result |
|---|---|---|
| `ad2c8d5` … `bb6b7a4`, `c433500` (11 commits, one run each) | 139–149 | green |
| `57f6e91`, `d128e06` (pushed together) | 150 | **red** — see below |
| `e8d6192` | 151 | green |
| `c802007` | 152 | green |
| `0da35d3` (the tip) | 153 | green |

**One red run in the range, fixed:** run 150. `57f6e91` added a real-Docker test that used `busybox`,
present on the development host and not built in CI, so it failed there with `ImageNotPresent`. **Fixed by
`e8d6192`** (the test uses the sandbox's own `cyberorch/nmap` image — also because only the network can then
refuse the start), green in run 151 and in every run after it. `57f6e91` itself was never run alone: it is
covered by the head it was pushed with, which was red, and by its green descendant.

**No red run is open.** The repository's history has 24 non-success runs (63–68, 71, 72, 74, 75, 77–81, 84,
88, 97, 98, 101, 102, 111, 112 and 150). The first 23 are the ones D57 audited; each of those commits is an
ancestor of `main` (checked again, by `git merge-base --is-ancestor`), each with a later green run. Run 150
is the 24th, above. No run on `main` is red (run 138, the merge of D52–D57, is green).

## 3. Documentation

### 3.1 ACCEPTANCE 5.52 – 5.59, row by row

Each row was read against the report it cites; 17 file / test / commit references in them were resolved
mechanically (all exist). Statuses: **closed** 5.52 (D59), 5.53 (D60), 5.56 (D61), 5.58 (D58-7), 5.59 (D62);
**open** 5.54 and 5.55 (Class C, two unexecuted live-run scripts), 5.57 (Class B, an approved `ad.collect`
carries no credential). Found and fixed:

| Finding | Fix |
|---|---|
| **The rows sat under the heading "Found at D55, acted on at D56"** — nothing told a reader that 5.52–5.59 belong to D58–D62 | a heading and a two-line status of the group before 5.52; the stage index now lists D58–D62 |
| **5.54 / 5.55 point at scripts that carried no pointer back** (asked for earlier; the report did not show it). `d40_three_role.py` had only the 5.50 comment; `d45_ad_collection_e2e.py` had none | a "BEFORE THE NEXT RUN (ACCEPTANCE 5.54 / 5.55)" comment at the head of each file; byte-compile and `ruff` clean |
| 5.56 said `tests/test_approved_dispatch.py` has **23** tests; it has **41** (the D58-8 closeout added the re-derivation tests) and six more mutation checks | corrected, both numbers stated |
| 5.56's residual said "nothing in production calls `dispatch_approved` yet" | the scheduler (5.59) is now its first caller; rewritten |
| 5.58's "mutation-verified four ways" omitted the follow-up's three | stated |
| **5.4** said "there is still no scheduler in MVP-0" | a scheduler exists (v0); what is still missing is a *renewing* caller — reworded |
| **README's database-role table listed three roles**; `db/roles.sql` creates ten | table rewritten from `roles.sql` |

### 3.2 The D61 report and 5.56: one statement of the refusal rule

The two documents did not say the same thing. The re-derivation section describes a refusal that **looks at
the result** (the target, the classification, whether OPA now denies); the limits paragraph said **"any policy
publication refuses"**. Both are true of different layers, and neither text said so. Verified in the code and
by `test_a_policy_published_after_the_decision_invalidates_the_approval`:

* **Layer 1, the re-derivation** compares *outcomes* with the approval's snapshot (any difference in target,
  action, authorization or classification; a policy that now denies; a new reason to ask a human; another
  proposal's approval; a proposal that asks for more).
* **Layer 2, the broker at the issue** compares a *version number*: any policy layer published since the
  decision refuses (`policy_version_changed`), including one that only widens.

The net rule is *any policy publication refuses*; layer 1 covers what a publication does not (registry
changes, a grown proposal). Both documents now carry the same two-layer table (D61 report §2, ACCEPTANCE
5.56). **What is not re-verified between the re-derivation and the issue** (one stage hand-off, measured
< 1 s, no transaction held while OPA runs): the target's normalization and classification, the authorization
resolution beyond the scope object still standing and allowing the action, and the OPA verdict itself (a policy
*publication* in the window is caught by the version check; a registry change is not). What *is* re-checked at
the issue: engagement active, kill switch, approval live / unexpired / unrevoked, scope object, policy version.
Accepted — the capability that results is short-lived and single-dispatch — and recorded.

### 3.3 `ADR_PRODUCTION_ORCHESTRATOR.md`

The document opened with "**proposed — investigation and design only; nothing here is decided**", followed by
five addenda (D59, D60, D61, D58-7, D62) that each describe one piece. A reader of the first line would conclude
nothing is built; a reader of the last addendum might conclude it is done. The status is now an index at the top:

| Built | Not built |
|---|---|
| D58-1 (D62), -2 (D62), -3 (D62), -4 (D62), -5 (D60), -7 (D58-7, option B), -8 (D61), -14 (D59) | **D58-6** (failure ladder) and -6b; **D58-9** (reconciler / recovery); **D58-12** (planning); **D58-13** (quotas); **D58-15** (`credential_id` selection); **D58-16** (unattended credentialed dispatch / active kill); **D58-17** (secret residency); D58-10 only in part; D58-11 not yet needed |

The body is still the text written at `ad2c8d5`; the index says so. Two sentences in the addenda were stale
and are corrected (D61's "nothing in production calls `dispatch_approved` until the scheduler exists").
**D58-10 is recorded as partial, honestly:** defects X1–X5, X11 and X12 were recorded as they were closed (5.52, 5.53, 5.58), and X3/X8 in part (5.56, 5.57);
X6 (residual), X7, X9, X10, X13–X16 are listed only in the ADR, not as ACCEPTANCE rows. That is a gap in the
record, not in the code, and it is listed in §6 rather than papered over.

## 4. End-to-end coverage

### 4.1 `dispatch_approved` has its first production caller

* **5.28** (no production code constructs an `Observation`): **unchanged**. The scheduler constructs none
  (`grep` of `control_plane/`, `agents/`, `tool_gateway/`, `scripts/`: the only matches are the metadata
  canonicalizer's own type and a harness). A note to that effect is on the row.
* **5.51** (nothing in production assembles the effective policy): **partly changed, updated.** The
  scheduler's execution step now calls `load_effective_policy` in production — but only to dispatch an
  *approved* proposal. The decision stage (`propose_action`) still takes the policy as an argument and no
  production code assembles one for it. The row now says exactly that.
* The same shape elsewhere, checked: `renew_capability` (5.4) and `reconcile_stale_dispatches` still have no
  production caller — the scheduler neither renews nor reconciles; both stay as recorded.

### 4.2 Each supported action through a tick

**Gap found.** The scheduler's four actions route to two dispatchers with three tool images
(`dispatch_scan` → nmap for `network.scan` and `network.recon`; `dispatch_code_scan` → Semgrep for `code.scan`,
Gitleaks for `code.secrets`). The D62 tests drove **only `network.scan`** through a tick; `network.recon` and
both `code.*` actions had unit-level and skip-level coverage but no tick that ran them. Routing was not
assumed. **Closed by `tests/test_scheduler_actions.py`** (4 tests, one per action): a human-approved proposal,
a tick given *no* sandbox (so each dispatch builds the image its tool needs), a **real container** of the right
tool (`tool_runs.tool` = `nmap` / `nmap` / `semgrep` / `gitleaks`, `succeeded`, exit 0), one evidence row, and
the audit order `approval.granted < scheduler.dispatched < capability.issued < tool_run.started <
tool_run.succeeded`. All four passed on the first run (the routing was correct); mutation: dropping
`code.secrets` from `SUPPORTED_ACTIONS` turns exactly its test red.

## 5. Found by this audit, and what was done

1. §3.1's seven documentation findings and §3.2's unified refusal rule.
2. §3.3's status index for the ADR.
3. §4.1's two updated records (5.51; a note on 5.28; 5.4).
4. §4.2's missing per-action tick tests (`tests/test_scheduler_actions.py`).
5. §2's one historical red run, already fixed.

No production code was changed by this audit. (Before it, in the same round: `ip` scopes were changed from
"widened to a block" to "skipped", migration `0020`; that is D62, `0da35d3`, and is in the range.)

## 6. Scale

| | at `da8261a` (last merge) | at this audit |
|---|---|---|
| tests collected / passed | 1 430 (**re-verified**: 1 430 collected on a checkout of `da8261a`) | **1 709** collected; **1 709 passed** (full serial run, 13 min 17 s) |
| OPA tests | 51 / 51 | **51 / 51** (`opa test`; no Rego or `policy_tests` file changed in the range; `opa fmt` clean) |
| migration head | `0015` | **`0020`** (`0016` stages, `0017` approval stages, `0018` approval snapshot, `0019` scheduler, `0020` narrows its vocabulary) |
| database roles created by `db/roles.sql` | 7 | **10** (+`scheduler_reader`, `scheduler_admin`, `scheduler_state_writer`) — the development database also holds a leftover `bh_bench_user` from a D42 benchmark, not created by `roles.sql` |
| registered actions | 8 | 8 (unchanged; the scheduler dispatches 4 of them) |
| `ruff check .` | clean | clean |

## 7. For whoever deploys this

* Apply migrations `0016`–`0020`. `scripts/init_db.sh` now also creates the three scheduler roles and writes
  `SCHEDULER_{READER,ADMIN,STATE_WRITER}_DATABASE_URL`; give the admin URL only to the operator's environment.
* Nothing starts the scheduler. `python scripts/run_scheduler.py` runs it; it dispatches only engagements
  enrolled with `scripts/manage_scheduler_enrollment.py`. It does not restart or reconnect by itself (exit
  codes in the script's docstring); a supervisor must not restart it blindly.
* An approved proposal in an engagement that is not enrolled still waits at `approved`
  (`scripts/approvals.py awaiting-dispatch`).
* Open at merge, all recorded: 5.21–5.24, 5.26, 5.28, 5.32, 5.34, 5.38, 5.40, 5.42–5.47, 5.49–5.51, 5.54, 5.55,
  5.57; the ADR's unbuilt decision points (§3.3); and one candidate named for after v0 — separating a single-IP
  authorization from the Docker network range (`tool_gateway`), without which an `ip` scope cannot run.
* Two live-run scripts (`d40_three_role.py`, `d45_ad_collection_e2e.py`) have not been executed since D59/D60;
  the first step of their next run is written at the top of each file.
