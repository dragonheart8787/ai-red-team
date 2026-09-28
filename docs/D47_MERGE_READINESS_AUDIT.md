# D47 — D42-D46 merge-readiness audit

D45 found two deliverables (D42, D43) that had shipped with green suites and
had never actually run through their real production entry point. Before
merging this stage into `main`, this audit asks the question from a
different angle than D45/D46 already answered: is there a **second** class
of "each layer's tests are green, the whole thing was never actually strung
together" risk still hiding in this stage's code — not the routing question
D46 already closed, but any other form of a test quietly calling a lower
layer instead of the real entry point.

Following the precedent this project already set for a pre-merge audit
(`ACCEPTANCE_MVP_KERNEL.md`'s D18/D23 acceptance reviews; the D25-D41 stage's
own pre-merge audit at commit `64e4583`) rather than assuming this audit's
own conclusions without checking: nothing is taken on faith, including this
stage's own two reports (D45, D46) and the git/CI record itself.

**Headline: one real, previously unreported gap found — not a routing bug,
a test-layering one. Documentation cross-references were stale in four
places (D42/D43/D44's ADRs, plus one missing acceptance-doc pointer); all
four fixed in this audit as a documentation-only change, matching this
project's own precedent for how a pre-merge audit handles staleness. Git and
CI state confirmed, not assumed: the branch's actual range is exactly
D42-D46 (12 commits) — no earlier stranded work this time, unlike the
D31-D41 stage's own discovery that its true range was D25-D41.**

---

## 1. E2E coverage beyond routing: is anything else skipping the real entry point?

D46 closed the specific question of whether `propose_action` *routes* every
action correctly. This section asks a broader one: for D42 (BloodHound), D43
(Semgrep) and D44 (Credential Vault), is `propose_action` — the real,
single production entry point — ever actually exercised by any committed,
automated test at all, for anything beyond the pure routing decision D46's
own test isolates?

**Checked directly, not inferred:** every test file this stage produced,
grepped for `propose_action`:

| File | Deliverable | Calls `propose_action`? |
|---|---|---|
| `tests/test_ad_domain_scope.py` | D42-1 | No |
| `tests/test_graph_queries_structure.py` | D42-2/D42-6 | No |
| `tests/test_dispatch_collection.py` | D42-6/D44 | No |
| `tests/test_dispatch_code_scan.py` | D43 | No |
| `tests/test_dispatch_code_scan_credential.py` | D43/D44 | No |
| `tests/test_vault.py` | D44 | No |
| `tests/test_dispatch_routing.py` | D46 | Calls `_dispatch_for_action` directly — one layer *below* `propose_action`, by design (isolating the routing decision from canonicalization/OPA/capability issuance) |

**Zero committed, CI-run tests call the real `propose_action` for `ad.collect`
or `code.scan`, at any point in this stage's history.** The only time either
action was ever driven through the real entry point is D45's own
`scripts/live_run/d45_ad_collection_e2e.py` — a manual, real-infrastructure
live-run script, not part of the pytest suite, not run by CI, and not
repeatable without a hand-provisioned Samba AD DC.

This is not a false claim anywhere — every test file above is honestly
scoped in its own docstring (`test_dispatch_collection.py`: *"No Docker, no
real bloodhound-python... what is under test here is the control plane's
accounting"*), the same honest self-scoping D45's own report credited
`test_web_render_e2e.py` for. **The gap is what never got added afterward.**
`web.render` (D36) has both an adapter-level test *and* a permanent,
CI-committed, stub-sandbox `propose_action` test (`test_web_render_e2e.py`,
D37) *and* a real-container companion (`tests/scenarios/
test_scenario_web_render.py`) — three layers, each with a committed
regression test. `ad.collect`/`code.scan` have the adapter-level tests and,
now, D45's one-time real-infrastructure proof — but no middle layer: a
cheap, StubSandbox-based, `propose_action`-driven test that would catch a
*future* regression in the `propose_action` → `dispatch_collection`/
`dispatch_code_scan` integration (a broken `credential_id` thread-through, a
budget object shaped wrong, `execution_constraints` losing a field again)
without needing Samba, a real container, or a live run to notice.

**This is a real, actionable coverage gap, not a hypothetical one — reported
here rather than fixed unprompted**, per this deliverable's own framing as
an audit that reports before deciding next steps. The concrete shape of the
fix, if wanted: a `tests/test_ad_collection_e2e.py`/`tests/
test_code_scan_e2e.py` pair mirroring `test_web_render_e2e.py` exactly — a
real `propose_action` call, a `StubSandbox` (or the existing fixture-style
stand-in `test_dispatch_collection.py`'s own `StubSandbox` already provides),
real engagement/scope/credential setup, asserting a real `tool_runs` row and
a real `security_graph_*`/redacted-findings write resulted. Estimated as a
small, low-risk addition (the pieces — `StubSandbox`, `store_credential`,
`register_scope_object` — all already exist and are already exercised
individually); not built here pending your decision on whether to fold it
into this merge or take it as a follow-on.

Nothing else in D42/D43/D44 was found to bypass its own real entry point
beyond this. `vault.mount_for_run`/`vault.material_for` are called from
exactly two production sites each (`dispatch_collection`,
`dispatch_code_scan`/`git_fetch.py` respectively — confirmed by grep, no
other caller anywhere), consistent with the documented design; nothing
reaches them through a side door.

---

## 2. Documentation cross-reference audit

### 2.1 `ACCEPTANCE_MVP1_AGENTS.md` 5.20-5.25 against the D45/D46 reports

Checked line by line: 5.24 (sharpened) and 5.25 (new), added during D45's
own work, match `D45_AD_COLLECTION_E2E_REPORT.md`'s §6/§5 claims exactly —
same mechanism, same "not fixed here, deliberately" framing, same file
references. **One gap found**: the "Found at D45" section had no pointer to
D46's own confirmation that the routing bug was re-examined across every
action and rebuilt as a structural guarantee — D46's commit never touched
`ACCEPTANCE_MVP1_AGENTS.md` at all. **Fixed in this audit**: a "Status, as of
D46" paragraph added in the same place D40→D41's own precedent puts one.

### 2.2 D42/D43/D44 ADRs against the D45/D46 findings

**All three were stale, in the exact way this project's own precedent
(64e4583, for the D25-D41 stage) treats as worth fixing before a merge, not
after:**

* `docs/ADR_BLOODHOUND_NEO4J.md` — §4's dispatch design was implemented and
  then found broken at the routing layer by D45, and its own real-collection
  premise was found blocked one layer earlier than expected (the DNS gap,
  5.25). Neither was referenced anywhere in the document.
* `docs/ADR_SEMGREP.md` — §3.2/D43-5's git-fetch design depends on
  `dispatch_code_scan` actually running, which D45 found `propose_action`
  never made happen. Not referenced.
* `docs/ADR_CREDENTIAL_VAULT.md` — §2.2's exposure-window claim ("the sandbox
  kills the container... or, if D44-7 is adopted, as soon as the credential
  is revoked, whichever is sooner") is exactly the claim D45 found needs a
  sharper mechanism (a mid-flight revoke is invisible to the database, not
  merely slow). Not referenced.

**Fixed in this audit**: each ADR gained a "Status update (D45/D46)"
paragraph at the top, in the same style `ADR_BLOODHOUND_NEO4J.md`'s own
pre-existing D42-2 status update already used — a pointer to what changed
and where the full account lives, not a rewrite of the original
investigation text (matching 64e4583's own stated practice: "a pointer note
added alongside a stale claim, not a rewrite of what was actually found").

No other cross-document staleness found. `docs/D42_1_D42_6_DESIGN.md` and
`docs/D42_2_CTE_BENCHMARK.md` make no claims D45/D46 touch (collection
methods, benchmark numbers) and needed no changes.

---

## 3. Git and CI state — checked, not assumed

### 3.1 Where `main` actually stops

```
$ git fetch origin && git rev-parse origin/main
b82dc57998da628efd549a6fe9291cb0c9cd8546
```

Confirmed directly: `origin/main` is `b82dc57` — the D25-D41 merge commit —
exactly where the previous merge left it, not assumed from the deliverable
numbering.

### 3.2 The branch's actual range

```
$ git log --oneline origin/main..HEAD
```

Twelve commits, and — checked explicitly this time, per the brief's own
instruction not to repeat the D31-vs-D25 assumption — **the range is
genuinely D42 through D46, with nothing stranded from an earlier,
never-merged stage.** `origin/main` already carries everything through D41;
this branch's oldest commit (`984fff5`) is D42's own first commit. No repeat
of the D25 surprise.

### 3.3 Full commit list and CI result, every one checked individually

| Commit | Message | CI conclusion |
|---|---|---|
| `984fff5` | docs: D42 BloodHound + Neo4j phase-1 investigation ADR | success |
| `e6dadb7` | docs: D42-2 recursive-CTE benchmark for BloodHound path queries | **failure** (Lint) |
| `cdcb071` | docs: D42-1/D42-6 implementation design | **failure** (Lint) |
| `91ae7a6` | feat: D42-1/D42-6 implementation — ad_domain scope + Security Graph | success |
| `e02472a` | docs: D43 Semgrep phase-1 investigation ADR | success |
| `8c6eb16` | feat: D43 Semgrep — code.scan adapter, dispatch, redaction (implementation) | **failure** (test suite — CI had no `cyberorch/semgrep:local` image yet) |
| `8168084` | ci: build the semgrep image before the test suite (D43) | **failure** (test suite — image now built, but `semgrep.tool_version()` probed the CI host and got a different version string than the pinned constant expected) |
| `ab2849a` | fix: semgrep.tool_version() returns a pinned constant, not a host probe | success |
| `a4367ab` | docs: D44 Credential Vault phase-1 investigation ADR | success |
| `48eb063` | feat: D44 Credential Vault — storage, dual delivery modes, wired into D42/D43 | success |
| `9fbea2b` | D45: real AD Collection end-to-end verification, four bugs found and fixed | success |
| `27684d2` | D46: audit propose_action's dispatch routing across every action, close the class | success |

**Four historical CI failures, all in the D42/D43 portion, all diagnosed
and fixed by the very next commit in the same range** — the identical
pattern this project's own merge history already treats as normal and
expected: `b82dc57`'s own commit message states the standing practice
explicitly — *"several red runs... are kept as the audit trail of what was
tried and fixed, per this project's standing practice of merging with
history rather than squashing"* — and its own D25-D41 range carried a
comparable or worse streak (D36's own five-commit failure chain before that
stage's browser adapter went green). **None of the four is an unresolved
red**: every one was root-caused (a lint issue in scaffolding fixed by the
next commit; a missing CI image-build step, then a host-probe bug, both
fixed by the two commits immediately following) and the fix is part of this
same merge, not deferred past it. Current `HEAD` (`27684d2`) is green.

### 3.4 Working tree and remote state

```
$ git fetch origin && git status --short
(clean, before this audit's own documentation edits;
 clean again after they are committed)
```

No divergence from the remote, no uncommitted work left behind by any prior
deliverable in this range.

---

## 4. Scale, D41-close to this merge

| Metric | D41-close (`b82dc57`'s own figure) | This merge | Delta |
|---|---|---|---|
| Tests passed locally | 792 | 924 | **+132** |
| OPA tests | 41/41 | 44/44 | **+3** |
| Docker-gated tests in CI | 49 | see note | — |

**Note on the docker-gated figure**: the historical number was derived by
running the suite with no Docker daemon reachable and reading the
"passed/errors" split off pytest's own summary — a real, repeatable
measurement, but not one this audit re-ran (a first attempt to reproduce it
by pointing `DOCKER_HOST` at a nonexistent socket destabilized this session's
own PostgreSQL service through an apparently unrelated resource-pressure
interaction, immediately after a ten-minute container-heavy suite run — not
worth risking a second time for one comparison figure). In its place: a
direct, reproducible count of test **files** that construct a real
`DockerSandbox` — either inline or through a fixture whose own setup does
(`tests/scenarios/conftest.py`'s `sandbox`/`scan_target`) — currently stands
at **9 files, 120 tests**. This is not guaranteed to be the identical
counting method the "49" figure used (the project's own commit messages have
quoted 41, 43 and 49 at different points without a stated formula each
time), so it is given as a distinct, transparently-derived number rather
than presented as a strict continuation of the same series.

`opa fmt --fail --list` on `control_plane/policy/rego` and `policy_tests`:
clean, no reformatting needed.

---

## 5. Conclusion

One real coverage gap found (§1: no committed `propose_action`-level test
for `ad.collect`/`code.scan`, mirroring what `web.render` already has) —
reported, not fixed, pending your decision on scope. Four documentation
staleness issues found and fixed directly (§2), matching this project's own
established practice for handling exactly this class of finding during a
pre-merge audit. Git and CI state confirmed rather than assumed (§3): the
range is genuinely D42-D46, `main` is where it was left, and every historical
CI failure was resolved within the same range before this point. Scale
figures given in §4, with one honestly caveated on measurement methodology
rather than presented as more precise than it is.
