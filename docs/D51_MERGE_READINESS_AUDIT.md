# D51 — D49-D50 stage merge-readiness audit

Requested to cover "D42-D50" and, per this project's own repeated
D25-vs-D31 / D47's-own-precedent discipline, checked rather than assumed:
`origin/main` is already at `73f5cb0` — the D42-D48 merge — not D41. **This
stage's true range is D49-D50 (8 commits), not D42-D50.** D47 audited the
D42-D46 slice and D48 closed its one gap before that merge; this audit
covers only what was never previously merged or audited: D49 (DNS override)
and D50 (credential-identity/command-format fixes).

Also requested, and new to this audit relative to D18/D23/D38/D47's own
format: an explicit check of whether D48/D49/D50 themselves have a D47-class
gap — a core function exercised only below the real `propose_action` entry
point.

**Headline: one real, previously unreported gap found — the exact D47-class
pattern, reapplied to D49/D50's own new surface. Fixed in this audit, not
merely reported, with two new permanent CI tests, mutation-verified. One
documentation gap also found and fixed: task #42/#44/#45's final, precise
blocked status existed only inside a live-run investigation doc, not
anywhere a future reader scanning the acceptance document would see it.
Everything else checked clean. Git and CI state confirmed, not assumed.**

---

## 一. End-to-end coverage audit (D47's own angle, applied three deliverables further)

### 1. D48/D49/D50's new or changed core functions — real entry point, or still bypassed?

Checked directly by grepping every test file touching each deliverable's
core functions for `propose_action`, the same method D47 used:

| Core function | Deliverable | Previously exercised through `propose_action`? |
|---|---|---|
| `ad_collector.build_plan` (dns_server) | D49 | No committed test — only `scripts/live_run/d45_ad_collection_e2e.py`, a manual live-run script (not pytest, not CI) |
| `dispatch_collection`'s dns-outside-allowlist refusal | D49 | No |
| `vault.store_credential`/`identity_for` (D50-B identity binding) | D50 | No — `tests/test_vault.py` and `tests/test_dispatch_collection.py` both call the vault/dispatch functions directly, never through `propose_action` |
| `dispatch_collection`'s identity-mismatch and legacy-credential refusals (D50-B) | D50 | No |
| `ad_collector.build_plan`'s attached-form command assembly (D50 F1/F3) | D50 | Yes — `tests/test_ad_collection_e2e.py::test_ad_collect_runs_end_to_end_through_propose_action` (D47/D48) already drives a credentialed proposal through `propose_action`, and that test's own command-shape assertion already reflects F1/F3's attached-form output (nothing about F1/F3 itself was left unexercised at this level) |

**Gap confirmed**: `tests/test_ad_collection_e2e.py` (D47/D48's own permanent,
CI-committed `propose_action`-level test file) had exactly two tests, both
predating D49 and D50-B. D49's `dns_server` mechanism and D50-B's
credential-identity binding were each fully covered at the
`dispatch_collection`-direct level (`tests/test_dispatch_collection.py`,
`tests/test_vault.py`, `tests/test_dns_server_kernel_evidence.py`) but never
strung together through the one real production entry point — precisely the
class of gap D47 defined and D48 closed for D42-D44's own functions, now
reopened by D49/D50 adding new surface to the same file without adding the
matching top-level test.

**Fixed in this audit.** Five new tests added to
`tests/test_ad_collection_e2e.py`, following the file's own established
two-tier convention (`_RecordingDockerSandbox`, real `propose_action` call
inside `engagement_scope`):

1. `test_dns_server_reaches_the_real_command_through_propose_action` — a
   proposal stating `dns_server` inside the allowlist reaches the real
   command's `-ns "$6"` argument.
2. `test_a_dns_server_outside_the_allowlist_is_refused_through_propose_action`
   — the D49 fail-closed check reached through the real entry point, not
   only at `dispatch_collection`-direct level.
3. `test_the_credentials_identity_is_used_when_the_proposal_states_none` — a
   proposal naming no `domain_username`/`auth_mode` at all still runs, bound
   to the credential's own identity.
4. `test_a_proposal_stating_a_different_identity_than_the_credential_is_refused`
   — D50-B's assertion-must-match refusal, through `propose_action`.
5. `test_a_legacy_credential_with_no_bound_identity_is_refused_through_propose_action`
   — a credential stored before D50-B (via `tests.test_vault._legacy_store`)
   is refused with the "predates identity binding" reason, not silently run.

**Mutation-verified**, the two tests proving genuinely new wiring facts
(the others re-exercise logic already mutation-verified at the
`dispatch_collection`-direct level in `tests/test_dispatch_collection.py`,
so re-driving them through `propose_action` proves the wiring, not the
underlying logic a second time):

* Mutated `control_plane/api/function_api.py`'s `execution_constraints` to
  drop the `dns_server` carry-through — both dns_server tests failed with
  specific, meaningful assertions (wrong command string; a run that should
  have been refused instead succeeded). Restored, confirmed byte-identical.
* Mutated `dispatch_collection`'s identity-substitution line to only use a
  stated value and never fall back to the credential's bound identity — the
  no-stated-identity test failed (the run was refused as `UNBUILDABLE_PLAN`
  instead of succeeding with the credential's own account). Restored,
  confirmed byte-identical.

All 7 tests in the file pass (`7 passed`); the file's own `ruff check` is
clean.

### 2. D50-B's data-shape alignment: every `credential_material` reader

Checked every call site that reads `credential_material`/`encrypted_material`
for `ad_domain_bind` credentials, not only `ad_collector.py`, for a
leftover assumption of the pre-D50-B separated shape (`{"secret"}` alone,
with username/auth_mode supplied separately by the caller):

* `control_plane/vault/vault.py`'s `material_for`, `mount_for_run` and the
  new `identity_for`/`_bound_identity` are the only functions that decrypt
  `encrypted_material` at all — confirmed by grep, no other module opens the
  Fernet-encrypted blob directly.
* `dispatch_collection` (`ad.collect`) is the only production caller of
  `identity_for`; `dispatch_code_scan`/`git_fetch.py`'s own `material_for`
  call is for `git_token` credentials, a type D50-B does not touch (`vault.py`
  raises if `username`/`auth_mode` are passed for anything but
  `ad_domain_bind`).
* No test or production code anywhere still constructs or asserts a
  `{"secret"}`-only `ad_domain_bind` credential as the *expected* shape going
  forward — the only place that shape is still constructed on purpose is
  `tests/test_vault.py`'s own `_legacy_store` helper, whose entire purpose is
  to simulate a pre-D50-B row for the refusal tests, and it is named and
  commented as exactly that.

**No stale-shape assumption found anywhere in the codebase's actual
production readers.** (This matches what was already found and reported
before this audit session's compaction; re-confirmed here rather than
re-run from scratch, since the grep-based method leaves no ambiguity to
re-check.)

---

## 二. Documentation completeness

### 1. `ACCEPTANCE_MVP1_AGENTS.md` 5.20-5.26 against their source reports

Delegated to an independent read (a fresh pass, not reusing this session's
own prior read of either document, to avoid confirming a bias already held):
every cited section number, finding label (F1/F2/F4/F5), file path and test
name in 5.20 through 5.26 was opened and checked against its target.
**Result: no broken cross-reference, no content drift.** One purely
structural (non-factual) observation: 5.24's D45-era "sharpened" addendum
lives as prose between the D44 and D45 tables rather than inside the 5.24
table cell itself — the content is accurate and complete, just not
co-located with the row. Not fixed, since it is not a defect (D45's own
report explicitly frames it as an addendum "recorded... 5.24", and the
addendum's own placement immediately adjacent to the table is where a reader
scanning that section would find it).

### 2. `ADR_CREDENTIAL_VAULT.md` §8 (Revision, D50-B) against §1

Checked whether a reader could mistake §1's original design and §8's
revision for two live, co-existing decisions. They cannot be, for three
independent reasons already present in the document, not added by this
audit:

* The document's own top-of-file status banner (added at D50) already
  states forward: *"Revision (D50-B): §8 changes what an `ad_domain_bind`
  credential is..."* — a reader reaching §1 has already been told a later
  revision exists before they get there.
* §8.1 opens with **"Status: implemented at D50-B"** and describes the prior
  behavior entirely in past tense (*"Until D50-B `store_credential`
  encrypted only the secret"*) — there is no wording that could be read as
  "both are current."
* §1 itself never actually stated the secret-only decision as a formal ADR
  decision — §8.1 traces it to `store_credential`'s own docstring, not to
  §1's text, and that docstring has itself already been rewritten (checked:
  `control_plane/vault/vault.py` line 204 now reads "Until D50-B..." in the
  same past-tense framing as the ADR). §5's decision table (`D44-1` through
  `D44-7`) also contains no row asserting the secret-only shape as a
  decision — confirming §8.1's own honest admission that this was never a
  contested, dual-recorded ADR decision in the first place, only an
  implementation detail later found to need revising.

**No fix needed.** This item was flagged in the D51 brief as a real risk
worth checking; checking it directly found the existing text already
satisfies the ask.

### 3. Task #42/#44/#45's blocked status — visible where a reader would look

**Gap confirmed, and it is exactly what the brief predicted.** The final,
precise status — mechanism (DNS + credential format) verified working
end-to-end through the real production path; blocked on
`ldap3.core.exceptions.LDAPSessionTerminatedByServerError` because Samba's
AD DC does not support the legacy "Sicily" NTLM bind extension `ldap3`
requires; not fixable from this codebase — existed only in
`docs/D50_AD_COLLECTOR_AUTH_GAP_INVESTIGATION.md` §9, a live-run
investigation document nothing in `ACCEPTANCE_MVP1_AGENTS.md` pointed a
reader toward. ACCEPTANCE's own 5.25 entry still read, unchanged since D49,
"task #42/#44/#45 ... remain open, to be picked up now that this mechanism
is confirmed working" — true when written, superseded by D50's own §9
result, and never updated.

**Fixed in this audit.** 5.25's entry now ends with the final status
(mechanism verified; blocked on the Sicily-extension gap; #44/#45 blocked
for want of any real collected data anywhere; #42 deliberately unwritten
for want of any real output to translate; not fixable from this codebase),
with a pointer to §9 for full detail rather than repeating it — matching
this table's own established style for every other entry that summarizes a
fuller report elsewhere.

---

## 三. Git and CI state — checked, not assumed

### 1. Where `main` actually stops

```
$ git fetch origin main && git rev-parse origin/main
73f5cb0fcca2d61158ee1eafd4728db69790e386
```

Confirmed directly, per this project's own D25-vs-D31 lesson (never assume a
merge's range matches its deliverable numbering, or that `origin/main` sits
at any assumed prior commit): `origin/main` is `73f5cb0`, the **D42-D48**
merge, not D41. This stage merges on top of that, not on top of D41.

### 2. The branch's actual range

```
$ git log --oneline origin/main..HEAD
2d9f80e D50 follow-up: task 42/44/45 attempted against real Samba DC, still blocked
c16b96a D50 decisions: D50-A/C recorded as a new candidate, D50-B implemented, D50-D orders task 42/44/45 ahead of D50-A
96905bd D50 F2: ADR addendum draft -- argv exposure options, nothing decided
68269b4 D50 decisions F1 + F3: refuse credential-free ad.collect, attached-form arguments
5b62d3a D50: investigate the ad_collector authentication gap (no fix)
203d8d6 D49 fixup: build the bloodhound image in CI
79bbe99 D49 fixup: declare dnspython as a dev dependency
7f8dd87 D49: DNS server override for ad.collect, unblocking domain-controller discovery
```

**Eight commits, genuinely D49 through D50 — not D42-D50.** `origin/main`
already carries everything through D48; this branch's oldest unmerged
commit (`7f8dd87`) is D49's own first commit. No repeat of the D25-style
surprise this project has twice previously found (D31-D41's own true range
being D25-D41; nothing stranded here).

### 3. Full commit list and CI result

| Commit | Message | CI conclusion |
|---|---|---|
| `7f8dd87` | D49: DNS server override for ad.collect, unblocking domain-controller discovery | **failure** |
| `79bbe99` | D49 fixup: declare dnspython as a dev dependency | **failure** |
| `203d8d6` | D49 fixup: build the bloodhound image in CI | success |
| `5b62d3a` | D50: investigate the ad_collector authentication gap (no fix) | success |
| `68269b4` | D50 decisions F1 + F3: refuse credential-free ad.collect, attached-form arguments | success |
| `96905bd` | D50 F2: ADR addendum draft -- argv exposure options, nothing decided | success |
| `c16b96a` | D50 decisions: D50-A/C recorded as a new candidate, D50-B implemented, D50-D orders task 42/44/45 ahead of D50-A | success |
| `2d9f80e` | D50 follow-up: task 42/44/45 attempted against real Samba DC, still blocked | success |

**Two historical CI failures, both in D49's first two commits, both
diagnosed and fixed by the two commits immediately following** — the same
pattern this project's merge history already treats as normal (matching
`73f5cb0`'s own commit message precedent). Current `HEAD` (`2d9f80e`) is
green.

### 4. Working tree and remote state

```
$ git fetch origin main claude/mvp-kernel-cybersecurity-platform-su841g
$ git rev-parse origin/main HEAD origin/claude/mvp-kernel-cybersecurity-platform-su841g
73f5cb0fcca2d61158ee1eafd4728db69790e386
2d9f80e7aea64feb5bf34169ada4a5239f8bb66d
2d9f80e7aea64feb5bf34169ada4a5239f8bb66d
```

Local `HEAD` matches the remote branch exactly (before this audit's own
documentation and test additions). No divergence, nothing stranded.

---

## 四. Scale

| Metric | D42-D48 close (`73f5cb0`, the actual last merge — not D41) | D41-close (`b82dc57`, for continuity with the number named in the brief) | This merge (D49-D50) |
|---|---|---|---|
| Tests passed locally | 928 | 792 | **1004** (+76 vs. D42-D48 close; +212 vs. D41-close) |
| OPA tests | 44/44 | 41/41 | **44/44** (+0 — neither D49 nor D50 touched Rego) |

`opa fmt --fail --list control_plane/policy/rego policy_tests`: clean, no
reformatting needed. `ruff check .`: clean. Full local suite: `1004 passed`
(no skips, no xfails, one pre-existing `DeprecationWarning` from a
third-party dependency, unrelated to this stage).

The D42-D48 figure (928/44) is the correct immediate comparison — it is
where this branch's history actually starts, confirmed in §三 above; the
D41-close figure (792/41) is given alongside it only because the brief named
D41 specifically, following the same "don't silently substitute the number
that turned out to be wrong" discipline this project applied when D25-vs-D31
was first found.

---

## 5. Conclusion

One real coverage gap found (一-1: D49/D50's own new surface — dns_server
and credential-identity binding — had never been driven through the real
`propose_action` entry point) — **fixed in this audit**, not merely reported,
with five new tests and two mutation-verifications. One documentation gap
found (二-3: task #42/#44/#45's final blocked status was recorded only in a
live-run investigation doc) — **fixed**, with a pointer added to
`ACCEPTANCE_MVP1_AGENTS.md` 5.25. Everything else checked clean: the
cross-document consistency audit (二-1) and the ADR revision-clarity check
(二-2) found no defects, and D50-B's data-model alignment (一-2) has no
stale-shape reader anywhere in the codebase. Git and CI state confirmed
rather than assumed (三): the range is genuinely D49-D50 (8 commits), not
D42-D50; `main` is at the D42-D48 merge, not D41; every historical CI
failure was resolved within the same range. Scale figures given in 四, with
the correct baseline (D42-D48 close) reported alongside the one the brief
named (D41-close) rather than silently substituted.

**Clean to merge**, pending this audit's own new commits (the five new
tests plus the two documentation fixes) going green in CI.
