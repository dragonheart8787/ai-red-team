# D53 — Replaying the Semgrep integration through the onboarding skeleton

**The question.** Does the skeleton (`docs/NEW_TOOL_ONBOARDING.md`,
`scripts/new_tool_scaffold.py`, `tests/adapter_kit.py`,
`tests/test_adapter_contract.py`) save repeated work, *and* omit none of the
checkpoints earlier integrations found? Semgrep (D43) is the subject because it is
the most recent tool with a Dockerfile image, a bespoke dispatch function, an
evidence-sensitivity decision and a full ADR — every kind of step the skeleton has.

**Method.** Three independent measurements, so no single number carries the claim:

1. *Generation overlap* — render the scaffold as if for Semgrep and count how much of
   what D43 actually wrote it would have produced (§1).
2. *The walk* — work Semgrep through the generated test file, filling it in, and see
   what it asks that D43 did not answer (§2).
3. *Defect injection* — re-introduce each historical defect into the real code and
   confirm the skeleton goes red (§3). This is the check on "omitted no checkpoint":
   a checkpoint that nothing turns red for has been omitted, whatever the document says.

**Headline.** The skeleton saves little typing, catches every defect that had a
mechanical signature, and — the point of replaying — showed that the most recent
integration had two gaps the earlier ones did not, one of which is a real hole in a
neighbouring mechanism. It also cannot and does not cover the judgement steps or a
test dependency CI's fresh install lacks. Details and limits below.

---

## 1. What the scaffold would have generated

Non-blank, non-comment lines (docstrings excluded for Python) of the real Semgrep
files that appear **verbatim** in the scaffold rendered for `semgrep`/`code.scan`:

| Artifact | Real lines | Also in the scaffold | Share |
|---|---:|---:|---:|
| `tool_gateway/adapters/semgrep.py` | 131 | 30 | **23%** |
| `tool_gateway/images/semgrep.Dockerfile` | 17 | 10 | **59%** |
| `tool_gateway/images/build_semgrep_image.sh` | 29 | 23 | **79%** |
| the four `code.scan` test files | 575 | 45 | **8%** |

**Read this table for what it says, not for a headline.** The adapter figure is low
by construction: the decision constants (`WRITES_DATA`, `NEEDS_DISPATCH`, the pin) are
emitted as `NotImplemented` precisely so they do not match, and the rest is the
tool's own logic (the ruleset, snippet reading, redaction, the `#branch` target). The
test figure is low because the scaffold supplies *checkpoints*, not D43's specific
assertions. The overlap that is real is the image plumbing — the build script and, to
a lesser degree, the Dockerfile — which three integrations had near-copied by hand.
**Typing is not where the skeleton saves; it saves CI rounds** (below), and it
front-loads questions.

**CI rounds, from the record.** D43 reached green in three pushes: `8c6eb16`
(red — no image build step) → `8168084` (red — `tool_version()` probed the host) →
`ab2849a` (green). Both causes are now caught before the first push
(§3, rows 1–2), so three becomes one. D49 (BloodHound) took three: `7f8dd87`
(red — `dnspython` undeclared) → `79bbe99` (red — no image build step) → `203d8d6`
(green). The image step is caught; the undeclared test dependency is **not**
(§4 of the inventory: "not covered"), so three becomes two. One caveat that cuts the
other way: the same check would have demanded BloodHound's CI image step at D45, the
commit that first declared `IMAGE` and added the Dockerfile, four deliverables before
any test in the gate needed the image — a heavier CI earlier, accepted as the price of
the fail-rather-than-skip convention the workflow already states.

---

## 2. The walk — what Semgrep is asked, and what D43 had not answered

Working `tests/test_semgrep_onboarding.py` (the generated test file, filled in):

| Question the skeleton asks | D43's answer | Result |
|---|---|---|
| Is every input `build_plan` reads accounted for in the fingerprint, pinned both ways? | D43 tested the two *non-adapter* dimensions (commit, ruleset) but never `build_plan`'s own inputs against `as_params` | **New coverage**; passes. Adding `constraints.get("severity_floor")` without accounting for it now fails (§3 row 11). |
| Are the non-adapter dimensions still tested? | `test_dispatch_code_scan_dedup.py`, four tests | Confirmed present; pinned by name, since a deleted test does not fail (D27/D28) |
| Is redaction tested, with its negative control? | `test_semgrep_adapter.py` (D43-4), including the identity-redactor mutation | Confirmed present; pinned by name |
| **Is there an injection carrier test?** | **None.** Every other tool that reads content a third party can influence has one | **A gap.** Written: an address in a source comment reaches the model as evidence through the real `derive_view` and real redaction, and is marked introduced; a follow-on `network.scan` against it is refused by authorization |
| Does the carrier work for the target shape this tool actually has? | Not asked at D43 | **A second gap** — a `repo` named by location alone slips D20's comparison (below) |

**The repo gap, precisely.** `code.scan` accepts a target only as `<location>#<branch>`
(D43-1). Source that names a repository by location — `vendored from
http://evil.example/x/y.git` — never contains the string a Worker would propose,
`http://evil.example/x/y.git#main`, and D20's comparison treats a `repo` identity as
an opaque string. Executed: proposing `<location>#main` → `introduced_by_untrusted:
False`; proposing the bare location → `True`, a form `code.scan` would refuse to run.
Authorization still refuses a repo no scope object covers, so this is a missing second
layer, not a broken boundary. It is the same shape as D52's `url` finding, and it is
mine to own: I probed the bare form in D52 and not the `#branch` form, which is the
only one that runs. It was pinned by a known-gap test so it could not be forgotten or fixed silently,
recorded as ACCEPTANCE **5.31**, and **closed in the D53 closeout (`178c9e1`)**: a repo
is now keyed by its location, and the test was inverted.

The walk also surfaced, without being looked for, two defects in *other* tools that
the mechanical checks report on their first run (inventory F1, F2; ACCEPTANCE 5.29,
5.30).

---

## 3. Defect injection — each historical defect, re-introduced

Every row edits real code, runs the relevant tests, restores with `git checkout`, and
confirms the tracked tree is clean afterwards. **RED** = the skeleton caught it.

| # | Defect re-introduced | Origin | Result |
|--:|---|---|---|
| 1 | CI no longer builds the semgrep image | D43 `8168084` | **RED** — `test_every_adapter_is_wired_in_everywhere…[code.scan]` |
| 2 | CI no longer builds the bloodhound image | D49 `203d8d6` | **RED** — `…[ad.collect]` |
| 3 | `semgrep.tool_version()` probes the host again | D43 `ab2849a` | **RED** — `test_every_adapter_meets_the_local_contract[code.scan]` |
| 4 | `execution_constraints` drops `exclude_paths` | D45 | **RED** — wired-in check, `code.scan` |
| 5 | `execution_constraints` drops the web `port` | D37 | **RED** — wired-in check, `web.get` |
| 6 | Semgrep missing from `EVIDENCE_PREFIX` | latent | **RED** — wired-in check, `code.scan` |
| 7 | An adapter's `WRITES_DATA` undecided (browser) | D34 | **RED** — local contract, `web.render` |
| 8 | An adapter names a non-existent dispatch function | D46 | **RED** — local contract, `code.scan` |
| 9 | `exclude_paths` dropped from `as_params` | D11-3 | **RED** — `test_every_build_plan_input_is_accounted_for_in_the_fingerprint` |
| 10 | `target` dropped from `as_params` | D11-3 | **RED** — same |
| 11 | A new constraint read by `build_plan`, unaccounted | D11-3 (prospective) | **RED** — fingerprint accounting **and** wired-in check |
| 12 | Redaction silently stops being applied | D43-4 | **RED** — `test_derive_view_redacts_the_fake_secret_by_default` |
| 13 | The discovery check stops noticing a lure in evidence | D20 | **RED** — `test_an_address_named_in_scanned_source_is_a_discovery_candidate_only` |
| 14 | *Live:* BloodHound's `tool_version()` host probe (exemption removed) | D43 defect, present at D53 | **fired** — reported `'unknown'`; fixed in `d708117` |

Three properties of the checks themselves, also shown rather than assumed:

* A hand-written "lowercase and strip the dot" normalizer *passes* the D52 spelling
  cases I first wrote, and is caught only by the structural test that the
  canonicalizer is consulted — until IPv6-compression and IDNA cases were added.
  (The D52 mutation run; the same discipline applies here: a check is finished when it
  has been seen red.)
* Every declared exemption has a staleness test: the exemption for `web.post`'s body,
  for BloodHound's `tool_version`, and for nmap's missing `ACTION` each fail if the
  thing they excuse stops being true.
* An **untouched** scaffold fails seven of its nine generated tests, passes one (the
  untrusted-and-JSON derived view, which is the safe default), and has zero skips. The
  seven: `local contract`, `wired in everywhere`, `fingerprint accounting`,
  `non-adapter dimensions`, `derive_view decisions`, `lure marked introduced`,
  `end to end through propose_action`. The ninth, `a lure cannot be authorized`, needs
  the repository's database fixtures and is excluded from that run. Filling in the four decision constants and the
  pin turns the local contract green and *only* that; the wiring checks then name,
  one by one, the registry entry, the evidence prefix, the missing image build script,
  and the missing decided ADR.

**Coverage of the ledger.** The inventory's failure ledger has 22 rows. Seven are
enforced (rows 1–8 above cover six of them; the seventh, the untrusted-content marker,
is shown red on a deliberately broken adapter by
`test_the_local_contract_fires_on_a_broken_adapter`), five are scaffolded (a generated test fails
until it is written), nine are checklist or template comments, one is not covered.
Nothing was dropped between the ledger and the skeleton; what the skeleton does
*not* catch is listed, by name, in `NEW_TOOL_ONBOARDING.md` §7.

---

## 4. What this replay does not show

* **That the skeleton works on a tool no one has onboarded yet.** It was verified
  against six tools whose mistakes are known. A seventh will find a new one; §8 of the
  onboarding doc says to add its check and its ledger row.
* **That the judgement steps are done well by anyone using it.** The threat-model gate
  verifies a decided document exists, not that its analysis is right. The scaffold's
  point is that it cannot look as if it answered them.
* **That the image templates build.** They are deliberately unbuildable until decisions
  are made (a `exit 1` in the Dockerfile; the script refuses without a pin and a
  self-check). What is tested is their shape against three real ones (§1), that the
  script is valid shell, and that it refuses to run undecided. No new image was built.
* **Large savings in typing.** §1 says otherwise, and that is the honest number.
* **That the two DB-backed generated tests are green for a new tool.** The scaffold
  self-test excludes them (they need the repository's fixtures); they were exercised
  for Semgrep in `tests/test_semgrep_onboarding.py`.

## 5. Findings recorded

| ACCEPTANCE | Finding | Class |
|---|---|---|
| **5.29** | `web.post` can never build a plan through `propose_action` (no way to carry a body); `web.get` and `web.post` have never been driven past policy into dispatch by a committed test | C — **decided and closed** (option C); analysis and decision in `D53_5_29_WEB_POST_BODY_ANALYSIS.md` |
| **5.30** | `ad_collector.tool_version()` host-probes and returns `"unknown"` (the D43 `ab2849a` defect, unfixed in its sibling) | B — **closed `d708117`** |
| **5.31** | A repository named in scanned source by location alone is not escalated by D20, because a `repo` is compared as an opaque string and the only runnable form carries `#branch` | B — **closed `178c9e1`** |

At D53 none was fixed: 5.30 and 5.31 had small fixes with clear precedents (`ab2849a`;
D52's keying a `url` by its host) that changed behaviour outside this deliverable's
scope, so they waited for a go-ahead. **The closeout gave it and both are fixed**, each
with a test shown red against the pre-fix code and green after. Row 14 above was the
live case; with 5.30 fixed the exemption table it used is empty, and the staleness test
that guards the empty table remains. 5.29 was a design decision, made afterwards (a constructed-test-data body, refused at propose time if it matches a known secret format), and is closed too.
