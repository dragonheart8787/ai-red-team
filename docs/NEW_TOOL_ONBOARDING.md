# Onboarding a new tool

How to add a tool (a new `action` and the adapter behind it) so that the mistakes
the first six integrations made are caught before CI does — **without** turning
onboarding into something that can be done without thinking about the tool.

Built from `docs/D53_TOOL_ONBOARDING_INVENTORY.md`, which lists what six
integrations repeated, the failure that found each checkpoint, and what the
inventory itself turned up. Verified against Semgrep in
`docs/D53_SKELETON_REPLAY_SEMGREP.md`.

```
docs/templates/ADR_NEW_TOOL_TEMPLATE.md   the threat-model worksheet   (a person)
scripts/new_tool_scaffold.py              the mechanical skeleton       (generated, undecided)
tests/adapter_kit.py                      the checks, as functions
tests/test_adapter_contract.py            the checks, over every registered adapter (CI)
```

---

## 1. What this does not do — read first

**One tool at a time, each with its own analysis.** The order is a rule, not a
suggestion: **the ADR comes before the adapter.**

The scaffold and the checks accelerate *writing code*. They cannot answer, and are
built so that they never appear to answer, any question about how the system's
security model should constrain a tool. Those are decided by a person who has
looked at what the tool's data is, and recorded in `docs/ADR_<TOOL>.md`:

| Decision | What it looked like when it was actually made |
|---|---|
| What a scope object for the tool authorizes | D42-1: `ad_domain` authorizes *collecting*, never *acting on what is collected* |
| Precision and containment of the target | D43-1: pin repo + branch, not a commit; D43-2: refuse subdirectory containment |
| Whether the action needs a known classification | D32 yes for `web.get`; 5.48 yes for `web.render` (D32's argument, applied to what D36 added); D43-3 yes for `code.*`; no for `network.*` (a banner is a fragment) and `ad.collect` (collection is discovery, argued at 5.48 in `ADR_BLOODHOUND_NEO4J.md`). **Decided by the action's spelling** in `authz.rego`, so choosing the name is part of the decision (D56): the adapter states `KNOWN_CLASSIFICATION` (`"required"` or `"exempt: <reason>"`) and the check compares it with the rule |
| What a model may read of the output, and what is redacted or cut | D43-4: redact snippets before they leave the adapter; mark first-party content |
| Whether the tool gets the network, and by which route | proxy (web), namespace allowlist (nmap), none at all (Semgrep) |
| What the tool does to its target (`WRITES_DATA`, `CHANGES_STATE`) | D34: `web.post` ended the argument that `web.*` only reads |
| How credentials reach the tool | D44/D50: mounted file, never argv or environment; identity bound to the credential |

The scaffold emits every one of these as `NotImplemented` (which is not a `bool`),
so the contract check refuses it; its placeholder tests **fail**, they do not skip
(CI fails the build on any skip, and a scaffold that could go green by omission
would be batch onboarding). A precedent in the template is a consistency
constraint, never an answer.

**A green run means the code agrees with itself, not that the decisions were
right.** §7 lists exactly what the checks cannot see.

**There is a mechanical gate on the analysis, and its limit is stated.**
`tests/test_adapter_contract.py` fails for any tool registered after D53 that has no
`docs/ADR_<TOOL>.md`, or whose `Status:` is still *proposed/draft/investigation*.
It checks that the document exists and a decision was recorded. It cannot judge the
analysis — review does that. What it changes is that skipping the analysis becomes a
red run instead of something nobody notices. The six existing tools are grandfathered
by name in `adapter_kit.PRE_D53_TOOLS`; a test pins that set and nothing may be added.

---

## 2. The procedure

| # | Step | Who | Output |
|---|---|---|---|
| 1 | Write the threat-model ADR from the template; get the decisions signed off | a person | `docs/ADR_<TOOL>.md`, status *accepted* |
| 2 | `python scripts/new_tool_scaffold.py --name <tool> --action <ns.verb> --out <scratch>` — the `--action` is a choice, not a formality: the script prints whether the classification gate applies to that spelling | script | adapter, tests, Dockerfile, build script, ADR copy, registration list |
| 3 | Review and copy the output into the repository | a person | files in place |
| 4 | Replace every `DECIDE(...)` in the adapter with the ADR's answer | a person | adapter constants + `build_plan` + `derive_view` |
| 5 | Choose the image (§3); build it; run its self-check | a person | image + `build_<tool>_image.sh` passing |
| 6 | Work through `REGISTRATION_<tool>.md` Part A | a person, enforced by tests | registry, `EVIDENCE_PREFIX`, `execution_constraints`, CI step |
| 7 | Replace every placeholder test (§5) | a person | a red-to-green test file |
| 8 | `python scripts/new_tool_scaffold.py --check <tool>` — nothing unresolved | script | clean |
| 9 | Definition of done (§6) | a person | |

`scaffold --check <tool>` and `tests/test_adapter_contract.py` report the same
things; run either at any point to see what is left.

---

## 3. Sandbox and image staging

Every item is a defect an earlier image shipped. The Dockerfile and build-script
templates encode the ones marked *template*; the rest are yours.

**Image**
- Pin the tool to an exact version; `tool_version()` returns that constant. It must
  never probe a binary on the control-plane host — the tool lives in the image
  (D43 `ab2849a`; found unfixed in `ad_collector` at D53, ACCEPTANCE 5.30, fixed after). *Enforced* for an adapter whose image is a `<slug>.Dockerfile`; **not** for a scratch-route image, which has no such file (ACCEPTANCE 5.45) -- a test of your own is then the only guard.
- Bake a manifest recording the version and base; the build script checks it. *Template.*
- Run as a non-root user that owns nothing. *Template.*
- The sandbox runs the container `cap_drop=ALL`, `read_only`, `no-new-privileges`,
  memory and pid limited (`sandbox.py`). A `0600` file another uid owns is
  **unreadable to cap-dropped root** — it passed locally as uid 0 and failed on the
  runner's uid 1001 (D35). Run as the file's owner, or mount public material `0644`.
- The container `command` is **appended to `ENTRYPOINT`**, not a replacement for it,
  and so is anything a build check passes (D34, twice). Pass arguments only; make the
  check `--entrypoint`. *Template comment.*
- The scratch-image route (`_python_scratch.sh`): `ldd` on the interpreter does **not**
  see the libraries the stdlib's C extensions `dlopen`; a symlink can replace the
  interpreter it was meant to point at; an explicit document root beats `WORKDIR`;
  python needs `-u` or its startup line never leaves the buffer (D31, five rounds).
  The Dockerfile route avoids all of these; prefer it. **Use the scratch route only when it cannot
  be avoided** -- Gitleaks (D55) did: the development container's egress policy denies distro
  mirrors, so `apt` could not be run where the image had to be built and verified. There is no
  template for it yet (ACCEPTANCE 5.44); `build_gitleaks_image.sh` is the worked example, with a
  sha256-pinned download and a self-check that exercises the tool's *job* on a fixture.

**Self-check** (the build script; *template*)
- Run the tool **exactly as the sandbox does**: `--network none --cap-drop ALL
  --security-opt no-new-privileges:true --read-only`, plus a `--tmpfs` for every path the
  adapter's `TMPFS` declares. A check under looser flags proves nothing.
- **Print the output before gating on it.** A check that discards it reports "cannot
  launch" with no cause (D36).
- For a tool that can start with no input, the check needs no target: a required positional
  broke `--self-check` (D36). For a tool whose failure is a *silent no-op* (Gitleaks reads
  nothing and says "no leaks found"), `--version` proves nothing and the check must run its job
  on a built-in fixture (D55, ACCEPTANCE 5.44).
  A Python entrypoint needs an `if __name__ == "__main__"` guard or it imports, does
  nothing, and exits 0 (D36 `3e5598e`, three CI rounds).

**Runtime**
- A tool that writes under `$HOME` or `/tmp` needs a `TMPFS` (Semgrep wrote `~/.semgrep`;
  Chromium a whole profile). Leaving it `None` is safe: the tool fails loudly.
- Anything the tool does on its own initiative — version check, telemetry, rule-registry
  fetch — **hangs** under `--network none` rather than failing fast. Switch it off *in
  the built command*, never as an option a caller could omit (D43).
- A secret is never in argv: it is world-readable in the host process table for the
  whole run (D50, ACCEPTANCE 5.26).
- Readiness: `docker run -d` returns before the process binds. Gate on a log line, and
  make sure the line is flushed (D31 fixes 4–5, D34).
- Fixtures: two fixtures pinning one IP race on teardown; give each its own subnet (D35).

**CI**
- Add a step running `build_<tool>_image.sh` before the suite. Real-container tests
  **fail** on the runner without it — forgotten for Semgrep (D43) and BloodHound (D49).
  *Enforced.*
- Assume the runner differs from this machine: uid 1001 not 0, PyPI reachable where the
  dev sandbox's proxy re-signs TLS, PostgreSQL present. Declare test-only Python
  dependencies in `pyproject.toml` (D49 `7f8dd87`: `dnspython`). *Not covered.*

---

## 4. Evidence: what does a model read?

Answer in the ADR (§3 of the template) before writing `derive_view`. The scaffold's
default shows a model **none** of the output — only byte counts.

```
Is any of the output text a third party could have written?
├─ yes (almost always) ── set untrusted_content: true ............. enforced at write time
│
├─ Could it hold a secret the reader must not see?
│   ├─ yes ── redact BEFORE it leaves the adapter (redact_snippet, D43-4)
│   │          └─ write the negative control: swap the redactor for identity and watch the
│   │             secret appear (test_semgrep_adapter.py)   ← proves the redactor, not the input
│   │          └─ set first_party_source_content if it is the customer's own material —
│   │             a second axis: "is it true" vs "should it be seen in full"; never collapse them
│   └─ no ── say why in the ADR
│
├─ Is it unbounded? ── cap what a model sees; keep the raw artifact whole (§4.4)
│                      (D40: the argv limit was hit at three evidence artifacts, 5.21)
│
└─ Does it name addresses? ── extract them for DISCOVERY only, in the harness, never by the
                              agent (D20). Being listed authorizes nothing (I8).
```

Where you cut is a decision too: a cut that hides a finding is an omission, not a bound.

---

## 5. The tests

The scaffold generates `tests/test_<tool>_adapter.py`. Every test is a check from
`adapter_kit` or a placeholder that fails. Where each comes from:

| Test | Catches | Origin |
|---|---|---|
| local contract | undecided constants (incl. `KNOWN_CLASSIFICATION`); a bad `NEEDS_DISPATCH`; a host-probe `tool_version` | D34, D43, D46, D56 |
| wired in everywhere | no registry entry, no evidence prefix, no CI build step, a constraint `execution_constraints` drops, no decided ADR; **the function behind `NEEDS_DISPATCH` is bound to another adapter or refuses this action** (`dispatch_violations`: static and a probe through the real `_dispatch_for_action`); **`KNOWN_CLASSIFICATION` disagrees with what `authz.rego` does to the action's name** (`classification_violations`, asked of OPA) | D37, D43, D45, D49, D56 |
| fingerprint accounting | an input `build_plan` reads that neither reaches `as_params` nor is declared out, pinned both ways | D11-3 |
| non-adapter fingerprint dimensions *(placeholder)* | commit, ruleset hash, allowlist, credential id — dimensions no code can enumerate | D11-3, D43-1 |
| derive_view untrusted + JSON | a view a model could read as trusted | §4.4 |
| derive_view decisions *(placeholder)* | redaction, truncation, and its negative control | D43-4 |
| lure marked introduced *(placeholder + helper)* | the tool's own output naming an address it never observed | I8: D13, D31, D34, D37 |
| lure cannot be authorized | naming an address in content confers no scope | I8 |
| end to end through `propose_action` *(placeholder)* | wiring no lower layer can see; write a stub tier and, if it can run for real in CI, a real one | D45–D48, D51 |

*Sample-driven* checks (fingerprint, lure) need a working `build_plan` call and a
realistic lure-bearing output from you — only you know what a valid one looks like.
`fingerprint_violations` also reads `build_plan`'s source: an input the test does not
mention fails, so a constraint added later cannot escape the fingerprint.

The two "wired in" and "local contract" tests in the generated file are redundant
with `test_adapter_contract.py` once the tool is registered; they exist so the red
signal is visible before that.

---

## 6. Definition of done

- [ ] `docs/ADR_<TOOL>.md` is *accepted*, with its "what this document does not do"
      section honest about what was not verified.
- [ ] `python scripts/new_tool_scaffold.py --check <tool>` reports nothing.
- [ ] No `DECIDE(` remains in any file for the tool; no placeholder test remains.
- [ ] The image builds in CI, and its self-check ran as the sandbox runs it.
- [ ] The action has been driven through `propose_action` by a committed test, stating
      each constraint the tool reads and asserting it reaches the built command.
- [ ] Anything raised and not resolved is in `docs/ACCEPTANCE_MVP1_AGENTS.md`, including
      the honest limit — "verified with tests and a hand-built `Observation`; no
      production harness builds this tool's evidence into one" if that is still true
      (5.28).
- [ ] Before a merge of a whole stage: an independent audit in the D47/D51 style, asking
      whether any layer is green without ever having been driven through the entry point.

---

## 7. What a green result does not tell you

- That `WRITES_DATA = False` is **true**. The checks verify somebody stated it.
- That the scope model, the classification decision or the egress model was right.
- That the redaction patterns cover the secrets *this* tool's output can contain.
- That the fingerprint has every dimension. It verifies every `build_plan` input is
  accounted for; a dimension that is not an input (a resolved commit) is only as good
  as the placeholder test you wrote.
- That the image staging is sound beyond "the self-check ran". The scratch-image
  pitfalls, `0600`/uid, readiness and fixture collisions are a checklist, not tests.
- That the tool's evidence reaches a model correctly in production. Nothing in
  production builds an `Observation` from a tool's evidence yet (5.28); the injection
  helper verifies the computation on a hand-built one, as D31/D34/D37 did.
- That a test-only dependency is declared.

---

## 8. Keeping this honest

- When an integration finds a new mistake, add the check **and** the ledger row in the
  inventory. A lesson that lives only in a commit message is how six integrations
  repeated five of them.
- An exemption (`adapter_kit.CARRY_EXEMPTIONS`, `TOOL_VERSION_HOST_PROBE_EXEMPTIONS`,
  `MULTI_ACTION_ADAPTERS`) carries its reason, and a test fails when the thing it
  excuses stops being true. Do not add one to make a red run green; add one to record a
  known gap, with an ACCEPTANCE entry.
- Every check here has been shown red by re-introducing the defect it descends from
  (`docs/D53_SKELETON_REPLAY_SEMGREP.md` §3). A new check is not done until it has.
