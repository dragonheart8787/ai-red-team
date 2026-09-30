# D53 — What six tool integrations repeated, and what none of them could share

Input to `docs/NEW_TOOL_ONBOARDING.md`. Every row here was checked against the
tree at commit `54d53a2` (or against the commit it cites), not recalled: D45 and
D51 each found that a claim written from memory was false, and this document's
own first draft of one row was (see §4, F3).

**Scope note.** The brief names six integrations and lists five tools, because two
of the six are both HTTP: D6 nmap, D31 `web.get`, D34 `web.post` (these two share
`adapters/_http.py`), D36 `web.render` (the browser), D42 BloodHound (`ad.collect`),
D43 Semgrep (`code.scan`). D44 (Credential Vault) and D49/D50 (DNS override,
credential identity) extended adapters rather than adding a tool, and are used
here only as sources of lessons.

---

## 1. The steps that repeated

Legend: ● done as a step of that integration · ◐ done later as a retrofit ·
○ not applicable to that tool · **—** not done, and later shown to matter.

| # | Repeated step | D6 nmap | D31 GET | D34 POST | D36 browser | D42 BH | D43 Semgrep |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|
| 1 | Adapter module: `TOOL`, `ACTION`, `build_plan`, `as_params`, `tool_version`, `derive_view`, `AdapterError` | ● | ● | ● | ● | ● | ● |
| 2 | `registry.ADAPTERS` entry | ◐ D34 (the registry was created then) | ◐ D34 | ● | ● | ● | ● |
| 3 | Side-effect profile `WRITES_DATA` / `CHANGES_STATE` / `REQUIRES_PROXY` | ◐ D34 | ● D31 (`REQUIRES_PROXY` ◐ D34) | ● | ● | ● | ● |
| 4 | `NEEDS_DISPATCH` | ◐ D46 | ◐ D46 | ◐ D46 | ◐ D46 | ◐ D46 | ◐ D46 |
| 5 | `dispatch.EVIDENCE_PREFIX` entry | ◐ D31 (the table was created then) | ● | ● | ● | ● | ● |
| 6 | `execution_constraints` carries every constraint the adapter reads | ● | **— (D37)** | **— (never; F1)** | **— (D37)** | **— (D45)** | **— (D45)** |
| 7 | Image with pinned version | ● host export | ● the nmap image, `curl` added at D31 | ● same | ● Dockerfile | ● Dockerfile | ● Dockerfile |
| 8 | Image manifest + build script that verifies it | ○ | ○ | ○ | ● | ● | ● |
| 9 | Self-check run as the sandbox runs it (cap-dropped, read-only, no network) | ● workflow boundary check | ● workflow | ● workflow | ● | ● | ● |
| 10 | CI step building the image | ● | ● | ● | ● | **— (until D49)** | **— (until 8168084)** |
| 11 | `tool_version()` that does not depend on the control-plane host | n/a: image exported from host | n/a | n/a | ● pinned | **— (F2)** | **— (until ab2849a)** |
| 12 | Fingerprint dimensions enumerated (§7) | ● (+ allowlist, D11-3) | ● | ● (+ body) | ● | ● (+ D49/D50) | ● (+ commit, ruleset) |
| 13 | Evidence view: `untrusted_content`, bounded | ● | ● | ● | ● | ● | ● |
| 14 | Evidence sensitivity decision (redaction, first-party marker) | ○ | ○ | ○ | ○ | ○ | ● D43-4 (first time) |
| 15 | `candidate_targets` / address extraction for discovery | ○ (banner via D13) | ● | ● | ● | ○ | **○ — see F3** |
| 16 | Injection carrier test (I8) | ● D13 | ● | ● | ● D37 | ● I8 (authorization only) | **— (F3)** |
| 17 | Threat-model / decision document | design doc | acceptance doc | acceptance doc | acceptance doc + probes | ADR (D42-1…6) | ADR (D43-1…6) |
| 18 | `requires_known_classification` decision | no | **yes, D32** | (with GET) | no | no | **yes, D43-3** |
| 19 | New target type + `TARGET_TYPES` + scope guard | ○ | ○ | ○ | ○ | ● `ad_domain` | ● `repo` |
| 20 | Bespoke dispatch function | ○ | ○ | ○ | ○ | ● | ● |
| 21 | Driven through `propose_action` **into dispatch** by a committed test | ● scenario A/B | **— policy only, `_NoSandbox` (F1)** | **— policy only, `_NoSandbox` (F1)** | ● D37 | **— (D47 → D48)** | **— (D47 → D48)** |
| 22 | Candidate-list entries for what was raised and not resolved | ● | 5.8 5.9 | 5.11 5.12 | 5.14–5.17 | 5.23 | none recorded |

Rows 6, 10, 11, 16 and 21 are where an integration lacked a step that a later one
had to retrofit. Those are the checkpoints the skeleton exists to make automatic.

---

## 2. What no integration could share

These are the steps that were **different every time**, because they were answers
about the tool's data rather than code. The skeleton has no template for them and is
built not to look as though it does.

| Decision | What each tool concluded | Why it did not transfer |
|---|---|---|
| What a scope object authorizes | `ad_domain` authorizes *collection*, never *action* (D42-1); `repo` pins repo + branch, not a commit (D43-1); `cidr`/`ip` authorize the tool's reach (D6) | It depends on whether the tool's target is a place, a set, or a source of further targets |
| Containment | subdirectory containment refused (D43-2, echoing D25 §2.2's refusal for URL paths) | A policy choice with no arithmetic answer |
| Known classification as a prerequisite | `web.get` yes (D32), `code.*` yes (D43-3), `web.render`/`ad.collect`/`network.*` no | Argued independently each time; the Rego list is not derivable from the adapter |
| Evidence handling | Semgrep: redact snippets, mark first-party (D43-4); web: extract candidate addresses (D31); BloodHound: bounded summary (D42-6) | Depends on whether the content can hold a secret, name an address, or be unbounded |
| Egress model | namespace allowlist (nmap), proxy (web.*), none at all (Semgrep) | Depends on the protocol and on whether the tool needs the network at all |
| Dispatch shape | generic (`dispatch_scan`) for five, bespoke for two | Depends on whether the run needs a step before or after the sandbox |
| Credentials | mounted file, identity bound to the credential (D44, D50-B) | Depends on the tool's authentication surface |

---

## 3. The failures that found the checkpoints

Each row is a defect an integration shipped and CI or a later deliverable found.
"Skeleton" says what now catches it: **enforced** (a test over every registered
adapter, mutation-verified red), **scaffolded** (a generated test that fails until
a person writes it), **checklist** (a human step; nothing checks it), or **not
covered**.

| Defect | Found at | Skeleton |
|---|---|---|
| Image never built in CI; real-container tests fail on the runner | semgrep `8c6eb16`→`8168084`; bloodhound `79bbe99`→`203d8d6` | **enforced** (`registration_violations`) |
| `tool_version()` probed a host binary that exists only in the image → `"unknown"` | semgrep `ab2849a` | **enforced**; and the same defect found live in `ad_collector` (F2) |
| A constraint `build_plan` reads is dropped by `execution_constraints` | D37 (web port/path/scheme); D45 (ad.collect, code.scan) | **enforced**; and found live for `web.post` (F1) |
| Action mis-routed to the wrong dispatch function | D45 → D46 | **enforced** (`NEEDS_DISPATCH`, plus the pre-existing routing test) |
| Side-effect profile omitted, so a tool can under-state what it does | D34 | **enforced** |
| Evidence without `untrusted_content` | §4.4 | **enforced** (adapter smoke + the store's own refusal) |
| Evidence-id prefix missing → ids silently read `TOOL-…` | latent | **enforced** (new) |
| Fingerprint missing an input the tool reads | D11-3 (allowlist) | **scaffolded** — completeness is checked against `build_plan`'s source |
| Fingerprint missing a dimension that is *not* an adapter input (commit, ruleset hash, allowlist, credential id) | D11-3, D43-1 | **scaffolded placeholder + checklist**: no code can know what these are |
| Secret reaches a model in evidence | D43-4 | **scaffolded placeholder + checklist**: what is sensitive is a per-tool judgement |
| Tool never driven through the real entry point | D45–D48; D51 for D49/D50 | **scaffolded placeholder** |
| No injection carrier test | D13→D37 (five carriers), D22 constraints | **scaffolded**; `code.scan` had none (F3) |
| Container starts and does nothing: symlink over the interpreter, wrong doc root, dlopen'd libs not staged, stdout buffered | D31 fixes 1–5 | **checklist** (scratch-image technique; the templates cover the Dockerfile route only) |
| `ENTRYPOINT` + `command` concatenated; verifier appended to ENTRYPOINT | D34 fixes 1–2 | **checklist + template comment** |
| Cap-dropped root cannot read a `0600` file another uid owns; passed locally as uid 0, failed on the runner's uid 1001 | D35 | **checklist** |
| Fixture pinned an IP a sibling fixture also pinned | D35 fix | **checklist** |
| Self-check discarded the container's output, or the module had no `__main__` guard, or needed a positional | D36 chain | **template** (prints before gating) + **checklist** (`__main__`) |
| Tool's own network call (version check) hangs under `--network none` | D43 | **template comment + checklist** |
| Tool writes under `$HOME` with a read-only root | D36, D43 | **template comment** (`TMPFS`) |
| Test-only dependency not declared, so CI fails at collection | D49 `7f8dd87`→`79bbe99` | **not covered** |
| Classification prerequisite decided for a tool | D32, D43-3 | **checklist** (an ADR question) |
| Scope model for a tool | D42-1, D43-1/2 | **checklist** (an ADR question) |

The "not covered" row is deliberate honesty: a test dependency that CI's fresh
install does not have is a repository hygiene problem, not an adapter-contract one.

---

## 4. What the inventory itself found

Reported, not fixed. Each was verified by running code, not by reading it.

**F1 — `web.post` cannot build a plan through `propose_action`, and `web.get` has
never been shown to.**
`http_post.build_plan` raises unless `constraints["body"]` is present.
`function_api.execution_constraints` carries neither `body` nor `content_type`,
and the Worker schema has no field that could supply one. Executed:
`execution_constraints({… "body": "q=inventory", "content_type": …}, host)` returns
`{host, path, port, ports, scan_type}`, and `http_post.build_plan` on that raises
`AdapterError: web.post requires an explicit body…`. It fails closed (the proposal
is refused as unbuildable), so nothing is exposed; the tool is simply unreachable
on the real path, and whether that is intended is not recorded anywhere.
The tests do not notice because both `tests/test_web_post.py` and
`tests/test_http_get.py` call `propose_action` only with a `_NoSandbox` stub
("dispatch is not what this test measures") and stop at the policy decision, so
neither reaches `build_plan`. For `web.get` nothing is known to be broken —
`execution_constraints` carries what it reads, and it shares `dispatch_scan` with
the browser that D37 did drive end to end — but it has no test that runs it
through the entry point, and D37's own lesson is that this is where wiring gaps
hide. → ACCEPTANCE **5.29** (decided and closed after D53; see `D53_5_29_WEB_POST_BODY_ANALYSIS.md`).

**F2 — `ad_collector.tool_version()` returns `"unknown"`.** It shells out to
`bloodhound-python` on the control-plane host; the tool exists only in the
Dockerfile image (`BLOODHOUND_VERSION=1.9.0`). This is defect `ab2849a` (Semgrep,
D43), unfixed in its sibling. Consequence: a bloodhound-python upgrade cannot
change the fingerprint, so a re-collection after an upgrade can be skipped as
already done. → ACCEPTANCE **5.30**.

**F3 — `code.scan` has no injection carrier test, and one shape of the
carrier slips through D20.** Every tool that reads content a third party can
influence got a lure test (§1 row 16); Semgrep, whose evidence is source code, did
not. Writing it (`tests/test_semgrep_onboarding.py`) found that an address named in
source *is* handled, but a **repository** named in source by location alone is not:
`code.scan` accepts a target only as `<location>#<branch>`, so a Worker's proposal
always carries a `#branch` the comment never contained, and D20 compares repo
identities as opaque strings. Authorization still refuses the repo; what is missing
is the second look D20 adds for content-introduced targets. I probed the bare
location in D52 (`True`) and not the `#branch` form, which is the only form that
runs — a miss in D52's own probe, not something D52 could have known. → ACCEPTANCE
**5.31** (closed after D53, `178c9e1`).

**F4 — `EVIDENCE_PREFIX` was an unenforced registration point.** A tool with no
entry silently got `TOOL-…` evidence ids. Cosmetic, but the same shape as the
others: a place a new tool had to be added, that nothing checked. Now enforced.

---

## 5. What follows

`docs/NEW_TOOL_ONBOARDING.md` is the operating procedure built from §1–§3.
`tests/adapter_kit.py` and `tests/test_adapter_contract.py` are the "enforced"
rows; `scripts/new_tool_scaffold.py` and its templates are the "scaffolded" ones.
The replay against Semgrep, including how much it saves and what it does not,
is `docs/D53_SKELETON_REPLAY_SEMGREP.md`.
