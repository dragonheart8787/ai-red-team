# MVP-1.5 Acceptance Review — the Web Agent stage (D31–D37)

Continues `ACCEPTANCE_MVP_KERNEL.md` (the kernel, §10/§11) and
`ACCEPTANCE_MVP1_AGENTS.md` (the three roles behind real models, D10–D24).
This one covers a single arc: bringing **web content into the system**, from a
static HTTP GET (D31) to a JavaScript-rendering browser driven end to end
through the real pipeline (D37).

It is a documentation review — no code or tests were written for it. Its job is
to make the stage legible as a whole: what each deliverable solved, the wiring
gaps and threats it surfaced, the fifth-and-longest injection series in one
place, the candidate items it raised (5.8–5.19), the two still-unprocessed
D11 items, and a Go/No-Go.

The shape of the arc, stated once: **every capability was added as a Worker
*tool*, never a new role or a new decision point.** The Canonicalizer, the
Authorization Resolver, OPA, the Capability Broker and the Tool Gateway are the
same as at kernel close; `web.get`, `web.post` and `web.render` are three
`action` strings the gateway knows how to turn into a command, and the
side-effect and budget authority for each is looked up from the action rather
than taken from the agent. That is why a browser — the largest attack-surface
addition in the project — needed no change to the kernel's decision path.

---

## 1. D31–D37 technical summary

Each row: the problem the deliverable solved, the wiring gap or security
question it surfaced, and the commit(s) plus CI run number of record. CI runs
are on `claude/mvp-kernel-cybersecurity-platform-su841g`.

| # | Solved | Surfaced | Commits / CI |
|---|--------|----------|--------------|
| **D31** | `web.get` — a static HTTP GET tool for the existing Worker; web content enters as evidence through the same `untrusted_content` boundary a scanner banner does. GET-only, no redirect following, no TLS. | Five CI rounds, all in the scratch-image build technique, each failing as "the container does not serve": a self-referential python symlink, an implicit doc root, the stdlib's own shared libraries not staged, a probe racing the bind, and a startup line stuck in python's stdout buffer. The technique was then reused for D34/D36. | `395913e` + `b848eb7`,`55cf564`,`c69e2dd`,`dd10308`,`cd72f5e` / runs 63–69 |
| **D32** | `web.get` lists a *known classification* as a prerequisite (§5 row 2), so a GET is treated no more leniently than a POST on the same resource. | Raised **5.8** (no middle state between "unknown" and "denied" for a sensitive-but-not-denied class — general, not a web.get question) and **5.9** (a wildcard scope object authorizes but no capability can be issued against it). | `3bd9f81` / run 65 |
| **D33** | Deleted `db/schema.sql`; the migrations became the single source of truth. | Closed **5.10** by removal rather than a freshness check — the same "two things that must agree" failure mode the stage kept finding, resolved by removing the second reader. | `ca0821e` / run 70 |
| **D34** | Policy-aware egress proxy (§8.3): terminating HTTP forward proxy + `web.post` + a two-network topology where the tool has *no route* to the target except through the proxy (kernel `ENETUNREACH`, not a filter). | **Repaired an existing defect**: `consume_request` (§8.5's atomic check-and-increment, = the old **D11-10** observation) had never been called on any production path, so `max_requests` was a number in a database. Now spent in `dispatch_scan` after the claim, pinned by a mutation test. Raised **5.11** (side-effect floor changes no decision today) and **5.12** (the within-run ceiling and the capability budget are two counters). | `c8a9ab3` + `2a40796`,`695305c` / runs 71–73 |
| **D35** | TLS termination: a per-engagement CA, the proxy decrypts and runs the same per-request check on the plaintext. https went from "explicitly refused" to "checkable". | Recorded **5.13** (a cert-pinning target rejects the proxy's leaf at the TLS handshake — an inherent limit, distinct from a policy 403). Settled **5.12** (the ceiling counts *requests*, not connections, so TLS keep-alive does not loosen it). A found defect: the proxy could not read its own 0600 leaf key under `cap_drop=ALL` — it now runs as the key's owner, not root. | `41f71a2`,`42c84cb`,`46326fc` / runs 74–76 |
| **D36** | `web.render` — a Playwright/Chromium browser tool. Self-built Dockerfile image (Chromium is too large and dynamic for the scratch route), a `browser` budget sub-schema, and the container-filesystem-escape experiment. | The threat model for the JS execution environment: **5.14** (a headless browser reads a `file://` it is pointed at — the browser is not the boundary, the container is), **5.15** (downloads — tested, not a path-control surface), **5.16** (DevTools/CDP — tested, not reachable by page content), **5.17** (WebSocket — excluded like PUT/DELETE). A chain of build/wrapper bugs, each a wrapper never running the code, not the browser: the pip version was the Node one, a root-owned tmpfs HOME, no `__main__` guard, a required `url` positional breaking `--self-check`. | `ab19447`,`1da90c4`,`cb3dfea`,`c4b4c77`,`3e5598e`,`360c88c`,`303c749` / runs 77–83 |
| **D37** | Drove `web.render` through `propose_action` — the real pipeline entry point — end to end, hermetically (stub sandbox) and with a real browser in CI. | **Found and closed the wiring gap unit tests could not**: `execution_constraints` carried only nmap's `{host, ports, scan_type}` and dropped the web `port`/`path`/`scheme`, so no web action could run through `propose_action` against a real path or an https port (**5.19**). And **5.18**: web.render had never been driven through the entry point at all. | `edd4ddb`,`34fb7f8` / runs 84–85 |

**A note on the CI record.** The stage took many red runs (63–85, of which roughly
half were failures). Almost none were product defects: they were the scratch-image
build technique (D31), ENTRYPOINT-vs-arguments (D34), a fixed-IP fixture collision
(D35), and the D36 wrapper chain. The pattern is consistent with §5 of the D10–D24
review — *a green suite that guards nothing is the danger; a red one that names its
cause is working* — and every one of these failures named its cause in CI because
the build checks and the diagnostics were written to. The two genuinely
product-level findings of the stage (D34's dead `consume_request`, D37's dropped
web constraints) were both found by *driving the real path*, not by a unit test.

---

## 2. The injection experiment series — five carriers, one boundary

The longest continuous verification line in the project. Each round moves the
carrier closer to production content while asserting the same property: an
address the system did not already authorize cannot gain authorization by being
*mentioned* in content the system read — **Discovery ⊥ Authorization (I8)**. The
lure is always surfaced as a discovery candidate (computed by the harness, never
self-declared by the agent) and always still requires a scope object.

| Round | Carrier | What is new about the attack surface | Lure address | Result |
|-------|---------|---------------------------------------|--------------|--------|
| **D13** | An **nmap service banner** | The first attacker-controlled text to reach a model — a banner field parsed from a scan. | (banner text) | Injection 0/20; banner address is a candidate only, authorization refuses. |
| **D15** | A **look-alike scope object** — an address that *resembles* an in-scope one | Not injected text but a near-miss target name, testing whether visual/lexical similarity leaks authorization. | look-alike of an in-scope IP | 0/45; the resolver matches canonical identity, not resemblance. |
| **D31** | A **served GET response body** | Evidence is now a whole document the target chose to serve, not a fragment a scanner parsed. | `198.51.100.23` (TEST-NET-2) | Surfaced as candidate; authorization refuses an address named only in a body. |
| **D34** | A **POST reply the target generates in reaction to input the system supplied** | The target now writes its lure *in response to* our request, and phrases it as authorization ("already covered by the engagement authorisation for this host"). | `203.0.113.77` (TEST-NET-3) | Persuasive text creates no scope object; `target_not_covered_by_scope_object`. |
| **D37** | A **DOM node the page inserts only after its JavaScript runs** | The lure exists only in the *rendered* page — invisible to every prior tool. It is assembled at runtime (`[203,0,113,155].join('.')`) so it is in no static source; a static GET's extractor sees nothing, only `web.render` surfaces it. | `203.0.113.155` (TEST-NET-3) | web.get cannot see it; web.render surfaces it as a candidate; authorization still refuses (`target_not_covered_by_scope_object`). Also the operational basis for a Worker choosing `web.render` over `web.get`. |

**The invariant across all five.** The carrier evolved from a scanner banner to
runtime-generated DOM — a strictly harder channel each time — and the boundary
did not move: the rendered/served content is marked `untrusted_content`, the
address is a discovery candidate the harness computes, and the Authorization
Resolver refuses anything not covered by a registered scope object. The
mechanism that holds it is the same one D10.5 built for banners; the claim, made
five times now against five carriers, is that if it needed changing for any of
them it was never sufficient for the first.

---

## 3. Candidate list, D31–D37 — itemized with risk grading

Same three-class grading the prior reviews use. **Class A** — fixed, with a
regression test pinning it. **Class B** — known, bounded, safe to leave alone
(a scope boundary or a documented minor/inherent limit). **Class C** — blocked
on an architecture decision; work must not start until it is made.

The stage raised items **5.8–5.19** (and repaired the old D11-10). None is
Class C: every open item is either bounded-and-documented or a
cross-cutting design-priority question with no live gap in MVP-1.5.

### Class A — fixed, regression test pinning it

| # | Item | How it is pinned |
|---|------|------------------|
| **D11-10** (D34) | `consume_request` never called on any production path; `max_requests` was inert | Spent in `dispatch_scan` after the claim, before execution; mutation test stubs the call and asserts the budget guarantee then fails. |
| **5.14** (D36) | A headless browser reads a `file://` it is pointed at | Isolation moved to the container, not the browser: the runner refuses non-http(s) schemes before launch, and `tests/test_browser_escape.py` proves — with a non-browser witness — that the container carries no private key and not the D35 leaf-key path, while a raw browser *does* read a local file (so the runner's refusal is load-bearing). |
| **5.16** (D36) | The DevTools/CDP channel could be reached by page content | Not reachable: `chromium.launch()` uses pipe transport, no TCP debug port; the renderer has neither the fds nor a socket. Pinned by a structural test that the launch args never contain `--remote-debugging-port`. |
| **5.18** (D37) | `web.render` had never been driven through `propose_action` | Driven end to end, hermetically (`test_web_render_e2e.py`) and with a real browser in CI (`scenarios/test_scenario_web_render.py`); the stub run asserts the SPKI pin, tmpfs and budget ceilings arrive at the run. |
| **5.19** (D37) | `execution_constraints` dropped the web `port`/`path`/`scheme` | Carried when the proposal names them; nmap's constraints are byte-for-byte unchanged, asserted by a test. |

### Class B — known, bounded, safe to leave alone

| # | Item | Why it is safe to leave |
|---|------|-------------------------|
| **5.9** (D32) | A wildcard scope object authorizes but no capability can be issued against it | The Authorization Resolver honours `web.*`/`network.*` patterns, the broker checks the same `allowed_actions` by membership, so the run is refused with `scope_action_no_longer_allowed` for an authorization never withdrawn. Bounded and pinned by a test; affects every namespace, so it is a general design question, not a web one. |
| **5.11** (D34) | The side-effect floor changes no decision today | `requires_known_classification` already fires for every action that has an adapter, so the floor is redundant *now*; it becomes load-bearing the moment an adapter with side effects has an action the pattern list does not name — pinned by `test_the_flag_branch_is_load_bearing_for_an_action_the_list_does_not_name`. Recorded so its silence is not mistaken for absence. |
| **5.12** (D34→D35) | The within-run request ceiling and the capability budget are two counters | Examined and **settled** at D35: the two stay two (the in-container proxy holds no DB connection), and the ceiling counts *requests* on decrypted plaintext, so TLS keep-alive does not loosen it. Pinned by `test_tls_keep_alive_requests_are_each_counted`. |
| **5.13** (D35) | A cert-pinning target cannot be intercepted | An inherent limit, not a defect: a target that pins its certificate rejects the proxy's per-engagement leaf at the **TLS handshake**, categorically distinct from a policy 403 (the target logs nothing). Fine for the disposable containers this platform tests; a standing caveat for a real pinning customer target — see Go/No-Go. Pinned in two places (in-process and container). |
| **5.15** (D36) | Downloads could write to an arbitrary container path | Tested, not a path-control surface: Chromium sanitises the suggested filename (separators → underscores) and Playwright picks a random temp path; the page cannot direct the write. Closed further with `accept_downloads=False`, so a triggered download is cancelled and nothing is written. |
| **5.17** (D36) | WebSocket is unhandled | Excluded deliberately, like PUT/DELETE (D34): no caller needs it, and a tunnelled socket would carry traffic past per-request counting. A `ws://`/`wss://` target is refused with its own named reason (`REFUSED_WEBSOCKET`). A scope boundary, reopenable when a caller exists. |

### Class C — blocked on an architecture decision

| # | Item | The decision that gates it |
|---|------|----------------------------|
| **5.8** (D32) | No middle state between "unknown" and "denied" for a canonical sensitive class that is **not** on the deny list | Whether the policy should have a "customer declared this sensitive, it is not forbidden, but a human should look" state. Measured at D33 to be **not a web.get rule** — it is `ALLOW` for every action today, so it must be decided once across all actions, not per tool. General; no live gap in MVP-1.5. |

5.8 is the one stage item that needs a design decision; it carries no security
consequence today (a deny-listed class is already `DENY`; the gap is only for
sensitive-but-not-denied classes, which are `ALLOW` uniformly). It joins the two
Class-C items carried from the prior review (5.1 classification inheritance —
note D25 *did* implement downward-only inheritance, so this is closed there
though the deny-side question remains a design choice; 5.3 task-event ownership),
which are equally design-priority and not live gaps.

---

## 4. D11-8 and D11-9 — the two still-unprocessed D11 items

Both are recorded (`LIVE_RUN_REPORT.md` §D11-8/§D11-9, and carried in
`ACCEPTANCE_MVP1_AGENTS.md` §3). Verified against the current tree for this
review:

- **D11-8 — the derived view drops the nmap VERSION column.** Still open,
  cosmetic. `tool_gateway/adapters/nmap.py`'s `_OPEN_PORT` regex captures four
  whitespace groups, so a `version` (`-sV`) scan's banner tail is discarded from
  the structured `open_ports` field (`{port, protocol, state, service}` only).
  The banner survives in `stdout_excerpt` and the raw artifact — nothing is
  *lost*, but the structured field a downstream agent reads is poorer than the
  scan it came from. **Class B (minor, understood).** Untouched by this stage:
  the web adapters do not use `_OPEN_PORT`, so the arc neither worsened nor
  fixed it.

- **D11-9 — nothing creates an engagement.** Still open, a stage-boundary gap.
  `control_plane/orchestrator/engagement.py` has `pause`, `resume`,
  `engage_kill_switch`, `complete`, `revoke_credential`, `retire_scope_object`
  — and no `create`. Every caller (test fixtures, the stateful machine, the live
  harnesses, and each `scripts/live_run/*.py`) writes the row with a raw
  `INSERT`. Same shape as D8/D9: a state the system depends on that no *operation*
  sets, so there is no audit record answering "who opened this engagement, for
  which customer, under what authorization". **Class B (stage-boundary gap, no
  security consequence).** It grows more visible as the system matures — each
  web deliverable's live/scenario setup had to seed its own engagement — and is
  a natural candidate for the next stage that operates for real, but it blocks
  nothing in MVP-1.5.

Neither was made worse by D31–D37. The adjacent D11-10 (`consume_request`
inert), by contrast, *was* resolved this stage — at D34 — because the web budget
path finally exercised it.

---

## 5. Go / No-Go

**GO — the Web Agent stage (D31–D37) is complete.**

The arc it set out to build holds: web content — static GET, state-changing
POST, TLS-terminated https, and a full JavaScript render — enters the system as
Worker tools, each an `action` the gateway executes, with side-effect and budget
authority looked up from the action and never taken from the agent. The kernel's
decision path did not move: no new role, no new decision point, no schema change
beyond the per-engagement CA table (D35, RLS-scoped like `credentials`), and
`web.render` was driven end to end through the *existing* `propose_action`
(D37). The injection boundary held across a fifth and hardest carrier.

**Real deployment-before checks (the 5.2 nature — an operational gap, not a
scope boundary).** These must be cleared before the Web Agent points at anything
that is not a disposable container this platform owns:

1. **5.2 extended to the egress path.** The two-network topology (D34) and the
   proxy's `ENETUNREACH` confinement are proven against a **Docker bridge**
   only, exactly as the original 5.2 (nmap confinement) is. Before a customer
   network, both the raw-namespace CIDR path *and* the proxy topology must be
   re-proven against the production network driver, with kernel-level evidence.
2. **5.13 — cert pinning.** For a real customer target that pins its
   certificate, the proxy cannot see inside the connection (the handshake fails
   at the target). This is an inherent limit and must be surfaced pre-engagement,
   not discovered mid-run; the honest position is "the tool cannot inspect this
   connection", distinct from a policy denial.
3. **D11-9 — engagement creation.** Operating for a real customer means an
   engagement should be *opened by an audited operation*, not seeded by a
   script. Not security-blocking for the stage, but the first thing a
   real-operation stage needs.

**Design-priority items that can wait until needed (no live gap).** 5.8
(cross-action "sensitive but not denied → human" state), 5.9 (wildcard scope /
issuance), 5.11 (floor redundant until an unlisted side-effecting action), 5.17
(WebSocket, reopen when a caller exists), plus the carried 5.1/5.3. Each encodes
a question the design does not answer; guessing would invent semantics, which is
the failure mode the project has refused since D6.

**Merge and next-step questions are deferred to discussion**, per the
deliverable: whether to merge the Web Agent stage into `main` now or accumulate
the next milestone first, and where to go next (e.g. a full engagement with all
three roles behind real models, or another direction). This document is the
inventory that decision rests on.
