# ACCEPTANCE 5.29 — carrying a `web.post` body: what D43-4's redaction can and cannot do

**Status: decided and implemented (option C) — see section 6.** Sections 1–5 are the
investigation as it was put to the decision-maker, left unchanged: the verification
results, and the options with their trade-offs. Everything under "Verified" was
executed or read in the code named, not recalled.

## 1. The question

`web.post` cannot be reached through `propose_action` today: `function_api.execution_constraints`
does not carry `body`/`content_type`, so `http_post.build_plan` raises and the capability
is refused as unbuildable (fails closed). Before deciding *how* a proposal carries a
body, D53's closeout asked whether D43-4's sensitive-content mechanism (truncation rule,
`first_party_source_content`) can or should apply to a body, because a Worker-authored body
may contain test credentials it generated itself — the same shape of problem Semgrep had.

## 2. Verified

**2.1 The marker is a label with no consumer.** `first_party_source_content` is produced
in exactly one place (`semgrep.derive_view`). Nothing in `control_plane/`, `agents/` or
`tool_gateway/` reads it. (`untrusted_content`, by contrast, is enforced:
`evidence/store.py:77` refuses a derived view without it.) So "reusing the marker" would
reuse a *declaration*; the behaviour D43-4 actually has is `redact_snippet` applied at the
one place Semgrep builds its snippets, plus the decision that its evidence is shown
redacted by default.

**2.2 `redact_snippet` does not fit a body's shape.** Run through the real function
(`control_plane/evidence/redaction.py`) on realistic bodies:

| Body shape | Secret survives | Pattern that fired |
|---|---|---|
| urlencoded `user=a&password=…` | **yes** | none |
| urlencoded `api_key=…` | **yes** | none |
| JSON `{"password":"…"}` compact | **yes** | none |
| JSON pretty-printed | **yes** | none |
| code-shaped `password = "…"` | no | credential-assignment |
| bearer / AWS key / JWT / credential-in-URL inside a body | no | token patterns |
| secret beyond column 160 on one line | no — **but only because the line was cut** | length-cap |

The rules were written for source code (quoted assignment, token shapes). The two body
formats the adapter accepts by allowlist (`x-www-form-urlencoded`, `application/json`)
are exactly the ones the assignment rule does not match. The 160-column cap is a
backstop that hides a secret incidentally, and it truncates a single-line body, so the
result is no longer the body that was sent.

**2.3 Truncation cannot apply to what is executed or approved.** D30's rule is that the
approval record describes exactly what was authorized. A redacted or truncated body on
the approval, or the executed request, would make the reviewer approve something other
than what is sent. Redaction is admissible only on surfaces that *display* the body, never
on the value that is approved, fingerprinted, or sent.

**2.4 Where a carried body would land** (traced through the code, if `execution_constraints`
carried it as it does `port`/`path`/`exclude_paths`):

| Surface | Gets the body? | Note |
|---|---|---|
| `action_proposals.target` (jsonb) | yes, plaintext | `_persist_proposal` stores `{**proposal.target, **canonical}` |
| Reviewer LLM prompt | yes | `reviewer_base.build_prompt` puts `proposal.target` verbatim in `target_as_proposed` |
| Pending-approvals queue / approval preview | yes | `list_pending` returns `target`; §4.7 record's `constraints` carries it — this one is **required** (D30) |
| Capability constraints | yes | the body is the capability |
| `tool_runs.normalized_params` | yes, plaintext | `plan.as_params()["body"]` — deliberately in the fingerprint (two bodies are two actions) |
| Execution fingerprint | hashed | fine |
| `tool_run.started` audit payload | **no** | payload has `command`, not `stdin`; `dispatch.py:424` documents this |
| Evidence raw blob | **no** | raw is `command` + stdout/stderr; the body is on stdin |
| Response derived view | no (it is the *reply*) | already `untrusted_content`; D34 |

So the exposure is not the evidence pipeline D43-4 protects. It is the **request side**:
the proposal, its DB row, the reviewer prompt, the approval record and `normalized_params`.
D43-4's mechanism is an evidence-side control and does not touch any of them.

**2.5 Who writes the body.** The body is authored by the Worker (a model), not read from
the target — `http_post` refuses target-derived bodies by design (I8 inverted). The
"sensitive test data" in question is therefore *the Worker's own invention* (fake
credentials for a login probe), not customer data. That is a weaker confidentiality
concern than Semgrep's (real secrets in a customer repo), and it is where the
comparison to D43-4 partly fails: nothing here is a customer secret unless the Worker was
handed one, and the only sanctioned way to hand a Worker a credential is the D44 vault,
which exists so a credential never appears in a proposal.

## 3. Options

**A — Carry the body inline; extend and reuse the redactor on display surfaces only.**
Add `body`/`content_type` to `execution_constraints`; the approval record shows it in full.
For the reviewer prompt, queue and logs, run a body-aware redactor (a new
form/JSON-key rule set alongside `redact_snippet`).
*For:* the smallest change; the reviewer and human see the real body. *Against:* the
redactor is new work, not reuse (§2.2) and heuristic — a miss leaks into the reviewer
prompt and DB; plaintext still lands in `action_proposals.target` and `normalized_params`
(§2.4), which redaction on "display" does not cover; two representations of one body to
keep consistent (the D25/D30 "one fact, one source" concern).

**B — Carry the body by reference, the way D44 carries credentials.** The Worker never
puts a body in a proposal; it names a stored, content-addressed body (or a credential
reference for the secret fields). The approval shows the resolved body; the fingerprint
uses its hash.
*For:* the sensitive material is outside every §2.4 surface by construction; reuses D44's
pattern and its audit/cleanup discipline rather than a pattern-matcher. *Against:* needs
a way to author and store bodies (a new write path and table or vault use), so the Worker
loses the ability to compose a body in one step; the biggest change; only worth it if
bodies routinely carry real secrets, which §2.5 suggests they need not.

**C — Carry the body inline, unredacted, with existing limits; make the plain exposure
explicit.** Carry `body`/`content_type` (already bounded by 64,000 bytes and the content
type allowlist), show it in full everywhere, and state in the ADR that a body is
Worker-authored, non-secret by policy, and that a secret belongs in the D44 vault, not in a
body. Add the propose-time refusal of a body matching the existing token patterns
(`redact_snippet(...).patterns_matched` non-empty → refuse), which reuses the *detector*
without redacting anything.
*For:* simplest; approval/execution/fingerprint stay identical and truthful; the
reused detector catches the high-confidence cases (§2.2's bottom four rows) as a refusal
rather than a rewrite. *Against:* misses form/JSON secrets (§2.2 top rows) — they would be
in the reviewer prompt and `normalized_params`; relies on the "no real secrets in bodies"
policy, which nothing enforces for those shapes.

**D — A closed template model.** The Worker selects a template and fills declared fields
(`login`, `search`), each field typed; free-form bodies are not allowed.
*For:* removes the free-form body, so most of the problem. *Against:* the largest design
surface, and it narrows web.post to what the templates cover — a change to what the tool is.

## 4. What I would want decided (not decided here)

1. Are Worker-authored bodies allowed to contain *real* secrets, or only fabricated test
   values? If "only fabricated", C is enough and the answer to the D43-4 question is
   "no — different threat, and the mechanism doesn't fit"; if "real", B (D44 pattern) is the
   direction and A/C are unsafe.
2. Is a reviewer LLM allowed to see the body? Today it would (§2.4). That is the surface
   with no analogue in D43-4.
3. Only after that, whether this warrants the full ADR-gate process. The two facts that
   make it heavier than a typing fix: it is a new model-influenced field on a
   `changes_state` action, and the approval record must describe it (D30).

**Independent of the decision:** the `web.get` half of 5.29 (no committed test drives
it through `propose_action` into dispatch) needs no design decision and can be closed on
its own.

## 5. What this note does not do

It does not change `redaction.py`, `execution_constraints`, or the Worker schema. It does
not claim the option ranking is settled; the recommendation, if asked for one, is that
question 1 decides between C and B and that A is the weakest (a heuristic display filter
in front of plaintext storage).

---

## 6. Decision and implementation (option C)

**Decided:** a Worker-authored body is *constructed test data only* and never a real
secret. This continues the trust model of `ADR_CREDENTIAL_VAULT.md` section 0 — the
vault is the one mechanism approved to bring a real secret into an execution path — and
is not a new principle. Option B (by reference) would create a second secret entry point,
against "one fact, one authoritative source"; A and D were excluded in section 3. The
reviewer LLM keeps seeing the body: once a body cannot hold a real secret, judging what a
proposal would send is part of its job, and D44's "no LLM should see a secret" concern
does not apply.

**Implemented:**

1. `function_api.execution_constraints` carries `body` and `content_type` (the bug the D53
   report named), unmodified — never redacted or truncated (section 2.3).
2. `propose_action` refuses, at step 1b **before `_persist_proposal`**, a body that
   (a) the adapter would refuse (not a string, over `MAX_REQUEST_BODY_BYTES`, content type
   outside the allowlist), or (b) matches a known secret **format**. Refused, not masked.
   The audit record names the formats found and never the value; the reviewer is not shown
   the proposal; no proposal row, capability or run exists. A proposal that names no body
   is unchanged (still unbuildable at dispatch).
3. The detector is `redaction.detect_secret_formats`, which reads the *same*
   `_WHOLE_MATCH_PATTERNS` list `redact_snippet` masks (`KNOWN_SECRET_FORMATS`): AWS access
   key id, PEM private key, JWT-shaped token, bearer token, credential in a URL.
   A body is checked both as sent and percent-decoded, because `Bearer%20<token>` in a
   form-encoded body is the same token.
4. Deliberately **not** refused: the name-based `credential-assignment` heuristic and the
   `length-cap`. The first cannot tell a constructed `password=hunter2` from a real one and
   flags any variable so named; the second is a display backstop. Refusing either would
   reject ordinary forms and JSON, which is the over-defence the decision excluded.
   Consequently `password=Test1234` in a form field and `{"password": "hunter2"}` pass —
   which is the intended use of a constructed value.

**The vault question (checked before implementing).** Could a POST that needs a real
credential reference a vault `credential_id`, resolved control-plane-side and composed
into the body at dispatch, with the Worker handling only the id? Result: **not with the
interface as it is.** The capability side is generic (`credential_id` is issued, checked
for revocation and cascaded for any action), but `dispatch_scan` never reads it, the vault
has no credential type for it (`CREDENTIAL_TYPES`, plus a DB `CHECK`), and both delivery
modes are ruled out (`material_for` must never reach a sandbox; `mount_for_run` refuses
all but `ad_domain_bind`, and delivers a file, not stdin). It is a **new delivery mode**,
which `ADR_CREDENTIAL_VAULT.md` requires be decided in that document. Recorded there as
section 9; pinned by a test. So the honest wording is: *a POST that needs a real
credential is not supported today; the route is a D44 extension, not something this
change provides* — not "handled by D44".

**Known limits, stated rather than glossed.** The detector recognises a fixed set of
shapes: a secret in no known format (a bare hex API key, a password in JSON) passes, as the
redactor's own docstring says of itself. Percent-decoding is the only normalisation; a
secret hidden by base64, JSON `\uXXXX` escapes or splitting across fields is not caught.
The decision rests on the policy (bodies are constructed values) more than on the detector,
which is a guard against a Worker that is handed or invents a well-known secret shape, not
a proof that none is present.

**Follow-ups recorded (not worked).** The four vault-extension decisions (credential
type, delivery mode, approval wording, reply echo) are ACCEPTANCE **5.32**; the standing
caveat that the detector is a guard and the policy is the guarantee is **5.33**; a
real-container test for `web.get`/`web.post` over the egress proxy is **5.34**.
