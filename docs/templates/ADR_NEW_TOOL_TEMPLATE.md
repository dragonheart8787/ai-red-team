# ADR: {{NAME}} — Phase 1 investigation (Dnn)

Status: **proposed. Awaiting a decision before any implementation.** No adapter,
schema, Rego or CI change is made until the decisions in §5 are answered.

> **How to use this template.** Copy it to `docs/ADR_<TOOL>.md` *before* writing
> adapter code (`docs/NEW_TOOL_ONBOARDING.md` §1). It is a worksheet, not a form:
> every "Question" is one the previous integrations had to answer by thinking
> about that tool's data, and every "Precedent" is the answer that was reached
> for a different tool. **A precedent is a consistency constraint, not an
> answer.** "Semgrep did X" is a reason to check whether X holds here, never a
> reason to do X. Delete guidance as you fill each section; leave a section
> visibly empty only with a reason.
>
> Nothing in `scripts/new_tool_scaffold.py` or `tests/adapter_kit.py` answers any
> of this for you, and neither is meant to. Their job starts after this document
> is decided.

Every claim about the current system is to be checked against the tree at the
time of writing (record the commit), not assumed from a brief or from memory.
D45 and D51 each found that a claim written from memory was false.

---

## 0. What the tool is, and what it is not

* What does it do, in one sentence, and to what? Name the exact binary/library
  and version you are pinning (the pin becomes `tool_version`).
* What is the smallest version of this integration that is useful? Everything
  outside it is a candidate-list entry (§6), not scope.
* Is it read-only against its target? **Read the built command's verbs**, not
  the tool's description (D34: `web.post` ended the argument that "web.* only
  reads").

## 1. Scope model — what does authorizing a target mean?

| Question | Precedent to stay consistent with |
|---|---|
| What is the target's **identity type**? An existing one (`ip`, `cidr`, `fqdn`, `url`), or a new one? | `ad_domain` (D42-1) and `repo` (D43) each needed a new type; check `worker_base.TARGET_TYPES`, `canonicalizer/target.py`, `scope_registry` guards. |
| What does a scope object for it **authorize**: acting on the target, or only collecting from it? | D42-1: an `ad_domain` scope authorizes *collection*, never *action against what collection discovers* (I8). |
| **Precision.** Does authorizing the target pin a version/ref/path, or the mutable name? | D43-1: a repo scope pins repo + branch; the resolved commit is a fingerprint dimension either way. |
| **Containment.** Is "a part of the target" a thing you can authorize? | D43-2 refused subdirectory containment (matches D25 §2.2's refusal for URL paths). Refusing is a legitimate answer. |
| How big can one run be? Does I3's `max_targets` mean anything for it? | D42 §1.2: `ad_domain` has no notion of "how big is this domain". |

## 2. Authorization and classification

* Does `<action>` need a **known classification** as a prerequisite
  (`requires_known_classification`)? Argue it for this tool independently. The rule keys
  on the action's **spelling**, so the name you gave the action is part of the answer: state
  it as `KNOWN_CLASSIFICATION` in the adapter (`"required"` / `"exempt: <reason>"`), and the
  check compares it with the rule (D56). A name that silently skips the gate is a decision
  you have to have made.
  Precedent: `web.get` joined (D32: a GET is no more lenient than a POST on the
  same resource); `code.*` joined (D43-3, argued separately); `web.render`,
  `ad.collect` and `network.*` did not.
* What do `WRITES_DATA` / `CHANGES_STATE` say, and what does the built command
  actually do? The registry looks them up **from the action**, so a Worker
  cannot claim less (D34).
* Is there an approval path a human must see? What in the tool's output could
  make the Reviewer under- or over-estimate risk (D10.5's `risk_hint` split)?

## 3. Evidence — what does a model read, and what must it not?

Answer each; the answers become `derive_view`.

1. **Is the output third-party content?** (Almost always yes: `untrusted_content:
   true` is enforced by the evidence store at write time.) Could an attacker who
   controls the target's data place text in it? *That field is your injection
   carrier (§4).*
2. **Can it contain a secret the reader must not see?** If yes: redact before the
   content leaves the adapter, and write the negative control that proves the
   redaction (not the input) is what removed it (D43-4). Distinguish
   *"is this true"* (`untrusted_content`) from *"should this be seen in full"*
   (`first_party_source_content`) — two axes, never collapsed.
3. **Is it unbounded?** Cap what a model sees; keep the full artifact raw (§4.4).
   D40 hit the OS argv limit at three evidence artifacts (ACCEPTANCE 5.21).
4. **Does it name addresses?** Then extract them **for discovery only** — computed
   by the harness, never by the agent (D20) — and note that being listed
   authorizes nothing.
5. **Truncation rule.** Where you cut, and why cutting there is not itself an
   information leak or an omission that hides a finding (D43-4's rule).

## 4. The threat model — the injection carrier and the confinement

* **The carrier.** Five rounds so far, each closer to production content:
  nmap banner (D13), look-alike scope object (D15), served GET body (D31), POST
  reply generated in reaction to our input (D34), DOM node inserted by runtime
  JavaScript (D37); a fabricated graph edge for BloodHound (D42 I8). `code.scan`
  has none (found at D53). **What is this tool's?** Write the payload, and state
  the property that must hold: *an address the system did not already authorize
  cannot gain authorization by being mentioned in content it read* (I8).
* **Egress.** Does the tool need the network? Through the proxy (HTTP, D34), the
  namespace allowlist (raw TCP, D6), or none (D43-5: inputs mounted read-only from
  outside; the container is given no route at all)? Fewer routes is stronger.
* **What can the tool do if it is fully compromised?** Read the sandbox flags in
  `tool_gateway/sandbox.py` (cap-dropped, read-only root, no-new-privileges, pid
  and memory limits) and say what remains. This is the blast radius, stated like
  ADR_CREDENTIAL_VAULT §2.2.
* **Credentials.** If it needs one: mounted file only, never argv or env
  (D44, D50); identity bound to the credential (D50-B); and say what the process
  table and host temp file expose (ACCEPTANCE 5.26).

## 5. Tool Gateway integration

* **Dispatch shape.** Fits `dispatch_scan` (one target, run, record)? Or needs a
  step before/after the sandbox (D42's graph write, D43's control-plane fetch and
  cleanup)? A tool routed through the wrong dispatch function starts with nothing
  mounted (D45).
* **Image.** Own Dockerfile (pin, manifest, non-root, self-check) or exported
  from the host (nmap)? What does the tool write under `$HOME`/`/tmp` (→ `TMPFS`)?
  What does it try to do on its own initiative that will hang under
  `--network none` (version check, telemetry, registry fetch)?
* **Fingerprint (§7).** List **every** input that changes what the tool does or
  sees, and where each lives: `normalized_target`, `as_params`, `tool_version`,
  `ruleset_version`, `execution_context`. State explicitly what is *excluded* and
  why (budget: a change is not a different scan). A missing dimension makes the
  system skip a scan it should have run (D11-3). Non-adapter dimensions (a commit
  SHA, a ruleset hash, the allowlist, a credential id) are the ones forgotten.
* **Entry point.** How will this action be driven through `propose_action`, the
  one real entry point? (D45/D47/D48: none of D42's or D43's layers had been.)

## 6. Decisions needing your sign-off

| # | Decision | Options on the table | This document's lean |
|---|---|---|---|
| **Dnn-1** | Scope model | | |
| **Dnn-2** | Known classification | | |
| **Dnn-3** | Evidence handling (redaction / truncation) | | |
| **Dnn-4** | Egress model | | |
| **Dnn-5** | Dispatch shape | | |
| **Dnn-6** | Fingerprint dimensions | | |

Record anything raised and *not* resolved as a candidate item in
`docs/ACCEPTANCE_MVP1_AGENTS.md` (class A/B/C), including the honest limits
("verified by tests only; no production harness builds this tool's `Observation`
yet", 5.28).

## 7. What this document does not do

State what was **not** verified, exactly as ADR_SEMGREP §5 and ADR_CREDENTIAL_VAULT
§6 do: which flags remain unchecked against the real binary, which behaviour was
inferred from documentation, what was not run.
