# ADR: the goal-laundering channel — where untrusted text could reach the Supervisor

Status: **investigation, D22. No code change.** Produced to answer whether
`DEFERRED_MVP0.md` §11.4 has a *live* exposure path today, and to leave a
binding rule for whoever later widens what the Supervisor may read. Whether a
second (implementation) step follows is the reader's call once this is reviewed.

Scope: this traces the two interfaces D17 added for the Supervisor —
`query_state()` and `query_findings()` — field by field, back to the source of
each field's content. It does not re-open the *downstream* half of §11.4 (a
Supervisor goal landing on the Worker's trusted side); D17 recorded that and
ruled out the wrong fix (wrapping the Supervisor's own output). The question
here is the upstream one the brief names: **can the state a Supervisor reads
carry attacker-controlled text, and if so, is that text still marked untrusted
when the Supervisor sees it?**

---

## 1. Where the untrusted marker actually lives

One fact frames everything below. The `untrusted_content: true` marker is not a
general property of every model-visible string. It exists on exactly one thing:
an **`evidence.derived_view`**, and it is *enforced* there —
`control_plane/evidence/store.py` refuses to write an evidence row whose
`derived_view` does not carry `untrusted_content: true` (§4.4, §8.1). Nowhere
else in the schema is there such a flag. In particular, three columns that hold
model-visible free text are bare `TEXT` with no marker of any kind:

| Column | Type | Carries an untrusted flag? |
|---|---|---|
| `evidence.derived_view` | JSONB | **yes** — enforced on write |
| `findings.claim` | `TEXT NOT NULL` | no |
| `tasks.goal` | `TEXT NOT NULL` | no |
| `tasks.result_summary` | `TEXT` | no |

This matters because "is the marker preserved by `query_findings`?" turns out to
be the wrong question. `query_findings` does not return `derived_view`; it
returns `findings.claim`, a *different column that never had a marker*. The
marker is not stripped in transit — it is dropped earlier, at whatever step
would copy tool-derived text out of `derived_view` and into `claim`. §3 is about
that step.

---

## 2. Field-by-field: what each interface returns, and its source

### 2.1 `query_state()` — `control_plane/api/function_api.py`

Returns `{counts, tasks, recent_decisions}`.

| Field | Source | Class |
|---|---|---|
| `counts.*` (tasks/proposals/capabilities/runs/evidence) | `count(*)` over tables | **deterministic** |
| `tasks[].task_id`, `status`, `owner_agent_id`, `created_by`, `parent_task_id`, `priority`, `lease_expires_at`, `created_at` | kernel-generated ids, enums, timestamps | **deterministic** |
| `tasks[].overlaps_with` | task ids (D19) | **deterministic** |
| `tasks[].goal` | **free text authored by a prior Supervisor plan** | model text |
| `tasks[].result_summary` | **free text passed to `complete_task(result_summary=…)`** | free text |
| `recent_decisions[].proposal_id`, `task_id`, `agent_id` | kernel ids | **deterministic** |
| `recent_decisions[].action` | proposal action enum | **deterministic** |
| `recent_decisions[].target_value`, `target_type` | the **canonicalized** target (`target -> logical_identity`) | normalized identity |
| `recent_decisions[].decision` | ALLOW / DENY / HUMAN_APPROVAL | **deterministic** |
| `recent_decisions[].decision_reasons` | kernel constant strings | **deterministic** |
| `recent_decisions[].created_at` | timestamp | **deterministic** |

Two fields are not deterministic system values:

* **`goal`** is text a previous planning round wrote. It is not *directly*
  evidence-derived — but it is exactly the field §11.4's downstream half warns
  about, read back in. If round *k* laundered a banner string into a goal, round
  *k+1* reads that goal as trusted input (§4 explains why "trusted").
* **`result_summary`** is whatever a caller hands `complete_task`. The signature
  types it `str` and imposes nothing. A Worker or orchestrator summarising "what
  the scan found" from tool output would put target-derived text here.

`target_value` is a third, milder case: it is the *canonicalized* identity, not
free prose — a normalized ip/cidr/fqdn/url or a `CanonicalizationError`. An fqdn
can be attacker-chosen, but it is a validated hostname token, not a paragraph,
so it is a narrow channel and is noted rather than counted with the two above.

### 2.2 `query_findings()` — `control_plane/api/function_api.py`

Returns a list of finding rows.

| Field | Source | Class |
|---|---|---|
| `finding_id` | kernel id | **deterministic** |
| `claim` | **"derived from tool output" (§4.3, and the function's own docstring)** | tool-derived free text |
| `state`, `evidence_strength`, `verifier_state` | discrete enums (§4.3) | **deterministic** |
| `evidence_ids`, `attack_path_ids` | id lists | **deterministic** |
| `affects` | `{asset_id: …}` — an id reference | **deterministic** |
| `verification_conflict` | boolean | **deterministic** |
| `created_at`, `confirmed_at` | timestamps | **deterministic** |

Exactly one field carries target-derived free text: **`claim`**. The function's
docstring already says so and tells the caller to wrap it. That instruction is
the whole subject of §3.

---

## 3. The one real channel, and why it is not live today

There is a genuine structural channel, and it is precisely a place where the
untrusted marker disappears — but it is **pre-armed, not currently reachable**.
Both halves are true and both must be stated.

### 3.1 The channel (where the marker is lost)

`findings.claim` is, by §4.3's design, tool-output-derived. A finding is
promoted from evidence, and its `claim` is a statement about what a scan or a
page showed. The text originates in an `evidence.derived_view` that carried
`untrusted_content: true` — and the promotion copies it into a bare `TEXT`
column that carries nothing. **The marker is dropped at the copy, at
finding-creation time.** `query_findings` then returns `claim` as a plain
string, and its return value gives a consumer no signal that the string is
target-derived. Data flow, named explicitly:

```
target output → nmap/tool → evidence.derived_view {untrusted_content: true}   ← marked
                                   │  (finding-creation copies the text out)
                                   ▼
                          findings.claim : TEXT                                ← marker gone
                                   │  query_findings() returns it verbatim
                                   ▼
                          Supervisor state.findings[].claim                    ← bare string
```

The symmetric, slightly nearer case on the other interface:
`tasks.result_summary` (and `tasks.goal`) are bare `TEXT` on
`query_state().tasks`, and a caller that fills `result_summary` from tool output
puts target-derived text there with no marker either.

### 3.2 Why it is not a live exposure right now

Following the standard this project set at D13/D15 — a negative result has to
explain *why* — here is why the channel above carries nothing today:

1. **Nothing in the control plane writes a finding.** `grep -rn "INSERT INTO
   findings" control_plane/` returns *only the reader*. Every writer is a test
   fixture or the D17 harness seeding a fixture row. §8.10's
   finding-verification workflow is Phase-1 (this is `DEFERRED` 5.6). So
   `query_findings` returns nothing in production, and the copy that drops the
   marker has no code that performs it yet.
2. **Nothing in the control plane fills `result_summary` from tool output.**
   `complete_task` has no production caller either; the field is populated only
   by the harness. So the `query_state` free-text fields are, in practice,
   empty or model-authored, not evidence-derived.
3. **`goal` is model-authored, not evidence-derived.** It can *re-circulate*
   laundered text across planning rounds (§2.1), but that is the downstream
   §11.4 loop, not a new upstream source — and D17 measured it at **0/81** goals
   quoting the lure.

### 3.3 What is actually holding the line, and why that is fragile

The channel is inert because of (1)–(3) — *absences*. There is also one active
mitigation, and it is worth being precise that it is a **convention at a single
consumer**, not a property of the interface:

`BaseWorker`'s sibling on the Supervisor side, `agents/llm/supervisor_base.py`
`build_prompt`, splits its prompt by **source**: the objective, scope, task
ledger and decision ledger go on the trusted side; **findings and evidence are
wrapped in the untrusted block** (`wrap_untrusted`, "Collected from the
targets"). So even though `claim` arrives as a bare string, the Supervisor
re-marks it untrusted because it *knows by source* that findings are
target-derived.

Two things follow, and they are the reason §11.4 stays open rather than being
declared closed:

* **The safety is by-source, applied by one consumer.** `query_findings` hands
  any caller bare untrusted text with no signal. A *second* consumer — a future
  agent, a UI, a different prompt builder — that does not carry the same
  "findings are untrusted by source" assumption would place `claim` wherever it
  liked. The interface does not defend itself; the D17 Supervisor does.
* **`query_state.tasks` is on the *trusted* side.** `goal` and `result_summary`
  land in the Supervisor's trusted header. Today that is safe only because
  neither is evidence-derived in production (§3.2). The moment a Worker writes a
  tool-derived `result_summary`, target text is on the trusted side of a model
  prompt with nothing marking it — no consumer convention catches this one,
  because the convention wraps *findings and evidence*, not the task ledger.

---

## 4. The finding, stated plainly

**Investigation result: no *live* laundering path exists through
`query_state`/`query_findings` today** — because the control plane never writes
a finding and never fills `result_summary` from tool output, and because the
sole consumer (the Supervisor prompt builder) wraps findings by source. **The
channel is real and pre-armed, not closed.** It opens the moment either of two
Phase-1-shaped changes lands, and neither is obviously security-relevant to
whoever writes it:

1. A finding-writer that promotes evidence to a finding, copying
   `derived_view` text into `findings.claim` — dropping the `untrusted_content`
   marker at the copy. (`query_findings` → Supervisor untrusted block; safe only
   while the Supervisor remains the only reader.)
2. A `complete_task(result_summary=…)` caller that summarises tool output —
   putting target-derived text on `query_state.tasks[].result_summary`, which is
   on the Supervisor's **trusted** side, caught by nothing.

The precise attack surface, in field terms: **`findings.claim` and
`tasks.result_summary` are bare `TEXT`, and the `untrusted_content` marker that
lives on `evidence.derived_view` does not travel into them.** `query_findings`
and `query_state` return them without re-attaching it.

---

## 5. The binding rule for widening these interfaces (§5 of the brief)

If `query_state`/`query_findings` are later extended to show the Supervisor more
evidence detail — a claim's supporting excerpt, a service banner, a page snippet
— to let it plan more precisely, the following must hold, or the widening opens
the channel §3 describes. These are preventive constraints, not an
implementation:

1. **The untrusted marker travels with the data through the interface, as a
   machine-readable fact — never as a consumer's assumption.** Any field derived
   from evidence or target output must be returned already flagged (e.g.
   `{"value": …, "untrusted": true}`), so *any* reader is told, not only the one
   reader that happens to know findings are untrusted by source. This is the D20
   principle applied here: the system establishes provenance as a fact carried
   with the data; a consumer may only add caution, never assume trust.

2. **Preserve the marker at every *copy*, because that is where it is lost.**
   The channel does not open at the query; it opens at finding-creation copying
   `derived_view` → `claim`. A finding-writer (Phase-1) must carry the
   `untrusted_content` marker onto the finding, and `query_findings` must surface
   it. The same applies to any code that fills `result_summary` from tool
   output.

3. **Nothing evidence-derived may sit on the trusted side of any prompt.** The
   trust split must be by **provenance** — is this field target-derived — not by
   which table or ledger it arrived in. `tasks.goal` and `tasks.result_summary`
   are the standing counterexample: they are on the trusted side today and are
   safe only by the absence of an evidence-derived writer. A widening that lets
   either carry target text must move it to the untrusted side or block it.

4. **Prefer deterministic derivations over raw text.** Counts, enums, canonical
   identities, ids and timestamps can be shown freely; they are what the two
   interfaces mostly return today, and that is why they are mostly safe. If free
   text from a target must be shown to improve planning, it is untrusted by
   construction and must be marked as such at the interface boundary — the
   burden is on the field that carries prose, not on the reader.

5. **A single wrapping consumer is not an invariant.** The Supervisor wrapping
   findings-by-source is correct and should stay, but it must not be *the* thing
   that makes these interfaces safe. The interface is used by whatever asks it;
   its guarantees have to be its own.

---

## 6. Recommendation

The channel is real but currently unreachable, and closing it fully means
attaching and carrying an untrusted marker through `findings.claim` /
`tasks.result_summary` and the interfaces that return them — work that has no
trigger until a finding-writer or a tool-derived `result_summary` writer exists
(both Phase-1). My recommendation is therefore **not to build a defence now**,
but to:

* record §5 as the binding constraint on `DEFERRED_MVP0.md` §11.4, so the two
  Phase-1 changes that would arm the channel cannot land without carrying the
  marker; and
* treat §11.4 as *characterised, mitigated-by-absence, and gated* rather than
  closed — the honest status, matching what the investigation found.

If you would rather pre-empt it — attach an `untrusted` flag to `claim` and
`result_summary` in the two query functions and have the Supervisor read the
flag instead of wrapping by source — that is a small, self-contained step and I
can take it as D22 step two. It buys defence-in-depth against a *future* second
consumer at the cost of adding a field nothing reads yet. Which of the two you
prefer is the decision this ADR is asking for.
