# MVP-1.5 Acceptance Review — the Web Agent stage (D31–D37)

Status: **D38, documentation inventory only.** No code or tests changed in D38.

This review follows D18/D23: what each deliverable closed, what it found, the
evidence (commit and CI run), the candidate list graded into three risk classes,
and a Go/No-Go. It is a separate document because the Web Agent is a distinct
stage from the one `ACCEPTANCE_MVP1_AGENTS.md` reviews ("the three roles behind
real models", D10–D24).

**One record per item.** The detailed status of every candidate item stays in
`ACCEPTANCE_MVP1_AGENTS.md` §3, where it already lives. This document grades and
cross-references those items by number; it does not restate them. The project
has closed too many "two descriptions that must agree" defects (D27, D29, D30,
D33) to open another one here.

---

## 1. What the stage built, deliverable by deliverable

The CI column gives the **first green run** for the deliverable's final commit.
Earlier red runs are listed because the stage's lesson is visible in them: almost
every red run was a build