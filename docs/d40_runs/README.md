# D40 run artifacts

The raw record behind `../D40_THREE_ROLE_INTEGRATION_REPORT.md` — committed
for the same reason D17's are: a report whose figures cannot be re-derived
has to be believed rather than checked.

`d40_three_role.json` is the corrected run (evidence capped at
`MAX_EVIDENCE_SHOWN = 3` per round; see the script and the report's §2.4 for
why). The first attempt, whose Supervisor crashed from round 2 onward with
`OSError: Argument list too long`, is not here — its round-1 data is a
subset of what the corrected run's round 1 already contains, and nothing
past round 1 in that attempt is real.

Each task record carries the Supervisor/Worker's own output, latency, the
structural/work key the task reduces to, the real Authorization Resolver's
verdict, and the full decision outcome. No credentials, no raw evidence
artifact: evidence is summarized into a finding's claim (truncated to 400
characters) before anything is written to this file, the same boundary
`agents/llm/*`'s untrusted-content wrapping already draws elsewhere.

```
python -c "import json; print(json.dumps(json.load(open('docs/d40_runs/d40_three_role.json'))['main_run']['duplication'], indent=2))"
```
