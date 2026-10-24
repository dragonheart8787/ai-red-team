# Proposals waiting for a person, in the database reachable from the build session

Read only, 2026-10-24 15:59 UTC, as the database superuser of the local cluster (`cyberorch`);
nothing was changed or processed. **This is the development database of this session -- a scratch
database full of test and harness engagements -- and not a deployment**; no other database is
reachable from here [R]. The number that matters for a real publication is the one in the
deployment the owner publishes to, to be read there with the query below.

A proposal is waiting when `action_proposals.pipeline_stage = 'awaiting_approval'`
(`decision = 'HUMAN_APPROVAL'` for a decision still to be made; `ALLOW` for one granted and not yet
dispatched).

| engagement family | waiting proposals | engagements | what they are |
|---|---|---|---|
| `ENG-TEST-*` | 6,559 | 4,077 | pytest fixtures (this suite makes more with every run; the figure was 6,526 / 4,044 earlier today) |
| `ENG-D40-MAIN-*` | 79 | 38 | live-run harness (`scripts/live_run/d40_three_role.py`) |
| `ENG-CTL-*` | 2 | 2 | S8a/S8b control engagements |
| `ENG-S8A-*` | 2 | 1 | the S8a effects trial |
| **total** | **6,642** | **4,118** | |

**It is not zero.** None of it was processed. Publishing a global layer would void every one of them
(`policy_version_changed` at dispatch; ACCEPTANCE 5.124) -- here all are test or harness leftovers,
in a deployment they would be real approvals and must be read first.

The non-test engagements, in full (proposals waiting in each):
`ENG-CTL-1022143838` 1, `ENG-CTL-1022143916` 1, `ENG-S8A-1022205819` 2, and `ENG-D40-MAIN-` +
`0cffc3643e` 2, `0e73279731` 2, `100aaca77e` 1, `1449295a95` 2, `16e8ebebe4` 2, `36b39f8951` 2,
`3703ee4a53` 1, `381d88d95a` 4, `39a0254e80` 2, `42b569da27` 2, `4e8defd8ad` 2, `4ee15c4a37` 2,
`502a401863` 2, `5553dc11f5` 3, `5b727076f5` 2, `5c8fcb8a68` 2, `601dc00385` 3, `62a9295440` 2,
`664415ed61` 2, `66885e1d46` 2, `694706d9a5` 2, `7752461cd0` 2, `77ad49be62` 2, `79b0bc8204` 2,
`8d83bcdd2b` 2, `a305d5d60b` 2, `a33afaada6` 1, `a54273999d` 2, `b229229509` 2, `b73842c370` 2,
`c615873b36` 2, `cb89299805` 2, `df206dd7ce` 3, `e1ef1f9e96` 3, `edde63c19f` 2, `f34063f0c8` 2,
`f68d4f64cd` 2, `f77b78a8a1` 2. The 4,077 `ENG-TEST` engagements are not listed one by one.

The query (superuser, so that row-level security does not hide other engagements):

```sql
SELECT engagement_id, count(*) FROM action_proposals
WHERE pipeline_stage = 'awaiting_approval' GROUP BY 1 ORDER BY 1;
```
