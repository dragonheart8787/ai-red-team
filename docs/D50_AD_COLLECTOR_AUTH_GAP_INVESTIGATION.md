# D50 — ad_collector authentication gap: investigation (no fix)

**Scope, as instructed:** find out what class of problem the D49 side-finding is
before touching anything. No production code was changed; task #42/#44/#45 were
not started. Every claim below was observed against the real
`cyberorch/bloodhound:local` image (`bloodhound==1.9.0`) and, where the D44 path
is concerned, the real vault, `mount_for_run`, `build_plan` and `DockerSandbox`.
`scripts/live_run/d50_ad_collector_auth_probe.py` reproduces all of it (no domain
controller needed).

## 0. Verdict

The symptom is real but it is **not one problem, and it is not the one the brief
hypothesised.** Five separate findings, of different classes:

| # | Finding | Class | Blocks #42/#44/#45? |
|---|---|---|---|
| F1 | The uncredentialed command has no valid form against the real tool; nothing refuses it | Design-premise defect (leftover interim path) | No — it is a dead branch, not the path #42/#44/#45 use |
| F2 | The vault-mounted secret ends up in argv, visible in the **host** process table for the whole run | D44 mechanism deviates from ADR §2.1 (partial; delivery itself is correct) | No, but needs a decision + ADR addendum |
| F3 | Four latent parameter-level defects in the credentialed branch | Parameter class | No (each fails as an opaque tool error) |
| F4 | D49's `-ns` covers SRV discovery and LDAP, **not** Kerberos KDC connections | New gap (D49's fix is incomplete for Kerberos) | Only for Kerberos-required targets — unverified |
| F5 | **No authentication has ever succeeded with this tool anywhere in this project** | Never verified end to end | **Yes — this is the real gate**, independent of F1–F4 |

Against the brief's three-way taxonomy: F1/F3 are class 1 (parameters) in shape,
F2 is class 2 (D44 mechanism) but narrower than "the mount does not match the
tool", and F5 is class 3. **No single class covers it, and the sharpest correction
is to the framing of #42/#44/#45's blocker: it is F5, not the usage-printing
command.**

## 1. Reproduction: what the tool wants vs what `build_plan` emits

Real binary, ten credential shapes (`-ns` pointed at a blackhole so it stops at
the DNS stage; `-v` makes the tool announce which auth branch it took):

| Shape given to the tool | Result |
|---|---|
| no auth flag (**= ad_collector's uncredentialed command**) | prints usage, `exit 1`, before the `AD` object exists |
| `--dns-tcp` only / `-no-pass` only / `-u alice -no-pass` | same |
| `-p secret` or `--hashes …` **without** `-u` | `ERROR: … provided without username`, exit 1 |
| `-k` without `-u` | `ERROR: Specifying the username explicitly is required` |
| `-u alice -p secret` | auth branch taken, reaches `dns_resolve` |
| `-u alice --hashes LM:NT` | auth branch taken, reaches `dns_resolve` |
| `-u alice --hashes <single hash>` | crashes at `lm, nt = hashes.split(":")` (`ValueError`), before any DNS |
| `-u alice -aesKey <hex>` | Kerberos branch taken, reaches `dns_resolve` |

Source (`bloodhound/__init__.py`, `main()`): the `else:` of the auth ladder is
`if not args.kerberos: parser.print_help(); sys.exit(1)`. **Every accepted
branch requires a username; there is no credential-free mode in 1.9.0.** (For
the brief's list: `--dns-tcp` is DNS transport, not an authentication option; the
real auth options are `-u/-p/--hashes/-aesKey/-k/-no-pass/--auth-method`.)

What `build_plan` emits:

| Branch | argv | Equivalent tool invocation | Real-tool outcome |
|---|---|---|---|
| A. no `domain_username` | `bloodhound-python -d D -c M --zip` | no auth flag | **usage, exit 1** |
| B. `auth_mode=password` | `sh -c 'exec bh -d "$1" -u "$2" "$3" "$(cat "$4")" -c "$5" --zip' sh D U -p /creds/secret M` | `-u U -p <file contents>` | accepted |
| C. `auth_mode=hashes` | same, `--hashes` | `-u U --hashes <file contents>` | accepted if contents are `LM:NT` |

Not missing a flag: **no flag exists that would make branch A work.** What the
adapter lacks is not a parameter but a premise.

Through the real sandbox, branch A yields `exit_code=1, succeeded=False`, stdout
beginning `usage: bloodhound-python …`; `dispatch_collection` records `failed`
and never attempts the graph write. No security consequence — it fails closed at
the tool — but it is a run that cannot succeed and is not refused.

> The two tables above are the **snapshot at investigation time** and are kept as
> the evidence for what the tool wants. §1.1 is the code as it stands now.

### 1.1 Current state (after F1, F3 and D50-B)

| Capability | Where the bind identity comes from | Outcome |
|---|---|---|
| no `credential_id` | — | **refused** as `UNBUILDABLE_PLAN` by `dispatch_collection`, before any sandbox, `tool_runs` row or credential mount (was: branch A, a run the real tool could only fail) |
| a credential stored **before** D50-B (secret only) | unknown | **refused** (`predates identity binding`); not backfilled, not run without an account |
| a credential with a bound identity, states no username/mode | the credential (`vault.identity_for`) | runs as the bound account, in the bound mode |
| a credential with a bound identity, states a *different* username or mode | the credential; the statement is an assertion that must match | **refused** on mismatch |

What the one remaining command shape looks like (branches A/B/C above collapse
to it; `$3` is `--password` or `--hashes`, chosen by the credential's bound mode):

```
sh -c 'exec bloodhound-python -d "$1" "--username=$2" "$3=$(cat "$4")" -c "$5" --zip'
   sh <domain> <bound username> --password|--hashes /creds/secret <methods>
```

Not changed by any of this, and still open: the secret is in that process's argv
and in a `0644` host file (F2, tracked as ACCEPTANCE 5.26); the KDC hostname is
not covered by `-ns` (F4); and no authentication has succeeded anywhere (F5).

## 2. Has D44's mount → command-line path actually been walked?

**Yes, with two qualifications — so the brief's class-3 hypothesis ("D45's real
run was uncredentialed, so the path was never walked") does not hold.** D45's
live-run script and D49's re-run both propose with `domain_username=collector`
and a vault credential; the recorded command is branch B, and the tool logged
`Getting TGT for user`, i.e. it took the username/password branch.

That only shows the tool *accepted* the arguments. Nothing before D50 showed the
secret *arrived intact*, and no test asserts it (the D44/D48 tests use
`StubSandbox` and only assert the secret is **absent** from records). So D50
measured it: real `store_credential` → real `mount_for_run` (mode `0644`, read-only
bind mount, cleanup in `finally` — all as the ADR §4.1 "net design" says) →
real `build_plan` → real `DockerSandbox.run`, with only the bloodhound binary
replaced by a stub printing its argv:

* **intact:** plain, spaces, shell metacharacters (`$HOME $(id) \`id\` "q" 'q' \ ; | & *`),
  a password beginning with `-`, unicode, `LM:NT`.
* **differs:** a secret with a *trailing* newline loses it (`$(cat)` strips it) —
  negligible in practice.

So **the D44 delivery mechanism is sound**, and the "mount is the wrong shape for
the tool" reading of class 2 is not supported. What *is* supported is F2 and F3.

## 3. Findings

### F1 — the uncredentialed branch is a leftover, not a bug in a flag

D42's ADR already said BloodHound "is the first tool … that needs the control
plane to hand a tool container a secret"; `build_plan`'s docstring called the
uncredentialed command "buildable and testable against fixture output … no
live/production path until the Vault lands". So it was an interim, fixture-stage
path. When D44 landed it was neither retired nor turned into a refusal, and no
document says "ad.collect without a credential cannot run for real". Consequences:

* `dispatch_collection` accepts an `ad.collect` capability with no
  `domain_username` and starts a container that cannot succeed.
* Tests pin the dead command as correct:
  `test_no_domain_username_builds_the_original_uncredentialed_command`,
  the `dispatch_collection` "normal path" tests (fixture output), and D48's
  `test_ad_collect_without_a_credential_still_reaches_dispatch_collection`. All
  use `StubSandbox`, which is exactly why none could see it.

### F2 — the secret is in argv, on the host, for the whole run

`bloodhound-python` has no read-from-file option, so the wrapper uses
`exec … "$(cat …)"` (the adapter docstring says so). Where the secret can be seen,
by source of the evidence:

| Where | Contains the secret? | Evidence |
|---|---|---|
| `docker inspect` `Config.Cmd` (what the daemon records) | no | measured in D50 (probe 4) |
| `tool_runs.normalized_params`, `tool_run.started` audit payload | no — D44's real guarantee holds | **not re-measured in D50**: D45/D49 live-run checks ("command never carries the plaintext secret") plus reading `dispatch_collection` |
| `docker top <container>` | **yes** | measured in D50 (probe 4), while the tool ran |
| host `ps -eo args` | **yes** — `… bloodhound-python -d corp.test -u alice -p <secret> -c Group --zip` | measured in D50 (probe 4), while the tool ran |

Because the wrapper `exec`s, that argv exists for the entire run, not "for the
moment it execs".

This is a direct deviation from ADR §2.1 ("path in argv, secret content only in a
mounted file, never in argv or the environment … generalizes **without change**")
and from the project's own D34/D35 reasoning (`sandbox.py`: "argv … the process
table would expose them"). Two statements in the record understate it:
the adapter docstring limits the exposure to "*inside* the container … for the
moment it execs" and says ADR §2.2 "already prices this in"; §2.2 never mentions
the process table, and the exposure is host-wide and run-long.

Calibration, so this is not overstated: the same run already leaves the secret in
a world-readable (`0644`) temp file on the host, a choice ADR §4.1 made
explicitly. Anyone who can list host processes can very likely also read that
file, so the *practical* increment is small on a single-tenant host. What is not
small is that a stated design principle is not met for this tool and the record
describes it inaccurately.

The mount mechanism does not have to change to fix this. **Feasibility probe
(not an implementation):** a Python launcher that reads `/creds/secret` and calls
`bloodhound.main()` with `sys.argv` set in-process left the secret out of both
`docker top` and host `ps`, and the tool still took its auth branch.

### F3 — four latent parameter defects in the credentialed branch

1. **A password beginning with `-` is rejected.** The shell delivers `-abc123`
   intact (§2) but the wrapper's `-p -abc123` makes argparse fail with
   `expected one argument` (rc 2). The attached forms `-p=…` / `--password=…` work.
2. **`--hashes` needs `LM:NT`; anything else crashes before DNS.** `build_plan`
   never sees the secret, so it cannot validate; D45 noted the stored form must
   already be joined, and nothing enforces it.
3. **Nothing binds the secret's shape or identity to the credential.** The vault
   stores only `secret`; `domain_username` and `auth_mode` come from the
   *proposal's* target block (Worker-supplied). A password stored for one
   account can be paired with another username or with `hashes`. It fails at
   the tool rather than authorising anything new, so this is an observation about
   D44's record shape, not an exploit.
4. Trailing newline stripped (§2). Negligible.

### F4 — D49's `-ns` does not reach Kerberos

`-ns` sets dnspython's resolver, which covers the SRV lookup and the A record
used for the LDAP connection. Kerberos goes through impacket's `sendReceive`,
which calls `socket.getaddrinfo(<KDC hostname>, 88)` — the **system** resolver,
which in the sandbox cannot resolve AD names. D49's live run already showed it:
`Failed to get Kerberos TGT. Falling back to NTLM … [Errno -3] Temporary failure
in name resolution` (`<dc>.d45test.local:88`). With the default
`--auth-method auto` the tool falls back to NTLM silently; `-aesKey` (a
Kerberos-only mode) would have no fallback. So D49's "closed" (5.25) is true for
discovery and LDAP and incomplete for Kerberos. Whether it matters depends on a
target that refuses NTLM; none was available to test.

### F5 — authentication has never succeeded

Not new, but it is the actual blocker and the brief's framing partly hides it:
against Samba, the client libraries fail for reasons in `ldap3`/`impacket`
(D45, documented); against a real Windows AD it has never been run. So what is
proven is "the tool accepts and receives the credential"; what is unproven, and
what #42/#44/#45 need, is "the credential authenticates and a collection
completes". F1–F4 can all be fixed and #42/#44/#45 would still be blocked.

## 4. Impact scope

* **Only `ad_collector.py` and `dispatch_collection`** for F1, F3, F4.
* **`mount_for_run` / the vault mechanism: not wrong.** F2 is about how the
  adapter *consumes* what it mounts, given this tool's CLI. Design observation
  for D44: the credential record carries no username or secret-shape.
* **The D44 ADR needs an addendum** (F2): §2.1's "generalizes without change" is
  false for a tool whose CLI accepts secrets only in argv; §2.2's blast radius
  should state the host process-table exposure if any option that keeps it is chosen.
* Other tools: `code.scan`'s git token is consumed control-plane-side (never in a
  container) and Semgrep holds no credential, so neither is affected. Any *future*
  sandbox tool with an argv-only secret CLI inherits F2.
* Tests give false confidence at F1 (three tests pin the dead command) and had no
  delivery assertion at all until this probe.

## 5. Not verified

Authentication success anywhere (F5); a Kerberos-only or NTLM-disabled target
(F4's practical reach); the in-process launcher against a real DC; the
Kerberos-ccache route (`-k`, needs a control-plane `kinit`, untried);
`hidepid`-style host hardening that would change F2's practical exposure.

## 6. Decisions this leaves to you (options, nothing implemented)

* **F1.** (a) Refuse `ad.collect` without a credential in `dispatch_collection`
  as `UNBUILDABLE_PLAN` before any container, delete the branch, and move the
  three fixture tests to the credentialed shape; or (b) keep it as fixture-only.
  I lean (a): small, no ADR, fail-closed like the D49 check.
* **F2.** (i) in-process launcher (probe positive; keeps the mount design);
  (ii) Kerberos ccache minted control-plane-side (changes the trust model,
  untested); (iii) accept it, capped by `max_duration_seconds`, and correct the
  ADR/docstring. Any choice needs a short **ADR addendum**, not a new ADR — the
  vault and mount design are unchanged — but that is your call, per the
  D42/D43/D44 precedent.
* **F3.** Attached-form arguments are trivial; where hash-shape and
  username↔secret binding belong (vault record vs adapter) is a D44-level
  question.
* **F4.** Open design question (how KDC hostnames resolve in the sandbox;
  `DockerSandbox` has no `extra_hosts`) that needs a target to test against.
* **F5.** Needs an environment where authentication can succeed; independent of
  the above and the true prerequisite for #42/#44/#45.

---

## 7. Status, as of the D50 follow-up

Decisions taken on §6, and what was done:

| Finding | Decision | State |
|---|---|---|
| F1 | Approved: refuse, remove the dead branch, no ADR | **Done.** `build_plan` refuses a capability with no (or blank / non-string) `domain_username`; `dispatch_collection` reports it as `UNBUILDABLE_PLAN` before any sandbox, `tool_runs` row or credential mount; the uncredentialed command branch and the conditionals it made dead are gone. |
| F3 | Approved: attached-form arguments, no ADR | **Done.** `--username=$2` / `$3=$(cat "$4")` with `$3` in `{--password, --hashes}`. Applied to the username as well as the secret — the real tool rejects `-u -alice` exactly as it rejects `-p -abc123`, and `domain_username` is Worker-supplied, so it is the same defect. Hash shape and username↔secret binding were split out into D50-B (next row). |
| F3 (hash shape, username binding) → **D50-B** | Approved: store-time, bound into `encrypted_material`; a formal revision of a D44 implementation-time decision, not a new feature | **Implemented** — `store_credential` requires and validates `username` + `auth_mode` for `ad_domain_bind`; `vault.identity_for`; `dispatch_collection` takes the identity from the credential and treats the proposal's as an assertion that must match; a credential stored before D50-B is refused (unknown, never "none needed"), not backfilled. Recorded as ADR §8 ("Revision"). |
| F2 | ADR addendum first; decisions taken on it | **D50-A: no option adopted** — recorded as **ACCEPTANCE 5.26**, to be re-evaluated once a real threat model exists (ADR §7.11). **D50-C** (the `0644` file) folded into the same item. Behaviour unchanged: probe 4 still shows the secret in host `ps` (now as `--password=<secret>`). The `ad_collector.py` docstring's inaccurate statements about the exposure were corrected (a factual fix, not an acceptance). |
| F4 | Record only, not a priority | Recorded (5.25 caveat). Not fixed. |
| F5 | Confirmed as the gate | **D50-D: task #42/#44/#45 are assessed after F1/F3/D50-B and do *not* wait for F2** — whether a credential can complete an LDAP/NTLM authentication and how visible it is on the host do not block each other. (This replaces the earlier ordering, in which F2 had to be decided and implemented first.) |

**Existing-data survey for D50-B (before implementing).** The only database
available is this branch's development database. Surveyed as the superuser
(RLS scopes every ordinary role to one engagement, so a first survey through
`credential_admin_scope` returned 0 — a wrong number that only *looked* like a
finding): 357 `credential_material` rows — 305 `ad_domain_bind` (278 secret-only,
27 undecryptable with the current master key) and 52 `git_token` (42 readable,
10 undecryptable; untouched by D50-B). All from this branch's own `ENG-TEST`,
`ENG-D45` and `ENG-D50` engagements; none is deployment or customer data.
D50-B changes **none of them**: legacy rows stay as they are and are refused at
use (`predates identity binding`; an undecryptable one is refused by the
decrypt error). No backfill was done — a username cannot be recovered from a
secret, and for the ten D45 rows the username appears only in a free-text
*label*, which is not an identity. Whether to clean these rows up is left to you;
nothing depends on it.

What the F1/F3 change taught about the test suite, beyond the code:

* The affected tests were not "three": `test_ad_collector_adapter.py` (the uncredentialed
  command test, and every dns test that used the uncredentialed shape),
  `test_dispatch_collection.py` (its *default* capability was uncredentialed, so seven
  tests ran the dead branch), and D48's E2E test.
* **Two D49 dns_server tests would have kept passing for the wrong reason.** Left on
  the default capability, `..._outside_network_allowlist_is_refused_as_unbuildable`
  would have been refused earlier for the missing bind identity and stayed green with
  the dns_server check deleted. They were moved to credentialed capabilities and the
  dns_server mutation was re-run against the rewritten test (red, as it must be).
* **The ADR work corrected one of this report's own calibrations.** §3 F2 called the practical increment of the argv exposure small because the secret already sits in a world-readable file. That considered only live local observers; argv, unlike a temp file, is routinely recorded and shipped off-host by `execve` auditing and process-telemetry agents. Not measured here, so it is a risk to assess, not a finding — but the "small" was too quick (ADR §7.1).
* There is now a permanent test of what a real container receives
  (`tests/test_ad_collector_credential_delivery.py`) — the gap §2 found.

---

## 9. Attempt against the real Samba DC (task #42/#44/#45), after D50-D

Per D50-D, task #42/#44/#45 were attempted directly after CI confirmed green on
D50-B — without waiting for D50-A. Result: **the DNS and credential-format
mechanisms are now confirmed working end to end through the real, unmodified
production path; real collection still cannot complete, for the identical,
pre-existing reason D45 already found and documented.** Nothing here is a new
D49/D50 defect, and nothing here is fixable from this codebase.

**What was re-provisioned and re-run:** a fresh `nowsci/samba-domain` DC
(domain `d45test.local`), a fresh `collector` domain user, and
`scripts/live_run/d45_ad_collection_e2e.py --dns-server <dc-ip>` — the same
script D49 used, now exercising D50-B's credential-identity path for the first
time against real infrastructure (the credential is stored with
`username="collector", auth_mode="password"`; the proposal states the same
pair; `dispatch_collection` reads the identity from the credential and confirms
the match).

**Confirmed working, through the real pipeline, for the first time with the
post-D50-B attached-form command:**

```
sh -c 'exec bloodhound-python -d "$1" "--username=$2" "$3=$(cat "$4")" -c "$5" -ns "$6" --zip'
   sh d45test.local collector --password /creds/secret Group,ACL 10.85.0.53
```

The real binary logged `Found AD domain: d45test.local` (DNS/SRV resolution
succeeded via `-ns`) and reached the LDAP bind attempt — past every stage D49
and D50 own.

**Where it still stops**, verified from the raw evidence artifact (not the
derived view's own truncated excerpt):

```
File ".../ldap3/core/connection.py", line 628, in bind
    response = self.do_ntlm_bind(controls)
File ".../ldap3/strategy/base.py", line 370, in get_response
    raise LDAPSessionTerminatedByServerError(self.connection.last_error)
ldap3.core.exceptions.LDAPSessionTerminatedByServerError: session terminated by server
```

This is the exact failure D45 already identified and attributed to a verified,
static cause: `ldap3`'s NTLM bind uses the legacy Microsoft "Sicily" LDAP
extension, which Samba's AD DC implementation does not support and closes the
connection on sight — a protocol-level gap in the server implementation this
test environment uses as a Windows AD substitute, not a configuration option,
not a credential problem, and not anything D49 or D50 touched. (The Kerberos
attempt immediately above it also failed, for the separate, already-documented
reason of the DC's own container-ID hostname not being resolvable — expected,
and why the tool falls back to NTLM in the first place.)

**Consequences for the three tasks, stated plainly rather than worked around:**

* **#44 (query real collected data) and #45 (I8 re-test against real data)
  remain blocked.** No collection has ever completed against any environment
  available to this project, so there is no real collected data to query or
  re-test against — not a gap this attempt introduced, one it re-confirmed.
* **#42 (the real output translator) remains unwritten, deliberately.**
  `bloodhound-python` crashes before `prefetch_info` returns, i.e. before it
  ever calls any of the `enumeration/*.py` writers that produce the real
  per-object-type JSON files `--zip` would bundle (`ad_collector.parse_graph`'s
  own docstring). No real output exists anywhere to translate. Writing a
  translator against the documented-but-unverified format now would be
  exactly the "silently assumed solved" gap this project's own discipline
  (D45's own module docstring, quoted at the top of this file) refuses to
  accept.
* **What D49/D50 set out to unblock is unblocked.** The mechanism, not the
  environment, was this deliverable's scope, and it is now proven correct
  against real infrastructure, not merely by construction.

**Not attempted, and why:** re-litigating whether Samba's Sicily-extension gap
or the Kerberos checksum issue (the second failure D45 found one layer deeper,
reached only by bypassing `DockerSandbox` entirely) can be worked around.
D45 already read both `ldap3` and `impacket`'s own source to reach that
conclusion; nothing observed here contradicts it, and re-deriving it a second
time would not change the answer. The only paths forward are a real Windows AD
test environment (not available here) or an explicit decision to accept
fixture-based verification as the permanent method for #42/#44/#45 — a scope
decision, not an engineering one, and not this session's to make unasked.
