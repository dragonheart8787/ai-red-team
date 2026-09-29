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
| F3 | Approved: attached-form arguments, no ADR | **Done.** `--username=$2` / `$3=$(cat "$4")` with `$3` in `{--password, --hashes}`. Applied to the username as well as the secret — the real tool rejects `-u -alice` exactly as it rejects `-p -abc123`, and `domain_username` is Worker-supplied, so it is the same defect. Hash shape and username↔secret binding are **not** addressed here: they go into the F2 ADR addendum. |
| F2 | ADR addendum first; **no implementation until reviewed** | Addendum to `docs/ADR_CREDENTIAL_VAULT.md` (status DRAFT) is being written as a separate, docs-only commit. Unchanged in behaviour: probe 4 still shows the secret in host `ps` (now as `--password=<secret>`). |
| F4 | Record only, not a priority | Recorded (5.25 caveat). Not fixed. |
| F5 | Confirmed as the gate | Task #42/#44/#45 stay blocked until F1/F3 are in (done), F2's direction is decided **and** implemented, and only then are they re-assessed — in that order. |

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
* There is now a permanent test of what a real container receives
  (`tests/test_ad_collector_credential_delivery.py`) — the gap §2 found.
