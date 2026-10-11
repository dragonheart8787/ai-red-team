# D65-A — A deadline inside the tool container: design checkpoint

**Status: design only.** No code, migration or test is written or changed by this document; the helper prototypes
used for the experiments live in the session's scratch area. Nothing is built until the decisions in §11 are
answered.

**How claims are tagged.** `[R]` read in the code at this commit; `[E]` executed here, on this machine, with the
experiment named in §12; `[D]` taken from an older document (named); `[N]` not verified — knowledge or reasoning
that I have not checked against this system.

Origin: `docs/D64_RECONCILER_DESIGN.md` §8 listed this as a separate deliverable candidate. It is written first
because the reconciler's thresholds (D64 §1.2) assume it exists, and it goes into implementation first.

## 0. In one page

A tool container's duration is enforced from outside: the control plane calls `container.wait(timeout)` and then
`kill()` `[R: sandbox.py]`. If the control plane dies, nothing stops the container: one given a 5 s budget was
still running 21 s after its parent was `kill -9`'d `[E: E16-A]`, and Docker has no option for a maximum lifetime
(`docker run --help` offers `--stop-timeout` and `--health-timeout`, neither of which is one) `[E: E15]`.

The answer measured here: a **small static program as the container's PID 1** that starts the tool, waits, and
ends the container when a deadline passes (exit **124**). It is bind-mounted read-only through the existing
`source_mounts` primitive, so no image changes and `DockerSandbox.run` needs one place changed. With the parent
`kill -9`'d it ended a container on its deadline to within 0.1 s by Docker's own timestamps (6.1 s for a 6 s
deadline), took a trapped-TERM tool and a `setsid` grandchild with it, passed stdin through, forwarded
`docker stop` (0.2 s), preserved the tool's own exit codes, and worked as uid 65534 with all capabilities dropped
and a read-only root `[E: E25]`. With the control plane alive the budget still wins `[E: E16-C]`.

The decisions that are yours (§11): the language (Go recommended — one hash pins it on every machine and
architecture; C is smaller but its hash belongs to a toolchain), how it reaches the container (bind-mount
recommended, baking it into the images is the alternative), what happens when it is missing (fail closed,
recommended), the slack (10 s), and what 124 is mapped to.

## 1. The measurement that motivates it

| Question | Answer |
|---|---|
| What happens to a running tool container when the control plane is `kill -9`'d? | It keeps running. Budget 5 s, parent killed at 3 s: `running` 20.9 s later when observation stopped; in the first run (E5) still running 25 s later `[E: E16-A, E5]` |
| Does Docker have a maximum-lifetime option? | No: `--stop-timeout` is the grace given to a stop that someone requests; `--health-timeout` bounds a health check `[E: E15]` |
| What bounds it today besides the control plane? | Nothing in the system. The reconciler of D64 would kill it at `StartedAt + B + 60 s` and could only declare the proposal's outcome unknown at `B + 660 s` (D64 §1.2) |
| Do the tools bound themselves? | Partly: adapters pass a soft deadline `tool_deadline(B) = B − 5 s` to the tool where the tool has one `[R: adapters/*.py, TOOL_STOP_GRACE_SECONDS = 5]`. A tool that ignores it, hangs, or a control plane that is gone — nothing else |

## 2. What the helper is

`cyberorch-deadline SECONDS -- COMMAND [ARGS…]`, run as the container's command. As PID 1 it:

1. starts COMMAND in its own process group;
2. waits for it, reaping every orphan that is re-parented to it (PID 1 must);
3. forwards `SIGTERM`, `SIGINT`, `SIGHUP`, `SIGQUIT`, `SIGUSR1`, `SIGUSR2` to the command, so `docker stop` still
   works;
4. if the command ends first, exits with **the command's own exit code** (`128 + N` if it died of signal N);
5. if the deadline passes first, prints one line to stderr (`cyberorch-deadline: expired after Ns`), sends
   `SIGKILL` to the command's process group, and exits **124**. PID 1 exiting ends the PID namespace, which takes
   every other process with it;
6. exits **125** on a usage error, **127** if COMMAND cannot be executed (with a message).

Behaviour, both builds (§3), through `DockerSandbox.run` or Docker directly `[E: E25]`:

| Case | Result |
|---|---|
| stdin passed by `DockerSandbox.run(stdin=…)` into `/bin/cat` | the same bytes on stdout |
| the command exits 3 | container exit 3 |
| the command kills itself with `SIGKILL` | container exit 137 |
| the command's own `exit 124` | container exit 124 after 0.2 s — **distinguishable from the deadline by duration** (§7) |
| COMMAND missing | exit 127, `cannot execute /nope: …`, 0.2–0.3 s |
| deadline 3 s, command `sleep 1000` | exit 124 after 3.2 s, stderr line as above |
| `docker stop` (10 s grace) of a command that traps TERM | 0.2 s, exit 0 — TERM was forwarded (the first prototype did not forward: a stop with a 5 s grace took 5.2 s and the container ended 137) |
| uid 65534, `cap_drop ALL`, read-only root, `no-new-privileges`, no network | works |
| control plane `kill -9`'d at 2 s, deadline 6 s, a TERM-trapping command plus a `setsid` grandchild | container `exited`, code 124, ran 6.1 s by Docker's `StartedAt`/`FinishedAt`; no leftover process on the host (positive control: 2 while it ran) |

## 3. Source, language and pin

### 3.1 Two builds were made and compared (E24)

| | **C** (`gcc -O2 -static -s -fno-ident -Wl,--build-id=none`) | **Go** (`CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid="`) |
|---|---|---|
| Size | 714,680 bytes | 1,757,332 bytes |
| Source | ~55 lines, `sigtimedwait` loop | ~55 lines, `os/exec` + a timer |
| Same sha256 from another directory, another file name, a second later | yes | yes |
| What the hash depends on | the compiler **and the static libc** that built it: a CI runner with another gcc or glibc gives another hash `[N: not tried on a second machine]` | the Go version (pinned in `go.mod` and by `GOTOOLCHAIN`); no libc `[N: cross-machine not tried]` |
| Other architecture | needs a cross toolchain (none here) | `GOARCH=arm64` built here without one (not run on arm64 hardware `[N]`) |
| PID 1 character | no runtime, one thread | a runtime with several threads; larger than the program needs |
| Read + sha256 per run | 2.4 ms | 5.7 ms (negligible against a run of 120 s) |

**Recommendation (D65A-1): Go.** The point of a pin is that anyone can rebuild and compare; that works across
machines and architectures with Go and only on a matching toolchain with C. The cost is a 1.7 MB binary and a
runtime in PID 1, which is acceptable for a program with this little to do. If you would rather keep PID 1 as
small as possible, C is a defensible choice with a per-toolchain hash, committed alongside the binary.

### 3.2 Where it lives, how it is pinned (proposed layout)

```
tool_gateway/deadline/
    main.go            the whole program
    go.mod             module + `toolchain go1.24.7`
    build.sh           the one build command, with the reproducibility flags; writes bin/cyberorch-deadline-linux-<arch>
    SHA256SUMS         the expected sha256 of each architecture's binary (committed)
    README.md          behaviour table of §2, exit codes of §7
    bin/               the built binaries (git-ignored)
```

* **Pin:** `SHA256SUMS` is committed. The sandbox compares the file's sha256 with it before every run (§5).
  A change to `main.go` or to the Go version changes the hash, and the commit that does it has to update
  `SHA256SUMS` — a reviewer sees both together.
* **CI:** a step builds the helper with the pinned Go and compares with `SHA256SUMS`; a mismatch fails the job.
  That is also the reproducibility test: if CI cannot reproduce the committed hash, the pin is worth nothing, and
  the job says so `[N: the first CI run is the real test of cross-machine reproducibility]`.
* **Provenance** is therefore "built from this commit's source with this toolchain, and equal to the committed
  hash", not "a binary somebody put there".

## 4. How it reaches the container

In `DockerSandbox.run` the command is built in one place (`containers.create(command=list(command), …)`, `volumes`
from `source_mounts`) `[R]`. The change is local to it:

* `volumes[<helper path on the host>] = {"bind": "/cyberorch-deadline", "mode": "ro"}`;
* `command = ["/cyberorch-deadline", str(D), "--", *command]`;
* the container gets one more label, `cyberorch.deadline=<D>`, so the reconciler can read the container's own
  deadline and report a container without one;
* adapters, the registry, the Rego policy and the `Budget` are untouched; `max_duration_seconds` keeps its meaning.

Facts that make this safe to do:

* the existing `source_mounts` primitive already bind-mounts files read-only into the read-only root, and the
  experiments used exactly that `[E: E25]`;
* it needs no write access, no capability and no network;
* **a host filesystem mounted `noexec` fails closed:** the container's `start` is refused ("failed to create task
  for container…") before anything of the tool runs, and the sandbox types that refusal as `ContainerStartRefused`,
  a `NotStarted` `[E: E26]`; the deployment notes must say where the file lives;
* images with an `ENTRYPOINT`: the images here have none (`Config.Entrypoint` null for `nmap` and `gitleaks`); the
  others were not checked, and for an image that has one `command` becomes its arguments, so the wrapper would not
  run `[N]` — the implementation checks each adapter image and the test suite asserts it.

**Alternative (D65A-2): bake the helper into each image.** The image digest then pins it, there is no host path,
no `noexec` question, and no check at run time. Against: six image builds change (there are seven `build_*.sh` scripts; one builds a test target; any image built later must
remember), different images can carry different helper versions, an old image keeps an old helper, and the
existing practice of `source_mounts` for control-plane-owned inputs is already there. **Recommendation:
bind-mount.**

## 5. Checking the file at run time, and what that does and does not give

`DockerSandbox.run` reads the helper file, computes its sha256, compares it with `SHA256SUMS` for this
architecture, and only then creates the container. A mismatch, a missing file or an unreadable one raises a new
`DeadlineHelperUnavailable(NotStarted)` — the run is recorded as "not started", retryable, never as an unknown
outcome — **and no run proceeds without a deadline** (D65A-4).

Said plainly, what this protects: against an accidentally corrupted or replaced file, and against a party who can
write the file but not act as root. What it does **not**: there is a window between the check and Docker opening
the file for the bind mount, and root (or the Docker daemon's user) can replace the file inside it; whoever can do
that can already do anything to the host. The directory holding the binary should be root-owned and not writable by
the control plane's user, so that the window needs root. This is the same trust level as the rest of the sandbox
code, not more.

Lab scripts and probes that call `DockerSandbox` directly (`NO_OWNER`) opt out *explicitly*
(`deadline_helper=None`), which sets the label `cyberorch.deadline=none`; the reconciler reports such containers
and leaves them (D64 §2.4). There is no silent default to "no deadline".

## 6. The deadline value, and the timeline of a run

`D = B + slack` with **slack = 10 s `[N]`**, chosen, not derived: the control plane's own timeout fires at `B`
and its kill took 0.3 s in the measured run (`run()` returned after 5.3 s on a 5 s budget `[E: E16-C]`), so a
slack of 10 s is far longer than the normal path needs and short enough not to matter when the control plane is
gone. `B` here is the capability's `max_duration_seconds` as the run uses it (the same `plan.max_duration_seconds`
the sandbox already receives `[R]`); the cap `B_cap` of D64 §1.2 is the reconciler's judgement, not the helper's —
the helper must never end a run earlier than its owner expects, so it takes the budget as given.

Timeline, in seconds after the container starts, for a run with budget `B` (the earliest actor wins):

| t | Who | What |
|---|---|---|
| `B − 5` | the tool itself | its soft deadline, where the adapter passes one (`tool_deadline`) |
| `B` | the control plane | `wait(timeout)` fires and `kill()`s (0.3 s measured) → `timed_out=True` |
| `B + 10` | **the helper** | **kills the group, exits 124 — only reached if the control plane is gone or stuck** |
| `B_cap + 60` | the reconciler | kills a container *still running* (D64 §1.2) — now a backstop that should seldom fire |
| `B_cap + 660` | the reconciler | declares the proposal's outcome unknown (a database fact) |

## 7. Exit code 124, and what each outcome becomes

124 is `timeout(1)`'s convention. A tool can exit 124 for its own reasons (E25: `exit 124` returned 124 after 0.2 s),
so the code alone is not the deadline. **The discriminator is the pair (exit 124, the container ran at least
`D − 2 s`)**, measured from Docker's own `State.StartedAt`/`FinishedAt` — a tool cannot forge those, and one that
exits 124 early fails the duration test.

| Situation | Seen by | Becomes |
|---|---|---|
| control plane alive; its own `wait` times out at `B`, it kills | `DockerSandbox.run` | `timed_out=True`, `exit_code=-1` — today's path, unchanged → `FAILED`, evidence from the logs |
| control plane alive but its `kill` failed or was slow; the helper fires at `B + 10` | `DockerSandbox.run` (`wait` returns 124) | the discriminator is true → `timed_out=True`, `exit_code=-1`, the same as above; the stderr line is part of the captured stderr |
| the tool exits 124 on its own, early | `DockerSandbox.run` | a normal non-zero exit → `FAILED`, exit 124 |
| control plane dead; the helper fires | **the reconciler**, finding an exited container with label `cyberorch.run_id`, code 124, and duration ≥ `D − 2 s` | the run is **`unknown_outcome`**, reason `container_deadline` — *not* `failed`: what the tool did before it was killed is unknown, and the control plane never recorded its output (I7). The exited container is kept for the retention window so a person can read its logs (D64-4) |
| the helper cannot execute COMMAND (127 with the helper's message, within seconds of start) | `DockerSandbox.run` | `ContainerStartRefused` (a `NotStarted`), as a missing binary is today, so "never ran" stays "never ran" |
| the helper's own usage error (125) | `DockerSandbox.run` | `FAILED`, exit 125 — unreachable by construction, asserted by the command-assembly test |
| anything else | unchanged | unchanged: the helper passes the tool's exit code through |

One stderr line is added to a deadline run's stderr. The adapters parse stdout for their views; the tests check that
each adapter's `derive_view` is unaffected by the extra stderr line.

## 8. Relation to the reconciler

* **Independent value.** It is useful without the reconciler: an orphaned container ends itself.
* **What it changes for D64.** The container-kill rule `T_kill` stays as the backstop (a helper that did not run, a
  container created without one, the lab scripts); it is expected to fire only for those. The bound
  `B_cap + 660 s` then governs **database state only**, not running processes, and the reconciler's retention
  rules apply to the exited containers the helper leaves.
* **What the reconciler reads from it.** The label `cyberorch.deadline`; the exit code and Docker timestamps of
  exited containers (the table above).
* **What it does not replace.** Orphan proxies (R7), networks (R8), files (R9) and database residue (R1, R3–R6) are
  not containers with a tool deadline. The egress proxy has no deadline of its own; whether it should get one (its
  life is bounded by `stop_egress_proxy`, which the dying control plane never calls) is open (D65A-7).

## 9. What the change touches

| Part | Change |
|---|---|
| `tool_gateway/deadline/` | new: source, `go.mod`, `build.sh`, `SHA256SUMS`, README |
| `tool_gateway/sandbox.py` `run` | wrap the command, add the mount and the label, verify the hash, map exit 124 per §7, type the two new failures; `DeadlineHelperUnavailable` is a new `NotStarted` subclass with a `reason` code |
| `.github/workflows/test.yml` | a Go setup step (pinned) and the build + hash comparison step; the helper must be built before the tests that run containers |
| `tests/test_image_literals.py` | no new image; the CI-built set gains nothing, but a sibling test checks that the helper is built by CI |
| `docs` | ACCEPTANCE: the exposure window of D44-7 no longer depends on the control plane staying alive; `D64` updated to say the helper exists |
| adapters, registry, Rego, `Budget`, the schema | **none** |

## 10. Tests the implementation will need

Each is mutation-checked (`scripts/mutation_check.py`) and the container ones use a real image CI already builds
(`nmap`) or pulls (`python:3.12-slim`), never an image CI does not have (`tests/test_image_literals.py`).

1. **kill -9 backstop (real Docker).** A child process runs `DockerSandbox.run` with a short budget; the test
   `kill -9`s it; the container must be `exited` with 124 by `StartedAt + D + 1 s`. *Mutation:* run without the
   wrapper → red.
2. **normal path unchanged (real Docker).** Control plane alive, budget 5 s, helper `D = 15 s`: `run()` returns at
   about 5 s with `timed_out=True`. *Mutation:* make `D` equal to `B` or less → the race changes the result.
3. **process-tree kill.** A tool that traps TERM and starts a `setsid` grandchild; after the deadline there is no
   survivor (checked through the container's PID namespace, not the host's process list). *Mutation:* kill only the
   child.
4. **stdin passthrough** (web.post uses it) and **exit-code preservation** (0, 3, killed-by-signal).
5. **the 124 discriminator.** A tool that exits 124 immediately is `FAILED` exit 124, not `timed_out`; a real
   deadline is `timed_out`. *Mutation:* test the code only.
6. **hash verification.** A tampered file, a missing file, an unreadable file, a wrong-architecture entry each
   raise `DeadlineHelperUnavailable`, are recorded as "not started" and start no container. *Mutation:* skip the
   comparison.
7. **fail-closed assembly.** An AST/behaviour test that every container started by `DockerSandbox.run` carries the
   wrapper and the label, except where `deadline_helper=None` is passed explicitly, and then the label says `none`.
8. **`noexec` / start refusal** typed as `ContainerStartRefused`.
9. **signal forwarding.** `docker stop` returns in well under the grace period for a tool that handles TERM.
10. **reproducibility.** The CI step of §3.2; a local test that rebuilds in a temporary directory and compares.
11. **derive_view unaffected** by the extra stderr line, per adapter.
12. **the reconciler's reading** of an exited-124 container (with the reconciler's own tests, later).

## 11. Decisions (⚑ = needs your answer)

| # | Question | Recommendation and why |
|---|---|---|
| **D65A-1** ⚑ | Language and pin | **Go**, pinned by `go.mod` + `GOTOOLCHAIN`, hash in `SHA256SUMS`, CI rebuild-and-compare. Same hash on any machine and architecture (to be confirmed by CI, `[N]`); 1.7 MB and a runtime in PID 1. C is smaller (0.7 MB, one thread) but its hash is tied to a compiler and libc. |
| **D65A-2** ⚑ | Delivery | **Bind-mount** the verified file (no image changes, one place to check). Alternative: bake it into the six images (image digest as the pin; more build scripts, drift between images). |
| **D65A-3** | Slack | **10 s `[N]`** beyond `B`; measured normal-path kill latency 0.3 s. |
| **D65A-4** ⚑ | Missing or wrong helper | **Fail closed:** `DeadlineHelperUnavailable(NotStarted)`, nothing runs. Lab scripts opt out explicitly; the label records `none`. |
| **D65A-5** | The exit code | **124**, with the discriminator "exit 124 and ran ≥ `D − 2 s` by Docker's timestamps". |
| **D65A-6** | The mapping | With the control plane alive: the existing `timed_out=True, exit_code=-1` → `FAILED`. With it dead: the reconciler records `unknown_outcome`, reason `container_deadline`, and keeps the exited container. |
| **D65A-7** | Scope of the first version | **Tool runs only.** The egress proxy (R7) is left to the reconciler; a deadline for it (its own budget: the longest run it serves) is a follow-up if you want it. |
| **D65A-8** | Where the binary lives and who may write it | A root-owned directory not writable by the control plane's user; the deployment notes say so and that the filesystem must not be `noexec`. |

## 12. Experiments

All run on this machine (Docker 29.3.1, docker-py 7.2.0, Go 1.24.7, gcc 13.3), with cleanup afterwards (no
container, network or file left; the helper binaries were in the scratch area).

| # | What | Result |
|---|---|---|
| **E5, E16** | (from the D64 document) a tool container with its control plane `kill -9`'d, without and with a first prototype helper | without: running 20.9–25 s later. With a 10 s deadline: exited 124 at 10.7 s; with the control plane alive and a 5 s budget: `run()` returned at 5.3 s, `timed_out=True`; a TERM-trapping tool with a `setsid` grandchild: exited 124 at 4.7 s on a 4 s deadline, no survivor |
| **E15** | Docker's own options; which images have `timeout(1)`; a static helper builds | no maximum lifetime; `timeout` in `semgrep`, `bloodhound`, `browser`, absent from `nmap`, `gitleaks`, `egress-proxy`; static C helper builds |
| **E24** | the helper builds, C and Go | §3.1 |
| **E25** | the helper's behaviour, both builds, through `DockerSandbox.run` and directly | §2 |
| **E26** | the helper on a `noexec` filesystem | the container's `start` is refused before anything runs |

Not run: the Go build on another machine or in CI (reproducibility across toolchains `[N]`); the arm64 binary on
arm64; images other than `nmap`, `gitleaks`, busybox and `python:3.12-slim` with a wrapped command; the helper as
PID 1 under a user-namespace-remapped daemon `[N]`.
