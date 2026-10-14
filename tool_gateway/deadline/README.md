# cyberorch-deadline

The program a tool container runs as PID 1 (D65-A, `docs/D65A_CONTAINER_DEADLINE_DESIGN.md`). It starts the
tool, waits for it, and ends the container when a wall-clock deadline passes, so a tool container does not
outlive a control plane that died.

    cyberorch-deadline SECONDS -- COMMAND [ARGS...]

| Outcome | Exit status |
|---|---|
| COMMAND ended first | its own exit code; `128 + N` if it died of signal `N` |
| the deadline passed first | **124**, one line `cyberorch-deadline: expired after Ns` on stderr; COMMAND's process group gets `SIGKILL`, and PID 1 exiting ends every other process in the container |
| usage error (`SECONDS` not 1..86400, no `--`, no command) | 125 |
| COMMAND cannot be executed | 127, a line `cyberorch-deadline: cannot execute COMMAND: reason` on stderr; the tool never ran |

As PID 1 it reaps every orphan re-parented to it, and forwards `SIGTERM SIGINT SIGHUP SIGQUIT SIGUSR1 SIGUSR2`
to COMMAND so that `docker stop` reaches the tool. 124 is `timeout(1)`'s convention and a tool can exit 124 for
its own reasons; the sandbox therefore treats it as the deadline only when Docker's own timestamps show the
container ran at least `D - 2` seconds (`tool_gateway/sandbox.py`).

## Layout and what is pinned

| File | What it pins |
|---|---|
| `src/main.rs` | the program |
| `Cargo.toml`, `Cargo.lock` | one dependency, `libc 0.2.190`, with its registry checksum |
| `vendor/`, `.cargo/config.toml` | the source of `libc`, in the repository; the build is offline and `--locked`, and cargo checks every vendored file against `vendor/libc/.cargo-checksum.json` |
| `rust-toolchain.toml` | the compiler version, for a developer using rustup by hand |
| `TOOLCHAIN.sha256` | sha256 of the five tarballs of Rust 1.94.1 the build uses (compiler, cargo, host std, two musl std) |
| `toolchain.sh` | downloads exactly those tarballs, **verifies each sha256 before unpacking**, installs them under `.toolchain/`, and checks that `rustc` reports commit `e408947bf` |
| `build.sh` | the one build command (`--release --locked --offline`, musl static, `rust-lld`, remapped paths, a cleared environment) |
| `SHA256SUMS` | the expected sha256 of the built binary per architecture. **Committed.** |

The sandbox (`tool_gateway/sandbox.py`) recomputes the sha256 of the file it is about to mount before **every**
run and refuses to start a container if it is missing, unreadable, not executable or not equal to `SHA256SUMS`.
CI builds from scratch and compares with `SHA256SUMS`; a mismatch fails the job and the expected value is **not**
updated to match.

## Building

    ./build.sh            # both architectures into bin/ (x86_64 Linux host)
    ./build.sh --check    # the same, then compare with SHA256SUMS (what CI runs)

Changing `src/main.rs`, `Cargo.lock`, `vendor/`, the build flags or the toolchain changes the hash. The commit
that does that updates `SHA256SUMS` by hand (`cd bin && sha256sum cyberorch-deadline-linux-*`), so a reviewer sees
the source change and the new pin together.

## Where the built file must live

Root-owned, in a directory the control plane's user cannot write to, on a filesystem not mounted `noexec`
(a `noexec` mount makes Docker refuse to start the container; the sandbox reports that as `NotStarted`).
Verification protects against an accidentally corrupted or replaced file and against a party who can write the
file but is not root; it does not close the window between the check and Docker opening the file, which only a
root-owned directory does.
