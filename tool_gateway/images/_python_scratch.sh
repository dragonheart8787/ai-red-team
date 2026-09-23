# shellcheck shell=bash
# Stage a self-contained python into a scratch image tree. Sourced, not run.
#
# Two images need this now (the D31 web target and the D34 egress proxy) and
# the logic is not obvious: it took four CI rounds to get right, and each round
# failed as "the container does not serve", which is the most expensive shape
# of failure to diagnose. A second copy would be a second thing to fix every
# time one of them is wrong -- the drift D30 recorded and D33 refused to
# reintroduce. So it lives here once, with the reasons attached.
#
# The no-registry constraint is unchanged: every image in this repository is
# assembled from the operator's own installation and imported directly, so what
# runs in a container is pinned to what was installed rather than to a tag that
# can move.
#
# Expects PY, PYVER, PYLIB and STAGE to be set by the caller.

# Stage every shared library an ELF file needs, at the same absolute path the
# loader will look for it at inside the container.
#
# A statically linked extension module makes grep match nothing, and under
# `set -o pipefail` an empty match is a failed pipeline -- so swallow it, or one
# dependency-free .so aborts the whole build.
scratch_stage_libs_for() {
    ldd "$1" 2>/dev/null | awk '{print $3}' | grep -E '^/' | while read -r lib; do
        mkdir -p "$STAGE$(dirname "$lib")"
        cp -n "$lib" "$STAGE$lib" 2>/dev/null || true
    done || true
    return 0
}

# Copy the interpreter, its stdlib, and everything either of them links against.
scratch_stage_python() {
    cp "$PY" "$STAGE/usr/bin/"
    scratch_stage_libs_for "$PY"
    cp /lib64/ld-linux-x86-64.so.2 "$STAGE/lib64/" 2>/dev/null || true

    cp -r "$PYLIB" "$STAGE/usr/lib/python$PYVER"
    rm -rf "$STAGE/usr/lib/python$PYVER"/{test,idlelib,tkinter,turtledemo,ensurepip}
    find "$STAGE/usr/lib/python$PYVER" -name '__pycache__' -type d \
        -exec rm -rf {} + 2>/dev/null || true

    # The stdlib's C extension modules have their own shared-library
    # dependencies, and `ldd` on the interpreter binary does not see any of
    # them: they are dlopen'd at import time, not linked into the interpreter.
    # Staging only the interpreter's own dependencies produced a container that
    # started and then died on `import http.server` with
    # `ImportError: libz.so.1: cannot open shared object file` -- http.server
    # imports email.utils, which reaches base64, which imports binascii, which
    # is one of these modules and links against libz. Walk them all.
    find "$STAGE/usr/lib/python$PYVER/lib-dynload" -name '*.so' -print0 2>/dev/null \
      | while IFS= read -r -d "" so; do
            scratch_stage_libs_for "$so"
        done

    # Alias to python3 only when the interpreter is not already called that.
    #
    # `ln -sf python3 .../python3` is a symlink pointing at itself, and it
    # replaces the interpreter copy staged above -- the staged interpreter
    # becomes a 7-byte dangling link and the container exits immediately on
    # start. The D11 script this technique came from never hit it because its
    # PY was pinned to python3.11, so the link had a different name to point
    # at; generalising to `command -v python3` introduced the collision, and CI
    # caught it as a web target that would not serve.
    local pybin
    pybin="$(basename "$PY")"
    if [ "$pybin" != "python3" ]; then
        ln -sf "$pybin" "$STAGE/usr/bin/python3"
    fi

    printf 'root:x:0:0:root:/:/bin/sh\n' > "$STAGE/etc/passwd"
    printf 'hosts: files\n' > "$STAGE/etc/nsswitch.conf"
}

# Fail at build time rather than at run time.
#
# A staged tree that cannot execute python produces a container that starts,
# exits immediately, and leaves the tests reporting what looks like a network
# problem. `test -e` follows symlinks, so a dangling or self-referential link
# fails this check.
#
# The second half is the check the run-time-only version could not make.
# Running the staged interpreter on the build host proves nothing about the
# container: the host's loader resolves anything missing from the staged tree
# out of /lib and /usr/lib, so `import http.server` succeeded there while the
# same import died inside the scratch image. Comparing the NEEDED set against
# the staged tree asks the question the container will ask.
scratch_verify_stage() {
    [ -e "$STAGE/usr/bin/python3" ] && [ -x "$STAGE/usr/bin/python3" ] || {
        echo "error: staged /usr/bin/python3 is missing or not executable" >&2
        ls -l "$STAGE/usr/bin/" >&2
        return 1
    }

    local missing=0
    _scratch_check_elf() {
        local elf="$1" line lib
        while IFS= read -r line; do
            case "$line" in
                *"not found"*)
                    echo "unresolved: ${line%% *} (needed by ${elf#"$STAGE"})" >&2
                    missing=1
                    ;;
                *) ;;
            esac
            lib="$(printf '%s\n' "$line" | awk '{print $3}')"
            case "$lib" in
                /*) [ -e "$STAGE$lib" ] || {
                        echo "missing: $lib (needed by ${elf#"$STAGE"})" >&2
                        missing=1
                    } ;;
            esac
        done < <(ldd "$elf" 2>/dev/null)
    }

    local elf so
    for elf in "$STAGE/usr/bin/"*; do
        [ -f "$elf" ] && _scratch_check_elf "$elf"
    done
    for so in "$STAGE/usr/lib/python$PYVER/lib-dynload/"*.so; do
        [ -f "$so" ] && _scratch_check_elf "$so"
    done
    [ "$missing" -eq 0 ] || {
        echo "error: staged tree is not self-contained; the container will fail at import time" >&2
        return 1
    }
}

# The only check that runs where the container runs.
#
# Everything above inspects the staging tree from the build host, whose loader
# and filesystem are exactly what the scratch image does not have; this asks
# the image itself, with no network, whether the interpreter it ships can
# import the modules it is about to work with. It costs one container start and
# it is the check that would have caught both of this technique's failures at
# build time instead of in CI.
scratch_verify_image() {
    local image="$1"
    shift
    # --entrypoint, because one of these images has one.
    #
    # Without it the arguments are *appended* to the image's ENTRYPOINT rather
    # than replacing it, so the proxy image ran its own proxy script with
    # "-c import http.server" as argv and argparse refused the missing
    # --grant. The check then reported "cannot import http.server", which was
    # not true and pointed at the wrong file entirely. A verification step that
    # can report the wrong cause is worth one flag.
    local module
    for module in "$@"; do
        docker run --rm --network none --entrypoint /usr/bin/python3 "$image" \
            -c "import $module" || {
            echo "error: $image cannot import $module inside the container" >&2
            return 1
        }
    done
}
