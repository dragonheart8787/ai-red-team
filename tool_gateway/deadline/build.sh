#!/usr/bin/env bash
# Build cyberorch-deadline (D65-A): pinned toolchain, vendored libc, offline, --locked.
#
#   ./build.sh                build both architectures into bin/
#   ./build.sh x86_64         build one
#   ./build.sh --check [ARCH] build, then compare with SHA256SUMS; exit 1 and print both hashes if
#                             any differs. It never rewrites SHA256SUMS: a changed pin is a commit.
#
# CYBERORCH_DEADLINE_OUT   where bin/ and target/ go (default: next to this script). The mutation
#                          checks build a deliberately broken copy of the source somewhere else.
#
# Everything that could change the bytes is fixed here: the compiler (toolchain.sh), the one
# dependency (vendor/, Cargo.lock), the linker (rust-lld, shipped with that compiler -- not the
# host's), the source path (remapped), and the environment (cleared of CARGO_*/RUSTFLAGS).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check=0
if [ "${1:-}" = "--check" ]; then check=1; shift; fi
archs=("$@")
[ "${#archs[@]}" -gt 0 ] || archs=(x86_64 aarch64)

"$here/toolchain.sh"
home="${CYBERORCH_RUST_HOME:-$here/.toolchain}"
prefix="$home/prefix"
export PATH="$prefix/bin:/usr/bin:/bin"
for var in $(env | sed -n 's/^\(CARGO_[A-Z_]*\|RUSTFLAGS\|RUSTC[A-Z_]*\|RUSTUP_[A-Z_]*\)=.*/\1/p'); do unset "$var"; done
export CARGO_HOME="$home/cargo-home"
mkdir -p "$CARGO_HOME"

# Not the repository's absolute path, not a developer's home directory: panics and debug paths
# that reach the binary then read the same on every machine.
remap="--remap-path-prefix=$here=/build/cyberorch-deadline --remap-path-prefix=$prefix=/toolchain"
out="${CYBERORCH_DEADLINE_OUT:-$here}"
rm -rf "$out/bin"; mkdir -p "$out/bin"
export CARGO_TARGET_DIR="$out/target"

for arch in "${archs[@]}"; do
  triple="$arch-unknown-linux-musl"
  upper="$(echo "$triple" | tr 'a-z-' 'A-Z_')"
  export "CARGO_TARGET_${upper}_LINKER=rust-lld"
  export "CARGO_TARGET_${upper}_RUSTFLAGS=$remap -C linker-flavor=ld.lld -C target-feature=+crt-static"
  (cd "$here" && cargo build --release --locked --offline --target "$triple")
  install -m 0755 "$CARGO_TARGET_DIR/$triple/release/cyberorch-deadline" \
    "$out/bin/cyberorch-deadline-linux-$arch"
  echo "built bin/cyberorch-deadline-linux-$arch  $(sha256sum "$out/bin/cyberorch-deadline-linux-$arch" | cut -d' ' -f1)"
done

if [ "$check" = 1 ]; then
  status=0
  for arch in "${archs[@]}"; do
    name="cyberorch-deadline-linux-$arch"
    want="$(awk -v n="$name" '$2 == n {print $1}' "$here/SHA256SUMS")"
    got="$(sha256sum "$out/bin/$name" | cut -d' ' -f1)"
    if [ -z "$want" ]; then
      echo "MISMATCH $name: no entry in SHA256SUMS (built $got)" >&2; status=1
    elif [ "$want" != "$got" ]; then
      echo "MISMATCH $name: SHA256SUMS says $want, this build is $got" >&2; status=1
    else
      echo "ok $name $got"
    fi
  done
  exit $status
fi
