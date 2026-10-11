#!/usr/bin/env bash
# Install the pinned Rust toolchain into tool_gateway/deadline/.toolchain (D65-A).
#
# Every tarball is checked against TOOLCHAIN.sha256 *before* it is unpacked, and a mismatch deletes
# the file and stops. Nothing here asks rustup, a package manager or a "latest" URL for anything.
# Idempotent: a second run with an unchanged TOOLCHAIN.sha256 does nothing.
#
# CYBERORCH_RUST_HOME   where to install (default: ./.toolchain, git-ignored)
# CYBERORCH_RUST_DIST   where the tarballs are cached (default: $CYBERORCH_RUST_HOME/dist). A cache
#                       is not trusted: its files are verified exactly as downloaded ones are.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
version="1.94.1"
commit="e408947bf"
home="${CYBERORCH_RUST_HOME:-$here/.toolchain}"
dist="${CYBERORCH_RUST_DIST:-$home/dist}"
prefix="$home/prefix"
pins="$here/TOOLCHAIN.sha256"
stamp="$prefix/.installed-$(sha256sum "$pins" | cut -c1-16)"

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "toolchain.sh: the pinned host toolchain is x86_64 Linux; this is $(uname -s) $(uname -m)" >&2
  exit 2
fi

if [ -e "$stamp" ] && [ "$("$prefix/bin/rustc" -V 2>/dev/null | cut -d' ' -f2)" = "$version" ]; then
  exit 0
fi

mkdir -p "$dist"
rm -rf "$prefix" "$home/src"
mkdir -p "$prefix" "$home/src"

grep -v '^#' "$pins" | while read -r want file; do
  [ -n "$file" ] || continue
  path="$dist/$file"
  if [ -f "$path" ] && [ "$(sha256sum "$path" | cut -d' ' -f1)" != "$want" ]; then
    echo "toolchain.sh: cached $file does not match TOOLCHAIN.sha256; discarding it" >&2
    rm -f "$path"
  fi
  if [ ! -f "$path" ]; then
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$path.part" \
      "https://static.rust-lang.org/dist/$file"
    mv "$path.part" "$path"
  fi
  got="$(sha256sum "$path" | cut -d' ' -f1)"
  if [ "$got" != "$want" ]; then
    rm -f "$path"
    echo "toolchain.sh: $file has sha256 $got, expected $want (TOOLCHAIN.sha256). Nothing was installed." >&2
    exit 1
  fi
  echo "verified $file"
  tar -xJf "$path" -C "$home/src"
  (cd "$home/src/${file%.tar.xz}" && ./install.sh --prefix="$prefix" --disable-ldconfig >/dev/null)
done

reported="$("$prefix/bin/rustc" -vV | sed -n 's/^commit-hash: //p')"
case "$reported" in
  "$commit"*) ;;
  *) echo "toolchain.sh: installed rustc is commit $reported, expected $commit" >&2; exit 1 ;;
esac
touch "$stamp"
echo "installed rustc $version ($commit) into $prefix"
