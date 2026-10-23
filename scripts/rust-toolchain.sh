#!/bin/sh
# version: 1
#
# Usage: rust-toolchain.sh <manifest> <version> <host> <prefix> <src>
#
# Installs rustc, cargo and rust-std for <host> from the Rust release that
# <manifest> (channel-rust-<version>.toml, whose signature the caller has
# checked) describes, into <prefix>, and unpacks the release's rust-src
# archive into <src> for the license files of the standard library. Each
# archive is downloaded from the URL in the manifest and checked against the
# SHA-256 listed there. These are the components of rustup's minimal profile.
#
# Prints "<component>: <url> <sha256>" for each archive.
set -eu

manifest=$1
version=$2
host=$3
prefix=$4
src=$5

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# get <table> <key>: a string or boolean value from [<table>] of the manifest.
get() {
  awk -v sec="[$1]" -v key="$2" '
    $0 == sec { s = 1; next }
    /^\[/ { s = 0 }
    s && $1 == key && $2 == "=" { sub(/^[^=]*= *"?/, ""); sub(/"$/, ""); print; exit }
  ' "$manifest"
}

test "$(awk -F ' = ' '$1 == "manifest-version" { print $2 }' "$manifest")" = '"2"' \
  || { echo "$manifest is not a version 2 manifest" >&2; exit 1; }
case $(get pkg.rust version) in
  "$version "*) ;;
  *) echo "$manifest is not Rust $version: $(get pkg.rust version)" >&2; exit 1 ;;
esac
commit=$(get pkg.rust git_commit_hash)
printf '%s\n' "$commit" | grep -Eqx '[0-9a-f]{40}' || { echo "$manifest has no commit" >&2; exit 1; }

# fetch <table> <name>: download, check and unpack one archive into $work/<name>.
fetch() {
  test "$(get "$1" available)" = true || { echo "[$1] is not available" >&2; exit 1; }
  url=$(get "$1" xz_url)
  sha256=$(get "$1" xz_hash)
  case $url in
    https://static.rust-lang.org/dist/*/"$2-$version"*.tar.xz) ;;
    *) echo "unexpected URL in [$1]: $url" >&2; exit 1 ;;
  esac
  printf '%s\n' "$sha256" | grep -Eqx '[0-9a-f]{64}' || { echo "[$1] has no SHA-256" >&2; exit 1; }
  curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 -o "$work/$2.tar.xz" "$url"
  echo "$sha256  $work/$2.tar.xz" | sha256sum -c - > /dev/null \
    || { echo "$url does not match the SHA-256 in the manifest" >&2; exit 1; }
  mkdir "$work/$2"
  tar -xJf "$work/$2.tar.xz" -C "$work/$2" --strip-components 1
  rm "$work/$2.tar.xz"
  echo "$2: $url $sha256"
}

# Each archive lists its components, and each component directory is laid out
# relative to the prefix. install.sh, a bash script, would copy them the same
# way.
mkdir -p "$prefix"
for name in rustc cargo rust-std; do
  fetch "pkg.$name.target.$host" "$name"
  while read -r component; do
    cp -R "$work/$name/$component/." "$prefix/"
  done < "$work/$name/components"
  rm -f "$prefix/manifest.in"
  rm -rf "${work:?}/$name"
done
fetch 'pkg.rust-src.target."*"' rust-src
mkdir -p "$src"
cp -R "$work/rust-src/." "$src/"
test "$(cat "$src/git-commit-hash")" = "$commit" || { echo "rust-src is not commit $commit" >&2; exit 1; }

"$prefix/bin/rustc" -vV > "$work/rustc"
for line in "release: $version" "host: $host" "commit-hash: $commit"; do
  grep -Fqx "$line" "$work/rustc" || { cat "$work/rustc" >&2; echo "rustc: expected $line" >&2; exit 1; }
done
"$prefix/bin/cargo" -V > "$work/cargo"
grep -q "^cargo $version " "$work/cargo" || { cat "$work/cargo" >&2; echo "cargo is not $version" >&2; exit 1; }
