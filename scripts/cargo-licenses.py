# version: 3
"""Collect the license files of a Rust program and check its license label.

Usage:
  python3 -I cargo-licenses.py --binary <file> [--binary <file> ...]
      --workspace <dir> --package-yml <file> --extra <dir> --rust-src <dir>
      --licenses <dir> --sources <dir>

The crates are those that cargo-auditable recorded in the .dep-v0 section of
each binary. Their license expressions and directories come from
`cargo metadata --frozen` for the host platform, so the crates must have
been fetched already; nothing is downloaded.

For each crates.io crate, the license files at the top of the crate (names
starting with COPYING, COPYRIGHT, NOTICE or UNLICENSE, or containing LICENSE
or LICENCE, in any case), its REUSE LICENSES/ directory and its license-file
go to <licenses>/crates/<name>-<version>/. Workspace members with license
files of their own get them in <licenses>/workspace/<name>/.

<extra> holds what crates lack: <extra>/<name>-<version>/ or, to keep it
across versions, <extra>/<name>/. Its files are added to the crate's. A file
EXPRESSION in it gives the license of a crate that has only a license-file,
and must equal the crate's license expression when the crate has one. A
directory without a version must have an EXPRESSION file, so that it is
looked at again when the license changes. When a crate's expression leaves
something out, such as data it compiles in under other terms, a file
DECLARED next to EXPRESSION holds the crate's own expression, which it must
equal, and EXPRESSION the one to use instead. Neither file is copied. A
crate uses its versioned directory if there is one, and the directory
without a version otherwise. A crate with a `links` key builds or links
native code, which its own license files may not cover. When it is linked
into a binary, it needs a directory here, or a line in
<extra>/native-covered, either `<name>` or `<name>@<version>`, optionally
followed by `: <path>` to copy a license file from inside the crate. Every
directory and line must be used by a crate the binaries record, and a crate
without any license file stops the build.

The license guard: package.yml's `license:` line gives the allowed terms (an
identifier, or one with WITH and its exception). A crate linked into a binary
passes when one choice of its expression uses only those terms; build-time
crates (proc macros and build scripts) are not linked and are not checked. A
crate that is available only under MPL, EPL or CDDL has its .crate file
copied to <sources>/, checked against Cargo.lock. A crate that needs a GPL,
LGPL or AGPL term passes only when the label has that term.

A label with a GPL, LGPL or AGPL term puts the binaries as a whole under
that license, and their corresponding source includes every crate compiled
into them. The .crate file of every crates.io crate that the binaries record,
build-time crates included, is then copied to <sources>/, checked against
Cargo.lock.

The Rust standard library is linked in too. Its license files are copied from
<rust-src> (the unpacked rust-src component) to <licenses>/rust/, without
LLVM's libunwind when every binary is linked dynamically. Every /rustc/<commit>/
path in the binaries must name the commit of <rust-src>, every /rust/deps/
path a crate that the standard library vendors, and every crates.io source
path a recorded crate.

Prints "crate: <name> <version> <source> <kind> <expression>" for each crate
and "source: <url>" for each .crate file copied; also writes
<licenses>/crates/CRATES.tsv.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tomllib
import zlib
from pathlib import Path

CRATES_IO = {"registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"}
WEAK_COPYLEFT = ("mpl-", "epl-", "cddl-")
STRONG_COPYLEFT = ("gpl-", "lgpl-", "agpl-")
RUST_SRC_ROOT = "rust-src/lib/rustlib/src/rust/"
LIBUNWIND = "src/llvm-project/libunwind/"
MAX_CHOICES = 4096

errors: list[str] = []


def fail(message: str) -> None:
    errors.append(message)


def stop() -> None:
    if errors:
        for message in errors:
            print(f"cargo-licenses.py: {message}", file=sys.stderr)
        sys.exit(1)


def is_license_name(name: str) -> bool:
    upper = name.upper()
    if upper.endswith(".RS"):
        return False
    if upper.startswith(("COPYING", "COPYRIGHT", "NOTICE", "UNLICENSE")):
        return True
    return "LICENSE" in upper or "LICENCE" in upper


# ELF


def elf_read(path: Path) -> tuple[dict[str, bytes], bool, bytes]:
    """The sections named .dep-v0, whether the file has an interpreter, and its bytes."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SystemExit(f"cargo-licenses.py: {path} is not a 64-bit little-endian ELF file")
    phoff, shoff = struct.unpack_from("<QQ", data, 0x20)
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 0x36)
    interp = any(struct.unpack_from("<I", data, phoff + i * phentsize)[0] == 3 for i in range(phnum))
    headers = [struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize) for i in range(shnum)]
    names_offset, names_size = headers[shstrndx][4], headers[shstrndx][5]
    names = data[names_offset : names_offset + names_size]
    sections = {}
    for name, kind, _, _, offset, size in headers:
        label = names[name : names.index(b"\0", name)].decode("ascii", "replace")
        if label == ".dep-v0" and kind != 8:
            sections[label] = data[offset : offset + size]
    return sections, interp, data


def audit_packages(path: Path, sections: dict[str, bytes]) -> list[dict]:
    if ".dep-v0" not in sections:
        raise SystemExit(f"cargo-licenses.py: {path} has no .dep-v0 section; build it with cargo auditable")
    info = json.loads(zlib.decompress(sections[".dep-v0"]))
    packages = info.get("packages")
    if not isinstance(packages, list) or not packages:
        raise SystemExit(f"cargo-licenses.py: the .dep-v0 section of {path} lists no packages")
    return packages


# SPDX expressions


def tokens(expression: str) -> list[str]:
    out = []
    for token in re.findall(r"\(|\)|/|[^\s()/]+", expression):
        upper = token.upper()
        out.append(upper if upper in ("AND", "OR", "WITH") else token)
    return out


def parse(expression: str):
    """A tree of ("or", ...), ("and", ...) and ("leaf", term) nodes; "/" counts as OR."""
    items = tokens(expression)
    pos = 0

    def peek():
        return items[pos] if pos < len(items) else None

    def take(expected=None):
        nonlocal pos
        token = peek()
        if token is None or (expected and token != expected):
            raise ValueError(f"expected {expected or 'a license'} at {' '.join(items[pos:]) or 'the end'}")
        pos += 1
        return token

    def any_of():
        nodes = [all_of()]
        while peek() in ("OR", "/"):
            take()
            nodes.append(all_of())
        return nodes[0] if len(nodes) == 1 else ("or", *nodes)

    def all_of():
        nodes = [term()]
        while peek() == "AND":
            take()
            nodes.append(term())
        return nodes[0] if len(nodes) == 1 else ("and", *nodes)

    def term():
        if peek() == "(":
            take("(")
            node = any_of()
            take(")")
            return node
        name = take()
        if name in ("AND", "OR", "WITH", "/", ")"):
            raise ValueError(f"unexpected {name}")
        if peek() == "WITH":
            take()
            exception = take()
            if exception in ("AND", "OR", "WITH", "/", "(", ")"):
                raise ValueError(f"unexpected {exception}")
            return ("leaf", f"{name} WITH {exception}")
        return ("leaf", name)

    node = any_of()
    if peek() is not None:
        raise ValueError(f"unexpected {' '.join(items[pos:])}")
    return node


def key(term: str) -> str:
    return " ".join(term.split()).casefold()


def leaves(node) -> list[str]:
    if node[0] == "leaf":
        return [node[1]]
    return [leaf for child in node[1:] for leaf in leaves(child)]


def choices(node) -> list[frozenset[str]]:
    """Each way to satisfy the expression, as the set of terms it uses."""
    if node[0] == "leaf":
        return [frozenset([node[1]])]
    if node[0] == "or":
        out = []
        for child in node[1:]:
            out += choices(child)
    else:
        out = [frozenset()]
        for child in node[1:]:
            out = [a | b for a in out for b in choices(child)]
            if len(out) > MAX_CHOICES:
                raise ValueError("too many combinations")
    return list(dict.fromkeys(out))


def copyleft(choice: frozenset[str], prefixes: tuple[str, ...]) -> bool:
    return any(key(term).split(" with ")[0].startswith(prefixes) for term in choice)


# Files


def readable(path: Path, root: Path) -> bool:
    """A regular file that resolves to a path inside root, so a symlink cannot copy files from elsewhere."""
    return path.is_file() and path.resolve().is_relative_to(root.resolve())


def copy_license_files(directory: Path, root: Path, dest: Path, license_file: str | None) -> None:
    for entry in sorted(directory.iterdir()):
        if entry.name == "LICENSES" and entry.is_dir():
            for f in sorted(entry.rglob("*")):
                if readable(f, root):
                    target = dest / "LICENSES" / f.relative_to(entry)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(f, target)
        elif readable(entry, root) and is_license_name(entry.name):
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(entry, dest / entry.name)
    if license_file:
        source = directory / license_file
        if not readable(source, root):
            fail(f"{directory}: license-file {license_file} is missing or outside {root}")
            return
        dest.mkdir(parents=True, exist_ok=True)
        if not (dest / source.name).exists():
            shutil.copyfile(source, dest / source.name)


def copy_tree(source: Path, dest: Path) -> None:
    for f in sorted(source.rglob("*")):
        if f.is_file() and f.relative_to(source).as_posix() not in ("EXPRESSION", "DECLARED"):
            target = dest / f.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, target)


def has_files(directory: Path) -> bool:
    return directory.is_dir() and any(f.is_file() for f in directory.rglob("*"))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def run(*command: str) -> str:
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"cargo-licenses.py: {' '.join(command)} failed:\n{result.stderr}")
    return result.stdout


def label_terms(package_yml: Path) -> dict[str, str]:
    lines = [line for line in package_yml.read_text(encoding="utf-8").splitlines() if line.startswith("license:")]
    if len(lines) != 1:
        raise SystemExit(f"cargo-licenses.py: {package_yml} must have one top-level license: line")
    value = lines[0].removeprefix("license:").strip().strip("'\"")
    try:
        return {key(term): term for term in leaves(parse(value))}
    except ValueError as e:
        raise SystemExit(f"cargo-licenses.py: {package_yml}: cannot read license '{value}': {e}") from None


def native_entries(path: Path) -> list[tuple[str, str | None, str | None, str]]:
    entries = []
    if not path.is_file():
        return entries
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        crate, _, inner = line.partition(":")
        name, _, version = crate.strip().partition("@")
        inner = inner.strip() or None
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or (version and not re.fullmatch(r"[0-9A-Za-z.+-]+", version)):
            fail(f"{path}:{number}: expected <name>[@<version>][: <path>], got {line!r}")
            continue
        if inner and (inner.startswith("/") or ".." in Path(inner).parts):
            fail(f"{path}:{number}: {inner} must be a path inside the crate")
            continue
        entries.append((name, version or None, inner, f"{path.name}:{number}"))
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--binary", action="append", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--package-yml", required=True, type=Path)
    parser.add_argument("--extra", required=True, type=Path)
    parser.add_argument("--rust-src", required=True, type=Path)
    parser.add_argument("--licenses", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    args = parser.parse_args()

    allowed = label_terms(args.package_yml)
    order = {k: i for i, k in enumerate(allowed)}
    all_sources = any(copyleft(frozenset([term]), STRONG_COPYLEFT) for term in allowed.values())

    # Crates recorded in the binaries: one entry per name, version and source;
    # a crate is runtime if any binary links it.
    recorded: dict[tuple[str, str, str], str] = {}
    dynamic = True
    contents = []
    for binary in args.binary:
        sections, interp, data = elf_read(binary)
        dynamic = dynamic and interp
        contents.append((binary, data))
        for p in audit_packages(binary, sections):
            name, version, source = p.get("name"), p.get("version"), p.get("source")
            if not all(isinstance(v, str) and v for v in (name, version, source)):
                raise SystemExit(f"cargo-licenses.py: {binary}: unexpected .dep-v0 entry {p}")
            kind = p.get("kind", "runtime")
            if kind not in ("runtime", "build"):
                raise SystemExit(f"cargo-licenses.py: {binary}: {name} {version} has kind {kind!r}")
            k = (name, version, source)
            recorded[k] = "runtime" if "runtime" in (kind, recorded.get(k)) else "build"
    for name, version, source in sorted(recorded):
        if source not in ("crates.io", "local"):
            fail(f"{name} {version} comes from {source}, not from crates.io or the workspace")
    stop()

    host = next(
        (line.split(": ", 1)[1] for line in run(os.environ.get("RUSTC", "rustc"), "-vV").splitlines() if line.startswith("host: ")),
        None,
    )
    if not host:
        raise SystemExit("cargo-licenses.py: rustc -vV names no host")
    metadata = json.loads(
        run(
            os.environ.get("CARGO", "cargo"), "metadata", "--frozen", "--format-version", "1", "--all-features",
            "--filter-platform", host, "--manifest-path", str(args.workspace / "Cargo.toml"),
        )
    )
    meta: dict[tuple[str, str, str], dict] = {}
    for p in metadata["packages"]:
        source = "local" if p.get("source") is None else "crates.io" if p["source"] in CRATES_IO else p["source"]
        meta[(p["name"], p["version"], source)] = p
    lock = tomllib.loads((args.workspace / "Cargo.lock").read_text(encoding="utf-8"))
    checksums = {
        (p["name"], p["version"]): p.get("checksum")
        for p in lock.get("package", [])
        if p.get("source") in CRATES_IO
    }

    extra_dirs = {d.name: d for d in sorted(args.extra.iterdir()) if d.is_dir()} if args.extra.is_dir() else {}
    if args.extra.is_dir():
        for f in sorted(args.extra.iterdir()):
            if not f.is_dir() and f.name != "native-covered":
                fail(f"{f}: only crate directories and native-covered belong in {args.extra}")
    natives = native_entries(args.extra / "native-covered")
    used_dirs: set[str] = set()
    used_natives: set[str] = set()

    crates_dir = args.licenses / "crates"
    crates_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    sources = []
    for name, version, source in sorted(recorded, key=lambda k: (k[0].casefold(), k)):
        kind = recorded[(name, version, source)]
        p = meta.get((name, version, source))
        if p is None:
            fail(f"{name} {version} ({source}) is in .dep-v0 but not in cargo metadata")
            continue
        directory = Path(p["manifest_path"]).parent
        extra = extra_dirs.get(f"{name}-{version}") or extra_dirs.get(name)
        if extra is not None:
            used_dirs.add(extra.name)
            if extra.name == name and not (extra / "EXPRESSION").is_file():
                fail(f"{extra}: a directory without a version needs an EXPRESSION file with the crate's license expression")
        dest = crates_dir / f"{name}-{version}" if source == "crates.io" else args.licenses / "workspace" / name

        expression = p.get("license")
        given = (extra / "EXPRESSION").read_text(encoding="utf-8").strip() if extra and (extra / "EXPRESSION").is_file() else None
        declared = (extra / "DECLARED").read_text(encoding="utf-8").strip() if extra and (extra / "DECLARED").is_file() else None
        if declared is not None:
            if given is None:
                fail(f"{extra}/DECLARED needs an EXPRESSION file next to it")
            elif expression is None or " ".join(declared.split()) != " ".join(expression.split()):
                fail(f"{name} {version} is now '{expression}', but {extra}/DECLARED says '{declared}'; check the files there and update it")
            else:
                expression = given
        elif given is not None and expression is not None and " ".join(given.split()) != " ".join(expression.split()):
            fail(f"{name} {version} is now '{expression}', but {extra}/EXPRESSION says '{given}'; check the files there and update it")
        expression = expression or given

        root = directory if source == "crates.io" else args.workspace
        copy_license_files(directory, root, dest, p.get("license_file"))
        if extra is not None:
            copy_tree(extra, dest)

        covering = [e for e in natives if e[0] == name and e[1] in (None, version)]
        for _, _, inner, where in covering:
            used_natives.add(where)
            if inner:
                if not readable(directory / inner, root):
                    fail(f"{where}: {name} {version} has no {inner}")
                    continue
                target = dest / inner
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(directory / inner, target)
        if p.get("links") and kind == "runtime" and extra is None and not covering:
            fail(
                f"{name} {version} builds or links native code (links = {p['links']!r}): add its license files "
                f"to {args.extra}/{name}/ or list it in {args.extra}/native-covered"
            )

        if source == "crates.io" and not has_files(dest):
            fail(f"{name} {version} has no license file; add it to {args.extra}/{name}-{version}/")

        terms = "-"
        weak = False
        if expression is None:
            if source == "crates.io" or kind == "runtime":
                fail(f"{name} {version} has no license expression; add {args.extra}/{name}-{version}/EXPRESSION")
            expression = "-"
        elif kind == "runtime":
            try:
                options = choices(parse(expression))
            except ValueError as e:
                fail(f"{name} {version}: cannot read '{expression}': {e}")
                options = []
            covered = [c for c in options if all(key(t) in allowed for t in c)]
            covered.sort(key=lambda c: (copyleft(c, STRONG_COPYLEFT), copyleft(c, WEAK_COPYLEFT), len(c), sorted(order[key(t)] for t in c)))
            if options and not covered:
                fail(f"{name} {version}: '{expression}' is not covered by package.yml license")
            elif covered:
                best = covered[0]
                terms = " AND ".join(sorted(best, key=lambda t: order[key(t)]))
                weak = copyleft(best, WEAK_COPYLEFT)
        if source == "crates.io" and (all_sources or weak):
            sources.append((name, version, directory))
        rows.append((name, version, source, kind, expression, terms))

    for name in sorted(set(extra_dirs) - used_dirs):
        fail(f"{args.extra / name}: no crate in the binaries uses this directory")
    for entry in natives:
        if entry[3] not in used_natives:
            fail(f"{entry[3]}: no crate in the binaries matches {entry[0]}{'@' + entry[1] if entry[1] else ''}")
    stop()

    for name, version, directory in sources:
        index_dir = directory.parent
        crate = index_dir.parent.parent / "cache" / index_dir.name / f"{name}-{version}.crate"
        expected = checksums.get((name, version))
        if not crate.is_file() or not expected or sha256(crate) != expected:
            fail(f"{crate} is missing or does not match the checksum in Cargo.lock")
            continue
        args.sources.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(crate, args.sources / crate.name)

    # The Rust standard library.
    rust_dest = args.licenses / "rust"
    commit_file = args.rust_src / "git-commit-hash"
    commit = commit_file.read_text(encoding="ascii").strip() if commit_file.is_file() else ""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit(f"cargo-licenses.py: {commit_file} has no commit")
    vendor = args.rust_src / RUST_SRC_ROOT / "library" / "vendor"
    for path in sorted(args.rust_src.rglob("*")):
        if not path.is_file() or not is_license_name(path.name):
            continue
        rel = path.relative_to(args.rust_src).as_posix().removeprefix(RUST_SRC_ROOT)
        if dynamic and rel.startswith(LIBUNWIND):
            continue
        target = rust_dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    required = ["COPYRIGHT", "LICENSE-APACHE", "LICENSE-MIT"] + ([] if dynamic else [LIBUNWIND + "LICENSE.TXT"])
    for rel in required:
        if not (rust_dest / rel).is_file():
            fail(f"{args.rust_src} has no {rel}")

    names = {f"{n}-{v}" for n, v, s in recorded if s == "crates.io"}
    for binary, data in contents:
        commits = set(re.findall(rb"/rustc/([0-9a-f]{40})/", data))
        if commits != {commit.encode()}:
            found = ", ".join(sorted(c.decode() for c in commits)) or "none"
            fail(f"{binary} was not built with the standard library of commit {commit} (it names {found})")
        for dep in sorted(set(re.findall(rb"/rust/deps/([A-Za-z0-9_.+-]+)/", data))):
            if not (vendor / dep.decode()).is_dir():
                fail(f"{binary} names /rust/deps/{dep.decode()}/, which the standard library does not vendor")
        for crate in sorted(set(re.findall(rb"/registry/src/[A-Za-z0-9_.-]+/([A-Za-z0-9_.+-]+)/", data))):
            if crate.decode() not in names:
                fail(f"{binary} names the source of {crate.decode()}, which .dep-v0 does not record")
    stop()

    for top in (args.licenses, args.sources):
        if not top.exists():
            continue
        for path in [top, *top.rglob("*")]:
            if path.is_dir():
                path.chmod(0o755)
            else:
                path.chmod(0o644)
                if path.stat().st_size == 0:
                    fail(f"{path} is empty")
    stop()

    with (crates_dir / "CRATES.tsv").open("w", encoding="utf-8") as f:
        f.write("name\tversion\tsource\tkind\texpression\tterms\n")
        for row in rows:
            f.write("\t".join(row) + "\n")
    (crates_dir / "CRATES.tsv").chmod(0o644)
    for name, version, source, kind, expression, _ in rows:
        print(f"crate: {name} {version} {source} {kind} {expression}")
    for name, version, _ in sources:
        print(f"source: https://static.crates.io/crates/{name}/{name}-{version}.crate")


if __name__ == "__main__":
    main()
