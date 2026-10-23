# yara-x

Container images with [YARA-X](https://virustotal.github.io/yara-x/), the successor of YARA that VirusTotal rewrote in Rust. A YARA rule describes a family of files by text, hex and regular expression strings and a condition, and `yr scan` reports which rules match each file it scans. The same `yr` program also compiles rules ahead of time, formats rule files and shows what its modules read from a file. The images build `yr` from the source of each YARA-X release with a pinned Rust release. The default image also contains 7-Zip, for unpacking the encrypted archives that samples are usually shared in. The images are built on Ubuntu and Alpine for `linux/amd64` and `linux/arm64`, and rebuilt when YARA-X publishes a release and when the base image changes.

YARA-X reads most YARA rules without changes, but it rejects some and handles some cases differently; upstream lists them in [Differences with YARA](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/). YARA itself, which upstream keeps in maintenance mode, is published by this project as `ghcr.io/randomcontainers/yara` (see [randomcontainers/yara](https://github.com/randomcontainers/yara)).

This is an unofficial build, not affiliated with or endorsed by VirusTotal. Report problems with the image in this repository and YARA-X bugs at [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x/issues).

## Quick start

Scan every file under `samples` with the rules in `rules.yar`:

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/work:ro" \
  ghcr.io/randomcontainers/yara-x scan -r rules.yar samples
```

`yr scan` prints one line per matching rule and file, `<rule> <file>`. Without `-r` it scans only the files directly in a directory; `-r` follows subdirectories up to 1000 levels deep, and `--recursive=<depth>` sets another limit. The entrypoint runs `yr` under `tini` in `/work`, so paths are relative to the directory you mount, and the image's default command is `--help`. A few more commands:

```sh
# Also print each matching string with its offset and length, such as 0x1a:8:$w: <data>
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work:ro" \
  ghcr.io/randomcontainers/yara-x scan -s rules.yar sample.bin

# Print the namespace, tags and metadata, and only the rules tagged "banker"
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work:ro" \
  ghcr.io/randomcontainers/yara-x scan -e -g -m -t banker rules.yar sample.bin

# Scan the files listed in files.txt, one path per line, with 4 threads
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work:ro" \
  ghcr.io/randomcontainers/yara-x scan -p 4 --scan-list rules.yar files.txt

# Write one JSON object per matching file
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work:ro" \
  ghcr.io/randomcontainers/yara-x scan -o ndjson rules.yar samples
```

`-n` prints the rules that did not match and `-c` the number of rules that matched in each file. `-d` sets an external variable to a JSON value, so a string needs quotes inside the shell's: `-d 'filename="invoice.pdf"'`, `-d size=1024`. `-x cuckoo=report.json` passes a Cuckoo sandbox report to the `cuckoo` module. `yr help scan` lists every option, and the [YARA-X documentation](https://virustotal.github.io/yara-x/) describes the rule language, the modules and the [commands](https://virustotal.github.io/yara-x/docs/cli/commands/).

The images contain no rules. Rule collections are published under their own licenses; mount the ones you use.

## Working with rule files

```sh
# Format rule files in place; with -c, list the files that need it and exit with 1
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" \
  ghcr.io/randomcontainers/yara-x fmt rules.yar

# Apply the changes that warnings suggest, such as "none of them" for "0 of them"
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" \
  ghcr.io/randomcontainers/yara-x fix warnings rules.yar

# Show the data that the pe module reads from a file, as YAML or with -o json as JSON
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work:ro" \
  ghcr.io/randomcontainers/yara-x dump -m pe sample.exe
```

`yr fmt` aligns metadata and strings, indents with two spaces and exits with 1 when it changed a file. A [config file](https://virustotal.github.io/yara-x/docs/cli/config-file/) passed with `yr --config <file>` changes the format and turns warnings off. `yr fix encoding` converts rule files to UTF-8, `yr deps` shows which rules and modules each rule depends on, and `yr completion bash` prints a completion script.

## Compiled rules

`yr compile` compiles one or more rule files into a single file that `yr scan -C` loads without parsing the sources again, which saves time with large rule sets:

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" \
  ghcr.io/randomcontainers/yara-x compile -o rules.yarc rules.yar
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work:ro" \
  ghcr.io/randomcontainers/yara-x scan -C -r rules.yarc samples
```

A compiled file loads only in a YARA-X build that writes the same format, and YARA cannot load it, so keep the sources and compile them again after an update. Load compiled rules only from files you compiled yourself: upstream warns against loading compiled rules that someone else produced or could have changed. For rules from other people, get the source and compile it.

## Modules

| Module | What it reads |
|---|---|
| `pe` | Windows executables and DLLs, including Authenticode signatures |
| `elf` | Linux and other ELF executables and libraries |
| `macho` | Mach-O executables and libraries, as used on macOS and iOS |
| `dex` | Android DEX files |
| `dotnet` | .NET assemblies |
| `lnk` | Windows shortcut files |
| `crx` | Chrome extension packages |
| `zip` | The entries of a zip file, with their paths, sizes and compression methods |
| `hash` | MD5, SHA-1 and SHA-256 hashes and CRC32 checksums of the file, a range of it or a string |
| `math` | Entropy and other statistics of the file or a range of it |
| `cuckoo` | A Cuckoo sandbox JSON report, passed with `-x cuckoo=report.json` |
| `time`, `string`, `console` | The current time, string conversions, and `console.log()` for debugging rules, which writes to standard error |
| `vt` | Data that only VirusTotal's own scans provide; empty here |

These are the modules of upstream's default build. The `magic` module, which identifies file types with libmagic, is not built, unlike in the YARA image. YARA-X cannot scan the memory of running processes.

## Archives (default image)

YARA-X does not look inside archives: a zip or 7z file is scanned as the compressed bytes it contains, and the `zip` module lists only its entries. Samples are usually shared in zip files encrypted with the password `infected`, so unpack them first with `7zz` from the default image:

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/work" --entrypoint sh \
  ghcr.io/randomcontainers/yara-x -c '7zz x -pinfected -osamples samples.zip > /dev/null && yr scan -r rules.yar samples'
```

`7zz x -so` writes the extracted files to standard output instead, one after another, so name the one file you want: `7zz x -so -pinfected samples.7z sample.exe > sample.bin`. The [7zip repository](https://github.com/randomcontainers/7zip) describes the formats `7zz` reads.

## Untrusted files

YARA-X's modules parse the structure of executables and other formats from the files you scan. Mount the samples read-only and take away what the container does not need:

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work:ro" \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 2g --cpus 2 --pids-limit 64 \
  ghcr.io/randomcontainers/yara-x scan -r rules.yar samples
```

`yr` starts a scanning thread for each CPU the container may use, plus a pool of the same size that compiles rule conditions. `--cpus` sets that number, so keep it well below `--pids-limit`.

YARA-X compiles rule conditions to native code with wasmtime when it loads the rules, so the process makes memory executable at run time. Docker's default seccomp profile allows that; hosts that forbid it, such as SELinux with the `deny_execmem` boolean set, stop `yr` from loading rules.

## What is in the image

| | slim | default |
|---|---|---|
| `yr`, with the modules above | yes | yes |
| 7-Zip (`7zz` and the `7z` link) | no | yes |

7-Zip is the [randomcontainers/7zip](https://github.com/randomcontainers/7zip) build.

`yr` is built from the release tag with upstream's `release-lto` profile, the one upstream's release binaries use: the release profile with link-time optimization. It is linked against the distro's C library and libgcc_s: glibc on Ubuntu, musl on Alpine. Because of that, copying `/usr/local/bin/yr` with `COPY --from` into an image with another C library does not work. Upstream's `.cargo/config.toml` sets two things for `x86_64-unknown-linux-musl`, the Alpine amd64 build, that this build leaves out: the `musl-gcc` linker, which Alpine does not have (Alpine's `cc` links against musl), and `-C relocation-model=static`, which upstream uses against crashes of statically linked musl programs; `yr` here is linked dynamically.

Not included: the `yara-x` library and its C, Python and Go interfaces, the language server, and any rules. `/usr/local/share/randomcontainers/yara-x/buildinfo` has the commit, the Rust release with the URL and SHA-256 of each archive it was installed from, the output of `rustc -vV`, the cargo-auditable version, the version `yr` reports, and every crate `yr` was built from, with its version, whether it is linked in or used only during the build, and its license.

## Default or slim

Use the default image (`latest`) when your samples come in archives: 7-Zip unpacks zip, 7z, RAR and many other formats, including encrypted ones (see [Archives](#archives-default-image)). `slim` has `yr` without 7-Zip. Use it to scan files that are already unpacked, or as the base of your own image.

The default image includes 7-Zip, which is licensed under the GNU Lesser General Public License (LGPL-2.1-or-later), and its RAR decoders carry the unRAR license restriction. Use `slim` if your policy excludes either. The default image is also published as `ghcr.io/randomcontainers/yara-x-7zip`, built in the [yara-x-7zip](https://github.com/randomcontainers/yara-x-7zip) repository with the same contents and a different digest.

## Tags

`<version>` is a YARA-X release such as `1.22.0`. `<minor>` and `<major>` are its shorter forms, `1.22` and `1`, and follow the newest release in that series.

| Default (with 7-Zip) | Slim | Base |
|---|---|---|
| `latest`, `<version>`, `<minor>`, `<major>` | `slim`, `<version>-slim`, `<minor>-slim`, `<major>-slim` | Ubuntu |
| `ubuntu`, `<version>-ubuntu`, `<minor>-ubuntu`, `<major>-ubuntu` | `slim-ubuntu`, `<version>-slim-ubuntu`, `<minor>-slim-ubuntu`, `<major>-slim-ubuntu` | Ubuntu |
| `<version>-ubuntu26.04` | `<version>-slim-ubuntu26.04` | Ubuntu 26.04 |
| `alpine`, `<version>-alpine`, `<minor>-alpine`, `<major>-alpine` | `slim-alpine`, `<version>-slim-alpine`, `<minor>-slim-alpine`, `<major>-slim-alpine` | Alpine |
| `<version>-alpine3.24` | `<version>-slim-alpine3.24` | Alpine 3.24 |

The images are currently built on Ubuntu 26.04 and Alpine 3.24. Tags without a distro version move to the next distro release when the project does; tags ending in `ubuntu26.04` or `alpine3.24` stay on that release and are no longer rebuilt once the project moves to the next one. Every tag of the current YARA-X version, including the exact version, is rebuilt in place (see [Updates](#updates)), so pin a digest when you need the same bytes every time.

## Platforms

`linux/amd64` and `linux/arm64`, for both Ubuntu and Alpine. Each image contains `yr` built for its own architecture and is built natively on GitHub-hosted runners, without emulation.

## Files and permissions

The working directory is `/work`. The image runs as UID 1000, and any other UID works too: `HOME` is then `/`, and caches go to `/cache`, which anyone can write to. `yr` reads a `.yara-x.toml` in `HOME` when there is one, so pass your configuration with `--config` instead. How to get output files owned by you depends on how you run containers:

| Runtime | Flag |
|---|---|
| Docker on Linux (rootful), GitHub Actions | `--user "$(id -u):$(id -g)"` |
| Rootless Podman | `--userns=keep-id` |
| Rootless Docker | `--user 0:0` (root in the container is your user on the host) |
| Docker Desktop on macOS or Windows | none, file ownership is mapped for you |

`yr scan` only reads the files it scans, so a read-only mount (`:ro`) is enough for it. `yr compile`, `yr fmt`, `yr fix` and `7zz x` write files and need a writable mount.

## Extending the slim image

Use a `slim` tag as the base for your own image. It has no 7-Zip, so 7-Zip updates do not rebuild it. This image carries its own rule file and scans whatever is mounted at `/work`:

```dockerfile
FROM ghcr.io/randomcontainers/yara-x:slim-alpine@sha256:...
COPY rules.yar /usr/local/share/rules/
CMD ["scan", "-r", "/usr/local/share/rules/rules.yar", "/work"]
```

The entrypoint is `["tini", "--", "yr"]`, so `CMD` holds the command, its options, the rules and the target. The image runs as UID 1000, so switch to `USER root` to install distro packages, then back to `USER 1000:1000`. Everything the image adds is under `/usr/local`, and `/usr/local/share/randomcontainers/yara-x/runtime-deps` lists the distro packages `yr` needs at run time: none on Ubuntu, and on Alpine musl and libgcc_s by their `so:` names. To pick up new YARA-X releases and base image fixes, let Dependabot or Renovate update the digest in your `FROM` line.

## Verifying

Each image has a build provenance attestation from this repository's GitHub Actions run, signed by the shared build workflow in `randomcontainers/ci`:

```sh
gh attestation verify oci://ghcr.io/randomcontainers/yara-x:latest \
  --repo randomcontainers/yara-x --signer-repo randomcontainers/ci
```

Images from `ghcr.io/randomcontainers/yara-x-7zip` are built in that repository, so verify them with `--repo randomcontainers/yara-x-7zip` and the same `--signer-repo`.

Each platform image also carries an SPDX SBOM that lists every distro package with its version:

```sh
docker buildx imagetools inspect ghcr.io/randomcontainers/yara-x:latest --format '{{ json .SBOM }}'
```

`yr` is built with [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable), which stores the list of crates compiled into it in the binary's `.dep-v0` section. Syft, Grype and Trivy read that list, so SBOM tools and image scanners see those crates, including wasmtime. The build uses the crate versions in upstream's `Cargo.lock` as they are, so an advisory for one of them goes away with the YARA-X release that updates it. The Rust standard library is not in the list, and scanners do not report its advisories; `buildinfo` names the Rust release that built `yr`, and [Updates](#updates) says when it moves. Follow YARA-X's [security advisories](https://github.com/VirusTotal/yara-x/security) as well.

YARA-X attaches no source tarball to its releases, so each version is pinned to the commit of its tag. The build clones the `v<version>` tag of [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x) and stops unless the tag points to the commit recorded in `package.yml`. cargo downloads the crates in the tag's `Cargo.lock` and checks each against the checksum there, and the build that follows has no network access. It also stops when upstream's `.cargo/config.toml`, which applies to the build, differs from the copy pinned in `cargo-config.sha256`.

Rust comes from static.rust-lang.org. The release manifest named in `package.yml` is checked against the SHA-256 recorded there and against its signature, made with the Rust release key (fingerprint `108F 6620 5EAE B0AA A8DD 5E1C 85AB 96E6 FA1B E5FE`, kept in [keys/rust.gpg](keys/rust.gpg)). Each archive installed from it is checked against the SHA-256 that the manifest lists. cargo-auditable, which runs only during the build, is compiled from its crates.io crate, checked against the SHA-256 in `package.yml`, with the crates listed in its own `Cargo.lock`.

## Updates

The project checks the releases of [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x/releases) every 15 minutes. Upstream creates each release as a draft and publishes it some hours later; a published release is picked up once it is 24 hours old. The new version and the commit of its tag are then committed to `package.yml` and the images are rebuilt. Only the newest release is built; tags of older versions stay as they were last built.

The Rust release that builds `yr` follows Rust's stable channel. Each new stable release is committed to `package.yml` once it is 7 days old, and the images are rebuilt with it. cargo-auditable is pinned by hand. A YARA-X release that needs a newer Rust than the pinned one does not build until the pin moves. A release also waits for a person when it adds a crate under a license that the image's label does not cover or a crate without a license file, changes the version of ascii_tree, asn1-rs-impl or tinyzip, or changes the license of a crate whose license texts this repository keeps or drops one of those crates (see [Licenses](#licenses)). The same goes for a release that stops using rayon-core or regex-syntax, moves the license file of regex-syntax's Unicode tables, moves the TLSH or Teddy code it took from other projects or its `AUTHORS` file, or changes upstream's `.cargo/config.toml`.

The images of the current version are also rebuilt when the Ubuntu or Alpine base image changes, the default ones when a new 7-Zip image is published, and all of them at least every 7 days, so distro security fixes reach the current tags.

## Building

```sh
docker build -f Dockerfile.ubuntu --target slim \
  --build-arg VERSION=<version> \
  --build-arg SOURCE_COMMIT=<commit from package.yml> \
  --build-arg RUST_TOOLCHAIN_VERSION=<rust-toolchain version from package.yml> \
  --build-arg RUST_TOOLCHAIN_SHA256=<rust-toolchain sha256 from package.yml> \
  --build-arg CARGO_AUDITABLE_VERSION=<cargo-auditable version from package.yml> \
  --build-arg CARGO_AUDITABLE_SHA256=<cargo-auditable sha256 from package.yml> \
  -t yara-x:local .
```

Use `Dockerfile.alpine`, with the same arguments, for the Alpine image. The build downloads 115 to 135 MB of Rust archives on Ubuntu and about 170 MB on Alpine, and the crates in `Cargo.lock`. `--build-arg JOBS=<n>` limits the number of crates cargo compiles in parallel. The `release-lto` profile compiles `yr` as a single code generation unit, so its final compile and link use one core. The default image is generated from the `combos` entry in `package.yml` by [randomcontainers/ci](https://github.com/randomcontainers/ci).

## Licenses

YARA-X is licensed under the [BSD 3-Clause license](https://github.com/VirusTotal/yara-x/blob/main/LICENSE). Parts of it keep other terms:

- MIT: the Teddy matcher in `lib/src/teddy`, taken from aho-corasick by Andrew Gallant.
- BSD-3-Clause or Apache-2.0, at the user's choice: the TLSH code in `lib/src/modules/elf/tlsh`, taken from tlsh-rs, copyright TrendMicro. The image uses it under BSD-3-Clause.

`yr` also contains the Rust crates YARA-X depends on. Most of them are under `MIT OR Apache-2.0` or MIT, and others offer a choice of licenses that includes MIT. wasmtime, Cranelift, Pulley, regalloc2 and target-lexicon are under `Apache-2.0 WITH LLVM-exception`, zopfli is under Apache-2.0, dunce offers CC0-1.0, MIT-0 or Apache-2.0 and is used under Apache-2.0, foldhash and zlib-rs are under the zlib license, subtle is under BSD-3-Clause, encoding_rs includes WHATWG data under BSD-3-Clause and unicode-ident includes Unicode data under Unicode-3.0. regex-syntax compiles in Unicode tables under the Unicode license that ships with them (Unicode-DFS-2016), and psl compiles in Mozilla's Public Suffix List, which is under MPL-2.0 although the crate declares `MIT OR Apache-2.0`. The Rust standard library and the crates it uses are linked in too. They are under `MIT OR Apache-2.0` or another choice that includes MIT, except compiler-builtins, which is under `MIT AND Apache-2.0 WITH LLVM-exception`.

The image's license label is `BSD-3-Clause AND MIT AND Apache-2.0 AND Apache-2.0 WITH LLVM-exception AND Zlib AND Unicode-3.0 AND Unicode-DFS-2016 AND MPL-2.0`, with MIT chosen wherever a crate offers it. The build stops when a crate linked into `yr` has a license that this label does not cover.

The license files are in `/usr/local/share/randomcontainers/yara-x/licenses/`: YARA-X's `LICENSE`, `AUTHORS` (the list of the YARA-X Authors that `LICENSE` names) and `teddy/LICENSE-MIT.md` from the release tag; `tlsh-rs/LICENSE-BSD`; `crates/<crate>-<version>/` with the license files of every crate that the binary records, including those used only while it is built, and `crates/CRATES.tsv`, which lists each of them with its license; the Unicode license in `crates/regex-syntax-<version>/src/unicode_tables/LICENSE-UNICODE`; and `rust/` with the license files of rust-lang/rust, the standard library and the crates it vendors, from the `rust-src` archive of the Rust release that built `yr` (all of them except LLVM's libunwind, which the dynamically linked binary does not contain). Seventeen crates publish no license file: twelve wasmtime, Cranelift and Pulley crates, wasm-encoder and wasmparser 0.245.1, asn1-rs-impl, ascii_tree and tinyzip. This repository keeps their license texts in [licenses](licenses), together with the license of tlsh-rs, which the YARA-X source does not include, and the MPL-2.0 text with a notice for the Public Suffix List in psl. The build copies them into the image. [licenses/README.md](licenses/README.md) says where each file comes from. The Ubuntu and Alpine packages in the image keep their own licenses.

The default image adds 7-Zip, licensed under LGPL-2.1-or-later with BSD-licensed parts and the unRAR license restriction; see [randomcontainers/7zip](https://github.com/randomcontainers/7zip#licenses) for its sources and license files.

The source for each image:

- YARA-X: built from the `v<version>` tag of [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x). `/usr/local/share/randomcontainers/yara-x/source` names the commit of that tag, the Rust release manifest, the `rust-src` archive with the source of the Rust standard library, the cargo-auditable crate and the psl crate. The crates are on [crates.io](https://crates.io/) at the versions in that commit's `Cargo.lock`, and `buildinfo` lists those `yr` was built from.
- psl, whose Public Suffix List is under MPL-2.0: its `.crate` file from crates.io, checked against `Cargo.lock`, is in `/usr/local/share/randomcontainers/yara-x/crate-sources/`.
- Build scripts: this repository at the commit in the image's `org.opencontainers.image.revision` label.
- Ubuntu packages: the source packages on [Launchpad](https://launchpad.net/ubuntu) for the versions listed in the SBOM. `apt-get source <package>=<version>` fetches a version that is still in the Ubuntu archive.
- Alpine packages: Alpine has no source packages. For the versions listed in the SBOM, the source is the APKBUILD and patches in [aports](https://gitlab.alpinelinux.org/alpine/aports/-/tree/3.24-stable), branch `3.24-stable`, and the archives on [distfiles.alpinelinux.org](https://distfiles.alpinelinux.org/distfiles/v3.24/).

The files in this repository are available under the MIT license, see [LICENSE](LICENSE), except the license texts in `licenses/`, which keep their own terms.

## Requesting a tool

To suggest another tool, use the [Request a tool](https://github.com/randomcontainers/.github/issues/new?template=tool-request.yml) form.
