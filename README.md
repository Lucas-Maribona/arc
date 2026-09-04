# arc

**arc is a small, safe Linux package manager written in Rust.** It is built for
bootstrapping and maintaining an arc-based system with readable package and
state formats, authenticated repositories, and recoverable transactions.

```text
hello-1.0-1-x86_64.arc
├── .arc/meta.toml
├── .arc/hooks/post-install     # optional
├── etc/hello.conf
└── usr/bin/hello
```

An `.arc` package is a Zstandard-compressed tar archive. Removing `.arc/`
leaves the tree installed beneath `/`; installed-state records are readable TOML
under `/var/lib/arc/installed`.

## Highlights

- Journaled installs, upgrades, replacements, and removals with recovery after
  interruption.
- Dependency solving with versions, virtual providers, conflicts, replacements,
  explicit/dependency reasons, and orphan detection.
- Signed HTTPS indexes and file manifests, per-package signatures, SHA-256
  archive verification, rollback protection, resumable downloads, mirrors,
  retries, rate limits, and configurable parallel transfers.
- File ownership, modes, xattrs, symlinks, hardlinks, checksums, and ownership
  queries.
- Lifecycle hooks, declarative triggers, system users/groups, and bootstrapping.
- Local package installs, repository publishing/signing, and Arch conversion.

## Repository trust and download policy

arc authenticates repository indexes and each package digest with Ed25519. A
repository can use multiple pinned keys while rotating signing keys, or a
one-level delegated online signing key that is authorized by a pinned root key.
Cached indexes are protected against generation rollback. Package downloads are
resumable, verified before cache publication, and may use mirrors, retries,
timeouts, concurrency limits, and an optional byte-per-second cap.

Repository metadata includes signed file manifests, package groups, optional
dependencies, and provider information. This allows `search`, `info`, `files`,
`group`, and `required-by` to query synchronized metadata without downloading
packages first.

## Install and use

arc targets Linux and requires Rust 1.85 or newer.

```sh
cargo build --release --locked
sudo install -m755 target/release/arc /usr/bin/arc

# Configure /etc/arc/repos.toml first.
sudo arc sync
sudo arc install hello
```

Package-changing commands preview the transaction before proceeding. Use
`--yes` (or `--noconfirm`) only for unattended work.

```text
arc [--root <target>] [--yes] [--non-interactive] [--json] <command> [arguments]
```

`--root` operates on another absolute filesystem root; omit it for `/`.
`NO_COLOR=1` disables colors. Status and progress are written to standard error
so standard output stays usable in scripts.

### Automation contract

`--yes` and `--noconfirm` accept every transaction without reading stdin.
`--non-interactive` is accepted before or after every command and guarantees
that arc will never read a confirmation; combine it with `--yes` for unattended
changes. Without `--yes`, a command that needs approval exits before mutating
the target.

`--json` is also accepted before or after every command. It makes stdout a
stable JSON Lines stream, with one object per regular output record:

```json
{"type":"output","message":"-1"}
```

Errors are written as one JSON object to stderr, with `type`, `code`, and
`message` fields. Exit codes are stable: `0` success, `1` operational failure,
`2` usage, `3` authentication, `4` network, `5` dependency resolution, and
`6` invalid installed state. This lets callers use both the status and the
machine-readable diagnostic without parsing terminal UI text.

## Command reference

### Repositories and installation

| Command | Purpose |
| --- | --- |
| `sync` | Download and authenticate configured repository indexes. |
| `install <package>...` | Resolve dependencies and install repository packages. Requests accept constraints such as `glibc>=2.40` or `foo=1.2-1`. |
| `upgrade` | Upgrade all installed packages to compatible repository versions. |
| `reinstall <package>...` | Fetch and apply repository packages again, even when installed. |
| `downgrade <package=requirement>...` | Install an explicitly requested older repository version; the exact requirement is required. |
| `install-file <package.arc>...` | Transactionally install local archives. |
| `bootstrap <target> <package.arc>...` | Populate an empty target root from local packages in dependency order. |

### Package management and inspection

| Command | Purpose |
| --- | --- |
| `list` | Show installed package names, versions, architectures, and reasons. |
| `info <package>...` | Print synchronized repository metadata; without repository configuration, print installed metadata and reason. |
| `search <query>` | Search synchronized repositories; without repository configuration, search installed packages. |
| `group <group>` | List packages in a repository or installed package group. |
| `required-by <package>` | List repository dependents (including virtual-provider matches), or installed dependents without repository configuration. |
| `files <package>` | List signed repository manifest paths, or installed paths without repository configuration. |
| `owns <path>` | Print the installed package owning a path. |
| `verify [package]...` | Check recorded file type, mode, owner/group, symlink target, and regular-file digest. |
| `mark <explicit\|dependency> <package>...` | Change an installed package’s reason. |
| `orphans` | List dependency packages no longer needed by another package. |
| `autoremove` | Preview and remove all orphan packages transactionally. |
| `remove [--recursive] <package>...` | Remove packages; regular removal protects reverse dependencies and `--recursive` includes dependents. `glibc`, `init`, and `arc` are protected. |
| `history` | Print committed install/remove transaction records. |
| `doctor [path]...` | Validate installed state, payload files, repository-cache integrity, and resumable partial downloads. Named paths are also scanned for unowned files. |
| `cache list` / `cache clean [--keep <n>]` | List archives, remove all cached archives, or retain the newest `n` authenticated versions of each package. |

### Package and repository authors

| Command | Purpose |
| --- | --- |
| `pack <package-root> [output.arc]` | Build a deterministic package archive. |
| `inspect <package.arc>` | Validate and display archive metadata. |
| `convert-arch <package.pkg.tar.zst> [output.arc]` | Convert a supported Arch package archive. |
| `repo-index <repository-directory>` | Generate `index.toml` from `packages/`. |
| `repo-keygen <private-key-file>` | Generate an Ed25519 repository-signing key. |
| `repo-sign <index.toml> <private-key-file>` | Sign a repository index. |
| `version <first> <second>` | Compare arc versions (`-1`, `0`, or `1`). |

Use `arc help`, `arc --help`, or `arc -h` for compact usage.

## Package example

```sh
mkdir -p hello/.arc hello/usr/bin
cat > hello/.arc/meta.toml <<'EOF'
format = 1
name = "hello"
version = "1.0-1"
arch = "x86_64"
description = "A friendly example"
EOF

install -m755 /path/to/hello hello/usr/bin/hello
arc pack hello
```

Package metadata can declare system accounts:

```toml
[[groups]]
name = "hello"
gid = 971

[[users]]
name = "hello"
uid = 971
gid = 971
home = "/var/lib/hello"
shell = "/usr/sbin/nologin"
```

Payload ownership is normalized to `root:root` unless it belongs to the package
builder or its UID/GID is explicitly declared by both a package user and group.
The installer applies declared ownership and adds required accounts to the
target root’s `/etc/group` and `/etc/passwd`.

## Repository layout

```text
core/
├── index.toml
├── index.toml.sig
└── packages/
    └── hello-1.0-1-x86_64.arc
```

```sh
arc repo-keygen repo.sec
arc repo-index /srv/arc/core
arc repo-sign /srv/arc/core/index.toml repo.sec
```

Run `repo-index` and then `repo-sign` again whenever the contents of
`packages/` change. `repo-sign` records a signature for every package digest
in the index and writes a detached signature for the resulting exact
`index.toml` bytes to `index.toml.sig`. Keep `repo.sec` private; the public key
printed by `repo-keygen` is what belongs in client configuration.

Serve the repository over HTTPS, then configure `/etc/arc/repos.toml`:

```toml
architecture = "x86_64"

# Excluded from `arc upgrade`; explicit install/reinstall/downgrade requests
# intentionally override this safeguard.
hold = ["critical-service"]

[[repository]]
name = "core"
url = "https://packages.example.org/core"
key = "<lowercase-ed25519-public-key>"
# Optional retiring keys during a planned key rotation.
keys = ["<another-lowercase-ed25519-public-key>"]
priority = 10
mirrors = ["https://mirror.example.org/arc/core"]
retries = 2
timeout_seconds = 60
bandwidth_limit = 0 # bytes/s; zero leaves downloads unlimited
```

`hold` and `ignore` exclude packages from `arc upgrade`; explicit `install`,
`reinstall`, and exact-version `downgrade` requests override them deliberately.
`downgrade` never guesses a version: its request must include `=` and must be
satisfied by a synchronized, authenticated repository package.

Transaction history is stored as readable TOML under
`/var/lib/arc/history/`. Each committed entry records a nanosecond timestamp,
action, outcome, and every affected package’s version, architecture, and
explicit/dependency reason.

## Security model

arc treats archives, metadata, repository responses, cached objects, and hook
output as untrusted input. Before installing a repository package, arc
authenticates the signed index, checks the archive size and SHA-256 digest, and
confirms archive metadata matches the signed record. archives are validated and
staged before filesystem mutation.

- [Package format](docs/FORMAT.md)
- [Repository format](docs/REPOSITORY.md)
- [Security model](docs/SECURITY.md)
- [Architecture](docs/ARCHITECTURE.md)

## Releases

Tagged releases publish a static Linux binary, `SHA256SUMS`, and an SPDX JSON
SBOM. The release workflow also creates GitHub OIDC build provenance for all
three files, which can be verified with GitHub's attestation tooling. The test
suite exercises local-package lifecycle and a release-to-release upgrade inside
a disposable target root; it never changes the developer's host installation.

## Development

### Code guide

The code intentionally keeps one responsibility per module. Start with
`src/main.rs` for command parsing and dispatch, then follow the command into
the library modules:

| Module | Responsibility |
| --- | --- |
| `metadata`, `version` | Validate package fields and compare requirements. |
| `package` | Read, create, hash, and safely extract `.arc` archives. |
| `repository`, `remote`, `resolver` | Load signed indexes, choose packages, and download them. |
| `database`, `transaction` | Track installed files and apply journaled changes safely. |
| `publisher` | Build and sign repository indexes. |
| `bootstrap`, `convert`, `triggers` | Local bootstrap ordering, Arch conversion, and configured maintenance commands. |
| `atomic_file`, `encoding`, `system` | Small shared helpers for durable writes, hexadecimal data, and Linux filesystem/lock calls. |

High-level functions are written as short sequences of named steps. Keep new
code in the same style: give each helper one job, use ordinary structs and
enums for state, and add a focused test beside the behavior it protects.

Arc keeps small, auditable helpers in-tree when they are safer and clearer than
another general-purpose dependency. Cryptography, secure randomness, archive
formats, TLS HTTP, TOML, compression, extended attributes, and temporary
workspace handling remain provided by their dedicated libraries.

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
```

Parser fuzz targets for repository indexes and package archives live in
[`fuzz/`](fuzz/README.md). Run them with `cargo fuzz run repository_index` or
`cargo fuzz run package_archive` after installing `cargo-fuzz`.

The release workflow produces an `x86_64-unknown-linux-musl` static binary for
bootstrapping a root without a preinstalled C runtime.

arc is proprietary software. Copyright © 2026 Lucas Maribona. All Rights
Reserved. See [LICENSE](LICENSE).
