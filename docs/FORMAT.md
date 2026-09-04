# Arc package format v1

## Container

An Arc package has the `.arc` extension and is a Zstandard-compressed POSIX tar
archive. The first archive member must be a regular file named
`.arc/meta.toml`. This lets readers obtain package metadata without scanning or
extracting the payload.

All archive member names must be normalized relative UTF-8 paths. Absolute
paths, empty components, `.` and `..` components, duplicate paths, and paths
outside the archive root are invalid. Arc rejects special files such as device
nodes, FIFOs, and sockets.

The `.arc` top-level directory is reserved for format data. All other members
form the payload and use their final paths relative to the target root.

## Metadata

`.arc/meta.toml` is UTF-8 TOML with this shape:

```toml
format = 1
name = "hello"
version = "1.0.0-1"
arch = "x86_64"
description = "A friendly example"
license = "MIT"
url = "https://example.test/hello"
self_contained = true

[[bundled]]
name = "openssl"
version = "3.6.0"

depends = ["libc>=1.0"]
provides = ["greeter=1.0"]
conflicts = ["hello-old"]
replaces = ["hello-old<1.0"]
backup = ["etc/hello.conf"]
triggers = ["ldconfig"]
```

Only `format`, `name`, `version`, and `arch` are required. Unknown keys are an
error rather than being silently ignored. Array fields default to empty.

`self_contained` defaults to `false`; it records author intent and enables
strict runtime auditing, but does not alter dependency resolution. `[[bundled]]`
records internal software for provenance only, not packages Arc must install.
See [self-contained packages](SELF_CONTAINED_PACKAGES.md).

Package names use lowercase ASCII letters, digits, `+`, `-`, `.`, `_`, and
`@`. Architectures use lowercase ASCII letters, digits, and `_`; `any` means
architecture-independent.

Versions optionally start with a numeric epoch followed by `:`. The remaining
characters may be ASCII letters, digits, `.`, `+`, `_`, `~`, and `-`. Numeric
runs compare numerically, alphabetic runs compare lexically, and `~` sorts
before everything. Package authors should use `~` for prereleases.

Dependencies have no whitespace and use one of `<`, `<=`, `=`, `>=`, or `>`:

```text
name
name>=1.2
name=2:4.0-3
```

## Hooks

The optional hook files are:

```text
.arc/hooks/pre-install
.arc/hooks/post-install
.arc/hooks/pre-upgrade
.arc/hooks/post-upgrade
.arc/hooks/pre-remove
.arc/hooks/post-remove
```

Hooks are POSIX shell source signed as part of the package. Arc invokes
`/bin/sh -eu`, feeds the hook on standard input, clears the inherited
environment, changes root to the target, and sets only:

```text
PATH=/usr/bin:/bin:/usr/sbin:/sbin
ARC_HOOK=<hook name>
ARC_PACKAGE=<package name>
ARC_VERSION=<new or installed version>
ARC_OLD_VERSION=<old version during upgrades, otherwise empty>
```

Pre-hooks run after every archive has been staged and validated but before the
filesystem transaction. Post-hooks run after the complete transaction payload
and package records have been applied but before commit. A failed hook fails the
operation and payload changes are rolled back.

Hooks cannot make arbitrary filesystem changes rollback-safe. Packages should
prefer declarative system users, temporary files, caches, and triggers whenever
possible.

## System triggers

A package may request named system triggers in its metadata. Arc collects the
names from every installed, upgraded, replaced, or removed package and runs
each requested trigger once near the end of the transaction. This avoids, for
example, running `ldconfig` separately for every library in a large bootstrap.

The distro defines available triggers in `/etc/arc/triggers.toml`:

```toml
[[trigger]]
name = "ldconfig"
command = ["/sbin/ldconfig"]

[[trigger]]
name = "update-icon-cache"
command = ["/usr/bin/gtk-update-icon-cache", "-f", "/usr/share/icons/hicolor"]
```

Commands are argument arrays, never shell strings. Executables must be
normalized absolute paths. Arc changes root to the target, clears the inherited
environment, and supplies only `PATH` and `ARC_TRIGGER`. Definitions run once
in configuration order. An undefined trigger, missing executable, timeout, or
nonzero exit fails the operation; Arc rolls back package payload and database
changes.

Hooks and triggers have a five-minute execution limit. Their own external side
effects cannot be undone, so they should be idempotent and operate only inside
the target root.

## Ownership and reproducibility

Version 1 archives install payload members as `root:root`. File modes and link
targets are preserved. The reference packer stores a normalized timestamp and
sorted member order, making repeated builds from the same tree reproducible.

Package filenames conventionally use `<name>-<version>-<arch>.arc`, but
metadata—not the filename—is authoritative.
