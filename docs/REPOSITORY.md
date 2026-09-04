# Arc repository format v1

## Compatibility policy

Arc v1 accepts only `format = 1` package metadata and repository indexes. New
optional fields must be declared with a backwards-compatible default; changes
to authentication, path semantics, ownership, or transaction behavior require
a new format version. Unknown fields are rejected rather than silently ignored.
Publishers should retain v1 indexes and archives for clients that have not yet
upgraded; clients must never treat a higher format number as compatible.

A repository is an ordinary HTTPS directory containing:

```text
index.toml
index.toml.sig
packages/
└── hello-1.0-1-x86_64.arc
```

The detached Ed25519 signature authenticates the exact bytes of `index.toml`.
The signed index contains the SHA-256 digest, size, metadata, and an Ed25519
signature over the digest of every package. Clients verify both signatures.

The index is deliberately one readable TOML document:

```toml
format = 1
generated = 1788105600

[[package]]
format = 1
name = "hello"
version = "1.0-1"
arch = "x86_64"
description = "An example"
depends = ["libc>=1"]
filename = "packages/hello-1.0-1-x86_64.arc"
sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
size = 12345
files = ["usr/bin/hello", "usr/share/doc/hello/readme"]
```

Package metadata is repeated in the index so dependency resolution does not
require downloading archives. Arc validates that downloaded archive metadata
exactly matches the signed record before installation.
The signed `files` manifest lists package payload paths and powers repository
`arc files` queries without trusting an archive download.

Repositories are listed in `/etc/arc/repos.toml` alongside their Ed25519 public
keys. Repository order breaks ties only when two repositories contain the same
package version; version selection itself is deterministic.

```toml
architecture = "x86_64"
include = ["repos.d/extra.toml"]

[[repository]]
name = "core"
url = "https://packages.example.org/core"
key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
# Keep the retiring key here while a replacement key is rolled out.
keys = ["abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"]
# A signing key authorized by `key` or `keys`; its signature covers the exact
# string `arc-delegate-v1:<delegated-key>`.
delegated_keys = [{
  key = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
  signature = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}]
priority = 10
mirrors = ["https://mirror.example.org/arc/core"]
retries = 2
timeout_seconds = 60
bandwidth_limit = 0 # bytes/s; zero leaves downloads unlimited
```

URLs must use HTTPS. Public keys and signatures use lowercase hexadecimal;
public keys are 32 bytes and signatures are 64 bytes. Arc re-verifies cached
indexes whenever it plans an install. Repository URLs cannot contain embedded
credentials. Once a newer signed index generation has been cached, `arc sync`
rejects an older generation signed by the same key.

Repository priority selects a source only for an otherwise identical package
identity. Mirrors are attempted after the primary URL; only network failures
are retried, while malformed or unauthenticated data fails immediately. Each
request has a configurable end-to-end deadline. During
key rotation, sign the repository with the new key and configure both public
keys until every client has received the new configuration, then remove the old
one.

Delegated keys are one-level authorizations: a directly pinned key signs the
literal `arc-delegate-v1:<delegated-key>` statement. Arc verifies that statement
locally before accepting an index or package signed by the delegated key. This
allows a protected root key to authorize a short-lived online signing key without
making arbitrary chains of trust implicit. Revocation is performed by removing a
delegation or pinned key from client configuration, then synchronizing again.

Includes are relative to the configuration file and cannot escape its
directory. Included files use the same schema and architecture; their
repositories, holds, and ignores are merged before validation.

## Publishing

Create a repository with all packages directly inside `packages/`, then run:

```sh
arc repo-keygen repo.sec
arc repo-index /srv/arc/core
arc repo-sign /srv/arc/core/index.toml repo.sec
```

`repo-keygen` creates a private Ed25519 key and prints its public key.
`repo-sign` first signs the ASCII SHA-256 value for every package and stores
those signatures in `index.toml`; it then signs the resulting exact index bytes
and writes the lowercase-hex detached signature to `index.toml.sig`. Therefore
run `repo-index` followed by `repo-sign` after every package addition, removal,
or replacement. Keep `repo.sec` offline and private. Publish only
`index.toml`, `index.toml.sig`, and `packages/` through an HTTPS static file
server. Copy the public key printed by `repo-keygen` into each client's
`repos.toml`.

Clients use `arc sync` to authenticate and cache configured indexes, then
`arc install <name>` to resolve, download, verify, and transactionally install
packages. Package bodies stream directly into a temporary cache file instead of
being held in memory. Arc caps the stream at the size authenticated by the
index, verifies its SHA-256 digest and embedded metadata, syncs it to disk, and
then atomically publishes the cache entry.

## Integration test

The repository integration test creates a real package, builds and signs an
index, serves the repository through a loopback TCP HTTP server, then performs
the same sync, resolve, streaming download, verification, and transactional
install path used by the CLI. A second case changes the served package bytes and
proves that the signed size/digest check rejects it. Loopback HTTP is enabled
only in test builds; normal Arc builds continue to require HTTPS.
