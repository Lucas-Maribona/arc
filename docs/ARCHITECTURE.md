# Architecture

Arc deliberately uses one path through each operation:

1. Load signed repository indexes.
2. Resolve the complete transaction in memory.
3. Download packages into the cache.
4. Verify index signatures, archive hashes, metadata, and every archive path.
5. Acquire the target root's Arc lock.
6. Run pre-hooks inside the target root.
7. Journal and commit filesystem changes and installed-package records.
8. Run queued post-hooks and each requested system trigger once.
9. Mark the journal complete and remove the journal.

The install engine never parses Arch, Debian, or other foreign package formats.
Converters turn those inputs into ordinary `.arc` files before they reach the
repository.

## Source modules

```text
metadata     package identity and dependency declarations
version      version ordering and requirement matching
error        shared error vocabulary and process exit categories
package      archive inspection, packing, and staged extraction
runtime_audit safe non-executing ELF and shebang inspection of package roots
bootstrap    complete-set validation and dependency ordering
repository   repository index data model
remote       signed index loading and streaming package downloads
resolver     deterministic dependency and conflict planning
database     plain installed-package records and ownership lookup
transaction  locking, journaling, commit, and recovery
triggers     declarative target-root maintenance commands
process      bounded child-process execution
publisher    repository index, key, and signature creation
convert      Arch package adapter
atomic_file  durable write-then-rename publication
encoding     lowercase hexadecimal encoding and decoding
system       Linux free-space queries and advisory file locks
```

The local database is a directory of TOML records under
`/var/lib/arc/installed`. This keeps recovery and inspection possible with
ordinary tools. A transaction journal is the only mutable coordination state.

The three small shared helpers deliberately avoid general-purpose wrapper
crates: `atomic_file` centralizes durable publication, `encoding` handles the
fixed hexadecimal forms used for digests and keys, and `system` contains the
small, documented Linux `statvfs` and `flock` boundaries. Format parsing,
cryptography, networking, compression, xattrs, secure randomness, and
temporary-directory handling remain delegated to focused libraries.

## Acceptance bar for the first beta

- A static Arc binary installs a base set into an empty `--root` directory.
- That root can boot in a VM.
- Dependency cycles, conflicts, replacements, and version constraints have
  deterministic tests.
- Invalid archives cannot escape staging through names, symlinks, or hardlinks.
- Injected failures at every commit step either leave the old state intact or
  recover it on Arc's next invocation.
- Installing, upgrading, and removing preserve modified configured files.
- Repository metadata and downloaded package hashes are authenticated.
- Older signed repository generations cannot replace a newer cached index.
- An Arch `.pkg.tar.zst` converter preserves supported package metadata and
  payload entries.
