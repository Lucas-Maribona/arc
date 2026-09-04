# Security model

Arc treats package archives, repository responses, cached indexes, metadata,
hooks, and trigger configuration as untrusted input. The current controls are
intended for a distro beta; they are not a substitute for an independent
security audit.

## Repository trust

- Repository indexes and each package digest require Ed25519 signatures from a
  key pinned in `/etc/arc/repos.toml`.
- Arc verifies the detached signature over the exact index bytes before parsing
  the index. The authenticated record then supplies each package's size,
  SHA-256 digest, metadata, file manifest, and digest signature.
- A repository may pin an overlapping set of keys during planned key rotation.
- Directly pinned keys can authorize a one-level delegated signing key through
  a signed, domain-separated delegation statement in local configuration.
- Repository transport requires HTTPS, and URLs with embedded credentials are
  rejected.
- A signed index authenticates each package's byte size, SHA-256 digest, and
  complete metadata record.
- Cached signed generation numbers prevent straightforward repository rollback
  to an older index.
- Downloads stream into exclusive temporary files, are size-bounded and fully
  authenticated, then are atomically renamed and synced.

Revocation is configuration-driven: remove a direct or delegated key and
synchronize the new trusted configuration. This does not provide threshold
signatures or a transparency log. A compromised trusted repository signing key
can authorize malicious package contents and hooks.

## Archive limits

Arc rejects packages that exceed these v1 limits:

| Resource | Limit |
|---|---:|
| Compressed archive | 64 GiB |
| Declared payload | 64 GiB |
| One member | 16 GiB |
| Metadata or internal hook | 1 MiB |
| Members | 250,000 |
| Path | 4,096 bytes |
| Path component | 255 bytes |
| Link target | 4,096 bytes |
| PAX attributes per member | 256 |
| PAX attribute data per member | 4 MiB |
| One extended-attribute value | 1 MiB |
| Zstandard window | approximately 128 MiB |

Paths must be normalized relative UTF-8. Special files, duplicate paths,
unsafe hardlinks, link-parent traversal, sparse archive members, oversized
extended attributes, and reserved payload paths are rejected. Extraction goes
to a new staging directory, never directly to the target root. Arc checks free
staging space and verifies that the archive digest did not change while it was
staged.

## Transactions and commands

Payload and database mutations are journaled, synced, and rolled back on
failure or recovered at the next invocation after a crash. A per-root lock
prevents concurrent Arc transactions.

Hooks and system triggers run after `chroot` and `chdir` into the target with a
cleared environment. Triggers use direct argument arrays rather than a shell.
Child processes are killed and reaped after five minutes. Package filesystem
changes are rollback-safe, but side effects performed by hooks or triggers are
not generally reversible; commands should therefore be idempotent.

Local `install-file` and `bootstrap` archives are not signed. The operator is
responsible for their provenance. Repository installs authenticate them through
the signed index.
