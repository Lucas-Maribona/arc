# Converting Arch packages

Arc's built-in adapter accepts current Zstandard-compressed Arch Linux package
archives:

```sh
arc convert-arch hello-1.0-1-x86_64.pkg.tar.zst
```

The adapter maps `.PKGINFO` fields directly:

| Arch field | Arc field |
|---|---|
| `pkgname` | `name` |
| `pkgver` | `version` |
| `arch` | `arch` |
| `pkgdesc` | `description` |
| `url` | `url` |
| `license` | `license` |
| `depend` | `depends` |
| `provides` | `provides` |
| `conflict` | `conflicts` |
| `replaces` | `replaces` |
| `backup` | `backup` |

`.BUILDINFO`, `.MTREE`, and other Arch-only metadata are removed. Regular
files, directories, symlinks, hardlinks, modes, and extended attributes are
repacked as an ordinary Arc payload.

Recognized functions in `.INSTALL` become the equivalent Arc hooks. Their Arch
arguments are preserved: install/remove functions receive one version and
upgrade functions receive the new and old versions. Unsupported dependency
syntax or payload types fail conversion explicitly instead of being silently
dropped.
