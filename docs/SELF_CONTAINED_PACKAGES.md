# Self-contained Mercury packages

Mercury application packages normally carry their ordinary userspace runtime inside the same `.arc` archive. Arc consumes and validates that payload; it does not fetch sources, compile programs, find libraries, or patch ELF files.

```toml
format = 1
name = "git"
version = "2.55.0-1"
arch = "x86_64"
self_contained = true
depends = []

[[bundled]]
name = "openssl"
version = "3.6.0"
```

`self_contained` defaults to `false`. It is an author intent and runtime-audit policy, never a switch that disables Arc's resolver. A self-contained package may still depend on a separate system component such as `dbus`, a kernel, service, or bootloader. Bundled components record internally shipped software for provenance and security response; they are not install dependencies.

## Layout

Use package-private runtime directories to prevent ownership collisions:

```text
git package
├── usr/bin/git
├── usr/libexec/git-core/
├── usr/lib/arc/git/
│   ├── ld-linux-x86-64.so.2
│   ├── libc.so.6
│   ├── libcurl.so.4
│   ├── libssl.so.3
│   └── libcrypto.so.3
└── usr/share/
```

Thus `git` can own `/usr/lib/arc/git/libssl.so.3` while another package owns its different pathname. Normal Arc collision detection still rejects two packages owning the exact same path; there is no implicit file sharing.

Package builders should statically link where sensible, otherwise bundle runtime files under `/usr/lib/arc/<package>/`, and patch ELF interpreter and RPATH/RUNPATH (usually using `$ORIGIN`) before calling Arc. Build-time tools are not runtime dependencies merely because they were used to create payload.

## Runtime audit

Run `arc audit <package-root>` before packaging. It parses Linux ELF metadata without executing files: `PT_INTERP`, `DT_NEEDED`, RPATH/RUNPATH, and recursive private-library requirements. It also flags broken symlinks and obvious build paths such as `/tmp`, `/build`, `/home/...`, and GitHub Actions workspaces. Executable scripts are checked only for their shebang. `/bin/sh` is a narrow fundamental system interface for hooks/scripts; Python, Perl, Ruby, Node, and other interpreters are external requirements unless supplied or deliberately declared separately.

For `self_contained = true`, missing ELF interpreters and libraries outside the package are failures. Arc does not consult the host `/usr/lib` and does not infer package dependencies from `DT_NEEDED`. `arc pack` runs this audit automatically for self-contained metadata and refuses a failed package. The expert-only `arc pack --skip-runtime-audit ...` bypasses that protection.

Library resolution is deliberately strict: carrying a matching filename under
`/usr/lib/arc` is not enough. Each ELF object's own RUNPATH (or RPATH when
RUNPATH is absent) must reach the library through an absolute or
`$ORIGIN`/`${ORIGIN}` path contained by the package root. This is a
conservative static model of direct dependencies; Arc does not emulate every
loader edge case. Absolute symlinks are evaluated relative to the package root,
never the build host.

For `#!/usr/bin/env python3` and `env -S`, audit requires a bundled
`/usr/bin/env` and the selected command at `/usr/bin/<command>`. Other env
option forms are rejected rather than guessed.

Linux kernel/syscall interfaces, `/proc`, `/sys`, `/dev`, filesystem conventions, `/bin/sh`, and declared interaction with system services such as D-Bus are system interfaces rather than ordinary bundled shared libraries.

## Security response

Bundling reduces dependency chains but duplicates security-sensitive code. An OpenSSL vulnerability can require rebuilding every package which declares an affected bundled OpenSSL. `arc inspect`, `arc info`, and signed repository metadata retain `self_contained` and `[[bundled]]` records. `arc bundled openssl` finds installed packages (or synchronized repository records) that declare it. Package authors remain responsible for accurate component records and rebuilding affected payloads.

Responsibilities remain separate:

```text
builder: source, compile, bundle, patch ELF, prepare root
Arc:     audit, pack, sign/index, install, own, upgrade, remove, verify
```
