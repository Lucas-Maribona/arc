# Arc fuzz targets

Install `cargo-fuzz`, then run either target from the repository root:

```sh
cargo fuzz run repository_index
cargo fuzz run package_archive
```

The index target exercises TOML decoding and every repository-record
invariant. The archive target sends arbitrary bytes through the bounded,
path-safe archive inspection path. Any crash, panic, timeout, or sanitizer
finding is a bug.
