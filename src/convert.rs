//! Conversion of supported third-party package archives into Arc archives.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use tar::Archive;

use crate::error::{ArcError, Result};
use crate::metadata::Metadata;
use crate::package;

const MAX_ARCH_METADATA: u64 = 1024 * 1024;
const ARCH_INTERNAL: &[&str] = &[".BUILDINFO", ".CHANGELOG", ".INSTALL", ".MTREE", ".PKGINFO"];

pub fn arch_package(input: &Path, output: Option<&Path>) -> Result<PathBuf> {
    let workspace = tempfile::tempdir()?;
    let root = workspace.path().join("root");
    fs::create_dir(&root)?;

    let file = File::open(input)?;
    let decoder = zstd::Decoder::new(file).map_err(|error| {
        ArcError::InvalidArchive(format!(
            "cannot decompress Arch package as Zstandard: {error}"
        ))
    })?;
    let mut archive = Archive::new(decoder);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(true);
    archive.set_overwrite(false);
    let mut pkginfo = None;
    let mut install = None;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw = entry.path()?;
        let path = raw.to_str().ok_or_else(|| {
            ArcError::InvalidArchive("Arch package contains a non-UTF-8 path".into())
        })?;
        let path = path.strip_prefix("./").unwrap_or(path).to_owned();
        package::validate_member_path(&path)?;
        let entry_type = entry.header().entry_type();

        if ARCH_INTERNAL.contains(&path.as_str()) {
            if !entry_type.is_file() {
                return Err(ArcError::InvalidArchive(format!(
                    "Arch metadata {path} is not a regular file"
                )));
            }
            if entry.size() > MAX_ARCH_METADATA {
                return Err(ArcError::InvalidArchive(format!(
                    "Arch metadata {path} exceeds 1 MiB"
                )));
            }
            if path == ".PKGINFO" || path == ".INSTALL" {
                let mut value = String::new();
                entry.read_to_string(&mut value)?;
                if path == ".PKGINFO" {
                    if pkginfo.replace(value).is_some() {
                        return Err(ArcError::InvalidArchive(
                            "Arch package contains .PKGINFO twice".into(),
                        ));
                    }
                } else if install.replace(value).is_some() {
                    return Err(ArcError::InvalidArchive(
                        "Arch package contains .INSTALL twice".into(),
                    ));
                }
            }
            continue;
        }
        if path.starts_with('.') {
            return Err(ArcError::InvalidArchive(format!(
                "unsupported Arch package metadata {path:?}"
            )));
        }
        if !(entry_type.is_file()
            || entry_type.is_dir()
            || entry_type.is_symlink()
            || entry_type.is_hard_link())
        {
            return Err(ArcError::InvalidArchive(format!(
                "unsupported Arch payload type for {path:?}"
            )));
        }
        if !entry.unpack_in(&root)? {
            return Err(ArcError::InvalidArchive(format!(
                "Arch payload path {path:?} escapes the package root"
            )));
        }
    }

    let fields = parse_pkginfo(
        pkginfo
            .as_deref()
            .ok_or_else(|| ArcError::InvalidArchive("Arch package has no .PKGINFO".into()))?,
    )?;
    let metadata = metadata_from_pkginfo(&fields)?;
    fs::create_dir_all(root.join(".arc/hooks"))?;
    fs::write(root.join(".arc/meta.toml"), metadata.to_toml()?)?;
    if let Some(script) = install {
        convert_install_script(&root, &script)?;
    }

    let output = match output {
        Some(path) => path.to_owned(),
        None => std::env::current_dir()?.join(format!(
            "{}-{}-{}.arc",
            metadata.name, metadata.version, metadata.arch
        )),
    };
    package::pack(&root, Some(&output))
}

fn parse_pkginfo(input: &str) -> Result<BTreeMap<String, Vec<String>>> {
    let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (number, raw) in input.lines().enumerate() {
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once(" = ").ok_or_else(|| {
            ArcError::InvalidArchive(format!("invalid .PKGINFO line {}", number + 1))
        })?;
        if key.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(ArcError::InvalidArchive(format!(
                "invalid .PKGINFO line {}",
                number + 1
            )));
        }
        fields.entry(key.into()).or_default().push(value.into());
    }
    Ok(fields)
}

fn metadata_from_pkginfo(fields: &BTreeMap<String, Vec<String>>) -> Result<Metadata> {
    let one = |name: &str| -> Result<String> {
        let values = fields.get(name).ok_or_else(|| {
            ArcError::InvalidArchive(format!("Arch .PKGINFO has no {name} field"))
        })?;
        if values.len() != 1 || values[0].is_empty() {
            return Err(ArcError::InvalidArchive(format!(
                "Arch .PKGINFO must contain exactly one {name} field"
            )));
        }
        Ok(values[0].clone())
    };
    let many = |name: &str| fields.get(name).cloned().unwrap_or_default();
    let optional = |name: &str| -> Result<String> {
        match fields.get(name) {
            None => Ok(String::new()),
            Some(values) if values.len() == 1 => Ok(values[0].clone()),
            Some(_) => Err(ArcError::InvalidArchive(format!(
                "Arch .PKGINFO contains {name} more than once"
            ))),
        }
    };

    let metadata = Metadata {
        format: 1,
        name: one("pkgname")?,
        version: one("pkgver")?,
        arch: one("arch")?,
        description: optional("pkgdesc")?,
        license: many("license").join(", "),
        url: optional("url")?,
        depends: many("depend"),
        optdepends: vec![],
        package_groups: vec![],
        provides: many("provides"),
        conflicts: many("conflict"),
        replaces: many("replaces"),
        backup: many("backup"),
        triggers: vec![],
        groups: vec![],
        users: vec![],
    };
    metadata.validate().map_err(|error| {
        ArcError::InvalidArchive(format!(
            "Arch metadata cannot be represented by Arc: {error}"
        ))
    })?;
    Ok(metadata)
}

fn convert_install_script(root: &Path, script: &str) -> Result<()> {
    let hooks = [
        ("pre-install", "pre_install", false),
        ("post-install", "post_install", false),
        ("pre-upgrade", "pre_upgrade", true),
        ("post-upgrade", "post_upgrade", true),
        ("pre-remove", "pre_remove", false),
        ("post-remove", "post_remove", false),
    ];
    for (arc_name, arch_name, upgrade) in hooks {
        if !defines_function(script, arch_name) {
            continue;
        }
        let arguments = if upgrade {
            "\"$ARC_VERSION\" \"$ARC_OLD_VERSION\""
        } else {
            "\"$ARC_VERSION\""
        };
        fs::write(
            root.join(".arc/hooks").join(arc_name),
            format!("{script}\n{arch_name} {arguments}\n"),
        )?;
    }
    Ok(())
}

fn defines_function(script: &str, name: &str) -> bool {
    script.lines().any(|line| {
        let line = line.trim_start();
        line.strip_prefix(name)
            .is_some_and(|rest| rest.trim_start().starts_with("()"))
            || line
                .strip_prefix("function")
                .and_then(|rest| rest.trim_start().strip_prefix(name))
                .is_some_and(|rest| {
                    rest.is_empty()
                        || rest.chars().next().is_some_and(char::is_whitespace)
                        || rest.trim_start().starts_with("()")
                })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append(builder: &mut tar::Builder<zstd::Encoder<'_, File>>, path: &str, data: &[u8]) {
        let mut header = tar::Header::new_ustar();
        header.set_path(path).unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append(&header, data).unwrap();
    }

    #[test]
    fn pkginfo_maps_directly_to_arc_metadata() {
        let fields = parse_pkginfo(
            "pkgname = hello\npkgver = 2:1.0-3\narch = x86_64\ndepend = libc>=1\nbackup = etc/hello.conf\n",
        )
        .unwrap();
        let metadata = metadata_from_pkginfo(&fields).unwrap();
        assert_eq!(metadata.name, "hello");
        assert_eq!(metadata.version, "2:1.0-3");
        assert_eq!(metadata.depends, ["libc>=1"]);
        assert_eq!(metadata.backup, ["etc/hello.conf"]);
    }

    #[test]
    fn install_function_detection_avoids_comment_mentions() {
        assert!(defines_function("post_install() { :; }", "post_install"));
        assert!(defines_function(
            "function pre_upgrade { :; }",
            "pre_upgrade"
        ));
        assert!(!defines_function("# post_remove() { :; }", "post_remove"));
    }

    #[test]
    fn arch_archive_converts_to_an_installable_arc_archive() {
        let workspace = tempfile::tempdir().unwrap();
        let input = workspace.path().join("hello.pkg.tar.zst");
        let output = workspace.path().join("hello.arc");
        let encoder = zstd::Encoder::new(File::create(&input).unwrap(), 3).unwrap();
        let mut builder = tar::Builder::new(encoder);
        append(
            &mut builder,
            ".PKGINFO",
            b"pkgname = hello\npkgver = 1-1\narch = any\nbackup = etc/hello.conf\n",
        );
        append(
            &mut builder,
            ".INSTALL",
            b"post_install() { test \"$1\" = 1-1; }\n",
        );
        append(&mut builder, "etc/hello.conf", b"hello\n");
        builder.into_inner().unwrap().finish().unwrap();

        arch_package(&input, Some(&output)).unwrap();
        let inspection = package::inspect(&output).unwrap();
        assert_eq!(inspection.metadata.name, "hello");
        assert_eq!(inspection.metadata.backup, ["etc/hello.conf"]);
        assert!(
            inspection
                .members
                .iter()
                .any(|member| member.path == ".arc/hooks/post-install")
        );
        assert!(
            inspection
                .members
                .iter()
                .any(|member| member.path == "etc/hello.conf")
        );
    }
}
