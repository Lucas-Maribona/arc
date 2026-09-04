//! Safe inspection, packing, extraction, and hashing of `.arc` archives.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};
use tar::{Archive, Builder, EntryType, Header};

use crate::error::{ArcError, Result};
use crate::metadata::Metadata;

const METADATA_PATH: &str = ".arc/meta.toml";
const MAX_METADATA_SIZE: u64 = 1024 * 1024;
const MAX_ARCHIVE_SIZE: u64 = 64 * 1024 * 1024 * 1024;
const MAX_PAYLOAD_SIZE: u64 = 64 * 1024 * 1024 * 1024;
const MAX_MEMBER_SIZE: u64 = 16 * 1024 * 1024 * 1024;
const MAX_INTERNAL_SIZE: u64 = 1024 * 1024;
const MAX_MEMBERS: usize = 250_000;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_COMPONENT_LENGTH: usize = 255;
const MAX_LINK_LENGTH: usize = 4096;
const MAX_PAX_ATTRIBUTES: usize = 256;
const MAX_PAX_SIZE: usize = 4 * 1024 * 1024;
const MAX_XATTR_NAME: usize = 255;
const MAX_XATTR_VALUE: usize = 1024 * 1024;
const MAX_ZSTD_WINDOW_LOG: u32 = 27;
pub const HOOK_NAMES: &[&str] = &[
    "pre-install",
    "post-install",
    "pre-upgrade",
    "post-upgrade",
    "pre-remove",
    "post-remove",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberKind {
    File,
    Directory,
    Symlink,
    Hardlink,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Member {
    pub path: String,
    pub kind: MemberKind,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub size: u64,
    pub target: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inspection {
    pub metadata: Metadata,
    pub members: Vec<Member>,
    pub payload_size: u64,
    pub sha256: String,
}

pub fn inspect(path: &Path) -> Result<Inspection> {
    let archive_metadata = fs::metadata(path)?;
    if !archive_metadata.is_file() || archive_metadata.len() > MAX_ARCHIVE_SIZE {
        return Err(ArcError::InvalidArchive(
            "package must be a regular file no larger than 64 GiB".into(),
        ));
    }
    let file = File::open(path)?;
    let mut decoder = zstd::Decoder::new(file)?;
    decoder.window_log_max(MAX_ZSTD_WINDOW_LOG)?;
    let mut archive = Archive::new(decoder);
    let mut entries = archive.entries()?;
    let Some(first) = entries.next() else {
        return Err(ArcError::InvalidArchive("archive is empty".into()));
    };
    let mut first = first?;
    let first_path = member_path(&first)?;
    if first_path != METADATA_PATH || !first.header().entry_type().is_file() {
        return Err(ArcError::InvalidArchive(format!(
            "first member must be the regular file {METADATA_PATH}"
        )));
    }
    if first.size() > MAX_METADATA_SIZE {
        return Err(ArcError::InvalidArchive(
            "metadata is larger than 1 MiB".into(),
        ));
    }
    let mut metadata_text = String::new();
    first.read_to_string(&mut metadata_text)?;
    let metadata = Metadata::from_toml(&metadata_text)?;

    let mut seen = HashSet::from([METADATA_PATH.to_owned()]);
    let mut members = Vec::new();
    let mut payload_size = 0_u64;

    for entry in entries {
        if members.len() >= MAX_MEMBERS {
            return Err(ArcError::InvalidArchive(format!(
                "package contains more than {MAX_MEMBERS} members"
            )));
        }
        let mut entry = entry?;
        validate_pax(&mut entry)?;
        let path = member_path(&entry)?;
        if !seen.insert(path.clone()) {
            return Err(ArcError::InvalidArchive(format!(
                "duplicate member {path:?}"
            )));
        }

        let entry_type = entry.header().entry_type();
        let kind = classify_member(&path, entry_type)?;
        let target = if entry_type.is_hard_link() || entry_type.is_symlink() {
            let target = entry
                .link_name()?
                .ok_or_else(|| ArcError::InvalidArchive(format!("link {path:?} has no target")))?;
            let target = target.to_str().ok_or_else(|| {
                ArcError::InvalidArchive(format!("link {path:?} has a non-UTF-8 target"))
            })?;
            if target.is_empty() {
                return Err(ArcError::InvalidArchive(format!(
                    "link {path:?} has an empty target"
                )));
            }
            if target.len() > MAX_LINK_LENGTH {
                return Err(ArcError::InvalidArchive(format!(
                    "link target for {path:?} exceeds {MAX_LINK_LENGTH} bytes"
                )));
            }
            if entry_type.is_hard_link() {
                validate_member_path(target)?;
                if is_internal(target) {
                    return Err(ArcError::InvalidArchive(format!(
                        "payload hardlink {path:?} targets reserved path {target:?}"
                    )));
                }
            }
            target.to_owned()
        } else {
            String::new()
        };

        let mode = entry.header().mode()? & 0o7777;
        let uid = entry.header().uid()?;
        let gid = entry.header().gid()?;
        let size = entry.size();
        if size > MAX_MEMBER_SIZE {
            return Err(ArcError::InvalidArchive(format!(
                "member {path:?} exceeds 16 GiB"
            )));
        }
        if kind == MemberKind::Internal && size > MAX_INTERNAL_SIZE {
            return Err(ArcError::InvalidArchive(format!(
                "internal member {path:?} exceeds 1 MiB"
            )));
        }
        if matches!(
            kind,
            MemberKind::Directory | MemberKind::Symlink | MemberKind::Hardlink
        ) && size != 0
        {
            return Err(ArcError::InvalidArchive(format!(
                "non-regular member {path:?} has a nonzero size"
            )));
        }
        if kind != MemberKind::Internal {
            payload_size = payload_size
                .checked_add(size)
                .ok_or_else(|| ArcError::InvalidArchive("payload size overflow".into()))?;
            if payload_size > MAX_PAYLOAD_SIZE {
                return Err(ArcError::InvalidArchive(
                    "package payload exceeds 64 GiB".into(),
                ));
            }
        }
        members.push(Member {
            path,
            kind,
            mode,
            uid,
            gid,
            size,
            target,
        });
    }
    validate_member_graph(&members)?;

    Ok(Inspection {
        metadata,
        members,
        payload_size,
        sha256: sha256(path)?,
    })
}

/// Extract a fully validated package into a newly created staging directory.
///
/// Callers commit files from this directory; Arc never extracts an untrusted
/// archive directly into a target root.
pub fn extract(path: &Path, destination: &Path) -> Result<Inspection> {
    let inspection = inspect(path)?;
    if destination.exists() {
        return Err(ArcError::Usage(format!(
            "staging directory {} already exists",
            destination.display()
        )));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| ArcError::Usage("staging path has no parent".into()))?;
    fs::create_dir_all(parent)?;
    let available = crate::system::available_space(parent)?;
    if available < inspection.payload_size {
        return Err(ArcError::Transaction(format!(
            "package needs {} bytes of staging space; only {available} are available",
            inspection.payload_size
        )));
    }
    fs::create_dir(destination)?;

    let result = (|| -> Result<()> {
        let file = File::open(path)?;
        let mut decoder = zstd::Decoder::new(file)?;
        decoder.window_log_max(MAX_ZSTD_WINDOW_LOG)?;
        let mut archive = Archive::new(decoder);
        archive.set_preserve_permissions(true);
        archive.set_preserve_mtime(true);
        archive.set_unpack_xattrs(true);
        archive.set_overwrite(false);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let _ = member_path(&entry)?;
            if !entry.unpack_in(destination)? {
                return Err(ArcError::InvalidArchive(
                    "an archive member escaped the staging directory".into(),
                ));
            }
        }
        if sha256(path)? != inspection.sha256 {
            return Err(ArcError::Authentication(
                "package archive changed while it was being staged".into(),
            ));
        }
        Ok(())
    })();

    if let Err(error) = result {
        let _ = fs::remove_dir_all(destination);
        return Err(error);
    }
    Ok(inspection)
}

pub fn pack(source: &Path, output: Option<&Path>) -> Result<PathBuf> {
    pack_with_options(source, output, false)
}

/// Pack a tree, auditing self-contained payloads by default. Skipping the
/// audit is deliberately an explicit caller choice for expert recovery cases.
pub fn pack_with_options(
    source: &Path,
    output: Option<&Path>,
    skip_runtime_audit: bool,
) -> Result<PathBuf> {
    let source = source.canonicalize()?;
    if !source.is_dir() {
        return Err(ArcError::Usage(format!(
            "package root {} is not a directory",
            source.display()
        )));
    }

    let metadata_path = source.join(METADATA_PATH);
    let metadata_text = fs::read_to_string(&metadata_path)?;
    let metadata = Metadata::from_toml(&metadata_text)?;
    if metadata.self_contained && !skip_runtime_audit {
        let report = crate::runtime_audit::audit_root(&source, Some(&metadata))?;
        if !report.passed() {
            return Err(ArcError::InvalidMetadata(format!(
                "self-contained runtime audit failed:\n{}",
                crate::runtime_audit::format_report(Some(&metadata), &report)
            )));
        }
    }
    let filename = format!(
        "{}-{}-{}.arc",
        metadata.name, metadata.version, metadata.arch
    );
    let output = match output {
        Some(path) if path.is_absolute() => path.to_owned(),
        Some(path) => std::env::current_dir()?.join(path),
        None => source
            .parent()
            .ok_or_else(|| ArcError::Usage("package root has no parent directory".into()))?
            .join(filename),
    };
    if output.exists() {
        return Err(ArcError::Usage(format!(
            "refusing to overwrite {}",
            output.display()
        )));
    }
    if output.starts_with(&source) {
        return Err(ArcError::Usage(
            "output package cannot be inside its package root".into(),
        ));
    }
    let parent = output
        .parent()
        .ok_or_else(|| ArcError::Usage("output path has no parent directory".into()))?;
    fs::create_dir_all(parent)?;
    let part = parent.join(format!(
        ".{}.part-{}",
        output
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("arc-package"),
        std::process::id()
    ));

    if let Err(error) = write_package(&source, &metadata_path, &part, &metadata) {
        let _ = fs::remove_file(&part);
        return Err(error);
    }
    fs::rename(&part, &output)?;
    Ok(output)
}

fn write_package(
    source: &Path,
    metadata_path: &Path,
    output: &Path,
    metadata: &Metadata,
) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let mut encoder = zstd::Encoder::new(file, 10)?;
    encoder.include_checksum(true)?;
    let mut builder = Builder::new(encoder);

    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                ArcError::Usage("SOURCE_DATE_EPOCH must be an unsigned integer".into())
            })
        })
        .transpose()?
        .unwrap_or(0);

    append_regular(
        &mut builder,
        metadata_path,
        Path::new(METADATA_PATH),
        epoch,
        (0, 0),
    )?;
    let mut hardlinks = HashMap::new();
    for relative in collect_members(source)? {
        if relative == Path::new(METADATA_PATH) || relative == Path::new(".arc") {
            continue;
        }
        append_source_member(
            &mut builder,
            source,
            &relative,
            epoch,
            &mut hardlinks,
            metadata,
        )?;
    }
    builder.finish()?;
    let encoder = builder.into_inner()?;
    let file = encoder.finish()?;
    file.sync_all()?;
    Ok(())
}

fn collect_members(root: &Path) -> Result<Vec<PathBuf>> {
    fn visit(root: &Path, relative: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
        let directory = root.join(relative);
        let mut children = fs::read_dir(directory)?.collect::<io::Result<Vec<_>>>()?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let name = child.file_name();
            let name = name.to_str().ok_or_else(|| {
                ArcError::InvalidArchive("package source contains a non-UTF-8 path".into())
            })?;
            let child_relative = relative.join(name);
            let path = child_relative
                .to_str()
                .ok_or_else(|| ArcError::InvalidArchive("non-UTF-8 path".into()))?;
            validate_member_path(path)?;
            output.push(child_relative.clone());
            if child.file_type()?.is_dir() {
                visit(root, &child_relative, output)?;
            }
        }
        Ok(())
    }

    let mut output = Vec::new();
    visit(root, Path::new(""), &mut output)?;
    Ok(output)
}

fn base_header(
    entry_type: EntryType,
    mode: u32,
    size: u64,
    epoch: u64,
    uid: u64,
    gid: u64,
) -> Header {
    let mut header = Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_mode(mode);
    header.set_uid(uid);
    header.set_gid(gid);
    header.set_size(size);
    header.set_mtime(epoch);
    header
}

type PackageBuilder = Builder<zstd::Encoder<'static, File>>;

fn append_regular(
    builder: &mut PackageBuilder,
    source: &Path,
    archive_path: &Path,
    epoch: u64,
    owner: (u64, u64),
) -> Result<()> {
    let metadata = fs::metadata(source)?;
    let mut header = base_header(
        EntryType::Regular,
        metadata.permissions().mode() & 0o7777,
        metadata.len(),
        epoch,
        owner.0,
        owner.1,
    );
    let mut file = File::open(source)?;
    append_xattrs(builder, source)?;
    builder.append_data(&mut header, archive_path, &mut file)?;
    Ok(())
}

fn append_source_member(
    builder: &mut PackageBuilder,
    root: &Path,
    relative: &Path,
    epoch: u64,
    hardlinks: &mut HashMap<(u64, u64), PathBuf>,
    package_metadata: &Metadata,
) -> Result<()> {
    let source = root.join(relative);
    let metadata = fs::symlink_metadata(&source)?;
    let mode = metadata.permissions().mode() & 0o7777;
    let owner = payload_owner(package_metadata, metadata.uid(), metadata.gid());
    let file_type = metadata.file_type();

    if file_type.is_file() {
        let identity = (metadata.dev(), metadata.ino());
        if metadata.nlink() > 1 {
            if let Some(target) = hardlinks.get(&identity) {
                let mut header = base_header(EntryType::Link, mode, 0, epoch, owner.0, owner.1);
                header.set_link_name(target)?;
                builder.append_data(&mut header, relative, io::empty())?;
                return Ok(());
            }
            hardlinks.insert(identity, relative.to_owned());
        }
        append_regular(builder, &source, relative, epoch, owner)
    } else if file_type.is_dir() {
        let mut header = base_header(EntryType::Directory, mode, 0, epoch, owner.0, owner.1);
        append_xattrs(builder, &source)?;
        builder.append_data(&mut header, relative, io::empty())?;
        Ok(())
    } else if file_type.is_symlink() {
        let target = fs::read_link(&source)?;
        if target.to_str().is_none() {
            return Err(ArcError::InvalidArchive(format!(
                "symlink {} has a non-UTF-8 target",
                relative.display()
            )));
        }
        let mut header = base_header(EntryType::Symlink, mode, 0, epoch, owner.0, owner.1);
        header.set_link_name(target)?;
        append_xattrs(builder, &source)?;
        builder.append_data(&mut header, relative, io::empty())?;
        Ok(())
    } else {
        Err(ArcError::InvalidArchive(format!(
            "unsupported special file {}",
            relative.display()
        )))
    }
}

fn payload_owner(metadata: &Metadata, uid: u32, gid: u32) -> (u64, u64) {
    if uid == 0 && gid == 0 {
        return (0, 0);
    }
    let build_uid = unsafe { libc::geteuid() };
    let build_gid = unsafe { libc::getegid() };
    if uid == build_uid && gid == build_gid {
        return (u64::from(uid), u64::from(gid));
    }
    let declared_user = metadata
        .users
        .iter()
        .any(|user| user.uid == uid && user.gid == gid);
    let declared_group = metadata.groups.iter().any(|group| group.gid == gid);
    if declared_user && declared_group {
        (u64::from(uid), u64::from(gid))
    } else {
        (0, 0)
    }
}

fn append_xattrs(builder: &mut PackageBuilder, source: &Path) -> Result<()> {
    let mut attributes = xattr::list(source)?
        .map(|name| {
            let name = name.into_string().map_err(|_| {
                ArcError::InvalidArchive(format!(
                    "{} has a non-UTF-8 extended attribute name",
                    source.display()
                ))
            })?;
            let value = xattr::get(source, &name)?.ok_or_else(|| {
                ArcError::InvalidArchive(format!(
                    "extended attribute {name:?} disappeared from {}",
                    source.display()
                ))
            })?;
            Ok((format!("SCHILY.xattr.{name}"), value))
        })
        .collect::<Result<Vec<_>>>()?;
    attributes.sort_by(|first, second| first.0.cmp(&second.0));
    validate_xattrs(source, &attributes)?;
    builder.append_pax_extensions(
        attributes
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice())),
    )?;
    Ok(())
}

fn validate_xattrs(source: &Path, attributes: &[(String, Vec<u8>)]) -> Result<()> {
    if attributes.len() > MAX_PAX_ATTRIBUTES {
        return Err(ArcError::InvalidArchive(format!(
            "{} has more than {MAX_PAX_ATTRIBUTES} extended attributes",
            source.display()
        )));
    }
    let mut total = 0_usize;
    for (key, value) in attributes {
        let name = key.strip_prefix("SCHILY.xattr.").unwrap_or(key);
        if name.is_empty() || name.len() > MAX_XATTR_NAME || name.contains('\0') {
            return Err(ArcError::InvalidArchive(format!(
                "{} has an invalid extended attribute name",
                source.display()
            )));
        }
        if value.len() > MAX_XATTR_VALUE {
            return Err(ArcError::InvalidArchive(format!(
                "extended attribute {name:?} on {} exceeds 1 MiB",
                source.display()
            )));
        }
        total = total
            .checked_add(key.len() + value.len())
            .ok_or_else(|| ArcError::InvalidArchive("extended attribute size overflow".into()))?;
    }
    if total > MAX_PAX_SIZE {
        return Err(ArcError::InvalidArchive(format!(
            "extended attributes on {} exceed 4 MiB",
            source.display()
        )));
    }
    Ok(())
}

fn validate_pax<R: Read>(entry: &mut tar::Entry<'_, R>) -> Result<()> {
    let Some(extensions) = entry.pax_extensions()? else {
        return Ok(());
    };
    let mut count = 0_usize;
    let mut total = 0_usize;
    for extension in extensions {
        let extension = extension?;
        count += 1;
        if count > MAX_PAX_ATTRIBUTES {
            return Err(ArcError::InvalidArchive(format!(
                "archive member has more than {MAX_PAX_ATTRIBUTES} PAX attributes"
            )));
        }
        let key = extension.key_bytes();
        let value = extension.value_bytes();
        total = total
            .checked_add(key.len() + value.len())
            .ok_or_else(|| ArcError::InvalidArchive("PAX attribute size overflow".into()))?;
        if total > MAX_PAX_SIZE {
            return Err(ArcError::InvalidArchive(
                "archive member PAX attributes exceed 4 MiB".into(),
            ));
        }
        if key.starts_with(b"GNU.sparse.") {
            return Err(ArcError::InvalidArchive(
                "GNU sparse archive members are unsupported".into(),
            ));
        }
        if let Some(name) = key.strip_prefix(b"SCHILY.xattr.") {
            if name.is_empty()
                || name.len() > MAX_XATTR_NAME
                || name.contains(&0)
                || std::str::from_utf8(name).is_err()
                || value.len() > MAX_XATTR_VALUE
            {
                return Err(ArcError::InvalidArchive(
                    "archive member contains an invalid extended attribute".into(),
                ));
            }
        }
    }
    Ok(())
}

fn member_path<R: Read>(entry: &tar::Entry<'_, R>) -> Result<String> {
    let path = entry.path()?;
    let path = path
        .to_str()
        .ok_or_else(|| ArcError::InvalidArchive("member path is not UTF-8".into()))?;
    validate_member_path(path)?;
    Ok(path.to_owned())
}

pub(crate) fn validate_member_path(path: &str) -> Result<()> {
    if path.len() > MAX_PATH_LENGTH
        || path
            .split('/')
            .any(|component| component.len() > MAX_COMPONENT_LENGTH)
    {
        return Err(ArcError::InvalidArchive(format!(
            "member path exceeds filesystem limits: {path:?}"
        )));
    }
    let path = Path::new(path);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ArcError::InvalidArchive(format!(
            "unsafe or non-normalized member path {:?}",
            path
        )));
    }
    Ok(())
}

fn is_internal(path: &str) -> bool {
    path == ".arc" || path.starts_with(".arc/")
}

fn classify_member(path: &str, entry_type: EntryType) -> Result<MemberKind> {
    if is_internal(path) {
        let valid_internal = ((path == ".arc" || path == ".arc/hooks") && entry_type.is_dir())
            || path
                .strip_prefix(".arc/hooks/")
                .is_some_and(|hook| HOOK_NAMES.contains(&hook) && entry_type.is_file());
        if !valid_internal {
            return Err(ArcError::InvalidArchive(format!(
                "unknown or invalid internal member {path:?}"
            )));
        }
        return Ok(MemberKind::Internal);
    }

    if entry_type.is_file() {
        Ok(MemberKind::File)
    } else if entry_type.is_dir() {
        Ok(MemberKind::Directory)
    } else if entry_type.is_symlink() {
        Ok(MemberKind::Symlink)
    } else if entry_type.is_hard_link() {
        Ok(MemberKind::Hardlink)
    } else {
        Err(ArcError::InvalidArchive(format!(
            "unsupported member type for {path:?}"
        )))
    }
}

fn validate_member_graph(members: &[Member]) -> Result<()> {
    let kinds = members
        .iter()
        .map(|member| (member.path.as_str(), member.kind))
        .collect::<BTreeMap<_, _>>();

    for member in members {
        if member.kind == MemberKind::Internal {
            continue;
        }
        let mut parent = Path::new(&member.path).parent();
        while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
            let path = path.to_str().expect("validated UTF-8 member path");
            if kinds
                .get(path)
                .is_some_and(|kind| *kind != MemberKind::Directory)
            {
                return Err(ArcError::InvalidArchive(format!(
                    "member {:?} is nested below non-directory {path:?}",
                    member.path
                )));
            }
            parent = Path::new(path).parent();
        }

        if member.kind == MemberKind::Hardlink
            && !kinds
                .get(member.target.as_str())
                .is_some_and(|kind| *kind == MemberKind::File)
        {
            return Err(ArcError::InvalidArchive(format!(
                "hardlink {:?} does not target a regular payload file",
                member.path
            )));
        }
    }
    Ok(())
}

pub fn sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(crate::encoding::hex_encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn unsafe_paths_are_rejected() {
        for path in ["", "/etc/passwd", "../escape", "usr/../escape", "./usr/bin"] {
            assert!(validate_member_path(path).is_err(), "accepted {path:?}");
        }
        assert!(validate_member_path("usr/bin/hello").is_ok());
        assert!(validate_member_path(&"a".repeat(MAX_COMPONENT_LENGTH + 1)).is_err());
    }

    #[test]
    fn oversized_internal_files_are_rejected() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path().join("root");
        fs::create_dir_all(root.join(".arc/hooks")).unwrap();
        fs::write(
            root.join(METADATA_PATH),
            "format = 1\nname = \"large-hook\"\nversion = \"1\"\narch = \"any\"\n",
        )
        .unwrap();
        fs::write(
            root.join(".arc/hooks/post-install"),
            vec![b'x'; MAX_INTERNAL_SIZE as usize + 1],
        )
        .unwrap();
        let archive = workspace.path().join("large-hook.arc");
        pack(&root, Some(&archive)).unwrap();
        let error = inspect(&archive).unwrap_err();
        assert!(error.to_string().contains("exceeds 1 MiB"));
    }

    #[test]
    fn links_cannot_redirect_later_extraction() {
        let members = vec![
            Member {
                path: "usr".into(),
                kind: MemberKind::Symlink,
                mode: 0o777,
                uid: 0,
                gid: 0,
                size: 0,
                target: "/tmp".into(),
            },
            Member {
                path: "usr/bin/escape".into(),
                kind: MemberKind::File,
                mode: 0o755,
                uid: 0,
                gid: 0,
                size: 1,
                target: String::new(),
            },
        ];
        assert!(validate_member_graph(&members).is_err());
    }

    #[test]
    fn hardlinks_must_target_packaged_regular_files() {
        let members = vec![Member {
            path: "usr/bin/tool".into(),
            kind: MemberKind::Hardlink,
            mode: 0o755,
            uid: 0,
            gid: 0,
            size: 0,
            target: "usr/bin/missing".into(),
        }];
        assert!(validate_member_graph(&members).is_err());
    }

    #[test]
    fn package_round_trip_is_deterministic() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path().join("root");
        fs::create_dir_all(root.join(".arc")).unwrap();
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::write(
            root.join(METADATA_PATH),
            "format = 1\nname = \"hello\"\nversion = \"1.0-1\"\narch = \"x86_64\"\n",
        )
        .unwrap();
        fs::write(root.join("usr/bin/hello"), "hello\n").unwrap();
        fs::hard_link(root.join("usr/bin/hello"), root.join("usr/bin/hello-hard")).unwrap();
        let has_xattrs =
            xattr::set(root.join("usr/bin/hello"), "user.arc-test", b"preserved").is_ok();
        symlink("hello", root.join("usr/bin/hi")).unwrap();

        let first = workspace.path().join("first.arc");
        let second = workspace.path().join("second.arc");
        pack(&root, Some(&first)).unwrap();
        pack(&root, Some(&second)).unwrap();

        let inspection = inspect(&first).unwrap();
        assert_eq!(inspection.metadata.name, "hello");
        assert_eq!(inspection.payload_size, 6);
        assert_eq!(sha256(&first).unwrap(), sha256(&second).unwrap());
        assert!(
            inspection.members.iter().any(|member| {
                member.path == "usr/bin/hi" && member.kind == MemberKind::Symlink
            })
        );
        assert!(inspection.members.iter().any(|member| {
            member.path == "usr/bin/hello-hard" && member.kind == MemberKind::Hardlink
        }));

        let staging = workspace.path().join("staging");
        extract(&first, &staging).unwrap();
        assert_eq!(
            fs::read_to_string(staging.join("usr/bin/hello")).unwrap(),
            "hello\n"
        );
        assert_eq!(
            fs::read_link(staging.join("usr/bin/hi")).unwrap(),
            Path::new("hello")
        );
        assert_eq!(
            fs::metadata(staging.join("usr/bin/hello")).unwrap().ino(),
            fs::metadata(staging.join("usr/bin/hello-hard"))
                .unwrap()
                .ino()
        );
        if has_xattrs {
            assert_eq!(
                xattr::get(staging.join("usr/bin/hello"), "user.arc-test").unwrap(),
                Some(b"preserved".to_vec())
            );
        }
    }
}
