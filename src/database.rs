//! Reading, validating, and writing Arc's installed-package records.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{ArcError, Result};
use crate::metadata::Metadata;
use crate::package::validate_member_path;

pub const STATE_FORMAT_VERSION: u32 = 1;
const MAX_RECORD_SIZE: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Hardlink,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    pub path: String,
    pub kind: FileKind,
    pub mode: u32,
    #[serde(default)]
    pub uid: u64,
    #[serde(default)]
    pub gid: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledPackage {
    pub format: u32,
    pub explicit: bool,
    pub package: Metadata,
    #[serde(default)]
    pub files: Vec<FileRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub hooks: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryPackage {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub format: u32,
    pub timestamp_ns: u128,
    pub action: String,
    pub outcome: String,
    #[serde(default, rename = "package")]
    pub packages: Vec<HistoryPackage>,
}

impl InstalledPackage {
    pub fn validate(&self) -> Result<()> {
        if self.format != STATE_FORMAT_VERSION {
            return Err(ArcError::InvalidState(format!(
                "unsupported state format {}; expected {STATE_FORMAT_VERSION}",
                self.format
            )));
        }
        self.package.validate()?;

        for (name, script) in &self.hooks {
            if !crate::package::HOOK_NAMES.contains(&name.as_str()) {
                return Err(ArcError::InvalidState(format!(
                    "unknown hook {name:?} for {}",
                    self.package.name
                )));
            }
            if script.len() > 1024 * 1024 || script.contains('\0') {
                return Err(ArcError::InvalidState(format!(
                    "invalid hook {name:?} for {}",
                    self.package.name
                )));
            }
        }

        let mut previous: Option<&str> = None;
        for file in &self.files {
            file.validate()?;
            if previous.is_some_and(|path| path >= file.path.as_str()) {
                return Err(ArcError::InvalidState(format!(
                    "file records for {} are not uniquely sorted",
                    self.package.name
                )));
            }
            previous = Some(&file.path);
        }
        Ok(())
    }
}

impl FileRecord {
    pub fn validate(&self) -> Result<()> {
        validate_member_path(&self.path)
            .map_err(|error| ArcError::InvalidState(error.to_string()))?;
        if self.path == ".arc" || self.path.starts_with(".arc/") {
            return Err(ArcError::InvalidState(format!(
                "installed file path {:?} is reserved",
                self.path
            )));
        }
        if self.mode > 0o7777 {
            return Err(ArcError::InvalidState(format!(
                "invalid mode for {:?}",
                self.path
            )));
        }

        match self.kind {
            FileKind::Regular => {
                validate_digest(&self.sha256, &self.path)?;
                if !self.target.is_empty() {
                    return Err(ArcError::InvalidState(format!(
                        "regular file {:?} has a link target",
                        self.path
                    )));
                }
            }
            FileKind::Directory => {
                if !self.sha256.is_empty() || !self.target.is_empty() {
                    return Err(ArcError::InvalidState(format!(
                        "directory {:?} has file-only metadata",
                        self.path
                    )));
                }
            }
            FileKind::Symlink => {
                if self.target.is_empty() || !self.sha256.is_empty() {
                    return Err(ArcError::InvalidState(format!(
                        "invalid symlink record {:?}",
                        self.path
                    )));
                }
            }
            FileKind::Hardlink => {
                validate_member_path(&self.target)
                    .map_err(|error| ArcError::InvalidState(error.to_string()))?;
                if !self.sha256.is_empty() {
                    return Err(ArcError::InvalidState(format!(
                        "hardlink {:?} has an independent digest",
                        self.path
                    )));
                }
            }
        }
        Ok(())
    }
}

fn validate_digest(digest: &str, path: &str) -> Result<()> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ArcError::InvalidState(format!(
            "invalid SHA-256 digest for {path:?}"
        )))
    }
}

#[derive(Clone, Debug)]
pub struct Database {
    root: PathBuf,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DoctorReport {
    pub packages: usize,
    pub files: usize,
    pub problems: Vec<String>,
}

impl Database {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        if !root.is_absolute() {
            return Err(ArcError::Usage(
                "target root must be an absolute path".into(),
            ));
        }
        Ok(Self { root })
    }

    pub fn state_dir(&self) -> PathBuf {
        self.root.join("var/lib/arc")
    }

    pub fn installed_dir(&self) -> PathBuf {
        self.state_dir().join("installed")
    }

    pub fn load_all(&self) -> Result<Vec<InstalledPackage>> {
        let directory = self.installed_dir();
        if !directory.exists() {
            return Ok(Vec::new());
        }

        let mut paths = fs::read_dir(&directory)?
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
            .collect::<Vec<_>>();
        paths.sort_by_key(|entry| entry.file_name());

        let mut packages = Vec::with_capacity(paths.len());
        for entry in paths {
            if !entry.file_type()?.is_file()
                || entry.path().extension().and_then(|value| value.to_str()) != Some("toml")
            {
                return Err(ArcError::InvalidState(format!(
                    "unexpected installed-state entry {}",
                    entry.path().display()
                )));
            }
            let metadata = entry.metadata()?;
            if metadata.len() > MAX_RECORD_SIZE {
                return Err(ArcError::InvalidState(format!(
                    "installed-state record {} exceeds 128 MiB",
                    entry.path().display()
                )));
            }
            let text = fs::read_to_string(entry.path())?;
            let package: InstalledPackage = toml::from_str(&text)?;
            package.validate()?;
            let expected = format!("{}.toml", package.package.name);
            if entry.file_name() != expected.as_str() {
                return Err(ArcError::InvalidState(format!(
                    "record {} contains package {}",
                    entry.path().display(),
                    package.package.name
                )));
            }
            packages.push(package);
        }
        Ok(packages)
    }

    pub fn load(&self, name: &str) -> Result<Option<InstalledPackage>> {
        crate::version::validate_name(name)?;
        let path = self.installed_dir().join(format!("{name}.toml"));
        if !path.exists() {
            return Ok(None);
        }
        let text = fs::read_to_string(path)?;
        let package: InstalledPackage = toml::from_str(&text)?;
        package.validate()?;
        Ok(Some(package))
    }

    pub fn write(&self, package: &InstalledPackage) -> Result<()> {
        package.validate()?;
        let directory = self.installed_dir();
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
        let destination = directory.join(format!("{}.toml", package.package.name));
        let temporary = directory.join(format!(
            ".{}.toml.part-{}",
            package.package.name,
            std::process::id()
        ));
        let text = toml::to_string_pretty(package)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        if let Err(error) = (|| -> Result<()> {
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            fs::rename(&temporary, &destination)?;
            sync_directory(&directory)?;
            Ok(())
        })() {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        Ok(())
    }

    pub fn remove(&self, name: &str) -> Result<bool> {
        crate::version::validate_name(name)?;
        let path = self.installed_dir().join(format!("{name}.toml"));
        match fs::remove_file(path) {
            Ok(()) => {
                sync_directory(&self.installed_dir())?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn ownership(&self) -> Result<BTreeMap<String, String>> {
        let mut ownership = BTreeMap::new();
        for package in self.load_all()? {
            for file in package
                .files
                .iter()
                .filter(|file| file.kind != FileKind::Directory)
            {
                if let Some(owner) =
                    ownership.insert(file.path.clone(), package.package.name.clone())
                {
                    return Err(ArcError::InvalidState(format!(
                        "file {:?} is owned by both {owner} and {}",
                        file.path, package.package.name
                    )));
                }
            }
        }
        Ok(ownership)
    }

    pub fn set_explicit(&self, names: &[String], explicit: bool) -> Result<()> {
        for name in names {
            let mut package = self
                .load(name)?
                .ok_or_else(|| ArcError::Usage(format!("package {name} is not installed")))?;
            package.explicit = explicit;
            self.write(&package)?;
        }
        Ok(())
    }

    pub fn verify(&self, names: &[String]) -> Result<Vec<String>> {
        let wanted = if names.is_empty() { None } else { Some(names) };
        let mut problems = Vec::new();
        for package in self.load_all()? {
            if wanted.is_some_and(|names| !names.contains(&package.package.name)) {
                continue;
            }
            for file in &package.files {
                let path = self.root.join(&file.path);
                let metadata = match fs::symlink_metadata(&path) {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        problems.push(format!("{}: missing {}", package.package.name, file.path));
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let kind_matches = match file.kind {
                    FileKind::Regular => metadata.is_file(),
                    FileKind::Directory => metadata.is_dir(),
                    FileKind::Symlink => metadata.file_type().is_symlink(),
                    FileKind::Hardlink => metadata.is_file(),
                };
                if !kind_matches {
                    problems.push(format!(
                        "{}: type differs: {}",
                        package.package.name, file.path
                    ));
                    continue;
                }
                if metadata.permissions().mode() & 0o7777 != file.mode {
                    problems.push(format!(
                        "{}: mode differs: {}",
                        package.package.name, file.path
                    ));
                }
                if u64::from(metadata.uid()) != file.uid || u64::from(metadata.gid()) != file.gid {
                    problems.push(format!(
                        "{}: ownership differs: {}",
                        package.package.name, file.path
                    ));
                }
                if file.kind == FileKind::Regular && crate::package::sha256(&path)? != file.sha256 {
                    problems.push(format!(
                        "{}: checksum differs: {}",
                        package.package.name, file.path
                    ));
                }
                if file.kind == FileKind::Symlink
                    && fs::read_link(&path)?.to_string_lossy() != file.target
                {
                    problems.push(format!(
                        "{}: link differs: {}",
                        package.package.name, file.path
                    ));
                }
            }
        }
        Ok(problems)
    }

    pub fn doctor(&self) -> Result<DoctorReport> {
        let packages = self.load_all()?;
        let files = packages.iter().map(|package| package.files.len()).sum();
        let mut report = DoctorReport {
            packages: packages.len(),
            files,
            problems: self.verify(&[])?,
        };
        if let Err(error) = self.ownership() {
            report.problems.push(error.to_string());
        }
        Ok(report)
    }

    pub fn unowned_paths(&self, selected: &[PathBuf]) -> Result<Vec<String>> {
        let ownership = self.ownership()?;
        let mut unowned = Vec::new();
        for selected in selected {
            let relative = selected.strip_prefix("/").unwrap_or(selected).to_path_buf();
            if relative.as_os_str().is_empty()
                || relative
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err(ArcError::Usage(format!(
                    "invalid path selection {}",
                    selected.display()
                )));
            }
            self.collect_unowned(&relative, &ownership, &mut unowned)?;
        }
        unowned.sort();
        unowned.dedup();
        Ok(unowned)
    }

    pub fn required_by(&self, name: &str) -> Result<Vec<InstalledPackage>> {
        crate::version::validate_name(name)?;
        let packages = self.load_all()?;
        Ok(packages
            .iter()
            .filter(|package| {
                package.package.depends.iter().any(|dependency| {
                    crate::version::Requirement::parse(dependency)
                        .map(|requirement| requirement.name == name)
                        .unwrap_or(false)
                })
            })
            .cloned()
            .collect())
    }

    fn collect_unowned(
        &self,
        relative: &Path,
        ownership: &BTreeMap<String, String>,
        output: &mut Vec<String>,
    ) -> Result<()> {
        let path = self.root.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            ArcError::Usage(format!("cannot inspect /{}: {error}", relative.display()))
        })?;
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                self.collect_unowned(&relative.join(entry.file_name()), ownership, output)?;
            }
        } else {
            let relative = relative.to_string_lossy().into_owned();
            if !ownership.contains_key(&relative) {
                output.push(format!("unowned /{relative}"));
            }
        }
        Ok(())
    }

    pub fn log(&self, action: &str, packages: &[InstalledPackage]) -> Result<()> {
        let directory = self.state_dir().join("history");
        fs::create_dir_all(&directory)?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ArcError::InvalidState("system clock is before the Unix epoch".into()))?
            .as_nanos();
        let path = directory.join(format!("{stamp}-{}.toml", std::process::id()));
        let entry = HistoryEntry {
            format: STATE_FORMAT_VERSION,
            timestamp_ns: stamp,
            action: action.into(),
            outcome: "committed".into(),
            packages: packages
                .iter()
                .map(|package| HistoryPackage {
                    name: package.package.name.clone(),
                    version: package.package.version.clone(),
                    architecture: package.package.arch.clone(),
                    reason: if package.explicit {
                        "explicit".into()
                    } else {
                        "dependency".into()
                    },
                })
                .collect(),
        };
        let contents = toml::to_string_pretty(&entry)?;
        let temporary = directory.join(format!(".{stamp}-{}.part", std::process::id()));
        fs::write(&temporary, contents)?;
        fs::rename(temporary, path)?;
        sync_directory(&directory)?;
        Ok(())
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn installed(name: &str, path: &str) -> InstalledPackage {
        InstalledPackage {
            format: 1,
            explicit: true,
            package: Metadata {
                format: 1,
                name: name.into(),
                version: "1".into(),
                arch: "x86_64".into(),
                description: String::new(),
                license: String::new(),
                url: String::new(),
                self_contained: false,
                bundled: vec![],
                depends: vec![],
                optdepends: vec![],
                package_groups: vec![],
                provides: vec![],
                conflicts: vec![],
                replaces: vec![],
                backup: vec![],
                triggers: vec![],
                groups: vec![],
                users: vec![],
            },
            files: vec![FileRecord {
                path: path.into(),
                kind: FileKind::Regular,
                mode: 0o755,
                uid: 0,
                gid: 0,
                sha256: HASH.into(),
                target: String::new(),
            }],
            hooks: BTreeMap::new(),
        }
    }

    #[test]
    fn records_round_trip_atomically() {
        let root = tempfile::tempdir().unwrap();
        let database = Database::new(root.path()).unwrap();
        let package = installed("hello", "usr/bin/hello");
        database.write(&package).unwrap();
        assert_eq!(database.load("hello").unwrap(), Some(package.clone()));
        assert_eq!(database.load_all().unwrap(), [package]);
        assert!(database.remove("hello").unwrap());
        assert!(!database.remove("hello").unwrap());
    }

    #[test]
    fn history_records_versions_reasons_and_outcome() {
        let workspace = tempfile::tempdir().unwrap();
        let database = Database::new(workspace.path()).unwrap();
        let mut dependency = installed("libhello", "usr/lib/libhello.so");
        dependency.explicit = false;
        database.log("install", &[dependency]).unwrap();

        let history = workspace.path().join("var/lib/arc/history");
        let entry = fs::read_dir(&history).unwrap().next().unwrap().unwrap();
        let record: HistoryEntry =
            toml::from_str(&fs::read_to_string(entry.path()).unwrap()).unwrap();
        assert_eq!(record.format, STATE_FORMAT_VERSION);
        assert_eq!(record.action, "install");
        assert_eq!(record.outcome, "committed");
        assert_eq!(record.packages.len(), 1);
        assert_eq!(record.packages[0].name, "libhello");
        assert_eq!(record.packages[0].version, "1");
        assert_eq!(record.packages[0].reason, "dependency");
    }

    #[test]
    fn ownership_conflicts_are_detected() {
        let root = tempfile::tempdir().unwrap();
        let database = Database::new(root.path()).unwrap();
        database.write(&installed("first", "usr/bin/tool")).unwrap();
        database
            .write(&installed("second", "usr/bin/tool"))
            .unwrap();
        assert!(database.ownership().is_err());
    }

    #[test]
    fn records_must_be_uniquely_sorted() {
        let mut package = installed("hello", "usr/bin/hello");
        package.files.push(package.files[0].clone());
        assert!(package.validate().is_err());
    }

    #[test]
    fn doctor_reports_missing_payload_files() {
        let root = tempfile::tempdir().unwrap();
        let database = Database::new(root.path()).unwrap();
        database
            .write(&installed("hello", "usr/bin/hello"))
            .unwrap();
        let report = database.doctor().unwrap();
        assert_eq!(report.packages, 1);
        assert_eq!(report.files, 1);
        assert_eq!(report.problems, ["hello: missing usr/bin/hello"]);
    }

    #[test]
    fn unowned_paths_only_walk_explicit_selections() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        fs::write(root.path().join("usr/bin/unowned"), "data").unwrap();
        fs::write(root.path().join("elsewhere"), "data").unwrap();
        let database = Database::new(root.path()).unwrap();
        assert_eq!(
            database.unowned_paths(&[PathBuf::from("/usr")]).unwrap(),
            ["unowned /usr/bin/unowned"]
        );
    }
}
