//! Journaled installation and removal of package payloads.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use serde::{Deserialize, Serialize};

use crate::database::{Database, FileKind, FileRecord, InstalledPackage};
use crate::error::{ArcError, Result};
use crate::package::{self, Inspection, Member, MemberKind};
use crate::resolver::package_satisfies;
use crate::triggers;
use crate::version::{Requirement, validate_name};

const JOURNAL_FORMAT_VERSION: u32 = 1;
const STATE_RELATIVE: &str = "var/lib/arc";
const TRANSACTION_RELATIVE: &str = "var/lib/arc/transaction";

#[derive(Clone, Debug)]
pub struct InstallArchive {
    pub path: PathBuf,
    pub explicit: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallSummary {
    pub packages: Vec<String>,
    pub files: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoveSummary {
    pub packages: Vec<String>,
    pub preserved: Vec<String>,
}

pub fn install(root: &Path, archives: &[InstallArchive]) -> Result<InstallSummary> {
    install_inner(root, archives, None)
}

pub fn plan_removal(root: &Path, names: &[String]) -> Result<Vec<InstalledPackage>> {
    let requested = removal_request(root, names)?;
    let root = root.canonicalize()?;
    let _lock = ArcLock::acquire(&root)?;
    recover_locked(&root)?;
    let installed = Database::new(&root)?.load_all()?;
    validate_removal_set(&installed, &requested)?;
    Ok(installed
        .into_iter()
        .filter(|package| requested.contains(&package.package.name))
        .collect())
}

pub fn orphans(root: &Path) -> Result<Vec<InstalledPackage>> {
    let installed = Database::new(root)?.load_all()?;
    Ok(installed
        .iter()
        .filter(|candidate| {
            !candidate.explicit
                && !installed.iter().any(|package| {
                    package.package.depends.iter().any(|dependency| {
                        Requirement::parse(dependency)
                            .ok()
                            .is_some_and(|requirement| {
                                package_satisfies(&candidate.package, &requirement)
                            })
                    })
                })
        })
        .cloned()
        .collect())
}

pub fn recursive_removal(root: &Path, names: &[String]) -> Result<Vec<String>> {
    let mut requested = removal_request(root, names)?;
    let installed = Database::new(root)?.load_all()?;
    loop {
        let mut added = false;
        for package in &installed {
            if requested.contains(&package.package.name) {
                continue;
            }
            if package.package.depends.iter().any(|dependency| {
                Requirement::parse(dependency)
                    .ok()
                    .is_some_and(|requirement| {
                        installed.iter().any(|candidate| {
                            requested.contains(&candidate.package.name)
                                && package_satisfies(&candidate.package, &requirement)
                        })
                    })
            }) {
                added |= requested.insert(package.package.name.clone());
            }
        }
        if !added {
            break;
        }
    }
    Ok(requested.into_iter().collect())
}

fn removal_request(root: &Path, names: &[String]) -> Result<BTreeSet<String>> {
    if names.is_empty() {
        return Err(ArcError::Transaction(
            "no packages were selected for removal".into(),
        ));
    }
    if !root.is_absolute() {
        return Err(ArcError::Transaction(
            "target root must be an absolute path".into(),
        ));
    }
    for name in names {
        validate_name(name)?;
    }
    let requested = names.iter().cloned().collect::<BTreeSet<_>>();
    if requested.len() != names.len() {
        return Err(ArcError::Transaction(
            "a package was selected for removal more than once".into(),
        ));
    }
    Ok(requested)
}

fn validate_removal_set(
    installed: &[InstalledPackage],
    requested: &BTreeSet<String>,
) -> Result<()> {
    for essential in ["glibc", "init", "arc"] {
        if requested.contains(essential) {
            return Err(ArcError::Transaction(format!(
                "refusing to remove protected essential package {essential}"
            )));
        }
    }
    for name in requested {
        if !installed
            .iter()
            .any(|package| package.package.name == *name)
        {
            return Err(ArcError::Transaction(format!(
                "package {name} is not installed"
            )));
        }
    }
    let remaining = installed
        .iter()
        .filter(|package| !requested.contains(&package.package.name))
        .collect::<Vec<_>>();
    for package in &remaining {
        for dependency in &package.package.depends {
            let requirement = Requirement::parse(dependency)?;
            if !remaining
                .iter()
                .any(|candidate| package_satisfies(&candidate.package, &requirement))
            {
                return Err(ArcError::Transaction(format!(
                    "removal would leave {} without dependency {dependency}",
                    package.package.name
                )));
            }
        }
    }
    Ok(())
}

pub fn remove(root: &Path, names: &[String]) -> Result<RemoveSummary> {
    let requested = removal_request(root, names)?;
    let root = root.canonicalize()?;
    let _lock = ArcLock::acquire(&root)?;
    recover_locked(&root)?;
    let database = Database::new(&root)?;
    let installed = database.load_all()?;
    validate_removal_set(&installed, &requested)?;

    let removing = installed
        .iter()
        .filter(|package| requested.contains(&package.package.name))
        .collect::<Vec<_>>();
    let requested_triggers = removing
        .iter()
        .flat_map(|package| package.package.triggers.iter().cloned())
        .collect::<BTreeSet<_>>();
    let trigger_configuration = triggers::Configuration::load(&root)?;
    for package in &removing {
        run_hook(&root, package, "pre-remove", None)?;
    }
    let mut journal = JournalStore::create(&root)?;
    let result = (|| -> Result<RemoveSummary> {
        let mut apply = ApplyState::default();
        let (directories, preserved) =
            remove_payload_files(&root, &removing, &mut journal, &mut apply)?;
        remove_empty_directories(&root, directories, &mut journal, &mut apply)?;
        remove_installed_records(&root, &removing, &mut journal, &mut apply)?;
        for package in &removing {
            run_hook(&root, package, "post-remove", None)?;
        }
        trigger_configuration.run(&root, &requested_triggers)?;
        journal.mark_committed()?;
        Database::new(&root)?.log("remove", &removing.into_iter().cloned().collect::<Vec<_>>())?;
        Ok(RemoveSummary {
            packages: requested.into_iter().collect(),
            preserved,
        })
    })();

    finish_transaction(&mut journal, result)
}

/// Remove non-directory payloads and remember directories for a later,
/// deepest-first pass. Modified configuration files are renamed, not deleted.
fn remove_payload_files(
    root: &Path,
    packages: &[&InstalledPackage],
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<(BTreeSet<String>, Vec<String>)> {
    let mut directories = BTreeSet::new();
    let mut preserved = Vec::new();

    for package in packages {
        for file in package.files.iter().rev() {
            if file.kind == FileKind::Directory {
                directories.insert(file.path.clone());
                continue;
            }
            let relative = Path::new(&file.path);
            let target = root.join(relative);
            let metadata = match fs::symlink_metadata(&target) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let is_backup =
                file.kind == FileKind::Regular && package.package.backup.contains(&file.path);
            let is_modified =
                is_backup && (!metadata.is_file() || package::sha256(&target)? != file.sha256);
            if is_modified {
                let saved = PathBuf::from(format!("{}.arc-save", file.path));
                if fs::symlink_metadata(root.join(&saved)).is_ok() {
                    return Err(ArcError::Transaction(format!(
                        "cannot preserve {:?}: {} already exists",
                        file.path,
                        saved.display()
                    )));
                }
                journal.record_created(&saved)?;
                journal.record_replaced(relative)?;
                fs::rename(&target, root.join(&saved))?;
                sync_directory(target.parent().expect("configuration has parent"))?;
                apply.changed()?;
                preserved.push(saved.to_string_lossy().into_owned());
            } else {
                journal.record_replaced(relative)?;
                remove_node(&target)?;
                sync_directory(target.parent().expect("payload file has parent"))?;
                apply.changed()?;
            }
        }
    }
    Ok((directories, preserved))
}

fn remove_empty_directories(
    root: &Path,
    directories: BTreeSet<String>,
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<()> {
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by(|first, second| {
        second
            .split('/')
            .count()
            .cmp(&first.split('/').count())
            .then_with(|| second.cmp(first))
    });
    for directory in directories {
        let relative = Path::new(&directory);
        let target = root.join(relative);
        let empty = match fs::read_dir(&target) {
            Ok(mut entries) => entries.next().is_none(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => false,
            Err(error) => return Err(error.into()),
        };
        if empty {
            journal.record_replaced(relative)?;
            fs::remove_dir(&target)?;
            sync_directory(target.parent().expect("payload directory has parent"))?;
            apply.changed()?;
        }
    }
    Ok(())
}

fn remove_installed_records(
    root: &Path,
    packages: &[&InstalledPackage],
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<()> {
    for package in packages {
        let relative = PathBuf::from(format!(
            "{STATE_RELATIVE}/installed/{}.toml",
            package.package.name
        ));
        journal.record_replaced(&relative)?;
        fs::remove_file(root.join(&relative))?;
        sync_directory(
            root.join(&relative)
                .parent()
                .expect("database record has parent"),
        )?;
        apply.changed()?;
    }
    Ok(())
}

fn install_inner(
    root: &Path,
    archives: &[InstallArchive],
    fail_after: Option<u64>,
) -> Result<InstallSummary> {
    if archives.is_empty() {
        return Err(ArcError::Transaction(
            "no package archives were supplied".into(),
        ));
    }
    if !root.is_absolute() {
        return Err(ArcError::Transaction(
            "target root must be an absolute path".into(),
        ));
    }
    let root = root.canonicalize()?;
    if !root.is_dir() {
        return Err(ArcError::Transaction(format!(
            "target root {} is not a directory",
            root.display()
        )));
    }

    let _lock = ArcLock::acquire(&root)?;
    recover_locked(&root)?;
    let mut journal = JournalStore::create(&root)?;
    let result = (|| -> Result<InstallSummary> {
        let mut staged = stage_archives(&root, archives)?;
        preflight(&root, &mut staged)?;
        let mut apply = ApplyState {
            fail_after,
            ..ApplyState::default()
        };
        apply_installation(&root, &staged, &mut journal, &mut apply)
    })();

    finish_transaction(&mut journal, result)
}

/// Apply one already-staged, preflighted package set in its required order.
fn apply_installation(
    root: &Path,
    staged: &[StagedPackage],
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<InstallSummary> {
    apply_system_accounts(root, staged, journal, apply)?;
    run_replacement_hooks(root, staged, "pre-remove")?;
    run_install_hooks(root, staged, InstallHookPhase::Pre)?;

    apply_staged(root, staged, journal, apply)?;
    remove_obsolete(root, staged, journal, apply)?;
    remove_replaced_records(root, staged, journal, apply)?;

    run_replacement_hooks(root, staged, "post-remove")?;
    let summary = write_installed_records(root, staged, journal, apply)?;
    run_install_hooks(root, staged, InstallHookPhase::Post)?;
    run_install_triggers(root, staged)?;

    journal.mark_committed()?;
    let records = staged
        .iter()
        .map(|package| package.record.clone())
        .collect::<Vec<_>>();
    Database::new(root)?.log("install", &records)?;
    Ok(summary)
}

fn run_replacement_hooks(root: &Path, staged: &[StagedPackage], hook: &str) -> Result<()> {
    for package in staged {
        for replaced in &package.replaced {
            run_hook(root, replaced, hook, None)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum InstallHookPhase {
    Pre,
    Post,
}

fn run_install_hooks(root: &Path, staged: &[StagedPackage], phase: InstallHookPhase) -> Result<()> {
    let (install_hook, upgrade_hook) = match phase {
        InstallHookPhase::Pre => ("pre-install", "pre-upgrade"),
        InstallHookPhase::Post => ("post-install", "post-upgrade"),
    };
    for package in staged {
        let (hook, old_version) = match &package.old {
            Some(old) => (upgrade_hook, Some(old.package.version.as_str())),
            None => (install_hook, None),
        };
        run_hook(root, &package.record, hook, old_version)?;
    }
    Ok(())
}

fn write_installed_records(
    root: &Path,
    staged: &[StagedPackage],
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<InstallSummary> {
    let mut packages = Vec::with_capacity(staged.len());
    let mut files = 0;
    for package in staged {
        let record_source = journal
            .directory
            .join("records")
            .join(format!("{}.toml", package.record.package.name));
        fs::create_dir_all(record_source.parent().expect("record has parent"))?;
        fs::write(&record_source, toml::to_string_pretty(&package.record)?)?;
        fs::set_permissions(&record_source, fs::Permissions::from_mode(0o644))?;
        let destination = PathBuf::from(format!(
            "{STATE_RELATIVE}/installed/{}.toml",
            package.record.package.name
        ));
        apply_regular(
            root,
            &destination,
            &record_source,
            0o644,
            u64::MAX,
            u64::MAX,
            package.old.is_some(),
            journal,
            apply,
        )?;
        packages.push(package.record.package.name.clone());
        files += package.record.files.len();
    }
    Ok(InstallSummary { packages, files })
}

fn run_install_triggers(root: &Path, staged: &[StagedPackage]) -> Result<()> {
    let requested = staged
        .iter()
        .flat_map(|package| {
            package
                .record
                .package
                .triggers
                .iter()
                .chain(
                    package
                        .replaced
                        .iter()
                        .flat_map(|replaced| replaced.package.triggers.iter()),
                )
                .cloned()
        })
        .collect::<BTreeSet<_>>();
    triggers::Configuration::load(root)?.run(root, &requested)
}

/// Complete a journaled operation. Successful operations discard their
/// backups; failed operations restore them before reporting the original error.
fn finish_transaction<T>(journal: &mut JournalStore, result: Result<T>) -> Result<T> {
    match result {
        Ok(value) => {
            journal.cleanup()?;
            Ok(value)
        }
        Err(error) => match journal.rollback() {
            Ok(()) => Err(error),
            Err(rollback) => Err(ArcError::Transaction(format!(
                "{error}; rollback also failed: {rollback}"
            ))),
        },
    }
}

fn apply_system_accounts(
    root: &Path,
    staged: &[StagedPackage],
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<()> {
    let groups = staged
        .iter()
        .flat_map(|package| package.record.package.groups.iter())
        .map(|group| {
            (
                group.name.clone(),
                group.gid,
                format!("{}:x:{}:", group.name, group.gid),
            )
        })
        .collect::<Vec<_>>();
    let users = staged
        .iter()
        .flat_map(|package| package.record.package.users.iter())
        .map(|user| {
            (
                user.name.clone(),
                user.uid,
                format!(
                    "{}:x:{}:{}::{}:{}",
                    user.name, user.uid, user.gid, user.home, user.shell
                ),
            )
        })
        .collect::<Vec<_>>();
    if groups.is_empty() && users.is_empty() {
        return Ok(());
    }
    apply_account_file(root, "etc/group", &groups, journal, apply)?;
    apply_account_file(root, "etc/passwd", &users, journal, apply)?;
    Ok(())
}

fn apply_account_file(
    root: &Path,
    relative: &str,
    requested: &[(String, u32, String)],
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<()> {
    if requested.is_empty() {
        return Ok(());
    }
    let relative_path = Path::new(relative);
    ensure_parents(root, relative_path, journal, apply)?;
    let path = root.join(relative_path);
    let current = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    let mut names = BTreeMap::new();
    let mut ids = BTreeMap::new();
    for (name, id, line) in requested {
        if names.insert(name, (*id, line)).is_some() || ids.insert(*id, name).is_some() {
            return Err(ArcError::Transaction(format!(
                "conflicting declared account {name:?}"
            )));
        }
    }
    let mut additions = Vec::new();
    for (name, id, line) in requested {
        let matching_name = current
            .lines()
            .find(|existing| existing.split(':').next() == Some(name));
        let matching_id = current
            .lines()
            .find(|existing| existing.split(':').nth(2) == Some(&id.to_string()));
        if let Some(existing) = matching_name {
            if existing != line {
                return Err(ArcError::Transaction(format!(
                    "existing account {name:?} conflicts with package declaration"
                )));
            }
        } else if let Some(existing) = matching_id {
            return Err(ArcError::Transaction(format!(
                "account ID {id} is already assigned to {existing:?}"
            )));
        } else {
            additions.push(line);
        }
    }
    if additions.is_empty() {
        return Ok(());
    }
    if path.exists() {
        journal.record_replaced(relative_path)?;
    } else {
        journal.record_created(relative_path)?;
    }
    let mut output = OpenOptions::new().create(true).append(true).open(&path)?;
    for line in additions {
        writeln!(output, "{line}")?;
    }
    output.set_permissions(fs::Permissions::from_mode(0o644))?;
    output.sync_all()?;
    sync_directory(path.parent().expect("account file has parent"))?;
    apply.changed()
}

fn run_hook(
    root: &Path,
    package: &InstalledPackage,
    hook: &str,
    old_version: Option<&str>,
) -> Result<()> {
    let Some(script) = package.hooks.get(hook) else {
        return Ok(());
    };
    if !root.join("bin/sh").is_file() {
        return Err(ArcError::Transaction(format!(
            "cannot run {hook} hook for {}: target root has no /bin/sh",
            package.package.name
        )));
    }

    let hook_root = root.to_owned();
    let mut command = Command::new("/bin/sh");
    command
        .arg("-eu")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("ARC_HOOK", hook)
        .env("ARC_PACKAGE", &package.package.name)
        .env("ARC_VERSION", &package.package.version)
        .env("ARC_OLD_VERSION", old_version.unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // SAFETY: this closure only invokes async-signal-safe chroot/chdir syscalls
    // before exec. It does not allocate, lock, or touch shared Rust state.
    unsafe {
        command.pre_exec(move || {
            if hook_root != Path::new("/") {
                rustix::process::chroot(&hook_root).map_err(std::io::Error::from)?;
            }
            rustix::process::chdir("/").map_err(std::io::Error::from)?;
            Ok(())
        });
    }

    let mut child = command.spawn().map_err(|error| {
        ArcError::Transaction(format!(
            "cannot start {hook} hook for {}: {error}",
            package.package.name
        ))
    })?;
    let mut stdin = child.stdin.take().expect("hook stdin is piped");
    let script = script.clone();
    let writer = thread::spawn(move || stdin.write_all(script.as_bytes()));
    let status_result = crate::process::wait_with_timeout(
        &mut child,
        &format!("{hook} hook for {}", package.package.name),
    );
    let write_result = writer
        .join()
        .map_err(|_| ArcError::Transaction("hook input writer panicked".into()))?;
    let status = status_result?;
    if let Err(error) = write_result {
        return Err(ArcError::Transaction(format!(
            "cannot provide script to {hook} hook for {}: {error}",
            package.package.name
        )));
    }
    if !status.success() {
        return Err(ArcError::Transaction(format!(
            "{hook} hook for {} exited with {status}",
            package.package.name
        )));
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct ArcLock {
    file: File,
}

impl ArcLock {
    pub(crate) fn acquire(root: &Path) -> Result<Self> {
        let state = root.join(STATE_RELATIVE);
        fs::create_dir_all(&state)?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755))?;
        let path = state.join("lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        crate::system::lock_exclusive(&file)?;
        Ok(Self { file })
    }
}

impl Drop for ArcLock {
    fn drop(&mut self) {
        let _ = crate::system::unlock(&self.file);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Applying,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    backup: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format: u32,
    phase: Phase,
    #[serde(default)]
    operation: Vec<Operation>,
}

impl Journal {
    fn validate(&self) -> Result<()> {
        if self.format != JOURNAL_FORMAT_VERSION {
            return Err(ArcError::Transaction(format!(
                "unsupported journal format {}",
                self.format
            )));
        }
        let mut paths = BTreeSet::new();
        for operation in &self.operation {
            validate_relative(&operation.path)?;
            if !paths.insert(&operation.path) {
                return Err(ArcError::Transaction(format!(
                    "duplicate journal operation for {:?}",
                    operation.path
                )));
            }
            if !operation.backup.is_empty() {
                validate_relative(&operation.backup)?;
                if !operation.backup.starts_with("backups/") {
                    return Err(ArcError::Transaction(format!(
                        "invalid backup path {:?}",
                        operation.backup
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct JournalStore {
    root: PathBuf,
    directory: PathBuf,
    journal: Journal,
}

impl JournalStore {
    fn create(root: &Path) -> Result<Self> {
        let directory = root.join(TRANSACTION_RELATIVE);
        if directory.exists() {
            return Err(ArcError::Transaction(
                "a previous transaction was not recovered".into(),
            ));
        }
        fs::create_dir(&directory)?;
        fs::create_dir(directory.join("backups"))?;
        let mut store = Self {
            root: root.to_owned(),
            directory,
            journal: Journal {
                format: JOURNAL_FORMAT_VERSION,
                phase: Phase::Applying,
                operation: Vec::new(),
            },
        };
        store.persist()?;
        Ok(store)
    }

    fn load(root: &Path) -> Result<Self> {
        let directory = root.join(TRANSACTION_RELATIVE);
        let text = fs::read_to_string(directory.join("journal.toml"))?;
        let journal: Journal = toml::from_str(&text)?;
        journal.validate()?;
        Ok(Self {
            root: root.to_owned(),
            directory,
            journal,
        })
    }

    fn persist(&mut self) -> Result<()> {
        self.journal.validate()?;
        let destination = self.directory.join("journal.toml");
        let temporary = self.directory.join(".journal.toml.part");
        let _ = fs::remove_file(&temporary);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(toml::to_string_pretty(&self.journal)?.as_bytes())?;
        file.sync_all()?;
        fs::rename(temporary, destination)?;
        sync_directory(&self.directory)?;
        Ok(())
    }

    fn record_created(&mut self, path: &Path) -> Result<()> {
        let path = relative_string(path)?;
        if self
            .journal
            .operation
            .iter()
            .any(|operation| operation.path == path)
        {
            return Err(ArcError::Transaction(format!(
                "path {path:?} was modified twice in one transaction"
            )));
        }
        self.journal.operation.push(Operation {
            path,
            backup: String::new(),
        });
        self.persist()
    }

    fn record_replaced(&mut self, path: &Path) -> Result<()> {
        let path = relative_string(path)?;
        if self
            .journal
            .operation
            .iter()
            .any(|operation| operation.path == path)
        {
            return Err(ArcError::Transaction(format!(
                "path {path:?} was modified twice in one transaction"
            )));
        }
        let target = self.root.join(&path);
        fs::symlink_metadata(&target).map_err(|error| {
            ArcError::Transaction(format!(
                "cannot back up {} before replacement: {error}",
                target.display()
            ))
        })?;
        let backup = format!("backups/{:08}", self.journal.operation.len());
        backup_node(&target, &self.directory.join(&backup))?;
        sync_directory(self.directory.join("backups").as_path())?;
        self.journal.operation.push(Operation { path, backup });
        self.persist()
    }

    fn mark_committed(&mut self) -> Result<()> {
        self.journal.phase = Phase::Committed;
        self.persist()
    }

    fn rollback(&mut self) -> Result<()> {
        if self.journal.phase == Phase::Committed {
            return self.cleanup();
        }
        for operation in self.journal.operation.iter().rev() {
            let target = self.root.join(&operation.path);
            if operation.backup.is_empty() {
                remove_node(&target)?;
            } else {
                remove_node(&target)?;
                restore_node(&self.directory.join(&operation.backup), &target)?;
            }
        }
        self.cleanup()
    }

    fn cleanup(&self) -> Result<()> {
        if self.directory.exists() {
            fs::remove_dir_all(&self.directory)?;
            sync_directory(
                self.directory
                    .parent()
                    .expect("transaction directory has parent"),
            )?;
        }
        Ok(())
    }
}

fn recover_locked(root: &Path) -> Result<()> {
    let directory = root.join(TRANSACTION_RELATIVE);
    if !directory.exists() {
        return Ok(());
    }
    if !directory.join("journal.toml").exists() {
        fs::remove_dir_all(&directory)?;
        sync_directory(
            directory
                .parent()
                .expect("transaction directory has parent"),
        )?;
        return Ok(());
    }
    JournalStore::load(root)?.rollback()
}

#[derive(Debug)]
struct StagedPackage {
    root: PathBuf,
    inspection: Inspection,
    record: InstalledPackage,
    old: Option<InstalledPackage>,
    replaced: Vec<InstalledPackage>,
    alternate: BTreeMap<String, String>,
    replace_paths: BTreeSet<String>,
}

fn stage_archives(root: &Path, archives: &[InstallArchive]) -> Result<Vec<StagedPackage>> {
    let transaction = root.join(TRANSACTION_RELATIVE);
    let stage_root = transaction.join("stage");
    fs::create_dir(&stage_root)?;
    let mut names = BTreeSet::new();
    let mut staged = Vec::with_capacity(archives.len());

    for (position, archive) in archives.iter().enumerate() {
        let directory = stage_root.join(position.to_string());
        let inspection = package::extract(&archive.path, &directory)?;
        if !names.insert(inspection.metadata.name.clone()) {
            return Err(ArcError::Transaction(format!(
                "package {} was supplied more than once",
                inspection.metadata.name
            )));
        }
        let record = installed_record(&inspection, &directory, archive.explicit)?;
        staged.push(StagedPackage {
            root: directory,
            inspection,
            record,
            old: None,
            replaced: Vec::new(),
            alternate: BTreeMap::new(),
            replace_paths: BTreeSet::new(),
        });
    }
    Ok(staged)
}

fn installed_record(
    inspection: &Inspection,
    root: &Path,
    explicit: bool,
) -> Result<InstalledPackage> {
    let mut files = inspection
        .members
        .iter()
        .filter(|member| member.kind != MemberKind::Internal)
        .map(|member| {
            let (kind, sha256) = match member.kind {
                MemberKind::File => (
                    FileKind::Regular,
                    package::sha256(&root.join(&member.path))?,
                ),
                MemberKind::Directory => (FileKind::Directory, String::new()),
                MemberKind::Symlink => (FileKind::Symlink, String::new()),
                MemberKind::Hardlink => (FileKind::Hardlink, String::new()),
                MemberKind::Internal => unreachable!(),
            };
            Ok(FileRecord {
                path: member.path.clone(),
                kind,
                mode: member.mode,
                uid: member.uid,
                gid: member.gid,
                sha256,
                target: member.target.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    files.sort_by(|first, second| first.path.cmp(&second.path));

    let record = InstalledPackage {
        format: 1,
        explicit,
        package: inspection.metadata.clone(),
        files,
        hooks: inspection
            .members
            .iter()
            .filter_map(|member| {
                member
                    .path
                    .strip_prefix(".arc/hooks/")
                    .map(|name| (name.to_owned(), root.join(&member.path)))
            })
            .map(|(name, path)| Ok((name, fs::read_to_string(path)?)))
            .collect::<Result<BTreeMap<_, _>>>()?,
    };
    record.validate()?;
    for backup in &record.package.backup {
        if !record
            .files
            .iter()
            .any(|file| file.path == *backup && file.kind == FileKind::Regular)
        {
            return Err(ArcError::Transaction(format!(
                "backup path {backup:?} is not a regular payload file"
            )));
        }
    }
    Ok(record)
}

fn preflight(root: &Path, staged: &mut [StagedPackage]) -> Result<()> {
    let database = Database::new(root)?;
    let installed = database.load_all()?;
    let installed = installed
        .into_iter()
        .map(|package| (package.package.name.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let ownership = database.ownership()?;
    let mut planned: BTreeMap<String, (String, FileKind)> = BTreeMap::new();
    let staged_names = staged
        .iter()
        .map(|package| package.record.package.name.clone())
        .collect::<BTreeSet<_>>();
    let mut claimed_replacements = BTreeMap::new();

    for package in staged.iter_mut() {
        for replacement in &package.record.package.replaces {
            let requirement = Requirement::parse(replacement)?;
            for candidate in installed.values().filter(|candidate| {
                !staged_names.contains(&candidate.package.name)
                    && package_satisfies(&candidate.package, &requirement)
            }) {
                if package
                    .replaced
                    .iter()
                    .any(|replaced| replaced.package.name == candidate.package.name)
                {
                    continue;
                }
                if let Some(first) = claimed_replacements.insert(
                    candidate.package.name.clone(),
                    package.record.package.name.clone(),
                ) {
                    return Err(ArcError::Transaction(format!(
                        "packages {first} and {} both replace {}",
                        package.record.package.name, candidate.package.name
                    )));
                }
                package.replaced.push(candidate.clone());
            }
        }
    }

    for package in staged.iter_mut() {
        let name = package.record.package.name.clone();
        let old = installed.get(&name).cloned();
        if let Some(old) = &old {
            package.record.explicit |= old.explicit;
        }
        let mut alternate = BTreeMap::new();
        let mut replace_paths = BTreeSet::new();
        for file in &package.record.files {
            if file.path == STATE_RELATIVE || file.path.starts_with(&format!("{STATE_RELATIVE}/")) {
                return Err(ArcError::Transaction(format!(
                    "package {} attempts to install Arc state path {:?}",
                    package.record.package.name, file.path
                )));
            }
            if file
                .path
                .split('/')
                .any(|component| component.starts_with(".arc-txn-"))
            {
                return Err(ArcError::Transaction(format!(
                    "payload path {:?} uses Arc's temporary-file prefix",
                    file.path
                )));
            }
            let previous = old
                .as_ref()
                .into_iter()
                .chain(package.replaced.iter())
                .find_map(|previous| {
                    previous
                        .files
                        .iter()
                        .find(|old| old.path == file.path)
                        .map(|file| (previous, file))
                });
            if previous.is_some() {
                replace_paths.insert(file.path.clone());
            }
            if let Some(owner) = ownership.get(&file.path) {
                if owner != &name
                    && !package
                        .replaced
                        .iter()
                        .any(|replaced| replaced.package.name == *owner)
                {
                    return Err(ArcError::Transaction(format!(
                        "file {:?} is already owned by {owner}",
                        file.path
                    )));
                }
            }
            if ownership.get(&file.path) == Some(&name) && previous.is_none() {
                return Err(ArcError::InvalidState(format!(
                    "ownership database for {name} disagrees about {:?}",
                    file.path
                )));
            }
            if previous.is_some_and(|(_, old)| {
                (old.kind == FileKind::Directory) != (file.kind == FileKind::Directory)
            }) {
                return Err(ArcError::Transaction(format!(
                    "upgrade of {name} changes {:?} between directory and non-directory",
                    file.path
                )));
            }

            let mut destination = file.path.clone();
            if file.kind == FileKind::Regular
                && previous.is_some_and(|(package, old)| {
                    package.package.backup.contains(&file.path) && old.kind == FileKind::Regular
                })
            {
                let target = root.join(&file.path);
                let modified = match fs::symlink_metadata(&target) {
                    Ok(metadata) if metadata.is_file() => {
                        package::sha256(&target)? != previous.expect("checked above").1.sha256
                    }
                    Ok(_) => true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                    Err(error) => return Err(error.into()),
                };
                if modified {
                    destination = format!("{}.arc-new", file.path);
                    if fs::symlink_metadata(root.join(&destination)).is_ok() {
                        return Err(ArcError::Transaction(format!(
                            "cannot preserve modified {:?}: {:?} already exists",
                            file.path, destination
                        )));
                    }
                    alternate.insert(file.path.clone(), destination.clone());
                }
            }

            if let Some((owner, kind)) =
                planned.insert(destination.clone(), (name.clone(), file.kind))
            {
                if kind != FileKind::Directory || file.kind != FileKind::Directory {
                    return Err(ArcError::Transaction(format!(
                        "packages {owner} and {} both contain {:?}",
                        package.record.package.name, destination
                    )));
                }
            }

            let target = root.join(&destination);
            match fs::symlink_metadata(&target) {
                Ok(metadata) if file.kind == FileKind::Directory && metadata.is_dir() => {}
                Ok(_) if destination == file.path && previous.is_some() => {}
                Ok(_) => {
                    return Err(ArcError::Transaction(format!(
                        "target path {:?} already exists",
                        destination
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        package.old = old;
        package.alternate = alternate;
        package.replace_paths = replace_paths;
    }

    for path in planned.keys() {
        let mut parent = Path::new(path).parent();
        while let Some(ancestor) = parent.filter(|value| !value.as_os_str().is_empty()) {
            let ancestor = ancestor.to_str().expect("validated payload path");
            if planned
                .get(ancestor)
                .is_some_and(|(_, kind)| *kind != FileKind::Directory)
            {
                return Err(ArcError::Transaction(format!(
                    "payload path {path:?} is below non-directory {ancestor:?}"
                )));
            }
            parent = Path::new(ancestor).parent();
        }
    }
    let replaced_names = staged
        .iter()
        .flat_map(|package| package.replaced.iter())
        .map(|package| package.package.name.as_str())
        .collect::<BTreeSet<_>>();
    let final_packages = installed
        .values()
        .filter(|package| {
            !staged_names.contains(&package.package.name)
                && !replaced_names.contains(package.package.name.as_str())
        })
        .map(|package| &package.package)
        .chain(staged.iter().map(|package| &package.record.package))
        .collect::<Vec<_>>();
    validate_package_set(&final_packages)?;
    Ok(())
}

fn validate_package_set(packages: &[&crate::metadata::Metadata]) -> Result<()> {
    for package in packages {
        for dependency in &package.depends {
            let requirement = Requirement::parse(dependency)?;
            if !packages
                .iter()
                .any(|candidate| package_satisfies(candidate, &requirement))
            {
                return Err(ArcError::Transaction(format!(
                    "{} requires unavailable dependency {dependency}",
                    package.name
                )));
            }
        }
        for conflict in &package.conflicts {
            let requirement = Requirement::parse(conflict)?;
            if packages.iter().any(|candidate| {
                candidate.name != package.name && package_satisfies(candidate, &requirement)
            }) {
                return Err(ArcError::Transaction(format!(
                    "{} conflicts with installed requirement {conflict}",
                    package.name
                )));
            }
        }
    }
    Ok(())
}

fn apply_staged(
    root: &Path,
    staged: &[StagedPackage],
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<()> {
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut hardlinks = Vec::new();
    for package in staged {
        for member in package
            .inspection
            .members
            .iter()
            .filter(|member| member.kind != MemberKind::Internal)
        {
            let entry = (package, member);
            match member.kind {
                MemberKind::Directory => directories.push(entry),
                MemberKind::Hardlink => hardlinks.push(entry),
                MemberKind::File | MemberKind::Symlink => files.push(entry),
                MemberKind::Internal => unreachable!(),
            }
        }
    }
    directories.sort_by(|(_, first), (_, second)| {
        first
            .path
            .split('/')
            .count()
            .cmp(&second.path.split('/').count())
            .then_with(|| first.path.cmp(&second.path))
    });
    files.sort_by(|(_, first), (_, second)| first.path.cmp(&second.path));
    hardlinks.sort_by(|(_, first), (_, second)| first.path.cmp(&second.path));

    for (package, member) in directories {
        apply_directory(
            root,
            Path::new(&member.path),
            &package.root.join(&member.path),
            member.mode,
            member.uid,
            member.gid,
            journal,
            apply,
        )?;
    }
    for (package, member) in files.into_iter().chain(hardlinks) {
        let target = package
            .alternate
            .get(&member.path)
            .map_or(member.path.as_str(), String::as_str);
        let may_replace = !package.alternate.contains_key(&member.path)
            && package.replace_paths.contains(&member.path);
        apply_member(
            root,
            &package.root,
            member,
            Path::new(target),
            may_replace,
            journal,
            apply,
        )?;
    }
    Ok(())
}

fn remove_obsolete(
    root: &Path,
    staged: &[StagedPackage],
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<()> {
    let mut directories = BTreeSet::new();
    for package in staged {
        let current = package
            .record
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<BTreeSet<_>>();
        for (old, file) in package
            .old
            .as_ref()
            .into_iter()
            .chain(package.replaced.iter())
            .flat_map(|old| old.files.iter().map(move |file| (old, file)))
            .filter(|(_, file)| !current.contains(file.path.as_str()))
        {
            if file.kind == FileKind::Directory {
                directories.insert(file.path.clone());
                continue;
            }
            let relative = Path::new(&file.path);
            let target = root.join(relative);
            let metadata = match fs::symlink_metadata(&target) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let preserve = file.kind == FileKind::Regular
                && old.package.backup.contains(&file.path)
                && (!metadata.is_file() || package::sha256(&target)? != file.sha256);
            if preserve {
                continue;
            }
            journal.record_replaced(relative)?;
            remove_node(&target)?;
            sync_directory(target.parent().expect("payload file has parent"))?;
            apply.changed()?;
        }
    }

    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by(|first, second| {
        second
            .split('/')
            .count()
            .cmp(&first.split('/').count())
            .then_with(|| second.cmp(first))
    });
    for directory in directories {
        let relative = Path::new(&directory);
        let target = root.join(relative);
        let empty = match fs::read_dir(&target) {
            Ok(mut entries) => entries.next().is_none(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => false,
            Err(error) => return Err(error.into()),
        };
        if empty {
            journal.record_replaced(relative)?;
            fs::remove_dir(&target)?;
            sync_directory(target.parent().expect("payload directory has parent"))?;
            apply.changed()?;
        }
    }
    Ok(())
}

fn remove_replaced_records(
    root: &Path,
    staged: &[StagedPackage],
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<()> {
    for replaced in staged.iter().flat_map(|package| package.replaced.iter()) {
        let relative = PathBuf::from(format!(
            "{STATE_RELATIVE}/installed/{}.toml",
            replaced.package.name
        ));
        journal.record_replaced(&relative)?;
        fs::remove_file(root.join(&relative))?;
        sync_directory(
            root.join(&relative)
                .parent()
                .expect("database record has parent"),
        )?;
        apply.changed()?;
    }
    Ok(())
}

#[derive(Debug, Default)]
struct ApplyState {
    mutations: u64,
    temporary: u64,
    fail_after: Option<u64>,
}

impl ApplyState {
    fn changed(&mut self) -> Result<()> {
        self.mutations += 1;
        if self.fail_after == Some(self.mutations) {
            return Err(ArcError::Transaction(format!(
                "injected failure after mutation {}",
                self.mutations
            )));
        }
        Ok(())
    }

    fn temporary_path(&mut self, parent: &Path) -> PathBuf {
        self.temporary += 1;
        parent.join(format!(
            ".arc-txn-{}-{}",
            std::process::id(),
            self.temporary
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_directory(
    root: &Path,
    relative: &Path,
    source: &Path,
    mode: u32,
    uid: u64,
    gid: u64,
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<()> {
    ensure_parents(root, relative, journal, apply)?;
    let target = root.join(relative);
    match fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(ArcError::Transaction(format!(
                "cannot create directory {} over another file",
                target.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    journal.record_created(relative)?;
    fs::create_dir(&target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
    set_owner(&target, uid, gid, false)?;
    copy_xattrs(source, &target)?;
    sync_directory(target.parent().expect("created directory has parent"))?;
    apply.changed()
}

fn apply_member(
    root: &Path,
    stage: &Path,
    member: &Member,
    target: &Path,
    may_replace: bool,
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<()> {
    let relative = Path::new(&member.path);
    match member.kind {
        MemberKind::File => apply_regular(
            root,
            target,
            &stage.join(relative),
            member.mode,
            member.uid,
            member.gid,
            may_replace,
            journal,
            apply,
        ),
        MemberKind::Symlink => apply_link(
            root,
            target,
            &member.target,
            false,
            member.uid,
            member.gid,
            may_replace,
            journal,
            apply,
        ),
        MemberKind::Hardlink => apply_link(
            root,
            target,
            &member.target,
            true,
            member.uid,
            member.gid,
            may_replace,
            journal,
            apply,
        ),
        MemberKind::Directory | MemberKind::Internal => unreachable!(),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_regular(
    root: &Path,
    relative: &Path,
    source: &Path,
    mode: u32,
    uid: u64,
    gid: u64,
    may_replace: bool,
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<()> {
    ensure_parents(root, relative, journal, apply)?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let temporary = apply.temporary_path(parent);
    journal.record_created(&temporary)?;
    let temporary_target = root.join(&temporary);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut output = options.open(&temporary_target)?;
    let mut input = File::open(source)?;
    std::io::copy(&mut input, &mut output)?;
    output.set_permissions(fs::Permissions::from_mode(mode))?;
    if uid != u64::MAX {
        set_owner(&temporary_target, uid, gid, false)?;
    }
    copy_xattrs(source, &temporary_target)?;
    output.sync_all()?;
    apply.changed()?;
    finish_temporary(root, relative, &temporary, may_replace, journal, apply)
}

#[allow(clippy::too_many_arguments)]
fn apply_link(
    root: &Path,
    relative: &Path,
    link_target: &str,
    hard: bool,
    uid: u64,
    gid: u64,
    may_replace: bool,
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<()> {
    ensure_parents(root, relative, journal, apply)?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let temporary = apply.temporary_path(parent);
    journal.record_created(&temporary)?;
    let temporary_target = root.join(&temporary);
    if hard {
        fs::hard_link(root.join(link_target), &temporary_target)?;
    } else {
        symlink(link_target, &temporary_target)?;
    }
    set_owner(&temporary_target, uid, gid, !hard)?;
    apply.changed()?;
    finish_temporary(root, relative, &temporary, may_replace, journal, apply)
}

fn set_owner(path: &Path, uid: u64, gid: u64, symlink: bool) -> Result<()> {
    let uid = u32::try_from(uid).map_err(|_| {
        ArcError::Transaction(format!(
            "UID {uid} for {} exceeds the platform limit",
            path.display()
        ))
    })?;
    let gid = u32::try_from(gid).map_err(|_| {
        ArcError::Transaction(format!(
            "GID {gid} for {} exceeds the platform limit",
            path.display()
        ))
    })?;
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| ArcError::Transaction("path contains a NUL byte".into()))?;
    let result = unsafe {
        if symlink {
            libc::lchown(path.as_ptr(), uid as libc::uid_t, gid as libc::gid_t)
        } else {
            libc::chown(path.as_ptr(), uid as libc::uid_t, gid as libc::gid_t)
        }
    };
    if result == 0 {
        Ok(())
    } else {
        Err(ArcError::Transaction(format!(
            "cannot set ownership on {} to {uid}:{gid}: {}",
            path.to_string_lossy(),
            std::io::Error::last_os_error()
        )))
    }
}

fn finish_temporary(
    root: &Path,
    relative: &Path,
    temporary: &Path,
    may_replace: bool,
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<()> {
    let target = root.join(relative);
    match fs::symlink_metadata(&target) {
        Ok(_) if may_replace => journal.record_replaced(relative)?,
        Ok(_) => {
            return Err(ArcError::Transaction(format!(
                "target {} appeared during transaction",
                target.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            journal.record_created(relative)?;
        }
        Err(error) => return Err(error.into()),
    }
    fs::rename(root.join(temporary), &target)?;
    sync_directory(target.parent().expect("payload path has parent"))?;
    apply.changed()
}

fn ensure_parents(
    root: &Path,
    relative: &Path,
    journal: &mut JournalStore,
    apply: &mut ApplyState,
) -> Result<()> {
    let Some(parent) = relative.parent() else {
        return Ok(());
    };
    let mut current = PathBuf::new();
    for component in parent.components() {
        let Component::Normal(component) = component else {
            return Err(ArcError::Transaction(format!(
                "invalid target path {}",
                relative.display()
            )));
        };
        current.push(component);
        let target = root.join(&current);
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(ArcError::Transaction(format!(
                    "target ancestor {} is not a directory",
                    target.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                journal.record_created(&current)?;
                fs::create_dir(&target)?;
                fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
                sync_directory(target.parent().expect("created directory has parent"))?;
                apply.changed()?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn copy_xattrs(source: &Path, target: &Path) -> Result<()> {
    for name in xattr::list(source)? {
        if let Some(value) = xattr::get(source, &name)? {
            xattr::set(target, &name, &value)?;
        }
    }
    Ok(())
}

fn remove_node(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn restore_node(source: &Path, target: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_file() {
        fs::copy(source, target)?;
        fs::set_permissions(target, metadata.permissions())?;
        copy_xattrs(source, target)?;
    } else if metadata.file_type().is_symlink() {
        symlink(fs::read_link(source)?, target)?;
        copy_xattrs(source, target)?;
    } else if metadata.is_dir() {
        fs::create_dir(target)?;
        fs::set_permissions(target, metadata.permissions())?;
        copy_xattrs(source, target)?;
    } else {
        return Err(ArcError::Transaction(format!(
            "cannot restore special backup {}",
            source.display()
        )));
    }
    Ok(())
}

fn backup_node(source: &Path, target: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_file() {
        fs::copy(source, target)?;
        fs::set_permissions(target, metadata.permissions())?;
        copy_xattrs(source, target)?;
        File::open(target)?.sync_all()?;
    } else if metadata.file_type().is_symlink() {
        symlink(fs::read_link(source)?, target)?;
        copy_xattrs(source, target)?;
    } else if metadata.is_dir() {
        fs::create_dir(target)?;
        fs::set_permissions(target, metadata.permissions())?;
        copy_xattrs(source, target)?;
        sync_directory(target)?;
    } else {
        return Err(ArcError::Transaction(format!(
            "cannot back up special file {}",
            source.display()
        )));
    }
    Ok(())
}

fn validate_relative(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        Err(ArcError::Transaction(format!(
            "invalid relative transaction path {value:?}"
        )))
    } else {
        Ok(())
    }
}

fn relative_string(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| ArcError::Transaction("transaction path is not UTF-8".into()))?;
    validate_relative(value)?;
    Ok(value.to_owned())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook_package(hook: &str, script: &str) -> InstalledPackage {
        InstalledPackage {
            format: 1,
            explicit: true,
            package: crate::metadata::Metadata {
                format: 1,
                name: "hook-test".into(),
                version: "2".into(),
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
            files: vec![],
            hooks: BTreeMap::from([(hook.into(), script.into())]),
        }
    }

    fn make_package(workspace: &Path, name: &str, files: &[(&str, &str)]) -> PathBuf {
        make_package_version(workspace, name, "1", &[], files)
    }

    #[test]
    fn account_file_changes_roll_back_and_reject_id_collisions() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path();
        fs::create_dir(root.join("etc")).unwrap();
        fs::create_dir_all(root.join(STATE_RELATIVE)).unwrap();
        fs::write(root.join("etc/group"), "existing:x:100:\n").unwrap();
        let mut journal = JournalStore::create(root).unwrap();
        let mut apply = ApplyState::default();
        apply_account_file(
            root,
            "etc/group",
            &[("arc".into(), 971, "arc:x:971:".into())],
            &mut journal,
            &mut apply,
        )
        .unwrap();
        assert!(
            fs::read_to_string(root.join("etc/group"))
                .unwrap()
                .contains("arc:x:971:")
        );
        journal.rollback().unwrap();
        assert_eq!(
            fs::read_to_string(root.join("etc/group")).unwrap(),
            "existing:x:100:\n"
        );

        let mut journal = JournalStore::create(root).unwrap();
        let error = apply_account_file(
            root,
            "etc/group",
            &[("other".into(), 100, "other:x:100:".into())],
            &mut journal,
            &mut ApplyState::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("already assigned"));
        journal.cleanup().unwrap();
    }

    #[test]
    fn abandoned_account_change_is_recovered() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path();
        fs::create_dir(root.join("etc")).unwrap();
        fs::create_dir_all(root.join(STATE_RELATIVE)).unwrap();
        fs::write(root.join("etc/group"), "existing:x:100:\n").unwrap();
        let mut journal = JournalStore::create(root).unwrap();
        apply_account_file(
            root,
            "etc/group",
            &[("arc".into(), 971, "arc:x:971:".into())],
            &mut journal,
            &mut ApplyState::default(),
        )
        .unwrap();
        drop(journal);

        recover_locked(root).unwrap();
        assert_eq!(
            fs::read_to_string(root.join("etc/group")).unwrap(),
            "existing:x:100:\n"
        );
    }

    fn make_package_version(
        workspace: &Path,
        name: &str,
        version: &str,
        backup: &[&str],
        files: &[(&str, &str)],
    ) -> PathBuf {
        make_package_spec(workspace, name, version, &[], backup, files)
    }

    fn make_package_spec(
        workspace: &Path,
        name: &str,
        version: &str,
        depends: &[&str],
        backup: &[&str],
        files: &[(&str, &str)],
    ) -> PathBuf {
        make_package_relations(workspace, name, version, depends, &[], backup, files)
    }

    fn make_package_relations(
        workspace: &Path,
        name: &str,
        version: &str,
        depends: &[&str],
        replaces: &[&str],
        backup: &[&str],
        files: &[(&str, &str)],
    ) -> PathBuf {
        let root = workspace.join(format!("{name}-{version}-root"));
        fs::create_dir_all(root.join(".arc")).unwrap();
        let depends = depends
            .iter()
            .map(|dependency| format!("{dependency:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        let backup = backup
            .iter()
            .map(|path| format!("{path:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        let replaces = replaces
            .iter()
            .map(|replacement| format!("{replacement:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        fs::write(
            root.join(".arc/meta.toml"),
            format!(
                "format = 1\nname = {name:?}\nversion = {version:?}\narch = \"x86_64\"\ndepends = [{depends}]\nreplaces = [{replaces}]\nbackup = [{backup}]\n"
            ),
        )
        .unwrap();
        for (path, contents) in files {
            let target = root.join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, contents).unwrap();
        }
        let output = workspace.join(format!("{name}-{version}.arc"));
        package::pack(&root, Some(&output)).unwrap();
        output
    }

    #[test]
    fn local_package_installs_with_a_plain_database_record() {
        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        fs::create_dir(&target).unwrap();
        let archive = make_package(workspace.path(), "hello", &[("usr/bin/hello", "hello\n")]);
        let summary = install(
            &target,
            &[InstallArchive {
                path: archive,
                explicit: true,
            }],
        )
        .unwrap();

        assert_eq!(summary.packages, ["hello"]);
        assert_eq!(
            fs::read_to_string(target.join("usr/bin/hello")).unwrap(),
            "hello\n"
        );
        let database = Database::new(target.canonicalize().unwrap()).unwrap();
        assert_eq!(database.load_all().unwrap()[0].package.name, "hello");
    }

    #[test]
    fn hooks_receive_a_small_stable_environment() {
        let package = hook_package(
            "post-upgrade",
            r#"test "$ARC_HOOK" = post-upgrade
test "$ARC_PACKAGE" = hook-test
test "$ARC_VERSION" = 2
test "$ARC_OLD_VERSION" = 1
test "$PATH" = /usr/bin:/bin:/usr/sbin:/sbin
"#,
        );
        run_hook(Path::new("/"), &package, "post-upgrade", Some("1")).unwrap();
    }

    #[test]
    fn a_failed_hook_fails_the_transaction_step() {
        let package = hook_package("pre-install", "exit 7\n");
        let error = run_hook(Path::new("/"), &package, "pre-install", None).unwrap_err();
        assert!(error.to_string().contains("exited with exit status: 7"));
    }

    #[test]
    fn injected_failure_rolls_back_every_payload_path() {
        let workspace = tempfile::tempdir().unwrap();
        let archive = make_package(
            workspace.path(),
            "broken",
            &[("usr/bin/first", "one"), ("usr/bin/second", "two")],
        );
        let mut failures = 0;
        for mutation in 1..=32 {
            let target = workspace.path().join(format!("target-{mutation}"));
            fs::create_dir(&target).unwrap();
            let result = install_inner(
                &target,
                &[InstallArchive {
                    path: archive.clone(),
                    explicit: true,
                }],
                Some(mutation),
            );
            if result.is_ok() {
                break;
            }
            failures += 1;
            assert!(!target.join("usr/bin/first").exists());
            assert!(!target.join("usr/bin/second").exists());
            let database = Database::new(target.canonicalize().unwrap()).unwrap();
            assert!(database.load_all().unwrap().is_empty());
            assert!(!target.join(TRANSACTION_RELATIVE).exists());
        }
        assert!(failures >= 6, "test must cover several mutation stages");
    }

    #[test]
    fn undefined_trigger_rolls_back_payload_and_database() {
        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        let root = workspace.path().join("trigger-root");
        fs::create_dir(&target).unwrap();
        fs::create_dir_all(root.join(".arc")).unwrap();
        fs::create_dir_all(root.join("usr/share")).unwrap();
        fs::write(
            root.join(".arc/meta.toml"),
            "format = 1\nname = \"triggered\"\nversion = \"1\"\narch = \"x86_64\"\ntriggers = [\"missing-cache\"]\n",
        )
        .unwrap();
        fs::write(root.join("usr/share/triggered"), "payload").unwrap();
        let archive = workspace.path().join("triggered.arc");
        package::pack(&root, Some(&archive)).unwrap();

        let error = install(
            &target,
            &[InstallArchive {
                path: archive,
                explicit: true,
            }],
        )
        .unwrap_err();
        assert!(error.to_string().contains("undefined system trigger"));
        assert!(!target.join("usr/share/triggered").exists());
        assert!(
            Database::new(target.canonicalize().unwrap())
                .unwrap()
                .load_all()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn upgrades_replace_files_and_remove_obsolete_ones() {
        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        fs::create_dir(&target).unwrap();
        let first = make_package_version(
            workspace.path(),
            "hello",
            "1",
            &[],
            &[("usr/bin/hello", "old"), ("usr/bin/obsolete", "gone")],
        );
        let second = make_package_version(
            workspace.path(),
            "hello",
            "2",
            &[],
            &[("usr/bin/hello", "new")],
        );
        install(
            &target,
            &[InstallArchive {
                path: first,
                explicit: true,
            }],
        )
        .unwrap();
        install(
            &target,
            &[InstallArchive {
                path: second,
                explicit: true,
            }],
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(target.join("usr/bin/hello")).unwrap(),
            "new"
        );
        assert!(!target.join("usr/bin/obsolete").exists());
        let database = Database::new(target.canonicalize().unwrap()).unwrap();
        assert_eq!(
            database.load("hello").unwrap().unwrap().package.version,
            "2"
        );
    }

    #[test]
    fn replacement_removes_the_old_package_in_the_same_transaction() {
        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        fs::create_dir(&target).unwrap();
        let old = make_package_version(
            workspace.path(),
            "legacy",
            "1",
            &[],
            &[("usr/bin/tool", "old"), ("usr/bin/obsolete", "old")],
        );
        install(
            &target,
            &[InstallArchive {
                path: old,
                explicit: true,
            }],
        )
        .unwrap();
        let new = make_package_relations(
            workspace.path(),
            "modern",
            "1",
            &[],
            &["legacy"],
            &[],
            &[("usr/bin/tool", "new")],
        );
        install(
            &target,
            &[InstallArchive {
                path: new,
                explicit: true,
            }],
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(target.join("usr/bin/tool")).unwrap(),
            "new"
        );
        assert!(!target.join("usr/bin/obsolete").exists());
        let database = Database::new(target.canonicalize().unwrap()).unwrap();
        assert!(database.load("legacy").unwrap().is_none());
        assert!(database.load("modern").unwrap().is_some());
    }

    #[test]
    fn failed_replacement_restores_the_old_package() {
        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        fs::create_dir(&target).unwrap();
        let old = make_package(workspace.path(), "legacy", &[("usr/bin/tool", "old")]);
        install(
            &target,
            &[InstallArchive {
                path: old,
                explicit: true,
            }],
        )
        .unwrap();
        let new = make_package_relations(
            workspace.path(),
            "modern",
            "1",
            &[],
            &["legacy"],
            &[],
            &[("usr/bin/tool", "new"), ("usr/bin/second", "new")],
        );
        assert!(
            install_inner(
                &target,
                &[InstallArchive {
                    path: new,
                    explicit: true,
                }],
                Some(4),
            )
            .is_err()
        );

        assert_eq!(
            fs::read_to_string(target.join("usr/bin/tool")).unwrap(),
            "old"
        );
        let database = Database::new(target.canonicalize().unwrap()).unwrap();
        assert!(database.load("legacy").unwrap().is_some());
        assert!(database.load("modern").unwrap().is_none());
    }

    #[test]
    fn failed_upgrade_restores_the_previous_file_and_record() {
        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        fs::create_dir(&target).unwrap();
        let first = make_package_version(
            workspace.path(),
            "hello",
            "1",
            &[],
            &[("usr/bin/hello", "old")],
        );
        let second = make_package_version(
            workspace.path(),
            "hello",
            "2",
            &[],
            &[("usr/bin/hello", "new")],
        );
        install(
            &target,
            &[InstallArchive {
                path: first,
                explicit: true,
            }],
        )
        .unwrap();
        let result = install_inner(
            &target,
            &[InstallArchive {
                path: second,
                explicit: true,
            }],
            Some(2),
        );

        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(target.join("usr/bin/hello")).unwrap(),
            "old"
        );
        let database = Database::new(target.canonicalize().unwrap()).unwrap();
        assert_eq!(
            database.load("hello").unwrap().unwrap().package.version,
            "1"
        );
    }

    #[test]
    fn modified_configuration_gets_an_arc_new_file() {
        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        fs::create_dir(&target).unwrap();
        let first = make_package_version(
            workspace.path(),
            "service",
            "1",
            &["etc/service.conf"],
            &[("etc/service.conf", "default=1\n")],
        );
        let second = make_package_version(
            workspace.path(),
            "service",
            "2",
            &["etc/service.conf"],
            &[("etc/service.conf", "default=2\n")],
        );
        install(
            &target,
            &[InstallArchive {
                path: first,
                explicit: true,
            }],
        )
        .unwrap();
        fs::write(target.join("etc/service.conf"), "custom=true\n").unwrap();
        install(
            &target,
            &[InstallArchive {
                path: second,
                explicit: true,
            }],
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(target.join("etc/service.conf")).unwrap(),
            "custom=true\n"
        );
        assert_eq!(
            fs::read_to_string(target.join("etc/service.conf.arc-new")).unwrap(),
            "default=2\n"
        );
    }

    #[test]
    fn removal_deletes_payload_and_database_record() {
        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        fs::create_dir(&target).unwrap();
        let archive = make_package(workspace.path(), "hello", &[("usr/bin/hello", "hello")]);
        install(
            &target,
            &[InstallArchive {
                path: archive,
                explicit: true,
            }],
        )
        .unwrap();

        let summary = remove(&target, &["hello".into()]).unwrap();
        assert_eq!(summary.packages, ["hello"]);
        assert!(!target.join("usr/bin/hello").exists());
        let database = Database::new(target.canonicalize().unwrap()).unwrap();
        assert!(database.load_all().unwrap().is_empty());
    }

    #[test]
    fn removal_protects_reverse_dependencies() {
        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        fs::create_dir(&target).unwrap();
        let library = make_package(workspace.path(), "library", &[("usr/lib/library", "lib")]);
        let application = make_package_spec(
            workspace.path(),
            "application",
            "1",
            &["library"],
            &[],
            &[("usr/bin/application", "app")],
        );
        install(
            &target,
            &[
                InstallArchive {
                    path: library,
                    explicit: false,
                },
                InstallArchive {
                    path: application,
                    explicit: true,
                },
            ],
        )
        .unwrap();

        assert!(plan_removal(&target, &["library".into()]).is_err());
        assert!(remove(&target, &["library".into()]).is_err());
        remove(&target, &["application".into(), "library".into()]).unwrap();
        assert!(!target.join("usr/bin/application").exists());
        assert!(!target.join("usr/lib/library").exists());
    }

    #[test]
    fn installation_rejects_missing_dependencies() {
        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        fs::create_dir(&target).unwrap();
        let application = make_package_spec(
            workspace.path(),
            "application",
            "1",
            &["missing>=1"],
            &[],
            &[("usr/bin/application", "app")],
        );
        let result = install(
            &target,
            &[InstallArchive {
                path: application,
                explicit: true,
            }],
        );
        assert!(result.is_err());
        assert!(!target.join("usr/bin/application").exists());
    }

    #[test]
    fn transaction_rejects_conflicting_payload_ownership_before_mutation() {
        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        fs::create_dir(&target).unwrap();
        let first = make_package(workspace.path(), "first", &[("usr/bin/tool", "first")]);
        let second = make_package(workspace.path(), "second", &[("usr/bin/tool", "second")]);
        let error = install(
            &target,
            &[
                InstallArchive {
                    path: first,
                    explicit: true,
                },
                InstallArchive {
                    path: second,
                    explicit: true,
                },
            ],
        )
        .unwrap_err();
        assert!(error.to_string().contains("both contain"));
        assert!(!target.join("usr/bin/tool").exists());
        assert!(
            Database::new(target.canonicalize().unwrap())
                .unwrap()
                .load_all()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn removal_preserves_modified_configuration() {
        let workspace = tempfile::tempdir().unwrap();
        let target = workspace.path().join("target");
        fs::create_dir(&target).unwrap();
        let archive = make_package_version(
            workspace.path(),
            "service",
            "1",
            &["etc/service.conf"],
            &[("etc/service.conf", "default\n")],
        );
        install(
            &target,
            &[InstallArchive {
                path: archive,
                explicit: true,
            }],
        )
        .unwrap();
        fs::write(target.join("etc/service.conf"), "custom\n").unwrap();

        let summary = remove(&target, &["service".into()]).unwrap();
        assert_eq!(summary.preserved, ["etc/service.conf.arc-save"]);
        assert!(!target.join("etc/service.conf").exists());
        assert_eq!(
            fs::read_to_string(target.join("etc/service.conf.arc-save")).unwrap(),
            "custom\n"
        );
    }

    #[test]
    fn abandoned_journal_is_recovered() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join(STATE_RELATIVE)).unwrap();
        let mut journal = JournalStore::create(root.path()).unwrap();
        journal.record_created(Path::new("usr/bin/orphan")).unwrap();
        fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        fs::write(root.path().join("usr/bin/orphan"), "partial").unwrap();
        drop(journal);

        recover_locked(root.path()).unwrap();
        assert!(!root.path().join("usr/bin/orphan").exists());
        assert!(!root.path().join(TRANSACTION_RELATIVE).exists());
    }
}
