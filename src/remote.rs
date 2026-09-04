//! Repository configuration, synchronization, planning, and downloads.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::database::Database;
use crate::error::{ArcError, Result};
use crate::package;
use crate::repository::{RepositoryIndex, RepositoryPackage};
use crate::resolver;
use crate::transaction::InstallArchive;
use crate::version::{Requirement, Version, validate_name};

const MAX_CONFIG_SIZE: u64 = 1024 * 1024;
const MAX_INDEX_SIZE: u64 = 64 * 1024 * 1024;
const MAX_SIGNATURE_SIZE: u64 = 1024;
const MAX_PACKAGE_SIZE: u64 = 64 * 1024 * 1024 * 1024;
const INSTALLED_SOURCE: &str = "@installed";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositorySettings {
    #[serde(default = "host_architecture")]
    pub architecture: String,
    #[serde(default, rename = "repository")]
    pub repositories: Vec<ConfiguredRepository>,
    /// Packages excluded from unattended system upgrades. Explicit install,
    /// reinstall, and downgrade requests deliberately override this policy.
    #[serde(default)]
    pub hold: Vec<String>,
    /// Packages skipped by unattended upgrades, following pacman's IgnorePkg
    /// intent. Explicit requests still take precedence.
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Maximum number of package archives downloaded concurrently.
    #[serde(default = "default_download_parallelism")]
    pub download_parallelism: usize,
    /// Relative configuration snippets, resolved beneath `/etc/arc`.
    #[serde(default)]
    pub include: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredRepository {
    pub name: String,
    pub url: String,
    /// Current lowercase hexadecimal Ed25519 public key. Kept for backwards
    /// compatible configuration; `keys` contains additional trusted keys.
    #[serde(default)]
    pub key: String,
    /// Additional trusted public keys, for safe repository-key rotation.
    #[serde(default)]
    pub keys: Vec<String>,
    /// A non-root signing key authorized by a directly pinned repository key.
    #[serde(default)]
    pub delegated_keys: Vec<DelegatedKey>,
    /// Higher values win when otherwise equal candidates are available.
    #[serde(default)]
    pub priority: i32,
    /// Alternate base URLs used after a primary URL failure.
    #[serde(default)]
    pub mirrors: Vec<String>,
    /// Number of retries for each primary or mirror URL.
    #[serde(default = "default_retries")]
    pub retries: u8,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    /// Optional aggregate cap for a single archive transfer; zero is unlimited.
    #[serde(default)]
    pub bandwidth_limit: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedKey {
    /// Lowercase hexadecimal Ed25519 public key.
    pub key: String,
    /// Signature over the UTF-8 bytes `arc-delegate-v1:<key>`.
    pub signature: String,
}

fn default_download_parallelism() -> usize {
    4
}
fn default_retries() -> u8 {
    2
}
fn default_timeout_seconds() -> u64 {
    60
}

#[derive(Clone, Debug)]
pub struct PreparedInstall {
    pub archives: Vec<InstallArchive>,
    pub selected: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    Install,
    Upgrade { from: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedChange {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub repository: String,
    pub download_size: u64,
    pub cached: bool,
    pub explicit: bool,
    pub kind: ChangeKind,
    pub replaces: Vec<ReplacedPackage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacedPackage {
    pub name: String,
    pub version: String,
    pub architecture: String,
}

#[derive(Clone, Debug)]
pub struct InstallPlan {
    settings: RepositorySettings,
    packages: Vec<resolver::PlannedPackage>,
    explicit_override: Option<HashSet<String>>,
    pub changes: Vec<PlannedChange>,
    pub selected: Vec<String>,
}

impl InstallPlan {
    pub fn download_size(&self) -> u64 {
        self.changes
            .iter()
            .filter(|package| !package.cached)
            .map(|package| package.download_size)
            .fold(0_u64, u64::saturating_add)
    }
}

pub trait SyncObserver {
    fn started(&mut self, _repository: &str) {}
    fn finished(&mut self, _repository: &str, _packages: usize) {}
}

struct SilentSync;

impl SyncObserver for SilentSync {}

pub trait DownloadObserver {
    fn cached(&mut self, _package: &str, _size: u64) {}
    fn started(&mut self, _package: &str, _size: u64) {}
    fn advanced(&mut self, _package: &str, _received: u64, _size: u64) {}
    fn finished(&mut self, _package: &str, _size: u64) {}
    fn failed(&mut self, _package: &str) {}
}

struct SilentDownloads;

impl DownloadObserver for SilentDownloads {}

enum DownloadEvent {
    Cached(String, u64),
    Started(String, u64),
    Advanced(String, u64, u64),
    Finished(String, u64),
    Failed(String),
}

struct ChannelDownloads(mpsc::Sender<DownloadEvent>);

impl DownloadObserver for ChannelDownloads {
    fn cached(&mut self, package: &str, size: u64) {
        let _ = self.0.send(DownloadEvent::Cached(package.into(), size));
    }
    fn started(&mut self, package: &str, size: u64) {
        let _ = self.0.send(DownloadEvent::Started(package.into(), size));
    }
    fn advanced(&mut self, package: &str, received: u64, size: u64) {
        let _ = self
            .0
            .send(DownloadEvent::Advanced(package.into(), received, size));
    }
    fn finished(&mut self, package: &str, size: u64) {
        let _ = self.0.send(DownloadEvent::Finished(package.into(), size));
    }
    fn failed(&mut self, package: &str) {
        let _ = self.0.send(DownloadEvent::Failed(package.into()));
    }
}

/// Everything one download worker needs. Keeping these values together avoids
/// parallel vectors and makes the worker's inputs obvious.
struct DownloadJob {
    repository: ConfiguredRepository,
    package: RepositoryPackage,
    explicit: bool,
}

fn replay_download_events(
    observer: &mut dyn DownloadObserver,
    receiver: mpsc::Receiver<DownloadEvent>,
) {
    for event in receiver {
        match event {
            DownloadEvent::Cached(name, size) => observer.cached(&name, size),
            DownloadEvent::Started(name, size) => observer.started(&name, size),
            DownloadEvent::Advanced(name, received, size) => {
                observer.advanced(&name, received, size)
            }
            DownloadEvent::Finished(name, size) => observer.finished(&name, size),
            DownloadEvent::Failed(name) => observer.failed(&name),
        }
    }
}

pub fn load_settings(root: &Path) -> Result<RepositorySettings> {
    let path = root.join("etc/arc/repos.toml");
    let mut visited = HashSet::new();
    load_settings_file(&path, &mut visited)
}

fn load_settings_file(path: &Path, visited: &mut HashSet<PathBuf>) -> Result<RepositorySettings> {
    let canonical = path.canonicalize().map_err(|error| {
        ArcError::InvalidRepository(format!("cannot read {}: {error}", path.display()))
    })?;
    if !visited.insert(canonical.clone()) {
        return Err(ArcError::InvalidRepository(format!(
            "configuration include cycle at {}",
            canonical.display()
        )));
    }
    let metadata = fs::metadata(path).map_err(|error| {
        ArcError::InvalidRepository(format!("cannot read {}: {error}", path.display()))
    })?;
    if metadata.len() > MAX_CONFIG_SIZE {
        return Err(ArcError::InvalidRepository(format!(
            "{} exceeds 1 MiB",
            path.display()
        )));
    }
    let input = fs::read_to_string(path)?;
    let mut settings: RepositorySettings = toml::from_str(&input)?;
    let includes = std::mem::take(&mut settings.include);
    let parent = path.parent().ok_or_else(|| {
        ArcError::InvalidRepository("repository configuration has no parent directory".into())
    })?;
    for include in includes {
        let relative = include_path(&include)?;
        let extra = load_settings_file(&parent.join(relative), visited)?;
        if extra.architecture != settings.architecture {
            return Err(ArcError::InvalidRepository(format!(
                "included configuration {include:?} has a different architecture"
            )));
        }
        settings.repositories.extend(extra.repositories);
        settings.hold.extend(extra.hold);
        settings.ignore.extend(extra.ignore);
    }
    settings.validate()?;
    Ok(settings)
}

/// Includes stay below the configuration directory. This keeps one obvious
/// boundary for configuration files and prevents `..` traversal.
fn include_path(include: &str) -> Result<&Path> {
    let path = Path::new(include);
    let normalized = !path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)));
    if normalized {
        Ok(path)
    } else {
        Err(ArcError::InvalidRepository(format!(
            "include {include:?} must be a relative path without traversal"
        )))
    }
}

impl RepositorySettings {
    pub fn validate(&self) -> Result<()> {
        crate::metadata::validate_architecture(&self.architecture).map_err(|error| {
            ArcError::InvalidRepository(format!("invalid configured architecture: {error}"))
        })?;
        if self.repositories.is_empty() {
            return Err(ArcError::InvalidRepository(
                "repos.toml contains no repositories".into(),
            ));
        }
        let mut names = HashSet::new();
        for repository in &self.repositories {
            repository.validate()?;
            if !names.insert(&repository.name) {
                return Err(ArcError::InvalidRepository(format!(
                    "duplicate repository name {:?}",
                    repository.name
                )));
            }
        }
        let mut held = HashSet::new();
        for name in self.hold.iter().chain(&self.ignore) {
            validate_name(name)?;
            if !held.insert(name) {
                return Err(ArcError::InvalidRepository(format!(
                    "duplicate held package {name:?}"
                )));
            }
        }
        if !(1..=32).contains(&self.download_parallelism) {
            return Err(ArcError::InvalidRepository(
                "download_parallelism must be between 1 and 32".into(),
            ));
        }
        Ok(())
    }
}

impl ConfiguredRepository {
    fn pinned_keys(&self) -> Vec<&str> {
        std::iter::once(self.key.as_str())
            .filter(|key| !key.is_empty())
            .chain(
                self.keys
                    .iter()
                    .map(String::as_str)
                    .filter(|key| !key.is_empty()),
            )
            .collect()
    }

    fn trusted_keys(&self) -> Vec<&str> {
        self.pinned_keys()
            .into_iter()
            .chain(
                self.delegated_keys
                    .iter()
                    .map(|delegation| delegation.key.as_str()),
            )
            .collect()
    }

    fn validate(&self) -> Result<()> {
        validate_name(&self.name)?;
        validate_repository_url(&self.name, &self.url)?;
        let mut mirrors = HashSet::new();
        for mirror in &self.mirrors {
            validate_repository_url(&self.name, mirror)?;
            if !mirrors.insert(mirror) {
                return Err(ArcError::InvalidRepository(format!(
                    "repository {} repeats mirror {mirror:?}",
                    self.name
                )));
            }
        }
        if !(1..=3_600).contains(&self.timeout_seconds) {
            return Err(ArcError::InvalidRepository(format!(
                "repository {} timeout_seconds must be between 1 and 3600",
                self.name
            )));
        }
        self.validate_keys()?;
        self.validate_delegations()
    }

    fn object_urls(&self, path: &str) -> Vec<String> {
        std::iter::once(&self.url)
            .chain(self.mirrors.iter())
            .map(|url| format!("{}/{}", url.trim_end_matches('/'), path))
            .collect()
    }
}

fn validate_repository_url(name: &str, url: &str) -> Result<()> {
    let remainder = url.strip_prefix("https://");
    #[cfg(test)]
    let remainder = remainder.or_else(|| url.strip_prefix("http://127.0.0.1:"));
    let remainder = remainder.ok_or_else(|| {
        ArcError::InvalidRepository(format!("repository {name} URL must use HTTPS"))
    })?;
    if remainder.is_empty()
        || remainder.starts_with('/')
        || remainder.contains('@')
        || url.bytes().any(|byte| byte.is_ascii_whitespace())
        || url.contains(['?', '#'])
    {
        return Err(ArcError::InvalidRepository(format!(
            "invalid URL for repository {name}",
        )));
    }
    Ok(())
}

impl ConfiguredRepository {
    fn validate_keys(&self) -> Result<()> {
        let keys = self.pinned_keys();
        if keys.is_empty() {
            return Err(ArcError::InvalidRepository(format!(
                "repository {} has no trusted public key",
                self.name
            )));
        }
        let mut unique = HashSet::new();
        for key in keys {
            decode_array::<32>(key, "public key")?;
            if !unique.insert(key) {
                return Err(ArcError::InvalidRepository(format!(
                    "repository {} repeats a trusted public key",
                    self.name
                )));
            }
        }
        Ok(())
    }

    fn validate_delegations(&self) -> Result<()> {
        let pinned = self.pinned_keys();
        let mut all = pinned.iter().copied().collect::<HashSet<_>>();
        for delegation in &self.delegated_keys {
            decode_array::<32>(&delegation.key, "delegated public key")?;
            if !all.insert(&delegation.key) {
                return Err(ArcError::InvalidRepository(format!(
                    "repository {} repeats a delegated public key",
                    self.name
                )));
            }
            let message = format!("arc-delegate-v1:{}", delegation.key);
            verify_index_with_keys(message.as_bytes(), delegation.signature.as_bytes(), &pinned)
                .map_err(|_| {
                    ArcError::Authentication(format!(
                        "delegated key for repository {} is not authorized by a pinned key",
                        self.name
                    ))
                })?;
        }
        Ok(())
    }
}

pub fn sync(root: &Path) -> Result<usize> {
    sync_with_observer(root, &mut SilentSync)
}

pub fn sync_with_observer(root: &Path, observer: &mut dyn SyncObserver) -> Result<usize> {
    let _lock = crate::transaction::ArcLock::acquire(root)?;
    let settings = load_settings(root)?;
    let mut count = 0;
    for repository in &settings.repositories {
        observer.started(&repository.name);
        let index_bytes = get_repository_object(repository, "index.toml", MAX_INDEX_SIZE)?;
        let signature = get_repository_object(repository, "index.toml.sig", MAX_SIGNATURE_SIZE)?;
        verify_index_with_keys(&index_bytes, &signature, &repository.trusted_keys())?;
        let index_text = std::str::from_utf8(&index_bytes).map_err(|_| {
            ArcError::InvalidRepository(format!(
                "repository {} index is not UTF-8",
                repository.name
            ))
        })?;
        let index = RepositoryIndex::from_toml(index_text)?;

        let cache = repository_cache(root, &repository.name);
        reject_index_rollback(&cache, repository, &index)?;
        crate::atomic_file::write(&cache.join("index.toml.sig"), &signature, 0o644)?;
        crate::atomic_file::write(&cache.join("index.toml"), &index_bytes, 0o644)?;
        count += index.packages.len();
        observer.finished(&repository.name, index.packages.len());
    }
    Ok(count)
}

fn reject_index_rollback(
    cache: &Path,
    repository: &ConfiguredRepository,
    incoming: &RepositoryIndex,
) -> Result<()> {
    let Ok(index_bytes) = fs::read(cache.join("index.toml")) else {
        return Ok(());
    };
    let Ok(signature) = fs::read(cache.join("index.toml.sig")) else {
        return Ok(());
    };
    // Only a previously authenticated index is a trustworthy rollback floor.
    if verify_index_with_keys(&index_bytes, &signature, &repository.trusted_keys()).is_err() {
        return Ok(());
    }
    let Ok(index_text) = std::str::from_utf8(&index_bytes) else {
        return Ok(());
    };
    let Ok(cached) = RepositoryIndex::from_toml(index_text) else {
        return Ok(());
    };
    if incoming.generated < cached.generated {
        return Err(ArcError::Authentication(format!(
            "repository {} offered older index generation {}; cached generation is {}",
            repository.name, incoming.generated, cached.generated
        )));
    }
    Ok(())
}

pub fn prepare_install(root: &Path, requests: &[String]) -> Result<PreparedInstall> {
    let plan = plan_install(root, requests)?;
    download_plan(root, plan, &mut SilentDownloads)
}

pub fn prepare_upgrade(root: &Path) -> Result<PreparedInstall> {
    let Some(plan) = plan_upgrade(root)? else {
        return Ok(PreparedInstall {
            archives: vec![],
            selected: vec![],
        });
    };
    download_plan(root, plan, &mut SilentDownloads)
}

pub fn plan_install(root: &Path, requests: &[String]) -> Result<InstallPlan> {
    plan(root, requests, None, false, None)
}

pub fn plan_reinstall(root: &Path, requests: &[String]) -> Result<InstallPlan> {
    if requests.is_empty() {
        return Err(ArcError::Usage(
            "reinstall needs at least one package".into(),
        ));
    }
    let installed = Database::new(root)?.load_all()?;
    for request in requests {
        let requirement = Requirement::parse(request)?;
        if !installed
            .iter()
            .any(|package| resolver::package_satisfies(&package.package, &requirement))
        {
            return Err(ArcError::Usage(format!(
                "package {request} is not installed"
            )));
        }
    }
    plan(root, requests, None, true, None)
}

pub fn search_catalog(root: &Path, query: &str) -> Result<Vec<RepositoryPackage>> {
    let (_, catalog) = load_catalog(root, false)?;
    let query = query.to_ascii_lowercase();
    Ok(catalog
        .packages
        .into_iter()
        .filter(|package| {
            package.metadata.name.to_ascii_lowercase().contains(&query)
                || package
                    .metadata
                    .description
                    .to_ascii_lowercase()
                    .contains(&query)
        })
        .collect())
}

pub fn catalog_info(root: &Path, name: &str) -> Result<Vec<RepositoryPackage>> {
    validate_name(name)?;
    let (_, catalog) = load_catalog(root, false)?;
    Ok(catalog
        .packages
        .into_iter()
        .filter(|package| package.metadata.name == name)
        .collect())
}

/// Return synchronized package records that declare an internally bundled
/// component. This is a provenance query, not dependency resolution.
pub fn catalog_bundled(root: &Path, component: &str) -> Result<Vec<RepositoryPackage>> {
    validate_name(component)?;
    let (_, catalog) = load_catalog(root, false)?;
    Ok(catalog
        .packages
        .into_iter()
        .filter(|package| {
            package
                .metadata
                .bundled
                .iter()
                .any(|item| item.name == component)
        })
        .collect())
}

pub fn catalog_group(root: &Path, group: &str) -> Result<Vec<RepositoryPackage>> {
    validate_name(group)?;
    let (_, catalog) = load_catalog(root, false)?;
    Ok(catalog
        .packages
        .into_iter()
        .filter(|package| {
            package
                .metadata
                .package_groups
                .iter()
                .any(|value| value == group)
        })
        .collect())
}

pub fn catalog_required_by(root: &Path, name: &str) -> Result<Vec<RepositoryPackage>> {
    validate_name(name)?;
    let (_, catalog) = load_catalog(root, false)?;
    let targets = catalog
        .packages
        .iter()
        .filter(|package| package.metadata.name == name)
        .map(|package| package.metadata.clone())
        .collect::<Vec<_>>();
    Ok(catalog
        .packages
        .into_iter()
        .filter(|package| {
            package.metadata.depends.iter().any(|dependency| {
                Requirement::parse(dependency)
                    .ok()
                    .is_some_and(|requirement| {
                        targets
                            .iter()
                            .any(|target| resolver::package_satisfies(target, &requirement))
                    })
            })
        })
        .collect())
}

pub fn plan_upgrade(root: &Path) -> Result<Option<InstallPlan>> {
    let installed = Database::new(root)?.load_all()?;
    if installed.is_empty() {
        return Ok(None);
    }
    let settings = load_settings(root)?;
    let held = settings
        .hold
        .iter()
        .chain(&settings.ignore)
        .cloned()
        .collect::<HashSet<_>>();
    let requests = installed
        .iter()
        .filter(|package| !held.contains(&package.package.name))
        .map(|package| package.package.name.clone())
        .collect::<Vec<_>>();
    let explicit = installed
        .into_iter()
        .filter(|package| package.explicit)
        .map(|package| package.package.name)
        .collect::<HashSet<_>>();
    if requests.is_empty() {
        return Ok(Some(InstallPlan {
            settings,
            packages: vec![],
            explicit_override: Some(explicit),
            changes: vec![],
            selected: vec![],
        }));
    }
    plan(root, &requests, Some(&explicit), false, Some(&held)).map(Some)
}

fn plan(
    root: &Path,
    requests: &[String],
    explicit_override: Option<&HashSet<String>>,
    force_repository: bool,
    held: Option<&HashSet<String>>,
) -> Result<InstallPlan> {
    let (settings, index) = load_catalog(root, !force_repository)?;
    let plan = resolver::resolve(&index, &settings.architecture, requests)?;
    let installed = Database::new(root)?
        .load_all()?
        .into_iter()
        .map(|package| (package.package.name.clone(), package.package))
        .collect::<BTreeMap<_, _>>();
    let staged_names = plan
        .packages
        .iter()
        .filter(|planned| planned.package.source != INSTALLED_SOURCE)
        .map(|planned| planned.package.metadata.name.clone())
        .collect::<HashSet<_>>();
    let mut claimed_replacements = BTreeMap::new();
    let mut changes = Vec::new();
    let mut selected = Vec::new();
    for planned in &plan.packages {
        selected.push(format!(
            "{}-{}",
            planned.package.metadata.name, planned.package.metadata.version
        ));
        if planned.package.source == INSTALLED_SOURCE {
            continue;
        }
        if held.is_some_and(|held| held.contains(&planned.package.metadata.name)) {
            return Err(ArcError::Transaction(format!(
                "upgrade would change held package {}; use an explicit install request to override",
                planned.package.metadata.name
            )));
        }
        let cached_path = package_cache_path(root, &planned.package);
        let keys = settings
            .repositories
            .iter()
            .find(|repository| repository.name == planned.package.source)
            .map(ConfiguredRepository::trusted_keys);
        let cached = cached_path.exists()
            && keys
                .is_some_and(|keys| verify_package(&cached_path, &planned.package, &keys).is_ok());
        let kind =
            installed
                .get(&planned.package.metadata.name)
                .map_or(ChangeKind::Install, |metadata| ChangeKind::Upgrade {
                    from: metadata.version.clone(),
                });
        let mut replaces = Vec::new();
        for replacement in &planned.package.metadata.replaces {
            let requirement = Requirement::parse(replacement)?;
            replaces.extend(
                installed
                    .values()
                    .filter(|metadata| {
                        !staged_names.contains(&metadata.name)
                            && resolver::package_satisfies(metadata, &requirement)
                    })
                    .map(|metadata| ReplacedPackage {
                        name: metadata.name.clone(),
                        version: metadata.version.clone(),
                        architecture: metadata.arch.clone(),
                    }),
            );
        }
        replaces.sort_by(|first, second| first.name.cmp(&second.name));
        replaces.dedup_by(|first, second| first.name == second.name);
        for replaced in &replaces {
            if let Some(first) = claimed_replacements
                .insert(replaced.name.clone(), planned.package.metadata.name.clone())
            {
                return Err(ArcError::Transaction(format!(
                    "packages {first} and {} both replace {}",
                    planned.package.metadata.name, replaced.name
                )));
            }
        }
        changes.push(PlannedChange {
            name: planned.package.metadata.name.clone(),
            version: planned.package.metadata.version.clone(),
            architecture: planned.package.metadata.arch.clone(),
            repository: planned.package.source.clone(),
            download_size: planned.package.size,
            cached,
            explicit: explicit_override.map_or(planned.explicit, |names| {
                names.contains(&planned.package.metadata.name)
            }),
            kind,
            replaces,
        });
    }
    Ok(InstallPlan {
        settings,
        packages: plan.packages,
        explicit_override: explicit_override.cloned(),
        changes,
        selected,
    })
}

pub fn download_plan(
    root: &Path,
    plan: InstallPlan,
    observer: &mut dyn DownloadObserver,
) -> Result<PreparedInstall> {
    let _lock = crate::transaction::ArcLock::acquire(root)?;
    let parallelism = plan.settings.download_parallelism;
    let jobs = download_jobs(&plan)?;
    let mut archives = Vec::with_capacity(jobs.len());

    // Cache paths are derived from the package digest, so separate downloads
    // do not write the same destination.
    for batch in jobs.chunks(parallelism) {
        archives.extend(download_batch(root, batch, observer)?);
    }
    Ok(PreparedInstall {
        archives,
        selected: plan.selected,
    })
}

fn download_jobs(plan: &InstallPlan) -> Result<Vec<DownloadJob>> {
    let repositories = plan
        .settings
        .repositories
        .iter()
        .map(|repository| (repository.name.as_str(), repository))
        .collect::<BTreeMap<_, _>>();
    let mut jobs = Vec::new();
    for planned in &plan.packages {
        if planned.package.source == INSTALLED_SOURCE {
            continue;
        }
        let repository = repositories
            .get(planned.package.source.as_str())
            .ok_or_else(|| {
                ArcError::InvalidRepository(format!(
                    "package {} refers to unknown repository {:?}",
                    planned.package.metadata.name, planned.package.source
                ))
            })?;
        let explicit = plan
            .explicit_override
            .as_ref()
            .map_or(planned.explicit, |names| {
                names.contains(&planned.package.metadata.name)
            });
        jobs.push(DownloadJob {
            repository: (*repository).clone(),
            package: planned.package.clone(),
            explicit,
        });
    }
    Ok(jobs)
}

fn download_batch(
    root: &Path,
    jobs: &[DownloadJob],
    observer: &mut dyn DownloadObserver,
) -> Result<Vec<InstallArchive>> {
    let (sender, receiver) = mpsc::channel();
    let results = std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for job in jobs {
            let sender = sender.clone();
            workers.push(scope.spawn(move || {
                let mut events = ChannelDownloads(sender);
                download_package(root, &job.repository, &job.package, &mut events).map(|path| {
                    InstallArchive {
                        path,
                        explicit: job.explicit,
                    }
                })
            }));
        }
        drop(sender);
        workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| ArcError::Network("download worker panicked".into()))?
            })
            .collect::<Vec<_>>()
    });
    replay_download_events(observer, receiver);
    results.into_iter().collect()
}

fn load_catalog(
    root: &Path,
    include_installed: bool,
) -> Result<(RepositorySettings, RepositoryIndex)> {
    let settings = load_settings(root)?;
    let mut packages = Vec::new();
    let mut identities = HashSet::new();

    // Installed packages win an exact identity tie, so an already-current
    // package is not downloaded and reinstalled. Newer repository versions
    // still sort ahead normally in the resolver.
    for installed in Database::new(root)?
        .load_all()?
        .into_iter()
        .filter(|_| include_installed)
    {
        let identity = (
            installed.package.name.clone(),
            installed.package.version.clone(),
            installed.package.arch.clone(),
        );
        identities.insert(identity);
        packages.push(RepositoryPackage {
            filename: format!("installed/{}.arc", installed.package.name),
            metadata: installed.package,
            sha256: "0".repeat(64),
            size: 1,
            signature: String::new(),
            files: vec![],
            source: INSTALLED_SOURCE.into(),
        });
    }

    let mut repositories = settings.repositories.iter().collect::<Vec<_>>();
    repositories.sort_by(|first, second| {
        second
            .priority
            .cmp(&first.priority)
            .then_with(|| first.name.cmp(&second.name))
    });
    for repository in repositories {
        let cache = repository_cache(root, &repository.name);
        let index_bytes = fs::read(cache.join("index.toml")).map_err(|error| {
            ArcError::InvalidRepository(format!(
                "repository {} is not synchronized: {error}",
                repository.name
            ))
        })?;
        let signature = fs::read(cache.join("index.toml.sig"))?;
        verify_index_with_keys(&index_bytes, &signature, &repository.trusted_keys())?;
        let input = std::str::from_utf8(&index_bytes).map_err(|_| {
            ArcError::InvalidRepository(format!(
                "cached index for {} is not UTF-8",
                repository.name
            ))
        })?;
        let mut index = RepositoryIndex::from_toml(input)?;
        for mut package in index.packages.drain(..) {
            let identity = (
                package.metadata.name.clone(),
                package.metadata.version.clone(),
                package.metadata.arch.clone(),
            );
            if identities.insert(identity) {
                package.source = repository.name.clone();
                packages.push(package);
            }
        }
    }

    let index = RepositoryIndex {
        format: 1,
        generated: 0,
        packages,
    };
    index.validate()?;
    Ok((settings, index))
}

fn download_package(
    root: &Path,
    repository: &ConfiguredRepository,
    expected: &RepositoryPackage,
    observer: &mut dyn DownloadObserver,
) -> Result<PathBuf> {
    if expected.size > MAX_PACKAGE_SIZE {
        return Err(ArcError::InvalidRepository(format!(
            "package {} exceeds Arc's 64 GiB download limit",
            expected.metadata.name
        )));
    }
    let cache = root.join("var/cache/arc/packages");
    fs::create_dir_all(&cache)?;
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o755))?;
    let destination = cache.join(format!("{}.arc", expected.sha256));
    let keys = repository.trusted_keys();
    if destination.exists() && verify_package(&destination, expected, &keys).is_ok() {
        observer.cached(&expected.metadata.name, expected.size);
        return Ok(destination);
    }

    let mut last_error = None;
    for url in repository.object_urls(&expected.filename) {
        for _ in 0..=repository.retries {
            match stream_package(
                &url,
                &destination,
                expected,
                &keys,
                repository.timeout_seconds,
                repository.bandwidth_limit,
                observer,
            ) {
                Ok(()) => return Ok(destination),
                Err(error @ ArcError::Network(_)) => last_error = Some(error),
                Err(error) => return Err(error),
            }
        }
    }
    Err(last_error.unwrap_or_else(|| ArcError::Network("no repository URL available".into())))
}

fn package_cache_path(root: &Path, expected: &RepositoryPackage) -> PathBuf {
    root.join("var/cache/arc/packages")
        .join(format!("{}.arc", expected.sha256))
}

fn stream_package(
    url: &str,
    destination: &Path,
    expected: &RepositoryPackage,
    trusted_keys: &[&str],
    timeout_seconds: u64,
    bandwidth_limit: u64,
    observer: &mut dyn DownloadObserver,
) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| ArcError::InvalidRepository("package cache path has no parent".into()))?;
    let temporary = parent.join(format!(
        ".{}.part",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("package.arc"),
    ));
    let resume_from = fs::metadata(&temporary)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    if resume_from > expected.size {
        let _ = fs::remove_file(&temporary);
    }
    let resume_from = fs::metadata(&temporary)
        .map(|metadata| metadata.len())
        .unwrap_or(0);

    observer.started(&expected.metadata.name, expected.size);
    let result = (|| -> Result<()> {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(timeout_seconds)))
            .build()
            .new_agent();
        let request = if resume_from == 0 {
            agent.get(url)
        } else {
            agent
                .get(url)
                .header("Range", &format!("bytes={resume_from}-"))
        };
        let mut response = request
            .call()
            .map_err(|error| ArcError::Network(format!("GET {url}: {error}")))?;
        let append = resume_from > 0 && response.status().as_u16() == 206;
        let mut reader = response
            .body_mut()
            .as_reader()
            .take(expected.size.saturating_add(1));
        let mut output = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(!append)
            .append(append)
            .open(&temporary)?;
        output.set_permissions(fs::Permissions::from_mode(0o644))?;

        let mut received = if append { resume_from } else { 0 };
        let started = Instant::now();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|error| ArcError::Network(format!("GET {url}: {error}")))?;
            if count == 0 {
                break;
            }
            output.write_all(&buffer[..count])?;
            received += count as u64;
            if bandwidth_limit != 0 {
                let required = Duration::from_secs_f64(received as f64 / bandwidth_limit as f64);
                let elapsed = started.elapsed();
                if required > elapsed {
                    std::thread::sleep(required - elapsed);
                }
            }
            observer.advanced(&expected.metadata.name, received, expected.size);
        }
        if received != expected.size {
            return Err(ArcError::Authentication(format!(
                "package {} downloaded {received} bytes; signed index requires {}",
                expected.metadata.name, expected.size
            )));
        }
        output.sync_all()?;
        verify_package(&temporary, expected, trusted_keys)?;
        fs::rename(&temporary, destination)?;
        File::open(parent)?.sync_all()?;
        observer.finished(&expected.metadata.name, expected.size);
        Ok(())
    })();

    if result.is_err() {
        // Keep a partial file so the next invocation can continue with HTTP Range.
        observer.failed(&expected.metadata.name);
    }
    result
}

fn verify_package(path: &Path, expected: &RepositoryPackage, trusted_keys: &[&str]) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if metadata.len() != expected.size || package::sha256(path)? != expected.sha256 {
        return Err(ArcError::Authentication(format!(
            "package {} does not match its signed size and digest",
            expected.metadata.name
        )));
    }
    let inspection = package::inspect(path)?;
    if inspection.metadata != expected.metadata {
        return Err(ArcError::Authentication(format!(
            "package {} metadata differs from its signed index record",
            expected.metadata.name
        )));
    }
    if !expected.signature.is_empty()
        && verify_index_with_keys(
            expected.sha256.as_bytes(),
            expected.signature.as_bytes(),
            trusted_keys,
        )
        .is_err()
    {
        return Err(ArcError::Authentication(format!(
            "package {} has an invalid detached signature",
            expected.metadata.name
        )));
    }
    Ok(())
}

pub fn verify_index(index: &[u8], signature: &[u8], public_key: &str) -> Result<()> {
    let key = decode_array::<32>(public_key, "public key")?;
    let signature_text = std::str::from_utf8(signature)
        .map_err(|_| ArcError::Authentication("index signature is not UTF-8".into()))?
        .trim();
    let signature = decode_array::<64>(signature_text, "index signature")?;
    let key = VerifyingKey::from_bytes(&key)
        .map_err(|error| ArcError::Authentication(format!("invalid public key: {error}")))?;
    key.verify(index, &Signature::from_bytes(&signature))
        .map_err(|_| ArcError::Authentication("index signature is invalid".into()))
}

fn verify_index_with_keys(index: &[u8], signature: &[u8], trusted_keys: &[&str]) -> Result<()> {
    if trusted_keys
        .iter()
        .any(|key| verify_index(index, signature, key).is_ok())
    {
        Ok(())
    } else {
        Err(ArcError::Authentication(
            "signature is invalid for every trusted repository key".into(),
        ))
    }
}

fn get_repository_object(
    repository: &ConfiguredRepository,
    path: &str,
    limit: u64,
) -> Result<Vec<u8>> {
    let mut last_error = None;
    for url in repository.object_urls(path) {
        for _ in 0..=repository.retries {
            match get(&url, limit, repository.timeout_seconds) {
                Ok(bytes) => return Ok(bytes),
                Err(error @ ArcError::Network(_)) => last_error = Some(error),
                Err(error) => return Err(error),
            }
        }
    }
    Err(last_error.unwrap_or_else(|| ArcError::Network("no repository URL available".into())))
}

pub fn cache_entries(root: &Path) -> Result<Vec<(String, u64)>> {
    let directory = root.join("var/cache/arc/packages");
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut entries = fs::read_dir(directory)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|entry| {
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
        })
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_owned();
            if name.ends_with(".arc") {
                Some((name, entry.metadata().ok()?.len()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    entries.sort();
    Ok(entries)
}

pub fn clean_cache(root: &Path) -> Result<usize> {
    let _lock = crate::transaction::ArcLock::acquire(root)?;
    let directory = root.join("var/cache/arc/packages");
    if !directory.exists() {
        return Ok(0);
    }
    let mut removed = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_file() && entry.file_name().to_string_lossy().ends_with(".arc") {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn prune_cache(root: &Path, keep: usize) -> Result<usize> {
    let _lock = crate::transaction::ArcLock::acquire(root)?;
    let (_, catalog) = load_catalog(root, false)?;
    let mut by_name = BTreeMap::<String, Vec<&RepositoryPackage>>::new();
    for package in &catalog.packages {
        by_name
            .entry(package.metadata.name.clone())
            .or_default()
            .push(package);
    }
    let mut retained = HashSet::new();
    for packages in by_name.values_mut() {
        packages.sort_by(|first, second| {
            Version::parse(&second.metadata.version)
                .expect("validated catalog version")
                .cmp(&Version::parse(&first.metadata.version).expect("validated catalog version"))
        });
        retained.extend(
            packages
                .iter()
                .take(keep)
                .map(|package| format!("{}.arc", package.sha256)),
        );
    }
    let directory = root.join("var/cache/arc/packages");
    if !directory.exists() {
        return Ok(0);
    }
    let mut removed = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type()?.is_file() && name.ends_with(".arc") && !retained.contains(&name) {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn partial_downloads(root: &Path) -> Result<Vec<(String, u64)>> {
    let directory = root.join("var/cache/arc/packages");
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut entries = fs::read_dir(directory)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|entry| {
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
        })
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_owned();
            if name.ends_with(".part") {
                Some((name, entry.metadata().ok()?.len()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    entries.sort();
    Ok(entries)
}

/// Check cache entries against the currently authenticated repository catalog.
/// A root without repository configuration has no catalog to validate against.
pub fn cache_problems(root: &Path) -> Result<Vec<String>> {
    if !root.join("etc/arc/repos.toml").exists() {
        return Ok(Vec::new());
    }
    let (settings, catalog) = load_catalog(root, true)?;
    let expected = catalog
        .packages
        .iter()
        .filter(|package| package.source != INSTALLED_SOURCE)
        .map(|package| (format!("{}.arc", package.sha256), package))
        .collect::<BTreeMap<_, _>>();
    let mut problems = Vec::new();
    for (name, _) in cache_entries(root)? {
        let Some(package) = expected.get(&name) else {
            problems.push(format!("stale cached archive {name}"));
            continue;
        };
        let path = root.join("var/cache/arc/packages").join(&name);
        let keys = settings
            .repositories
            .iter()
            .find(|repository| repository.name == package.source)
            .map(ConfiguredRepository::trusted_keys)
            .unwrap_or_default();
        if verify_package(&path, package, &keys).is_err() {
            problems.push(format!("corrupt cached archive {name}"));
        }
    }
    Ok(problems)
}

fn decode_array<const N: usize>(value: &str, kind: &str) -> Result<[u8; N]> {
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ArcError::Authentication(format!(
            "{kind} is not lowercase hexadecimal"
        )));
    }
    let decoded = crate::encoding::hex_decode(value)
        .ok_or_else(|| ArcError::Authentication(format!("{kind} is not hexadecimal")))?;
    decoded
        .try_into()
        .map_err(|_| ArcError::Authentication(format!("{kind} has the wrong length")))
}

fn get(url: &str, limit: u64, timeout_seconds: u64) -> Result<Vec<u8>> {
    let mut response = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_seconds)))
        .build()
        .new_agent()
        .get(url)
        .call()
        .map_err(|error| ArcError::Network(format!("GET {url}: {error}")))?;
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|error| ArcError::Network(format!("GET {url}: {error}")))
}

fn repository_cache(root: &Path, name: &str) -> PathBuf {
    root.join("var/lib/arc/repos").join(name)
}

fn host_architecture() -> String {
    std::env::consts::ARCH.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[derive(Default)]
    struct RecordingDownloads {
        started: usize,
        advanced: usize,
        finished: usize,
        failed: usize,
    }

    impl DownloadObserver for RecordingDownloads {
        fn started(&mut self, _package: &str, _size: u64) {
            self.started += 1;
        }

        fn advanced(&mut self, _package: &str, _received: u64, _size: u64) {
            self.advanced += 1;
        }

        fn finished(&mut self, _package: &str, _size: u64) {
            self.finished += 1;
        }

        fn failed(&mut self, _package: &str) {
            self.failed += 1;
        }
    }

    fn repository_fixture(workspace: &Path) -> (PathBuf, SigningKey) {
        let repository = workspace.join("repository");
        let package_root = workspace.join("package-root");
        fs::create_dir_all(repository.join("packages")).unwrap();
        fs::create_dir_all(package_root.join(".arc")).unwrap();
        fs::create_dir_all(package_root.join("usr/share/hello")).unwrap();
        fs::write(
            package_root.join(".arc/meta.toml"),
            "format = 1\nname = \"hello\"\nversion = \"1\"\narch = \"x86_64\"\n",
        )
        .unwrap();
        fs::write(
            package_root.join("usr/share/hello/message"),
            "network install\n",
        )
        .unwrap();
        package::pack(&package_root, Some(&repository.join("packages/hello.arc"))).unwrap();
        let key = SigningKey::from_bytes(&[9; 32]);
        crate::publisher::build_index(&repository).unwrap();
        let key_path = workspace.join("repo.key");
        fs::write(&key_path, crate::encoding::hex_encode(key.to_bytes())).unwrap();
        crate::publisher::sign_index(&repository.join("index.toml"), &key_path).unwrap();
        (repository, key)
    }

    fn serve_repository(
        repository: &Path,
        tamper_package: bool,
    ) -> (String, thread::JoinHandle<()>) {
        let mut files = BTreeMap::from([
            (
                "/index.toml".to_owned(),
                fs::read(repository.join("index.toml")).unwrap(),
            ),
            (
                "/index.toml.sig".to_owned(),
                fs::read(repository.join("index.toml.sig")).unwrap(),
            ),
            (
                "/packages/hello.arc".to_owned(),
                fs::read(repository.join("packages/hello.arc")).unwrap(),
            ),
        ]);
        if tamper_package {
            files.get_mut("/packages/hello.arc").unwrap().push(0xff);
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                serve_request(&mut stream, &files);
            }
        });
        (format!("http://{address}"), handle)
    }

    fn serve_request(stream: &mut TcpStream, files: &BTreeMap<String, Vec<u8>>) {
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count != 0, "client closed before sending headers");
            request.extend_from_slice(&buffer[..count]);
            assert!(request.len() <= 16 * 1024, "request headers are too large");
        }
        let request = String::from_utf8(request).unwrap();
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap();
        let (status, body) = files
            .get(path)
            .map_or(("404 Not Found", &b"not found"[..]), |body| {
                ("200 OK", body.as_slice())
            });
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    }

    fn configure(root: &Path, url: &str, key: &SigningKey) {
        fs::create_dir_all(root.join("etc/arc")).unwrap();
        fs::write(
            root.join("etc/arc/repos.toml"),
            format!(
                "architecture = \"x86_64\"\n\n[[repository]]\nname = \"core\"\nurl = {url:?}\nkey = {:?}\n",
                crate::encoding::hex_encode(key.verifying_key().to_bytes())
            ),
        )
        .unwrap();
    }

    #[test]
    fn index_signatures_authenticate_exact_bytes() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let index = b"format = 1\ngenerated = 1\n";
        let signature = crate::encoding::hex_encode(key.sign(index).to_bytes());
        let public = crate::encoding::hex_encode(key.verifying_key().to_bytes());

        verify_index(index, signature.as_bytes(), &public).unwrap();
        assert!(verify_index(b"format = 2\n", signature.as_bytes(), &public).is_err());
    }

    #[test]
    fn repository_settings_require_https_and_unique_names() {
        let repository = ConfiguredRepository {
            name: "core".into(),
            url: "https://packages.example.test/arc".into(),
            key: "00".repeat(32),
            keys: vec![],
            delegated_keys: vec![],
            priority: 0,
            mirrors: vec![],
            retries: default_retries(),
            timeout_seconds: default_timeout_seconds(),
            bandwidth_limit: 0,
        };
        let settings = RepositorySettings {
            architecture: "x86_64".into(),
            repositories: vec![repository.clone()],
            hold: vec![],
            ignore: vec![],
            download_parallelism: default_download_parallelism(),
            include: vec![],
        };
        settings.validate().unwrap();

        let mut invalid = settings.clone();
        invalid.repositories[0].url = "http://packages.example.test".into();
        assert!(invalid.validate().is_err());

        let mut credentials = settings.clone();
        credentials.repositories[0].url = "https://user:secret@packages.example.test".into();
        assert!(credentials.validate().is_err());

        let mut duplicate = settings;
        duplicate.repositories.push(repository);
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn delegated_key_must_be_authorized_by_a_pinned_key() {
        let root = SigningKey::from_bytes(&[3; 32]);
        let delegated = SigningKey::from_bytes(&[4; 32]);
        let delegated_key = crate::encoding::hex_encode(delegated.verifying_key().to_bytes());
        let authorization = format!("arc-delegate-v1:{delegated_key}");
        let repository = ConfiguredRepository {
            name: "core".into(),
            url: "https://packages.example.test".into(),
            key: crate::encoding::hex_encode(root.verifying_key().to_bytes()),
            keys: vec![],
            delegated_keys: vec![DelegatedKey {
                key: delegated_key,
                signature: crate::encoding::hex_encode(
                    root.sign(authorization.as_bytes()).to_bytes(),
                ),
            }],
            priority: 0,
            mirrors: vec![],
            retries: default_retries(),
            timeout_seconds: default_timeout_seconds(),
            bandwidth_limit: 0,
        };
        repository.validate().unwrap();
        let expected = crate::encoding::hex_encode(delegated.verifying_key().to_bytes());
        assert!(repository.trusted_keys().contains(&expected.as_str()));

        let mut invalid = repository;
        invalid.delegated_keys[0].signature = "00".repeat(64);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn older_signed_indexes_cannot_replace_a_newer_cache() {
        let workspace = tempfile::tempdir().unwrap();
        let cache = workspace.path();
        let key = SigningKey::from_bytes(&[5; 32]);
        let repository = ConfiguredRepository {
            name: "core".into(),
            url: "https://packages.example.test".into(),
            key: crate::encoding::hex_encode(key.verifying_key().to_bytes()),
            keys: vec![],
            delegated_keys: vec![],
            priority: 0,
            mirrors: vec![],
            retries: default_retries(),
            timeout_seconds: default_timeout_seconds(),
            bandwidth_limit: 0,
        };
        let cached = RepositoryIndex {
            format: 1,
            generated: 20,
            packages: vec![],
        };
        let cached_bytes = cached.to_toml().unwrap().into_bytes();
        fs::write(cache.join("index.toml"), &cached_bytes).unwrap();
        fs::write(
            cache.join("index.toml.sig"),
            crate::encoding::hex_encode(key.sign(&cached_bytes).to_bytes()),
        )
        .unwrap();
        let incoming = RepositoryIndex {
            format: 1,
            generated: 19,
            packages: vec![],
        };
        let error = reject_index_rollback(cache, &repository, &incoming).unwrap_err();
        assert!(error.to_string().contains("older index generation"));
    }

    #[test]
    fn repository_network_round_trip_syncs_downloads_and_installs() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path().join("root");
        fs::create_dir(&root).unwrap();
        let (repository, key) = repository_fixture(workspace.path());
        let (url, server) = serve_repository(&repository, false);
        configure(&root, &url, &key);

        assert_eq!(sync(&root).unwrap(), 1);
        let plan = plan_install(&root, &["hello".into()]).unwrap();
        assert_eq!(plan.changes.len(), 1);
        assert!(plan.download_size() > 0);
        let mut downloads = RecordingDownloads::default();
        let prepared = download_plan(&root, plan, &mut downloads).unwrap();
        assert_eq!(prepared.archives.len(), 1);
        assert_eq!(downloads.started, 1);
        assert!(downloads.advanced > 0);
        assert_eq!(downloads.finished, 1);
        assert_eq!(downloads.failed, 0);
        crate::transaction::install(&root, &prepared.archives).unwrap();
        assert_eq!(
            fs::read_to_string(root.join("usr/share/hello/message")).unwrap(),
            "network install\n"
        );
        server.join().unwrap();
    }

    #[test]
    fn repository_network_round_trip_rejects_tampered_packages() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path().join("root");
        fs::create_dir(&root).unwrap();
        let (repository, key) = repository_fixture(workspace.path());
        let (url, server) = serve_repository(&repository, true);
        configure(&root, &url, &key);

        sync(&root).unwrap();
        let plan = plan_install(&root, &["hello".into()]).unwrap();
        let mut downloads = RecordingDownloads::default();
        let error = download_plan(&root, plan, &mut downloads).unwrap_err();
        assert!(error.to_string().contains("signed index requires"));
        assert_eq!(downloads.started, 1);
        assert_eq!(downloads.finished, 0);
        assert_eq!(downloads.failed, 1);
        assert!(
            fs::read_dir(root.join("var/cache/arc/packages"))
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".part"))
        );
        server.join().unwrap();
    }
}
