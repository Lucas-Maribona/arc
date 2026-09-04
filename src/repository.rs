//! The signed repository-index data model.

use std::collections::HashSet;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::error::{ArcError, Result};
use crate::metadata::Metadata;

pub const INDEX_FORMAT_VERSION: u32 = 1;
const MAX_PACKAGE_SIZE: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryIndex {
    pub format: u32,
    pub generated: u64,
    #[serde(default, rename = "package")]
    pub packages: Vec<RepositoryPackage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPackage {
    #[serde(flatten)]
    pub metadata: Metadata,
    pub filename: String,
    pub sha256: String,
    pub size: u64,
    /// Ed25519 signature over the package SHA-256 digest. It is populated by
    /// `arc repo-sign` and authenticated again by the signed index.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    /// Signed manifest of payload paths. This lets clients query repository
    /// contents without first downloading an archive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// Populated after loading a configured repository. It is never serialized
    /// and therefore is not part of the signed index format.
    #[serde(skip)]
    pub source: String,
}

impl RepositoryIndex {
    pub fn from_toml(input: &str) -> Result<Self> {
        let index: Self = toml::from_str(input)?;
        index.validate()?;
        Ok(index)
    }

    pub fn to_toml(&self) -> Result<String> {
        self.validate()?;
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != INDEX_FORMAT_VERSION {
            return Err(ArcError::InvalidRepository(format!(
                "unsupported index format {}; expected {INDEX_FORMAT_VERSION}",
                self.format
            )));
        }

        let mut identities = HashSet::new();
        let mut filenames = HashSet::new();
        for package in &self.packages {
            package.validate()?;
            let identity = (
                &package.metadata.name,
                &package.metadata.version,
                &package.metadata.arch,
            );
            if !identities.insert(identity) {
                return Err(ArcError::InvalidRepository(format!(
                    "duplicate package {} {} {}",
                    package.metadata.name, package.metadata.version, package.metadata.arch
                )));
            }
            if !filenames.insert((&package.source, &package.filename)) {
                return Err(ArcError::InvalidRepository(format!(
                    "duplicate package filename {:?}",
                    package.filename
                )));
            }
        }
        Ok(())
    }
}

impl RepositoryPackage {
    pub fn validate(&self) -> Result<()> {
        self.metadata.validate()?;
        validate_repository_path(&self.filename)?;
        if !self.filename.ends_with(".arc") {
            return Err(ArcError::InvalidRepository(format!(
                "package filename {:?} does not end in .arc",
                self.filename
            )));
        }
        if self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ArcError::InvalidRepository(format!(
                "invalid SHA-256 digest for {}",
                self.metadata.name
            )));
        }
        if self.size == 0 || self.size > MAX_PACKAGE_SIZE {
            return Err(ArcError::InvalidRepository(format!(
                "package {} archive size must be between 1 byte and 64 GiB",
                self.metadata.name
            )));
        }
        let mut files = HashSet::new();
        for file in &self.files {
            validate_repository_path(file)?;
            if !files.insert(file) {
                return Err(ArcError::InvalidRepository(format!(
                    "duplicate manifest path {file:?} for {}",
                    self.metadata.name
                )));
            }
        }
        Ok(())
    }
}

fn validate_repository_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    let valid = !value.is_empty()
        && value.is_ascii()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    if valid {
        Ok(())
    } else {
        Err(ArcError::InvalidRepository(format!(
            "unsafe package filename {value:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn index() -> RepositoryIndex {
        RepositoryIndex {
            format: 1,
            generated: 1,
            packages: vec![RepositoryPackage {
                metadata: Metadata {
                    format: 1,
                    name: "hello".into(),
                    version: "1.0-1".into(),
                    arch: "x86_64".into(),
                    description: String::new(),
                    license: String::new(),
                    url: String::new(),
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
                filename: "packages/hello.arc".into(),
                sha256: HASH.into(),
                size: 10,
                signature: String::new(),
                files: vec![],
                source: String::new(),
            }],
        }
    }

    #[test]
    fn index_round_trips_as_toml() {
        let index = index();
        let encoded = index.to_toml().unwrap();
        assert_eq!(RepositoryIndex::from_toml(&encoded).unwrap(), index);
    }

    #[test]
    fn duplicate_identities_are_rejected() {
        let mut index = index();
        let mut duplicate = index.packages[0].clone();
        duplicate.filename = "packages/duplicate.arc".into();
        index.packages.push(duplicate);
        assert!(index.validate().is_err());
    }
}
