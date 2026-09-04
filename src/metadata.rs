//! Package metadata and its validation rules.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::{ArcError, Result};
use crate::package::validate_member_path;
use crate::version::{Operator, Requirement, Version, validate_name};

pub const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub format: u32,
    pub name: String,
    pub version: String,
    pub arch: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub license: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optdepends: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub package_groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backup: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub triggers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<SystemGroup>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<SystemUser>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemGroup {
    pub name: String,
    pub gid: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    #[serde(default = "default_home")]
    pub home: String,
    #[serde(default = "default_shell")]
    pub shell: String,
}

fn default_home() -> String {
    "/".into()
}
fn default_shell() -> String {
    "/usr/sbin/nologin".into()
}

impl Metadata {
    pub fn from_toml(input: &str) -> Result<Self> {
        let metadata: Self = toml::from_str(input)?;
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn to_toml(&self) -> Result<String> {
        self.validate()?;
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn version(&self) -> Result<Version> {
        Version::parse(&self.version)
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != FORMAT_VERSION {
            return Err(ArcError::InvalidMetadata(format!(
                "unsupported package format {}; expected {FORMAT_VERSION}",
                self.format
            )));
        }
        validate_name(&self.name)?;
        Version::parse(&self.version)?;
        validate_architecture(&self.arch)?;

        validate_unique_requirements("depends", &self.depends, false)?;
        validate_unique_requirements("optdepends", &self.optdepends, false)?;
        validate_unique_requirements("provides", &self.provides, true)?;
        validate_unique_requirements("conflicts", &self.conflicts, false)?;
        validate_unique_requirements("replaces", &self.replaces, false)?;
        let mut package_groups = HashSet::new();
        for group in &self.package_groups {
            validate_name(group)?;
            if !package_groups.insert(group) {
                return Err(ArcError::InvalidMetadata(format!(
                    "duplicate package group {group:?}"
                )));
            }
        }

        let mut paths = HashSet::new();
        for path in &self.backup {
            validate_member_path(path)?;
            if path == ".arc" || path.starts_with(".arc/") {
                return Err(ArcError::InvalidMetadata(format!(
                    "backup path {path:?} is reserved"
                )));
            }
            if !paths.insert(path) {
                return Err(ArcError::InvalidMetadata(format!(
                    "duplicate backup path {path:?}"
                )));
            }
        }
        let mut triggers = HashSet::new();
        for trigger in &self.triggers {
            validate_name(trigger)?;
            if !triggers.insert(trigger) {
                return Err(ArcError::InvalidMetadata(format!(
                    "duplicate system trigger {trigger:?}"
                )));
            }
        }
        let mut group_names = HashSet::new();
        let mut group_ids = HashSet::new();
        for group in &self.groups {
            validate_name(&group.name)?;
            if !group_names.insert(&group.name) || !group_ids.insert(group.gid) {
                return Err(ArcError::InvalidMetadata(format!(
                    "duplicate group {:?}",
                    group.name
                )));
            }
        }
        let mut user_names = HashSet::new();
        let mut user_ids = HashSet::new();
        for user in &self.users {
            validate_name(&user.name)?;
            if user.home.is_empty()
                || !user.home.starts_with('/')
                || user.home.contains(':')
                || user.shell.is_empty()
                || !user.shell.starts_with('/')
                || user.shell.contains(':')
            {
                return Err(ArcError::InvalidMetadata(format!(
                    "invalid account paths for {:?}",
                    user.name
                )));
            }
            if !user_names.insert(&user.name) || !user_ids.insert(user.uid) {
                return Err(ArcError::InvalidMetadata(format!(
                    "duplicate user {:?}",
                    user.name
                )));
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_architecture(architecture: &str) -> Result<()> {
    let valid = !architecture.is_empty()
        && architecture.len() <= 32
        && architecture
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(ArcError::InvalidMetadata(format!(
            "invalid architecture {architecture:?}"
        )))
    }
}

fn validate_unique_requirements(field: &str, values: &[String], provides: bool) -> Result<()> {
    let mut names = HashSet::new();
    for value in values {
        let requirement = Requirement::parse(value)?;
        if provides && matches!(requirement.operator, Some(operator) if operator != Operator::Equal)
        {
            return Err(ArcError::InvalidMetadata(format!(
                "{field} entry {value:?} may only use ="
            )));
        }
        if !names.insert(requirement.name.clone()) {
            return Err(ArcError::InvalidMetadata(format!(
                "duplicate {field} entry for {:?}",
                requirement.name
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_metadata_is_valid() {
        let metadata = Metadata::from_toml(
            r#"
                format = 1
                name = "hello"
                version = "1.0-1"
                arch = "x86_64"
            "#,
        )
        .unwrap();
        assert_eq!(metadata.name, "hello");
        assert!(metadata.depends.is_empty());
    }

    #[test]
    fn unknown_fields_fail_loudly() {
        let result = Metadata::from_toml(
            r#"
                format = 1
                name = "hello"
                version = "1"
                arch = "any"
                typo = true
            "#,
        );
        assert!(result.is_err());
    }
}
