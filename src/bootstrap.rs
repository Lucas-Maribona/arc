//! Dependency validation and ordering for local bootstrap archives.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{ArcError, Result};
use crate::package;
use crate::repository::{RepositoryIndex, RepositoryPackage};
use crate::resolver;
use crate::transaction::InstallArchive;

/// Validate and dependency-order a complete local bootstrap set.
///
/// Every supplied package is an explicit bootstrap request. The resolver is
/// used here for ordering and validation, not version selection: duplicate
/// package names are rejected before it runs.
pub fn order(archives: &[InstallArchive]) -> Result<Vec<InstallArchive>> {
    if archives.is_empty() {
        return Err(ArcError::Resolution(
            "bootstrap package set is empty".into(),
        ));
    }

    let mut packages = Vec::with_capacity(archives.len());
    let mut by_filename = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut architectures = BTreeSet::new();
    for (position, archive) in archives.iter().enumerate() {
        let inspection = package::inspect(&archive.path)?;
        if !names.insert(inspection.metadata.name.clone()) {
            return Err(ArcError::Resolution(format!(
                "bootstrap contains package {} more than once",
                inspection.metadata.name
            )));
        }
        if inspection.metadata.arch != "any" {
            architectures.insert(inspection.metadata.arch.clone());
        }
        let filename = format!("packages/{position:08}.arc");
        by_filename.insert(filename.clone(), archive.clone());
        packages.push(RepositoryPackage {
            metadata: inspection.metadata,
            filename,
            sha256: inspection.sha256,
            size: std::fs::metadata(&archive.path)?.len(),
            signature: String::new(),
            files: vec![],
            source: String::new(),
        });
    }
    if architectures.len() > 1 {
        return Err(ArcError::Resolution(format!(
            "bootstrap mixes architectures: {}",
            architectures.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    let architecture = architectures
        .into_iter()
        .next()
        .unwrap_or_else(|| std::env::consts::ARCH.into());
    let requests = names.into_iter().collect::<Vec<_>>();
    let plan = resolver::resolve(
        &RepositoryIndex {
            format: 1,
            generated: 0,
            packages,
        },
        &architecture,
        &requests,
    )?;

    plan.packages
        .into_iter()
        .map(|planned| {
            by_filename
                .remove(&planned.package.filename)
                .ok_or_else(|| ArcError::Resolution("bootstrap plan lost an archive".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::*;

    fn make_package(
        workspace: &Path,
        name: &str,
        architecture: &str,
        dependencies: &[&str],
    ) -> PathBuf {
        let root = workspace.join(format!("{name}-root"));
        fs::create_dir_all(root.join(".arc")).unwrap();
        fs::create_dir_all(root.join("usr/share")).unwrap();
        let dependencies = dependencies
            .iter()
            .map(|dependency| format!("{dependency:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        fs::write(
            root.join(".arc/meta.toml"),
            format!(
                "format = 1\nname = {name:?}\nversion = \"1\"\narch = {architecture:?}\ndepends = [{dependencies}]\n"
            ),
        )
        .unwrap();
        fs::write(root.join("usr/share").join(name), name).unwrap();
        let output = workspace.join(format!("{name}.arc"));
        package::pack(&root, Some(&output)).unwrap();
        output
    }

    #[test]
    fn dependencies_are_ordered_before_consumers() {
        let workspace = tempfile::tempdir().unwrap();
        let application = make_package(workspace.path(), "application", "x86_64", &["library"]);
        let library = make_package(workspace.path(), "library", "x86_64", &[]);
        let ordered = order(&[
            InstallArchive {
                path: application,
                explicit: true,
            },
            InstallArchive {
                path: library.clone(),
                explicit: true,
            },
        ])
        .unwrap();
        assert_eq!(ordered[0].path, library);
    }

    #[test]
    fn mixed_architectures_and_missing_dependencies_are_rejected() {
        let workspace = tempfile::tempdir().unwrap();
        let x86 = make_package(workspace.path(), "x86", "x86_64", &["missing"]);
        assert!(
            order(&[InstallArchive {
                path: x86,
                explicit: true,
            }])
            .is_err()
        );

        let first = make_package(workspace.path(), "first", "x86_64", &[]);
        let second = make_package(workspace.path(), "second", "aarch64", &[]);
        assert!(
            order(&[
                InstallArchive {
                    path: first,
                    explicit: true,
                },
                InstallArchive {
                    path: second,
                    explicit: true,
                },
            ])
            .is_err()
        );
    }
}
