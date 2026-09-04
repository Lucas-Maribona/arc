//! Non-executing runtime inspection for prepared package roots.
//!
//! The parser reads ELF metadata directly; it deliberately never invokes
//! `ldd`, a loader, or a file from the package being inspected.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use goblin::elf::{Elf, program_header::PT_INTERP};

use crate::error::{ArcError, Result};
use crate::metadata::Metadata;

#[derive(Debug, Default)]
pub struct AuditReport {
    pub elf: Vec<ElfReport>,
    pub scripts: Vec<ScriptReport>,
    pub problems: Vec<String>,
}

#[derive(Debug)]
pub struct ElfReport {
    pub path: String,
    pub dynamic: bool,
    pub interpreter: Option<String>,
    pub needed: Vec<(String, bool)>,
    pub rpaths: Vec<String>,
}

#[derive(Debug)]
pub struct ScriptReport {
    pub path: String,
    pub interpreter: String,
}

struct ElfAudit<'a> {
    root: &'a Path,
    libraries: &'a HashMap<String, PathBuf>,
    self_contained: bool,
    report: &'a mut AuditReport,
    seen: &'a mut HashSet<PathBuf>,
}

impl AuditReport {
    pub fn passed(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Audit a package tree. `metadata` may be omitted for `arc audit`; when it is
/// present its self-contained policy is applied.
pub fn audit_root(root: &Path, metadata: Option<&Metadata>) -> Result<AuditReport> {
    if !root.is_dir() {
        return Err(ArcError::Usage(format!(
            "package root {} is not a directory",
            root.display()
        )));
    }
    let self_contained = metadata.is_some_and(|value| value.self_contained);
    let files = collect_files(root)?;
    let libraries = library_index(root, &files);
    let mut report = AuditReport::default();
    let mut seen_elf = HashSet::new();
    let mut elf_audit = ElfAudit {
        root,
        libraries: &libraries,
        self_contained,
        report: &mut report,
        seen: &mut seen_elf,
    };
    for path in &files {
        let relative = display_path(root, path)?;
        let file_metadata = fs::symlink_metadata(path)?;
        if file_metadata.file_type().is_symlink() {
            if fs::canonicalize(path).is_err() {
                elf_audit
                    .report
                    .problems
                    .push(format!("broken symlink: {relative}"));
            }
            continue;
        }
        if !file_metadata.is_file() {
            continue;
        }
        let bytes = fs::read(path)?;
        if bytes.starts_with(b"\x7fELF") {
            elf_audit.inspect(path, &relative, &bytes)?;
        } else if file_metadata.permissions().mode() & 0o111 != 0 && bytes.starts_with(b"#!") {
            inspect_script(root, path, &relative, &bytes, metadata, elf_audit.report);
        }
    }
    Ok(report)
}

impl ElfAudit<'_> {
    fn inspect(&mut self, path: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
        let elf = Elf::parse(bytes).map_err(|error| {
            ArcError::InvalidArchive(format!("invalid ELF {relative}: {error}"))
        })?;
        let interpreter = elf
            .program_headers
            .iter()
            .find(|header| header.p_type == PT_INTERP)
            .and_then(|header| {
                let start = usize::try_from(header.p_offset).ok()?;
                let end = start.checked_add(usize::try_from(header.p_filesz).ok()?)?;
                bytes
                    .get(start..end)
                    .and_then(|raw| raw.split(|byte| *byte == 0).next())
                    .and_then(|raw| std::str::from_utf8(raw).ok())
                    .map(str::to_owned)
            });
        let mut rpaths = elf
            .rpaths
            .iter()
            .chain(elf.runpaths.iter())
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        rpaths.sort();
        rpaths.dedup();
        for rpath in &rpaths {
            if has_build_path(rpath) {
                self.report
                    .problems
                    .push(format!("build-path RPATH/RUNPATH in {relative}: {rpath}"));
            }
        }
        if self.self_contained {
            if let Some(interpreter) = &interpreter {
                if !self
                    .root
                    .join(interpreter.trim_start_matches('/'))
                    .is_file()
                {
                    self.report.problems.push(format!(
                        "missing ELF interpreter: {relative} -> {interpreter}"
                    ));
                }
            } else if !elf.libraries.is_empty() {
                self.report
                    .problems
                    .push(format!("dynamic ELF without PT_INTERP: {relative}"));
            }
        }
        let mut needed = Vec::new();
        for library in &elf.libraries {
            let resolved = resolve_library(self.root, path, library, &rpaths, self.libraries);
            needed.push(((*library).to_owned(), resolved.is_some()));
            if self.self_contained && resolved.is_none() {
                self.report.problems.push(format!(
                    "missing runtime requirement: {relative} -> {library}"
                ));
            }
            if let Some(resolved) = resolved {
                if self.seen.insert(resolved.clone()) {
                    let child = fs::read(&resolved)?;
                    if child.starts_with(b"\x7fELF") {
                        let child_relative = display_path(self.root, &resolved)?;
                        self.inspect(&resolved, &child_relative, &child)?;
                    }
                }
            }
        }
        self.report.elf.push(ElfReport {
            path: relative.into(),
            dynamic: interpreter.is_some() || !elf.libraries.is_empty(),
            interpreter,
            needed,
            rpaths,
        });
        Ok(())
    }
}

fn inspect_script(
    root: &Path,
    _path: &Path,
    relative: &str,
    bytes: &[u8],
    metadata: Option<&Metadata>,
    report: &mut AuditReport,
) {
    let line = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let command = String::from_utf8_lossy(&line[2..])
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_owned();
    if command.is_empty() {
        report.problems.push(format!("invalid shebang: {relative}"));
        return;
    }
    if metadata.is_some_and(|value| value.self_contained)
        && command != "/bin/sh"
        && !root.join(command.trim_start_matches('/')).is_file()
    {
        report.problems.push(format!(
            "external script interpreter: {relative} -> {command}"
        ));
    }
    report.scripts.push(ScriptReport {
        path: relative.into(),
        interpreter: command,
    });
}

fn resolve_library(
    root: &Path,
    object: &Path,
    library: &str,
    rpaths: &[String],
    libraries: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    for entry in rpaths.iter().flat_map(|value| value.split(':')) {
        let expanded = entry.replace(
            "$ORIGIN",
            &object.parent()?.strip_prefix(root).ok()?.to_string_lossy(),
        );
        let candidate = if expanded.starts_with('/') {
            root.join(expanded.trim_start_matches('/'))
        } else {
            root.join(expanded)
        }
        .join(library);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    libraries.get(library).cloned()
}

fn library_index(root: &Path, files: &[PathBuf]) -> HashMap<String, PathBuf> {
    files
        .iter()
        .filter_map(|path| {
            let relative = path.strip_prefix(root).ok()?;
            if relative.starts_with("usr/lib/arc") {
                Some((
                    path.file_name()?.to_string_lossy().into_owned(),
                    path.clone(),
                ))
            } else {
                None
            }
        })
        .collect()
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>> {
    fn visit(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for item in fs::read_dir(path)? {
            let item = item?;
            let child = item.path();
            let kind = item.file_type()?;
            files.push(child.clone());
            if kind.is_dir() {
                visit(&child, files)?;
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn display_path(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)
        .map_err(|_| ArcError::InvalidState("audit path escaped root".into()))?
        .to_string_lossy()
        .into_owned())
}
fn has_build_path(value: &str) -> bool {
    value.contains("/tmp")
        || value.contains("/build")
        || value.contains("/home/")
        || value.contains("/github/workspace")
        || value.contains("/home/runner/work")
}

/// Human-readable output shared by `arc audit` and automatic pack validation.
pub fn format_report(metadata: Option<&Metadata>, report: &AuditReport) -> String {
    let mut out = String::new();
    if let Some(metadata) = metadata {
        out.push_str(&format!(
            "Package: {}\nSelf-contained: {}\n\n",
            metadata.name,
            if metadata.self_contained { "yes" } else { "no" }
        ));
    }
    out.push_str("ELF:\n");
    for elf in &report.elf {
        out.push_str(&format!(
            "  {}\n    type: {}\n",
            elf.path,
            if elf.dynamic { "dynamic" } else { "static" }
        ));
        if let Some(interpreter) = &elf.interpreter {
            out.push_str(&format!("    interpreter: {interpreter}\n"));
        }
        for (library, bundled) in &elf.needed {
            out.push_str(&format!(
                "    {library}: {}\n",
                if *bundled {
                    "bundled"
                } else {
                    "external/missing"
                }
            ));
        }
    }
    if !report.scripts.is_empty() {
        out.push_str("Scripts:\n");
        for script in &report.scripts {
            out.push_str(&format!(
                "  {}\n    interpreter: {}\n",
                script.path, script.interpreter
            ));
        }
    }
    if report.problems.is_empty() {
        out.push_str("\nResult: PASS\n");
    } else {
        out.push_str("\nResult: FAILED\n");
        for problem in &report.problems {
            out.push_str(&format!("\n{problem}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_broken_symlinks_without_following_them() {
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("missing", root.path().join("broken")).unwrap();
        let report = audit_root(root.path(), None).unwrap();
        assert!(
            report
                .problems
                .iter()
                .any(|item| item.contains("broken symlink"))
        );
    }

    #[test]
    fn reports_shell_shebang_as_a_narrow_system_interface() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("helper");
        fs::write(&script, b"#!/bin/sh\necho safe\n").unwrap();
        fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let metadata = Metadata::from_toml(
            "format=1\nname=\"test\"\nversion=\"1\"\narch=\"x86_64\"\nself_contained=true\n",
        )
        .unwrap();
        let report = audit_root(root.path(), Some(&metadata)).unwrap();
        assert!(report.passed());
        assert_eq!(report.scripts[0].interpreter, "/bin/sh");
    }
}
