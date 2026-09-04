//! Safe, non-executing runtime inspection for prepared package roots.
//!
//! This only models package-contained paths. It never invokes a loader, `ldd`,
//! a payload executable, or consults host library directories.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use goblin::elf::{Elf, header::ET_EXEC, program_header::PT_INTERP};

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
    pub needed: Vec<LibraryReport>,
    pub rpaths: Vec<String>,
}
#[derive(Debug)]
pub struct LibraryReport {
    pub name: String,
    pub resolved: Option<String>,
    pub searched: Vec<String>,
}
#[derive(Debug)]
pub struct ScriptReport {
    pub path: String,
    pub interpreter: String,
}
impl AuditReport {
    pub fn passed(&self) -> bool {
        self.problems.is_empty()
    }
}

struct ElfAudit<'a> {
    root: &'a Path,
    self_contained: bool,
    report: &'a mut AuditReport,
    seen: &'a mut HashSet<PathBuf>,
}

pub fn audit_root(root: &Path, metadata: Option<&Metadata>) -> Result<AuditReport> {
    if !root.is_dir() {
        return Err(ArcError::Usage(format!(
            "package root {} is not a directory",
            root.display()
        )));
    }
    let files = collect_files(root)?;
    let mut report = AuditReport::default();
    let mut seen = HashSet::new();
    let mut audit = ElfAudit {
        root,
        self_contained: metadata.is_some_and(|value| value.self_contained),
        report: &mut report,
        seen: &mut seen,
    };
    for path in &files {
        let relative = display_path(root, path)?;
        let file_metadata = fs::symlink_metadata(path)?;
        if file_metadata.file_type().is_symlink() {
            if let Err(problem) = resolve_payload_path(root, path) {
                audit
                    .report
                    .problems
                    .push(format!("invalid symlink {relative}: {problem}"));
            }
            continue;
        }
        if !file_metadata.is_file() {
            continue;
        }
        let bytes = fs::read(path)?;
        if bytes.starts_with(b"\x7fELF") {
            audit.inspect(path, &relative, &bytes)?;
        } else if file_metadata.permissions().mode() & 0o111 != 0 && bytes.starts_with(b"#!") {
            inspect_script(root, &relative, &bytes, metadata, audit.report);
        }
    }
    Ok(report)
}

impl ElfAudit<'_> {
    fn inspect(&mut self, path: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
        let elf = Elf::parse(bytes).map_err(|error| {
            ArcError::InvalidArchive(format!("invalid ELF {relative}: {error}"))
        })?;
        let interpreter = interpreter(bytes, &elf);
        // RUNPATH serves this object's direct requirements. Where it is absent,
        // RPATH does; recursive objects are inspected with their own paths.
        let paths = if elf.runpaths.is_empty() {
            &elf.rpaths
        } else {
            &elf.runpaths
        };
        let rpaths = paths
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<Vec<_>>();
        for value in &rpaths {
            if has_build_path(value) {
                self.report
                    .problems
                    .push(format!("build-path RPATH/RUNPATH in {relative}: {value}"));
            }
        }
        if self.self_contained {
            match interpreter.as_deref() {
                Some(value) if value.starts_with('/') => match runtime_path(self.root, path, value)
                {
                    Some(candidate)
                        if resolve_payload_path(self.root, &candidate)
                            .is_ok_and(|target| target.is_file()) => {}
                    _ => self.report.problems.push(format!(
                        "missing or unsafe ELF interpreter: {relative} -> {value}"
                    )),
                },
                Some(value) => self.report.problems.push(format!(
                    "missing or unsafe ELF interpreter: {relative} -> {value}"
                )),
                None if elf.header.e_type == ET_EXEC && !elf.libraries.is_empty() => self
                    .report
                    .problems
                    .push(format!("dynamic ELF without PT_INTERP: {relative}")),
                None => {}
            }
        }
        let mut needed = Vec::new();
        for library in &elf.libraries {
            let (resolved, searched) = resolve_library(self.root, path, library, paths);
            if self.self_contained && resolved.is_none() {
                self.report.problems.push(format!(
                    "missing runtime requirement: {relative} -> {library}; searched: {}",
                    searched.join(", ")
                ));
            }
            if let Some(candidate) = &resolved {
                if self.seen.insert(candidate.clone()) {
                    let child = fs::read(candidate)?;
                    if child.starts_with(b"\x7fELF") {
                        let child_relative = display_path(self.root, candidate)?;
                        self.inspect(candidate, &child_relative, &child)?;
                    }
                }
            }
            needed.push(LibraryReport {
                name: (*library).to_owned(),
                resolved: resolved
                    .as_ref()
                    .and_then(|path| display_path(self.root, path).ok())
                    .map(|path| format!("/{path}")),
                searched,
            });
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

fn interpreter(bytes: &[u8], elf: &Elf<'_>) -> Option<String> {
    elf.program_headers
        .iter()
        .find(|header| header.p_type == PT_INTERP)
        .and_then(|header| {
            let start = usize::try_from(header.p_offset).ok()?;
            let end = start.checked_add(usize::try_from(header.p_filesz).ok()?)?;
            std::str::from_utf8(bytes.get(start..end)?.split(|byte| *byte == 0).next()?)
                .ok()
                .map(str::to_owned)
        })
}

fn resolve_library(
    root: &Path,
    object: &Path,
    library: &str,
    paths: &[&str],
) -> (Option<PathBuf>, Vec<String>) {
    let mut searched = Vec::new();
    for entry in paths.iter().flat_map(|path| path.split(':')) {
        let Some(directory) = runtime_path(root, object, entry) else {
            searched.push(format!("invalid:{entry}"));
            continue;
        };
        let candidate = directory.join(library);
        searched.push(
            display_path(root, &candidate)
                .map(|path| format!("/{path}"))
                .unwrap_or_else(|_| format!("invalid:{entry}")),
        );
        if let Ok(target) = resolve_payload_path(root, &candidate) {
            if target.is_file() {
                return (Some(target), searched);
            }
        }
    }
    (None, searched)
}

/// Expand an ELF loader path and lexically normalize it within `root`.
fn runtime_path(root: &Path, object: &Path, value: &str) -> Option<PathBuf> {
    if value.is_empty() || value.as_bytes().contains(&0) {
        return None;
    }
    let origin = format!("/{}", object.parent()?.strip_prefix(root).ok()?.display());
    let value = value
        .replace("${ORIGIN}", &origin)
        .replace("$ORIGIN", &origin);
    let base = if value.starts_with('/') {
        root
    } else {
        object.parent()?
    };
    normalize_inside(root, base, Path::new(&value))
}

fn normalize_inside(root: &Path, base: &Path, value: &Path) -> Option<PathBuf> {
    let mut parts = base
        .strip_prefix(root)
        .ok()?
        .components()
        .filter_map(normal)
        .collect::<Vec<_>>();
    if value.is_absolute() {
        parts.clear();
    }
    for component in value.components() {
        match component {
            Component::Normal(value) => parts.push(PathBuf::from(value)),
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::CurDir | Component::RootDir => {}
            Component::Prefix(_) => return None,
        }
    }
    Some(
        parts
            .into_iter()
            .fold(root.to_owned(), |path, part| path.join(part)),
    )
}
fn normal(component: Component<'_>) -> Option<PathBuf> {
    if let Component::Normal(value) = component {
        Some(PathBuf::from(value))
    } else {
        None
    }
}

/// Resolve a payload path under package-root semantics. Absolute symlink targets
/// are rooted at the package root, and loops or escapes are rejected.
fn resolve_payload_path(root: &Path, path: &Path) -> std::result::Result<PathBuf, String> {
    let initial = path
        .strip_prefix(root)
        .map_err(|_| "path escapes package root".to_owned())?;
    let mut pending = initial.to_owned();
    for _ in 0..40 {
        let normalized = normalize_inside(root, root, &pending)
            .ok_or_else(|| "path escapes package root".to_owned())?;
        let relative = normalized
            .strip_prefix(root)
            .expect("normalized beneath root");
        let mut current = root.to_owned();
        let mut components = relative.components().peekable();
        let mut followed_link = false;
        while let Some(component) = components.next() {
            let Component::Normal(component) = component else {
                continue;
            };
            current.push(component);
            let metadata =
                fs::symlink_metadata(&current).map_err(|_| "broken symlink".to_owned())?;
            if metadata.file_type().is_symlink() {
                let target =
                    fs::read_link(&current).map_err(|_| "unreadable symlink".to_owned())?;
                let base = if target.is_absolute() {
                    root.to_owned()
                } else {
                    current.parent().expect("path beneath root").to_owned()
                };
                let mut next = base
                    .strip_prefix(root)
                    .expect("path beneath root")
                    .to_owned();
                next.push(target.strip_prefix("/").unwrap_or(&target));
                for remaining in components {
                    next.push(remaining.as_os_str());
                }
                pending = next;
                followed_link = true;
                break;
            }
        }
        if !followed_link {
            return Ok(current);
        }
    }
    Err("symlink loop".into())
}

fn inspect_script(
    root: &Path,
    relative: &str,
    bytes: &[u8],
    metadata: Option<&Metadata>,
    report: &mut AuditReport,
) {
    let line = String::from_utf8_lossy(
        bytes
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default(),
    );
    let mut words = line.get(2..).unwrap_or_default().split_whitespace();
    let Some(interpreter) = words.next() else {
        report.problems.push(format!("invalid shebang: {relative}"));
        return;
    };
    let command = if interpreter == "/usr/bin/env" {
        match words.next() {
            Some("-S") => words.next(),
            Some(value) if value.starts_with('-') => None,
            Some(value) => Some(value),
            None => None,
        }
    } else {
        Some(interpreter)
    };
    let Some(command) = command else {
        report
            .problems
            .push(format!("unsupported env shebang: {relative}"));
        return;
    };
    if metadata.is_some_and(|value| value.self_contained) && command != "/bin/sh" {
        let direct = if interpreter == "/usr/bin/env" {
            PathBuf::from("usr/bin").join(command)
        } else {
            PathBuf::from(command.trim_start_matches('/'))
        };
        let env_ok = interpreter != "/usr/bin/env"
            || resolve_payload_path(root, &root.join("usr/bin/env"))
                .is_ok_and(|path| path.is_file());
        if !env_ok
            || !resolve_payload_path(root, &root.join(direct)).is_ok_and(|path| path.is_file())
        {
            report.problems.push(format!(
                "external script interpreter: {relative} -> {command}"
            ));
        }
    }
    report.scripts.push(ScriptReport {
        path: relative.into(),
        interpreter: command.into(),
    });
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>> {
    fn visit(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for item in fs::read_dir(path)? {
            let child = item?.path();
            let kind = fs::symlink_metadata(&child)?.file_type();
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
        || value.starts_with("/workspace")
        || value.starts_with("/src")
        || value.starts_with("/builddir")
}

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
        if let Some(value) = &elf.interpreter {
            out.push_str(&format!("    interpreter: {value}\n"));
        }
        for library in &elf.needed {
            match &library.resolved {
                Some(path) => out.push_str(&format!("    {}: bundled -> {path}\n", library.name)),
                None => out.push_str(&format!(
                    "    {}: unresolved\n      searched: {}\n",
                    library.name,
                    library.searched.join(", ")
                )),
            }
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
    fn metadata() -> Metadata {
        Metadata::from_toml(
            "format=1\nname=\"test\"\nversion=\"1\"\narch=\"x86_64\"\nself_contained=true\n",
        )
        .unwrap()
    }
    fn executable(root: &Path, name: &str, text: &str) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
        fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    }
    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn program_header(bytes: &mut [u8], index: usize, kind: u32, offset: u64, size: u64) {
        let base = 64 + index * 56;
        put_u32(bytes, base, kind);
        put_u64(bytes, base + 8, offset);
        put_u64(bytes, base + 16, offset);
        put_u64(bytes, base + 32, size);
        put_u64(bytes, base + 40, size);
    }
    /// A deterministic ELF64 fixture parsed by the auditor but never executed.
    fn elf_fixture(kind: u16, needed: &str, runpath: &str, interpreter: Option<&str>) -> Vec<u8> {
        let mut bytes = vec![0_u8; 1024];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        put_u16(&mut bytes, 16, kind);
        put_u16(&mut bytes, 18, 62);
        put_u32(&mut bytes, 20, 1);
        put_u64(&mut bytes, 32, 64);
        put_u16(&mut bytes, 52, 64);
        put_u16(&mut bytes, 54, 56);
        put_u16(&mut bytes, 56, if interpreter.is_some() { 3 } else { 2 });
        program_header(&mut bytes, 0, 1, 0, 1024);
        program_header(&mut bytes, 1, 2, 0x200, 80);
        if let Some(interpreter) = interpreter {
            bytes[0x180..0x180 + interpreter.len()].copy_from_slice(interpreter.as_bytes());
            program_header(
                &mut bytes,
                2,
                PT_INTERP,
                0x180,
                (interpreter.len() + 1) as u64,
            );
        }
        let strings = format!("\0{needed}\0{runpath}\0");
        bytes[0x300..0x300 + strings.len()].copy_from_slice(strings.as_bytes());
        let mut dynamic = vec![(5_u64, 0x300_u64), (10, strings.len() as u64)];
        if !needed.is_empty() {
            dynamic.push((1, 1));
        }
        dynamic.push((29, (needed.len() + 2) as u64));
        dynamic.push((0, 0));
        for (index, (tag, value)) in dynamic.into_iter().enumerate() {
            put_u64(&mut bytes, 0x200 + index * 16, tag);
            put_u64(&mut bytes, 0x208 + index * 16, value);
        }
        bytes
    }
    fn write_elf(root: &Path, name: &str, bytes: &[u8], mode: u32) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode)).unwrap();
    }

    #[test]
    fn shell_shebang_is_allowed() {
        let root = tempfile::tempdir().unwrap();
        executable(root.path(), "helper", "#!/bin/sh\n");
        assert!(audit_root(root.path(), Some(&metadata())).unwrap().passed());
    }
    #[test]
    fn direct_and_env_python_require_bundles() {
        let root = tempfile::tempdir().unwrap();
        executable(root.path(), "a", "#!/usr/bin/python3\n");
        executable(root.path(), "b", "#!/usr/bin/env python3\n");
        let report = audit_root(root.path(), Some(&metadata())).unwrap();
        assert_eq!(report.problems.len(), 2);
        executable(root.path(), "usr/bin/python3", "#!/bin/sh\n");
        executable(root.path(), "usr/bin/env", "#!/bin/sh\n");
        assert!(audit_root(root.path(), Some(&metadata())).unwrap().passed());
    }
    #[test]
    fn env_split_string_identifies_command() {
        let root = tempfile::tempdir().unwrap();
        executable(root.path(), "a", "#!/usr/bin/env -S python3 -u\n");
        let report = audit_root(root.path(), Some(&metadata())).unwrap();
        assert!(report.problems[0].contains("python3"));
    }
    #[test]
    fn absolute_symlinks_are_package_rooted_and_escapes_fail() {
        let root = tempfile::tempdir().unwrap();
        executable(root.path(), "usr/lib/arc/foo/libx.so", "x");
        std::os::unix::fs::symlink("/usr/lib/arc/foo/libx.so", root.path().join("link")).unwrap();
        assert!(audit_root(root.path(), Some(&metadata())).unwrap().passed());
        std::os::unix::fs::symlink("../../outside", root.path().join("bad")).unwrap();
        assert!(!audit_root(root.path(), Some(&metadata())).unwrap().passed());
    }
    #[test]
    fn runtime_paths_do_not_fallback_by_basename() {
        let root = tempfile::tempdir().unwrap();
        let object = root.path().join("usr/bin/foo");
        executable(root.path(), "usr/bin/foo", "x");
        executable(root.path(), "usr/lib/arc/foo/libx.so", "x");
        assert!(
            resolve_library(root.path(), &object, "libx.so", &[])
                .0
                .is_none()
        );
        assert!(
            resolve_library(root.path(), &object, "libx.so", &["$ORIGIN/../lib/arc/foo"])
                .0
                .is_some()
        );
    }

    #[test]
    fn symlinked_parent_cannot_escape_package_root() {
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/tmp", root.path().join("usr")).unwrap();
        assert!(resolve_payload_path(root.path(), &root.path().join("usr/file")).is_err());
    }

    #[test]
    fn runtime_paths_expand_both_origin_forms() {
        let root = tempfile::tempdir().unwrap();
        let object = root.path().join("usr/bin/foo");
        executable(root.path(), "usr/bin/foo", "x");
        executable(root.path(), "usr/lib/arc/foo/libx.so", "x");
        for path in ["$ORIGIN/../lib/arc/foo", "${ORIGIN}/../lib/arc/foo"] {
            assert!(
                resolve_library(root.path(), &object, "libx.so", &[path])
                    .0
                    .is_some()
            );
        }
    }

    #[test]
    fn executable_chain_accepts_mode_755_shared_objects_without_interpreters() {
        let root = tempfile::tempdir().unwrap();
        let runtime = "/usr/lib/arc/foo";
        write_elf(
            root.path(),
            "usr/bin/foo",
            &elf_fixture(ET_EXEC, "liba.so", runtime, Some("/usr/lib/arc/foo/ld.so")),
            0o755,
        );
        write_elf(
            root.path(),
            "usr/lib/arc/foo/liba.so",
            &elf_fixture(goblin::elf::header::ET_DYN, "libb.so", runtime, None),
            0o755,
        );
        write_elf(
            root.path(),
            "usr/lib/arc/foo/libb.so",
            &elf_fixture(goblin::elf::header::ET_DYN, "", runtime, None),
            0o755,
        );
        executable(root.path(), "usr/lib/arc/foo/ld.so", "loader");
        let report = audit_root(root.path(), Some(&metadata())).unwrap();
        assert!(report.passed(), "{:?}", report.problems);
        assert!(
            !report
                .problems
                .iter()
                .any(|problem| problem.contains("liba.so") && problem.contains("PT_INTERP"))
        );
    }
}
