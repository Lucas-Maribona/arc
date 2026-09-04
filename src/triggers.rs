//! Declarative post-transaction commands run inside the target root.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::error::{ArcError, Result};
use crate::version::validate_name;

const CONFIG_PATH: &str = "etc/arc/triggers.toml";
const MAX_CONFIG_SIZE: u64 = 1024 * 1024;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_LENGTH: usize = 4096;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    #[serde(default, rename = "trigger")]
    definitions: Vec<Definition>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    name: String,
    command: Vec<String>,
}

impl Configuration {
    pub(crate) fn load(root: &Path) -> Result<Self> {
        let path = root.join(CONFIG_PATH);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() || metadata.len() > MAX_CONFIG_SIZE {
            return Err(ArcError::InvalidState(format!(
                "/{CONFIG_PATH} must be a regular file no larger than 1 MiB"
            )));
        }
        let configuration: Self = toml::from_str(&fs::read_to_string(path)?)?;
        configuration.validate()?;
        Ok(configuration)
    }

    fn validate(&self) -> Result<()> {
        let mut names = HashSet::new();
        for definition in &self.definitions {
            validate_name(&definition.name).map_err(|error| {
                ArcError::InvalidState(format!("invalid trigger name: {error}"))
            })?;
            if !names.insert(&definition.name) {
                return Err(ArcError::InvalidState(format!(
                    "duplicate trigger definition {:?}",
                    definition.name
                )));
            }
            if definition.command.is_empty() || definition.command.len() > MAX_ARGUMENTS {
                return Err(ArcError::InvalidState(format!(
                    "trigger {} must have 1 to {MAX_ARGUMENTS} command arguments",
                    definition.name
                )));
            }
            validate_executable(&definition.name, &definition.command[0])?;
            if definition
                .command
                .iter()
                .any(|argument| argument.len() > MAX_ARGUMENT_LENGTH || argument.contains('\0'))
            {
                return Err(ArcError::InvalidState(format!(
                    "trigger {} contains an invalid command argument",
                    definition.name
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn run(&self, root: &Path, requested: &BTreeSet<String>) -> Result<()> {
        if requested.is_empty() {
            return Ok(());
        }
        let available = self
            .definitions
            .iter()
            .map(|definition| definition.name.as_str())
            .collect::<HashSet<_>>();
        if let Some(missing) = requested
            .iter()
            .find(|name| !available.contains(name.as_str()))
        {
            return Err(ArcError::Transaction(format!(
                "package requested undefined system trigger {missing:?}"
            )));
        }
        for definition in &self.definitions {
            if requested.contains(&definition.name) {
                run_definition(root, definition)?;
            }
        }
        Ok(())
    }
}

fn validate_executable(trigger: &str, executable: &str) -> Result<()> {
    let path = Path::new(executable);
    let mut components = path.components();
    let absolute = matches!(components.next(), Some(Component::RootDir))
        && components.all(|component| matches!(component, Component::Normal(_)));
    if !absolute || executable.len() > MAX_ARGUMENT_LENGTH || executable.contains('\0') {
        return Err(ArcError::InvalidState(format!(
            "trigger {trigger} executable must be a normalized absolute path"
        )));
    }
    Ok(())
}

fn run_definition(root: &Path, definition: &Definition) -> Result<()> {
    let executable = Path::new(&definition.command[0]);
    let target_executable = root.join(
        executable
            .strip_prefix("/")
            .expect("validated absolute trigger executable"),
    );
    if !target_executable.is_file() {
        return Err(ArcError::Transaction(format!(
            "cannot run trigger {}: {} is missing from the target root",
            definition.name, definition.command[0]
        )));
    }

    let trigger_root = root.to_owned();
    let mut command = Command::new(&definition.command[0]);
    command
        .args(&definition.command[1..])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("ARC_TRIGGER", &definition.name)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // SAFETY: only async-signal-safe chroot/chdir syscalls run before exec.
    unsafe {
        command.pre_exec(move || {
            if trigger_root != Path::new("/") {
                rustix::process::chroot(&trigger_root).map_err(std::io::Error::from)?;
            }
            rustix::process::chdir("/").map_err(std::io::Error::from)?;
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|error| {
        ArcError::Transaction(format!(
            "cannot start system trigger {}: {error}",
            definition.name
        ))
    })?;
    let status = crate::process::wait_with_timeout(
        &mut child,
        &format!("system trigger {}", definition.name),
    )?;
    if !status.success() {
        return Err(ArcError::Transaction(format!(
            "system trigger {} exited with {status}",
            definition.name
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_trigger_runs_with_a_minimal_environment() {
        let configuration = Configuration {
            definitions: vec![Definition {
                name: "ldconfig".into(),
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "test \"$ARC_TRIGGER\" = ldconfig && test \"$PATH\" = /usr/bin:/bin:/usr/sbin:/sbin"
                        .into(),
                ],
            }],
        };
        configuration.validate().unwrap();
        configuration
            .run(Path::new("/"), &BTreeSet::from(["ldconfig".into()]))
            .unwrap();
    }

    #[test]
    fn undefined_triggers_fail_loudly() {
        let configuration = Configuration::default();
        let error = configuration
            .run(Path::new("/"), &BTreeSet::from(["ldconfig".into()]))
            .unwrap_err();
        assert!(error.to_string().contains("undefined system trigger"));
    }
}
