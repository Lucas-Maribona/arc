//! Creation and signing of repository indexes.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};

use crate::error::{ArcError, Result};
use crate::package;
use crate::repository::{RepositoryIndex, RepositoryPackage};

pub fn build_index(repository: &Path) -> Result<PathBuf> {
    let repository = repository.canonicalize()?;
    let package_directory = repository.join("packages");
    if !package_directory.is_dir() {
        return Err(ArcError::Usage(format!(
            "repository {} has no packages directory",
            repository.display()
        )));
    }

    let mut paths = fs::read_dir(&package_directory)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("arc"))
        .collect::<Vec<_>>();
    paths.sort_by_key(|entry| entry.file_name());
    if paths.is_empty() {
        return Err(ArcError::Usage(format!(
            "{} contains no .arc packages",
            package_directory.display()
        )));
    }

    let mut packages = paths
        .iter()
        .map(package_record)
        .collect::<Result<Vec<_>>>()?;
    packages.sort_by(|first, second| {
        first
            .metadata
            .name
            .cmp(&second.metadata.name)
            .then_with(|| {
                first
                    .metadata
                    .version()
                    .expect("inspected metadata")
                    .cmp(&second.metadata.version().expect("inspected metadata"))
            })
            .then_with(|| first.metadata.arch.cmp(&second.metadata.arch))
    });

    let generated = unix_time()?;
    let index = RepositoryIndex {
        format: 1,
        generated,
        packages,
    };
    let destination = repository.join("index.toml");
    crate::atomic_file::write(&destination, index.to_toml()?.as_bytes(), 0o644)?;
    Ok(destination)
}

/// Read one archive and turn it into the complete public repository record.
fn package_record(entry: &fs::DirEntry) -> Result<RepositoryPackage> {
    if !entry.file_type()?.is_file() {
        return Err(ArcError::Usage(format!(
            "package entry {} is not a regular file",
            entry.path().display()
        )));
    }

    let inspection = package::inspect(&entry.path())?;
    let filename = entry.file_name().into_string().map_err(|_| {
        ArcError::Usage(format!(
            "package filename {} is not UTF-8",
            entry.path().display()
        ))
    })?;
    let files = inspection
        .members
        .into_iter()
        .filter(|member| member.kind != package::MemberKind::Internal)
        .map(|member| member.path)
        .collect();

    Ok(RepositoryPackage {
        metadata: inspection.metadata,
        filename: format!("packages/{filename}"),
        sha256: inspection.sha256,
        size: entry.metadata()?.len(),
        signature: String::new(),
        files,
        source: String::new(),
    })
}

fn unix_time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ArcError::Usage("system clock is before the Unix epoch".into()))?
        .as_secs())
}

pub fn generate_key(destination: &Path) -> Result<String> {
    if destination.exists() {
        return Err(ArcError::Usage(format!(
            "refusing to overwrite private key {}",
            destination.display()
        )));
    }
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret)
        .map_err(|error| ArcError::Usage(format!("cannot generate signing key: {error}")))?;
    let key = SigningKey::from_bytes(&secret);
    crate::atomic_file::write(
        destination,
        format!("{}\n", crate::encoding::hex_encode(secret)).as_bytes(),
        0o600,
    )?;
    Ok(crate::encoding::hex_encode(key.verifying_key().to_bytes()))
}

pub fn sign_index(index: &Path, private_key: &Path) -> Result<PathBuf> {
    let key = read_signing_key(private_key)?;
    let mut repository = RepositoryIndex::from_toml(&fs::read_to_string(index)?)?;
    for package in &mut repository.packages {
        package.signature =
            crate::encoding::hex_encode(key.sign(package.sha256.as_bytes()).to_bytes());
    }
    let index_bytes = repository.to_toml()?.into_bytes();
    crate::atomic_file::write(index, &index_bytes, 0o644)?;
    let signature = key.sign(&index_bytes);
    let destination = PathBuf::from(format!("{}.sig", index.display()));
    crate::atomic_file::write(
        &destination,
        format!("{}\n", crate::encoding::hex_encode(signature.to_bytes())).as_bytes(),
        0o644,
    )?;
    Ok(destination)
}

fn read_signing_key(path: &Path) -> Result<SigningKey> {
    let encoded = fs::read_to_string(path)?;
    let bytes = crate::encoding::hex_decode(encoded.trim())
        .ok_or_else(|| ArcError::Usage("private key is not hexadecimal".into()))?;
    let secret: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ArcError::Usage("private key must contain exactly 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::verify_index;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn generated_keys_sign_indexes() {
        let workspace = tempfile::tempdir().unwrap();
        let key = workspace.path().join("repo.key");
        let index = workspace.path().join("index.toml");
        fs::write(&index, "format = 1\ngenerated = 1\n").unwrap();

        let public = generate_key(&key).unwrap();
        let signature = sign_index(&index, &key).unwrap();
        verify_index(
            &fs::read(index).unwrap(),
            &fs::read(signature).unwrap(),
            &public,
        )
        .unwrap();
        assert_eq!(
            fs::metadata(key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
