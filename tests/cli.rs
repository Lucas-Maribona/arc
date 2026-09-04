use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;

fn arc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_arc"))
}

/// Create the smallest valid package tree used by a CLI test.
fn package_root(
    workspace: &Path,
    directory: &str,
    name: &str,
    version: &str,
    architecture: &str,
    payload_path: &str,
    contents: &str,
) -> PathBuf {
    let root = workspace.join(directory);
    let payload = root.join(payload_path);
    fs::create_dir_all(root.join(".arc")).unwrap();
    fs::create_dir_all(payload.parent().unwrap()).unwrap();
    fs::write(
        root.join(".arc/meta.toml"),
        format!("format = 1\nname = {name:?}\nversion = {version:?}\narch = {architecture:?}\n"),
    )
    .unwrap();
    fs::write(payload, contents).unwrap();
    root
}

#[test]
fn local_package_lifecycle_works_through_the_cli() {
    let workspace = tempfile::tempdir().unwrap();
    let package_root = package_root(
        workspace.path(),
        "hello-root",
        "hello",
        "1",
        "x86_64",
        "usr/bin/hello",
        "hello\n",
    );
    let package = workspace.path().join("hello.arc");
    let target = workspace.path().join("target");
    fs::create_dir(&target).unwrap();

    assert!(
        arc()
            .args([
                "pack",
                package_root.to_str().unwrap(),
                package.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        arc()
            .args([
                "--root",
                target.to_str().unwrap(),
                "--yes",
                "install-file",
                package.to_str().unwrap(),
            ])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::read_to_string(target.join("usr/bin/hello")).unwrap(),
        "hello\n"
    );

    let list = arc()
        .args(["--root", target.to_str().unwrap(), "list"])
        .output()
        .unwrap();
    assert!(list.status.success());
    let list = String::from_utf8(list.stdout).unwrap();
    assert!(list.contains("hello"));
    assert!(list.contains("x86_64"));
    assert!(list.contains("explicit"));

    assert!(
        arc()
            .args([
                "--root",
                target.to_str().unwrap(),
                "--yes",
                "remove",
                "hello",
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(!target.join("usr/bin/hello").exists());
}

#[test]
fn repository_publishing_commands_create_a_verifiable_index() {
    let workspace = tempfile::tempdir().unwrap();
    let package_root = package_root(
        workspace.path(),
        "hello-root",
        "hello",
        "1",
        "any",
        "usr/share/hello/message",
        "hello\n",
    );
    let repository = workspace.path().join("repo");
    let packages = repository.join("packages");
    fs::create_dir_all(&packages).unwrap();
    let package = packages.join("hello.arc");
    assert!(
        arc()
            .args([
                "pack",
                package_root.to_str().unwrap(),
                package.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );

    let key = workspace.path().join("repo.sec");
    let keygen = arc()
        .args(["repo-keygen", key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(keygen.status.success());
    let public = String::from_utf8(keygen.stdout)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("public key:  "))
        .unwrap()
        .to_owned();
    assert!(
        arc()
            .args(["repo-index", repository.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    let index = repository.join("index.toml");
    assert!(
        arc()
            .args(["repo-sign", index.to_str().unwrap(), key.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    arc::remote::verify_index(
        &fs::read(&index).unwrap(),
        &fs::read(repository.join("index.toml.sig")).unwrap(),
        &public,
    )
    .unwrap();
}

#[test]
fn declining_confirmation_leaves_the_target_untouched() {
    let workspace = tempfile::tempdir().unwrap();
    let package_root = package_root(
        workspace.path(),
        "decline-root",
        "decline",
        "1",
        "any",
        "usr/share/decline",
        "untouched\n",
    );
    let package = workspace.path().join("decline.arc");
    let target = workspace.path().join("target");
    fs::create_dir(&target).unwrap();
    arc::package::pack(&package_root, Some(&package)).unwrap();

    let mut child = arc()
        .args([
            "--root",
            target.to_str().unwrap(),
            "install-file",
            package.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"no\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(!target.join("usr/share/decline").exists());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("cancelled; no changes were made")
    );

    let unattended = arc()
        .args([
            "--root",
            target.to_str().unwrap(),
            "install-file",
            package.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!unattended.status.success());
    assert!(
        String::from_utf8(unattended.stderr)
            .unwrap()
            .contains("rerun with --yes")
    );
    assert!(!target.join("usr/share/decline").exists());

    let noninteractive = arc()
        .args([
            "--root",
            target.to_str().unwrap(),
            "--non-interactive",
            "install-file",
            package.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(noninteractive.status.code(), Some(2));
    assert!(
        String::from_utf8(noninteractive.stderr)
            .unwrap()
            .contains("requires confirmation")
    );
    assert!(!target.join("usr/share/decline").exists());
}

#[test]
fn disposable_root_upgrades_a_package_release_to_release() {
    let workspace = tempfile::tempdir().unwrap();
    let target = workspace.path().join("target");
    fs::create_dir(&target).unwrap();
    let first = workspace.path().join("hello-1.arc");
    let second = workspace.path().join("hello-2.arc");

    for (directory, version, message, archive) in [
        ("first-root", "1", "first release\n", &first),
        ("second-root", "2", "second release\n", &second),
    ] {
        let root = package_root(
            workspace.path(),
            directory,
            "hello",
            version,
            "any",
            "usr/share/hello/message",
            message,
        );
        assert!(arc::package::pack(&root, Some(archive)).is_ok());
    }

    for archive in [&first, &second] {
        assert!(
            arc()
                .args([
                    "--root",
                    target.to_str().unwrap(),
                    "--yes",
                    "--non-interactive",
                    "install-file",
                    archive.to_str().unwrap(),
                ])
                .status()
                .unwrap()
                .success()
        );
    }
    assert_eq!(
        fs::read_to_string(target.join("usr/share/hello/message")).unwrap(),
        "second release\n"
    );
    let list = arc()
        .args(["--root", target.to_str().unwrap(), "list"])
        .output()
        .unwrap();
    assert!(String::from_utf8(list.stdout).unwrap().contains("2"));
}

#[test]
fn json_output_and_noninteractive_exit_codes_are_scriptable() {
    let version = arc()
        .args(["--json", "version", "1", "2"])
        .output()
        .unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap(),
        "{\"type\":\"output\",\"message\":\"-1\"}\n"
    );

    let usage = arc().args(["--json", "version", "1"]).output().unwrap();
    assert_eq!(usage.status.code(), Some(2));
    let error = String::from_utf8(usage.stderr).unwrap();
    assert!(error.starts_with("{\"type\":\"error\",\"code\":2,\"message\":"));
}
