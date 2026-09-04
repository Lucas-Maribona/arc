//! The command-line application: parse arguments, dispatch commands, and
//! write user-facing output. Library modules contain the package-manager logic.

use std::cmp::Ordering;
use std::env;
use std::ffi::OsString;
use std::fmt::Display;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

mod ui;

use arc::bootstrap;
use arc::convert;
use arc::database::Database;
use arc::error::{ArcError, Result};
use arc::package;
use arc::publisher;
use arc::remote;
use arc::transaction::{self, InstallArchive};
use arc::version::Version;
use ui::{PlanRow, TerminalUi};

/// Writes command results to stdout in either human or JSON Lines form.
/// Keeping this value explicit makes it clear which output a command produces.
struct Output {
    json: bool,
}

impl Output {
    fn new(json: bool) -> Self {
        Self { json }
    }

    fn line(&self, message: impl Display) -> Result<()> {
        let message = message.to_string();
        let mut stdout = std::io::stdout().lock();
        if self.json {
            writeln!(stdout, "{}", json_record("output", None, &message))?;
        } else {
            writeln!(stdout, "{message}")?;
        }
        Ok(())
    }

    fn error(&self, error: &ArcError) {
        if self.json {
            eprintln!(
                "{}",
                json_record("error", Some(error.exit_code()), &error.to_string())
            );
        } else {
            TerminalUi::print_error(error);
        }
    }
}

/// Build the two JSON Lines records emitted by the CLI without a general JSON
/// dependency. The only dynamic field is a string, so escaping it here keeps
/// the format small and auditable.
fn json_record(kind: &str, code: Option<i32>, message: &str) -> String {
    let message = json_string(message);
    match code {
        Some(code) => format!(r#"{{"type":"{kind}","code":{code},"message":{message}}}"#),
        None => format!(r#"{{"type":"{kind}","message":{message}}}"#),
    }
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(output, "\\u{:04x}", character as u32).expect("write String");
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

const USAGE: &str = "usage:
  arc [--root <target>] [--yes] [--non-interactive] [--json] <command> [arguments]

  arc pack [--skip-runtime-audit] <package-root> [output.arc]
  arc audit <package-root>
  arc inspect <package.arc>
  arc convert-arch <package.pkg.tar.zst> [output.arc]
  arc version <first> <second>
  arc repo-index <repository-directory>
  arc repo-keygen <private-key-file>
  arc repo-sign <index.toml> <private-key-file>
  arc --root <target> sync
  arc --root <target> install <package>...
  arc --root <target> reinstall <package>...
  arc --root <target> downgrade <package=requirement>...
  arc --root <target> upgrade
  arc --root <target> install-file <package.arc>...
  arc bootstrap <target> <package.arc>...
  arc --root <target> list
  arc --root <target> remove [--recursive] <package>...
  arc --root <target> mark <explicit|dependency> <package>...
  arc --root <target> orphans
  arc --root <target> autoremove
  arc --root <target> verify [package]...
  arc --root <target> files <package>
  arc --root <target> owns <path>
  arc --root <target> info <package>...
  arc --root <target> bundled <component>
  arc --root <target> search <query>
  arc --root <target> group <group>
  arc --root <target> required-by <package>
  arc --root <target> cache <list|clean [--keep <count>]>
  arc --root <target> history
  arc --root <target> doctor [path]...

global options:
  --root <target>       operate on another filesystem root
  --yes, --noconfirm    answer yes to transaction prompts
  --non-interactive     never read confirmation input (requires --yes for changes)
  --json                emit stable JSON Lines records on standard output
  --help, -h            show this help
  --version, -V         show the Arc version";

struct Cli {
    root: PathBuf,
    assume_yes: bool,
    non_interactive: bool,
    json: bool,
    command: String,
    arguments: Vec<OsString>,
}

/// Options accepted by every command. Keeping them together makes argument
/// parsing and command dispatch use the same plain data.
struct GlobalOptions {
    root: PathBuf,
    root_seen: bool,
    assume_yes: bool,
    non_interactive: bool,
    json: bool,
}

impl Default for GlobalOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            root_seen: false,
            assume_yes: false,
            non_interactive: false,
            json: false,
        }
    }
}

fn main() {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let output = Output::new(arguments.iter().any(|argument| argument == "--json"));
    if let Err(error) = run(arguments) {
        output.error(&error);
        std::process::exit(error.exit_code());
    }
}

fn run(arguments: Vec<OsString>) -> Result<()> {
    let cli = parse_cli(arguments)?;
    let output = Output::new(cli.json);
    let mut ui = TerminalUi::new();
    match cli.command.as_str() {
        "pack" => pack(&cli.arguments, &ui, &output),
        "audit" => audit(&cli.arguments, &ui, &output),
        "inspect" => inspect(&cli.arguments, &ui, &output),
        "convert-arch" => convert_arch(&cli.arguments, &ui, &output),
        "version" => compare_versions(&cli.arguments, &output),
        "repo-index" => repo_index(&cli.arguments, &ui, &output),
        "repo-keygen" => repo_keygen(&cli.arguments, &ui, &output),
        "repo-sign" => repo_sign(&cli.arguments, &ui, &output),
        "sync" => sync(&cli.root, &cli.arguments, &mut ui),
        "install" => install(
            &cli.root,
            &cli.arguments,
            cli.assume_yes,
            cli.non_interactive,
            &mut ui,
        ),
        "reinstall" => reinstall(
            &cli.root,
            &cli.arguments,
            cli.assume_yes,
            cli.non_interactive,
            &mut ui,
        ),
        "downgrade" => install(
            &cli.root,
            &cli.arguments,
            cli.assume_yes,
            cli.non_interactive,
            &mut ui,
        ),
        "upgrade" => upgrade(
            &cli.root,
            &cli.arguments,
            cli.assume_yes,
            cli.non_interactive,
            &mut ui,
        ),
        "install-file" => install_files(
            &cli.root,
            &cli.arguments,
            cli.assume_yes,
            cli.non_interactive,
            &mut ui,
        ),
        "bootstrap" => {
            bootstrap_command(&cli.arguments, cli.assume_yes, cli.non_interactive, &mut ui)
        }
        "list" => list(&cli.root, &cli.arguments, &output),
        "mark" => mark(&cli.root, &cli.arguments),
        "orphans" => orphans(&cli.root, &cli.arguments, &output),
        "autoremove" => autoremove(
            &cli.root,
            &cli.arguments,
            cli.assume_yes,
            cli.non_interactive,
            &ui,
        ),
        "verify" => verify(&cli.root, &cli.arguments, &output),
        "files" => files(&cli.root, &cli.arguments, &output),
        "owns" => owns(&cli.root, &cli.arguments, &output),
        "info" => info(&cli.root, &cli.arguments, &output),
        "bundled" => bundled(&cli.root, &cli.arguments, &output),
        "search" => search(&cli.root, &cli.arguments, &output),
        "group" => group(&cli.root, &cli.arguments, &output),
        "required-by" => required_by(&cli.root, &cli.arguments, &output),
        "cache" => cache(&cli.root, &cli.arguments, &output),
        "history" => history(&cli.root, &cli.arguments, &output),
        "doctor" => doctor(&cli.root, &cli.arguments, &output),
        "remove" => remove(
            &cli.root,
            &cli.arguments,
            cli.assume_yes,
            cli.non_interactive,
            &ui,
        ),
        "help" | "--help" | "-h" => output.line(USAGE),
        "--version" | "-V" => output.line(format!("arc {}", env!("CARGO_PKG_VERSION"))),
        _ => Err(ArcError::Usage(format!(
            "unknown command {:?}\n{USAGE}",
            cli.command
        ))),
    }
}

fn parse_cli(arguments: Vec<OsString>) -> Result<Cli> {
    let mut options = GlobalOptions::default();
    let mut arguments = arguments.into_iter();

    // Global options are accepted before the command. Once we find the
    // command, the remaining values belong to that command.
    let command_argument = loop {
        let argument = arguments
            .next()
            .ok_or_else(|| ArcError::Usage(USAGE.into()))?;
        match argument.to_str() {
            Some("--root") => {
                if options.root_seen {
                    return Err(ArcError::Usage("--root may only be specified once".into()));
                }
                let value = arguments.next().ok_or_else(|| {
                    ArcError::Usage("--root requires a target path\n\n".to_owned() + USAGE)
                })?;
                options.root = PathBuf::from(value);
                options.root_seen = true;
            }
            Some("--yes" | "--noconfirm") => {
                options.assume_yes = true;
            }
            Some("--non-interactive" | "--noninteractive") => {
                options.non_interactive = true;
            }
            Some("--json") => {
                options.json = true;
            }
            Some("--help" | "-h" | "--version" | "-V") => break argument,
            Some(value) if value.starts_with('-') => {
                return Err(ArcError::Usage(format!(
                    "unknown global option {value:?}\n\n{USAGE}"
                )));
            }
            _ => break argument,
        }
    };
    let command = command_argument
        .to_str()
        .ok_or_else(|| ArcError::Usage("command is not valid UTF-8".into()))?
        .to_owned();
    let mut command_arguments = Vec::new();

    // These flags are also accepted after the command. Everything else stays
    // untouched, including command-specific options such as `--recursive`.
    for argument in arguments {
        match argument.to_str() {
            Some("--yes" | "--noconfirm") => {
                options.assume_yes = true;
            }
            Some("--non-interactive" | "--noninteractive") => {
                options.non_interactive = true;
            }
            Some("--json") => {
                options.json = true;
            }
            _ => command_arguments.push(argument),
        }
    }
    if options.root_seen && command == "bootstrap" {
        return Err(ArcError::Usage(
            "bootstrap takes its target as the first argument; do not combine it with --root"
                .into(),
        ));
    }
    Ok(Cli {
        root: options.root,
        assume_yes: options.assume_yes,
        non_interactive: options.non_interactive,
        json: options.json,
        command,
        arguments: command_arguments,
    })
}

fn install_files(
    root: &Path,
    arguments: &[OsString],
    assume_yes: bool,
    non_interactive: bool,
    ui: &mut TerminalUi,
) -> Result<()> {
    if arguments.is_empty() {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let archives = arguments
        .iter()
        .map(|path| InstallArchive {
            path: PathBuf::from(path),
            explicit: true,
        })
        .collect::<Vec<_>>();
    ui.phase("Inspecting local packages");
    let rows = local_package_rows(root, &archives)?;
    ui.plan("Local package transaction", &rows, 0);
    if !ui.confirm("Apply this transaction?", assume_yes, non_interactive)? {
        ui.cancelled();
        return Ok(());
    }
    ui.phase("Applying filesystem transaction");
    let summary = transaction::install(root, &archives)?;
    ui.success(&format!(
        "installed {} package(s); tracking {} path(s)",
        summary.packages.len(),
        summary.files
    ));
    Ok(())
}

fn convert_arch(arguments: &[OsString], ui: &TerminalUi, output: &Output) -> Result<()> {
    if !(1..=2).contains(&arguments.len()) {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let input = Path::new(&arguments[0]);
    let destination = arguments.get(1).map(Path::new);
    ui.phase("Converting Arch package");
    let archive = convert::arch_package(input, destination)?;
    ui.success(&format!("created {}", archive.display()));
    output.line(archive.display())
}

fn sync(root: &Path, arguments: &[OsString], ui: &mut TerminalUi) -> Result<()> {
    if !arguments.is_empty() {
        return Err(ArcError::Usage(USAGE.into()));
    }
    ui.phase("Synchronizing signed repository indexes");
    let packages = remote::sync_with_observer(root, ui)?;
    ui.success(&format!("synchronized {packages} package record(s)"));
    Ok(())
}

fn install(
    root: &Path,
    arguments: &[OsString],
    assume_yes: bool,
    non_interactive: bool,
    ui: &mut TerminalUi,
) -> Result<()> {
    if arguments.is_empty() {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let requests = utf8_arguments(arguments, "package request")?;
    ui.phase("Resolving dependencies");
    let plan = remote::plan_install(root, &requests)?;
    if plan.changes.is_empty() {
        ui.notice(&format!("already satisfied: {}", plan.selected.join(", ")));
        return Ok(());
    }
    ui.remote_plan("Repository transaction", &plan);
    if !ui.confirm("Apply this transaction?", assume_yes, non_interactive)? {
        ui.cancelled();
        return Ok(());
    }
    if plan.download_size() > 0 {
        ui.phase("Downloading and authenticating packages");
    } else {
        ui.phase("Verifying cached packages");
    }
    let prepared = remote::download_plan(root, plan, ui)?;
    ui.phase("Applying filesystem transaction");
    let summary = transaction::install(root, &prepared.archives)?;
    ui.success(&format!(
        "installed {} package(s); tracking {} path(s)",
        summary.packages.len(),
        summary.files
    ));
    Ok(())
}

fn upgrade(
    root: &Path,
    arguments: &[OsString],
    assume_yes: bool,
    non_interactive: bool,
    ui: &mut TerminalUi,
) -> Result<()> {
    if !arguments.is_empty() {
        return Err(ArcError::Usage(USAGE.into()));
    }
    ui.phase("Checking for upgrades");
    let Some(plan) = remote::plan_upgrade(root)? else {
        ui.notice("no packages are installed");
        return Ok(());
    };
    if plan.changes.is_empty() {
        ui.notice("all packages are current");
        return Ok(());
    }
    ui.remote_plan("System upgrade", &plan);
    if !ui.confirm("Apply this upgrade?", assume_yes, non_interactive)? {
        ui.cancelled();
        return Ok(());
    }
    if plan.download_size() > 0 {
        ui.phase("Downloading and authenticating packages");
    } else {
        ui.phase("Verifying cached packages");
    }
    let prepared = remote::download_plan(root, plan, ui)?;
    ui.phase("Applying filesystem transaction");
    let summary = transaction::install(root, &prepared.archives)?;
    ui.success(&format!("upgraded {} package(s)", summary.packages.len()));
    Ok(())
}

fn reinstall(
    root: &Path,
    arguments: &[OsString],
    assume_yes: bool,
    non_interactive: bool,
    ui: &mut TerminalUi,
) -> Result<()> {
    let requests = utf8_arguments(arguments, "package request")?;
    let plan = remote::plan_reinstall(root, &requests)?;
    ui.remote_plan("Reinstall transaction", &plan);
    if !ui.confirm("Apply this transaction?", assume_yes, non_interactive)? {
        ui.cancelled();
        return Ok(());
    }
    ui.phase("Downloading and authenticating packages");
    let prepared = remote::download_plan(root, plan, ui)?;
    ui.phase("Applying filesystem transaction");
    let summary = transaction::install(root, &prepared.archives)?;
    ui.success(&format!(
        "reinstalled {} package(s)",
        summary.packages.len()
    ));
    Ok(())
}

fn repo_index(arguments: &[OsString], ui: &TerminalUi, output: &Output) -> Result<()> {
    if arguments.len() != 1 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    ui.phase("Inspecting repository packages");
    let index = publisher::build_index(Path::new(&arguments[0]))?;
    ui.success(&format!("generated {}", index.display()));
    output.line(index.display())
}

fn repo_keygen(arguments: &[OsString], ui: &TerminalUi, output: &Output) -> Result<()> {
    if arguments.len() != 1 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let path = Path::new(&arguments[0]);
    ui.phase("Generating Ed25519 repository key");
    let public = publisher::generate_key(path)?;
    ui.success("repository signing key created");
    output.line(format!("private key: {}", path.display()))?;
    output.line(format!("public key:  {public}"))
}

fn repo_sign(arguments: &[OsString], ui: &TerminalUi, output: &Output) -> Result<()> {
    if arguments.len() != 2 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    ui.phase("Signing repository index");
    let signature = publisher::sign_index(Path::new(&arguments[0]), Path::new(&arguments[1]))?;
    ui.success(&format!("created {}", signature.display()));
    output.line(signature.display())
}

fn bootstrap_command(
    arguments: &[OsString],
    assume_yes: bool,
    non_interactive: bool,
    ui: &mut TerminalUi,
) -> Result<()> {
    if arguments.len() < 2 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let root = PathBuf::from(&arguments[0]);
    if !root.is_absolute() {
        return Err(ArcError::Usage(
            "bootstrap target must be an absolute path".into(),
        ));
    }
    ensure_empty_bootstrap_target(&root)?;
    let archives = arguments[1..]
        .iter()
        .map(|path| InstallArchive {
            path: PathBuf::from(path),
            explicit: true,
        })
        .collect::<Vec<_>>();
    ui.phase("Validating and ordering bootstrap packages");
    let archives = bootstrap::order(&archives)?;
    let rows = local_package_rows_uninstalled(&archives)?;
    ui.plan("Bootstrap transaction", &rows, 0);
    if !ui.confirm("Create this system root?", assume_yes, non_interactive)? {
        ui.cancelled();
        return Ok(());
    }
    // Recheck after prompting so another process cannot quietly populate the
    // target between the plan and the transaction.
    ensure_empty_bootstrap_target(&root)?;
    fs::create_dir_all(&root)?;
    ui.phase("Applying bootstrap transaction");
    let summary = transaction::install(&root, &archives)?;
    ui.success(&format!(
        "bootstrapped {} package(s); tracking {} path(s)",
        summary.packages.len(),
        summary.files
    ));
    Ok(())
}

fn list(root: &Path, arguments: &[OsString], output: &Output) -> Result<()> {
    if !arguments.is_empty() {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let packages = Database::new(root)?.load_all()?;
    if packages.is_empty() {
        return output.line("No packages installed.");
    }
    output.line(format!(
        "{:<24} {:<16} {:<10} Reason",
        "Package", "Version", "Arch"
    ))?;
    for package in packages {
        output.line(format!(
            "{:<24} {:<16} {:<10} {}",
            package.package.name,
            package.package.version,
            package.package.arch,
            if package.explicit {
                "explicit"
            } else {
                "dependency"
            }
        ))?;
    }
    Ok(())
}

fn remove(
    root: &Path,
    arguments: &[OsString],
    assume_yes: bool,
    non_interactive: bool,
    ui: &TerminalUi,
) -> Result<()> {
    let recursive = arguments
        .first()
        .is_some_and(|value| value == "--recursive" || value == "-r");
    let arguments = if recursive {
        &arguments[1..]
    } else {
        arguments
    };
    if arguments.is_empty() {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let names = arguments
        .iter()
        .map(|name| {
            name.to_str()
                .map(str::to_owned)
                .ok_or_else(|| ArcError::Usage("package name is not valid UTF-8".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    let names = if recursive {
        transaction::recursive_removal(root, &names)?
    } else {
        names
    };
    let rows = removal_rows(root, &names)?;
    ui.plan("Removal transaction", &rows, 0);
    if !ui.confirm("Remove these packages?", assume_yes, non_interactive)? {
        ui.cancelled();
        return Ok(());
    }
    ui.phase("Applying removal transaction");
    let summary = transaction::remove(root, &names)?;
    ui.success(&format!("removed {} package(s)", summary.packages.len()));
    for path in summary.preserved {
        ui.warning(&format!("preserved modified configuration as /{path}"));
    }
    Ok(())
}

fn mark(root: &Path, arguments: &[OsString]) -> Result<()> {
    if arguments.len() < 2 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let explicit = match arguments[0].to_str() {
        Some("explicit") => true,
        Some("dependency") => false,
        _ => {
            return Err(ArcError::Usage(
                "mark expects explicit or dependency".into(),
            ));
        }
    };
    let names = utf8_arguments(&arguments[1..], "package name")?;
    Database::new(root)?.set_explicit(&names, explicit)?;
    Ok(())
}

fn orphans(root: &Path, arguments: &[OsString], output: &Output) -> Result<()> {
    if !arguments.is_empty() {
        return Err(ArcError::Usage(USAGE.into()));
    }
    for package in transaction::orphans(root)? {
        output.line(format!(
            "{} {}",
            package.package.name, package.package.version
        ))?;
    }
    Ok(())
}

fn autoremove(
    root: &Path,
    arguments: &[OsString],
    assume_yes: bool,
    non_interactive: bool,
    ui: &TerminalUi,
) -> Result<()> {
    if !arguments.is_empty() {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let names = transaction::orphans(root)?
        .into_iter()
        .map(|package| package.package.name)
        .collect::<Vec<_>>();
    if names.is_empty() {
        ui.notice("no orphan packages to remove");
        return Ok(());
    }
    let rows = removal_rows(root, &names)?;
    ui.plan("Orphan removal transaction", &rows, 0);
    if !ui.confirm("Remove these orphan packages?", assume_yes, non_interactive)? {
        ui.cancelled();
        return Ok(());
    }
    ui.phase("Applying orphan removal transaction");
    let summary = transaction::remove(root, &names)?;
    ui.success(&format!(
        "removed {} orphan package(s)",
        summary.packages.len()
    ));
    Ok(())
}

fn verify(root: &Path, arguments: &[OsString], output: &Output) -> Result<()> {
    let names = utf8_arguments(arguments, "package name")?;
    let problems = Database::new(root)?.verify(&names)?;
    if problems.is_empty() {
        output.line("all installed files match their recorded state")?;
        Ok(())
    } else {
        for problem in problems {
            output.line(problem)?;
        }
        Err(ArcError::Transaction(
            "installed-file verification failed".into(),
        ))
    }
}

fn files(root: &Path, arguments: &[OsString], output: &Output) -> Result<()> {
    if arguments.len() != 1 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let name = arguments[0]
        .to_str()
        .ok_or_else(|| ArcError::Usage("package name is not valid UTF-8".into()))?;
    if root.join("etc/arc/repos.toml").exists() {
        let packages = remote::catalog_info(root, name)?;
        if !packages.is_empty() {
            for package in packages {
                for file in package.files {
                    output.line(format!("/{file}"))?;
                }
            }
            return Ok(());
        }
    }
    let package = Database::new(root)?.load(name)?.ok_or_else(|| {
        ArcError::Usage(format!(
            "package {name} is not installed or in a synchronized repository"
        ))
    })?;
    for file in package.files {
        output.line(format!("/{}", file.path))?;
    }
    Ok(())
}

fn owns(root: &Path, arguments: &[OsString], output: &Output) -> Result<()> {
    if arguments.len() != 1 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let path = Path::new(&arguments[0])
        .strip_prefix("/")
        .unwrap_or(Path::new(&arguments[0]))
        .to_string_lossy()
        .into_owned();
    match Database::new(root)?.ownership()?.get(&path) {
        Some(owner) => output.line(owner),
        None => Err(ArcError::Usage(format!(
            "no installed package owns /{path}"
        ))),
    }
}

fn info(root: &Path, arguments: &[OsString], output: &Output) -> Result<()> {
    if arguments.is_empty() {
        return Err(ArcError::Usage(USAGE.into()));
    }
    for name in utf8_arguments(arguments, "package name")? {
        let repository_packages = if root.join("etc/arc/repos.toml").exists() {
            remote::catalog_info(root, &name)?
        } else {
            Vec::new()
        };
        if repository_packages.is_empty() {
            let package = Database::new(root)?.load(&name)?.ok_or_else(|| {
                ArcError::Usage(format!(
                    "package {name} is not installed or in a synchronized repository"
                ))
            })?;
            output.line(package.package.to_toml()?)?;
            output.line(format!(
                "reason = {:?}",
                if package.explicit {
                    "explicit"
                } else {
                    "dependency"
                }
            ))?;
        } else {
            for package in repository_packages {
                output.line(package.metadata.to_toml()?)?;
                output.line(format!("repository = {:?}", package.source))?;
                output.line(format!("download_size = {}", package.size))?;
            }
        }
    }
    Ok(())
}

fn bundled(root: &Path, arguments: &[OsString], output: &Output) -> Result<()> {
    if arguments.len() != 1 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let component = arguments[0]
        .to_str()
        .ok_or_else(|| ArcError::Usage("component name is not valid UTF-8".into()))?;
    let metadata = if root.join("etc/arc/repos.toml").exists() {
        remote::catalog_bundled(root, component)?
            .into_iter()
            .map(|package| package.metadata)
            .collect::<Vec<arc::metadata::Metadata>>()
    } else {
        Database::new(root)?
            .load_all()?
            .into_iter()
            .map(|record| record.package)
            .collect::<Vec<arc::metadata::Metadata>>()
    };
    let mut found = false;
    for package in metadata {
        for bundled in package.bundled.iter().filter(|item| item.name == component) {
            output.line(format!(
                "{} {}    {} {}",
                package.name, package.version, bundled.name, bundled.version
            ))?;
            found = true;
        }
    }
    if found {
        Ok(())
    } else {
        Err(ArcError::Usage(format!(
            "no installed or synchronized package bundles {component}"
        )))
    }
}

fn search(root: &Path, arguments: &[OsString], output: &Output) -> Result<()> {
    if arguments.len() != 1 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let needle = arguments[0]
        .to_str()
        .ok_or_else(|| ArcError::Usage("search query is not valid UTF-8".into()))?
        .to_ascii_lowercase();
    if root.join("etc/arc/repos.toml").exists() {
        for package in remote::search_catalog(root, &needle)? {
            output.line(format!(
                "{}/{} {} - {}",
                package.source,
                package.metadata.name,
                package.metadata.version,
                package.metadata.description
            ))?;
        }
    } else {
        for package in Database::new(root)?.load_all()? {
            if package.package.name.to_ascii_lowercase().contains(&needle)
                || package
                    .package
                    .description
                    .to_ascii_lowercase()
                    .contains(&needle)
            {
                output.line(format!(
                    "{} {} - {}",
                    package.package.name, package.package.version, package.package.description
                ))?;
            }
        }
    }
    Ok(())
}

fn group(root: &Path, arguments: &[OsString], output: &Output) -> Result<()> {
    if arguments.len() != 1 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let name = arguments[0]
        .to_str()
        .ok_or_else(|| ArcError::Usage("group name is not valid UTF-8".into()))?;
    if root.join("etc/arc/repos.toml").exists() {
        for package in remote::catalog_group(root, name)? {
            output.line(format!(
                "{}/{} {}",
                package.source, package.metadata.name, package.metadata.version
            ))?;
        }
    } else {
        for package in Database::new(root)?.load_all()? {
            if package
                .package
                .package_groups
                .iter()
                .any(|group| group == name)
            {
                output.line(format!(
                    "{} {}",
                    package.package.name, package.package.version
                ))?;
            }
        }
    }
    Ok(())
}

fn required_by(root: &Path, arguments: &[OsString], output: &Output) -> Result<()> {
    if arguments.len() != 1 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let name = arguments[0]
        .to_str()
        .ok_or_else(|| ArcError::Usage("package name is not valid UTF-8".into()))?;
    if root.join("etc/arc/repos.toml").exists() {
        for package in remote::catalog_required_by(root, name)? {
            output.line(format!(
                "{}/{} {}",
                package.source, package.metadata.name, package.metadata.version
            ))?;
        }
    } else {
        for package in Database::new(root)?.required_by(name)? {
            output.line(format!(
                "{} {}",
                package.package.name, package.package.version
            ))?;
        }
    }
    Ok(())
}

fn cache(root: &Path, arguments: &[OsString], output: &Output) -> Result<()> {
    match arguments.first().and_then(|value| value.to_str()) {
        Some("list") if arguments.len() == 1 => {
            for (name, size) in remote::cache_entries(root)? {
                output.line(format!("{name} {size}"))?;
            }
            Ok(())
        }
        Some("clean") if arguments.len() == 1 => output.line(format!(
            "removed {} cached archive(s)",
            remote::clean_cache(root)?
        )),
        Some("clean") if arguments.len() == 3 && arguments[1] == "--keep" => {
            let keep = arguments[2]
                .to_str()
                .ok_or_else(|| ArcError::Usage("cache retention count is not valid UTF-8".into()))?
                .parse::<usize>()
                .map_err(|_| {
                    ArcError::Usage("cache retention count must be a non-negative integer".into())
                })?;
            output.line(format!(
                "removed {} cached archive(s)",
                remote::prune_cache(root, keep)?
            ))
        }
        _ => Err(ArcError::Usage(
            "cache expects list or clean [--keep <count>]".into(),
        )),
    }
}

fn history(root: &Path, arguments: &[OsString], output: &Output) -> Result<()> {
    if !arguments.is_empty() {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let directory = root.join("var/lib/arc/history");
    if !directory.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if entry.file_type()?.is_file() {
            output.line(fs::read_to_string(entry.path())?)?;
        }
    }
    Ok(())
}

fn doctor(root: &Path, arguments: &[OsString], output: &Output) -> Result<()> {
    let selected = arguments.iter().map(PathBuf::from).collect::<Vec<_>>();
    let database = Database::new(root)?;
    let report = database.doctor()?;
    let mut problems = report.problems;
    problems.extend(database.unowned_paths(&selected)?);
    for (path, bytes) in remote::partial_downloads(root)? {
        problems.push(format!(
            "incomplete cached download {path} ({bytes} bytes); it will resume"
        ));
    }
    problems.extend(remote::cache_problems(root)?);
    output.line(format!(
        "checked {} package(s) and {} recorded path(s)",
        report.packages, report.files
    ))?;
    if problems.is_empty() {
        output.line("system state is healthy")?;
        Ok(())
    } else {
        for problem in problems {
            output.line(format!("warning: {problem}"))?;
        }
        Err(ArcError::InvalidState("doctor found problems".into()))
    }
}

fn utf8_arguments(arguments: &[OsString], kind: &str) -> Result<Vec<String>> {
    arguments
        .iter()
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| ArcError::Usage(format!("{kind} is not valid UTF-8")))
        })
        .collect()
}

fn pack(arguments: &[OsString], ui: &TerminalUi, output: &Output) -> Result<()> {
    let (skip_runtime_audit, arguments) = match arguments.first().and_then(|value| value.to_str()) {
        Some("--skip-runtime-audit") => (true, &arguments[1..]),
        _ => (false, arguments),
    };
    if !(1..=2).contains(&arguments.len()) {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let source = PathBuf::from(&arguments[0]);
    let destination = arguments.get(1).map(PathBuf::from);
    ui.phase("Validating and packing payload");
    let package = package::pack_with_options(&source, destination.as_deref(), skip_runtime_audit)?;
    ui.success(&format!("created {}", package.display()));
    output.line(package.display())
}

fn audit(arguments: &[OsString], ui: &TerminalUi, output: &Output) -> Result<()> {
    if arguments.len() != 1 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let root = PathBuf::from(&arguments[0]);
    let metadata_path = root.join(".arc/meta.toml");
    let metadata = if metadata_path.is_file() {
        Some(arc::metadata::Metadata::from_toml(&fs::read_to_string(
            metadata_path,
        )?)?)
    } else {
        None
    };
    ui.phase("Auditing package runtime without executing payload files");
    let report = arc::runtime_audit::audit_root(&root, metadata.as_ref())?;
    output.line(arc::runtime_audit::format_report(
        metadata.as_ref(),
        &report,
    ))?;
    if report.passed() {
        ui.success("runtime audit passed");
        Ok(())
    } else {
        Err(ArcError::InvalidState("runtime audit failed".into()))
    }
}

fn inspect(arguments: &[OsString], ui: &TerminalUi, output: &Output) -> Result<()> {
    if arguments.len() != 1 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    ui.phase("Validating package archive");
    let inspection = package::inspect(&PathBuf::from(&arguments[0]))?;
    ui.success("package is valid");
    output.line(inspection.metadata.to_toml()?)?;
    output.line(format!(
        "Self-contained: {}",
        if inspection.metadata.self_contained {
            "yes"
        } else {
            "no"
        }
    ))?;
    let runtime_dir = format!("usr/lib/arc/{}", inspection.metadata.name);
    if inspection.members.iter().any(|member| {
        member.path == runtime_dir || member.path.starts_with(&(runtime_dir.clone() + "/"))
    }) {
        output.line(format!("Private runtime: /{runtime_dir}"))?;
    }
    output.line(format!("sha256 = {:?}", inspection.sha256))?;
    output.line(format!("members = {}", inspection.members.len()))?;
    output.line(format!("payload_size = {}", inspection.payload_size))
}

fn compare_versions(arguments: &[OsString], output: &Output) -> Result<()> {
    if arguments.len() != 2 {
        return Err(ArcError::Usage(USAGE.into()));
    }
    let parse = |value: &OsString| {
        value
            .to_str()
            .ok_or_else(|| ArcError::Usage("version is not valid UTF-8".into()))
            .and_then(Version::parse)
    };
    let result = match parse(&arguments[0])?.cmp(&parse(&arguments[1])?) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    };
    output.line(result)
}

fn local_package_rows(root: &Path, archives: &[InstallArchive]) -> Result<Vec<PlanRow>> {
    let installed = Database::new(root)?
        .load_all()?
        .into_iter()
        .map(|package| (package.package.name, package.package.version))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut seen = std::collections::BTreeSet::new();
    archives
        .iter()
        .map(|archive| {
            let inspection = package::inspect(&archive.path)?;
            if !seen.insert(inspection.metadata.name.clone()) {
                return Err(ArcError::Usage(format!(
                    "local transaction contains package {} more than once",
                    inspection.metadata.name
                )));
            }
            let (action, version) = installed.get(&inspection.metadata.name).map_or_else(
                || ("install".into(), inspection.metadata.version.clone()),
                |old| {
                    (
                        "upgrade".into(),
                        format!("{old} -> {}", inspection.metadata.version),
                    )
                },
            );
            Ok(PlanRow {
                action,
                name: inspection.metadata.name,
                version,
                architecture: inspection.metadata.arch,
                source: "local".into(),
                reason: "explicit".into(),
                size: fs::metadata(&archive.path)?.len(),
            })
        })
        .collect()
}

fn local_package_rows_uninstalled(archives: &[InstallArchive]) -> Result<Vec<PlanRow>> {
    archives
        .iter()
        .map(|archive| {
            let inspection = package::inspect(&archive.path)?;
            Ok(PlanRow {
                action: "install".into(),
                name: inspection.metadata.name,
                version: inspection.metadata.version,
                architecture: inspection.metadata.arch,
                source: "local".into(),
                reason: "explicit".into(),
                size: fs::metadata(&archive.path)?.len(),
            })
        })
        .collect()
}

fn removal_rows(root: &Path, names: &[String]) -> Result<Vec<PlanRow>> {
    let packages = transaction::plan_removal(root, names)?;
    Ok(packages
        .into_iter()
        .map(|installed| {
            let package = &installed.package;
            PlanRow {
                action: "remove".into(),
                name: package.name.clone(),
                version: package.version.clone(),
                architecture: package.arch.clone(),
                source: "installed".into(),
                reason: "-".into(),
                size: 0,
            }
        })
        .collect())
}

fn ensure_empty_bootstrap_target(root: &Path) -> Result<()> {
    match fs::metadata(root) {
        Ok(metadata) if !metadata.is_dir() => Err(ArcError::Usage(format!(
            "bootstrap target {} exists but is not a directory",
            root.display()
        ))),
        Ok(_) if fs::read_dir(root)?.next().is_some() => Err(ArcError::Usage(format!(
            "bootstrap target {} is not empty",
            root.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_options_can_be_combined() {
        let cli = parse_cli(vec![
            "--yes".into(),
            "--root".into(),
            "/tmp/root".into(),
            "install".into(),
            "hello".into(),
        ])
        .unwrap();
        assert!(cli.assume_yes);
        assert_eq!(cli.root, Path::new("/tmp/root"));
        assert_eq!(cli.command, "install");
        assert_eq!(cli.arguments, [OsString::from("hello")]);
    }

    #[test]
    fn bootstrap_rejects_nonempty_targets() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(workspace.path().join("existing"), "data").unwrap();
        assert!(ensure_empty_bootstrap_target(workspace.path()).is_err());
    }

    #[test]
    fn help_and_version_are_commands_not_unknown_options() {
        assert_eq!(parse_cli(vec!["--help".into()]).unwrap().command, "--help");
        assert_eq!(parse_cli(vec!["-V".into()]).unwrap().command, "-V");
    }

    #[test]
    fn output_and_noninteractive_flags_work_after_the_command() {
        let cli = parse_cli(vec![
            "install".into(),
            "hello".into(),
            "--noconfirm".into(),
            "--non-interactive".into(),
            "--json".into(),
        ])
        .unwrap();
        assert!(cli.assume_yes);
        assert!(cli.non_interactive);
        assert_eq!(cli.arguments, [OsString::from("hello")]);
        assert!(cli.json);
    }

    #[test]
    fn json_output_escapes_strings_without_a_json_dependency() {
        assert_eq!(
            json_record(
                "output",
                None,
                "quote: \"; slash: \\; newline: \n; control: \u{001f}"
            ),
            r#"{"type":"output","message":"quote: \"; slash: \\; newline: \n; control: \u001f"}"#
        );
    }
}
