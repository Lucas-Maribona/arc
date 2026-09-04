//! Terminal-only status, progress, and confirmation handling.

use std::env;
use std::io::{self, BufRead, IsTerminal, Write};
use std::time::{Duration, Instant};

use arc::error::{ArcError, Result};
use arc::remote::{ChangeKind, DownloadObserver, InstallPlan, SyncObserver};

const DRAW_INTERVAL: Duration = Duration::from_millis(50);

pub struct PlanRow {
    pub action: String,
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub source: String,
    pub reason: String,
    pub size: u64,
}

struct ActiveDownload {
    name: String,
    size: u64,
    started: Instant,
    last_draw: Instant,
}

pub struct TerminalUi {
    interactive: bool,
    color: bool,
    active: Option<ActiveDownload>,
}

impl TerminalUi {
    pub fn new() -> Self {
        let interactive = io::stderr().is_terminal();
        let color = interactive && env::var_os("NO_COLOR").is_none();
        Self {
            interactive,
            color,
            active: None,
        }
    }

    pub fn phase(&self, message: &str) {
        eprintln!("{} {message}", self.paint("[arc]", "1;36"));
    }

    pub fn success(&self, message: &str) {
        eprintln!("{} {message}", self.paint("[done]", "1;32"));
    }

    pub fn notice(&self, message: &str) {
        eprintln!("{} {message}", self.paint("[info]", "1;34"));
    }

    pub fn warning(&self, message: &str) {
        eprintln!("{} {message}", self.paint("[warn]", "1;33"));
    }

    pub fn plan(&self, title: &str, rows: &[PlanRow], download_size: u64) {
        eprintln!();
        eprintln!("{}", self.paint(title, "1"));
        eprintln!(
            "  {:<8} {:<18} {:<14} {:<8} {:<12} Reason",
            "Action", "Package", "Version", "Arch", "Source"
        );
        for row in rows {
            eprintln!(
                "  {:<8} {:<18} {:<14} {:<8} {:<12} {}",
                truncate(&row.action, 8),
                truncate(&row.name, 18),
                truncate(&row.version, 14),
                truncate(&row.architecture, 8),
                truncate(&row.source, 12),
                row.reason,
            );
        }
        let package_size = rows
            .iter()
            .map(|row| row.size)
            .fold(0_u64, u64::saturating_add);
        eprintln!();
        eprintln!("  Changes:        {}", rows.len());
        if package_size > 0 {
            eprintln!("  Archive data:   {}", format_bytes(package_size));
        }
        if download_size > 0 {
            eprintln!("  To download:    {}", format_bytes(download_size));
        } else if rows
            .iter()
            .any(|row| row.source != "local" && row.source != "installed")
        {
            eprintln!("  To download:    0 B (cached)");
        }
        eprintln!();
    }

    pub fn remote_plan(&self, title: &str, plan: &InstallPlan) {
        let mut rows = Vec::new();
        for change in &plan.changes {
            rows.extend(change.replaces.iter().map(|replaced| PlanRow {
                action: "replace".into(),
                name: replaced.name.clone(),
                version: replaced.version.clone(),
                architecture: replaced.architecture.clone(),
                source: "installed".into(),
                reason: format!("by {}", change.name),
                size: 0,
            }));
            rows.push(PlanRow {
                action: match &change.kind {
                    ChangeKind::Install => "install".into(),
                    ChangeKind::Upgrade { .. } => "upgrade".into(),
                },
                name: change.name.clone(),
                version: match &change.kind {
                    ChangeKind::Install => change.version.clone(),
                    ChangeKind::Upgrade { from } => format!("{from} -> {}", change.version),
                },
                architecture: change.architecture.clone(),
                source: if change.cached {
                    format!("{} (cached)", change.repository)
                } else {
                    change.repository.clone()
                },
                reason: if change.explicit {
                    "explicit".into()
                } else {
                    "dependency".into()
                },
                size: change.download_size,
            });
        }
        self.plan(title, &rows, plan.download_size());
    }

    pub fn confirm(&self, question: &str, assume_yes: bool, non_interactive: bool) -> Result<bool> {
        if assume_yes {
            self.notice(&format!("{question}: yes (--yes)"));
            return Ok(true);
        }
        if non_interactive {
            return Err(ArcError::Usage(format!(
                "{question} requires confirmation; rerun with --yes or omit --non-interactive"
            )));
        }
        let stdin = io::stdin();
        let interactive_input = stdin.is_terminal();
        let mut input = stdin.lock();
        loop {
            eprint!("{} {question} [Y/n] ", self.paint("[confirm]", "1;35"));
            io::stderr().flush()?;
            let mut answer = String::new();
            if input.read_line(&mut answer)? == 0 {
                if interactive_input {
                    eprintln!();
                    return Ok(false);
                }
                return Err(ArcError::Usage(format!(
                    "confirmation input ended before an answer; rerun with --yes: {question}"
                )));
            }
            if !interactive_input {
                eprintln!();
            }
            match answer.trim().to_ascii_lowercase().as_str() {
                "" | "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => self.warning("please answer yes or no"),
            }
        }
    }

    pub fn cancelled(&self) {
        self.notice("cancelled; no changes were made");
    }

    pub fn print_error(error: &ArcError) {
        let ui = Self::new();
        eprintln!("{} {error}", ui.paint("error:", "1;31"));
        if let Some(hint) = error_hint(error) {
            eprintln!("{} {hint}", ui.paint("hint:", "1;33"));
        }
    }

    fn paint(&self, value: &str, style: &str) -> String {
        if self.color {
            format!("\x1b[{style}m{value}\x1b[0m")
        } else {
            value.to_owned()
        }
    }

    fn draw_download(&self, received: u64) {
        let Some(active) = &self.active else {
            return;
        };
        let total = active.size.max(1);
        let received = received.min(active.size);
        let percent = received.saturating_mul(100) / total;
        let width = terminal_bar_width();
        let filled = (received.saturating_mul(width as u64) / total) as usize;
        let mut bar = String::with_capacity(width);
        bar.push_str(&"=".repeat(filled));
        if filled < width {
            bar.push('>');
            bar.push_str(&".".repeat(width - filled - 1));
        }
        let elapsed = active.started.elapsed().as_secs_f64().max(0.001);
        let rate = format_bytes((received as f64 / elapsed) as u64);
        eprint!(
            "\r\x1b[2K  {:<20} [{}] {:>3}% {:>9}/{:<9} {rate}/s",
            truncate(&active.name, 20),
            bar,
            percent,
            format_bytes(received),
            format_bytes(active.size),
        );
        let _ = io::stderr().flush();
    }
}

impl DownloadObserver for TerminalUi {
    fn cached(&mut self, package: &str, size: u64) {
        eprintln!(
            "  {:<24} {} cached",
            truncate(package, 24),
            format_bytes(size)
        );
    }

    fn started(&mut self, package: &str, size: u64) {
        let now = Instant::now();
        self.active = Some(ActiveDownload {
            name: package.to_owned(),
            size,
            started: now,
            last_draw: now.checked_sub(DRAW_INTERVAL).unwrap_or(now),
        });
        if self.interactive {
            self.draw_download(0);
        } else {
            eprintln!("  downloading {package} ({})", format_bytes(size));
        }
    }

    fn advanced(&mut self, _package: &str, received: u64, size: u64) {
        if !self.interactive {
            return;
        }
        let should_draw = self
            .active
            .as_ref()
            .is_some_and(|active| active.last_draw.elapsed() >= DRAW_INTERVAL || received >= size);
        if should_draw {
            if let Some(active) = &mut self.active {
                active.last_draw = Instant::now();
            }
            self.draw_download(received);
        }
    }

    fn finished(&mut self, _package: &str, size: u64) {
        if self.interactive {
            self.draw_download(size);
            eprintln!();
        } else if let Some(active) = &self.active {
            eprintln!("  downloaded {}", active.name);
        }
        self.active = None;
    }

    fn failed(&mut self, _package: &str) {
        if self.interactive {
            eprint!("\r\x1b[2K");
            let _ = io::stderr().flush();
        }
        self.active = None;
    }
}

impl SyncObserver for TerminalUi {
    fn started(&mut self, repository: &str) {
        eprintln!("  {:<24} fetching signed index", truncate(repository, 24));
    }

    fn finished(&mut self, repository: &str, packages: usize) {
        eprintln!(
            "  {:<24} {packages} package record(s)",
            truncate(repository, 24)
        );
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn terminal_bar_width() -> usize {
    env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|columns| columns.saturating_sub(68).clamp(12, 36))
        .unwrap_or(24)
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_owned();
    }
    let mut output = value
        .chars()
        .take(width.saturating_sub(1))
        .collect::<String>();
    output.push('~');
    output
}

fn error_hint(error: &ArcError) -> Option<&'static str> {
    match error {
        ArcError::Network(_) => Some("check the network connection and repository URL, then retry"),
        ArcError::Authentication(_) => {
            Some("do not bypass this check; verify the repository key and published files")
        }
        ArcError::Resolution(_) => Some(
            "run `arc sync`, check package names/version constraints, and inspect dependencies",
        ),
        ArcError::InvalidRepository(message) if message.contains("not synchronized") => {
            Some("synchronize configured repositories with `arc sync` first")
        }
        ArcError::InvalidRepository(_) => {
            Some("check `/etc/arc/repos.toml` and the repository documentation")
        }
        ArcError::InvalidArchive(_) | ArcError::InvalidMetadata(_) => {
            Some("run `arc inspect <package.arc>` to validate the package independently")
        }
        ArcError::InvalidState(_) => Some(
            "the installed database or an interrupted transaction may need inspection under `/var/lib/arc`",
        ),
        ArcError::Transaction(message) if message.contains("removal would leave") => {
            Some("remove the dependent packages in the same command, or keep the required package")
        }
        ArcError::Transaction(message) if message.contains("undefined system trigger") => {
            Some("define the requested trigger in `/etc/arc/triggers.toml` before retrying")
        }
        ArcError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            Some("check ownership and permissions; system-root operations normally require root")
        }
        ArcError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
            Some("check that every referenced path exists")
        }
        ArcError::TomlDecode(_) => Some("fix the named TOML configuration or metadata file"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_sizes_are_human_readable() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn long_labels_are_bounded() {
        assert_eq!(truncate("short", 8), "short");
        assert_eq!(truncate("abcdefghijkl", 8), "abcdefg~");
    }
}
