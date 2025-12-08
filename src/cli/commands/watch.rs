//! Watch command - File system monitoring with automatic rescanning
//!
//! Monitors server files for changes and automatically triggers security scans.

use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::Duration;

use anyhow::Result;
use colored::Colorize;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{debug, info, warn};

use crate::scanner::{ScanConfig, ScanEngine, ScanProfile};

/// Run watch mode with file system monitoring
#[allow(clippy::too_many_arguments)]
pub async fn run(
    server: &str,
    args: &[String],
    watch_paths: Vec<PathBuf>,
    profile: ScanProfile,
    debounce_ms: u64,
    clear_screen: bool,
) -> Result<()> {
    info!("Starting watch mode for MCP server: {}", server);

    println!("{}", "Starting watch mode...".cyan().bold());
    println!("  Server: {}", server.yellow());
    println!("  Profile: {:?}", profile);
    println!(
        "  Watching: {}",
        watch_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
            .yellow()
    );
    println!("  Debounce: {}ms", debounce_ms);
    println!();
    println!("{}", "Press Ctrl+C to stop watching".bright_black());
    println!("{}", "─".repeat(60));
    println!();

    // Run initial scan
    run_scan(server, args, profile, clear_screen).await?;

    // Set up file watcher
    let (tx, rx) = channel();

    let config = Config::default()
        .with_poll_interval(Duration::from_millis(debounce_ms))
        .with_compare_contents(false);

    let mut watcher: RecommendedWatcher =
        Watcher::new(tx, config).map_err(|e| anyhow::anyhow!("Failed to create watcher: {}", e))?;

    // Watch all specified paths
    for path in &watch_paths {
        if path.exists() {
            watcher
                .watch(path, RecursiveMode::Recursive)
                .map_err(|e| anyhow::anyhow!("Failed to watch {}: {}", path.display(), e))?;
            debug!("Watching: {}", path.display());
        } else {
            warn!("Path does not exist, skipping: {}", path.display());
        }
    }

    // Watch server file if it's a path
    let server_path = PathBuf::from(server);
    if server_path.exists() && !watch_paths.iter().any(|p| p == &server_path) {
        watcher
            .watch(&server_path, RecursiveMode::NonRecursive)
            .map_err(|e| anyhow::anyhow!("Failed to watch server file: {}", e))?;
    }

    // Also watch parent directory of server if it's a file
    if let Some(parent) = server_path.parent() {
        if parent.exists() && !watch_paths.iter().any(|p| p == parent) {
            let _ = watcher.watch(parent, RecursiveMode::NonRecursive);
        }
    }

    // Debounce tracking
    let mut last_event_time = std::time::Instant::now();
    let debounce_duration = Duration::from_millis(debounce_ms);

    // Event loop
    loop {
        match rx.recv() {
            Ok(result) => match result {
                Ok(event) => {
                    if should_trigger_scan(&event) {
                        let now = std::time::Instant::now();
                        if now.duration_since(last_event_time) >= debounce_duration {
                            last_event_time = now;

                            println!();
                            println!(
                                "{} {}",
                                "File changed:".cyan(),
                                event
                                    .paths
                                    .first()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_default()
                                    .yellow()
                            );

                            // Run scan
                            if let Err(e) = run_scan(server, args, profile, clear_screen).await {
                                eprintln!("{}", format!("Scan error: {}", e).red());
                            }
                        } else {
                            debug!("Debouncing event");
                        }
                    }
                }
                Err(e) => {
                    warn!("Watch error: {}", e);
                }
            },
            Err(e) => {
                eprintln!("{}", format!("Channel error: {}", e).red());
                break;
            }
        }
    }

    Ok(())
}

/// Determine if an event should trigger a scan
fn should_trigger_scan(event: &Event) -> bool {
    match event.kind {
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
            // Filter out temporary files and editor backup files
            event.paths.iter().any(|p| {
                let path_str = p.to_string_lossy();
                // Exclude .git directory contents
                if path_str.contains(".git") {
                    return false;
                }

                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    !name.starts_with('.')
                        && !name.ends_with('~')
                        && !name.ends_with(".swp")
                        && !name.ends_with(".tmp")
                } else {
                    true
                }
            })
        }
        _ => false,
    }
}

/// Run a security scan
async fn run_scan(
    server: &str,
    args: &[String],
    profile: ScanProfile,
    clear_screen: bool,
) -> Result<()> {
    if clear_screen {
        // Clear screen
        print!("\x1B[2J\x1B[1;1H");
    }

    println!("{}", "Running security scan...".cyan());
    println!("{}", "─".repeat(60));

    let config = ScanConfig::default().with_profile(profile).with_timeout(30);

    let engine = ScanEngine::new(config);
    let results = engine.scan(server, args, None).await?;

    results.print_text();

    println!();
    println!(
        "{}",
        format!(
            "Scan completed at {}",
            chrono::Local::now().format("%H:%M:%S")
        )
        .bright_black()
    );
    println!("{}", "Waiting for file changes...".bright_black());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, ModifyKind, RemoveKind};

    #[test]
    fn should_trigger_on_create() {
        let event = Event {
            kind: EventKind::Create(CreateKind::File),
            paths: vec![PathBuf::from("test.rs")],
            attrs: Default::default(),
        };
        assert!(should_trigger_scan(&event));
    }

    #[test]
    fn should_trigger_on_modify() {
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Content)),
            paths: vec![PathBuf::from("server.js")],
            attrs: Default::default(),
        };
        assert!(should_trigger_scan(&event));
    }

    #[test]
    fn should_trigger_on_remove() {
        let event = Event {
            kind: EventKind::Remove(RemoveKind::File),
            paths: vec![PathBuf::from("old_file.py")],
            attrs: Default::default(),
        };
        assert!(should_trigger_scan(&event));
    }

    #[test]
    fn should_not_trigger_on_hidden_files() {
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![PathBuf::from(".hidden")],
            attrs: Default::default(),
        };
        assert!(!should_trigger_scan(&event));
    }

    #[test]
    fn should_not_trigger_on_swap_files() {
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![PathBuf::from("file.swp")],
            attrs: Default::default(),
        };
        assert!(!should_trigger_scan(&event));
    }

    #[test]
    fn should_not_trigger_on_backup_files() {
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![PathBuf::from("file.js~")],
            attrs: Default::default(),
        };
        assert!(!should_trigger_scan(&event));
    }

    #[test]
    fn should_not_trigger_on_git_files() {
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![PathBuf::from("project/.git/index")],
            attrs: Default::default(),
        };
        assert!(!should_trigger_scan(&event));
    }
}
