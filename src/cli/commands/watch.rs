//! Watch command - File system monitoring with automatic rescanning
//!
//! Monitors server files for changes and automatically triggers security scans.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use colored::Colorize;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{debug, info, warn};

use crate::cli::server::resolve_server;
use crate::client::McpClient;
use crate::protocol::Implementation;
use crate::scanner::context::ServerContext;
use crate::scanner::rules::{
    OAuthAbuseDetector, SchemaPoisoningDetector, ToolInjectionDetector, ToolShadowingDetector,
    UnicodeHiddenDetector,
};
use crate::scanner::{ScanProfile, ScanResults};
use crate::transport::{connect_with_type, TransportConfig, TransportType};

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

    // Resolve server from config if not a direct path/URL
    let (server_name, resolved_cmd, mut resolved_args, resolved_env) =
        resolve_server(server, None)?;

    // Merge CLI args with resolved args
    resolved_args.extend(args.iter().cloned());

    // Set environment variables for spawned process
    for (key, value) in &resolved_env {
        std::env::set_var(key, value);
    }

    println!("{}", "Starting watch mode...".cyan().bold());
    println!("  Server: {}", server_name.yellow());
    println!(
        "  Command: {} {}",
        resolved_cmd.dimmed(),
        resolved_args.join(" ").dimmed()
    );
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

    // Run initial scan - pass server name, not resolved command
    // ScanEngine resolves the server internally
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

                            // Run scan - pass server name, not resolved command
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

/// Run a security scan with proper server resolution
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

    // Resolve server from config
    let (server_name, command, mut resolved_args, env) = resolve_server(server, None)?;
    resolved_args.extend(args.iter().cloned());

    // Run the scan with resolved values
    let results = run_resolved_scan(&server_name, &command, &resolved_args, &env, profile).await?;

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

/// Run a security scan using resolved server specification
async fn run_resolved_scan(
    name: &str,
    command: &str,
    args: &[String],
    env: &HashMap<String, String>,
    profile: ScanProfile,
) -> Result<ScanResults> {
    let start = Instant::now();
    let mut results = ScanResults::new(name, profile);

    // Determine transport type and connect
    let transport_type = if command.starts_with("http://") || command.starts_with("https://") {
        TransportType::StreamableHttp
    } else {
        TransportType::Stdio
    };

    let transport_config = TransportConfig {
        timeout_secs: 30,
        ..Default::default()
    };

    tracing::info!("Connecting to server: {} via {:?}", name, transport_type);
    let transport_box = connect_with_type(command, args, env, transport_config, transport_type)
        .await
        .context("Failed to connect to server")?;

    // Create and initialize client
    let client_info = Implementation::new("mcplint-scanner", env!("CARGO_PKG_VERSION"));
    let mut client = McpClient::new(transport_box, client_info);
    client.mark_connected();

    let init_result = client.initialize().await?;

    // Build server context
    let mut ctx = ServerContext::new(
        &init_result.server_info.name,
        &init_result.server_info.version,
        &init_result.protocol_version,
        init_result.capabilities.clone(),
    )
    .with_transport(transport_type.to_string())
    .with_target(name);

    // Collect tools, resources, prompts
    if init_result.capabilities.has_tools() {
        if let Ok(tools) = client.list_tools().await {
            ctx = ctx.with_tools(tools);
        }
    }

    if init_result.capabilities.has_resources() {
        if let Ok(resources) = client.list_resources().await {
            ctx = ctx.with_resources(resources);
        }
    }

    if init_result.capabilities.has_prompts() {
        if let Ok(prompts) = client.list_prompts().await {
            ctx = ctx.with_prompts(prompts);
        }
    }

    // Run security checks (simplified for watch mode - quick profile)
    let mut checks = 0;

    // Only run checks if there are tools
    if !ctx.tools.is_empty() {
        // Tool injection checks
        let detector = ToolInjectionDetector::new();
        for finding in detector.check_tools(&ctx.tools) {
            results.add_finding(finding);
        }
        checks += 1;

        // Tool shadowing checks
        let detector = ToolShadowingDetector::new();
        for finding in detector.check_tools(&ctx.tools, Some(name)) {
            results.add_finding(finding);
        }
        checks += 1;

        // Schema poisoning checks
        let detector = SchemaPoisoningDetector::new();
        for finding in detector.check_tools(&ctx.tools) {
            results.add_finding(finding);
        }
        checks += 1;

        // Unicode hidden character checks
        let detector = UnicodeHiddenDetector::new();
        for finding in detector.check_tools(&ctx.tools) {
            results.add_finding(finding);
        }
        checks += 1;

        // OAuth abuse checks
        let detector = OAuthAbuseDetector::new();
        for finding in detector.check_tools(&ctx.tools) {
            results.add_finding(finding);
        }
        checks += 1;
    }

    // Close connection
    let _ = client.close().await;

    results.total_checks = checks;
    results.duration_ms = start.elapsed().as_millis() as u64;

    Ok(results)
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
