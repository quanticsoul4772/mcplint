//! Watch command - File system monitoring with automatic rescanning
//!
//! Monitors server files for changes and automatically triggers security scans.
//! Supports differential display showing new and fixed issues between scans.

use std::collections::{HashMap, HashSet};
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
use crate::scanner::Finding;
use crate::scanner::{ScanProfile, ScanResults};
use crate::transport::{connect_with_type, TransportConfig, TransportType};

/// Represents the diff between two scan results
#[derive(Debug, Clone)]
pub struct ResultsDiff {
    /// Newly detected findings (present in new scan, not in previous)
    pub new_findings: Vec<Finding>,
    /// Fixed findings (present in previous scan, not in new)
    pub fixed_findings: Vec<Finding>,
    /// Unchanged findings (present in both scans)
    pub unchanged_findings: Vec<Finding>,
}

impl ResultsDiff {
    /// Compute the diff between previous and new scan results
    pub fn compute(previous: &ScanResults, current: &ScanResults) -> Self {
        // Build a set of fingerprints for previous findings
        let previous_fingerprints: HashSet<String> =
            previous.findings.iter().map(Self::fingerprint).collect();

        // Build a set of fingerprints for current findings
        let current_fingerprints: HashSet<String> =
            current.findings.iter().map(Self::fingerprint).collect();

        // New findings: in current but not in previous
        let new_findings: Vec<Finding> = current
            .findings
            .iter()
            .filter(|f| !previous_fingerprints.contains(&Self::fingerprint(f)))
            .cloned()
            .collect();

        // Fixed findings: in previous but not in current
        let fixed_findings: Vec<Finding> = previous
            .findings
            .iter()
            .filter(|f| !current_fingerprints.contains(&Self::fingerprint(f)))
            .cloned()
            .collect();

        // Unchanged findings: in both
        let unchanged_findings: Vec<Finding> = current
            .findings
            .iter()
            .filter(|f| previous_fingerprints.contains(&Self::fingerprint(f)))
            .cloned()
            .collect();

        Self {
            new_findings,
            fixed_findings,
            unchanged_findings,
        }
    }

    /// Create a fingerprint for a finding based on its key attributes
    /// This is used to compare findings across scans (ignoring unique IDs and timestamps)
    fn fingerprint(finding: &Finding) -> String {
        format!(
            "{}:{}:{}:{}",
            finding.rule_id, finding.location.component, finding.location.identifier, finding.title
        )
    }

    /// Check if there are any changes between scans
    pub fn has_changes(&self) -> bool {
        !self.new_findings.is_empty() || !self.fixed_findings.is_empty()
    }

    /// Display the diff in a human-readable format
    pub fn display(&self) {
        if !self.has_changes() {
            println!("{}", "No changes detected since last scan.".dimmed());
            println!(
                "  Total issues: {}",
                self.unchanged_findings.len().to_string().yellow()
            );
            return;
        }

        // Display new findings
        if !self.new_findings.is_empty() {
            println!();
            println!(
                "{} {} {}",
                "▲".red().bold(),
                self.new_findings.len().to_string().red().bold(),
                "NEW ISSUE(S) DETECTED:".red().bold()
            );
            for finding in &self.new_findings {
                println!(
                    "  {} {} [{}] {}",
                    "+".red(),
                    finding.severity.colored_display(),
                    finding.rule_id.dimmed(),
                    finding.title
                );
                if !finding.location.identifier.is_empty() {
                    println!(
                        "    └─ {}: {}",
                        finding.location.component.dimmed(),
                        finding.location.identifier.yellow()
                    );
                }
            }
        }

        // Display fixed findings
        if !self.fixed_findings.is_empty() {
            println!();
            println!(
                "{} {} {}",
                "▼".green().bold(),
                self.fixed_findings.len().to_string().green().bold(),
                "ISSUE(S) FIXED:".green().bold()
            );
            for finding in &self.fixed_findings {
                println!(
                    "  {} {} [{}] {}",
                    "-".green(),
                    finding.severity.as_str().dimmed(),
                    finding.rule_id.dimmed(),
                    finding.title.strikethrough()
                );
            }
        }

        // Summary
        println!();
        println!(
            "{}",
            format!(
                "Summary: {} new, {} fixed, {} unchanged",
                self.new_findings.len(),
                self.fixed_findings.len(),
                self.unchanged_findings.len()
            )
            .bright_black()
        );
    }
}

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
    let spec = resolve_server(server, None)?;
    let server_name = spec.name;
    let resolved_cmd = spec.command;
    let resolved_env = spec.env;

    // Merge CLI args with resolved args
    let mut resolved_args = spec.args;
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
    println!("  Differential display: {}", "enabled".green());
    println!();
    println!("{}", "Press Ctrl+C to stop watching".bright_black());
    println!("{}", "─".repeat(60));
    println!();

    // Run initial scan - pass server name, not resolved command
    // ScanEngine resolves the server internally
    let mut previous_results =
        run_scan_with_results(server, args, profile, clear_screen, None).await?;

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

                            // Run scan with diff comparison - pass server name, not resolved command
                            match run_scan_with_results(
                                server,
                                args,
                                profile,
                                clear_screen,
                                Some(&previous_results),
                            )
                            .await
                            {
                                Ok(new_results) => {
                                    previous_results = new_results;
                                }
                                Err(e) => {
                                    eprintln!("{}", format!("Scan error: {}", e).red());
                                }
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

/// Run a security scan with proper server resolution and optional diff display
async fn run_scan_with_results(
    server: &str,
    args: &[String],
    profile: ScanProfile,
    clear_screen: bool,
    previous_results: Option<&ScanResults>,
) -> Result<ScanResults> {
    if clear_screen {
        // Clear screen
        print!("\x1B[2J\x1B[1;1H");
    }

    println!("{}", "Running security scan...".cyan());
    println!("{}", "─".repeat(60));

    // Resolve server from config
    let spec = resolve_server(server, None)?;
    let server_name = spec.name;
    let command = spec.command;
    let env = spec.env;
    let mut resolved_args = spec.args;
    resolved_args.extend(args.iter().cloned());

    // Run the scan with resolved values
    let results = run_resolved_scan(&server_name, &command, &resolved_args, &env, profile).await?;

    // If we have previous results, show diff; otherwise show full results
    if let Some(prev) = previous_results {
        let diff = ResultsDiff::compute(prev, &results);
        diff.display();

        // Also show current total summary
        println!();
        println!("{}", "─".repeat(60));
        println!(
            "Current state: {} critical, {} high, {} medium, {} low, {} info",
            results.summary.critical.to_string().red().bold(),
            results.summary.high.to_string().red(),
            results.summary.medium.to_string().yellow(),
            results.summary.low.to_string().blue(),
            results.summary.info.to_string().dimmed()
        );
    } else {
        results.print_text();
    }

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

    Ok(results)
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
    use crate::scanner::{FindingLocation, Severity};
    use notify::event::{CreateKind, ModifyKind, RemoveKind};

    // Helper to create a test finding
    fn make_finding(
        rule_id: &str,
        severity: Severity,
        title: &str,
        component: &str,
        identifier: &str,
    ) -> Finding {
        Finding::new(rule_id, severity, title, "Test description").with_location(FindingLocation {
            component: component.to_string(),
            identifier: identifier.to_string(),
            context: None,
        })
    }

    // Helper to create empty scan results
    fn make_empty_results() -> ScanResults {
        ScanResults::new("test-server", ScanProfile::Standard)
    }

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

    // ResultsDiff tests
    #[test]
    fn diff_empty_results_has_no_changes() {
        let prev = make_empty_results();
        let curr = make_empty_results();
        let diff = ResultsDiff::compute(&prev, &curr);

        assert!(!diff.has_changes());
        assert!(diff.new_findings.is_empty());
        assert!(diff.fixed_findings.is_empty());
        assert!(diff.unchanged_findings.is_empty());
    }

    #[test]
    fn diff_detects_new_findings() {
        let prev = make_empty_results();
        let mut curr = make_empty_results();
        curr.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "New Issue",
            "tool",
            "test_tool",
        ));

        let diff = ResultsDiff::compute(&prev, &curr);

        assert!(diff.has_changes());
        assert_eq!(diff.new_findings.len(), 1);
        assert!(diff.fixed_findings.is_empty());
        assert!(diff.unchanged_findings.is_empty());
    }

    #[test]
    fn diff_detects_fixed_findings() {
        let mut prev = make_empty_results();
        prev.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Fixed Issue",
            "tool",
            "test_tool",
        ));
        let curr = make_empty_results();

        let diff = ResultsDiff::compute(&prev, &curr);

        assert!(diff.has_changes());
        assert!(diff.new_findings.is_empty());
        assert_eq!(diff.fixed_findings.len(), 1);
        assert!(diff.unchanged_findings.is_empty());
    }

    #[test]
    fn diff_detects_unchanged_findings() {
        let mut prev = make_empty_results();
        prev.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Unchanged Issue",
            "tool",
            "test_tool",
        ));

        let mut curr = make_empty_results();
        curr.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Unchanged Issue",
            "tool",
            "test_tool",
        ));

        let diff = ResultsDiff::compute(&prev, &curr);

        assert!(!diff.has_changes());
        assert!(diff.new_findings.is_empty());
        assert!(diff.fixed_findings.is_empty());
        assert_eq!(diff.unchanged_findings.len(), 1);
    }

    #[test]
    fn diff_handles_mixed_changes() {
        let mut prev = make_empty_results();
        prev.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Fixed Issue",
            "tool",
            "tool1",
        ));
        prev.add_finding(make_finding(
            "MCP-INJ-002",
            Severity::Medium,
            "Unchanged Issue",
            "tool",
            "tool2",
        ));

        let mut curr = make_empty_results();
        curr.add_finding(make_finding(
            "MCP-INJ-002",
            Severity::Medium,
            "Unchanged Issue",
            "tool",
            "tool2",
        ));
        curr.add_finding(make_finding(
            "MCP-INJ-003",
            Severity::Critical,
            "New Issue",
            "tool",
            "tool3",
        ));

        let diff = ResultsDiff::compute(&prev, &curr);

        assert!(diff.has_changes());
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.fixed_findings.len(), 1);
        assert_eq!(diff.unchanged_findings.len(), 1);

        // Verify the correct findings in each category
        assert_eq!(diff.new_findings[0].rule_id, "MCP-INJ-003");
        assert_eq!(diff.fixed_findings[0].rule_id, "MCP-INJ-001");
        assert_eq!(diff.unchanged_findings[0].rule_id, "MCP-INJ-002");
    }

    #[test]
    fn diff_ignores_finding_id_differences() {
        // Same finding with different UUIDs should be considered the same
        let mut prev = make_empty_results();
        prev.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Issue",
            "tool",
            "test_tool",
        ));

        let mut curr = make_empty_results();
        curr.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Issue",
            "tool",
            "test_tool",
        ));

        let diff = ResultsDiff::compute(&prev, &curr);

        // Even though the UUIDs are different, the fingerprint (rule_id + location + title) matches
        assert!(!diff.has_changes());
        assert_eq!(diff.unchanged_findings.len(), 1);
    }

    #[test]
    fn diff_treats_different_locations_as_different_findings() {
        let mut prev = make_empty_results();
        prev.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Issue",
            "tool",
            "tool_a",
        ));

        let mut curr = make_empty_results();
        curr.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Issue",
            "tool",
            "tool_b",
        ));

        let diff = ResultsDiff::compute(&prev, &curr);

        // Different tool location = different findings
        assert!(diff.has_changes());
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.fixed_findings.len(), 1);
    }

    #[test]
    fn diff_treats_different_titles_as_different_findings() {
        let mut prev = make_empty_results();
        prev.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Issue A",
            "tool",
            "test_tool",
        ));

        let mut curr = make_empty_results();
        curr.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Issue B",
            "tool",
            "test_tool",
        ));

        let diff = ResultsDiff::compute(&prev, &curr);

        // Different title = different findings
        assert!(diff.has_changes());
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.fixed_findings.len(), 1);
    }

    #[test]
    fn fingerprint_is_consistent() {
        let finding = make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Test Issue",
            "tool",
            "my_tool",
        );
        let fp1 = ResultsDiff::fingerprint(&finding);
        let fp2 = ResultsDiff::fingerprint(&finding);

        assert_eq!(fp1, fp2);
        assert_eq!(fp1, "MCP-INJ-001:tool:my_tool:Test Issue");
    }

    #[test]
    fn diff_multiple_findings_same_rule() {
        // Multiple findings with same rule but different locations
        let mut prev = make_empty_results();
        prev.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Injection",
            "tool",
            "tool_a",
        ));
        prev.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Injection",
            "tool",
            "tool_b",
        ));

        let mut curr = make_empty_results();
        curr.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Injection",
            "tool",
            "tool_b",
        ));
        curr.add_finding(make_finding(
            "MCP-INJ-001",
            Severity::High,
            "Injection",
            "tool",
            "tool_c",
        ));

        let diff = ResultsDiff::compute(&prev, &curr);

        assert!(diff.has_changes());
        assert_eq!(diff.new_findings.len(), 1); // tool_c is new
        assert_eq!(diff.fixed_findings.len(), 1); // tool_a was fixed
        assert_eq!(diff.unchanged_findings.len(), 1); // tool_b unchanged
    }
}
