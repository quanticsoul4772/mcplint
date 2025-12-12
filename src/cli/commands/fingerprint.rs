//! Fingerprint command - Tool definition fingerprinting
//!
//! Generates and compares tool definition fingerprints to detect schema changes.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use colored::Colorize;
use tracing::{debug, info};

use crate::baseline::Baseline;
use crate::cli::server::resolve_server;
use crate::fingerprinting::{
    ChangeSeverity, FingerprintComparator, FingerprintDiff, FingerprintHasher, ToolFingerprint,
};
use crate::protocol::mcp::Tool;
use crate::transport::{stdio::StdioTransport, Transport, TransportConfig};
use crate::OutputFormat;

/// Fetch tools from an MCP server
async fn fetch_tools(
    command: &str,
    args: &[String],
    env: &HashMap<String, String>,
    timeout: u64,
) -> Result<Vec<Tool>> {
    let config = TransportConfig {
        timeout_secs: timeout,
        ..Default::default()
    };

    let mut transport = StdioTransport::spawn(command, args, env, config).await?;

    // Initialize protocol
    let init_params = serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {
            "name": "mcplint",
            "version": env!("CARGO_PKG_VERSION")
        }
    });

    let response = transport.request("initialize", Some(init_params)).await?;

    if response.error.is_some() {
        anyhow::bail!("Server initialization failed: {:?}", response.error);
    }

    // Send initialized notification
    let _ = transport.notify("notifications/initialized", None).await;

    // List tools
    let tools_response = transport
        .request("tools/list", Some(serde_json::json!({})))
        .await?;

    let tools: Vec<Tool> = tools_response
        .result
        .and_then(|r| r.get("tools").cloned())
        .and_then(|t| serde_json::from_value(t).ok())
        .unwrap_or_default();

    transport.close().await?;

    Ok(tools)
}

/// Generate fingerprints for tools
pub async fn run_generate(
    server: &str,
    config: Option<&Path>,
    output: Option<&Path>,
    timeout: u64,
    format: OutputFormat,
) -> Result<()> {
    let spec = resolve_server(server, config)?;
    let name = spec.name;
    let command = spec.command;
    let args = spec.args;
    let env = spec.env;

    info!("Generating fingerprints for: {} ({})", name, command);
    debug!("Args: {:?}, Timeout: {}s", args, timeout);

    println!("{}", "━".repeat(60).dimmed());
    println!("{} {}", "Fingerprinting:".cyan(), name.yellow().bold());
    println!("  Command: {} {}", command, args.join(" ").dimmed());
    println!();

    // Fetch tools from server
    let tools = fetch_tools(&command, &args, &env, timeout).await?;

    if tools.is_empty() {
        println!("{}", "No tools found on server".yellow());
        return Ok(());
    }

    println!("{} {} tools", "Found:".green(), tools.len());

    // Generate fingerprints
    let fingerprints: Vec<ToolFingerprint> = tools
        .iter()
        .filter_map(|tool| match FingerprintHasher::fingerprint(tool) {
            Ok(fp) => Some(fp),
            Err(e) => {
                println!(
                    "  {} Failed to fingerprint {}: {}",
                    "⚠".yellow(),
                    tool.name,
                    e
                );
                None
            }
        })
        .collect();

    println!(
        "{} {} fingerprints",
        "Generated:".green(),
        fingerprints.len()
    );
    println!();

    // Output fingerprints
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&fingerprints)?);
        }
        _ => {
            print_fingerprints_text(&fingerprints);
        }
    }

    // Save to file if requested
    if let Some(path) = output {
        let content = serde_json::to_string_pretty(&fingerprints)?;
        std::fs::write(path, content)?;
        println!();
        println!("{} {}", "Saved to:".green(), path.display());
    }

    Ok(())
}

/// Compare fingerprints against a baseline
pub async fn run_compare(
    server: &str,
    baseline_path: &Path,
    config: Option<&Path>,
    timeout: u64,
    format: OutputFormat,
) -> Result<()> {
    let spec = resolve_server(server, config)?;
    let name = spec.name;
    let command = spec.command;
    let args = spec.args;
    let env = spec.env;

    // Load baseline
    let baseline = Baseline::load(baseline_path)?;

    let baseline_fingerprints = baseline.tool_fingerprints.as_ref().ok_or_else(|| {
        anyhow::anyhow!("Baseline does not contain tool fingerprints. Generate a new baseline with --save-baseline")
    })?;

    info!("Comparing fingerprints for: {} ({})", name, command);
    println!("{}", "━".repeat(60).dimmed());
    println!("{} {}", "Comparing:".cyan(), name.yellow().bold());
    println!("  Baseline: {}", baseline_path.display());
    println!("  Baseline fingerprints: {}", baseline_fingerprints.len());
    println!();

    // Fetch current tools
    let tools = fetch_tools(&command, &args, &env, timeout).await?;
    let current_fingerprints = FingerprintHasher::fingerprint_all_ok(&tools);

    println!("{} {} current tools", "Found:".green(), tools.len());
    println!();

    // Compare fingerprints
    let mut diffs: Vec<FingerprintDiff> = Vec::new();
    let mut added_tools: Vec<&ToolFingerprint> = Vec::new();
    let mut removed_tools: Vec<&ToolFingerprint> = Vec::new();

    // Find changed and removed tools
    for old_fp in baseline_fingerprints {
        if let Some(new_fp) = current_fingerprints
            .iter()
            .find(|fp| fp.tool_name == old_fp.tool_name)
        {
            let diff = FingerprintComparator::compare(old_fp, new_fp);
            if !diff.changes.is_empty() {
                diffs.push(diff);
            }
        } else {
            removed_tools.push(old_fp);
        }
    }

    // Find added tools
    for new_fp in &current_fingerprints {
        if !baseline_fingerprints
            .iter()
            .any(|fp| fp.tool_name == new_fp.tool_name)
        {
            added_tools.push(new_fp);
        }
    }

    // Output results
    match format {
        OutputFormat::Json => {
            let result = serde_json::json!({
                "added": added_tools,
                "removed": removed_tools,
                "changed": diffs,
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        _ => {
            print_comparison_text(&diffs, &added_tools, &removed_tools);
        }
    }

    // Exit with appropriate code
    let has_breaking = diffs.iter().any(|d| d.severity == ChangeSeverity::Breaking);
    let has_major = diffs.iter().any(|d| d.severity == ChangeSeverity::Major);

    if has_breaking || !removed_tools.is_empty() {
        std::process::exit(1); // Breaking changes detected
    } else if has_major {
        std::process::exit(2); // Major changes detected
    }

    Ok(())
}

/// Print fingerprints in text format
fn print_fingerprints_text(fingerprints: &[ToolFingerprint]) {
    for fp in fingerprints {
        println!("{} {}", "Tool:".cyan(), fp.tool_name.yellow().bold());
        println!("  Semantic: {}", &fp.semantic_hash[..16]);
        println!("  Full:     {}", &fp.full_hash[..16]);
        println!(
            "  Parameters: {} (required: {})",
            fp.metadata.parameter_count,
            fp.metadata.required_params.len()
        );
        if fp.metadata.complexity_score > 0 {
            println!("  Complexity: {}", fp.metadata.complexity_score);
        }
        println!();
    }
}

/// Print comparison results in text format
fn print_comparison_text(
    diffs: &[FingerprintDiff],
    added: &[&ToolFingerprint],
    removed: &[&ToolFingerprint],
) {
    // Added tools
    if !added.is_empty() {
        println!("{}", "Added Tools:".green().bold());
        for fp in added {
            println!("  {} {}", "+".green(), fp.tool_name);
        }
        println!();
    }

    // Removed tools
    if !removed.is_empty() {
        println!("{}", "Removed Tools:".red().bold());
        for fp in removed {
            println!("  {} {}", "-".red(), fp.tool_name);
        }
        println!();
    }

    // Changed tools
    if !diffs.is_empty() {
        println!("{}", "Changed Tools:".yellow().bold());
        for diff in diffs {
            let severity_color = match diff.severity {
                ChangeSeverity::Breaking => "BREAKING".red().bold(),
                ChangeSeverity::Major => "MAJOR".red(),
                ChangeSeverity::Minor => "MINOR".yellow(),
                ChangeSeverity::Patch => "PATCH".dimmed(),
                ChangeSeverity::None => "NONE".dimmed(),
            };

            println!("  {} {} [{}]", "~".yellow(), diff.tool_name, severity_color);
            println!("    {}", diff.summary);

            for change in &diff.changes {
                println!("    • {:?}", change);
            }

            if !diff.recommendations.is_empty() {
                println!("    Recommendations:");
                for rec in &diff.recommendations {
                    println!("      → {}", rec);
                }
            }
            println!();
        }
    }

    // Summary
    let total_changes = added.len() + removed.len() + diffs.len();
    if total_changes == 0 {
        println!("{}", "✓ No changes detected".green().bold());
    } else {
        println!(
            "{} {} added, {} removed, {} changed",
            "Summary:".cyan(),
            added.len(),
            removed.len(),
            diffs.len()
        );

        let breaking_count = diffs
            .iter()
            .filter(|d| d.severity == ChangeSeverity::Breaking)
            .count();
        if breaking_count > 0 || !removed.is_empty() {
            println!(
                "{}",
                format!(
                    "⚠ {} breaking changes require attention",
                    breaking_count + removed.len()
                )
                .red()
                .bold()
            );
        }
    }
}
