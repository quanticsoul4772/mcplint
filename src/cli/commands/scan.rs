//! Scan command - Security vulnerability scanning

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use colored::Colorize;
use tracing::{debug, info};

use crate::ai::{ExplainEngine, ExplanationContext};
use crate::baseline::{Baseline, DiffEngine};
use crate::cache::{CacheConfig, CacheManager};
use crate::cli::commands::explain::build_ai_config;
use crate::cli::config::{AiExplainConfig, ScanCommandConfig};
use crate::cli::server::resolve_server;
use crate::reporter::{generate_gitlab, generate_junit};
use crate::scanner::{ScanConfig, ScanProfile, Severity};
use crate::ui::{ConnectionSpinner, OutputMode};
use crate::cli::OutputFormat;

/// Run a security scan using resolved server specification
///
/// This function connects to the MCP server and performs security scanning
/// using the resolved command, args, and environment variables.
async fn run_resolved_scan(
    name: &str,
    command: &str,
    args: &[String],
    env: &HashMap<String, String>,
    scan_config: ScanConfig,
    timeout: u64,
    spinner: &mut ConnectionSpinner,
) -> Result<crate::scanner::ScanResults> {
    use crate::client::McpClient;
    use crate::protocol::Implementation;
    use crate::scanner::context::ServerContext;
    use crate::scanner::rules::{
        OAuthAbuseDetector, SchemaPoisoningDetector, ToolInjectionDetector, ToolShadowingDetector,
        UnicodeHiddenDetector,
    };
    use crate::scanner::ScanResults;
    use crate::transport::{connect_with_type, TransportConfig, TransportType};
    use std::time::Instant;

    let start = Instant::now();
    let mut results = ScanResults::new(name, scan_config.profile);

    // Determine transport type and connect
    let transport_type = if command.starts_with("http://") || command.starts_with("https://") {
        TransportType::StreamableHttp
    } else {
        TransportType::Stdio
    };

    let transport_config = TransportConfig {
        timeout_secs: timeout,
        ..Default::default()
    };

    tracing::info!("Connecting to server: {} via {:?}", name, transport_type);
    let transport_box = connect_with_type(command, args, env, transport_config, transport_type)
        .await
        .context("Failed to connect to server")?;

    // Update spinner: initializing
    spinner.phase_initializing();

    // Create and initialize client
    let client_info = Implementation::new("mcplint-scanner", env!("CARGO_PKG_VERSION"));
    let mut client = McpClient::new(transport_box, client_info);
    client.mark_connected(); // Mark as connected since transport is established

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
        spinner.phase_listing("tools");
        if let Ok(tools) = client.list_tools().await {
            ctx = ctx.with_tools(tools);
        }
    }

    if init_result.capabilities.has_resources() {
        spinner.phase_listing("resources");
        if let Ok(resources) = client.list_resources().await {
            ctx = ctx.with_resources(resources);
        }
    }

    if init_result.capabilities.has_prompts() {
        spinner.phase_listing("prompts");
        if let Ok(prompts) = client.list_prompts().await {
            ctx = ctx.with_prompts(prompts);
        }
    }

    // Run M6 advanced security checks
    // MCP-SEC-040: Enhanced Tool Description Injection
    spinner.phase_security_check("MCP-SEC-040");
    results.total_checks += 1;
    let detector = ToolInjectionDetector::new();
    let findings = detector.check_tools(&ctx.tools);
    for finding in findings {
        results.add_finding(finding);
    }

    // MCP-SEC-041: Cross-Server Tool Shadowing
    spinner.phase_security_check("MCP-SEC-041");
    results.total_checks += 1;
    let detector = ToolShadowingDetector::new();
    let server_name = Some(ctx.server_name.as_str());
    let findings = detector.check_tools(&ctx.tools, server_name);
    for finding in findings {
        results.add_finding(finding);
    }

    // MCP-SEC-043: OAuth Scope Abuse
    spinner.phase_security_check("MCP-SEC-043");
    results.total_checks += 1;
    let detector = OAuthAbuseDetector::new();
    let findings = detector.check_tools(&ctx.tools);
    for finding in findings {
        results.add_finding(finding);
    }

    // MCP-SEC-044: Unicode Hidden Instructions
    spinner.phase_security_check("MCP-SEC-044");
    results.total_checks += 1;
    let detector = UnicodeHiddenDetector::new();
    let findings = detector.check_tools(&ctx.tools);
    for finding in findings {
        results.add_finding(finding);
    }

    // MCP-SEC-045: Schema Poisoning
    spinner.phase_security_check("MCP-SEC-045");
    results.total_checks += 1;
    let detector = SchemaPoisoningDetector::new();
    let findings = detector.check_tools(&ctx.tools);
    for finding in findings {
        results.add_finding(finding);
    }

    // Cleanup
    let _ = client.close().await;

    results.duration_ms = start.elapsed().as_millis() as u64;
    Ok(results)
}

/// Run the scan command with the given configuration
pub async fn run(config: ScanCommandConfig) -> Result<()> {
    let ScanCommandConfig {
        run,
        baseline,
        ai,
        output,
    } = config;

    info!("Scanning MCP server: {}", run.server);
    debug!(
        "Profile: {:?}, Include: {:?}, Exclude: {:?}, Timeout: {}s, Explain: {}",
        run.profile, run.include, run.exclude, run.timeout, ai.enabled
    );

    // Resolve server to get command, args, env, and transport
    let spec = resolve_server(&run.server, run.config_path.as_deref())?;
    let name = spec.name;
    let command = spec.command;
    let env = spec.env;

    // Combine resolved args with any additional args provided
    let mut full_args = spec.args;
    full_args.extend(run.args.iter().cloned());

    debug!(
        "Resolved server '{}': {} {:?} (transport: {})",
        name, command, full_args, spec.transport
    );

    let profile_name = run.profile.as_str();
    let scan_profile: ScanProfile = run.profile.into();

    // Determine output mode based on format
    let output_mode = if matches!(output.format, OutputFormat::Text) {
        OutputMode::detect()
    } else {
        OutputMode::Plain // Non-text formats should not show progress
    };

    // Only show banner for text output in non-CI mode
    if matches!(output.format, OutputFormat::Text) && !output_mode.progress_enabled() {
        println!("{}", "Starting security scan...".cyan());
        println!("  Server: {}", name.yellow());
        println!("  Command: {} {}", command, full_args.join(" ").dimmed());
        println!("  Profile: {}", profile_name.green());
        if let Some(ref path) = baseline.baseline_path {
            println!("  Baseline: {}", path.display().to_string().yellow());
        }
        if ai.enabled {
            println!("  AI Explanations: {}", "Enabled".green());
        }
        println!();
    }

    // Build scan configuration
    let scan_config = ScanConfig::default()
        .with_profile(scan_profile)
        .with_timeout(run.timeout);

    // Create progress spinner for interactive mode
    let mut spinner = ConnectionSpinner::new(output_mode);
    spinner.start(&name);

    // Run scan using resolved server specification
    let results = run_resolved_scan(
        &name,
        &command,
        &full_args,
        &env,
        scan_config,
        run.timeout,
        &mut spinner,
    )
    .await;

    // Handle result and update spinner
    let results = match results {
        Ok(r) => {
            let findings_count = r.findings.len();
            if findings_count > 0 {
                spinner.finish_success(&format!(
                    "Scan complete: {} findings in {}ms",
                    findings_count, r.duration_ms
                ));
            } else {
                spinner
                    .finish_success(&format!("Scan complete: No findings ({}ms)", r.duration_ms));
            }
            r
        }
        Err(e) => {
            spinner.finish_error(&format!("Scan failed: {}", e));
            return Err(e);
        }
    };

    // Load baseline if provided
    let loaded_baseline = if let Some(ref path) = baseline.baseline_path {
        match Baseline::load(path) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!(
                    "{}",
                    format!("Warning: Failed to load baseline: {}", e).yellow()
                );
                None
            }
        }
    } else {
        None
    };

    // Compute diff if baseline exists
    let diff_result = loaded_baseline
        .as_ref()
        .map(|b| DiffEngine::diff(b, &results));

    // Handle diff-only mode
    if baseline.diff_only {
        if let Some(ref diff) = diff_result {
            print_diff_summary(diff, output.format)?;

            // Exit based on new findings
            if diff.has_new_critical_or_high() {
                std::process::exit(5); // New findings vs baseline
            }
            return Ok(());
        } else {
            eprintln!("{}", "Error: --diff-only requires --baseline".red());
            std::process::exit(2);
        }
    }

    // Output results based on format
    match output.format {
        OutputFormat::Text => {
            if let Some(ref diff) = diff_result {
                print_diff_text(&results, diff);
            } else {
                results.print_text();
            }
        }
        OutputFormat::Json => {
            results.print_json()?;
        }
        OutputFormat::Sarif => {
            results.print_sarif()?;
        }
        OutputFormat::Junit => {
            println!("{}", generate_junit(&results));
        }
        OutputFormat::Gitlab => {
            println!("{}", generate_gitlab(&results));
        }
    }

    // Save baseline if requested
    if let Some(ref path) = baseline.save_baseline {
        let new_baseline = Baseline::from_results(&results);
        new_baseline.save(path)?;
        if matches!(output.format, OutputFormat::Text) {
            println!();
            println!(
                "{}",
                format!("Baseline saved to: {}", path.display()).green()
            );
        }
    }

    // Update baseline if requested (with existing baseline)
    if baseline.update_baseline {
        if let Some(ref path) = baseline.baseline_path {
            let updated_baseline = Baseline::from_results(&results);
            updated_baseline.save(path)?;
            if matches!(output.format, OutputFormat::Text) {
                println!();
                println!(
                    "{}",
                    format!("Baseline updated: {}", path.display()).green()
                );
            }
        } else {
            eprintln!(
                "{}",
                "Warning: --update-baseline requires --baseline".yellow()
            );
        }
    }

    // Generate AI explanations if requested
    if ai.enabled && !results.findings.is_empty() {
        generate_ai_explanations(&results, &ai, &run.server).await?;
    }

    // Determine exit code
    let exit_code = determine_exit_code(&results, &diff_result, &baseline.fail_on);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// Print diff summary in various formats
fn print_diff_summary(diff: &crate::baseline::DiffResult, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Text => {
            println!("{}", "Baseline Comparison Summary".cyan().bold());
            println!("{}", "=".repeat(40));
            println!();
            println!("  Baseline findings:  {}", diff.summary.total_baseline);
            println!("  Current findings:   {}", diff.summary.total_current);
            println!();
            println!(
                "  {} New findings",
                if diff.summary.new_count > 0 {
                    format!("❌ {}", diff.summary.new_count).red().to_string()
                } else {
                    format!("✓ {}", diff.summary.new_count).green().to_string()
                }
            );
            println!(
                "  {} Fixed findings",
                format!("✅ {}", diff.summary.fixed_count).green()
            );
            println!("  ➖ {} Unchanged findings", diff.summary.unchanged_count);
            println!();

            if diff.summary.new_critical > 0 || diff.summary.new_high > 0 {
                println!(
                    "  {}",
                    format!(
                        "⚠️  {} critical, {} high severity NEW findings",
                        diff.summary.new_critical, diff.summary.new_high
                    )
                    .red()
                    .bold()
                );
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&diff.summary)?);
        }
        _ => {
            // Other formats not supported for diff-only
            println!("{}", serde_json::to_string_pretty(&diff.summary)?);
        }
    }
    Ok(())
}

/// Print text results with diff information
fn print_diff_text(results: &crate::scanner::ScanResults, diff: &crate::baseline::DiffResult) {
    println!("{}", "Security Scan Results (with Baseline)".cyan().bold());
    println!("{}", "=".repeat(60));
    println!();

    println!("  Server: {}", results.server.yellow());
    println!("  Profile: {}", results.profile.green());
    println!("  Duration: {}ms", results.duration_ms);
    println!();

    // Summary
    println!("{}", "Baseline Comparison:".cyan());
    println!(
        "  {} new | {} fixed | {} unchanged",
        if diff.new_count() > 0 {
            diff.new_count().to_string().red().to_string()
        } else {
            diff.new_count().to_string().green().to_string()
        },
        diff.fixed_count().to_string().green(),
        diff.unchanged_count.to_string().bright_black()
    );
    println!();

    // New findings
    if !diff.new_findings.is_empty() {
        println!("{}", "New Findings:".red().bold());
        for finding in &diff.new_findings {
            println!(
                "  [{}] {} ({})",
                finding.severity.colored_display(),
                finding.title,
                finding.rule_id.dimmed()
            );
            println!("    {}", finding.description);
            println!();
        }
    }

    // Fixed findings
    if !diff.fixed_findings.is_empty() {
        println!("{}", "Fixed Findings:".green().bold());
        for finding in &diff.fixed_findings {
            println!(
                "  [✓] {} ({})",
                finding.rule_id.green(),
                finding.location_fingerprint.dimmed()
            );
        }
        println!();
    }

    println!("{}", "─".repeat(60));
    println!(
        "Summary: {} critical, {} high, {} medium, {} low, {} info",
        results.summary.critical.to_string().red(),
        results.summary.high.to_string().red(),
        results.summary.medium.to_string().yellow(),
        results.summary.low.to_string().blue(),
        results.summary.info.to_string().dimmed()
    );
}

/// Generate AI explanations for findings
async fn generate_ai_explanations(
    results: &crate::scanner::ScanResults,
    ai_config: &AiExplainConfig,
    server: &str,
) -> Result<()> {
    println!();
    println!("{}", "Generating AI explanations...".cyan());
    println!();

    // Build AI configuration using shared function
    let config = match build_ai_config(ai_config.provider, ai_config.model.clone(), 120) {
        Ok(config) => config,
        Err(e) => {
            println!("{}", format!("Failed to build AI config: {}", e).red());
            return Ok(());
        }
    };

    // Create explain engine
    let mut explain_engine = match ExplainEngine::new(config) {
        Ok(engine) => engine,
        Err(e) => {
            println!("{}", format!("Failed to initialize AI engine: {}", e).red());
            return Ok(());
        }
    };

    // Add cache support with default config
    if let Ok(cache) = CacheManager::new(CacheConfig::default()).await {
        explain_engine = explain_engine.with_cache(Arc::new(cache));
    }

    // Set up explanation context
    let context = ExplanationContext::new(server);
    let explain_engine = explain_engine.with_default_context(context);

    // Explain findings (limit to 5 for brevity in scan output)
    let findings: Vec<_> = results.findings.iter().take(5).collect();

    for finding in &findings {
        println!("  {} {}", "▶".cyan(), finding.rule_id.yellow());

        match explain_engine.explain(finding).await {
            Ok(explanation) => {
                println!("    {}", "Summary:".green());
                for line in explanation.explanation.summary.lines() {
                    println!("      {}", line);
                }

                if !explanation.remediation.immediate_actions.is_empty() {
                    println!("    {}", "Quick Fix:".green());
                    if let Some(action) = explanation.remediation.immediate_actions.first() {
                        println!("      • {}", action);
                    }
                }
                println!();
            }
            Err(e) => {
                println!("    {}", format!("Failed to explain: {}", e).red());
                println!();
            }
        }
    }

    if results.findings.len() > 5 {
        println!(
            "  {}",
            format!(
                "... and {} more findings. Use 'mcplint explain' for full explanations.",
                results.findings.len() - 5
            )
            .bright_black()
        );
    }

    // Print stats
    let stats = explain_engine.stats().await;
    println!(
        "{}",
        format!(
            "AI Stats: {} explanations | {:.0}% cache hit | {} API calls",
            stats.total_explanations,
            stats.cache_hit_rate(),
            stats.api_calls
        )
        .bright_black()
    );

    Ok(())
}

/// Determine exit code based on results and options
fn determine_exit_code(
    results: &crate::scanner::ScanResults,
    diff_result: &Option<crate::baseline::DiffResult>,
    fail_on: &Option<Vec<Severity>>,
) -> i32 {
    // In baseline mode, only fail on new findings
    if let Some(ref diff) = diff_result {
        if let Some(ref severities) = fail_on {
            // Check if any new findings match the specified severities
            for finding in &diff.new_findings {
                if severities.contains(&finding.severity) {
                    return 5; // New findings vs baseline
                }
            }
            return 0;
        } else {
            // Default: fail on new critical/high
            if diff.has_new_critical_or_high() {
                return 5;
            }
            return 0;
        }
    }

    // Without baseline, use standard logic
    if let Some(ref severities) = fail_on {
        for finding in &results.findings {
            if severities.contains(&finding.severity) {
                return 1;
            }
        }
        return 0;
    }

    // Default behavior
    if results.has_critical_or_high() {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::commands::explain::CliAiProvider;
    use crate::cli::config::{BaselineConfig, OutputConfig, ScanRunConfig};
    use crate::scanner::{Finding, ScanResults, ScanSummary};
    use crate::cli::ScanProfile as CliScanProfile;
    use std::path::PathBuf;

    fn create_test_results(findings: Vec<Finding>) -> ScanResults {
        let summary = ScanSummary {
            critical: findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count(),
            high: findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count(),
            medium: findings
                .iter()
                .filter(|f| f.severity == Severity::Medium)
                .count(),
            low: findings
                .iter()
                .filter(|f| f.severity == Severity::Low)
                .count(),
            info: findings
                .iter()
                .filter(|f| f.severity == Severity::Info)
                .count(),
        };
        ScanResults {
            server: "test".to_string(),
            profile: "standard".to_string(),
            total_checks: 10,
            duration_ms: 100,
            findings,
            summary,
        }
    }

    fn create_finding(severity: Severity) -> Finding {
        Finding::new(
            format!("TEST-{:?}", severity).to_uppercase(),
            severity,
            "Test Finding",
            "Test description",
        )
    }

    #[test]
    fn scan_run_config_builder() {
        let config = ScanRunConfig::new("test-server", CliScanProfile::Standard)
            .with_args(vec!["arg1".to_string()])
            .with_timeout(30);

        assert_eq!(config.server, "test-server");
        assert_eq!(config.timeout, 30);
    }

    #[test]
    fn baseline_config_builder() {
        let config = BaselineConfig::default()
            .with_baseline(PathBuf::from("baseline.json"))
            .with_diff_only(true);

        assert!(config.baseline_path.is_some());
        assert!(config.diff_only);
    }

    #[test]
    fn ai_config_enabled() {
        let config = AiExplainConfig::enabled(CliAiProvider::Anthropic).with_model("claude-3-opus");

        assert!(config.enabled);
        assert!(config.model.is_some());
    }

    #[test]
    fn scan_command_config_new() {
        let run_config = ScanRunConfig::new("server", CliScanProfile::Standard);
        let config = ScanCommandConfig::new(run_config);

        assert_eq!(config.run.server, "server");
        assert!(!config.ai.enabled);
        assert!(config.baseline.baseline_path.is_none());
    }

    #[test]
    fn scan_command_config_full_builder() {
        let run_config = ScanRunConfig::new("my-server", CliScanProfile::Full)
            .with_args(vec!["--verbose".to_string()])
            .with_timeout(120);

        let baseline = BaselineConfig::default()
            .with_baseline(PathBuf::from("baseline.json"))
            .with_diff_only(true);

        let ai = AiExplainConfig::enabled(CliAiProvider::Anthropic).with_model("claude-3-opus");

        let output = OutputConfig::new(OutputFormat::Json);

        let config = ScanCommandConfig::new(run_config)
            .with_baseline(baseline)
            .with_ai(ai)
            .with_output(output);

        assert_eq!(config.run.server, "my-server");
        assert_eq!(config.run.timeout, 120);
        assert!(config.baseline.diff_only);
        assert!(config.ai.enabled);
        assert_eq!(config.ai.model, Some("claude-3-opus".to_string()));
        assert!(matches!(config.output.format, OutputFormat::Json));
    }

    #[test]
    fn determine_exit_code_no_findings() {
        let results = create_test_results(vec![]);
        let exit = determine_exit_code(&results, &None, &None);
        assert_eq!(exit, 0);
    }

    #[test]
    fn determine_exit_code_critical_finding() {
        let results = create_test_results(vec![create_finding(Severity::Critical)]);
        let exit = determine_exit_code(&results, &None, &None);
        assert_eq!(exit, 1);
    }

    #[test]
    fn determine_exit_code_high_finding() {
        let results = create_test_results(vec![create_finding(Severity::High)]);
        let exit = determine_exit_code(&results, &None, &None);
        assert_eq!(exit, 1);
    }

    #[test]
    fn determine_exit_code_medium_finding_no_fail() {
        let results = create_test_results(vec![create_finding(Severity::Medium)]);
        let exit = determine_exit_code(&results, &None, &None);
        assert_eq!(exit, 0);
    }

    #[test]
    fn determine_exit_code_custom_fail_on_medium() {
        let results = create_test_results(vec![create_finding(Severity::Medium)]);
        let exit = determine_exit_code(&results, &None, &Some(vec![Severity::Medium]));
        assert_eq!(exit, 1);
    }

    #[test]
    fn determine_exit_code_custom_fail_on_not_matched() {
        let results = create_test_results(vec![create_finding(Severity::Low)]);
        let exit = determine_exit_code(&results, &None, &Some(vec![Severity::Critical]));
        assert_eq!(exit, 0);
    }
}
