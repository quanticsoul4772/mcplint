//! Explain command - AI-powered vulnerability explanations
//!
//! Provides detailed AI-generated explanations for security findings.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use colored::Colorize;
use tracing::{debug, info};

use crate::ai::{
    AiConfig, AiProviderType, AudienceLevel, EngineStats, ExplainEngine, ExplanationContext,
    ExplanationResponse,
};
use crate::cache::{CacheConfig, CacheManager};
use crate::cli::server::resolve_server;
use crate::cli::OutputFormat;
use crate::scanner::{Finding, ScanProfile, Severity};
use crate::transport::TransportConfig;

/// AI provider selection for CLI
#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub enum CliAiProvider {
    /// Anthropic Claude (requires ANTHROPIC_API_KEY)
    Anthropic,
    /// OpenAI GPT (requires OPENAI_API_KEY)
    Openai,
    /// Local Ollama instance
    #[default]
    Ollama,
}

/// Audience level for explanations
#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub enum CliAudienceLevel {
    /// Beginner-friendly explanations
    Beginner,
    /// Intermediate technical level
    #[default]
    Intermediate,
    /// Expert-level technical detail
    Expert,
}

impl From<CliAiProvider> for AiProviderType {
    fn from(provider: CliAiProvider) -> Self {
        match provider {
            CliAiProvider::Anthropic => AiProviderType::Anthropic,
            CliAiProvider::Openai => AiProviderType::OpenAI,
            CliAiProvider::Ollama => AiProviderType::Ollama,
        }
    }
}

impl From<CliAudienceLevel> for AudienceLevel {
    fn from(level: CliAudienceLevel) -> Self {
        match level {
            CliAudienceLevel::Beginner => AudienceLevel::Beginner,
            CliAudienceLevel::Intermediate => AudienceLevel::Intermediate,
            CliAudienceLevel::Expert => AudienceLevel::Expert,
        }
    }
}

/// Run explain on a specific finding ID from previous scan results
#[allow(dead_code)]
pub async fn run_finding(
    finding_id: &str,
    _provider: CliAiProvider,
    _model: Option<String>,
    _audience: CliAudienceLevel,
    _format: OutputFormat,
    _no_cache: bool,
) -> Result<()> {
    info!("Explaining finding: {}", finding_id);

    // For now, we need to have scan results available
    // In a real implementation, we'd load from cache or a results file
    println!(
        "{}",
        "Note: Explain by finding ID requires cached scan results.".yellow()
    );
    println!(
        "To explain findings, run: {}",
        "mcplint scan <server> --explain".cyan()
    );

    Ok(())
}

/// Run a security scan using resolved server specification
///
/// This function connects to the MCP server and performs security scanning
/// using the resolved command, args, and environment variables.
async fn run_resolved_scan(
    name: &str,
    command: &str,
    args: &[String],
    env: &HashMap<String, String>,
    timeout: u64,
) -> Result<crate::scanner::ScanResults> {
    use crate::client::McpClient;
    use crate::protocol::Implementation;
    use crate::scanner::rules::{
        OAuthAbuseDetector, SchemaPoisoningDetector, ToolInjectionDetector, ToolShadowingDetector,
        UnicodeHiddenDetector,
    };
    use crate::scanner::{ScanResults, ServerContext};
    use crate::transport::{connect_with_type, TransportType};
    use std::time::Instant;

    let start = Instant::now();
    let scan_profile = ScanProfile::Standard;
    let mut results = ScanResults::new(name, scan_profile);

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

    // Run M6 advanced security checks (the main ones we care about for explain)
    // MCP-SEC-040: Enhanced Tool Description Injection
    results.total_checks += 1;
    let detector = ToolInjectionDetector::new();
    let findings = detector.check_tools(&ctx.tools);
    for finding in findings {
        results.add_finding(finding);
    }

    // MCP-SEC-041: Cross-Server Tool Shadowing
    results.total_checks += 1;
    let detector = ToolShadowingDetector::new();
    let server_name = Some(ctx.server_name.as_str());
    let findings = detector.check_tools(&ctx.tools, server_name);
    for finding in findings {
        results.add_finding(finding);
    }

    // MCP-SEC-043: OAuth Scope Abuse
    results.total_checks += 1;
    let detector = OAuthAbuseDetector::new();
    let findings = detector.check_tools(&ctx.tools);
    for finding in findings {
        results.add_finding(finding);
    }

    // MCP-SEC-044: Unicode Hidden Instructions
    results.total_checks += 1;
    let detector = UnicodeHiddenDetector::new();
    let findings = detector.check_tools(&ctx.tools);
    for finding in findings {
        results.add_finding(finding);
    }

    // MCP-SEC-045: Schema Poisoning
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

/// Run explain after scanning a server
#[allow(clippy::too_many_arguments)]
pub async fn run_scan(
    server: &str,
    args: &[String],
    provider: CliAiProvider,
    model: Option<String>,
    audience: CliAudienceLevel,
    severity_filter: Option<Severity>,
    max_findings: Option<usize>,
    format: OutputFormat,
    no_cache: bool,
    interactive: bool,
    timeout: u64,
    config_path: Option<&Path>,
) -> Result<()> {
    info!("Scanning and explaining: {}", server);

    // Resolve server to get command, args, env, and transport
    let spec = resolve_server(server, config_path)?;
    let name = spec.name;
    let command = spec.command;
    let env = spec.env;

    // Combine resolved args with any additional args provided
    let mut full_args = spec.args;
    full_args.extend(args.iter().cloned());

    debug!(
        "Resolved server '{}': {} {:?} (transport: {})",
        name, command, full_args, spec.transport
    );

    // First, run a security scan
    println!("{}", "Step 1: Scanning for security issues...".cyan());
    println!("  Server: {}", name.yellow());
    println!("  Command: {} {}", command, full_args.join(" ").dimmed());
    println!();

    // Run scan using resolved server specification
    let scan_results = run_resolved_scan(&name, &command, &full_args, &env, timeout).await?;

    // Filter findings by severity if specified
    let mut findings: Vec<&Finding> = scan_results.findings.iter().collect();

    if let Some(min_severity) = severity_filter {
        findings.retain(|f| f.severity >= min_severity);
    }

    // Limit number of findings to explain
    if let Some(max) = max_findings {
        findings.truncate(max);
    }

    if findings.is_empty() {
        // Show informative summary even when no findings
        println!();
        println!(
            "{}",
            "════════════════════════════════════════════════════════════".bright_green()
        );
        println!(
            "{}",
            "  ✓ Security Scan Complete - No Issues Found".bright_green()
        );
        println!(
            "{}",
            "════════════════════════════════════════════════════════════".bright_green()
        );
        println!();
        println!("  {}  {}", "Server:".dimmed(), name.white());
        println!(
            "  {}  {}",
            "Profile:".dimmed(),
            scan_results.profile.white()
        );
        println!(
            "  {} {}",
            "Checks:".dimmed(),
            scan_results.total_checks.to_string().white()
        );
        println!(
            "  {} {}ms",
            "Duration:".dimmed(),
            scan_results.duration_ms.to_string().white()
        );
        println!();
        println!(
            "  {} The server passed all {} security checks.",
            "Result:".dimmed(),
            scan_results.total_checks
        );
        println!(
            "  {}",
            "  No vulnerabilities were detected that require AI explanation.".dimmed()
        );
        println!();

        // Show what was checked
        println!("  {} Security checks performed:", "Details:".dimmed());
        println!("    • Tool injection detection");
        println!("    • Tool shadowing analysis");
        println!("    • Schema poisoning checks");
        println!("    • Hidden unicode character scan");
        println!("    • OAuth scope abuse detection");
        println!();

        if severity_filter.is_some() {
            println!(
                "  {} Severity filter was applied - some lower severity findings may have been excluded.",
                "Note:".yellow()
            );
            println!();
        }

        return Ok(());
    }

    println!(
        "{}",
        format!("Step 2: Explaining {} finding(s)...", findings.len()).cyan()
    );
    println!();

    // Create AI configuration
    let ai_config = build_ai_config(provider, model, timeout)?;

    // Create explain engine
    let mut engine = ExplainEngine::new(ai_config)?;

    // Add cache support if enabled
    if !no_cache {
        if let Ok(cache) = CacheManager::new(CacheConfig::default()).await {
            engine = engine.with_cache(Arc::new(cache));
        }
    }

    // Set up explanation context
    let context = ExplanationContext::new(server).with_audience(audience.into());
    let engine = engine.with_default_context(context);

    // Check provider health
    if !engine.health_check().await.unwrap_or(false) {
        println!(
            "{}",
            format!(
                "Warning: {} provider may not be available. Trying anyway...",
                engine.provider_name()
            )
            .yellow()
        );
    }

    // Generate explanations
    let mut explanations = Vec::new();

    for (idx, finding) in findings.iter().enumerate() {
        println!(
            "  Explaining finding {}/{}: {}",
            idx + 1,
            findings.len(),
            finding.rule_id.cyan()
        );

        match engine.explain(finding).await {
            Ok(explanation) => {
                explanations.push(explanation);
            }
            Err(e) => {
                println!("    {}", format!("Failed to explain: {}", e).red());
            }
        }
    }

    println!();

    // Output results
    match format {
        OutputFormat::Text => {
            print_explanations_text(&explanations).await?;
        }
        OutputFormat::Json => {
            print_explanations_json(&explanations)?;
        }
        OutputFormat::Sarif => {
            println!(
                "{}",
                "SARIF output for explanations not yet implemented.".yellow()
            );
            print_explanations_json(&explanations)?;
        }
        OutputFormat::Junit | OutputFormat::Gitlab => {
            // Explanation results use JSON as fallback for unsupported formats
            print_explanations_json(&explanations)?;
        }
    }

    // Print stats
    let stats = engine.stats().await;
    print_stats(&stats);

    // Enter interactive mode if requested
    if interactive && !explanations.is_empty() {
        run_interactive_mode(&engine, &explanations).await?;
    }

    Ok(())
}

/// Build AI configuration from CLI options
///
/// Priority order for settings:
/// 1. CLI arguments (highest priority)
/// 2. Config file (.mcplint.toml, mcplint.toml, ~/.config/mcplint/config.toml)
/// 3. Environment variables
/// 4. Defaults (lowest priority)
pub fn build_ai_config(
    provider: CliAiProvider,
    model: Option<String>,
    timeout: u64,
) -> Result<AiConfig> {
    // Start with config file or defaults
    let mut config = AiConfig::load_or_default(None);
    debug!(
        "Loaded base config: provider={}, model={}",
        config.provider, config.model
    );

    // Apply CLI overrides
    let provider_type: AiProviderType = provider.into();
    let original_provider = config.provider;

    // CLI provider always overrides config file
    config.provider = provider_type;

    // CLI model overrides config file, or use provider default
    if let Some(m) = model {
        config.model = m;
    } else if original_provider != provider_type {
        // Provider changed, use new provider's default model
        config.model = provider_type.default_model().to_string();
    }

    // CLI timeout overrides config file
    config.timeout_secs = timeout;

    // Ensure API key is loaded from environment
    config.load_api_key_from_env();

    // Validate required API keys for non-Ollama providers
    match provider_type {
        AiProviderType::Anthropic => {
            if config.api_key.is_none() {
                anyhow::bail!("ANTHROPIC_API_KEY environment variable not set");
            }
        }
        AiProviderType::OpenAI => {
            if config.api_key.is_none() {
                anyhow::bail!("OPENAI_API_KEY environment variable not set");
            }
        }
        AiProviderType::Ollama => {
            // Ollama doesn't require an API key
            // Check for OLLAMA_HOST override
            if let Ok(url) = std::env::var("OLLAMA_HOST") {
                config.ollama_url = url;
            }
        }
    }

    debug!(
        "Final config: provider={}, model={}, timeout={}s",
        config.provider, config.model, config.timeout_secs
    );

    Ok(config)
}

/// Print explanations in text format
async fn print_explanations_text(explanations: &[ExplanationResponse]) -> Result<()> {
    for (idx, explanation) in explanations.iter().enumerate() {
        println!("{}", "═".repeat(80).cyan());
        println!(
            "{} Finding: {} ({})",
            "▶".cyan(),
            explanation.finding_id.yellow(),
            explanation.rule_id.bright_black()
        );
        println!("{}", "─".repeat(80));

        // Summary
        println!("{}", "Summary:".green().bold());
        println!("  {}", explanation.explanation.summary);
        println!();

        // Technical Details
        println!("{}", "Technical Details:".green().bold());
        for line in explanation.explanation.technical_details.lines() {
            println!("  {}", line);
        }
        println!();

        // Attack Scenario
        println!("{}", "Attack Scenario:".red().bold());
        for line in explanation.explanation.attack_scenario.lines() {
            println!("  {}", line);
        }
        println!();

        // Impact
        println!("{}", "Impact:".yellow().bold());
        println!("  {}", explanation.explanation.impact);
        println!(
            "  Likelihood: {}",
            format!("{:?}", explanation.explanation.likelihood).magenta()
        );
        println!();

        // Remediation
        println!("{}", "Remediation:".green().bold());
        println!("  {} Immediate Actions:", "→".cyan());
        for action in &explanation.remediation.immediate_actions {
            println!("    • {}", action);
        }
        println!();
        println!("  {} Permanent Fix:", "→".cyan());
        for line in explanation.remediation.permanent_fix.lines() {
            println!("    {}", line);
        }
        println!();

        // Code Example (if present)
        if let Some(ref code) = explanation.remediation.code_example {
            println!("{}", "Code Example:".green().bold());
            println!("  Language: {}", code.language.cyan());
            println!();
            println!("  {} Before (Vulnerable):", "✗".red());
            for line in code.before.lines() {
                println!("    {}", line.red());
            }
            println!();
            println!("  {} After (Fixed):", "✓".green());
            for line in code.after.lines() {
                println!("    {}", line.green());
            }
            if !code.explanation.is_empty() {
                println!();
                println!("  Explanation: {}", code.explanation);
            }
            println!();
        }

        // Verification
        if !explanation.remediation.verification.is_empty() {
            println!("{}", "Verification Steps:".green().bold());
            for step in &explanation.remediation.verification {
                println!("  ☐ {}", step);
            }
            println!();
        }

        // Educational Context (if present)
        if let Some(ref edu) = explanation.education {
            println!("{}", "Educational Context:".blue().bold());

            if !edu.related_weaknesses.is_empty() {
                println!("  Related CWEs:");
                for weakness in &edu.related_weaknesses {
                    println!(
                        "    • {}: {} - {}",
                        weakness.cwe_id.cyan(),
                        weakness.name,
                        weakness.description
                    );
                }
            }

            if !edu.best_practices.is_empty() {
                println!("  Best Practices:");
                for practice in &edu.best_practices {
                    println!("    • {}", practice);
                }
            }

            if !edu.resources.is_empty() {
                println!("  Resources:");
                for resource in &edu.resources {
                    println!("    • {} - {}", resource.title, resource.url);
                }
            }
            println!();
        }

        // Metadata
        if explanation.metadata.response_time_ms > 0 {
            println!(
                "{}",
                format!(
                    "Generated by {} ({}) in {}ms",
                    explanation.metadata.provider,
                    explanation.metadata.model,
                    explanation.metadata.response_time_ms
                )
                .bright_black()
            );
        }

        if idx < explanations.len() - 1 {
            println!();
        }
    }

    println!("{}", "═".repeat(80).cyan());

    Ok(())
}

/// Print explanations in JSON format
fn print_explanations_json(explanations: &[ExplanationResponse]) -> Result<()> {
    let json = serde_json::to_string_pretty(explanations)?;
    println!("{}", json);
    Ok(())
}

/// Print engine statistics
fn print_stats(stats: &EngineStats) {
    println!();
    println!("{}", "Statistics:".bright_black());
    println!(
        "  Total: {} | Cache: {:.0}% ({}/{}) | API calls: {} | Tokens: {} | Avg time: {}ms",
        stats.total_explanations,
        stats.cache_hit_rate(),
        stats.cache_hits,
        stats.cache_hits + stats.cache_misses,
        stats.api_calls,
        stats.tokens_used,
        stats.avg_response_time_ms()
    );
}

/// Run interactive follow-up mode
async fn run_interactive_mode(
    engine: &ExplainEngine,
    explanations: &[ExplanationResponse],
) -> Result<()> {
    println!();
    println!("{}", "═".repeat(80).magenta());
    println!(
        "{}",
        "Interactive Mode - Ask follow-up questions about the findings"
            .magenta()
            .bold()
    );
    println!("{}", "─".repeat(80));
    println!();

    // Show available findings
    println!("{}", "Available findings:".cyan());
    for (idx, exp) in explanations.iter().enumerate() {
        println!(
            "  [{}] {} - {}",
            (idx + 1).to_string().yellow(),
            exp.rule_id.cyan(),
            truncate_str(&exp.explanation.summary, 50)
        );
    }
    println!();
    println!("{}", "Commands:".cyan());
    println!(
        "  {} - Select finding to ask about (e.g., '1')",
        "number".yellow()
    );
    println!("  {} - Quit interactive mode", "q/quit/exit".yellow());
    println!();

    let stdin = io::stdin();
    let mut current_explanation: Option<&ExplanationResponse> = None;

    loop {
        // Show prompt
        if let Some(exp) = current_explanation {
            print!(
                "{} {} {} ",
                "mcplint".cyan(),
                format!("[{}]", exp.rule_id).yellow(),
                ">".green()
            );
        } else {
            print!("{} {} ", "mcplint".cyan(), ">".green());
        }
        io::stdout().flush()?;

        // Read input
        let mut input = String::new();
        stdin.lock().read_line(&mut input)?;
        let input = input.trim();

        // Handle empty input
        if input.is_empty() {
            continue;
        }

        // Handle quit commands
        if matches!(input.to_lowercase().as_str(), "q" | "quit" | "exit") {
            println!("{}", "Exiting interactive mode.".bright_black());
            break;
        }

        // Handle help
        if matches!(input.to_lowercase().as_str(), "h" | "help" | "?") {
            println!();
            println!("{}", "Interactive Mode Help:".cyan().bold());
            println!("  {} - Select a finding by number", "1, 2, 3...".yellow());
            println!(
                "  {} - After selecting, type your question",
                "any text".yellow()
            );
            println!("  {} - List available findings", "list".yellow());
            println!("  {} - Clear current finding selection", "clear".yellow());
            println!("  {} - Exit interactive mode", "q/quit/exit".yellow());
            println!();
            continue;
        }

        // Handle list command
        if input.to_lowercase() == "list" {
            println!();
            println!("{}", "Available findings:".cyan());
            for (idx, exp) in explanations.iter().enumerate() {
                let marker = if current_explanation
                    .map(|e| e.finding_id == exp.finding_id)
                    .unwrap_or(false)
                {
                    "→".green()
                } else {
                    " ".normal()
                };
                println!(
                    " {} [{}] {} - {}",
                    marker,
                    (idx + 1).to_string().yellow(),
                    exp.rule_id.cyan(),
                    truncate_str(&exp.explanation.summary, 50)
                );
            }
            println!();
            continue;
        }

        // Handle clear command
        if input.to_lowercase() == "clear" {
            current_explanation = None;
            println!("{}", "Cleared finding selection.".bright_black());
            continue;
        }

        // Try to parse as finding number
        if let Ok(num) = input.parse::<usize>() {
            if num >= 1 && num <= explanations.len() {
                current_explanation = Some(&explanations[num - 1]);
                println!(
                    "{}",
                    format!(
                        "Selected: {} - {}",
                        explanations[num - 1].rule_id,
                        truncate_str(&explanations[num - 1].explanation.summary, 60)
                    )
                    .green()
                );
                println!(
                    "{}",
                    "Now you can ask questions about this finding.".bright_black()
                );
                continue;
            } else {
                println!(
                    "{}",
                    format!("Invalid finding number. Use 1-{}.", explanations.len()).red()
                );
                continue;
            }
        }

        // Handle as a question
        if let Some(exp) = current_explanation {
            println!();
            println!("{}", "Asking AI...".bright_black());

            match engine.ask_followup(exp, input).await {
                Ok(response) => {
                    println!();
                    println!("{}", "Answer:".green().bold());
                    for line in response.lines() {
                        println!("  {}", line);
                    }
                    println!();
                }
                Err(e) => {
                    println!("{}", format!("Error getting response: {}", e).red());
                }
            }
        } else {
            println!(
                "{}",
                "Please select a finding first (enter a number 1-N), or type 'help' for commands."
                    .yellow()
            );
        }
    }

    Ok(())
}

/// Truncate a string with ellipsis
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_provider_conversion() {
        assert!(matches!(
            AiProviderType::from(CliAiProvider::Anthropic),
            AiProviderType::Anthropic
        ));
        assert!(matches!(
            AiProviderType::from(CliAiProvider::Openai),
            AiProviderType::OpenAI
        ));
        assert!(matches!(
            AiProviderType::from(CliAiProvider::Ollama),
            AiProviderType::Ollama
        ));
    }

    #[test]
    fn cli_audience_conversion() {
        assert!(matches!(
            AudienceLevel::from(CliAudienceLevel::Beginner),
            AudienceLevel::Beginner
        ));
        assert!(matches!(
            AudienceLevel::from(CliAudienceLevel::Intermediate),
            AudienceLevel::Intermediate
        ));
        assert!(matches!(
            AudienceLevel::from(CliAudienceLevel::Expert),
            AudienceLevel::Expert
        ));
    }
}
