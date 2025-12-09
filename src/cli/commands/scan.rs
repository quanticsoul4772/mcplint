//! Scan command - Security vulnerability scanning

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use colored::Colorize;
use tracing::{debug, info};

use crate::ai::{ExplainEngine, ExplanationContext};
use crate::baseline::{Baseline, DiffEngine};
use crate::cache::{CacheConfig, CacheManager};
use crate::cli::commands::explain::{build_ai_config, CliAiProvider};
use crate::reporter::{generate_gitlab, generate_junit};
use crate::scanner::{ScanConfig, ScanEngine, ScanProfile, Severity};
use crate::{OutputFormat, ScanProfile as CliScanProfile};

/// Arguments for the scan command
pub struct ScanArgs {
    /// Server executable path
    pub server: String,
    /// Arguments to pass to the server
    pub args: Vec<String>,
    /// Scan options
    pub options: ScanOptions,
    /// Output options
    pub output: OutputOptions,
    /// Baseline options
    pub baseline: BaselineOptions,
    /// AI explanation options
    pub ai: AiOptions,
}

/// Scan configuration options
pub struct ScanOptions {
    /// Scan profile
    pub profile: CliScanProfile,
    /// Categories to include
    pub include: Option<Vec<String>>,
    /// Categories to exclude
    pub exclude: Option<Vec<String>>,
    /// Timeout in seconds
    pub timeout: u64,
}

/// Output configuration options
pub struct OutputOptions {
    /// Output format
    pub format: OutputFormat,
    /// Severities to fail on
    pub fail_on: Option<Vec<Severity>>,
}

/// Baseline comparison options
pub struct BaselineOptions {
    /// Path to baseline file for comparison
    pub baseline_path: Option<PathBuf>,
    /// Path to save new baseline
    pub save_baseline: Option<PathBuf>,
    /// Whether to update existing baseline
    pub update_baseline: bool,
    /// Show only diff summary
    pub diff_only: bool,
}

/// AI explanation options
pub struct AiOptions {
    /// Whether to generate AI explanations
    pub explain: bool,
    /// AI provider
    pub provider: CliAiProvider,
    /// AI model
    pub model: Option<String>,
}

impl ScanArgs {
    /// Create ScanArgs from individual parameters (for CLI compatibility)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        args: Vec<String>,
        profile: CliScanProfile,
        include: Option<Vec<String>>,
        exclude: Option<Vec<String>>,
        timeout: u64,
        format: OutputFormat,
        explain: bool,
        ai_provider: CliAiProvider,
        ai_model: Option<String>,
        baseline_path: Option<PathBuf>,
        save_baseline: Option<PathBuf>,
        update_baseline: bool,
        diff_only: bool,
        fail_on: Option<Vec<Severity>>,
    ) -> Self {
        Self {
            server,
            args,
            options: ScanOptions {
                profile,
                include,
                exclude,
                timeout,
            },
            output: OutputOptions { format, fail_on },
            baseline: BaselineOptions {
                baseline_path,
                save_baseline,
                update_baseline,
                diff_only,
            },
            ai: AiOptions {
                explain,
                provider: ai_provider,
                model: ai_model,
            },
        }
    }
}

/// Run the scan command with the given arguments
pub async fn run(args: ScanArgs) -> Result<()> {
    let ScanArgs {
        server,
        args: server_args,
        options,
        output,
        baseline,
        ai,
    } = args;
    info!("Scanning MCP server: {}", server);
    debug!(
        "Profile: {:?}, Include: {:?}, Exclude: {:?}, Timeout: {}s, Explain: {}",
        options.profile, options.include, options.exclude, options.timeout, ai.explain
    );

    let profile_name = options.profile.as_str();
    let scan_profile: ScanProfile = options.profile.into();

    // Only show banner for text output
    if matches!(output.format, OutputFormat::Text) {
        println!("{}", "Starting security scan...".cyan());
        println!("  Server: {}", server.yellow());
        println!("  Profile: {}", profile_name.green());
        if let Some(ref path) = baseline.baseline_path {
            println!("  Baseline: {}", path.display().to_string().yellow());
        }
        if ai.explain {
            println!("  AI Explanations: {}", "Enabled".green());
        }
        println!();
    }

    // Build scan configuration
    let mut config = ScanConfig::default()
        .with_profile(scan_profile)
        .with_timeout(options.timeout);

    if let Some(inc) = options.include {
        config = config.with_include_categories(inc);
    }

    if let Some(exc) = options.exclude {
        config = config.with_exclude_categories(exc);
    }

    // Create engine and run scan
    let engine = ScanEngine::new(config);
    let results = engine.scan(&server, &server_args, None).await?;

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
    if ai.explain && !results.findings.is_empty() {
        generate_ai_explanations(&results, ai.provider, ai.model, &server).await?;
    }

    // Determine exit code
    let exit_code = determine_exit_code(&results, &diff_result, &output.fail_on);
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
    ai_provider: CliAiProvider,
    ai_model: Option<String>,
    server: &str,
) -> Result<()> {
    println!();
    println!("{}", "Generating AI explanations...".cyan());
    println!();

    // Build AI configuration using shared function
    let ai_config = match build_ai_config(ai_provider, ai_model, 120) {
        Ok(config) => config,
        Err(e) => {
            println!("{}", format!("Failed to build AI config: {}", e).red());
            return Ok(());
        }
    };

    // Create explain engine
    let mut explain_engine = match ExplainEngine::new(ai_config) {
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

/// Create default scan options
impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            profile: CliScanProfile::Standard,
            include: None,
            exclude: None,
            timeout: 30,
        }
    }
}

/// Create default output options
impl Default for OutputOptions {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            fail_on: None,
        }
    }
}

/// Create default baseline options
impl Default for BaselineOptions {
    fn default() -> Self {
        Self {
            baseline_path: None,
            save_baseline: None,
            update_baseline: false,
            diff_only: false,
        }
    }
}

/// Create default AI options
impl Default for AiOptions {
    fn default() -> Self {
        Self {
            explain: false,
            provider: CliAiProvider::Ollama,
            model: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Finding, ScanResults, ScanSummary};

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
    fn scan_options_default() {
        let opts = ScanOptions::default();
        assert!(matches!(opts.profile, CliScanProfile::Standard));
        assert!(opts.include.is_none());
        assert!(opts.exclude.is_none());
        assert_eq!(opts.timeout, 30);
    }

    #[test]
    fn output_options_default() {
        let opts = OutputOptions::default();
        assert!(matches!(opts.format, OutputFormat::Text));
        assert!(opts.fail_on.is_none());
    }

    #[test]
    fn baseline_options_default() {
        let opts = BaselineOptions::default();
        assert!(opts.baseline_path.is_none());
        assert!(opts.save_baseline.is_none());
        assert!(!opts.update_baseline);
        assert!(!opts.diff_only);
    }

    #[test]
    fn ai_options_default() {
        let opts = AiOptions::default();
        assert!(!opts.explain);
        assert!(matches!(opts.provider, CliAiProvider::Ollama));
        assert!(opts.model.is_none());
    }

    #[test]
    fn scan_args_new_creates_args() {
        let args = ScanArgs::new(
            "server".to_string(),
            vec!["arg1".to_string()],
            CliScanProfile::Full,
            Some(vec!["injection".to_string()]),
            Some(vec!["dos".to_string()]),
            60,
            OutputFormat::Json,
            true,
            CliAiProvider::Anthropic,
            Some("claude-3".to_string()),
            Some(PathBuf::from("baseline.json")),
            None,
            false,
            false,
            Some(vec![Severity::Critical]),
        );

        assert_eq!(args.server, "server");
        assert_eq!(args.args.len(), 1);
        assert!(matches!(args.options.profile, CliScanProfile::Full));
        assert!(args.options.include.is_some());
        assert!(args.options.exclude.is_some());
        assert_eq!(args.options.timeout, 60);
        assert!(matches!(args.output.format, OutputFormat::Json));
        assert!(args.ai.explain);
        assert!(matches!(args.ai.provider, CliAiProvider::Anthropic));
        assert_eq!(args.ai.model, Some("claude-3".to_string()));
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

    #[test]
    fn scan_args_baseline_options() {
        let args = ScanArgs::new(
            "server".to_string(),
            vec![],
            CliScanProfile::Quick,
            None,
            None,
            30,
            OutputFormat::Text,
            false,
            CliAiProvider::Ollama,
            None,
            Some(PathBuf::from("old_baseline.json")),
            Some(PathBuf::from("new_baseline.json")),
            true,
            true,
            None,
        );

        assert!(args.baseline.baseline_path.is_some());
        assert!(args.baseline.save_baseline.is_some());
        assert!(args.baseline.update_baseline);
        assert!(args.baseline.diff_only);
    }
}
