//! Scan command - Security vulnerability scanning

use std::sync::Arc;

use anyhow::Result;
use colored::Colorize;
use tracing::{debug, info};

use crate::ai::{AiConfig, AiProviderType, ExplainEngine, ExplanationContext};
use crate::cache::{CacheConfig, CacheManager};
use crate::cli::commands::explain::CliAiProvider;
use crate::scanner::{ScanConfig, ScanEngine, ScanProfile};
use crate::{OutputFormat, ScanProfile as CliScanProfile};

pub async fn run(
    server: &str,
    args: &[String],
    profile: CliScanProfile,
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    timeout: u64,
    format: OutputFormat,
    explain: bool,
    ai_provider: CliAiProvider,
    ai_model: Option<String>,
) -> Result<()> {
    info!("Scanning MCP server: {}", server);
    debug!(
        "Profile: {:?}, Include: {:?}, Exclude: {:?}, Timeout: {}s, Explain: {}",
        profile, include, exclude, timeout, explain
    );

    let profile_name = match profile {
        CliScanProfile::Quick => "Quick",
        CliScanProfile::Standard => "Standard",
        CliScanProfile::Full => "Full",
        CliScanProfile::Enterprise => "Enterprise",
    };

    let scan_profile = match profile {
        CliScanProfile::Quick => ScanProfile::Quick,
        CliScanProfile::Standard => ScanProfile::Standard,
        CliScanProfile::Full => ScanProfile::Full,
        CliScanProfile::Enterprise => ScanProfile::Enterprise,
    };

    // Only show banner for text output
    if matches!(format, OutputFormat::Text) {
        println!("{}", "Starting security scan...".cyan());
        println!("  Server: {}", server.yellow());
        println!("  Profile: {}", profile_name.green());
        if explain {
            println!("  AI Explanations: {}", "Enabled".green());
        }
        println!();
    }

    // Build scan configuration
    let mut config = ScanConfig::default()
        .with_profile(scan_profile)
        .with_timeout(timeout);

    if let Some(inc) = include {
        config = config.with_include_categories(inc);
    }

    if let Some(exc) = exclude {
        config = config.with_exclude_categories(exc);
    }

    // Create engine and run scan
    let engine = ScanEngine::new(config);
    let results = engine.scan(server, args, None).await?;

    // Output results
    match format {
        OutputFormat::Text => {
            results.print_text();
        }
        OutputFormat::Json => {
            results.print_json()?;
        }
        OutputFormat::Sarif => {
            results.print_sarif()?;
        }
    }

    // Generate AI explanations if requested
    if explain && !results.findings.is_empty() {
        println!();
        println!("{}", "Generating AI explanations...".cyan());
        println!();

        // Build AI configuration
        let provider_type: AiProviderType = ai_provider.into();
        let mut ai_config = AiConfig::builder().provider(provider_type);

        if let Some(model) = ai_model {
            ai_config = ai_config.model(&model);
        }

        // Set API key from environment
        match provider_type {
            AiProviderType::Anthropic => {
                if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
                    ai_config = ai_config.api_key(&key);
                }
            }
            AiProviderType::OpenAI => {
                if let Ok(key) = std::env::var("OPENAI_API_KEY") {
                    ai_config = ai_config.api_key(&key);
                }
            }
            AiProviderType::Ollama => {
                if let Ok(url) = std::env::var("OLLAMA_HOST") {
                    ai_config = ai_config.base_url(&url);
                }
            }
        }

        let ai_config = ai_config.build();

        // Create explain engine
        let mut explain_engine = match ExplainEngine::new(ai_config) {
            Ok(engine) => engine,
            Err(e) => {
                println!("{}", format!("Failed to initialize AI engine: {}", e).red());
                if results.has_critical_or_high() {
                    std::process::exit(1);
                }
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
    }

    // Return error code if critical/high findings
    if results.has_critical_or_high() {
        std::process::exit(1);
    }

    Ok(())
}
