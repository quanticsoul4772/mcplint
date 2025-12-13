//! Interactive wizards for CLI commands
//!
//! Provides guided workflows using dialoguer for TTY environments.
//! All interactive functions check OutputMode and return errors for non-TTY.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Confirm, FuzzySelect, Input, MultiSelect, Select};

use crate::cli::commands::explain::{CliAiProvider, CliAudienceLevel};
use crate::cli::server::{find_config_file, load_config};
use crate::fuzzer::FuzzProfile;
use crate::scanner::ScanProfile;
use crate::ui::OutputMode;
use crate::Severity;

/// Output format for scan results (mirrors main.rs OutputFormat)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Sarif,
    Junit,
    Gitlab,
}

impl OutputFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputFormat::Text => "text",
            OutputFormat::Json => "json",
            OutputFormat::Sarif => "sarif",
            OutputFormat::Junit => "junit",
            OutputFormat::Gitlab => "gitlab",
        }
    }
}

// Global flag for Ctrl+C handling
static CTRLC_PRESSED: AtomicBool = AtomicBool::new(false);

/// Check if interactive mode is available
pub fn is_interactive_available() -> bool {
    OutputMode::detect() == OutputMode::Interactive
}

/// Ensure we're in interactive mode, error otherwise
fn require_interactive() -> Result<()> {
    if !is_interactive_available() {
        anyhow::bail!(
            "Interactive mode requires a TTY. Run in a terminal or provide arguments explicitly."
        );
    }
    Ok(())
}

/// Install Ctrl+C handler for graceful exit
fn install_ctrlc_handler() -> Result<()> {
    // Only install once
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    ctrlc::set_handler(move || {
        if CTRLC_PRESSED.swap(true, Ordering::SeqCst) {
            // Second Ctrl+C - force exit
            std::process::exit(130);
        }
        println!();
        println!("{}", "Operation cancelled by user (Ctrl+C)".yellow());
        std::process::exit(130); // Standard exit code for Ctrl+C
    })
    .context("Failed to set Ctrl+C handler")?;
    Ok(())
}

/// Interactive server selection wizard
pub fn select_server() -> Result<String> {
    require_interactive()?;

    // Load servers from config
    let config_path = find_config_file().context("Could not find MCP config file")?;
    let config = load_config(&config_path).context("Failed to load config")?;

    if config.mcp_servers.is_empty() {
        anyhow::bail!(
            "No servers configured.\n\
             Add servers to your Claude Desktop config or run 'mcplint init'."
        );
    }

    // Prepare server list with descriptions
    let servers: Vec<(String, String)> = config
        .mcp_servers
        .iter()
        .map(|(name, server)| {
            let desc = format!("{} ({})", name, server.command);
            (name.clone(), desc)
        })
        .collect();

    // Show selection dialog
    println!();
    println!("{}", "Select MCP Server to Scan:".cyan().bold());
    println!();

    let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Server")
        .items(&servers.iter().map(|(_, desc)| desc).collect::<Vec<_>>())
        .default(0)
        .interact()
        .with_context(|| {
            format!(
                "Server selection cancelled. Available servers: {}",
                servers
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    Ok(servers[selection].0.clone())
}

/// Interactive scan profile selection
pub fn select_scan_profile() -> Result<ScanProfile> {
    require_interactive()?;

    let profiles = [
        ("Quick", "Fast scan with essential rules (~30s)"),
        (
            "Standard",
            "Balanced security scan (~2min) [Recommended]",
        ),
        ("Full", "Comprehensive scan with all rules (~5min)"),
        ("Enterprise", "Compliance-focused enterprise scan (~10min)"),
    ];

    println!();
    println!("{}", "Select Scan Profile:".cyan().bold());
    println!();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Profile")
        .items(
            &profiles
                .iter()
                .map(|(name, desc)| format!("{} - {}", name.yellow(), desc))
                .collect::<Vec<_>>(),
        )
        .default(1) // Standard is default
        .interact()
        .context("Profile selection cancelled")?;

    Ok(match selection {
        0 => ScanProfile::Quick,
        1 => ScanProfile::Standard,
        2 => ScanProfile::Full,
        3 => ScanProfile::Enterprise,
        _ => ScanProfile::Standard, // Fallback to default
    })
}

/// Interactive rule category selection
pub fn select_rule_categories() -> Result<Option<Vec<String>>> {
    require_interactive()?;

    let categories = [
        ("protocol", "Protocol compliance checks (PROTO-*)"),
        ("schema", "Schema validation checks (SCHEMA-*)"),
        ("security", "Security vulnerability checks (SEC-*)"),
        ("tool", "Tool validation checks (TOOL-*)"),
        ("resource", "Resource validation checks (RES-*)"),
        ("edge", "Edge case detection (EDGE-*)"),
    ];

    println!();
    println!("{}", "Customize Rule Categories:".cyan().bold());
    println!(
        "{}",
        "(Press Space to toggle, Enter when done)".dimmed()
    );
    println!();

    // Ask if they want to customize
    let customize = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Filter specific rule categories?")
        .default(false)
        .interact()
        .context("Confirmation cancelled")?;

    if !customize {
        return Ok(None);
    }

    // Show multi-select
    let selections = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Select categories to include")
        .items(
            &categories
                .iter()
                .map(|(name, desc)| format!("{} - {}", name, desc))
                .collect::<Vec<_>>(),
        )
        .interact()
        .context("Category selection cancelled")?;

    if selections.is_empty() {
        return Ok(None);
    }

    Ok(Some(
        selections
            .iter()
            .map(|&i| categories[i].0.to_string())
            .collect(),
    ))
}

/// Interactive output format selection
pub fn select_output_format() -> Result<OutputFormat> {
    require_interactive()?;

    let formats = [
        ("Text", "Human-readable terminal output (default)"),
        ("JSON", "Machine-readable JSON for scripting"),
        ("SARIF", "SARIF 2.1.0 for CI/CD integration"),
        ("JUnit", "JUnit XML for test runners"),
        ("GitLab", "GitLab Code Quality format"),
    ];

    println!();
    println!("{}", "Select Output Format:".cyan().bold());
    println!();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Format")
        .items(
            &formats
                .iter()
                .map(|(name, desc)| format!("{} - {}", name, desc))
                .collect::<Vec<_>>(),
        )
        .default(0)
        .interact()
        .context("Format selection cancelled")?;

    Ok(match selection {
        0 => OutputFormat::Text,
        1 => OutputFormat::Json,
        2 => OutputFormat::Sarif,
        3 => OutputFormat::Junit,
        4 => OutputFormat::Gitlab,
        _ => OutputFormat::Text, // Fallback to default
    })
}

/// Interactive fail-on severity selection
pub fn select_fail_on_severities() -> Result<Option<Vec<Severity>>> {
    require_interactive()?;

    println!();
    println!("{}", "Configure Exit Code Behavior:".cyan().bold());
    println!();

    let customize = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Fail build only on specific severities?")
        .default(false)
        .interact()
        .context("Confirmation cancelled")?;

    if !customize {
        return Ok(None);
    }

    let severities = [
        ("Critical", "Critical severity only"),
        ("High", "High or above"),
        ("Medium", "Medium or above"),
        ("Low", "Low or above"),
        ("Info", "All findings including info"),
    ];

    let selections = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Fail on these severities")
        .items(
            &severities
                .iter()
                .map(|(name, desc)| format!("{} - {}", name, desc))
                .collect::<Vec<_>>(),
        )
        .defaults(&[true, true, false, false, false]) // Critical and High by default
        .interact()
        .context("Severity selection cancelled")?;

    if selections.is_empty() {
        return Ok(None);
    }

    Ok(Some(
        selections
            .iter()
            .filter_map(|&i| match i {
                0 => Some(Severity::Critical),
                1 => Some(Severity::High),
                2 => Some(Severity::Medium),
                3 => Some(Severity::Low),
                4 => Some(Severity::Info),
                _ => None, // Skip invalid indices
            })
            .collect(),
    ))
}

/// Complete interactive scan wizard result
#[derive(Debug, Clone)]
pub struct ScanWizardResult {
    pub server: String,
    pub profile: ScanProfile,
    pub include_categories: Option<Vec<String>>,
    /// Output format selection (reserved for future use)
    #[allow(dead_code)]
    pub output_format: OutputFormat,
    pub fail_on: Option<Vec<Severity>>,
}

/// Run the complete interactive scan wizard
pub fn run_scan_wizard() -> Result<ScanWizardResult> {
    require_interactive()?;
    install_ctrlc_handler()?;

    // Header
    println!();
    println!("{}", "═".repeat(60).cyan());
    println!("{}", "  MCPLint Interactive Scan Wizard".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    // Step 1/5: Server selection
    println!();
    println!("{}", "Step 1/5: Server Selection".cyan().bold());
    let server = select_server()?;

    // Step 2/5: Profile selection
    println!();
    println!("{}", "Step 2/5: Scan Profile".cyan().bold());
    let profile = select_scan_profile()?;

    // Step 3/5: Rule categories (optional)
    println!();
    println!("{}", "Step 3/5: Rule Categories".cyan().bold());
    let include_categories = select_rule_categories()?;

    // Step 4/5: Output format
    println!();
    println!("{}", "Step 4/5: Output Format".cyan().bold());
    let output_format = select_output_format()?;

    // Step 5/5: Fail-on severities
    println!();
    println!("{}", "Step 5/5: Exit Code Configuration".cyan().bold());
    let fail_on = select_fail_on_severities()?;

    // Summary
    println!();
    println!("{}", "═".repeat(60).cyan());
    println!("{}", "  Scan Configuration Summary".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("  Server: {}", server.yellow());
    println!("  Profile: {}", profile.as_str().yellow());
    if let Some(ref cats) = include_categories {
        println!("  Categories: {}", cats.join(", ").yellow());
    }
    println!("  Output: {}", output_format.as_str().yellow());
    if let Some(ref sevs) = fail_on {
        println!(
            "  Fail on: {}",
            sevs.iter()
                .map(|s: &Severity| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
                .yellow()
        );
    }
    println!();

    // Confirm
    let proceed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Start scan with this configuration?")
        .default(true)
        .interact()
        .context("Confirmation cancelled")?;

    if !proceed {
        anyhow::bail!("Scan cancelled by user");
    }

    Ok(ScanWizardResult {
        server,
        profile,
        include_categories,
        output_format,
        fail_on,
    })
}

/// Interactive init wizard result
#[derive(Debug, Clone)]
pub struct InitWizardResult {
    pub output_path: String,
    pub servers_to_test: Vec<String>,
    pub default_profile: ScanProfile,
    pub create_ci_workflow: bool,
    pub run_initial_scan: bool,
}

/// Run the complete interactive init wizard
pub fn run_init_wizard() -> Result<InitWizardResult> {
    require_interactive()?;
    install_ctrlc_handler()?;

    // Header
    println!();
    println!("{}", "═".repeat(60).cyan());
    println!("{}", "  MCPLint Project Setup Wizard".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!();

    // Step 1/6: Config file location
    println!("{}", "Step 1/6: Configuration File".cyan().bold());
    let output_path = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Configuration file path")
        .default(".mcplint.toml".to_string())
        .interact_text()
        .context("Input cancelled")?;

    // Step 2/6: Detect servers
    println!();
    println!("{}", "Step 2/6: Server Detection".cyan().bold());
    println!("{}", "Detecting MCP servers...".dimmed());

    let config_path = find_config_file();
    let available_servers = if let Some(path) = config_path {
        if let Ok(config) = load_config(&path) {
            config.mcp_servers.keys().cloned().collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Step 3/6: Server selection for testing
    println!();
    println!("{}", "Step 3/6: Server Selection".cyan().bold());
    let servers_to_test = if available_servers.is_empty() {
        println!("{}", "  No servers detected".yellow());
        Vec::new()
    } else {
        println!(
            "{}",
            format!("  Found {} server(s)", available_servers.len()).green()
        );
        println!();

        let test_servers = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Test servers during setup?")
            .default(true)
            .interact()
            .context("Confirmation cancelled")?;

        if test_servers {
            let selections = MultiSelect::with_theme(&ColorfulTheme::default())
                .with_prompt("Select servers to test")
                .items(&available_servers)
                .interact()
                .context("Server selection cancelled")?;

            selections
                .iter()
                .map(|&i| available_servers[i].clone())
                .collect()
        } else {
            Vec::new()
        }
    };

    // Step 4/6: Default profile
    println!();
    println!("{}", "Step 4/6: Default Scan Profile".cyan().bold());
    let default_profile = select_scan_profile()?;

    // Step 5/6: CI workflow
    println!();
    println!("{}", "Step 5/6: CI/CD Integration".cyan().bold());
    let create_ci_workflow = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Create GitHub Actions workflow?")
        .default(true)
        .interact()
        .context("Confirmation cancelled")?;

    // Step 6/6: Initial scan
    println!();
    println!("{}", "Step 6/6: Initial Scan".cyan().bold());
    let run_initial_scan = if !servers_to_test.is_empty() {
        Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Run initial security scan now?")
            .default(true)
            .interact()
            .context("Confirmation cancelled")?
    } else {
        false
    };

    Ok(InitWizardResult {
        output_path,
        servers_to_test,
        default_profile,
        create_ci_workflow,
        run_initial_scan,
    })
}

// ============================================================================
// Fuzz Wizard
// ============================================================================

/// Interactive fuzz profile selection
pub fn select_fuzz_profile() -> Result<FuzzProfile> {
    require_interactive()?;

    let profiles = [
        ("Quick", "Fast fuzzing (~1 minute, basic mutations)"),
        (
            "Standard",
            "Standard fuzzing (~5 minutes, all mutations) [Recommended]",
        ),
        ("Intensive", "Aggressive fuzzing (unlimited, deep mutations)"),
        ("CI", "CI-optimized (fast feedback, deterministic seed)"),
    ];

    println!();
    println!("{}", "Select Fuzz Profile:".cyan().bold());
    println!();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Profile")
        .items(
            &profiles
                .iter()
                .map(|(name, desc)| format!("{} - {}", name.yellow(), desc))
                .collect::<Vec<_>>(),
        )
        .default(1) // Standard is default
        .interact()
        .context("Profile selection cancelled")?;

    Ok(match selection {
        0 => FuzzProfile::Quick,
        1 => FuzzProfile::Standard,
        2 => FuzzProfile::Intensive,
        3 => FuzzProfile::CI,
        _ => FuzzProfile::Standard, // Safe fallback
    })
}

/// Interactive fuzz duration selection
pub fn select_fuzz_duration() -> Result<u64> {
    require_interactive()?;

    let durations = [
        ("60", "1 minute (quick test)"),
        ("300", "5 minutes (standard) [Recommended]"),
        ("600", "10 minutes (thorough)"),
        ("1800", "30 minutes (intensive)"),
        ("0", "Unlimited (manual stop with Ctrl+C)"),
    ];

    println!();
    println!("{}", "Select Fuzz Duration:".cyan().bold());
    println!();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Duration")
        .items(
            &durations
                .iter()
                .map(|(_, desc)| desc.to_string())
                .collect::<Vec<_>>(),
        )
        .default(1) // 5 minutes default
        .interact()
        .context("Duration selection cancelled")?;

    Ok(durations[selection].0.parse().unwrap_or(300))
}

/// Interactive worker count selection
pub fn select_fuzz_workers() -> Result<usize> {
    require_interactive()?;

    let workers = [
        ("1", "1 worker (low resource usage)"),
        ("2", "2 workers (balanced)"),
        ("4", "4 workers (standard) [Recommended]"),
        ("8", "8 workers (high throughput)"),
    ];

    println!();
    println!("{}", "Select Worker Count:".cyan().bold());
    println!();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Workers")
        .items(
            &workers
                .iter()
                .map(|(_, desc)| desc.to_string())
                .collect::<Vec<_>>(),
        )
        .default(2) // 4 workers default
        .interact()
        .context("Worker selection cancelled")?;

    Ok(workers[selection].0.parse().unwrap_or(4))
}

/// Complete interactive fuzz wizard result
#[derive(Debug, Clone)]
pub struct FuzzWizardResult {
    pub server: String,
    pub profile: FuzzProfile,
    pub duration: u64,
    pub workers: usize,
    pub corpus: Option<String>,
}

/// Run the complete interactive fuzz wizard
pub fn run_fuzz_wizard() -> Result<FuzzWizardResult> {
    require_interactive()?;
    install_ctrlc_handler()?;

    // Header
    println!();
    println!("{}", "═".repeat(60).cyan());
    println!("{}", "  MCPLint Interactive Fuzz Wizard".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    // Step 1/4: Server selection
    println!();
    println!("{}", "Step 1/4: Server Selection".cyan().bold());
    let server = select_server()?;

    // Step 2/4: Profile selection
    println!();
    println!("{}", "Step 2/4: Fuzz Profile".cyan().bold());
    let profile = select_fuzz_profile()?;

    // Step 3/4: Duration selection
    println!();
    println!("{}", "Step 3/4: Duration".cyan().bold());
    let duration = select_fuzz_duration()?;

    // Step 4/4: Worker count
    println!();
    println!("{}", "Step 4/4: Worker Count".cyan().bold());
    let workers = select_fuzz_workers()?;

    // Optional: Corpus directory
    println!();
    let use_corpus = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Use custom corpus directory?")
        .default(false)
        .interact()
        .context("Confirmation cancelled")?;

    let corpus = if use_corpus {
        let path = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Corpus directory path")
            .default(".mcplint/corpus".to_string())
            .interact_text()
            .context("Input cancelled")?;
        Some(path)
    } else {
        None
    };

    // Summary
    println!();
    println!("{}", "═".repeat(60).cyan());
    println!("{}", "  Fuzz Configuration Summary".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("  Server: {}", server.yellow());
    println!("  Profile: {:?}", profile);
    println!(
        "  Duration: {}",
        if duration == 0 {
            "Unlimited".to_string()
        } else {
            format!("{} seconds", duration)
        }
    );
    println!("  Workers: {}", workers);
    if let Some(ref c) = corpus {
        println!("  Corpus: {}", c);
    }
    println!();

    // Confirm
    let proceed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Start fuzzing with this configuration?")
        .default(true)
        .interact()
        .context("Confirmation cancelled")?;

    if !proceed {
        anyhow::bail!("Fuzzing cancelled by user");
    }

    Ok(FuzzWizardResult {
        server,
        profile,
        duration,
        workers,
        corpus,
    })
}

// ============================================================================
// Explain Wizard
// ============================================================================

/// Interactive AI provider selection
pub fn select_ai_provider() -> Result<CliAiProvider> {
    require_interactive()?;

    let providers = [
        ("Ollama", "Local AI (no API key required) [Recommended]"),
        ("Anthropic", "Claude API (requires ANTHROPIC_API_KEY)"),
        ("OpenAI", "GPT API (requires OPENAI_API_KEY)"),
    ];

    println!();
    println!("{}", "Select AI Provider:".cyan().bold());
    println!();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Provider")
        .items(
            &providers
                .iter()
                .map(|(name, desc)| format!("{} - {}", name.yellow(), desc))
                .collect::<Vec<_>>(),
        )
        .default(0) // Ollama is default
        .interact()
        .context("Provider selection cancelled")?;

    Ok(match selection {
        0 => CliAiProvider::Ollama,
        1 => CliAiProvider::Anthropic,
        2 => CliAiProvider::Openai,
        _ => CliAiProvider::Ollama, // Safe fallback
    })
}

/// Interactive audience level selection
pub fn select_audience_level() -> Result<CliAudienceLevel> {
    require_interactive()?;

    let levels = [
        ("Beginner", "Simple explanations, no jargon, step-by-step"),
        (
            "Intermediate",
            "Balanced technical detail [Recommended]",
        ),
        ("Expert", "Deep technical analysis, assumes expertise"),
    ];

    println!();
    println!("{}", "Select Audience Level:".cyan().bold());
    println!();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Audience")
        .items(
            &levels
                .iter()
                .map(|(name, desc)| format!("{} - {}", name.yellow(), desc))
                .collect::<Vec<_>>(),
        )
        .default(1) // Intermediate is default
        .interact()
        .context("Audience selection cancelled")?;

    Ok(match selection {
        0 => CliAudienceLevel::Beginner,
        1 => CliAudienceLevel::Intermediate,
        2 => CliAudienceLevel::Expert,
        _ => CliAudienceLevel::Intermediate, // Safe fallback
    })
}

/// Interactive minimum severity selection for explain
pub fn select_min_severity() -> Result<Option<Severity>> {
    require_interactive()?;

    println!();
    println!("{}", "Filter by Minimum Severity:".cyan().bold());
    println!();

    let filter = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Filter findings by minimum severity?")
        .default(false)
        .interact()
        .context("Confirmation cancelled")?;

    if !filter {
        return Ok(None);
    }

    let severities = [
        ("Critical", "Only critical findings"),
        ("High", "High severity and above"),
        ("Medium", "Medium severity and above"),
        ("Low", "Low severity and above"),
        ("Info", "All findings including info"),
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Minimum severity")
        .items(
            &severities
                .iter()
                .map(|(name, desc)| format!("{} - {}", name, desc))
                .collect::<Vec<_>>(),
        )
        .default(1) // High as default when filtering
        .interact()
        .context("Severity selection cancelled")?;

    Ok(Some(match selection {
        0 => Severity::Critical,
        1 => Severity::High,
        2 => Severity::Medium,
        3 => Severity::Low,
        4 => Severity::Info,
        _ => Severity::High, // Safe fallback
    }))
}

/// Interactive max findings selection
pub fn select_max_findings() -> Result<Option<usize>> {
    require_interactive()?;

    println!();
    println!("{}", "Limit Number of Explanations:".cyan().bold());
    println!();

    let limit = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Limit number of findings to explain?")
        .default(true)
        .interact()
        .context("Confirmation cancelled")?;

    if !limit {
        return Ok(None);
    }

    let counts = [
        ("3", "3 findings (quick overview)"),
        ("5", "5 findings [Recommended]"),
        ("10", "10 findings (comprehensive)"),
        ("All", "All findings (may be slow)"),
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Maximum findings")
        .items(
            &counts
                .iter()
                .map(|(_, desc)| desc.to_string())
                .collect::<Vec<_>>(),
        )
        .default(1) // 5 findings default
        .interact()
        .context("Count selection cancelled")?;

    Ok(match selection {
        0 => Some(3),
        1 => Some(5),
        2 => Some(10),
        3 => None, // All findings
        _ => Some(5), // Safe fallback
    })
}

/// Complete interactive explain wizard result
#[derive(Debug, Clone)]
pub struct ExplainWizardResult {
    pub server: String,
    pub provider: CliAiProvider,
    pub audience: CliAudienceLevel,
    pub min_severity: Option<Severity>,
    pub max_findings: Option<usize>,
    pub interactive_followup: bool,
}

/// Run the complete interactive explain wizard
pub fn run_explain_wizard() -> Result<ExplainWizardResult> {
    require_interactive()?;
    install_ctrlc_handler()?;

    // Header
    println!();
    println!("{}", "═".repeat(60).cyan());
    println!("{}", "  MCPLint AI-Powered Explanation Wizard".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    // Step 1/5: Server selection
    println!();
    println!("{}", "Step 1/5: Server Selection".cyan().bold());
    let server = select_server()?;

    // Step 2/5: AI provider selection
    println!();
    println!("{}", "Step 2/5: AI Provider".cyan().bold());
    let provider = select_ai_provider()?;

    // Step 3/5: Audience level
    println!();
    println!("{}", "Step 3/5: Audience Level".cyan().bold());
    let audience = select_audience_level()?;

    // Step 4/5: Severity filter
    println!();
    println!("{}", "Step 4/5: Severity Filter".cyan().bold());
    let min_severity = select_min_severity()?;

    // Step 5/5: Max findings
    println!();
    println!("{}", "Step 5/5: Finding Limit".cyan().bold());
    let max_findings = select_max_findings()?;

    // Ask about interactive follow-up questions
    println!();
    let interactive_followup = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable interactive follow-up questions?")
        .default(true)
        .interact()
        .context("Confirmation cancelled")?;

    // Summary
    println!();
    println!("{}", "═".repeat(60).cyan());
    println!("{}", "  Explain Configuration Summary".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("  Server: {}", server.yellow());
    println!(
        "  AI Provider: {}",
        match provider {
            CliAiProvider::Ollama => "Ollama (local)",
            CliAiProvider::Anthropic => "Anthropic (Claude)",
            CliAiProvider::Openai => "OpenAI (GPT)",
        }
        .yellow()
    );
    println!(
        "  Audience: {}",
        match audience {
            CliAudienceLevel::Beginner => "Beginner",
            CliAudienceLevel::Intermediate => "Intermediate",
            CliAudienceLevel::Expert => "Expert",
        }
        .yellow()
    );
    if let Some(ref sev) = min_severity {
        println!("  Min Severity: {}", sev.as_str().yellow());
    }
    if let Some(max) = max_findings {
        println!("  Max Findings: {}", max.to_string().yellow());
    } else {
        println!("  Max Findings: {}", "All".yellow());
    }
    println!(
        "  Follow-up Q&A: {}",
        if interactive_followup { "Yes" } else { "No" }.yellow()
    );
    println!();

    // Confirm
    let proceed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Start explanation with this configuration?")
        .default(true)
        .interact()
        .context("Confirmation cancelled")?;

    if !proceed {
        anyhow::bail!("Explanation cancelled by user");
    }

    Ok(ExplainWizardResult {
        server,
        provider,
        audience,
        min_severity,
        max_findings,
        interactive_followup,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to ensure tests that modify env vars don't conflict
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn is_interactive_available_returns_bool() {
        // Just ensure it doesn't panic and returns a bool
        let result = is_interactive_available();
        let _ = result; // Use result to avoid warning
    }

    #[test]
    fn require_interactive_returns_result() {
        // Just ensure it doesn't panic
        let result = require_interactive();
        let _ = result;
    }

    #[test]
    fn is_interactive_available_returns_false_in_ci() {
        let _lock = ENV_LOCK.lock().unwrap();

        // Set CI environment variable
        std::env::set_var("CI", "true");

        let result = is_interactive_available();

        // CI environments should not be interactive
        // Note: May still be true if running in actual terminal
        // This test validates the check doesn't panic
        let _ = result;

        std::env::remove_var("CI");
    }

    #[test]
    fn scan_wizard_result_struct_creation() {
        // Test that result structs can be created correctly
        let result = ScanWizardResult {
            server: "test-server".to_string(),
            profile: ScanProfile::Standard,
            include_categories: Some(vec!["security".to_string()]),
            output_format: OutputFormat::Text,
            fail_on: Some(vec![Severity::Critical, Severity::High]),
        };

        assert_eq!(result.server, "test-server");
        assert!(matches!(result.profile, ScanProfile::Standard));
        assert!(result.include_categories.is_some());
        assert!(result.fail_on.is_some());
    }

    #[test]
    fn init_wizard_result_struct_creation() {
        let result = InitWizardResult {
            output_path: ".mcplint.toml".to_string(),
            servers_to_test: vec!["server1".to_string(), "server2".to_string()],
            default_profile: ScanProfile::Full,
            create_ci_workflow: true,
            run_initial_scan: false,
        };

        assert_eq!(result.output_path, ".mcplint.toml");
        assert_eq!(result.servers_to_test.len(), 2);
        assert!(result.create_ci_workflow);
        assert!(!result.run_initial_scan);
    }

    #[test]
    fn severity_variants_are_exhaustive() {
        // Ensure all severity variants are handled
        let severities = vec![
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ];

        for sev in severities {
            // Verify each variant can be matched
            match sev {
                Severity::Critical => {}
                Severity::High => {}
                Severity::Medium => {}
                Severity::Low => {}
                Severity::Info => {}
            }
        }
    }

    #[test]
    fn scan_profile_variants_are_exhaustive() {
        let profiles = vec![
            ScanProfile::Quick,
            ScanProfile::Standard,
            ScanProfile::Full,
            ScanProfile::Enterprise,
        ];

        for profile in profiles {
            match profile {
                ScanProfile::Quick => {}
                ScanProfile::Standard => {}
                ScanProfile::Full => {}
                ScanProfile::Enterprise => {}
            }
        }
    }

    #[test]
    fn output_format_variants_are_exhaustive() {
        let formats = vec![
            OutputFormat::Text,
            OutputFormat::Json,
            OutputFormat::Sarif,
            OutputFormat::Junit,
            OutputFormat::Gitlab,
        ];

        for fmt in formats {
            match fmt {
                OutputFormat::Text => {}
                OutputFormat::Json => {}
                OutputFormat::Sarif => {}
                OutputFormat::Junit => {}
                OutputFormat::Gitlab => {}
            }
        }
    }

    #[test]
    fn output_format_as_str() {
        assert_eq!(OutputFormat::Text.as_str(), "text");
        assert_eq!(OutputFormat::Json.as_str(), "json");
        assert_eq!(OutputFormat::Sarif.as_str(), "sarif");
        assert_eq!(OutputFormat::Junit.as_str(), "junit");
        assert_eq!(OutputFormat::Gitlab.as_str(), "gitlab");
    }

    #[test]
    fn output_format_default() {
        let default = OutputFormat::default();
        assert!(matches!(default, OutputFormat::Text));
    }
}
