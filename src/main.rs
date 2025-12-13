//! MCPLint - MCP Server Testing, Fuzzing, and Security Scanning Platform
//!
//! A comprehensive security and quality assurance tool for Model Context Protocol servers.
//! Provides protocol validation, security scanning, and coverage-guided fuzzing.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// Declare modules (shared with lib.rs)
mod ai;
mod baseline;
mod cache;
mod cli;
mod client;
mod errors;
mod fingerprinting;
mod fuzzer;
mod protocol;
mod reporter;
mod rules;
mod scanner;
mod transport;
mod ui;
mod validator;

use cli::commands;
use cli::commands::explain::{CliAiProvider, CliAudienceLevel};
use cli::config::{
    AiExplainConfig, BaselineConfig, OutputConfig, ScanCommandConfig, ScanRunConfig,
};
use cli::interactive;
use cli::{OutputFormat, ScanProfile};
use fuzzer::FuzzProfile;
use scanner::Severity;

/// MCPLint - Security testing for MCP servers
#[derive(Parser)]
#[command(
    name = "mcplint",
    author = "Russ Smith",
    version,
    about = "MCP Server Testing, Fuzzing, and Security Scanning Platform",
    long_about = "MCPLint provides comprehensive security testing for Model Context Protocol servers.\n\n\
                  Features:\n\
                  • Protocol compliance validation\n\
                  • Security vulnerability scanning\n\
                  • Coverage-guided fuzzing\n\
                  • CI/CD integration with SARIF output"
)]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Output format
    #[arg(short, long, default_value = "text", global = true)]
    format: OutputFormat,

    /// Suppress all output except errors
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}


/// Shell type for completions generation
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum CompletionShell {
    /// Bash shell
    Bash,
    /// Zsh shell
    Zsh,
    /// Fish shell
    Fish,
    /// PowerShell
    #[value(name = "powershell")]
    PowerShell,
    /// Elvish shell
    Elvish,
}

impl From<CompletionShell> for clap_complete::Shell {
    fn from(shell: CompletionShell) -> Self {
        match shell {
            CompletionShell::Bash => clap_complete::Shell::Bash,
            CompletionShell::Zsh => clap_complete::Shell::Zsh,
            CompletionShell::Fish => clap_complete::Shell::Fish,
            CompletionShell::PowerShell => clap_complete::Shell::PowerShell,
            CompletionShell::Elvish => clap_complete::Shell::Elvish,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Validate MCP server protocol compliance
    Validate {
        /// Server to validate (name from config, npm package, URL, or file path)
        /// If not specified, validates all servers from config
        server: Option<String>,

        /// Path to MCP config file (auto-detected if not specified)
        #[arg(short, long)]
        config: Option<std::path::PathBuf>,

        /// Check specific protocol features only
        #[arg(short = 'F', long)]
        features: Option<Vec<String>>,

        /// Timeout for server operations (seconds)
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },

    /// Scan MCP server for security vulnerabilities
    Scan {
        /// Server name (from config) or path to MCP server executable.
        /// If not specified in interactive mode, launches wizard for selection.
        #[arg(default_value = None)]
        server: Option<String>,

        /// Arguments to pass to the server
        #[arg(last = true)]
        args: Vec<String>,

        /// Security scan profile
        #[arg(short, long, default_value = "standard")]
        profile: ScanProfile,

        /// Include specific rule categories
        #[arg(short, long)]
        include: Option<Vec<String>>,

        /// Exclude specific rule categories
        #[arg(short, long)]
        exclude: Option<Vec<String>>,

        /// Timeout for server operations (seconds)
        #[arg(short, long, default_value = "60")]
        timeout: u64,

        /// Generate AI-powered explanations for findings
        #[arg(long)]
        explain: bool,

        /// AI provider for explanations (ollama, anthropic, openai)
        #[arg(long, default_value = "ollama")]
        ai_provider: CliAiProvider,

        /// AI model for explanations
        #[arg(long)]
        ai_model: Option<String>,

        /// Path to baseline file for comparison
        #[arg(long)]
        baseline: Option<std::path::PathBuf>,

        /// Save scan results as new baseline
        #[arg(long)]
        save_baseline: Option<std::path::PathBuf>,

        /// Update existing baseline with current findings
        #[arg(long)]
        update_baseline: bool,

        /// Show only diff summary (requires --baseline)
        #[arg(long)]
        diff_only: bool,

        /// Fail only on specified severities (e.g., critical,high)
        #[arg(long, value_delimiter = ',')]
        fail_on: Option<Vec<Severity>>,

        /// Path to MCP config file (defaults to Claude Desktop config)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Scan multiple MCP servers in parallel
    #[command(name = "multi-scan")]
    MultiScan {
        /// Server names from config (comma-separated or multiple flags)
        #[arg(short, long, value_delimiter = ',')]
        servers: Option<Vec<String>>,

        /// Scan all configured servers
        #[arg(long)]
        all: bool,

        /// Maximum concurrent scans
        #[arg(short = 'j', long, default_value = "4")]
        concurrency: usize,

        /// Security scan profile for all servers
        #[arg(short, long, default_value = "standard")]
        profile: ScanProfile,

        /// Timeout per server (seconds)
        #[arg(short, long, default_value = "60")]
        timeout: u64,

        /// Path to MCP config file (defaults to Claude Desktop config)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Fail only on specified severities (e.g., critical,high)
        #[arg(long, value_delimiter = ',')]
        fail_on: Option<Vec<Severity>>,
    },

    /// Fuzz MCP server with generated inputs
    Fuzz {
        /// Path to MCP server executable or command.
        /// If not specified in interactive mode, launches wizard for selection.
        #[arg(default_value = None)]
        server: Option<String>,

        /// Arguments to pass to the server
        #[arg(last = true)]
        args: Vec<String>,

        /// Duration to run fuzzing (seconds, 0 = unlimited)
        #[arg(short, long, default_value = "300")]
        duration: u64,

        /// Path to corpus directory for inputs
        #[arg(short, long)]
        corpus: Option<String>,

        /// Maximum iterations (0 = unlimited)
        #[arg(short, long, default_value = "0")]
        iterations: u64,

        /// Number of parallel workers
        #[arg(short = 'W', long, default_value = "4")]
        workers: usize,

        /// Focus on specific tools
        #[arg(long)]
        tools: Option<Vec<String>>,

        /// Fuzzing profile (quick, standard, intensive, ci)
        #[arg(short, long, default_value = "standard")]
        profile: FuzzProfile,

        /// Random seed for reproducibility
        #[arg(long)]
        seed: Option<u64>,

        // Resource limit options
        /// Maximum memory usage (e.g., "512MB", "1GB")
        #[arg(long)]
        max_memory: Option<String>,

        /// Maximum time limit (e.g., "5m", "1h")
        #[arg(long)]
        max_time: Option<String>,

        /// Maximum corpus size (number of entries)
        #[arg(long)]
        max_corpus: Option<usize>,

        /// Maximum server restarts
        #[arg(long)]
        max_restarts: Option<u32>,

        /// Disable all resource limits (use with caution)
        #[arg(long)]
        no_limits: bool,
    },

    /// Generate a configuration file
    Init {
        /// Output path for config file (defaults to .mcplint.toml).
        /// If not specified in interactive mode, launches configuration wizard.
        #[arg(short, long)]
        output: Option<String>,

        /// Overwrite existing config
        #[arg(long)]
        force: bool,

        /// Skip interactive wizard and use defaults
        #[arg(long)]
        non_interactive: bool,
    },

    /// List available security rules
    Rules {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,

        /// Show rule details
        #[arg(short = 'd', long = "details")]
        details: bool,
    },

    /// Check MCPLint version and environment
    Doctor {
        /// Run extended diagnostics
        #[arg(short, long)]
        extended: bool,
    },

    /// Manage cache storage
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },

    /// Get AI-powered explanations for security findings
    Explain {
        /// Server name (from config) or path to MCP server executable.
        /// If not specified in interactive mode, launches wizard for selection.
        #[arg(default_value = None)]
        server: Option<String>,

        /// Arguments to pass to the server
        #[arg(last = true)]
        args: Vec<String>,

        /// AI provider to use
        #[arg(short = 'P', long, default_value = "ollama")]
        provider: CliAiProvider,

        /// AI model to use (defaults to provider's default)
        #[arg(short, long)]
        model: Option<String>,

        /// Audience level for explanations
        #[arg(short, long, default_value = "intermediate")]
        audience: CliAudienceLevel,

        /// Minimum severity to explain (critical, high, medium, low, info)
        #[arg(short, long)]
        severity: Option<Severity>,

        /// Maximum number of findings to explain
        #[arg(short = 'n', long)]
        max_findings: Option<usize>,

        /// Disable response caching
        #[arg(long)]
        no_cache: bool,

        /// Interactive mode (ask follow-up questions)
        #[arg(short, long)]
        interactive: bool,

        /// Timeout for server operations (seconds)
        #[arg(short, long, default_value = "120")]
        timeout: u64,

        /// Path to MCP config file (defaults to Claude Desktop config)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Watch files and rescan on changes
    Watch {
        /// Path to MCP server executable or command
        #[arg(required = true)]
        server: String,

        /// Arguments to pass to the server
        #[arg(last = true)]
        args: Vec<String>,

        /// Paths to watch for changes
        #[arg(short, long, default_value = ".")]
        watch: Vec<std::path::PathBuf>,

        /// Security scan profile
        #[arg(short, long, default_value = "quick")]
        profile: ScanProfile,

        /// Debounce delay in milliseconds
        #[arg(short, long, default_value = "500")]
        debounce: u64,

        /// Clear screen before each scan
        #[arg(short, long)]
        clear: bool,
    },

    /// List available MCP servers from config
    Servers {
        /// Path to MCP config file (auto-detected if not specified)
        #[arg(short, long)]
        config: Option<std::path::PathBuf>,
    },

    /// Generate and compare tool definition fingerprints
    Fingerprint {
        #[command(subcommand)]
        action: FingerprintAction,
    },

    /// Show contextual help and guided recipes
    #[command(name = "how-do-i")]
    HowDoI {
        /// Recipe name (e.g., first-scan, ci-integration, fuzz-testing)
        recipe: Option<String>,

        /// Search for recipes by keyword
        #[arg(short, long)]
        search: Option<String>,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: CompletionShell,

        /// Install completions to default location
        #[arg(long)]
        install: bool,
    },
}

#[derive(Subcommand)]
enum FingerprintAction {
    /// Generate fingerprints for a server's tools
    Generate {
        /// Path to MCP server executable or server name from config
        #[arg(required = true)]
        server: String,

        /// Path to MCP config file (auto-detected if not specified)
        #[arg(short, long)]
        config: Option<std::path::PathBuf>,

        /// Output file path for fingerprints
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,

        /// Timeout for server operations (seconds)
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },

    /// Compare current fingerprints against a baseline
    Compare {
        /// Path to MCP server executable or server name from config
        #[arg(required = true)]
        server: String,

        /// Path to baseline file for comparison
        #[arg(short, long, required = true)]
        baseline: std::path::PathBuf,

        /// Path to MCP config file (auto-detected if not specified)
        #[arg(short, long)]
        config: Option<std::path::PathBuf>,

        /// Timeout for server operations (seconds)
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
enum CacheAction {
    /// Show cache statistics
    Stats {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Clear cache entries
    Clear {
        /// Clear only specific category (schemas, scan_results, validation, corpus, tool_hashes)
        #[arg(short, long)]
        category: Option<String>,

        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },

    /// Remove expired cache entries
    Prune {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Export cache to file
    Export {
        /// Output file path
        #[arg(short, long, default_value = "mcplint-cache.json")]
        output: std::path::PathBuf,

        /// Export only specific category
        #[arg(short, long)]
        category: Option<String>,
    },

    /// Import cache from file
    Import {
        /// Input file path
        #[arg(short, long)]
        input: std::path::PathBuf,

        /// Merge with existing cache (skip existing keys)
        #[arg(long)]
        merge: bool,
    },

    /// List cache keys
    Keys {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}


fn init_logging(verbosity: u8, quiet: bool) {
    let filter = if quiet {
        EnvFilter::new("error")
    } else {
        match verbosity {
            0 => EnvFilter::new("mcplint=info"),
            1 => EnvFilter::new("mcplint=debug"),
            2 => EnvFilter::new("mcplint=trace"),
            _ => EnvFilter::new("trace"),
        }
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();
}

fn print_banner() {
    println!(
        r#"
{}
 ███╗   ███╗ ██████╗██████╗ ██╗     ██╗███╗   ██╗████████╗
 ████╗ ████║██╔════╝██╔══██╗██║     ██║████╗  ██║╚══██╔══╝
 ██╔████╔██║██║     ██████╔╝██║     ██║██╔██╗ ██║   ██║   
 ██║╚██╔╝██║██║     ██╔═══╝ ██║     ██║██║╚██╗██║   ██║   
 ██║ ╚═╝ ██║╚██████╗██║     ███████╗██║██║ ╚████║   ██║   
 ╚═╝     ╚═╝ ╚═════╝╚═╝     ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
{}
  MCP Server Security Testing Platform v{}
"#,
        "".cyan(),
        "".clear(),
        env!("CARGO_PKG_VERSION")
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    init_logging(cli.verbose, cli.quiet);

    if !cli.quiet {
        print_banner();
    }

    match cli.command {
        Commands::Validate {
            server,
            config,
            features,
            timeout,
        } => {
            commands::validate::run(
                server.as_deref(),
                config.as_deref(),
                features,
                timeout,
                cli.format,
            )
            .await?;
        }
        Commands::Scan {
            server,
            args,
            profile,
            include,
            exclude,
            timeout,
            explain,
            ai_provider,
            ai_model,
            baseline,
            save_baseline,
            update_baseline,
            diff_only,
            fail_on,
            config,
        } => {
            use cli::interactive;

            // Determine server - interactive mode or CLI args
            let (server_name, scan_profile, include_cats, fail_on_sevs): (
                String,
                scanner::ScanProfile,
                Option<Vec<String>>,
                Option<Vec<Severity>>,
            ) = if server.is_none() && interactive::is_interactive_available() {
                // Launch interactive wizard
                let wizard_result = interactive::run_scan_wizard()?;
                (
                    wizard_result.server,
                    wizard_result.profile,
                    wizard_result.include_categories,
                    wizard_result.fail_on,
                )
            } else if let Some(s) = server {
                // Non-interactive mode with server specified
                (s, profile.into(), include, fail_on)
            } else {
                // Non-interactive mode without server = error
                eprintln!(
                    "{}",
                    "Error: Server argument required in non-interactive mode".red()
                );
                eprintln!("Usage: mcplint scan <server>");
                eprintln!("   Or: mcplint scan (interactive mode in terminal)");
                std::process::exit(1);
            };

            // Convert scanner::ScanProfile to CLI ScanProfile for ScanRunConfig
            let cli_scan_profile: ScanProfile = match scan_profile {
                scanner::ScanProfile::Quick => ScanProfile::Quick,
                scanner::ScanProfile::Standard => ScanProfile::Standard,
                scanner::ScanProfile::Full => ScanProfile::Full,
                scanner::ScanProfile::Enterprise => ScanProfile::Enterprise,
            };

            // Build run configuration
            let mut run_config = ScanRunConfig::new(server_name, cli_scan_profile)
                .with_args(args)
                .with_timeout(timeout);
            if let Some(inc) = include_cats {
                run_config.include = Some(inc);
            }
            if let Some(exc) = exclude {
                run_config.exclude = Some(exc);
            }
            if let Some(path) = config {
                run_config = run_config.with_config_path(path);
            }

            // Build baseline configuration
            let mut baseline_config = BaselineConfig::default()
                .with_update(update_baseline)
                .with_diff_only(diff_only);
            if let Some(path) = baseline {
                baseline_config = baseline_config.with_baseline(path);
            }
            if let Some(path) = save_baseline {
                baseline_config = baseline_config.with_save_baseline(path);
            }
            if let Some(severities) = fail_on_sevs {
                baseline_config = baseline_config.with_fail_on(severities);
            }

            // Build AI configuration
            let ai_config = if explain {
                let mut config = AiExplainConfig::enabled(ai_provider);
                if let Some(model) = ai_model {
                    config = config.with_model(model);
                }
                config
            } else {
                AiExplainConfig::disabled()
            };

            // Build output configuration
            let output_config = OutputConfig::new(cli.format);

            // Combine into ScanCommandConfig
            let scan_config = ScanCommandConfig::new(run_config)
                .with_baseline(baseline_config)
                .with_ai(ai_config)
                .with_output(output_config);

            commands::scan::run(scan_config).await?;
        }
        Commands::MultiScan {
            servers,
            all,
            concurrency,
            profile,
            timeout,
            config,
            fail_on,
        } => {
            commands::multi_scan::run(
                servers,
                all,
                concurrency,
                profile.into(),
                timeout,
                config.as_deref(),
                fail_on,
                cli.format,
            )
            .await?;
        }
        Commands::Fuzz {
            server,
            args,
            duration,
            corpus,
            iterations,
            workers,
            tools,
            profile,
            seed,
            max_memory,
            max_time,
            max_corpus,
            max_restarts,
            no_limits,
        } => {
            // Interactive mode detection
            let (server_name, fuzz_profile, fuzz_duration, fuzz_workers, fuzz_corpus) =
                if server.is_none() && interactive::is_interactive_available() {
                    // Launch interactive wizard
                    let wizard_result = interactive::run_fuzz_wizard()?;
                    (
                        wizard_result.server,
                        wizard_result.profile,
                        wizard_result.duration,
                        wizard_result.workers,
                        wizard_result.corpus,
                    )
                } else if let Some(s) = server {
                    // Non-interactive mode with server specified
                    (s, profile, duration, workers, corpus)
                } else {
                    // Non-interactive mode without server = error
                    eprintln!(
                        "{}",
                        "Error: Server argument required in non-interactive mode".red()
                    );
                    eprintln!("Usage: mcplint fuzz <server>");
                    eprintln!("   Or: mcplint fuzz (interactive mode in terminal)");
                    std::process::exit(1);
                };

            let fuzz_args = commands::fuzz::FuzzArgs::new(
                server_name,
                args,
                fuzz_duration,
                fuzz_corpus,
                iterations,
                fuzz_workers,
                tools,
                fuzz_profile,
                seed,
                cli.format,
                max_memory,
                max_time,
                max_corpus,
                max_restarts,
                no_limits,
            );
            commands::fuzz::run(fuzz_args).await?;
        }
        Commands::Init {
            output,
            force,
            non_interactive,
        } => {
            // Determine output path and whether to use wizard
            let (output_path, use_wizard_config) =
                if output.is_none() && !non_interactive && interactive::is_interactive_available() {
                    // Launch interactive wizard
                    let wizard_result = interactive::run_init_wizard()?;
                    let path = wizard_result.output_path.clone();
                    (path, Some(wizard_result))
                } else {
                    // Use provided path or default
                    (output.unwrap_or_else(|| ".mcplint.toml".to_string()), None)
                };

            commands::init::run_with_config(&output_path, force, use_wizard_config)?;
        }
        Commands::Rules { category, details } => {
            commands::rules::run(category, details)?;
        }
        Commands::Doctor { extended } => {
            commands::doctor::run(extended).await?;
        }
        Commands::Cache { action } => match action {
            CacheAction::Stats { json } => {
                commands::cache::run_stats(json).await?;
            }
            CacheAction::Clear { category, force } => {
                commands::cache::run_clear(category, force).await?;
            }
            CacheAction::Prune { json } => {
                commands::cache::run_prune(json).await?;
            }
            CacheAction::Export { output, category } => {
                commands::cache::run_export(output, category).await?;
            }
            CacheAction::Import { input, merge } => {
                commands::cache::run_import(input, merge).await?;
            }
            CacheAction::Keys { category, json } => {
                commands::cache::run_keys(category, json).await?;
            }
        },
        Commands::Explain {
            server,
            args,
            provider,
            model,
            audience,
            severity,
            max_findings,
            no_cache,
            interactive,
            timeout,
            config,
        } => {
            // Check if we need interactive wizard
            let (resolved_server, resolved_provider, resolved_audience, resolved_severity, resolved_max, resolved_interactive) =
                if server.is_none() && interactive::is_interactive_available() {
                    // Launch explain wizard
                    let wizard_result = interactive::run_explain_wizard()?;
                    (
                        wizard_result.server,
                        wizard_result.provider,
                        wizard_result.audience,
                        wizard_result.min_severity,
                        wizard_result.max_findings,
                        wizard_result.interactive_followup,
                    )
                } else if let Some(s) = server {
                    // Use provided server and CLI args
                    (s, provider, audience, severity, max_findings, interactive)
                } else {
                    // No server and not interactive
                    anyhow::bail!(
                        "Server argument required in non-interactive mode.\n\
                         Run with --help for usage information."
                    );
                };

            commands::explain::run_scan(
                &resolved_server,
                &args,
                resolved_provider,
                model,
                resolved_audience,
                resolved_severity,
                resolved_max,
                cli.format,
                no_cache,
                resolved_interactive,
                timeout,
                config.as_deref(),
            )
            .await?;
        }
        Commands::Watch {
            server,
            args,
            watch,
            profile,
            debounce,
            clear,
        } => {
            commands::watch::run(&server, &args, watch, profile.into(), debounce, clear).await?;
        }
        Commands::Servers { config } => {
            commands::servers::run(config.as_deref())?;
        }
        Commands::Fingerprint { action } => match action {
            FingerprintAction::Generate {
                server,
                config,
                output,
                timeout,
            } => {
                commands::fingerprint::run_generate(
                    &server,
                    config.as_deref(),
                    output.as_deref(),
                    timeout,
                    cli.format,
                )
                .await?;
            }
            FingerprintAction::Compare {
                server,
                baseline,
                config,
                timeout,
            } => {
                commands::fingerprint::run_compare(
                    &server,
                    &baseline,
                    config.as_deref(),
                    timeout,
                    cli.format,
                )
                .await?;
            }
        },
        Commands::HowDoI { recipe, search } => {
            let help = cli::help::HelpSystem::new();
            let mode = ui::OutputMode::detect();
            if let Some(query) = search {
                help.show_search_results(&query, mode);
            } else if let Some(name) = recipe {
                help.show_recipe(&name, mode);
            } else {
                help.show_list(mode);
            }
        }
        Commands::Completions { shell, install } => {
            use clap::CommandFactory;
            let clap_shell: clap_complete::Shell = shell.into();
            let mut cmd = Cli::command();

            if install {
                // Install to default location
                if let Some(dir) = cli::completions::get_completions_dir(clap_shell) {
                    if !dir.exists() {
                        std::fs::create_dir_all(&dir)?;
                    }
                    let filename = cli::completions::get_completions_filename(clap_shell);
                    let path = dir.join(filename);
                    cli::completions::save_completions(clap_shell, &mut cmd, &path)?;
                    println!(
                        "{} Completions installed to: {}",
                        "✔".green(),
                        path.display()
                    );
                    println!();
                    println!("{}", "Installation instructions:".cyan().bold());
                    println!("{}", cli::completions::get_install_instructions(clap_shell));
                } else {
                    eprintln!(
                        "{} Could not determine default completions directory for {:?}",
                        "✖".red(),
                        shell
                    );
                    eprintln!("Use without --install to print completions to stdout");
                    std::process::exit(1);
                }
            } else {
                // Print to stdout
                cli::completions::print_completions(clap_shell, &mut cmd);
            }
        }
    }

    Ok(())
}
