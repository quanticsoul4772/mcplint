//! MCPLint - MCP Server Testing, Fuzzing, and Security Scanning Platform
//!
//! A comprehensive security and quality assurance tool for Model Context Protocol servers.
//! Provides protocol validation, security scanning, and coverage-guided fuzzing.

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod cache;
mod cli;
mod client;
mod fuzzer;
mod protocol;
mod reporter;
mod rules;
mod scanner;
mod transport;
mod validator;

use cli::commands;
use fuzzer::FuzzProfile;

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

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
enum OutputFormat {
    #[default]
    Text,
    Json,
    Sarif,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate MCP server protocol compliance
    Validate {
        /// Path to MCP server executable or command
        #[arg(required = true)]
        server: String,

        /// Arguments to pass to the server
        #[arg(last = true)]
        args: Vec<String>,

        /// Check specific protocol features only
        #[arg(short, long)]
        features: Option<Vec<String>>,

        /// Timeout for server operations (seconds)
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },

    /// Scan MCP server for security vulnerabilities
    Scan {
        /// Path to MCP server executable or command
        #[arg(required = true)]
        server: String,

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
    },

    /// Fuzz MCP server with generated inputs
    Fuzz {
        /// Path to MCP server executable or command
        #[arg(required = true)]
        server: String,

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
    },

    /// Generate a configuration file
    Init {
        /// Output path for config file
        #[arg(short, long, default_value = ".mcplint.toml")]
        output: String,

        /// Overwrite existing config
        #[arg(long)]
        force: bool,
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
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
enum ScanProfile {
    /// Quick scan with essential rules only
    Quick,
    /// Standard security scan
    #[default]
    Standard,
    /// Comprehensive scan including experimental rules
    Full,
    /// Enterprise compliance-focused scan
    Enterprise,
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
            args,
            features,
            timeout,
        } => {
            commands::validate::run(&server, &args, features, timeout, cli.format).await?;
        }
        Commands::Scan {
            server,
            args,
            profile,
            include,
            exclude,
            timeout,
        } => {
            commands::scan::run(
                &server, &args, profile, include, exclude, timeout, cli.format,
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
        } => {
            commands::fuzz::run(
                &server, &args, duration, corpus, iterations, workers, tools, profile, seed,
                cli.format,
            )
            .await?;
        }
        Commands::Init { output, force } => {
            commands::init::run(&output, force)?;
        }
        Commands::Rules { category, details } => {
            commands::rules::run(category, details)?;
        }
        Commands::Doctor { extended } => {
            commands::doctor::run(extended).await?;
        }
    }

    Ok(())
}
