//! Fuzz command - Coverage-guided fuzzing

use anyhow::Result;
use colored::Colorize;
use std::path::PathBuf;
use tracing::{debug, info};

use crate::cli::server::resolve_server;
use crate::fuzzer::limits::{format_bytes, format_duration, ResourceLimits};
use crate::fuzzer::{FuzzConfig, FuzzEngine, FuzzProfile};
use crate::OutputFormat;

/// Arguments for the fuzz command
pub struct FuzzArgs {
    /// Server executable path
    pub server: String,
    /// Arguments to pass to the server
    pub args: Vec<String>,
    /// Fuzzing options
    pub options: FuzzOptions,
    /// Output format
    pub format: OutputFormat,
}

/// Fuzzing options (subset of FuzzArgs for configuration)
pub struct FuzzOptions {
    /// Duration in seconds (0 = unlimited)
    pub duration: u64,
    /// Corpus directory path
    pub corpus: Option<String>,
    /// Maximum iterations (0 = unlimited)
    pub iterations: u64,
    /// Number of parallel workers
    pub workers: usize,
    /// Target tools to fuzz
    pub tools: Option<Vec<String>>,
    /// Fuzzing profile
    pub profile: FuzzProfile,
    /// Random seed for reproducibility
    pub seed: Option<u64>,
    /// Resource limit options
    pub limits: ResourceLimitOptions,
}

/// Resource limit options
pub struct ResourceLimitOptions {
    /// Maximum memory (e.g., "512MB")
    pub max_memory: Option<String>,
    /// Maximum time (e.g., "5m")
    pub max_time: Option<String>,
    /// Maximum corpus size
    pub max_corpus: Option<usize>,
    /// Maximum server restarts
    pub max_restarts: Option<u32>,
    /// Disable all resource limits
    pub no_limits: bool,
}

impl FuzzArgs {
    /// Create FuzzArgs from individual parameters (for CLI compatibility)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        args: Vec<String>,
        duration: u64,
        corpus: Option<String>,
        iterations: u64,
        workers: usize,
        tools: Option<Vec<String>>,
        profile: FuzzProfile,
        seed: Option<u64>,
        format: OutputFormat,
        max_memory: Option<String>,
        max_time: Option<String>,
        max_corpus: Option<usize>,
        max_restarts: Option<u32>,
        no_limits: bool,
    ) -> Self {
        Self {
            server,
            args,
            options: FuzzOptions {
                duration,
                corpus,
                iterations,
                workers,
                tools,
                profile,
                seed,
                limits: ResourceLimitOptions {
                    max_memory,
                    max_time,
                    max_corpus,
                    max_restarts,
                    no_limits,
                },
            },
            format,
        }
    }
}

/// Create default resource limit options
impl Default for ResourceLimitOptions {
    fn default() -> Self {
        Self {
            max_memory: None,
            max_time: None,
            max_corpus: None,
            max_restarts: None,
            no_limits: false,
        }
    }
}

/// Create default fuzz options
impl Default for FuzzOptions {
    fn default() -> Self {
        Self {
            duration: 300,
            corpus: None,
            iterations: 0,
            workers: 4,
            tools: None,
            profile: FuzzProfile::Standard,
            seed: None,
            limits: ResourceLimitOptions::default(),
        }
    }
}

/// Run the fuzz command with the given arguments
pub async fn run(args: FuzzArgs) -> Result<()> {
    let FuzzArgs {
        server,
        args: server_args,
        options,
        format,
    } = args;

    info!("Fuzzing MCP server: {}", server);

    // Resolve server from config if not a direct path/URL
    let (server_name, resolved_cmd, mut resolved_args, resolved_env) =
        resolve_server(&server, None)?;

    // Merge CLI args with resolved args
    resolved_args.extend(server_args);

    debug!(
        "Duration: {}s, Corpus: {:?}, Iterations: {}, Workers: {}, Tools: {:?}, Profile: {:?}",
        options.duration,
        options.corpus,
        options.iterations,
        options.workers,
        options.tools,
        options.profile
    );

    println!("{}", "Starting fuzzing session...".cyan());
    println!("  Server: {}", server_name.yellow());
    println!(
        "  Command: {} {}",
        resolved_cmd.dimmed(),
        resolved_args.join(" ").dimmed()
    );
    println!("  Profile: {}", format!("{:?}", options.profile).cyan());
    println!(
        "  Duration: {}s",
        if options.duration == 0 {
            "unlimited".to_string()
        } else {
            options.duration.to_string()
        }
    );
    println!("  Workers: {}", options.workers);
    if let Some(ref c) = options.corpus {
        println!("  Corpus: {}", c);
    }
    if let Some(s) = options.seed {
        println!("  Seed: {}", s);
    }

    // Build config from profile and options
    let mut config = FuzzConfig::with_profile(options.profile);
    config = config.with_workers(options.workers);

    if options.duration > 0 {
        config.duration_secs = options.duration;
    }
    if options.iterations > 0 {
        config.max_iterations = options.iterations;
    }
    if let Some(ref path) = options.corpus {
        config.corpus_path = Some(PathBuf::from(path));
    }
    if options.tools.is_some() {
        config.target_tools = options.tools.clone();
    }
    if let Some(s) = options.seed {
        config.seed = Some(s);
    }

    // Apply resource limits
    let limits = &options.limits;
    if limits.no_limits {
        config = config.with_unlimited_resources();
        println!("  {}", "Resource limits: DISABLED".yellow());
    } else {
        // Apply custom limits if specified
        if let Some(ref mem_str) = limits.max_memory {
            let bytes = ResourceLimits::parse_bytes(mem_str)
                .map_err(|e| anyhow::anyhow!("Invalid --max-memory value: {}", e))?;
            config = config.with_max_memory(bytes);
        }
        if let Some(ref time_str) = limits.max_time {
            let duration = ResourceLimits::parse_duration(time_str)
                .map_err(|e| anyhow::anyhow!("Invalid --max-time value: {}", e))?;
            config = config.with_max_time(duration);
        }
        if let Some(corpus_size) = limits.max_corpus {
            config = config.with_max_corpus_size(corpus_size);
        }
        if let Some(restarts) = limits.max_restarts {
            config = config.with_max_restarts(restarts);
        }

        // Display resource limits
        let cfg_limits = &config.resource_limits;
        println!("{}", "  Resource limits:".dimmed());
        if let Some(t) = cfg_limits.max_time {
            println!("    Max time: {}", format_duration(t).cyan());
        }
        if let Some(m) = cfg_limits.max_memory {
            println!("    Max memory: {}", format_bytes(m).cyan());
        }
        if let Some(c) = cfg_limits.max_corpus_size {
            println!("    Max corpus: {} entries", c.to_string().cyan());
        }
        if let Some(r) = cfg_limits.max_restarts {
            println!("    Max restarts: {}", r.to_string().cyan());
        }
    }
    println!();

    // Set environment variables for spawned process
    for (key, value) in &resolved_env {
        std::env::set_var(key, value);
    }

    // Create engine with config using resolved command and args
    let engine = FuzzEngine::with_config(&resolved_cmd, &resolved_args, config);
    let results = engine
        .run(
            options.duration,
            options.corpus,
            options.iterations,
            options.tools,
        )
        .await?;

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
        OutputFormat::Junit | OutputFormat::Gitlab => {
            // Fuzz results use JSON as fallback for unsupported formats
            results.print_json()?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_limit_options_default() {
        let opts = ResourceLimitOptions::default();
        assert!(opts.max_memory.is_none());
        assert!(opts.max_time.is_none());
        assert!(opts.max_corpus.is_none());
        assert!(opts.max_restarts.is_none());
        assert!(!opts.no_limits);
    }

    #[test]
    fn fuzz_options_default() {
        let opts = FuzzOptions::default();
        assert_eq!(opts.duration, 300);
        assert!(opts.corpus.is_none());
        assert_eq!(opts.iterations, 0);
        assert_eq!(opts.workers, 4);
        assert!(opts.tools.is_none());
        assert!(matches!(opts.profile, FuzzProfile::Standard));
        assert!(opts.seed.is_none());
    }

    #[test]
    fn fuzz_args_new_creates_args() {
        let args = FuzzArgs::new(
            "server".to_string(),
            vec!["arg1".to_string()],
            60,
            Some("corpus_path".to_string()),
            100,
            2,
            Some(vec!["tool1".to_string()]),
            FuzzProfile::Quick,
            Some(42),
            OutputFormat::Text,
            Some("512MB".to_string()),
            Some("5m".to_string()),
            Some(1000),
            Some(10),
            false,
        );

        assert_eq!(args.server, "server");
        assert_eq!(args.args.len(), 1);
        assert_eq!(args.options.duration, 60);
        assert_eq!(args.options.corpus, Some("corpus_path".to_string()));
        assert_eq!(args.options.iterations, 100);
        assert_eq!(args.options.workers, 2);
        assert!(args.options.tools.is_some());
        assert!(matches!(args.options.profile, FuzzProfile::Quick));
        assert_eq!(args.options.seed, Some(42));
        assert!(matches!(args.format, OutputFormat::Text));
    }

    #[test]
    fn fuzz_args_resource_limits() {
        let args = FuzzArgs::new(
            "server".to_string(),
            vec![],
            300,
            None,
            0,
            4,
            None,
            FuzzProfile::Standard,
            None,
            OutputFormat::Json,
            Some("1GB".to_string()),
            Some("10m".to_string()),
            Some(5000),
            Some(50),
            false,
        );

        assert_eq!(args.options.limits.max_memory, Some("1GB".to_string()));
        assert_eq!(args.options.limits.max_time, Some("10m".to_string()));
        assert_eq!(args.options.limits.max_corpus, Some(5000));
        assert_eq!(args.options.limits.max_restarts, Some(50));
        assert!(!args.options.limits.no_limits);
    }

    #[test]
    fn fuzz_args_no_limits() {
        let args = FuzzArgs::new(
            "server".to_string(),
            vec![],
            300,
            None,
            0,
            4,
            None,
            FuzzProfile::Intensive,
            None,
            OutputFormat::Sarif,
            None,
            None,
            None,
            None,
            true, // no_limits
        );

        assert!(args.options.limits.no_limits);
        assert!(matches!(args.options.profile, FuzzProfile::Intensive));
    }

    #[test]
    fn fuzz_options_with_seed() {
        let mut opts = FuzzOptions::default();
        opts.seed = Some(12345);
        assert_eq!(opts.seed, Some(12345));
    }

    #[test]
    fn fuzz_args_empty_args() {
        let args = FuzzArgs::new(
            "test-server".to_string(),
            vec![],
            0,
            None,
            0,
            1,
            None,
            FuzzProfile::CI,
            None,
            OutputFormat::Text,
            None,
            None,
            None,
            None,
            false,
        );

        assert_eq!(args.server, "test-server");
        assert!(args.args.is_empty());
        assert!(matches!(args.options.profile, FuzzProfile::CI));
    }
}
