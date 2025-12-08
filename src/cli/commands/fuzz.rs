//! Fuzz command - Coverage-guided fuzzing

use anyhow::Result;
use colored::Colorize;
use std::path::PathBuf;
use tracing::{debug, info};

use crate::fuzzer::{FuzzConfig, FuzzEngine, FuzzProfile};
use crate::OutputFormat;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    server: &str,
    args: &[String],
    duration: u64,
    corpus: Option<String>,
    iterations: u64,
    workers: usize,
    tools: Option<Vec<String>>,
    profile: FuzzProfile,
    seed: Option<u64>,
    format: OutputFormat,
) -> Result<()> {
    info!("Fuzzing MCP server: {}", server);
    debug!(
        "Duration: {}s, Corpus: {:?}, Iterations: {}, Workers: {}, Tools: {:?}, Profile: {:?}",
        duration, corpus, iterations, workers, tools, profile
    );

    println!("{}", "Starting fuzzing session...".cyan());
    println!("  Server: {}", server.yellow());
    println!("  Profile: {}", format!("{:?}", profile).cyan());
    println!(
        "  Duration: {}s",
        if duration == 0 {
            "unlimited".to_string()
        } else {
            duration.to_string()
        }
    );
    println!("  Workers: {}", workers);
    if let Some(ref c) = corpus {
        println!("  Corpus: {}", c);
    }
    if let Some(s) = seed {
        println!("  Seed: {}", s);
    }
    println!();

    // Build config from profile and options
    let mut config = FuzzConfig::with_profile(profile);
    config = config.with_workers(workers);

    if duration > 0 {
        config.duration_secs = duration;
    }
    if iterations > 0 {
        config.max_iterations = iterations;
    }
    if let Some(ref path) = corpus {
        config.corpus_path = Some(PathBuf::from(path));
    }
    if tools.is_some() {
        config.target_tools = tools.clone();
    }
    if let Some(s) = seed {
        config.seed = Some(s);
    }

    // Create engine with config
    let engine = FuzzEngine::with_config(server, args, config);
    let results = engine.run(duration, corpus, iterations, tools).await?;

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
