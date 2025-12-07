//! Fuzz command - Coverage-guided fuzzing

use anyhow::Result;
use colored::Colorize;
use tracing::{debug, info};

use crate::fuzzer::FuzzEngine;
use crate::OutputFormat;

pub async fn run(
    server: &str,
    args: &[String],
    duration: u64,
    corpus: Option<String>,
    iterations: u64,
    workers: usize,
    tools: Option<Vec<String>>,
    format: OutputFormat,
) -> Result<()> {
    info!("Fuzzing MCP server: {}", server);
    debug!(
        "Duration: {}s, Corpus: {:?}, Iterations: {}, Workers: {}, Tools: {:?}",
        duration, corpus, iterations, workers, tools
    );

    println!("{}", "Starting fuzzing session...".cyan());
    println!("  Server: {}", server.yellow());
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
    println!();

    // TODO: Implement actual fuzzing
    let engine = FuzzEngine::new(server, args, workers);
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
    }

    Ok(())
}
