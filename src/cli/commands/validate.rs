//! Validate command - MCP protocol compliance checking

use anyhow::Result;
use colored::Colorize;
use tracing::{debug, info};

use crate::validator::ProtocolValidator;
use crate::OutputFormat;

pub async fn run(
    server: &str,
    args: &[String],
    features: Option<Vec<String>>,
    timeout: u64,
    format: OutputFormat,
) -> Result<()> {
    info!("Validating MCP server: {}", server);
    debug!("Args: {:?}, Features: {:?}, Timeout: {}s", args, features, timeout);

    println!("{}", "Starting protocol validation...".cyan());
    println!("  Server: {}", server.yellow());
    if !args.is_empty() {
        println!("  Args: {}", args.join(" ").dimmed());
    }
    println!();

    // TODO: Implement actual validation
    let validator = ProtocolValidator::new(server, args, timeout);
    let results = validator.validate().await?;

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
