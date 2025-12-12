//! Validate command - MCP protocol compliance checking

use std::path::Path;

use anyhow::Result;
use colored::Colorize;
use tracing::{debug, info};

use crate::cli::server::resolve_servers;
use crate::validator::ProtocolValidator;
use crate::OutputFormat;

pub async fn run(
    server: Option<&str>,
    config: Option<&Path>,
    _features: Option<Vec<String>>,
    timeout: u64,
    format: OutputFormat,
) -> Result<()> {
    let servers = resolve_servers(server, config)?;

    let mut all_passed = true;

    for spec in &servers {
        let name = &spec.name;
        let command = &spec.command;
        let args = &spec.args;
        let env = &spec.env;

        info!("Validating MCP server: {} ({})", name, command);
        debug!(
            "Args: {:?}, Env: {:?}, Timeout: {}s",
            args,
            env.keys().collect::<Vec<_>>(),
            timeout
        );

        println!("{}", "━".repeat(60).dimmed());
        println!("{} {}", "Validating:".cyan(), name.yellow().bold());
        println!("  Command: {} {}", command, args.join(" ").dimmed());
        if !env.is_empty() {
            println!("  Env: {} variables", env.len());
        }
        println!();

        let validator = ProtocolValidator::new(command, args, env.clone(), timeout);
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
            OutputFormat::Junit | OutputFormat::Gitlab => {
                results.print_json()?;
            }
        }

        if results.failed > 0 {
            all_passed = false;
        }

        println!();
    }

    if servers.len() > 1 {
        println!("{}", "━".repeat(60).dimmed());
        if all_passed {
            println!("{}", "✓ All servers passed validation".green().bold());
        } else {
            println!("{}", "✗ Some servers failed validation".red().bold());
        }
    }

    Ok(())
}
