//! Validate command - MCP protocol compliance checking

use std::path::Path;

use anyhow::Result;
use colored::Colorize;
use tracing::{debug, info};

use crate::cli::server::resolve_servers;
use crate::cli::OutputFormat;
use crate::ui::{ConnectionSpinner, MultiServerProgress, OutputMode, Printer};
use crate::validator::ProtocolValidator;

pub async fn run(
    server: Option<&str>,
    config: Option<&Path>,
    _features: Option<Vec<String>>,
    timeout: u64,
    format: OutputFormat,
) -> Result<()> {
    let servers = resolve_servers(server, config)?;

    // Determine output mode based on format
    let output_mode = if matches!(format, OutputFormat::Text) {
        OutputMode::detect()
    } else {
        OutputMode::Plain // Non-text formats should not show progress
    };

    let printer = Printer::with_mode(output_mode);
    let multi_progress = MultiServerProgress::new(output_mode, servers.len());

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

        // Show header for text output when not using multi-progress
        if matches!(format, OutputFormat::Text) && !multi_progress.is_enabled() {
            printer.separator();
            println!("{} {}", "Validating:".cyan(), name.yellow().bold());
            println!("  Command: {} {}", command, args.join(" ").dimmed());
            if !env.is_empty() {
                println!("  Env: {} variables", env.len());
            }
            printer.newline();
        }

        // Create spinner for this server
        let mut spinner = ConnectionSpinner::new(output_mode);
        spinner.start(name);

        let validator = ProtocolValidator::new(command, args, env.clone(), timeout);

        // Update spinner phases during validation
        spinner.phase_initializing();

        let results = match validator.validate().await {
            Ok(r) => {
                if r.failed > 0 {
                    spinner.finish_error(&format!(
                        "{}: {} passed, {} failed",
                        name, r.passed, r.failed
                    ));
                } else {
                    spinner.finish_success(&format!("{}: {} passed", name, r.passed));
                }
                r
            }
            Err(e) => {
                spinner.finish_error(&format!("{}: {}", name, e));
                return Err(e);
            }
        };

        // Update multi-progress if enabled
        multi_progress.server_complete(name);

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
            OutputFormat::Junit | OutputFormat::Gitlab | OutputFormat::Html => {
                // HTML format not applicable to validation results, fall back to JSON
                results.print_json()?;
            }
        }

        if results.failed > 0 {
            all_passed = false;
        }

        printer.newline();
    }

    // Finish multi-progress
    multi_progress.finish();

    if servers.len() > 1 {
        printer.separator();
        if all_passed {
            printer.success("All servers passed validation");
        } else {
            printer.error("Some servers failed validation");
        }
    }

    Ok(())
}
