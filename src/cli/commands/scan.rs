//! Scan command - Security vulnerability scanning

use anyhow::Result;
use colored::Colorize;
use tracing::{debug, info};

use crate::scanner::SecurityScanner;
use crate::{OutputFormat, ScanProfile};

pub async fn run(
    server: &str,
    args: &[String],
    profile: ScanProfile,
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    timeout: u64,
    format: OutputFormat,
) -> Result<()> {
    info!("Scanning MCP server: {}", server);
    debug!(
        "Profile: {:?}, Include: {:?}, Exclude: {:?}, Timeout: {}s",
        profile, include, exclude, timeout
    );

    let profile_name = match profile {
        ScanProfile::Quick => "Quick",
        ScanProfile::Standard => "Standard",
        ScanProfile::Full => "Full",
        ScanProfile::Enterprise => "Enterprise",
    };

    println!("{}", "Starting security scan...".cyan());
    println!("  Server: {}", server.yellow());
    println!("  Profile: {}", profile_name.green());
    println!();

    // TODO: Implement actual scanning
    let scanner = SecurityScanner::new(server, args, profile, timeout);
    let findings = scanner.scan().await?;

    match format {
        OutputFormat::Text => {
            findings.print_text();
        }
        OutputFormat::Json => {
            findings.print_json()?;
        }
        OutputFormat::Sarif => {
            findings.print_sarif()?;
        }
    }

    Ok(())
}
