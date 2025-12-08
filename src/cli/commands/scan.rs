//! Scan command - Security vulnerability scanning

use anyhow::Result;
use colored::Colorize;
use tracing::{debug, info};

use crate::scanner::{ScanConfig, ScanEngine, ScanProfile};
use crate::{OutputFormat, ScanProfile as CliScanProfile};

pub async fn run(
    server: &str,
    args: &[String],
    profile: CliScanProfile,
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
        CliScanProfile::Quick => "Quick",
        CliScanProfile::Standard => "Standard",
        CliScanProfile::Full => "Full",
        CliScanProfile::Enterprise => "Enterprise",
    };

    let scan_profile = match profile {
        CliScanProfile::Quick => ScanProfile::Quick,
        CliScanProfile::Standard => ScanProfile::Standard,
        CliScanProfile::Full => ScanProfile::Full,
        CliScanProfile::Enterprise => ScanProfile::Enterprise,
    };

    // Only show banner for text output
    if matches!(format, OutputFormat::Text) {
        println!("{}", "Starting security scan...".cyan());
        println!("  Server: {}", server.yellow());
        println!("  Profile: {}", profile_name.green());
        println!();
    }

    // Build scan configuration
    let mut config = ScanConfig::default()
        .with_profile(scan_profile)
        .with_timeout(timeout);

    if let Some(inc) = include {
        config = config.with_include_categories(inc);
    }

    if let Some(exc) = exclude {
        config = config.with_exclude_categories(exc);
    }

    // Create engine and run scan
    let engine = ScanEngine::new(config);
    let results = engine.scan(server, args, None).await?;

    // Output results
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

    // Return error code if critical/high findings
    if results.has_critical_or_high() {
        std::process::exit(1);
    }

    Ok(())
}
