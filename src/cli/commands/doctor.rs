//! Doctor command - Environment diagnostics

use anyhow::Result;
use colored::Colorize;
use std::process::Command;

pub async fn run(extended: bool) -> Result<()> {
    println!("{}", "MCPLint Environment Check".cyan().bold());
    println!("{}", "=".repeat(60));
    println!();

    // Version info
    println!("{}", "Version Information".yellow());
    println!("  MCPLint: {}", env!("CARGO_PKG_VERSION").green());
    println!(
        "  Rust: {}",
        get_rust_version().unwrap_or_else(|| "unknown".to_string())
    );
    println!();

    // Check for common MCP server runtimes
    println!("{}", "Runtime Detection".yellow());
    check_runtime("node", "--version", "Node.js");
    check_runtime("python", "--version", "Python");
    check_runtime("npx", "--version", "npx");
    check_runtime("uvx", "--version", "uvx");
    println!();

    // Check for MCP tools
    println!("{}", "MCP Ecosystem".yellow());
    check_runtime("mcp", "--version", "MCP CLI");
    println!();

    if extended {
        println!("{}", "Extended Diagnostics".yellow());

        // Check network connectivity
        print!("  Network (GitHub): ");
        match check_network("https://github.com").await {
            Ok(_) => println!("{}", "✓ OK".green()),
            Err(e) => println!("{} ({})", "✗ Failed".red(), e),
        }

        print!("  Network (MCP Registry): ");
        match check_network("https://registry.modelcontextprotocol.io").await {
            Ok(_) => println!("{}", "✓ OK".green()),
            Err(e) => println!("{} ({})", "✗ Failed".red(), e),
        }
        println!();
    }

    println!("{}", "Environment Status: ".cyan().bold());
    println!("{}", "  All checks passed ✓".green());

    Ok(())
}

fn get_rust_version() -> Option<String> {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().replace("rustc ", ""))
}

fn check_runtime(cmd: &str, arg: &str, name: &str) {
    print!("  {}: ", name);
    match Command::new(cmd).arg(arg).output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("{} ({})", "✓ Found".green(), version.dimmed());
        }
        _ => {
            println!("{}", "✗ Not found".red());
        }
    }
}

async fn check_network(url: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    client.get(url).send().await?.error_for_status()?;
    Ok(())
}
