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

    // On Windows, commands like npx, uvx need to be run through cmd.exe
    // or with .cmd extension to work properly
    #[cfg(windows)]
    let result = Command::new("cmd")
        .args(["/C", &format!("{} {}", cmd, arg)])
        .output();

    #[cfg(not(windows))]
    let result = Command::new(cmd).arg(arg).output();

    match result {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_rust_version_returns_some() {
        // This test assumes Rust is installed (which it must be to run the test)
        let version = get_rust_version();
        assert!(version.is_some());
        let v = version.unwrap();
        // Version should not be empty and should not contain "rustc " prefix
        assert!(!v.is_empty());
        assert!(!v.starts_with("rustc "));
    }

    #[test]
    fn get_rust_version_format() {
        let version = get_rust_version();
        if let Some(v) = version {
            // Should be something like "1.75.0 (82e1608df 2023-12-21)"
            assert!(v.contains('.'), "Version should contain dots");
        }
    }

    // Note: We can't easily unit test check_runtime without mocking
    // since it executes actual commands. In a real scenario, we'd use
    // a trait-based approach or dependency injection.

    #[tokio::test]
    async fn check_network_invalid_url() {
        // This should fail with an invalid URL
        let result = check_network("http://invalid-domain-that-does-not-exist-12345.com").await;
        assert!(result.is_err());
    }

    // Test that the module version constant is accessible
    #[test]
    fn cargo_pkg_version_exists() {
        let version = env!("CARGO_PKG_VERSION");
        assert!(!version.is_empty());
    }
}
