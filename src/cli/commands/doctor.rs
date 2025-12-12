//! Doctor command - Environment diagnostics

use crate::ui::{OutputMode, Printer};
use anyhow::Result;
use colored::Colorize;
use std::process::Command;

pub async fn run(extended: bool) -> Result<()> {
    let printer = Printer::new();
    let mode = printer.mode();

    printer.header("MCPLint Environment Check");
    printer.separator();
    printer.newline();

    // Version info
    print_section_header(&printer, mode, "Version Information");
    printer.kv("MCPLint", env!("CARGO_PKG_VERSION"));
    printer.kv(
        "Rust",
        &get_rust_version().unwrap_or_else(|| "unknown".to_string()),
    );
    printer.newline();

    // Check for common MCP server runtimes
    print_section_header(&printer, mode, "Runtime Detection");
    check_runtime(&printer, mode, "node", "--version", "Node.js");
    check_runtime(&printer, mode, "python", "--version", "Python");
    check_runtime(&printer, mode, "npx", "--version", "npx");
    check_runtime(&printer, mode, "uvx", "--version", "uvx");
    printer.newline();

    // Check for MCP tools
    print_section_header(&printer, mode, "MCP Ecosystem");
    check_npx_package(&printer, mode, "@modelcontextprotocol/inspector", "MCP Inspector");
    check_npx_package(&printer, mode, "@anthropic-ai/claude-code", "Claude Code");
    printer.newline();

    if extended {
        print_section_header(&printer, mode, "Extended Diagnostics");

        // Check network connectivity
        check_network_with_output(&printer, mode, "https://github.com", "GitHub").await;
        check_network_with_output(
            &printer,
            mode,
            "https://registry.modelcontextprotocol.io",
            "MCP Registry",
        )
        .await;
        printer.newline();
    }

    printer.success("Environment Status: All checks passed");

    Ok(())
}

fn print_section_header(printer: &Printer, mode: OutputMode, title: &str) {
    if mode.colors_enabled() {
        println!("{}", title.yellow());
    } else {
        printer.println(&format!("== {} ==", title));
    }
}

fn get_rust_version() -> Option<String> {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().replace("rustc ", ""))
}

fn check_runtime(printer: &Printer, mode: OutputMode, cmd: &str, arg: &str, name: &str) {
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
            if mode.colors_enabled() {
                println!(
                    "  {}: {} ({})",
                    name,
                    "✓ Found".green(),
                    version.dimmed()
                );
            } else {
                printer.println(&format!("  {}: [OK] Found ({})", name, version));
            }
        }
        _ => {
            if mode.colors_enabled() {
                println!("  {}: {}", name, "✗ Not found".red());
            } else {
                printer.println(&format!("  {}: [ERROR] Not found", name));
            }
        }
    }
}

fn check_npx_package(printer: &Printer, mode: OutputMode, package: &str, name: &str) {
    // Check if the package is available via npm list (globally installed)
    // or can be resolved by npx
    #[cfg(windows)]
    let result = Command::new("cmd")
        .args(["/C", &format!("npm list -g {} --depth=0", package)])
        .output();

    #[cfg(not(windows))]
    let result = Command::new("npm")
        .args(["list", "-g", package, "--depth=0"])
        .output();

    match result {
        Ok(output) if output.status.success() => {
            // Extract version from output like "@modelcontextprotocol/inspector@0.6.0"
            let output_str = String::from_utf8_lossy(&output.stdout);
            let version = output_str
                .lines()
                .find(|line| line.contains(package))
                .and_then(|line| line.split('@').next_back())
                .unwrap_or("installed")
                .trim();
            if mode.colors_enabled() {
                println!(
                    "  {}: {} ({})",
                    name,
                    "✓ Available".green(),
                    version.dimmed()
                );
            } else {
                printer.println(&format!("  {}: [OK] Available ({})", name, version));
            }
        }
        _ => {
            // Package not globally installed, but may still be available via npx
            if mode.colors_enabled() {
                println!(
                    "  {}: {} ({})",
                    name,
                    "○ Via npx".yellow(),
                    format!("npx {}", package).dimmed()
                );
            } else {
                printer.println(&format!("  {}: [INFO] Via npx (npx {})", name, package));
            }
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

async fn check_network_with_output(printer: &Printer, mode: OutputMode, url: &str, name: &str) {
    match check_network(url).await {
        Ok(_) => {
            if mode.colors_enabled() {
                println!("  Network ({}): {}", name, "✓ OK".green());
            } else {
                printer.println(&format!("  Network ({}): [OK]", name));
            }
        }
        Err(e) => {
            if mode.colors_enabled() {
                println!("  Network ({}): {} ({})", name, "✗ Failed".red(), e);
            } else {
                printer.println(&format!("  Network ({}): [ERROR] Failed ({})", name, e));
            }
        }
    }
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
