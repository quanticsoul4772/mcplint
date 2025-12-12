//! Shell completion generation and dynamic completions
//!
//! Provides:
//! - Static shell completions for Bash, Zsh, Fish, PowerShell, Elvish
//! - Dynamic completions for server names from Claude Desktop config
//! - Dynamic completions for profiles, formats, and severities

// These functions are public APIs for shell completion scripts and external tools
#![allow(dead_code)]

use std::io::Write;
use std::path::PathBuf;

use clap::Command;
use clap_complete::{generate, Shell};

use crate::cli::server::{find_config_file, load_config};

/// Generate shell completions and write to the given writer
pub fn generate_completions<W: Write>(shell: Shell, cmd: &mut Command, buf: &mut W) {
    generate(shell, cmd, cmd.get_name().to_string(), buf);
}

/// Generate completions and print to stdout
pub fn print_completions(shell: Shell, cmd: &mut Command) {
    generate_completions(shell, cmd, &mut std::io::stdout());
}

/// Generate completions and save to a file
pub fn save_completions(shell: Shell, cmd: &mut Command, path: &std::path::Path) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    generate_completions(shell, cmd, &mut file);
    Ok(())
}

/// Get the default completions directory for a shell
pub fn get_completions_dir(shell: Shell) -> Option<PathBuf> {
    match shell {
        Shell::Bash => {
            // Try XDG_DATA_HOME first, then fallback to ~/.local/share
            if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
                Some(PathBuf::from(xdg).join("bash-completion/completions"))
            } else {
                dirs::home_dir().map(|h| h.join(".local/share/bash-completion/completions"))
            }
        }
        Shell::Zsh => {
            // Common zsh completions directories
            if let Ok(fpath) = std::env::var("FPATH") {
                // Return first writable directory in fpath
                for path in fpath.split(':') {
                    let p = PathBuf::from(path);
                    if p.exists() && p.is_dir() {
                        return Some(p);
                    }
                }
            }
            dirs::home_dir().map(|h| h.join(".zfunc"))
        }
        Shell::Fish => {
            // Fish completions directory
            if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
                Some(PathBuf::from(xdg).join("fish/completions"))
            } else {
                dirs::home_dir().map(|h| h.join(".config/fish/completions"))
            }
        }
        Shell::PowerShell => {
            // PowerShell profile directory
            dirs::home_dir().map(|h| {
                if cfg!(windows) {
                    h.join("Documents/PowerShell/Completions")
                } else {
                    h.join(".config/powershell/Completions")
                }
            })
        }
        Shell::Elvish => {
            // Elvish completions
            if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
                Some(PathBuf::from(xdg).join("elvish/lib"))
            } else {
                dirs::home_dir().map(|h| h.join(".config/elvish/lib"))
            }
        }
        _ => None,
    }
}

/// Get filename for completions file
pub fn get_completions_filename(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash => "mcplint",
        Shell::Zsh => "_mcplint",
        Shell::Fish => "mcplint.fish",
        Shell::PowerShell => "mcplint.ps1",
        Shell::Elvish => "mcplint.elv",
        _ => "mcplint",
    }
}

// =============================================================================
// Dynamic Completions - Server Names from Config
// =============================================================================

/// Get list of configured server names for completion
pub fn get_server_names() -> Vec<String> {
    let config_path = find_config_file();

    if let Some(path) = config_path {
        if let Ok(config) = load_config(&path) {
            let mut servers: Vec<String> = config.mcp_servers.keys().cloned().collect();
            servers.sort();
            return servers;
        }
    }

    Vec::new()
}

/// Get server names as completion candidates with descriptions
pub fn get_server_completions() -> Vec<(String, String)> {
    let config_path = find_config_file();

    if let Some(path) = config_path {
        if let Ok(config) = load_config(&path) {
            let mut completions: Vec<(String, String)> = config
                .mcp_servers
                .iter()
                .map(|(name, server_config)| {
                    let desc = format!("Command: {}", server_config.command);
                    (name.clone(), desc)
                })
                .collect();
            completions.sort_by(|a, b| a.0.cmp(&b.0));
            return completions;
        }
    }

    Vec::new()
}

// =============================================================================
// Static Completion Values
// =============================================================================

/// Scan profile completions with descriptions
pub fn get_profile_completions() -> Vec<(&'static str, &'static str)> {
    vec![
        ("quick", "Fast scan with essential rules only (~30s)"),
        ("standard", "Balanced security scan (~2min)"),
        ("full", "Comprehensive scan with all rules (~5min)"),
        ("enterprise", "Compliance-focused scan (~10min)"),
    ]
}

/// Fuzz profile completions with descriptions
pub fn get_fuzz_profile_completions() -> Vec<(&'static str, &'static str)> {
    vec![
        ("quick", "Quick fuzzing session (1 min, 100 iterations)"),
        ("standard", "Standard fuzzing (5 min, 1000 iterations)"),
        ("intensive", "Intensive fuzzing (15 min, 5000 iterations)"),
        ("ci", "CI-optimized fuzzing (2 min, 500 iterations)"),
    ]
}

/// Output format completions
pub fn get_format_completions() -> Vec<(&'static str, &'static str)> {
    vec![
        ("text", "Human-readable text output"),
        ("json", "JSON output for programmatic use"),
        ("sarif", "SARIF format for CI/CD integration"),
        ("junit", "JUnit XML format for test runners"),
        ("gitlab", "GitLab Code Quality format"),
    ]
}

/// Severity completions
pub fn get_severity_completions() -> Vec<(&'static str, &'static str)> {
    vec![
        ("critical", "Critical severity findings"),
        ("high", "High severity findings"),
        ("medium", "Medium severity findings"),
        ("low", "Low severity findings"),
        ("info", "Informational findings"),
    ]
}

/// AI provider completions
pub fn get_provider_completions() -> Vec<(&'static str, &'static str)> {
    vec![
        ("ollama", "Local Ollama server (default, free)"),
        ("anthropic", "Anthropic Claude API (requires API key)"),
        ("openai", "OpenAI GPT API (requires API key)"),
    ]
}

/// Audience level completions
pub fn get_audience_completions() -> Vec<(&'static str, &'static str)> {
    vec![
        ("beginner", "Detailed explanations for newcomers"),
        ("intermediate", "Balanced technical depth (default)"),
        ("expert", "Concise, technical explanations"),
    ]
}

/// Cache category completions
pub fn get_cache_category_completions() -> Vec<(&'static str, &'static str)> {
    vec![
        ("schemas", "Server schema cache"),
        ("scan_results", "Security scan result cache"),
        ("validation", "Protocol validation cache"),
        ("corpus", "Fuzzing corpus cache"),
        ("tool_hashes", "Tool fingerprint hash cache"),
    ]
}

/// Help recipe completions
pub fn get_recipe_completions() -> Vec<(&'static str, &'static str)> {
    vec![
        ("first-scan", "Get started with mcplint security scanning"),
        ("test-authentication", "Comprehensive authentication testing workflow"),
        ("prevent-injection", "How to detect and prevent injection vulnerabilities"),
        ("ci-integration", "Integrate mcplint into your CI/CD pipeline"),
        ("schema-validation", "Ensure your MCP server schemas are correct"),
        ("baseline-management", "Track security improvements with baselines"),
        ("fuzz-testing", "Find edge cases with coverage-guided fuzzing"),
        ("troubleshooting", "Diagnose and fix common problems"),
    ]
}

/// Rule category completions
pub fn get_rule_category_completions() -> Vec<(&'static str, &'static str)> {
    vec![
        ("protocol", "Protocol compliance rules (PROTO-*)"),
        ("schema", "Schema validation rules (SCHEMA-*)"),
        ("sequence", "Sequence validation rules (SEQ-*)"),
        ("tool", "Tool validation rules (TOOL-*)"),
        ("resource", "Resource validation rules (RES-*)"),
        ("security", "Security rules (SEC-*)"),
        ("edge", "Edge case rules (EDGE-*)"),
    ]
}

// =============================================================================
// Shell Detection
// =============================================================================

/// Detect the current shell from environment
pub fn detect_shell() -> Option<Shell> {
    // Check SHELL environment variable
    if let Ok(shell_path) = std::env::var("SHELL") {
        let shell_name = std::path::Path::new(&shell_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        return match shell_name {
            "bash" => Some(Shell::Bash),
            "zsh" => Some(Shell::Zsh),
            "fish" => Some(Shell::Fish),
            "elvish" => Some(Shell::Elvish),
            "pwsh" | "powershell" => Some(Shell::PowerShell),
            _ => None,
        };
    }

    // On Windows, check for PowerShell
    #[cfg(windows)]
    {
        if std::env::var("PSModulePath").is_ok() {
            return Some(Shell::PowerShell);
        }
    }

    None
}

/// Get installation instructions for a shell
pub fn get_install_instructions(shell: Shell) -> String {
    match shell {
        Shell::Bash => {
            r#"# Add to ~/.bashrc or ~/.bash_profile:
source <(mcplint completions bash)

# Or save to completions directory:
mcplint completions bash > ~/.local/share/bash-completion/completions/mcplint"#.to_string()
        }
        Shell::Zsh => {
            r#"# Add to ~/.zshrc (before compinit):
source <(mcplint completions zsh)

# Or save to fpath directory:
mcplint completions zsh > ~/.zfunc/_mcplint
# Then add to ~/.zshrc: fpath=(~/.zfunc $fpath)"#.to_string()
        }
        Shell::Fish => {
            r#"# Save to fish completions directory:
mcplint completions fish > ~/.config/fish/completions/mcplint.fish"#.to_string()
        }
        Shell::PowerShell => {
            r#"# Add to PowerShell profile ($PROFILE):
Invoke-Expression (& mcplint completions powershell | Out-String)

# Or save to completions file:
mcplint completions powershell > $HOME\Documents\PowerShell\Completions\mcplint.ps1"#.to_string()
        }
        Shell::Elvish => {
            r#"# Add to ~/.config/elvish/rc.elv:
eval (mcplint completions elvish | slurp)

# Or save to lib directory:
mcplint completions elvish > ~/.config/elvish/lib/mcplint.elv"#.to_string()
        }
        _ => "See shell documentation for completion installation".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_completions_filename() {
        assert_eq!(get_completions_filename(Shell::Bash), "mcplint");
        assert_eq!(get_completions_filename(Shell::Zsh), "_mcplint");
        assert_eq!(get_completions_filename(Shell::Fish), "mcplint.fish");
        assert_eq!(get_completions_filename(Shell::PowerShell), "mcplint.ps1");
    }

    #[test]
    fn test_profile_completions() {
        let profiles = get_profile_completions();
        assert_eq!(profiles.len(), 4);
        assert!(profiles.iter().any(|(name, _)| *name == "quick"));
        assert!(profiles.iter().any(|(name, _)| *name == "standard"));
    }

    #[test]
    fn test_format_completions() {
        let formats = get_format_completions();
        assert_eq!(formats.len(), 5);
        assert!(formats.iter().any(|(name, _)| *name == "text"));
        assert!(formats.iter().any(|(name, _)| *name == "sarif"));
    }

    #[test]
    fn test_severity_completions() {
        let severities = get_severity_completions();
        assert_eq!(severities.len(), 5);
        assert!(severities.iter().any(|(name, _)| *name == "critical"));
        assert!(severities.iter().any(|(name, _)| *name == "info"));
    }

    #[test]
    fn test_provider_completions() {
        let providers = get_provider_completions();
        assert_eq!(providers.len(), 3);
        assert!(providers.iter().any(|(name, _)| *name == "ollama"));
    }

    #[test]
    fn test_recipe_completions() {
        let recipes = get_recipe_completions();
        assert!(recipes.len() >= 8);
        assert!(recipes.iter().any(|(name, _)| *name == "first-scan"));
    }

    #[test]
    fn test_cache_category_completions() {
        let categories = get_cache_category_completions();
        assert_eq!(categories.len(), 5);
        assert!(categories.iter().any(|(name, _)| *name == "schemas"));
    }

    #[test]
    fn test_rule_category_completions() {
        let categories = get_rule_category_completions();
        assert_eq!(categories.len(), 7);
        assert!(categories.iter().any(|(name, _)| *name == "security"));
    }

    #[test]
    fn test_fuzz_profile_completions() {
        let profiles = get_fuzz_profile_completions();
        assert_eq!(profiles.len(), 4);
        assert!(profiles.iter().any(|(name, _)| *name == "ci"));
    }

    #[test]
    fn test_audience_completions() {
        let audiences = get_audience_completions();
        assert_eq!(audiences.len(), 3);
        assert!(audiences.iter().any(|(name, _)| *name == "intermediate"));
    }

    #[test]
    fn test_get_server_names_empty_without_config() {
        // Should return empty vec when no config exists (won't crash)
        let servers = get_server_names();
        // May or may not have servers depending on test environment
        // Just ensure it doesn't panic - Vec is always valid
        let _ = servers;
    }

    #[test]
    fn test_install_instructions_not_empty() {
        assert!(!get_install_instructions(Shell::Bash).is_empty());
        assert!(!get_install_instructions(Shell::Zsh).is_empty());
        assert!(!get_install_instructions(Shell::Fish).is_empty());
        assert!(!get_install_instructions(Shell::PowerShell).is_empty());
    }
}
