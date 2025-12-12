//! Enhanced error handling with miette diagnostics
//!
//! Provides rich, user-friendly error messages with source code context,
//! helpful suggestions, and documentation links.

// This module provides public API types for library consumers
#![allow(dead_code)]

pub mod suggestions;

use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

/// Main error type for mcplint with rich diagnostics
#[derive(Error, Debug, Diagnostic)]
pub enum McpLintError {
    /// Server connection failed
    #[error("Server connection failed: {message}")]
    #[diagnostic(
        code(mcplint::connection),
        help("{suggestion}"),
        url("https://github.com/quanticsoul4772/mcplint#troubleshooting")
    )]
    ServerConnectionFailed { message: String, suggestion: String },

    /// Unknown server name
    #[error("Unknown server: '{server_name}'")]
    #[diagnostic(code(mcplint::unknown_server), help("{suggestion}"))]
    UnknownServer {
        server_name: String,
        suggestion: String,
    },

    /// Invalid configuration file
    #[error("Invalid configuration: {advice}")]
    #[diagnostic(code(mcplint::config::invalid))]
    InvalidConfig {
        #[source_code]
        src: NamedSource<String>,
        #[label("error here")]
        span: SourceSpan,
        advice: String,
    },

    /// Configuration file not found
    #[error("Configuration file not found")]
    #[diagnostic(code(mcplint::config::not_found), help("{suggestion}"))]
    ConfigNotFound { suggestion: String },

    /// Security violation detected
    #[error("Security violation: {rule_id}")]
    #[diagnostic(code(mcplint::security), severity(Error))]
    SecurityViolation {
        rule_id: String,
        message: String,
        #[help]
        fix_suggestion: Option<String>,
    },

    /// Protocol error during MCP communication
    #[error("MCP protocol error: {message}")]
    #[diagnostic(code(mcplint::protocol), help("{suggestion}"))]
    ProtocolError { message: String, suggestion: String },

    /// Server timeout
    #[error("Server timeout after {timeout_secs} seconds")]
    #[diagnostic(
        code(mcplint::timeout),
        help(
            "Try increasing the timeout with --timeout {suggested_timeout}\n\
              Or check if the server is responding correctly"
        )
    )]
    Timeout {
        timeout_secs: u64,
        suggested_timeout: u64,
    },

    /// Server process exited unexpectedly
    #[error("Server process exited with code {exit_code}")]
    #[diagnostic(code(mcplint::process_exit), help("{suggestion}"))]
    ProcessExit { exit_code: i32, suggestion: String },

    /// Missing environment variable
    #[error("Missing environment variable: {var_name}")]
    #[diagnostic(
        code(mcplint::env::missing),
        help("Set the environment variable:\n  export {var_name}=<value>\n\n{context}")
    )]
    MissingEnvVar { var_name: String, context: String },

    /// Invalid command or argument
    #[error("Invalid command: '{command}'")]
    #[diagnostic(code(mcplint::invalid_command), help("{suggestion}"))]
    InvalidCommand { command: String, suggestion: String },

    /// File not found
    #[error("File not found: {path}")]
    #[diagnostic(
        code(mcplint::file::not_found),
        help("Check that the file path is correct and the file exists")
    )]
    FileNotFound { path: String },

    /// Permission denied
    #[error("Permission denied: {path}")]
    #[diagnostic(
        code(mcplint::permission),
        help("Check file permissions:\n  ls -la {path}\n\nOr run with appropriate permissions")
    )]
    PermissionDenied { path: String },

    /// JSON parsing error
    #[error("Failed to parse JSON: {message}")]
    #[diagnostic(code(mcplint::json::parse))]
    JsonParseError {
        message: String,
        #[source_code]
        src: Option<NamedSource<String>>,
        #[label("parse error here")]
        span: Option<SourceSpan>,
    },

    /// Generic IO error with context
    #[error("IO error: {message}")]
    #[diagnostic(code(mcplint::io), help("{suggestion}"))]
    IoError { message: String, suggestion: String },

    /// Validation failed
    #[error("Validation failed: {count} issues found")]
    #[diagnostic(
        code(mcplint::validation::failed),
        help("Run 'mcplint validate {server} --details' for more information")
    )]
    ValidationFailed { server: String, count: usize },

    /// Scan failed
    #[error("Security scan failed: {message}")]
    #[diagnostic(code(mcplint::scan::failed), help("{suggestion}"))]
    ScanFailed { message: String, suggestion: String },

    /// Fuzzing error
    #[error("Fuzzing error: {message}")]
    #[diagnostic(code(mcplint::fuzz::error), help("{suggestion}"))]
    FuzzError { message: String, suggestion: String },
}

impl McpLintError {
    /// Create a connection failed error with intelligent suggestions
    pub fn connection_failed(message: impl Into<String>) -> Self {
        let msg = message.into();
        let suggestion = Self::generate_connection_suggestion(&msg);

        Self::ServerConnectionFailed {
            message: msg,
            suggestion,
        }
    }

    /// Create an unknown server error with suggestions
    pub fn unknown_server(server_name: impl Into<String>, known_servers: &[String]) -> Self {
        let name = server_name.into();
        let suggestion = suggestions::suggest_server(&name, known_servers);

        Self::UnknownServer {
            server_name: name,
            suggestion,
        }
    }

    /// Create a timeout error with suggested timeout
    pub fn timeout(timeout_secs: u64) -> Self {
        Self::Timeout {
            timeout_secs,
            suggested_timeout: timeout_secs * 2,
        }
    }

    /// Create a protocol error with suggestion
    pub fn protocol_error(message: impl Into<String>) -> Self {
        let msg = message.into();
        let suggestion = Self::generate_protocol_suggestion(&msg);

        Self::ProtocolError {
            message: msg,
            suggestion,
        }
    }

    /// Create a process exit error with intelligent suggestions
    pub fn process_exit(exit_code: i32) -> Self {
        let suggestion = Self::generate_exit_suggestion(exit_code);

        Self::ProcessExit {
            exit_code,
            suggestion,
        }
    }

    /// Create an invalid command error with suggestions
    pub fn invalid_command(command: impl Into<String>) -> Self {
        let cmd = command.into();
        let suggestion = suggestions::suggest_command(&cmd);

        Self::InvalidCommand {
            command: cmd,
            suggestion,
        }
    }

    /// Create a missing env var error with context
    pub fn missing_env_var(var_name: impl Into<String>, context: impl Into<String>) -> Self {
        Self::MissingEnvVar {
            var_name: var_name.into(),
            context: context.into(),
        }
    }

    /// Create a config not found error
    pub fn config_not_found() -> Self {
        Self::ConfigNotFound {
            suggestion: "MCPLint reads server configuration from Claude Desktop config.\n\
                        \n\
                        Expected locations:\n\
                        • Windows: %APPDATA%\\Claude\\claude_desktop_config.json\n\
                        • macOS: ~/Library/Application Support/Claude/claude_desktop_config.json\n\
                        • Linux: ~/.config/Claude/claude_desktop_config.json\n\
                        \n\
                        Or create a project config with: mcplint init"
                .to_string(),
        }
    }

    fn generate_connection_suggestion(error: &str) -> String {
        let error_lower = error.to_lowercase();

        if error_lower.contains("connection refused") {
            "The server may not be running. Check that:\n\
             1. The server path is correct\n\
             2. The server has execute permissions\n\
             3. All dependencies are installed\n\
             \n\
             Try: mcplint doctor --extended"
                .to_string()
        } else if error_lower.contains("timeout") {
            "The server is not responding. Try:\n\
             1. Increasing the timeout: --timeout 60\n\
             2. Checking server logs for errors\n\
             3. Running 'mcplint doctor' to check prerequisites"
                .to_string()
        } else if error_lower.contains("permission") || error_lower.contains("access denied") {
            "Permission denied. Try:\n\
             1. Check the server file has execute permissions\n\
             2. On Unix: chmod +x <server-path>\n\
             3. Ensure no other process is using the server"
                .to_string()
        } else if error_lower.contains("not found") || error_lower.contains("no such file") {
            "The server executable was not found. Check that:\n\
             1. The path in your config is correct\n\
             2. The server is installed\n\
             3. For npx servers, ensure Node.js is installed"
                .to_string()
        } else if error_lower.contains("spawn") {
            "Failed to spawn server process. Possible causes:\n\
             1. Missing runtime (node, python, etc.)\n\
             2. Invalid server configuration\n\
             3. Environment issues\n\
             \n\
             Run: mcplint doctor --extended"
                .to_string()
        } else {
            "Check the server configuration and try again.\n\
             Run 'mcplint doctor' to diagnose common issues."
                .to_string()
        }
    }

    fn generate_protocol_suggestion(error: &str) -> String {
        let error_lower = error.to_lowercase();

        if error_lower.contains("version") || error_lower.contains("protocol") {
            "Protocol version mismatch. The server may use an incompatible MCP version.\n\
             Check that both mcplint and the server support compatible protocol versions."
                .to_string()
        } else if error_lower.contains("json") || error_lower.contains("parse") {
            "Invalid JSON response from server.\n\
             The server may be outputting non-JSON data to stdout.\n\
             Check server logs for errors or debug output."
                .to_string()
        } else if error_lower.contains("initialize") {
            "Server initialization failed.\n\
             The server may have crashed during startup or returned invalid capabilities."
                .to_string()
        } else {
            "An MCP protocol error occurred.\n\
             Check that the server implements the MCP specification correctly."
                .to_string()
        }
    }

    fn generate_exit_suggestion(exit_code: i32) -> String {
        match exit_code {
            0 => "Server exited successfully but unexpectedly.\n\
                  The server may have finished processing or encountered an internal exit condition."
                .to_string(),
            1 => "Server exited with error code 1 (general error).\n\
                  Check server logs for error messages."
                .to_string(),
            2 => "Server exited with code 2 (misuse of command).\n\
                  Check the server arguments in your configuration."
                .to_string(),
            126 => "Permission denied or command not executable.\n\
                    Check file permissions: chmod +x <server-path>"
                .to_string(),
            127 => "Command not found.\n\
                    The server executable or interpreter is missing.\n\
                    Run: mcplint doctor"
                .to_string(),
            130 => "Server was interrupted (Ctrl+C).\n\
                    This is usually expected behavior during testing."
                .to_string(),
            137 => "Server was killed (SIGKILL).\n\
                    Possible out-of-memory condition or external termination."
                .to_string(),
            139 => "Server crashed with segmentation fault.\n\
                    This indicates a bug in the server implementation."
                .to_string(),
            _ => format!(
                "Server exited with code {}.\n\
                 Check server logs for more information.",
                exit_code
            ),
        }
    }
}

/// Convert anyhow::Error to McpLintError for display
pub fn format_error(err: &anyhow::Error) -> String {
    let err_string = err.to_string();
    let err_lower = err_string.to_lowercase();

    // Add contextual help based on error content
    if err_lower.contains("connection") || err_lower.contains("connect") {
        format!(
            "{}\n\nHint: Run 'mcplint doctor' to check your environment",
            err
        )
    } else if err_lower.contains("timeout") {
        format!(
            "{}\n\nHint: Try increasing timeout with --timeout <seconds>",
            err
        )
    } else if err_lower.contains("not found") {
        format!(
            "{}\n\nHint: Run 'mcplint servers' to see available servers",
            err
        )
    } else {
        err.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_failed_suggests_doctor() {
        let err = McpLintError::connection_failed("Connection refused");
        if let McpLintError::ServerConnectionFailed { suggestion, .. } = err {
            assert!(suggestion.contains("doctor"));
        } else {
            panic!("Expected ServerConnectionFailed");
        }
    }

    #[test]
    fn connection_failed_timeout_suggests_increase() {
        let err = McpLintError::connection_failed("timeout waiting for response");
        if let McpLintError::ServerConnectionFailed { suggestion, .. } = err {
            assert!(suggestion.contains("timeout"));
        } else {
            panic!("Expected ServerConnectionFailed");
        }
    }

    #[test]
    fn unknown_server_generates_suggestion() {
        let known = vec!["filesystem".to_string(), "memory".to_string()];
        let err = McpLintError::unknown_server("filesystm", &known);
        if let McpLintError::UnknownServer { suggestion, .. } = err {
            assert!(suggestion.contains("filesystem") || suggestion.contains("servers"));
        } else {
            panic!("Expected UnknownServer");
        }
    }

    #[test]
    fn timeout_doubles_suggestion() {
        let err = McpLintError::timeout(30);
        if let McpLintError::Timeout {
            suggested_timeout, ..
        } = err
        {
            assert_eq!(suggested_timeout, 60);
        } else {
            panic!("Expected Timeout");
        }
    }

    #[test]
    fn process_exit_code_127() {
        let err = McpLintError::process_exit(127);
        if let McpLintError::ProcessExit { suggestion, .. } = err {
            assert!(suggestion.contains("not found"));
        } else {
            panic!("Expected ProcessExit");
        }
    }

    #[test]
    fn config_not_found_shows_paths() {
        let err = McpLintError::config_not_found();
        if let McpLintError::ConfigNotFound { suggestion } = err {
            assert!(suggestion.contains("Windows"));
            assert!(suggestion.contains("macOS"));
            assert!(suggestion.contains("Linux"));
        } else {
            panic!("Expected ConfigNotFound");
        }
    }

    #[test]
    fn invalid_command_generates_suggestion() {
        let err = McpLintError::invalid_command("scna");
        if let McpLintError::InvalidCommand { suggestion, .. } = err {
            assert!(!suggestion.is_empty());
        } else {
            panic!("Expected InvalidCommand");
        }
    }

    #[test]
    fn format_error_adds_hints() {
        let err = anyhow::anyhow!("Connection refused to server");
        let formatted = format_error(&err);
        assert!(formatted.contains("doctor"));
    }
}
