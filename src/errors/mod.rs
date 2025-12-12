//! Enhanced error handling with miette diagnostics
//!
//! Provides rich, user-friendly error messages with source code context,
//! helpful suggestions, and documentation links.

// This module provides public API types for library consumers
#![allow(dead_code)]
// Fields in error variants are used by miette/thiserror derive macros for formatting,
// but clippy incorrectly reports them as unused assignments
#![allow(unused_assignments)]

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

    // Test all error variant creation and Display
    #[test]
    fn server_connection_failed_display() {
        let err = McpLintError::ServerConnectionFailed {
            message: "Failed to connect".to_string(),
            suggestion: "Check configuration".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("Server connection failed"));
        assert!(display.contains("Failed to connect"));
    }

    #[test]
    fn unknown_server_display() {
        let err = McpLintError::UnknownServer {
            server_name: "test-server".to_string(),
            suggestion: "Did you mean 'filesystem'?".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("Unknown server"));
        assert!(display.contains("test-server"));
    }

    #[test]
    fn invalid_config_display() {
        let err = McpLintError::InvalidConfig {
            src: NamedSource::new("test.json", "{}".to_string()),
            span: (0, 2).into(),
            advice: "Fix the config".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("Invalid configuration"));
        assert!(display.contains("Fix the config"));
    }

    #[test]
    fn config_not_found_display() {
        let err = McpLintError::ConfigNotFound {
            suggestion: "Run mcplint init".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("Configuration file not found"));
    }

    #[test]
    fn security_violation_display() {
        let err = McpLintError::SecurityViolation {
            rule_id: "SEC-001".to_string(),
            message: "Path traversal detected".to_string(),
            fix_suggestion: Some("Sanitize input".to_string()),
        };
        let display = format!("{}", err);
        assert!(display.contains("Security violation"));
        assert!(display.contains("SEC-001"));
    }

    #[test]
    fn security_violation_without_fix_suggestion() {
        let err = McpLintError::SecurityViolation {
            rule_id: "SEC-002".to_string(),
            message: "Injection detected".to_string(),
            fix_suggestion: None,
        };
        let display = format!("{}", err);
        assert!(display.contains("Security violation"));
        assert!(display.contains("SEC-002"));
    }

    #[test]
    fn protocol_error_display() {
        let err = McpLintError::ProtocolError {
            message: "Invalid JSON-RPC".to_string(),
            suggestion: "Check protocol version".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("MCP protocol error"));
        assert!(display.contains("Invalid JSON-RPC"));
    }

    #[test]
    fn timeout_display() {
        let err = McpLintError::Timeout {
            timeout_secs: 30,
            suggested_timeout: 60,
        };
        let display = format!("{}", err);
        assert!(display.contains("Server timeout"));
        assert!(display.contains("30 seconds"));
    }

    #[test]
    fn process_exit_display() {
        let err = McpLintError::ProcessExit {
            exit_code: 1,
            suggestion: "Check logs".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("Server process exited"));
        assert!(display.contains("code 1"));
    }

    #[test]
    fn missing_env_var_display() {
        let err = McpLintError::MissingEnvVar {
            var_name: "API_KEY".to_string(),
            context: "Required for authentication".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("Missing environment variable"));
        assert!(display.contains("API_KEY"));
    }

    #[test]
    fn invalid_command_display() {
        let err = McpLintError::InvalidCommand {
            command: "scna".to_string(),
            suggestion: "Did you mean 'scan'?".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("Invalid command"));
        assert!(display.contains("scna"));
    }

    #[test]
    fn file_not_found_display() {
        let err = McpLintError::FileNotFound {
            path: "/path/to/file.txt".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("File not found"));
        assert!(display.contains("/path/to/file.txt"));
    }

    #[test]
    fn permission_denied_display() {
        let err = McpLintError::PermissionDenied {
            path: "/secure/file".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("Permission denied"));
        assert!(display.contains("/secure/file"));
    }

    #[test]
    fn json_parse_error_display() {
        let err = McpLintError::JsonParseError {
            message: "Unexpected token".to_string(),
            src: None,
            span: None,
        };
        let display = format!("{}", err);
        assert!(display.contains("Failed to parse JSON"));
        assert!(display.contains("Unexpected token"));
    }

    #[test]
    fn json_parse_error_with_source() {
        let err = McpLintError::JsonParseError {
            message: "Invalid syntax".to_string(),
            src: Some(NamedSource::new("data.json", "{invalid}".to_string())),
            span: Some((0, 9).into()),
        };
        let display = format!("{}", err);
        assert!(display.contains("Failed to parse JSON"));
        assert!(display.contains("Invalid syntax"));
    }

    #[test]
    fn io_error_display() {
        let err = McpLintError::IoError {
            message: "Failed to read file".to_string(),
            suggestion: "Check permissions".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("IO error"));
        assert!(display.contains("Failed to read file"));
    }

    #[test]
    fn validation_failed_display() {
        let err = McpLintError::ValidationFailed {
            server: "test-server".to_string(),
            count: 5,
        };
        let display = format!("{}", err);
        assert!(display.contains("Validation failed"));
        assert!(display.contains("5 issues"));
    }

    #[test]
    fn scan_failed_display() {
        let err = McpLintError::ScanFailed {
            message: "Scanner crashed".to_string(),
            suggestion: "Retry with --verbose".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("Security scan failed"));
        assert!(display.contains("Scanner crashed"));
    }

    #[test]
    fn fuzz_error_display() {
        let err = McpLintError::FuzzError {
            message: "Corpus generation failed".to_string(),
            suggestion: "Check input format".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("Fuzzing error"));
        assert!(display.contains("Corpus generation failed"));
    }

    // Test Debug implementations
    #[test]
    fn error_debug_format() {
        let err = McpLintError::timeout(30);
        let debug = format!("{:?}", err);
        assert!(debug.contains("Timeout"));
        assert!(debug.contains("timeout_secs"));
    }

    // Test connection_failed helper with different error types
    #[test]
    fn connection_failed_permission_error() {
        let err = McpLintError::connection_failed("Permission denied");
        if let McpLintError::ServerConnectionFailed { suggestion, .. } = err {
            assert!(suggestion.contains("permission") || suggestion.contains("chmod"));
        } else {
            panic!("Expected ServerConnectionFailed");
        }
    }

    #[test]
    fn connection_failed_not_found_error() {
        let err = McpLintError::connection_failed("No such file or directory");
        if let McpLintError::ServerConnectionFailed { suggestion, .. } = err {
            assert!(suggestion.contains("not found") || suggestion.contains("installed"));
        } else {
            panic!("Expected ServerConnectionFailed");
        }
    }

    #[test]
    fn connection_failed_spawn_error() {
        let err = McpLintError::connection_failed("Failed to spawn process");
        if let McpLintError::ServerConnectionFailed { suggestion, .. } = err {
            assert!(suggestion.contains("spawn") || suggestion.contains("doctor"));
        } else {
            panic!("Expected ServerConnectionFailed");
        }
    }

    #[test]
    fn connection_failed_generic_error() {
        let err = McpLintError::connection_failed("Unknown error");
        if let McpLintError::ServerConnectionFailed { suggestion, .. } = err {
            assert!(suggestion.contains("doctor") || suggestion.contains("configuration"));
        } else {
            panic!("Expected ServerConnectionFailed");
        }
    }

    // Test protocol_error helper with different error types
    #[test]
    fn protocol_error_version_mismatch() {
        let err = McpLintError::protocol_error("Protocol version mismatch");
        if let McpLintError::ProtocolError { suggestion, .. } = err {
            assert!(suggestion.contains("version") || suggestion.contains("compatible"));
        } else {
            panic!("Expected ProtocolError");
        }
    }

    #[test]
    fn protocol_error_json_parse() {
        let err = McpLintError::protocol_error("Invalid JSON response");
        if let McpLintError::ProtocolError { suggestion, .. } = err {
            assert!(suggestion.contains("JSON") || suggestion.contains("stdout"));
        } else {
            panic!("Expected ProtocolError");
        }
    }

    #[test]
    fn protocol_error_initialization() {
        let err = McpLintError::protocol_error("Failed to initialize server");
        if let McpLintError::ProtocolError { suggestion, .. } = err {
            assert!(suggestion.contains("initialization") || suggestion.contains("startup"));
        } else {
            panic!("Expected ProtocolError");
        }
    }

    #[test]
    fn protocol_error_generic() {
        let err = McpLintError::protocol_error("Unknown protocol error");
        if let McpLintError::ProtocolError { suggestion, .. } = err {
            assert!(suggestion.contains("protocol") || suggestion.contains("specification"));
        } else {
            panic!("Expected ProtocolError");
        }
    }

    // Test process_exit helper with different exit codes
    #[test]
    fn process_exit_code_0() {
        let err = McpLintError::process_exit(0);
        if let McpLintError::ProcessExit { suggestion, .. } = err {
            assert!(suggestion.contains("successfully") || suggestion.contains("unexpectedly"));
        } else {
            panic!("Expected ProcessExit");
        }
    }

    #[test]
    fn process_exit_code_1() {
        let err = McpLintError::process_exit(1);
        if let McpLintError::ProcessExit { suggestion, .. } = err {
            assert!(suggestion.contains("general error") || suggestion.contains("logs"));
        } else {
            panic!("Expected ProcessExit");
        }
    }

    #[test]
    fn process_exit_code_2() {
        let err = McpLintError::process_exit(2);
        if let McpLintError::ProcessExit { suggestion, .. } = err {
            assert!(suggestion.contains("misuse") || suggestion.contains("arguments"));
        } else {
            panic!("Expected ProcessExit");
        }
    }

    #[test]
    fn process_exit_code_126() {
        let err = McpLintError::process_exit(126);
        if let McpLintError::ProcessExit { suggestion, .. } = err {
            assert!(suggestion.contains("Permission") || suggestion.contains("chmod"));
        } else {
            panic!("Expected ProcessExit");
        }
    }

    #[test]
    fn process_exit_code_130() {
        let err = McpLintError::process_exit(130);
        if let McpLintError::ProcessExit { suggestion, .. } = err {
            assert!(suggestion.contains("interrupted") || suggestion.contains("Ctrl+C"));
        } else {
            panic!("Expected ProcessExit");
        }
    }

    #[test]
    fn process_exit_code_137() {
        let err = McpLintError::process_exit(137);
        if let McpLintError::ProcessExit { suggestion, .. } = err {
            assert!(suggestion.contains("killed") || suggestion.contains("memory"));
        } else {
            panic!("Expected ProcessExit");
        }
    }

    #[test]
    fn process_exit_code_139() {
        let err = McpLintError::process_exit(139);
        if let McpLintError::ProcessExit { suggestion, .. } = err {
            assert!(suggestion.contains("segmentation fault") || suggestion.contains("bug"));
        } else {
            panic!("Expected ProcessExit");
        }
    }

    #[test]
    fn process_exit_code_unknown() {
        let err = McpLintError::process_exit(99);
        if let McpLintError::ProcessExit { suggestion, .. } = err {
            assert!(suggestion.contains("code 99") || suggestion.contains("logs"));
        } else {
            panic!("Expected ProcessExit");
        }
    }

    // Test missing_env_var helper
    #[test]
    fn missing_env_var_creation() {
        let err = McpLintError::missing_env_var("DATABASE_URL", "Required for database connection");
        if let McpLintError::MissingEnvVar { var_name, context } = err {
            assert_eq!(var_name, "DATABASE_URL");
            assert_eq!(context, "Required for database connection");
        } else {
            panic!("Expected MissingEnvVar");
        }
    }

    // Test format_error with different error types
    #[test]
    fn format_error_timeout() {
        let err = anyhow::anyhow!("Operation timeout after 30s");
        let formatted = format_error(&err);
        assert!(formatted.contains("timeout"));
        assert!(formatted.contains("--timeout"));
    }

    #[test]
    fn format_error_not_found() {
        let err = anyhow::anyhow!("Server not found in configuration");
        let formatted = format_error(&err);
        assert!(formatted.contains("not found"));
        assert!(formatted.contains("mcplint servers"));
    }

    #[test]
    fn format_error_generic() {
        let err = anyhow::anyhow!("Some random error");
        let formatted = format_error(&err);
        assert_eq!(formatted, "Some random error");
    }

    // Test unknown_server with empty known servers
    #[test]
    fn unknown_server_no_known_servers() {
        let known: Vec<String> = vec![];
        let err = McpLintError::unknown_server("test", &known);
        if let McpLintError::UnknownServer {
            server_name,
            suggestion,
        } = err
        {
            assert_eq!(server_name, "test");
            assert!(!suggestion.is_empty());
        } else {
            panic!("Expected UnknownServer");
        }
    }

    // Test edge cases for timeout
    #[test]
    fn timeout_large_value() {
        let err = McpLintError::timeout(3600);
        if let McpLintError::Timeout {
            timeout_secs,
            suggested_timeout,
        } = err
        {
            assert_eq!(timeout_secs, 3600);
            assert_eq!(suggested_timeout, 7200);
        } else {
            panic!("Expected Timeout");
        }
    }

    #[test]
    fn timeout_zero() {
        let err = McpLintError::timeout(0);
        if let McpLintError::Timeout {
            timeout_secs,
            suggested_timeout,
        } = err
        {
            assert_eq!(timeout_secs, 0);
            assert_eq!(suggested_timeout, 0);
        } else {
            panic!("Expected Timeout");
        }
    }
}
