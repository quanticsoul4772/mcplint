//! Multi-Server Analysis - Parallel scanning of multiple MCP servers
//!
//! This module implements the M7 milestone Phase 2: Multi-Server Analysis.
//! It provides orchestrated scanning of multiple MCP servers in parallel
//! with combined reporting and aggregated results.
//!
//! # Features
//!
//! - Parallel execution of scans across multiple servers
//! - Combined SARIF/JSON/text reporting
//! - Aggregated statistics and cross-server analysis
//! - Configurable concurrency limits
//!
//! # Example
//!
//! ```ignore
//! use mcplint::scanner::multi_server::{MultiServerScanner, ServerConfig};
//!
//! let configs = vec![
//!     ServerConfig::new("server1", "/path/to/server1"),
//!     ServerConfig::new("server2", "/path/to/server2"),
//! ];
//!
//! let scanner = MultiServerScanner::new(configs)
//!     .with_concurrency(4)
//!     .with_timeout(60);
//!
//! let results = scanner.scan_all().await?;
//! results.print_summary();
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tracing::{debug, error, info};

use super::context::ScanConfig;
use super::{ScanEngine, ScanProfile, ScanResults, Severity};

/// Configuration for a single server to scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server name (display name)
    pub name: String,
    /// Server command or path
    pub command: String,
    /// Arguments to pass to the server
    pub args: Vec<String>,
    /// Environment variables to set
    pub env: HashMap<String, String>,
    /// Server-specific timeout override (optional)
    pub timeout: Option<u64>,
    /// Server-specific profile override (optional)
    pub profile: Option<ScanProfile>,
}

impl ServerConfig {
    /// Create a new server configuration
    pub fn new(name: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            command: command.into(),
            args: Vec::new(),
            env: HashMap::new(),
            timeout: None,
            profile: None,
        }
    }

    /// Add arguments to the server command
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Add environment variables
    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env = env;
        self
    }

    /// Set a server-specific timeout
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set a server-specific scan profile
    pub fn with_profile(mut self, profile: ScanProfile) -> Self {
        self.profile = Some(profile);
        self
    }
}

/// Result from scanning a single server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerScanResult {
    /// Server configuration
    pub server: ServerConfig,
    /// Scan results (if successful)
    pub results: Option<ScanResults>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Duration of the scan
    pub duration: Duration,
    /// Whether the scan completed successfully
    pub success: bool,
}

impl ServerScanResult {
    /// Create a successful result
    pub fn success(server: ServerConfig, results: ScanResults, duration: Duration) -> Self {
        Self {
            server,
            results: Some(results),
            error: None,
            duration,
            success: true,
        }
    }

    /// Create a failed result
    pub fn failure(server: ServerConfig, error: String, duration: Duration) -> Self {
        Self {
            server,
            results: None,
            error: Some(error),
            duration,
            success: false,
        }
    }

    /// Get finding count (0 if failed or no findings)
    pub fn finding_count(&self) -> usize {
        self.results.as_ref().map(|r| r.findings.len()).unwrap_or(0)
    }

    /// Get findings by severity
    #[allow(dead_code)] // Public API method for library consumers
    pub fn findings_by_severity(&self, severity: Severity) -> usize {
        self.results
            .as_ref()
            .map(|r| r.findings.iter().filter(|f| f.severity == severity).count())
            .unwrap_or(0)
    }
}

/// Combined results from scanning multiple servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiServerResults {
    /// Individual server results
    pub servers: Vec<ServerScanResult>,
    /// Total scan duration
    pub total_duration: Duration,
    /// Number of servers scanned
    pub server_count: usize,
    /// Number of successful scans
    pub success_count: usize,
    /// Number of failed scans
    pub failure_count: usize,
    /// Total findings across all servers
    pub total_findings: usize,
    /// Findings breakdown by severity
    pub severity_counts: HashMap<String, usize>,
}

impl MultiServerResults {
    /// Create results from individual server scans
    pub fn from_server_results(servers: Vec<ServerScanResult>, total_duration: Duration) -> Self {
        let server_count = servers.len();
        let success_count = servers.iter().filter(|s| s.success).count();
        let failure_count = server_count - success_count;
        let total_findings: usize = servers.iter().map(|s| s.finding_count()).sum();

        // Aggregate severity counts
        let mut severity_counts = HashMap::new();
        for server in &servers {
            if let Some(results) = &server.results {
                for finding in &results.findings {
                    let key = format!("{:?}", finding.severity).to_lowercase();
                    *severity_counts.entry(key).or_insert(0) += 1;
                }
            }
        }

        Self {
            servers,
            total_duration,
            server_count,
            success_count,
            failure_count,
            total_findings,
            severity_counts,
        }
    }

    /// Check if all scans were successful
    pub fn all_success(&self) -> bool {
        self.failure_count == 0
    }

    /// Check if any critical findings were found
    #[allow(dead_code)] // Public API method for library consumers
    pub fn has_critical_findings(&self) -> bool {
        self.severity_counts.get("critical").copied().unwrap_or(0) > 0
    }

    /// Check if any high findings were found
    #[allow(dead_code)] // Public API method for library consumers
    pub fn has_high_findings(&self) -> bool {
        self.severity_counts.get("high").copied().unwrap_or(0) > 0
    }

    /// Get all findings from all servers
    #[allow(dead_code)] // Public API method for library consumers
    pub fn all_findings(&self) -> Vec<&super::Finding> {
        self.servers
            .iter()
            .filter_map(|s| s.results.as_ref())
            .flat_map(|r| &r.findings)
            .collect()
    }

    /// Get failed server names
    pub fn failed_servers(&self) -> Vec<&str> {
        self.servers
            .iter()
            .filter(|s| !s.success)
            .map(|s| s.server.name.as_str())
            .collect()
    }

    /// Print a summary of results
    pub fn print_summary(&self) {
        use colored::Colorize;

        println!();
        println!("{}", "═══════════════════════════════════════".cyan());
        println!("{}", " Multi-Server Scan Results".cyan().bold());
        println!("{}", "═══════════════════════════════════════".cyan());
        println!();

        // Overview
        println!("{}", "Overview:".yellow().bold());
        println!(
            "  Servers scanned: {}",
            self.server_count.to_string().white()
        );
        println!("  Successful: {}", self.success_count.to_string().green());
        if self.failure_count > 0 {
            println!("  Failed: {}", self.failure_count.to_string().red());
        }
        println!(
            "  Total duration: {:.2}s",
            self.total_duration.as_secs_f64()
        );
        println!();

        // Findings summary
        println!("{}", "Findings Summary:".yellow().bold());
        println!(
            "  Total findings: {}",
            self.total_findings.to_string().white()
        );
        if let Some(critical) = self.severity_counts.get("critical") {
            if *critical > 0 {
                println!("  Critical: {}", critical.to_string().red().bold());
            }
        }
        if let Some(high) = self.severity_counts.get("high") {
            if *high > 0 {
                println!("  High: {}", high.to_string().red());
            }
        }
        if let Some(medium) = self.severity_counts.get("medium") {
            if *medium > 0 {
                println!("  Medium: {}", medium.to_string().yellow());
            }
        }
        if let Some(low) = self.severity_counts.get("low") {
            if *low > 0 {
                println!("  Low: {}", low.to_string().blue());
            }
        }
        println!();

        // Per-server breakdown
        println!("{}", "Per-Server Results:".yellow().bold());
        for result in &self.servers {
            let status = if result.success {
                "✓".green()
            } else {
                "✗".red()
            };
            let findings = if result.success {
                format!("{} findings", result.finding_count())
            } else {
                result
                    .error
                    .clone()
                    .unwrap_or_else(|| "Unknown error".to_string())
            };
            println!(
                "  {} {} - {} ({:.2}s)",
                status,
                result.server.name.white(),
                findings,
                result.duration.as_secs_f64()
            );
        }

        // Failed servers detail
        if self.failure_count > 0 {
            println!();
            println!("{}", "Failed Servers:".red().bold());
            for result in &self.servers {
                if !result.success {
                    println!(
                        "  {} - {}",
                        result.server.name.red(),
                        result.error.as_deref().unwrap_or("Unknown error")
                    );
                }
            }
        }

        println!();
        println!("{}", "═══════════════════════════════════════".cyan());
    }

    /// Convert to combined SARIF format
    pub fn to_sarif(&self) -> serde_json::Value {
        use std::collections::HashSet;

        // Collect all unique rules across all servers
        let mut all_rules: Vec<serde_json::Value> = Vec::new();
        let mut seen_rules: HashSet<String> = HashSet::new();
        let mut all_results: Vec<serde_json::Value> = Vec::new();

        for server_result in &self.servers {
            if let Some(results) = &server_result.results {
                for finding in &results.findings {
                    // Add rule if not seen
                    if !seen_rules.contains(&finding.rule_id) {
                        seen_rules.insert(finding.rule_id.clone());
                        all_rules.push(serde_json::json!({
                            "id": finding.rule_id,
                            "name": finding.title,
                            "shortDescription": {
                                "text": finding.description
                            },
                            "defaultConfiguration": {
                                "level": finding.severity.sarif_level()
                            }
                        }));
                    }

                    // Add result with server context
                    all_results.push(serde_json::json!({
                        "ruleId": finding.rule_id,
                        "level": finding.severity.sarif_level(),
                        "message": {
                            "text": format!("[{}] {}", server_result.server.name, finding.description)
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": server_result.server.command
                                }
                            }
                        }],
                        "properties": {
                            "server": server_result.server.name,
                            "component": finding.location.component,
                            "identifier": finding.location.identifier
                        }
                    }));
                }
            }
        }

        serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "mcplint-multi",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/quanticsoul4772/mcplint",
                        "rules": all_rules
                    }
                },
                "results": all_results,
                "invocations": [{
                    "executionSuccessful": self.all_success(),
                    "properties": {
                        "servers_scanned": self.server_count,
                        "servers_successful": self.success_count,
                        "servers_failed": self.failure_count,
                        "total_findings": self.total_findings,
                        "duration_secs": self.total_duration.as_secs_f64()
                    }
                }]
            }]
        })
    }
}

/// Multi-server scanner that orchestrates parallel scanning
pub struct MultiServerScanner {
    /// Server configurations to scan
    configs: Vec<ServerConfig>,
    /// Maximum concurrent scans
    concurrency: usize,
    /// Default timeout for each scan (seconds)
    default_timeout: u64,
    /// Default scan profile
    default_profile: ScanProfile,
}

impl MultiServerScanner {
    /// Create a new multi-server scanner
    pub fn new(configs: Vec<ServerConfig>) -> Self {
        Self {
            configs,
            concurrency: 4,
            default_timeout: 60,
            default_profile: ScanProfile::Standard,
        }
    }

    /// Set maximum concurrency
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }

    /// Set default timeout for scans
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Set default scan profile
    pub fn with_profile(mut self, profile: ScanProfile) -> Self {
        self.default_profile = profile;
        self
    }

    /// Add a server configuration
    #[allow(dead_code)] // Public API method for library consumers
    pub fn add_server(&mut self, config: ServerConfig) {
        self.configs.push(config);
    }

    /// Get the number of configured servers
    #[allow(dead_code)] // Public API method for library consumers
    pub fn server_count(&self) -> usize {
        self.configs.len()
    }

    /// Scan all configured servers in parallel
    pub async fn scan_all(&self) -> Result<MultiServerResults> {
        let start = Instant::now();

        info!(
            "Starting multi-server scan of {} servers with concurrency {}",
            self.configs.len(),
            self.concurrency
        );

        // Create semaphore for concurrency limiting
        let semaphore = Arc::new(Semaphore::new(self.concurrency));

        // Scan servers in parallel with concurrency limit
        let results: Vec<ServerScanResult> = stream::iter(self.configs.clone())
            .map(|config| {
                let sem = semaphore.clone();
                let timeout = config.timeout.unwrap_or(self.default_timeout);
                let profile = config.profile.unwrap_or(self.default_profile);

                async move {
                    // Acquire semaphore permit
                    let _permit = sem.acquire().await.unwrap();

                    debug!("Starting scan of server: {}", config.name);
                    let scan_start = Instant::now();

                    // Run the scan
                    let result = self.scan_server(&config, timeout, profile).await;
                    let duration = scan_start.elapsed();

                    match result {
                        Ok(scan_results) => {
                            info!(
                                "Completed scan of {}: {} findings in {:.2}s",
                                config.name,
                                scan_results.findings.len(),
                                duration.as_secs_f64()
                            );
                            ServerScanResult::success(config, scan_results, duration)
                        }
                        Err(e) => {
                            error!("Failed to scan {}: {}", config.name, e);
                            ServerScanResult::failure(config, e.to_string(), duration)
                        }
                    }
                }
            })
            .buffer_unordered(self.concurrency)
            .collect()
            .await;

        let total_duration = start.elapsed();
        info!(
            "Multi-server scan completed in {:.2}s",
            total_duration.as_secs_f64()
        );

        Ok(MultiServerResults::from_server_results(
            results,
            total_duration,
        ))
    }

    /// Scan a single server
    async fn scan_server(
        &self,
        config: &ServerConfig,
        timeout: u64,
        profile: ScanProfile,
    ) -> Result<ScanResults> {
        // Create scan config for this server
        let scan_config = ScanConfig::default()
            .with_profile(profile)
            .with_timeout(timeout);

        // Create scan engine with config
        let engine = ScanEngine::new(scan_config);

        // Run the scan
        engine.scan(&config.command, &config.args, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_creation() {
        let config = ServerConfig::new("test-server", "/path/to/server");
        assert_eq!(config.name, "test-server");
        assert_eq!(config.command, "/path/to/server");
        assert!(config.args.is_empty());
    }

    #[test]
    fn server_config_with_args() {
        let config = ServerConfig::new("test", "cmd")
            .with_args(vec!["--port".to_string(), "8080".to_string()]);
        assert_eq!(config.args.len(), 2);
    }

    #[test]
    fn server_config_with_env() {
        let mut env = HashMap::new();
        env.insert("KEY".to_string(), "VALUE".to_string());
        let config = ServerConfig::new("test", "cmd").with_env(env);
        assert_eq!(config.env.get("KEY"), Some(&"VALUE".to_string()));
    }

    #[test]
    fn server_config_with_timeout() {
        let config = ServerConfig::new("test", "cmd").with_timeout(120);
        assert_eq!(config.timeout, Some(120));
    }

    #[test]
    fn server_config_with_profile() {
        let config = ServerConfig::new("test", "cmd").with_profile(ScanProfile::Quick);
        assert_eq!(config.profile, Some(ScanProfile::Quick));
    }

    #[test]
    fn server_scan_result_success() {
        let config = ServerConfig::new("test", "cmd");
        let results = ScanResults::new("test", ScanProfile::Standard);
        let result = ServerScanResult::success(config, results, Duration::from_secs(10));
        assert!(result.success);
        assert!(result.results.is_some());
        assert!(result.error.is_none());
    }

    #[test]
    fn server_scan_result_failure() {
        let config = ServerConfig::new("test", "cmd");
        let result = ServerScanResult::failure(
            config,
            "Connection failed".to_string(),
            Duration::from_secs(5),
        );
        assert!(!result.success);
        assert!(result.results.is_none());
        assert!(result.error.is_some());
    }

    #[test]
    fn server_scan_result_finding_count() {
        let config = ServerConfig::new("test", "cmd");
        let result = ServerScanResult::failure(config, "error".to_string(), Duration::from_secs(1));
        assert_eq!(result.finding_count(), 0);
    }

    #[test]
    fn multi_server_results_creation() {
        let results = MultiServerResults::from_server_results(vec![], Duration::from_secs(1));
        assert_eq!(results.server_count, 0);
        assert_eq!(results.success_count, 0);
        assert_eq!(results.failure_count, 0);
        assert_eq!(results.total_findings, 0);
    }

    #[test]
    fn multi_server_results_all_success() {
        let results = MultiServerResults::from_server_results(vec![], Duration::from_secs(1));
        assert!(results.all_success());
    }

    #[test]
    fn multi_server_results_with_failures() {
        let config = ServerConfig::new("test", "cmd");
        let failure =
            ServerScanResult::failure(config, "error".to_string(), Duration::from_secs(1));
        let results =
            MultiServerResults::from_server_results(vec![failure], Duration::from_secs(1));
        assert!(!results.all_success());
        assert_eq!(results.failure_count, 1);
    }

    #[test]
    fn multi_server_results_failed_servers() {
        let config1 = ServerConfig::new("server1", "cmd1");
        let config2 = ServerConfig::new("server2", "cmd2");
        let success = ServerScanResult::success(
            config1,
            ScanResults::new("server1", ScanProfile::Standard),
            Duration::from_secs(1),
        );
        let failure =
            ServerScanResult::failure(config2, "error".to_string(), Duration::from_secs(1));
        let results =
            MultiServerResults::from_server_results(vec![success, failure], Duration::from_secs(2));

        let failed = results.failed_servers();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0], "server2");
    }

    #[test]
    fn multi_server_scanner_creation() {
        let configs = vec![ServerConfig::new("test", "cmd")];
        let scanner = MultiServerScanner::new(configs);
        assert_eq!(scanner.server_count(), 1);
        assert_eq!(scanner.concurrency, 4);
        assert_eq!(scanner.default_timeout, 60);
    }

    #[test]
    fn multi_server_scanner_with_concurrency() {
        let scanner = MultiServerScanner::new(vec![]).with_concurrency(8);
        assert_eq!(scanner.concurrency, 8);
    }

    #[test]
    fn multi_server_scanner_with_concurrency_minimum() {
        let scanner = MultiServerScanner::new(vec![]).with_concurrency(0);
        assert_eq!(scanner.concurrency, 1);
    }

    #[test]
    fn multi_server_scanner_with_timeout() {
        let scanner = MultiServerScanner::new(vec![]).with_timeout(120);
        assert_eq!(scanner.default_timeout, 120);
    }

    #[test]
    fn multi_server_scanner_with_profile() {
        let scanner = MultiServerScanner::new(vec![]).with_profile(ScanProfile::Quick);
        assert_eq!(scanner.default_profile, ScanProfile::Quick);
    }

    #[test]
    fn multi_server_scanner_add_server() {
        let mut scanner = MultiServerScanner::new(vec![]);
        assert_eq!(scanner.server_count(), 0);
        scanner.add_server(ServerConfig::new("test", "cmd"));
        assert_eq!(scanner.server_count(), 1);
    }

    #[test]
    fn multi_server_results_to_sarif() {
        let results = MultiServerResults::from_server_results(vec![], Duration::from_secs(1));
        let sarif = results.to_sarif();

        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["runs"][0]["tool"]["driver"]["name"]
            .as_str()
            .unwrap()
            .contains("mcplint"));
    }

    #[test]
    fn multi_server_results_has_critical_findings() {
        let results = MultiServerResults {
            servers: vec![],
            total_duration: Duration::from_secs(1),
            server_count: 0,
            success_count: 0,
            failure_count: 0,
            total_findings: 0,
            severity_counts: HashMap::new(),
        };
        assert!(!results.has_critical_findings());
    }

    #[test]
    fn multi_server_results_has_high_findings() {
        let results = MultiServerResults {
            servers: vec![],
            total_duration: Duration::from_secs(1),
            server_count: 0,
            success_count: 0,
            failure_count: 0,
            total_findings: 0,
            severity_counts: HashMap::new(),
        };
        assert!(!results.has_high_findings());
    }

    #[test]
    fn multi_server_results_with_severity_counts() {
        let mut severity_counts = HashMap::new();
        severity_counts.insert("critical".to_string(), 2);
        severity_counts.insert("high".to_string(), 5);

        let results = MultiServerResults {
            servers: vec![],
            total_duration: Duration::from_secs(1),
            server_count: 0,
            success_count: 0,
            failure_count: 0,
            total_findings: 7,
            severity_counts,
        };

        assert!(results.has_critical_findings());
        assert!(results.has_high_findings());
    }

    #[test]
    fn server_config_builder_chain() {
        let mut env = HashMap::new();
        env.insert("API_KEY".to_string(), "secret".to_string());

        let config = ServerConfig::new("my-server", "/usr/bin/server")
            .with_args(vec!["--config".to_string(), "/etc/config.toml".to_string()])
            .with_env(env)
            .with_timeout(180)
            .with_profile(ScanProfile::Full);

        assert_eq!(config.name, "my-server");
        assert_eq!(config.command, "/usr/bin/server");
        assert_eq!(config.args.len(), 2);
        assert_eq!(config.env.len(), 1);
        assert_eq!(config.timeout, Some(180));
        assert_eq!(config.profile, Some(ScanProfile::Full));
    }
}
