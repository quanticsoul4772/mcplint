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

    #[test]
    fn server_scan_result_findings_by_severity() {
        use super::super::{Finding, FindingLocation};

        let config = ServerConfig::new("test", "cmd");
        let mut results = ScanResults::new("test", ScanProfile::Standard);

        // Add findings with different severities
        results.findings.push(
            Finding::new(
                "TEST-001",
                Severity::Critical,
                "Critical Issue",
                "Critical finding",
            )
            .with_location(FindingLocation::tool("test")),
        );

        results.findings.push(
            Finding::new("TEST-002", Severity::High, "High Issue", "High finding")
                .with_location(FindingLocation::tool("test")),
        );

        results.findings.push(
            Finding::new(
                "TEST-003",
                Severity::Critical,
                "Another Critical",
                "Another critical finding",
            )
            .with_location(FindingLocation::tool("test")),
        );

        let result = ServerScanResult::success(config, results, Duration::from_secs(10));

        assert_eq!(result.findings_by_severity(Severity::Critical), 2);
        assert_eq!(result.findings_by_severity(Severity::High), 1);
        assert_eq!(result.findings_by_severity(Severity::Medium), 0);
        assert_eq!(result.findings_by_severity(Severity::Low), 0);
    }

    #[test]
    fn server_scan_result_findings_by_severity_on_failure() {
        let config = ServerConfig::new("test", "cmd");
        let result = ServerScanResult::failure(config, "error".to_string(), Duration::from_secs(1));

        assert_eq!(result.findings_by_severity(Severity::Critical), 0);
        assert_eq!(result.findings_by_severity(Severity::High), 0);
    }

    #[test]
    fn multi_server_results_all_findings() {
        use super::super::{Finding, FindingLocation};

        let config1 = ServerConfig::new("server1", "cmd1");
        let mut results1 = ScanResults::new("server1", ScanProfile::Standard);
        results1.findings.push(
            Finding::new("TEST-001", Severity::Critical, "Issue 1", "Finding 1")
                .with_location(FindingLocation::tool("test")),
        );

        let config2 = ServerConfig::new("server2", "cmd2");
        let mut results2 = ScanResults::new("server2", ScanProfile::Standard);
        results2.findings.push(
            Finding::new("TEST-002", Severity::High, "Issue 2", "Finding 2")
                .with_location(FindingLocation::tool("test")),
        );

        let success1 = ServerScanResult::success(config1, results1, Duration::from_secs(1));
        let success2 = ServerScanResult::success(config2, results2, Duration::from_secs(1));

        let multi_results = MultiServerResults::from_server_results(
            vec![success1, success2],
            Duration::from_secs(2),
        );

        let all_findings = multi_results.all_findings();
        assert_eq!(all_findings.len(), 2);
        assert_eq!(all_findings[0].rule_id, "TEST-001");
        assert_eq!(all_findings[1].rule_id, "TEST-002");
    }

    #[test]
    fn multi_server_results_all_findings_empty() {
        let results = MultiServerResults::from_server_results(vec![], Duration::from_secs(1));
        assert_eq!(results.all_findings().len(), 0);
    }

    #[test]
    fn multi_server_results_all_findings_with_failures() {
        use super::super::{Finding, FindingLocation};

        let config1 = ServerConfig::new("server1", "cmd1");
        let mut results1 = ScanResults::new("server1", ScanProfile::Standard);
        results1.findings.push(
            Finding::new("TEST-001", Severity::Critical, "Issue 1", "Finding 1")
                .with_location(FindingLocation::tool("test")),
        );

        let config2 = ServerConfig::new("server2", "cmd2");

        let success = ServerScanResult::success(config1, results1, Duration::from_secs(1));
        let failure =
            ServerScanResult::failure(config2, "error".to_string(), Duration::from_secs(1));

        let multi_results =
            MultiServerResults::from_server_results(vec![success, failure], Duration::from_secs(2));

        let all_findings = multi_results.all_findings();
        assert_eq!(all_findings.len(), 1);
        assert_eq!(all_findings[0].rule_id, "TEST-001");
    }

    #[test]
    fn multi_server_results_severity_aggregation() {
        use super::super::{Finding, FindingLocation};

        let config1 = ServerConfig::new("server1", "cmd1");
        let mut results1 = ScanResults::new("server1", ScanProfile::Standard);
        results1.findings.push(
            Finding::new(
                "TEST-001",
                Severity::Critical,
                "Critical 1",
                "Critical finding 1",
            )
            .with_location(FindingLocation::tool("test")),
        );
        results1.findings.push(
            Finding::new("TEST-002", Severity::High, "High 1", "High finding 1")
                .with_location(FindingLocation::tool("test")),
        );

        let config2 = ServerConfig::new("server2", "cmd2");
        let mut results2 = ScanResults::new("server2", ScanProfile::Standard);
        results2.findings.push(
            Finding::new(
                "TEST-003",
                Severity::Critical,
                "Critical 2",
                "Critical finding 2",
            )
            .with_location(FindingLocation::tool("test")),
        );
        results2.findings.push(
            Finding::new("TEST-004", Severity::Medium, "Medium 1", "Medium finding 1")
                .with_location(FindingLocation::tool("test")),
        );
        results2.findings.push(
            Finding::new("TEST-005", Severity::Low, "Low 1", "Low finding 1")
                .with_location(FindingLocation::tool("test")),
        );

        let success1 = ServerScanResult::success(config1, results1, Duration::from_secs(1));
        let success2 = ServerScanResult::success(config2, results2, Duration::from_secs(1));

        let multi_results = MultiServerResults::from_server_results(
            vec![success1, success2],
            Duration::from_secs(2),
        );

        assert_eq!(multi_results.total_findings, 5);
        assert_eq!(multi_results.severity_counts.get("critical"), Some(&2));
        assert_eq!(multi_results.severity_counts.get("high"), Some(&1));
        assert_eq!(multi_results.severity_counts.get("medium"), Some(&1));
        assert_eq!(multi_results.severity_counts.get("low"), Some(&1));
    }

    #[test]
    fn multi_server_results_mixed_success_and_failure() {
        use super::super::{Finding, FindingLocation};

        let config1 = ServerConfig::new("server1", "cmd1");
        let mut results1 = ScanResults::new("server1", ScanProfile::Standard);
        results1.findings.push(
            Finding::new("TEST-001", Severity::High, "Issue", "Finding")
                .with_location(FindingLocation::tool("test")),
        );

        let config2 = ServerConfig::new("server2", "cmd2");
        let config3 = ServerConfig::new("server3", "cmd3");

        let success = ServerScanResult::success(config1, results1, Duration::from_secs(1));
        let failure1 =
            ServerScanResult::failure(config2, "timeout".to_string(), Duration::from_secs(30));
        let failure2 = ServerScanResult::failure(
            config3,
            "connection refused".to_string(),
            Duration::from_secs(5),
        );

        let multi_results = MultiServerResults::from_server_results(
            vec![success, failure1, failure2],
            Duration::from_secs(36),
        );

        assert_eq!(multi_results.server_count, 3);
        assert_eq!(multi_results.success_count, 1);
        assert_eq!(multi_results.failure_count, 2);
        assert_eq!(multi_results.total_findings, 1);
        assert!(!multi_results.all_success());

        let failed = multi_results.failed_servers();
        assert_eq!(failed.len(), 2);
        assert!(failed.contains(&"server2"));
        assert!(failed.contains(&"server3"));
    }

    #[test]
    fn multi_server_scanner_empty_config() {
        let scanner = MultiServerScanner::new(vec![]);
        assert_eq!(scanner.server_count(), 0);
    }

    #[test]
    fn multi_server_scanner_multiple_servers() {
        let configs = vec![
            ServerConfig::new("server1", "cmd1"),
            ServerConfig::new("server2", "cmd2"),
            ServerConfig::new("server3", "cmd3"),
        ];
        let scanner = MultiServerScanner::new(configs);
        assert_eq!(scanner.server_count(), 3);
    }

    #[test]
    fn multi_server_scanner_builder_pattern() {
        let configs = vec![ServerConfig::new("test", "cmd")];
        let scanner = MultiServerScanner::new(configs)
            .with_concurrency(16)
            .with_timeout(300)
            .with_profile(ScanProfile::Full);

        assert_eq!(scanner.concurrency, 16);
        assert_eq!(scanner.default_timeout, 300);
        assert_eq!(scanner.default_profile, ScanProfile::Full);
    }

    #[test]
    fn multi_server_scanner_add_server_multiple() {
        let mut scanner = MultiServerScanner::new(vec![]);
        assert_eq!(scanner.server_count(), 0);

        scanner.add_server(ServerConfig::new("server1", "cmd1"));
        assert_eq!(scanner.server_count(), 1);

        scanner.add_server(ServerConfig::new("server2", "cmd2"));
        assert_eq!(scanner.server_count(), 2);

        scanner.add_server(ServerConfig::new("server3", "cmd3"));
        assert_eq!(scanner.server_count(), 3);
    }

    #[test]
    fn multi_server_results_to_sarif_with_findings() {
        use super::super::{Finding, FindingLocation};

        let config = ServerConfig::new("test-server", "/usr/bin/test");
        let mut results = ScanResults::new("test-server", ScanProfile::Standard);
        results.findings.push(
            Finding::new(
                "TEST-001",
                Severity::Critical,
                "Critical Issue",
                "Test finding",
            )
            .with_location(FindingLocation {
                component: "test-component".to_string(),
                identifier: "test-id".to_string(),
                context: None,
            })
            .with_remediation("Fix the issue"),
        );

        let success = ServerScanResult::success(config, results, Duration::from_secs(10));
        let multi_results =
            MultiServerResults::from_server_results(vec![success], Duration::from_secs(10));

        let sarif = multi_results.to_sarif();

        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "mcplint-multi");

        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "TEST-001");
        assert_eq!(rules[0]["name"], "Critical Issue");

        let results_array = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results_array.len(), 1);
        assert_eq!(results_array[0]["ruleId"], "TEST-001");
        assert_eq!(results_array[0]["properties"]["server"], "test-server");
        assert_eq!(
            results_array[0]["properties"]["component"],
            "test-component"
        );
        assert_eq!(results_array[0]["properties"]["identifier"], "test-id");

        let invocations = &sarif["runs"][0]["invocations"][0];
        assert_eq!(invocations["executionSuccessful"], true);
        assert_eq!(invocations["properties"]["servers_scanned"], 1);
        assert_eq!(invocations["properties"]["servers_successful"], 1);
        assert_eq!(invocations["properties"]["servers_failed"], 0);
        assert_eq!(invocations["properties"]["total_findings"], 1);
    }

    #[test]
    fn multi_server_results_to_sarif_deduplicates_rules() {
        use super::super::{Finding, FindingLocation};

        let config1 = ServerConfig::new("server1", "cmd1");
        let mut results1 = ScanResults::new("server1", ScanProfile::Standard);
        results1.findings.push(
            Finding::new(
                "TEST-001",
                Severity::High,
                "Same Rule",
                "Finding from server1",
            )
            .with_location(FindingLocation {
                component: "comp1".to_string(),
                identifier: "id1".to_string(),
                context: None,
            }),
        );

        let config2 = ServerConfig::new("server2", "cmd2");
        let mut results2 = ScanResults::new("server2", ScanProfile::Standard);
        results2.findings.push(
            Finding::new(
                "TEST-001",
                Severity::High,
                "Same Rule",
                "Finding from server2",
            )
            .with_location(FindingLocation {
                component: "comp2".to_string(),
                identifier: "id2".to_string(),
                context: None,
            }),
        );

        let success1 = ServerScanResult::success(config1, results1, Duration::from_secs(1));
        let success2 = ServerScanResult::success(config2, results2, Duration::from_secs(1));

        let multi_results = MultiServerResults::from_server_results(
            vec![success1, success2],
            Duration::from_secs(2),
        );

        let sarif = multi_results.to_sarif();

        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1, "Rules should be deduplicated");

        let results_array = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results_array.len(), 2, "Both findings should be included");
    }

    #[test]
    fn multi_server_results_to_sarif_with_failures() {
        use super::super::{Finding, FindingLocation};

        let config1 = ServerConfig::new("server1", "cmd1");
        let mut results1 = ScanResults::new("server1", ScanProfile::Standard);
        results1.findings.push(
            Finding::new("TEST-001", Severity::Medium, "Issue", "Finding").with_location(
                FindingLocation {
                    component: "comp".to_string(),
                    identifier: "id".to_string(),
                    context: None,
                },
            ),
        );

        let config2 = ServerConfig::new("server2", "cmd2");

        let success = ServerScanResult::success(config1, results1, Duration::from_secs(1));
        let failure = ServerScanResult::failure(
            config2,
            "connection error".to_string(),
            Duration::from_secs(5),
        );

        let multi_results =
            MultiServerResults::from_server_results(vec![success, failure], Duration::from_secs(6));

        let sarif = multi_results.to_sarif();

        let invocations = &sarif["runs"][0]["invocations"][0];
        assert_eq!(invocations["executionSuccessful"], false);
        assert_eq!(invocations["properties"]["servers_failed"], 1);
    }

    #[test]
    fn server_scan_result_finding_count_with_findings() {
        use super::super::{Finding, FindingLocation};

        let config = ServerConfig::new("test", "cmd");
        let mut results = ScanResults::new("test", ScanProfile::Standard);

        for i in 0..5 {
            results.findings.push(
                Finding::new(
                    format!("TEST-{:03}", i),
                    Severity::Medium,
                    format!("Issue {}", i),
                    format!("Finding {}", i),
                )
                .with_location(FindingLocation {
                    component: "test".to_string(),
                    identifier: format!("id{}", i),
                    context: None,
                }),
            );
        }

        let result = ServerScanResult::success(config, results, Duration::from_secs(10));
        assert_eq!(result.finding_count(), 5);
    }

    #[test]
    fn multi_server_results_failed_servers_empty() {
        let config = ServerConfig::new("server1", "cmd1");
        let results = ScanResults::new("server1", ScanProfile::Standard);
        let success = ServerScanResult::success(config, results, Duration::from_secs(1));

        let multi_results =
            MultiServerResults::from_server_results(vec![success], Duration::from_secs(1));

        let failed = multi_results.failed_servers();
        assert_eq!(failed.len(), 0);
    }

    #[test]
    fn multi_server_results_print_summary_no_findings() {
        let results = MultiServerResults::from_server_results(vec![], Duration::from_secs(1));
        // Test that print_summary doesn't panic with no servers
        results.print_summary();
    }

    #[test]
    fn multi_server_results_print_summary_with_success() {
        let config = ServerConfig::new("test-server", "cmd");
        let scan_results = ScanResults::new("test-server", ScanProfile::Standard);
        let success = ServerScanResult::success(config, scan_results, Duration::from_secs(5));

        let multi_results =
            MultiServerResults::from_server_results(vec![success], Duration::from_secs(5));

        // Test that print_summary works with successful scans
        multi_results.print_summary();
    }

    #[test]
    fn multi_server_results_print_summary_with_failures() {
        let config1 = ServerConfig::new("server1", "cmd1");
        let config2 = ServerConfig::new("server2", "cmd2");

        let scan_results = ScanResults::new("server1", ScanProfile::Standard);
        let success = ServerScanResult::success(config1, scan_results, Duration::from_secs(3));
        let failure = ServerScanResult::failure(
            config2,
            "Connection timeout".to_string(),
            Duration::from_secs(10),
        );

        let multi_results = MultiServerResults::from_server_results(
            vec![success, failure],
            Duration::from_secs(13),
        );

        // Test that print_summary displays failed servers
        multi_results.print_summary();
    }

    #[test]
    fn multi_server_results_print_summary_with_all_severities() {
        use super::super::{Finding, FindingLocation};

        let config = ServerConfig::new("test-server", "cmd");
        let mut results = ScanResults::new("test-server", ScanProfile::Standard);

        // Add findings of all severity levels
        results.findings.push(
            Finding::new(
                "TEST-001",
                Severity::Critical,
                "Critical Issue",
                "Critical finding",
            )
            .with_location(FindingLocation::tool("test")),
        );
        results.findings.push(
            Finding::new("TEST-002", Severity::High, "High Issue", "High finding")
                .with_location(FindingLocation::tool("test")),
        );
        results.findings.push(
            Finding::new(
                "TEST-003",
                Severity::Medium,
                "Medium Issue",
                "Medium finding",
            )
            .with_location(FindingLocation::tool("test")),
        );
        results.findings.push(
            Finding::new("TEST-004", Severity::Low, "Low Issue", "Low finding")
                .with_location(FindingLocation::tool("test")),
        );

        let success = ServerScanResult::success(config, results, Duration::from_secs(7));
        let multi_results =
            MultiServerResults::from_server_results(vec![success], Duration::from_secs(7));

        // Test that print_summary displays all severity levels
        multi_results.print_summary();

        assert_eq!(multi_results.severity_counts.get("critical"), Some(&1));
        assert_eq!(multi_results.severity_counts.get("high"), Some(&1));
        assert_eq!(multi_results.severity_counts.get("medium"), Some(&1));
        assert_eq!(multi_results.severity_counts.get("low"), Some(&1));
    }

    #[test]
    fn multi_server_results_print_summary_with_unknown_error() {
        let config = ServerConfig::new("test-server", "cmd");
        let mut result =
            ServerScanResult::failure(config, "Network error".to_string(), Duration::from_secs(2));

        // Simulate unknown error by clearing error message
        result.error = None;

        let multi_results =
            MultiServerResults::from_server_results(vec![result], Duration::from_secs(2));

        multi_results.print_summary();
    }

    #[test]
    fn multi_server_results_to_sarif_empty_results() {
        let results = MultiServerResults::from_server_results(vec![], Duration::from_secs(0));
        let sarif = results.to_sarif();

        assert_eq!(sarif["version"], "2.1.0");
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 0);

        let results_array = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results_array.len(), 0);

        let invocations = &sarif["runs"][0]["invocations"][0];
        assert_eq!(invocations["executionSuccessful"], true);
        assert_eq!(invocations["properties"]["total_findings"], 0);
    }

    #[test]
    fn multi_server_results_to_sarif_multiple_servers_multiple_findings() {
        use super::super::{Finding, FindingLocation};

        let mut servers = Vec::new();

        for i in 0..3 {
            let config = ServerConfig::new(format!("server{}", i), format!("cmd{}", i));
            let mut scan_results = ScanResults::new(&format!("server{}", i), ScanProfile::Standard);

            // Add multiple findings per server
            for j in 0..2 {
                scan_results.findings.push(
                    Finding::new(
                        format!("TEST-{:02}{:02}", i, j),
                        if j % 2 == 0 {
                            Severity::Critical
                        } else {
                            Severity::High
                        },
                        format!("Issue {} from server {}", j, i),
                        format!("Finding {} from server {}", j, i),
                    )
                    .with_location(FindingLocation {
                        component: format!("component{}", i),
                        identifier: format!("id{}{}", i, j),
                        context: None,
                    }),
                );
            }

            servers.push(ServerScanResult::success(
                config,
                scan_results,
                Duration::from_secs(i as u64 + 1),
            ));
        }

        let multi_results =
            MultiServerResults::from_server_results(servers, Duration::from_secs(10));

        let sarif = multi_results.to_sarif();

        // Should have 6 total findings (3 servers * 2 findings each)
        let results_array = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results_array.len(), 6);

        // Check that server names are included in messages
        assert!(results_array[0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("server0"));
    }

    #[test]
    fn multi_server_results_to_sarif_includes_version_info() {
        let results = MultiServerResults::from_server_results(vec![], Duration::from_secs(1));
        let sarif = results.to_sarif();

        assert_eq!(
            sarif["$schema"],
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        );
        assert_eq!(sarif["version"], "2.1.0");

        let driver = &sarif["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "mcplint-multi");
        assert!(driver["version"].is_string());
        assert_eq!(
            driver["informationUri"],
            "https://github.com/quanticsoul4772/mcplint"
        );
    }

    #[test]
    fn multi_server_results_to_sarif_location_mapping() {
        use super::super::{Finding, FindingLocation};

        let config = ServerConfig::new("test-server", "/usr/local/bin/test-command");
        let mut results = ScanResults::new("test-server", ScanProfile::Standard);

        results.findings.push(
            Finding::new("TEST-001", Severity::High, "Issue", "Finding").with_location(
                FindingLocation {
                    component: "my-component".to_string(),
                    identifier: "my-identifier".to_string(),
                    context: Some("additional context".to_string()),
                },
            ),
        );

        let success = ServerScanResult::success(config, results, Duration::from_secs(5));
        let multi_results =
            MultiServerResults::from_server_results(vec![success], Duration::from_secs(5));

        let sarif = multi_results.to_sarif();
        let results_array = sarif["runs"][0]["results"].as_array().unwrap();

        assert_eq!(results_array.len(), 1);
        assert_eq!(
            results_array[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "/usr/local/bin/test-command"
        );
        assert_eq!(results_array[0]["properties"]["component"], "my-component");
        assert_eq!(
            results_array[0]["properties"]["identifier"],
            "my-identifier"
        );
    }

    #[test]
    fn server_config_empty_env() {
        let config = ServerConfig::new("test", "cmd").with_env(HashMap::new());
        assert_eq!(config.env.len(), 0);
    }

    #[test]
    fn server_config_multiple_env_vars() {
        let mut env = HashMap::new();
        env.insert("VAR1".to_string(), "value1".to_string());
        env.insert("VAR2".to_string(), "value2".to_string());
        env.insert("VAR3".to_string(), "value3".to_string());

        let config = ServerConfig::new("test", "cmd").with_env(env);
        assert_eq!(config.env.len(), 3);
        assert_eq!(config.env.get("VAR1"), Some(&"value1".to_string()));
        assert_eq!(config.env.get("VAR2"), Some(&"value2".to_string()));
        assert_eq!(config.env.get("VAR3"), Some(&"value3".to_string()));
    }

    #[test]
    fn server_config_no_optional_overrides() {
        let config = ServerConfig::new("test", "cmd");
        assert_eq!(config.timeout, None);
        assert_eq!(config.profile, None);
    }

    #[test]
    fn server_scan_result_duration_tracking() {
        let config = ServerConfig::new("test", "cmd");
        let results = ScanResults::new("test", ScanProfile::Standard);

        let duration = Duration::from_millis(12345);
        let result = ServerScanResult::success(config, results, duration);

        assert_eq!(result.duration, duration);
        assert_eq!(result.duration.as_millis(), 12345);
    }

    #[test]
    fn multi_server_results_total_duration_tracking() {
        let config1 = ServerConfig::new("server1", "cmd1");
        let config2 = ServerConfig::new("server2", "cmd2");

        let results1 = ScanResults::new("server1", ScanProfile::Standard);
        let results2 = ScanResults::new("server2", ScanProfile::Standard);

        let success1 = ServerScanResult::success(config1, results1, Duration::from_secs(5));
        let success2 = ServerScanResult::success(config2, results2, Duration::from_secs(8));

        let total_duration = Duration::from_secs(15);
        let multi_results =
            MultiServerResults::from_server_results(vec![success1, success2], total_duration);

        assert_eq!(multi_results.total_duration, total_duration);
        assert_eq!(multi_results.total_duration.as_secs(), 15);
    }

    #[test]
    fn multi_server_results_zero_findings() {
        let config1 = ServerConfig::new("server1", "cmd1");
        let config2 = ServerConfig::new("server2", "cmd2");

        let results1 = ScanResults::new("server1", ScanProfile::Standard);
        let results2 = ScanResults::new("server2", ScanProfile::Standard);

        let success1 = ServerScanResult::success(config1, results1, Duration::from_secs(1));
        let success2 = ServerScanResult::success(config2, results2, Duration::from_secs(1));

        let multi_results = MultiServerResults::from_server_results(
            vec![success1, success2],
            Duration::from_secs(2),
        );

        assert_eq!(multi_results.total_findings, 0);
        assert_eq!(multi_results.severity_counts.len(), 0);
        assert!(!multi_results.has_critical_findings());
        assert!(!multi_results.has_high_findings());
    }

    #[test]
    fn multi_server_results_only_low_and_medium() {
        use super::super::{Finding, FindingLocation};

        let config = ServerConfig::new("server", "cmd");
        let mut results = ScanResults::new("server", ScanProfile::Standard);

        results.findings.push(
            Finding::new(
                "TEST-001",
                Severity::Medium,
                "Medium Issue",
                "Medium finding",
            )
            .with_location(FindingLocation::tool("test")),
        );
        results.findings.push(
            Finding::new("TEST-002", Severity::Low, "Low Issue", "Low finding")
                .with_location(FindingLocation::tool("test")),
        );

        let success = ServerScanResult::success(config, results, Duration::from_secs(1));
        let multi_results =
            MultiServerResults::from_server_results(vec![success], Duration::from_secs(1));

        assert!(!multi_results.has_critical_findings());
        assert!(!multi_results.has_high_findings());
        assert_eq!(multi_results.severity_counts.get("medium"), Some(&1));
        assert_eq!(multi_results.severity_counts.get("low"), Some(&1));
    }

    #[test]
    fn multi_server_scanner_default_values() {
        let scanner = MultiServerScanner::new(vec![]);
        assert_eq!(scanner.concurrency, 4);
        assert_eq!(scanner.default_timeout, 60);
        assert_eq!(scanner.default_profile, ScanProfile::Standard);
    }

    #[test]
    fn multi_server_scanner_concurrency_zero_clamped() {
        let scanner = MultiServerScanner::new(vec![]).with_concurrency(0);
        assert_eq!(
            scanner.concurrency, 1,
            "Concurrency should be clamped to minimum of 1"
        );
    }

    #[test]
    fn multi_server_scanner_high_concurrency() {
        let scanner = MultiServerScanner::new(vec![]).with_concurrency(100);
        assert_eq!(scanner.concurrency, 100);
    }

    #[test]
    fn multi_server_results_severity_counts_case_insensitive() {
        use super::super::{Finding, FindingLocation};

        let config = ServerConfig::new("server", "cmd");
        let mut results = ScanResults::new("server", ScanProfile::Standard);

        results.findings.push(
            Finding::new("TEST-001", Severity::Critical, "Issue", "Finding")
                .with_location(FindingLocation::tool("test")),
        );

        let success = ServerScanResult::success(config, results, Duration::from_secs(1));
        let multi_results =
            MultiServerResults::from_server_results(vec![success], Duration::from_secs(1));

        // Verify severity is stored in lowercase
        assert!(multi_results.severity_counts.contains_key("critical"));
        assert!(!multi_results.severity_counts.contains_key("Critical"));
    }

    #[test]
    fn server_scan_result_error_message_preserved() {
        let config = ServerConfig::new("test", "cmd");
        let error_msg = "Detailed error: connection refused on port 8080";
        let result =
            ServerScanResult::failure(config, error_msg.to_string(), Duration::from_secs(1));

        assert_eq!(result.error.as_deref(), Some(error_msg));
        assert!(!result.success);
    }

    #[test]
    fn multi_server_results_failed_servers_preserves_order() {
        let config1 = ServerConfig::new("alpha", "cmd1");
        let config2 = ServerConfig::new("beta", "cmd2");
        let config3 = ServerConfig::new("gamma", "cmd3");

        let failure1 =
            ServerScanResult::failure(config1, "error1".to_string(), Duration::from_secs(1));
        let failure2 =
            ServerScanResult::failure(config2, "error2".to_string(), Duration::from_secs(1));
        let failure3 =
            ServerScanResult::failure(config3, "error3".to_string(), Duration::from_secs(1));

        let multi_results = MultiServerResults::from_server_results(
            vec![failure1, failure2, failure3],
            Duration::from_secs(3),
        );

        let failed = multi_results.failed_servers();
        assert_eq!(failed.len(), 3);
        assert_eq!(failed[0], "alpha");
        assert_eq!(failed[1], "beta");
        assert_eq!(failed[2], "gamma");
    }

    #[test]
    fn multi_server_results_all_findings_ordering() {
        use super::super::{Finding, FindingLocation};

        let config1 = ServerConfig::new("server1", "cmd1");
        let mut results1 = ScanResults::new("server1", ScanProfile::Standard);
        results1.findings.push(
            Finding::new("TEST-001", Severity::Critical, "First", "First finding")
                .with_location(FindingLocation::tool("test")),
        );
        results1.findings.push(
            Finding::new("TEST-002", Severity::High, "Second", "Second finding")
                .with_location(FindingLocation::tool("test")),
        );

        let config2 = ServerConfig::new("server2", "cmd2");
        let mut results2 = ScanResults::new("server2", ScanProfile::Standard);
        results2.findings.push(
            Finding::new("TEST-003", Severity::Medium, "Third", "Third finding")
                .with_location(FindingLocation::tool("test")),
        );

        let success1 = ServerScanResult::success(config1, results1, Duration::from_secs(1));
        let success2 = ServerScanResult::success(config2, results2, Duration::from_secs(1));

        let multi_results = MultiServerResults::from_server_results(
            vec![success1, success2],
            Duration::from_secs(2),
        );

        let all = multi_results.all_findings();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].rule_id, "TEST-001");
        assert_eq!(all[1].rule_id, "TEST-002");
        assert_eq!(all[2].rule_id, "TEST-003");
    }
}
