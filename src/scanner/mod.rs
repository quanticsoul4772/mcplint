//! Security Scanner - Vulnerability detection for MCP servers
//!
//! This module implements the M2 milestone: Security Scanner
//! It scans MCP servers for security vulnerabilities using pattern-based detection.

mod context;
mod engine;
mod finding;
pub mod rules;

pub use context::{ScanConfig, ScanProfile};
// Re-exports for public API - used by external consumers and tests
#[allow(unused_imports)]
pub use engine::{ScanEngine, ScanResults, ScanSummary};
#[allow(unused_imports)]
pub use finding::{Evidence, EvidenceKind, Finding, FindingLocation, ReferenceKind, Severity};

use anyhow::Result;
use colored::Colorize;

impl ScanResults {
    pub fn print_text(&self) {
        println!("{}", "Security Scan Results".cyan().bold());
        println!("{}", "=".repeat(60));
        println!();

        println!("  Server: {}", self.server.yellow());
        println!("  Profile: {}", self.profile.green());
        println!("  Checks: {}", self.total_checks);
        println!("  Duration: {}ms", self.duration_ms);
        println!();

        if self.findings.is_empty() {
            println!("{}", "  No vulnerabilities found ✓".green().bold());
        } else {
            println!(
                "  {} {} found:",
                self.findings.len(),
                if self.findings.len() == 1 {
                    "vulnerability"
                } else {
                    "vulnerabilities"
                }
            );
            println!();

            for finding in &self.findings {
                println!(
                    "  [{}] {} ({})",
                    finding.severity.colored_display(),
                    finding.title,
                    finding.rule_id.dimmed()
                );
                println!("    {}", finding.description);

                if !finding.location.component.is_empty() {
                    println!(
                        "    Location: {}: {}",
                        finding.location.component.cyan(),
                        finding.location.identifier
                    );
                }

                if !finding.remediation.is_empty() {
                    println!("    Fix: {}", finding.remediation.green());
                }

                if !finding.references.is_empty() {
                    let refs: Vec<String> =
                        finding.references.iter().map(|r| r.id.clone()).collect();
                    println!("    References: {}", refs.join(", ").dimmed());
                }

                println!();
            }
        }

        println!("{}", "─".repeat(60));
        println!(
            "Summary: {} critical, {} high, {} medium, {} low, {} info",
            self.summary.critical.to_string().red(),
            self.summary.high.to_string().red(),
            self.summary.medium.to_string().yellow(),
            self.summary.low.to_string().blue(),
            self.summary.info.to_string().dimmed()
        );

        if self.has_critical_or_high() {
            println!(
                "\n{}",
                "Server has critical/high severity vulnerabilities!"
                    .red()
                    .bold()
            );
        } else if self.total_findings() > 0 {
            println!("\n{}", "Server has security issues to address.".yellow());
        } else {
            println!("\n{}", "No security issues detected.".green().bold());
        }
    }

    pub fn print_json(&self) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(self)?);
        Ok(())
    }

    pub fn print_sarif(&self) -> Result<()> {
        let sarif = to_sarif_report(self);
        println!("{}", serde_json::to_string_pretty(&sarif)?);
        Ok(())
    }
}

/// Convert scan results to SARIF format for CI/CD integration
fn to_sarif_report(results: &ScanResults) -> serde_json::Value {
    use std::collections::HashSet;

    // Collect unique rules
    let mut seen_rules: HashSet<String> = HashSet::new();
    let mut rules = Vec::new();

    for finding in &results.findings {
        if !seen_rules.contains(&finding.rule_id) {
            seen_rules.insert(finding.rule_id.clone());
            rules.push(serde_json::json!({
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {
                    "text": finding.title
                },
                "fullDescription": {
                    "text": finding.description
                },
                "defaultConfiguration": {
                    "level": finding.severity.sarif_level()
                },
                "helpUri": finding.references.first().and_then(|r| r.url.clone())
            }));
        }
    }

    // Convert findings to SARIF results
    let sarif_results: Vec<serde_json::Value> = results
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level(),
                "message": {
                    "text": format!("{}: {}", f.title, f.description)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": results.server.clone()
                        }
                    },
                    "logicalLocations": [{
                        "name": f.location.identifier.clone(),
                        "kind": f.location.component.clone()
                    }]
                }]
            })
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcplint",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/quanticsoul4772/mcplint",
                    "rules": rules
                }
            },
            "results": sarif_results
        }]
    })
}
