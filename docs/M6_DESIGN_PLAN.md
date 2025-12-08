# M6: Advanced Features & CI/CD Integration

**Status:** Design Phase
**Target Duration:** 6-8 weeks
**Dependencies:** M0-M5 complete

---

## Executive Summary

M6 focuses on **enterprise-ready features** that transform mcplint from a developer tool into a comprehensive CI/CD-integrated security platform. The milestone addresses three core objectives:

1. **Baseline/Diff Mode** - Enable incremental vulnerability detection for PR workflows
2. **New Security Rules** - Address emerging MCP attack classes identified in research
3. **Enhanced Output & Integration** - Expand format support and improve developer experience

---

## Feature Overview

| Feature | Priority | Complexity | Business Value |
|---------|----------|------------|----------------|
| Baseline/Diff Mode | 🔴 Critical | Medium | Enables PR-based security gates |
| New Security Rules (SEC-040+) | 🔴 Critical | Medium | Covers 6 undocumented attack classes |
| Watch Mode | 🟡 High | Low | Developer experience improvement |
| JUnit/GitLab Output | 🟡 High | Low | CI/CD integration expansion |
| HTML Report Generator | 🟢 Medium | Medium | Stakeholder communication |
| Plugin Architecture | 🟢 Medium | High | Extensibility for custom rules |
| Resource Limits | 🟢 Medium | Low | Fuzzer safety controls |

---

## Phase 1: Baseline/Diff Mode (Weeks 1-2)

### 1.1 Problem Statement

Current scan workflow reports ALL findings every run, making CI/CD integration noisy:
- PRs fail due to pre-existing vulnerabilities
- Teams cannot adopt gradually
- No visibility into security posture changes

### 1.2 Solution Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Baseline System                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Baseline   │    │   Current    │    │    Diff      │  │
│  │    Store     │───▶│    Scan      │───▶│   Engine     │  │
│  │  (JSON/DB)   │    │   Results    │    │              │  │
│  └──────────────┘    └──────────────┘    └──────┬───────┘  │
│                                                  │          │
│                                                  ▼          │
│                                          ┌──────────────┐  │
│                                          │  Delta Report │  │
│                                          │  • New (❌)   │  │
│                                          │  • Fixed (✅) │  │
│                                          │  • Same (➖)  │  │
│                                          └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 1.3 Data Structures

```rust
// src/baseline/mod.rs

/// Baseline storage format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Version for forward compatibility
    pub version: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Server identifier (name or path hash)
    pub server_id: String,
    /// Fingerprinted findings
    pub findings: Vec<BaselineFinding>,
    /// Scan configuration used
    pub config: BaselineConfig,
}

/// Fingerprinted finding for stable comparison
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct BaselineFinding {
    /// Rule ID (e.g., "MCP-INJ-001")
    pub rule_id: String,
    /// Location fingerprint (tool name, resource URI, etc.)
    pub location_fingerprint: String,
    /// Evidence hash for deduplication
    pub evidence_hash: String,
    /// Severity at time of baseline
    pub severity: Severity,
}

/// Diff result between baseline and current scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    /// Newly introduced findings
    pub new_findings: Vec<Finding>,
    /// Findings that were fixed
    pub fixed_findings: Vec<BaselineFinding>,
    /// Findings unchanged from baseline
    pub unchanged_count: usize,
    /// Summary statistics
    pub summary: DiffSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub total_baseline: usize,
    pub total_current: usize,
    pub new_count: usize,
    pub fixed_count: usize,
    pub unchanged_count: usize,
    pub new_critical: usize,
    pub new_high: usize,
}
```

### 1.4 CLI Interface

```bash
# Create a baseline from current scan
mcplint scan server.js --save-baseline baseline.json

# Compare against baseline (fail only on new findings)
mcplint scan server.js --baseline baseline.json

# Update baseline with current findings
mcplint scan server.js --baseline baseline.json --update-baseline

# Show diff summary only
mcplint scan server.js --baseline baseline.json --diff-only

# Fail on new critical/high only
mcplint scan server.js --baseline baseline.json --fail-on critical,high
```

### 1.5 Implementation Plan

#### File: `src/baseline/mod.rs`
```rust
pub mod store;
pub mod fingerprint;
pub mod diff;

pub use store::{Baseline, BaselineStore, FileBaselineStore};
pub use fingerprint::FindingFingerprint;
pub use diff::{DiffEngine, DiffResult, DiffSummary};
```

#### File: `src/baseline/fingerprint.rs`
```rust
use crate::scanner::Finding;
use sha2::{Sha256, Digest};

/// Generate stable fingerprint for a finding
pub struct FindingFingerprint;

impl FindingFingerprint {
    /// Create fingerprint from finding
    /// Uses: rule_id + location + normalized evidence
    pub fn from_finding(finding: &Finding) -> String {
        let mut hasher = Sha256::new();

        hasher.update(finding.rule_id.as_bytes());
        hasher.update(finding.location.component.as_bytes());
        hasher.update(finding.location.identifier.as_bytes());

        // Normalize and hash evidence
        for evidence in &finding.evidence {
            hasher.update(evidence.kind.as_str().as_bytes());
            hasher.update(Self::normalize_evidence(&evidence.data).as_bytes());
        }

        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    /// Normalize evidence data for stable comparison
    /// Removes timestamps, UUIDs, variable content
    fn normalize_evidence(data: &str) -> String {
        // Remove common variable patterns
        let normalized = data
            .lines()
            .filter(|l| !l.contains("timestamp"))
            .filter(|l| !l.contains("request_id"))
            .collect::<Vec<_>>()
            .join("\n");
        normalized
    }
}
```

#### File: `src/baseline/diff.rs`
```rust
use std::collections::HashSet;
use crate::scanner::{Finding, ScanResults};
use super::{Baseline, BaselineFinding};

pub struct DiffEngine;

impl DiffEngine {
    /// Compare current scan results against baseline
    pub fn diff(baseline: &Baseline, current: &ScanResults) -> DiffResult {
        let baseline_set: HashSet<_> = baseline.findings.iter()
            .map(|f| &f.evidence_hash)
            .collect();

        let current_fingerprints: Vec<_> = current.findings.iter()
            .map(|f| (FindingFingerprint::from_finding(f), f))
            .collect();

        let mut new_findings = Vec::new();
        let mut unchanged_count = 0;

        for (fingerprint, finding) in &current_fingerprints {
            if baseline_set.contains(fingerprint) {
                unchanged_count += 1;
            } else {
                new_findings.push((*finding).clone());
            }
        }

        // Find fixed findings
        let current_set: HashSet<_> = current_fingerprints.iter()
            .map(|(fp, _)| fp.clone())
            .collect();

        let fixed_findings: Vec<_> = baseline.findings.iter()
            .filter(|f| !current_set.contains(&f.evidence_hash))
            .cloned()
            .collect();

        DiffResult {
            new_findings,
            fixed_findings,
            unchanged_count,
            summary: DiffSummary {
                total_baseline: baseline.findings.len(),
                total_current: current.findings.len(),
                new_count: new_findings.len(),
                fixed_count: fixed_findings.len(),
                unchanged_count,
                new_critical: new_findings.iter()
                    .filter(|f| f.severity == Severity::Critical)
                    .count(),
                new_high: new_findings.iter()
                    .filter(|f| f.severity == Severity::High)
                    .count(),
            },
        }
    }
}
```

### 1.6 Exit Code Integration

```rust
// Extended exit codes for baseline mode
pub enum ExitCode {
    Success = 0,              // No findings (or no new findings in baseline mode)
    FindingsDetected = 1,     // Findings detected
    Error = 2,                // Error occurred
    PartialSuccess = 3,       // Some checks skipped
    TimeoutExceeded = 4,      // Timeout
    NewFindingsDetected = 5,  // New findings vs baseline (baseline mode)
    BaselineUpdated = 6,      // Baseline was updated
}
```

---

## Phase 2: New Security Rules (Weeks 2-4)

### 2.1 Attack Classes to Address

Based on research findings, six new rule categories are needed:

| Rule ID | Attack Class | CVSS Est. | Detection Method |
|---------|--------------|-----------|------------------|
| SEC-040 | Tool Description Injection | 7.5 | Pattern matching + AI analysis |
| SEC-041 | Cross-Server Tool Shadowing | 8.0 | Multi-server comparison |
| SEC-042 | Rug Pull Detection | 9.0 | Hash monitoring (M4 enhanced) |
| SEC-043 | OAuth Scope Abuse | 7.0 | Permission analysis |
| SEC-044 | Unicode Hidden Instructions | 6.5 | Character analysis |
| SEC-045 | Full-Schema Poisoning | 8.5 | Schema validation |

### 2.2 Rule Implementations

#### SEC-040: Tool Description Injection

```rust
// src/rules/injection/tool_description.rs

pub struct ToolDescriptionInjectionRule;

impl SecurityRule for ToolDescriptionInjectionRule {
    fn id(&self) -> &'static str { "MCP-INJ-040" }
    fn name(&self) -> &'static str { "Tool Description Injection" }
    fn severity(&self) -> Severity { Severity::High }

    fn check(&self, context: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for tool in &context.tools {
            // Check for injection patterns in description
            if let Some(desc) = &tool.description {
                let patterns = [
                    // Prompt injection patterns
                    r"ignore\s+(previous|prior|all)\s+instructions",
                    r"you\s+are\s+now",
                    r"disregard\s+.*\s+rules",
                    r"system\s*:\s*",
                    r"<\|.*\|>",  // Special tokens
                    r"\[INST\]",  // Instruction markers
                    // Hidden instructions
                    r"<!--.*-->",
                    r"/\*.*\*/",
                ];

                for pattern in patterns {
                    if Regex::new(pattern).unwrap().is_match(desc) {
                        findings.push(self.create_finding(
                            &tool.name,
                            "Tool description contains potential prompt injection",
                            desc,
                        ));
                    }
                }
            }
        }

        findings
    }
}
```

#### SEC-041: Cross-Server Tool Shadowing

```rust
// src/rules/injection/tool_shadowing.rs

pub struct ToolShadowingRule;

impl SecurityRule for ToolShadowingRule {
    fn id(&self) -> &'static str { "MCP-INJ-041" }
    fn name(&self) -> &'static str { "Cross-Server Tool Shadowing" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn check(&self, context: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build map of tools by name across servers
        let mut tool_servers: HashMap<String, Vec<&str>> = HashMap::new();

        for (server_name, tools) in &context.multi_server_tools {
            for tool in tools {
                tool_servers.entry(tool.name.clone())
                    .or_default()
                    .push(server_name);
            }
        }

        // Detect shadowing
        for (tool_name, servers) in &tool_servers {
            if servers.len() > 1 {
                // Check if descriptions differ significantly
                let descriptions: Vec<_> = servers.iter()
                    .filter_map(|s| context.get_tool_description(s, tool_name))
                    .collect();

                if Self::descriptions_conflict(&descriptions) {
                    findings.push(self.create_finding(
                        tool_name,
                        format!(
                            "Tool '{}' defined in multiple servers with conflicting descriptions: {:?}",
                            tool_name, servers
                        ),
                    ));
                }
            }
        }

        findings
    }
}
```

#### SEC-042: Rug Pull Detection (Enhanced)

```rust
// src/rules/temporal/rug_pull.rs

pub struct RugPullDetectionRule {
    cache: Arc<CacheManager>,
}

impl SecurityRule for RugPullDetectionRule {
    fn id(&self) -> &'static str { "MCP-TEMP-042" }
    fn name(&self) -> &'static str { "Rug Pull Attack Detection" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn check(&self, context: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for tool in &context.tools {
            let current_hash = self.hash_tool_definition(tool);

            // Check against cached hash
            if let Some(cached) = self.cache.get_tool_hash(&tool.name).await {
                if cached.hash != current_hash {
                    let changes = self.diff_tool_definitions(&cached.definition, tool);

                    // Classify change severity
                    let change_type = self.classify_change(&changes);

                    match change_type {
                        ChangeType::Benign => { /* Minor update, log only */ }
                        ChangeType::Suspicious => {
                            findings.push(self.create_finding(
                                &tool.name,
                                format!(
                                    "Tool definition changed suspiciously since {}: {:?}",
                                    cached.timestamp, changes
                                ),
                            ).with_severity(Severity::High));
                        }
                        ChangeType::Malicious => {
                            findings.push(self.create_finding(
                                &tool.name,
                                format!(
                                    "CRITICAL: Tool definition replaced with potentially malicious version: {:?}",
                                    changes
                                ),
                            ).with_severity(Severity::Critical));
                        }
                    }
                }
            }

            // Update cache with current hash
            self.cache.set_tool_hash(&tool.name, current_hash, tool).await;
        }

        findings
    }

    fn classify_change(&self, changes: &ToolChanges) -> ChangeType {
        // AI-assisted classification of change severity
        if changes.description_changed && changes.contains_injection_patterns() {
            ChangeType::Malicious
        } else if changes.schema_changed && changes.adds_dangerous_params() {
            ChangeType::Suspicious
        } else {
            ChangeType::Benign
        }
    }
}
```

#### SEC-043: OAuth Scope Abuse

```rust
// src/rules/auth/oauth_scope.rs

pub struct OAuthScopeAbuseRule;

impl SecurityRule for OAuthScopeAbuseRule {
    fn id(&self) -> &'static str { "MCP-AUTH-043" }
    fn name(&self) -> &'static str { "OAuth Scope Abuse" }
    fn severity(&self) -> Severity { Severity::High }

    fn check(&self, context: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(oauth_config) = &context.server_info.oauth {
            // Check for overly broad scopes
            let dangerous_scopes = [
                "admin",
                "write:all",
                "read:all",
                "*",
                "root",
                "sudo",
            ];

            for scope in &oauth_config.requested_scopes {
                if dangerous_scopes.iter().any(|d| scope.contains(d)) {
                    findings.push(self.create_finding(
                        "oauth",
                        format!("Server requests overly broad OAuth scope: '{}'", scope),
                    ));
                }
            }

            // Check scope-to-tool alignment
            let required_scopes = self.analyze_required_scopes(&context.tools);
            let excess_scopes: Vec<_> = oauth_config.requested_scopes.iter()
                .filter(|s| !required_scopes.contains(*s))
                .collect();

            if !excess_scopes.is_empty() {
                findings.push(self.create_finding(
                    "oauth",
                    format!(
                        "Server requests unnecessary OAuth scopes: {:?}",
                        excess_scopes
                    ),
                ).with_severity(Severity::Medium));
            }
        }

        findings
    }
}
```

#### SEC-044: Unicode Hidden Instructions

```rust
// src/rules/injection/unicode_hidden.rs

pub struct UnicodeHiddenInstructionsRule;

impl SecurityRule for UnicodeHiddenInstructionsRule {
    fn id(&self) -> &'static str { "MCP-INJ-044" }
    fn name(&self) -> &'static str { "Unicode Hidden Instructions" }
    fn severity(&self) -> Severity { Severity::High }

    fn check(&self, context: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for tool in &context.tools {
            // Check all text fields
            let fields_to_check = [
                ("name", &tool.name),
                ("description", tool.description.as_ref().unwrap_or(&String::new())),
            ];

            for (field_name, text) in fields_to_check {
                // Check for invisible/homoglyph characters
                let suspicious_chars = self.detect_suspicious_unicode(text);

                if !suspicious_chars.is_empty() {
                    findings.push(self.create_finding(
                        &tool.name,
                        format!(
                            "Tool {} contains suspicious Unicode characters: {:?}",
                            field_name,
                            suspicious_chars.iter()
                                .map(|(c, pos)| format!("U+{:04X} at pos {}", *c as u32, pos))
                                .collect::<Vec<_>>()
                        ),
                    ));
                }
            }
        }

        findings
    }

    fn detect_suspicious_unicode(&self, text: &str) -> Vec<(char, usize)> {
        let mut suspicious = Vec::new();

        for (pos, ch) in text.char_indices() {
            match ch {
                // Zero-width characters
                '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' |
                // Right-to-left override
                '\u{202E}' | '\u{202D}' |
                // Tag characters (invisible)
                '\u{E0001}'..='\u{E007F}' |
                // Combining characters that can hide text
                '\u{0300}'..='\u{036F}' if self.is_excessive_combining(text, pos) => {
                    suspicious.push((ch, pos));
                }
                _ => {}
            }
        }

        suspicious
    }
}
```

#### SEC-045: Full-Schema Poisoning

```rust
// src/rules/injection/schema_poisoning.rs

pub struct SchemaPoisoningRule;

impl SecurityRule for SchemaPoisoningRule {
    fn id(&self) -> &'static str { "MCP-INJ-045" }
    fn name(&self) -> &'static str { "Full-Schema Poisoning" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn check(&self, context: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for tool in &context.tools {
            if let Some(schema) = &tool.input_schema {
                // Check schema for injection in various fields
                self.check_schema_recursive(
                    &tool.name,
                    schema,
                    &mut findings,
                    &["title", "description", "default", "examples", "enum"],
                );
            }
        }

        findings
    }

    fn check_schema_recursive(
        &self,
        tool_name: &str,
        schema: &serde_json::Value,
        findings: &mut Vec<Finding>,
        fields_to_check: &[&str],
    ) {
        if let Some(obj) = schema.as_object() {
            for field in fields_to_check {
                if let Some(value) = obj.get(*field) {
                    let text = match value {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Array(arr) => {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(" ")
                        }
                        _ => continue,
                    };

                    if self.contains_injection_patterns(&text) {
                        findings.push(self.create_finding(
                            tool_name,
                            format!(
                                "Schema field '{}' contains potential injection: {}",
                                field,
                                Self::truncate(&text, 100)
                            ),
                        ));
                    }
                }
            }

            // Recurse into nested schemas
            if let Some(properties) = obj.get("properties").and_then(|p| p.as_object()) {
                for (_, prop_schema) in properties {
                    self.check_schema_recursive(tool_name, prop_schema, findings, fields_to_check);
                }
            }
        }
    }
}
```

---

## Phase 3: Watch Mode (Week 4-5)

### 3.1 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Watch Mode                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  File System │    │   Debounce   │    │    Scan      │  │
│  │   Watcher    │───▶│    Queue     │───▶│   Executor   │  │
│  │  (notify)    │    │   (300ms)    │    │              │  │
│  └──────────────┘    └──────────────┘    └──────┬───────┘  │
│                                                  │          │
│                                                  ▼          │
│                                          ┌──────────────┐  │
│                                          │  Live Output │  │
│                                          │  • Findings  │  │
│                                          │  • Stats     │  │
│                                          │  • Alerts    │  │
│                                          └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 CLI Interface

```bash
# Basic watch mode
mcplint watch ./server.js

# Watch with specific command on change
mcplint watch ./server-dir --on-change "mcplint scan {}"

# Watch with baseline comparison
mcplint watch ./server.js --baseline baseline.json

# Watch multiple paths
mcplint watch ./server.js ./config.json

# Watch with filters
mcplint watch ./server-dir --include "*.js,*.ts" --exclude "node_modules"
```

### 3.3 Implementation

```rust
// src/cli/commands/watch.rs

use notify::{Watcher, RecursiveMode, watcher};
use std::sync::mpsc::channel;
use std::time::Duration;

pub async fn run(
    paths: Vec<PathBuf>,
    on_change: Option<String>,
    baseline: Option<PathBuf>,
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    debounce_ms: u64,
) -> Result<()> {
    println!("{}", "Watch mode started. Press Ctrl+C to exit.".cyan());

    let (tx, rx) = channel();
    let mut watcher = watcher(tx, Duration::from_millis(debounce_ms))?;

    for path in &paths {
        watcher.watch(path, RecursiveMode::Recursive)?;
        println!("  Watching: {}", path.display().to_string().yellow());
    }

    let mut last_run = Instant::now();
    let debounce = Duration::from_millis(debounce_ms);

    loop {
        match rx.recv() {
            Ok(event) => {
                // Debounce rapid changes
                if last_run.elapsed() < debounce {
                    continue;
                }

                // Filter by include/exclude patterns
                if !should_process(&event, &include, &exclude) {
                    continue;
                }

                last_run = Instant::now();

                println!();
                println!("{}", format!("Change detected: {:?}", event).bright_black());

                // Run scan
                let result = if let Some(ref cmd) = on_change {
                    run_custom_command(cmd, &event).await
                } else {
                    run_default_scan(&paths, baseline.as_ref()).await
                };

                match result {
                    Ok(findings) => print_watch_results(&findings),
                    Err(e) => eprintln!("{}", format!("Scan error: {}", e).red()),
                }
            }
            Err(e) => {
                eprintln!("{}", format!("Watch error: {}", e).red());
            }
        }
    }
}

fn print_watch_results(findings: &[Finding]) {
    if findings.is_empty() {
        println!("{}", "✓ No issues found".green());
    } else {
        println!("{}", format!("✗ {} issue(s) found:", findings.len()).red());
        for finding in findings.iter().take(5) {
            println!("  {} {} - {}",
                severity_icon(finding.severity),
                finding.rule_id.yellow(),
                finding.title
            );
        }
        if findings.len() > 5 {
            println!("  {} more...", format!("... and {}", findings.len() - 5).bright_black());
        }
    }
}
```

---

## Phase 4: Enhanced Output Formats (Week 5-6)

### 4.1 JUnit XML Output

```rust
// src/reporter/junit.rs

pub fn generate_junit(results: &ScanResults) -> String {
    let mut xml = String::new();

    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<testsuite name=\"mcplint\" tests=\"{}\" failures=\"{}\" errors=\"0\" time=\"{:.3}\">\n",
        results.findings.len() + 1,  // +1 for the "no findings" test case
        results.findings.len(),
        results.duration.as_secs_f64()
    ));

    for finding in &results.findings {
        xml.push_str(&format!(
            "  <testcase name=\"{}\" classname=\"mcplint.{}\">\n",
            escape_xml(&finding.title),
            finding.rule_id
        ));
        xml.push_str(&format!(
            "    <failure message=\"{}\" type=\"{}\">\n",
            escape_xml(&finding.description),
            finding.severity.as_str()
        ));
        xml.push_str(&format!(
            "Location: {}\nRule: {}\nSeverity: {}\n\nEvidence:\n{}\n",
            finding.location.identifier,
            finding.rule_id,
            finding.severity,
            finding.evidence.iter()
                .map(|e| format!("- {}: {}", e.kind, e.description))
                .collect::<Vec<_>>()
                .join("\n")
        ));
        xml.push_str("    </failure>\n");
        xml.push_str("  </testcase>\n");
    }

    // Add summary test case
    if results.findings.is_empty() {
        xml.push_str("  <testcase name=\"Security Scan\" classname=\"mcplint.summary\"/>\n");
    }

    xml.push_str("</testsuite>\n");
    xml
}
```

### 4.2 GitLab Code Quality Format

```rust
// src/reporter/gitlab.rs

#[derive(Serialize)]
struct GitLabIssue {
    description: String,
    check_name: String,
    fingerprint: String,
    severity: String,  // "info", "minor", "major", "critical", "blocker"
    location: GitLabLocation,
}

#[derive(Serialize)]
struct GitLabLocation {
    path: String,
    lines: GitLabLines,
}

pub fn generate_gitlab(results: &ScanResults) -> String {
    let issues: Vec<GitLabIssue> = results.findings.iter()
        .map(|f| GitLabIssue {
            description: f.description.clone(),
            check_name: f.rule_id.clone(),
            fingerprint: FindingFingerprint::from_finding(f),
            severity: match f.severity {
                Severity::Critical => "blocker",
                Severity::High => "critical",
                Severity::Medium => "major",
                Severity::Low => "minor",
                Severity::Info => "info",
            }.to_string(),
            location: GitLabLocation {
                path: f.location.identifier.clone(),
                lines: GitLabLines { begin: 1 },
            },
        })
        .collect();

    serde_json::to_string_pretty(&issues).unwrap()
}
```

### 4.3 HTML Report

```rust
// src/reporter/html.rs

pub fn generate_html(results: &ScanResults, explanations: Option<&[ExplanationResponse]>) -> String {
    let template = include_str!("templates/report.html");

    let severity_counts = results.severity_counts();
    let findings_html = results.findings.iter()
        .enumerate()
        .map(|(i, f)| render_finding(f, explanations.and_then(|e| e.get(i))))
        .collect::<Vec<_>>()
        .join("\n");

    template
        .replace("{{TITLE}}", &format!("MCPLint Report - {}", results.server_name))
        .replace("{{TIMESTAMP}}", &chrono::Utc::now().to_rfc3339())
        .replace("{{CRITICAL_COUNT}}", &severity_counts.critical.to_string())
        .replace("{{HIGH_COUNT}}", &severity_counts.high.to_string())
        .replace("{{MEDIUM_COUNT}}", &severity_counts.medium.to_string())
        .replace("{{LOW_COUNT}}", &severity_counts.low.to_string())
        .replace("{{FINDINGS}}", &findings_html)
}
```

---

## Phase 5: Resource Limits (Week 6)

### 5.1 Fuzzer Resource Controls

```rust
// src/fuzzer/limits.rs

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum execution time
    pub max_time: Option<Duration>,
    /// Maximum memory usage (bytes)
    pub max_memory: Option<u64>,
    /// Maximum number of executions
    pub max_executions: Option<u64>,
    /// Maximum corpus size
    pub max_corpus_size: Option<usize>,
    /// CPU limit (percentage, 1-100)
    pub cpu_limit: Option<u8>,
}

impl ResourceLimits {
    pub fn from_cli(
        max_time: Option<&str>,
        max_memory: Option<&str>,
        max_execs: Option<u64>,
    ) -> Result<Self> {
        Ok(Self {
            max_time: max_time.map(parse_duration).transpose()?,
            max_memory: max_memory.map(parse_bytes).transpose()?,
            max_executions: max_execs,
            max_corpus_size: None,
            cpu_limit: None,
        })
    }

    pub fn check_exceeded(&self, stats: &FuzzStats) -> Option<LimitExceeded> {
        if let Some(max_time) = self.max_time {
            if stats.elapsed >= max_time {
                return Some(LimitExceeded::Time(max_time));
            }
        }

        if let Some(max_execs) = self.max_executions {
            if stats.executions >= max_execs {
                return Some(LimitExceeded::Executions(max_execs));
            }
        }

        if let Some(max_mem) = self.max_memory {
            if stats.peak_memory >= max_mem {
                return Some(LimitExceeded::Memory(max_mem));
            }
        }

        None
    }
}
```

### 5.2 CLI Integration

```bash
# Time limit (supports s, m, h suffixes)
mcplint fuzz server.js --max-time 5m

# Memory limit (supports K, M, G suffixes)
mcplint fuzz server.js --max-memory 512M

# Execution limit
mcplint fuzz server.js --max-execs 10000

# Combined limits
mcplint fuzz server.js --max-time 10m --max-memory 1G --max-execs 50000
```

---

## Phase 6: Plugin Architecture (Week 7-8) [Optional]

### 6.1 Plugin Trait Definition

```rust
// src/plugin/mod.rs

/// Plugin interface for custom security rules
pub trait SecurityPlugin: Send + Sync {
    /// Plugin metadata
    fn metadata(&self) -> PluginMetadata;

    /// Initialize the plugin
    fn init(&mut self, config: &PluginConfig) -> Result<()>;

    /// Return custom security rules
    fn rules(&self) -> Vec<Box<dyn SecurityRule>>;

    /// Optional: custom mutations for fuzzer
    fn mutations(&self) -> Vec<Box<dyn MutationStrategy>> {
        Vec::new()
    }

    /// Optional: custom output formatter
    fn formatter(&self) -> Option<Box<dyn OutputFormatter>> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
}
```

### 6.2 WASM Plugin Loading

```rust
// src/plugin/wasm.rs

use wasmtime::{Engine, Module, Store, Instance};

pub struct WasmPlugin {
    instance: Instance,
    store: Store<PluginState>,
}

impl WasmPlugin {
    pub fn load(path: &Path) -> Result<Self> {
        let engine = Engine::default();
        let module = Module::from_file(&engine, path)?;
        let mut store = Store::new(&engine, PluginState::default());

        let instance = Instance::new(&mut store, &module, &[])?;

        Ok(Self { instance, store })
    }

    pub fn call_check(&mut self, context: &ScanContext) -> Result<Vec<Finding>> {
        let check_fn = self.instance
            .get_typed_func::<(i32, i32), i32>(&mut self.store, "check")?;

        // Serialize context to WASM memory
        let context_ptr = self.write_to_memory(context)?;

        // Call plugin
        let result_ptr = check_fn.call(&mut self.store, context_ptr)?;

        // Read results from WASM memory
        let findings = self.read_findings(result_ptr)?;

        Ok(findings)
    }
}
```

---

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_fingerprint_stability() {
        let finding = create_test_finding();
        let fp1 = FindingFingerprint::from_finding(&finding);
        let fp2 = FindingFingerprint::from_finding(&finding);
        assert_eq!(fp1, fp2, "Fingerprints should be stable");
    }

    #[test]
    fn test_diff_detects_new_findings() {
        let baseline = create_baseline(vec![finding_a()]);
        let current = create_results(vec![finding_a(), finding_b()]);

        let diff = DiffEngine::diff(&baseline, &current);

        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.unchanged_count, 1);
    }

    #[test]
    fn test_unicode_detection() {
        let rule = UnicodeHiddenInstructionsRule;

        // Should detect zero-width space
        let text = "hello\u{200B}world";
        let suspicious = rule.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);

        // Should detect RTL override
        let text = "hello\u{202E}dlrow";
        let suspicious = rule.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
    }
}
```

### Integration Tests

```rust
// tests/baseline_integration.rs

#[tokio::test]
async fn test_baseline_workflow() {
    let server = start_test_server().await;

    // Initial scan
    let results1 = scan(&server, None).await.unwrap();
    assert!(results1.findings.len() > 0);

    // Create baseline
    let baseline = Baseline::from_results(&results1);
    baseline.save("test_baseline.json").unwrap();

    // Scan with baseline - should show no new findings
    let results2 = scan(&server, Some("test_baseline.json")).await.unwrap();
    assert_eq!(results2.diff.unwrap().new_findings.len(), 0);

    // Add new vulnerability
    server.add_vulnerable_tool().await;

    // Scan again - should detect new finding
    let results3 = scan(&server, Some("test_baseline.json")).await.unwrap();
    assert_eq!(results3.diff.unwrap().new_findings.len(), 1);
}
```

---

## CI/CD Integration Examples

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: MCP Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install mcplint
        run: cargo install mcplint

      - name: Run security scan
        run: |
          mcplint scan ./server.js \
            --baseline .mcplint-baseline.json \
            --format sarif \
            --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  script:
    - cargo install mcplint
    - mcplint scan ./server.js --format gitlab > gl-code-quality-report.json
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
```

---

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Baseline diff accuracy | >99% | False positive rate in PR workflows |
| New rule detection rate | 100% | Coverage of identified attack classes |
| Watch mode latency | <500ms | Time from change to feedback |
| CI/CD integration | 3 platforms | GitHub, GitLab, Jenkins |
| Plugin load time | <100ms | WASM plugin initialization |

---

## Dependencies

### New Crates

```toml
[dependencies]
# Baseline/Diff
sha2 = "0.10"

# Watch mode
notify = "6.0"

# HTML reports
askama = "0.12"  # Template engine

# Plugin system (optional)
wasmtime = "15.0"

# Resource monitoring
sysinfo = "0.30"
```

---

## Timeline Summary

| Week | Phase | Deliverables |
|------|-------|--------------|
| 1-2 | Baseline/Diff | Fingerprinting, diff engine, CLI integration |
| 2-4 | Security Rules | SEC-040 through SEC-045 implementation |
| 4-5 | Watch Mode | File watcher, debouncing, live output |
| 5-6 | Output Formats | JUnit, GitLab, HTML generators |
| 6 | Resource Limits | Fuzzer controls, memory/time limits |
| 7-8 | Plugin Architecture | WASM loading, plugin trait (optional) |

---

## Risk Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Fingerprint instability | Medium | High | Extensive normalization testing |
| WASM plugin security | Medium | Critical | Strict sandboxing, capability limits |
| Watch mode performance | Low | Medium | Debouncing, incremental scans |
| Unicode detection false positives | Medium | Low | Whitelist common legitimate uses |

---

*Document Version: 1.0*
*Last Updated: December 7, 2025*
*Author: Claude Code Design Agent*
