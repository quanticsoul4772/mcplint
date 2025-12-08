# M7 Enterprise Features - Implementation Plan

**Generated:** December 8, 2025
**Status:** Ready for Implementation
**Estimated Duration:** 8-10 weeks

---

## Executive Summary

This plan transforms MCPLint from a standalone security tool into an enterprise-grade platform with seven major features:

| Phase | Feature | Priority | Complexity | Est. Hours |
|-------|---------|----------|------------|------------|
| 1 | Resource Limits | High | Low | 16-20h |
| 2 | Multi-Server Analysis | High | Medium | 24-32h |
| 3 | WASM Plugin System | Critical | High | 40-48h |
| 4 | Parallel Scanning | Medium | Medium | 16-24h |
| 5 | Interactive AI Mode | High | Medium | 24-32h |
| 6 | Auto-Fix Suggestions | Medium | High | 32-40h |
| 7 | Distributed Fuzzing | Medium | High | 40-48h |

**Note:** HTML Reports already implemented in M6 (Phase 1 from original M7 design is complete).

---

## Phase 1: Resource Limits (Week 1)

### 1.1 Overview

Add resource controls to the fuzzer for production safety and CI/CD environments.

### 1.2 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Resource Limits System                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Limits     │    │   Monitor    │    │   Enforcer   │  │
│  │   Config     │───▶│   (sysinfo)  │───▶│  (shutdown)  │  │
│  │              │    │              │    │              │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                             │
│  Tracked Resources:                                         │
│  • Execution time (Duration)                                │
│  • Memory usage (bytes via sysinfo)                         │
│  • Iteration count (u64)                                    │
│  • Corpus size (entries)                                    │
│  • Server restarts (count)                                  │
└─────────────────────────────────────────────────────────────┘
```

### 1.3 File Structure

```
src/fuzzer/
├── limits.rs          # NEW: Resource limits and monitoring
├── mod.rs             # MODIFY: Add limits module, integrate with FuzzEngine
├── session.rs         # MODIFY: Add limit checking in fuzzing loop
└── config.rs          # MODIFY: Add limit fields to FuzzConfig
```

### 1.4 Implementation Steps

```rust
// Step 1: Create src/fuzzer/limits.rs

use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_time: Option<Duration>,
    pub max_memory: Option<u64>,
    pub max_executions: Option<u64>,
    pub max_corpus_size: Option<usize>,
    pub max_restarts: Option<u32>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_time: Some(Duration::from_secs(300)),
            max_memory: Some(512 * 1024 * 1024),  // 512MB
            max_executions: None,
            max_corpus_size: Some(10_000),
            max_restarts: Some(10),
        }
    }
}

#[derive(Debug)]
pub enum LimitExceeded {
    Time(Duration),
    Memory(u64),
    Executions(u64),
    CorpusSize(usize),
    Restarts(u32),
}

pub struct ResourceMonitor {
    limits: ResourceLimits,
    start_time: Instant,
    restart_count: u32,
}

impl ResourceMonitor {
    pub fn new(limits: ResourceLimits) -> Self;
    pub fn check(&mut self, stats: &FuzzStats) -> Option<LimitExceeded>;
    pub fn record_restart(&mut self);
}
```

### 1.5 CLI Changes

```bash
# New fuzz command options
mcplint fuzz server.js \
    --max-time 10m \
    --max-memory 1G \
    --max-execs 50000 \
    --max-restarts 5
```

### 1.6 Dependencies

```toml
# Add to Cargo.toml
sysinfo = "0.30"
humantime = "2.1"
```

### 1.7 Success Criteria

- [ ] Time limits enforce graceful shutdown
- [ ] Memory limits prevent OOM situations
- [ ] Execution limits stop after N iterations
- [ ] Corpus size limits prevent unbounded growth
- [ ] Restart limits prevent infinite restart loops
- [ ] All limits configurable via CLI and config file

---

## Phase 2: Multi-Server Analysis (Weeks 2-3)

### 2.1 Overview

Enable scanning multiple MCP servers simultaneously with cross-server security analysis.

### 2.2 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                Multi-Server Analysis System                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │Server A │  │Server B │  │Server C │  │Server D │        │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘        │
│       │            │            │            │              │
│       └────────────┴────────────┴────────────┘              │
│                         │                                   │
│                         ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Cross-Server Analyzer                    │  │
│  │                                                       │  │
│  │  • Tool shadowing detection (reuse SEC-041)          │  │
│  │  • Description conflicts                              │  │
│  │  • Permission inconsistencies                         │  │
│  │  • Duplicate tool detection                          │  │
│  │  • Security gap analysis                             │  │
│  └──────────────────────────────────────────────────────┘  │
│                         │                                   │
│                         ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Combined Report                          │  │
│  │  • Per-server findings                               │  │
│  │  • Cross-server findings                             │  │
│  │  • Aggregate statistics                              │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 File Structure

```
src/multi/                 # NEW directory
├── mod.rs                 # Multi-server orchestration
├── config.rs              # Server configuration
├── analyzer.rs            # Cross-server analysis
└── report.rs              # Combined reporting

src/cli/commands/
├── multi_scan.rs          # NEW: Multi-server scan command
└── mod.rs                 # MODIFY: Add multi-scan command
```

### 2.4 Implementation Steps

```rust
// Step 1: Create src/multi/config.rs

pub struct MultiServerConfig {
    pub servers: Vec<ServerSpec>,
    pub parallel: bool,
    pub cross_server_checks: bool,
    pub timeout_per_server: Duration,
}

pub struct ServerSpec {
    pub name: String,
    pub transport: TransportType,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    pub working_dir: Option<PathBuf>,
    pub env: HashMap<String, String>,
}

// Step 2: Create src/multi/analyzer.rs

pub struct CrossServerAnalyzer;

impl CrossServerAnalyzer {
    pub fn analyze(
        results: &HashMap<String, ScanResults>,
    ) -> Vec<CrossServerFinding>;

    fn detect_tool_shadowing(
        server_a: &str, tools_a: &[Tool],
        server_b: &str, tools_b: &[Tool],
    ) -> Vec<CrossServerFinding>;

    fn detect_description_conflicts(
        server_a: &str, tools_a: &[Tool],
        server_b: &str, tools_b: &[Tool],
    ) -> Vec<CrossServerFinding>;
}

pub enum CrossServerFindingType {
    ToolShadowing,
    DescriptionConflict,
    DuplicateTool,
    PermissionInconsistency,
    SecurityGap,
}
```

### 2.5 CLI Integration

```bash
# Scan multiple servers from CLI
mcplint multi-scan \
    --server "api:node api/server.js" \
    --server "db:python db/server.py" \
    --server "auth:./auth-server"

# From config file
mcplint multi-scan --config servers.toml

# With cross-server analysis
mcplint multi-scan --config servers.toml --cross-server

# Parallel execution
mcplint multi-scan --config servers.toml --parallel
```

### 2.6 Config File Format

```toml
# servers.toml

[options]
parallel = true
cross_server_checks = true
timeout_per_server = "60s"

[[servers]]
name = "api-gateway"
command = "node"
args = ["./api/server.js"]

[[servers]]
name = "database-bridge"
command = "python"
args = ["-m", "db_mcp"]
working_dir = "./database"

[[servers]]
name = "auth-service"
url = "http://localhost:3001/mcp"
transport = "streamable_http"
```

### 2.7 Success Criteria

- [ ] Scan multiple servers in sequence
- [ ] Scan multiple servers in parallel
- [ ] Detect tool shadowing across servers
- [ ] Detect description conflicts
- [ ] Generate combined HTML/JSON reports
- [ ] Cross-server findings include all involved servers

---

## Phase 3: WASM Plugin System (Weeks 3-5)

### 3.1 Overview

Enable custom security rules via WebAssembly plugins with sandboxed execution.

### 3.2 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Plugin System Architecture                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                 Plugin Host (mcplint)                 │  │
│  │                                                       │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐     │  │
│  │  │  Registry  │  │  Loader    │  │  Executor  │     │  │
│  │  │            │  │            │  │            │     │  │
│  │  │ • Discover │  │ • Validate │  │ • Sandbox  │     │  │
│  │  │ • Config   │  │ • Load     │  │ • Run      │     │  │
│  │  │ • Enable   │  │ • Init     │  │ • Timeout  │     │  │
│  │  └────────────┘  └────────────┘  └────────────┘     │  │
│  │                         │                            │  │
│  │                         ▼                            │  │
│  │  ┌──────────────────────────────────────────────┐   │  │
│  │  │          WASM Runtime (wasmtime)             │   │  │
│  │  │                                              │   │  │
│  │  │  Sandboxed Capabilities:                     │   │  │
│  │  │  • Memory limit: 16MB (configurable)         │   │  │
│  │  │  • CPU timeout: 5s (configurable)            │   │  │
│  │  │  • No filesystem access                      │   │  │
│  │  │  • No network access                         │   │  │
│  │  │  • Read-only scan context                    │   │  │
│  │  └──────────────────────────────────────────────┘   │  │
│  │                                                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Plugin (WASM Guest)                      │  │
│  │                                                       │  │
│  │  Required Exports:                                    │  │
│  │  • plugin_info() -> PluginInfo                       │  │
│  │  • plugin_init(config: &[u8]) -> i32                 │  │
│  │  • plugin_check(context: &[u8]) -> Vec<Finding>      │  │
│  │  • plugin_cleanup()                                  │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 File Structure

```
src/plugin/                # NEW directory
├── mod.rs                 # Plugin system entry point
├── host.rs                # WASM host implementation
├── registry.rs            # Plugin discovery and management
├── sandbox.rs             # Security sandbox configuration
├── interface.rs           # Plugin interface definitions
└── errors.rs              # Plugin-specific errors

mcplint-plugin-sdk/        # NEW crate for plugin developers
├── Cargo.toml
├── src/
│   ├── lib.rs             # SDK entry point
│   ├── types.rs           # Shared types (Finding, Tool, etc.)
│   └── macros.rs          # Helper macros for plugin creation

src/cli/commands/
├── plugins.rs             # NEW: Plugin management command
└── mod.rs                 # MODIFY: Add plugins command
```

### 3.4 Plugin SDK

```rust
// mcplint-plugin-sdk/src/lib.rs

/// Information about the plugin
#[repr(C)]
pub struct PluginInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub author: &'static str,
    pub description: &'static str,
}

/// A security finding from the plugin
#[derive(Serialize, Deserialize)]
pub struct PluginFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub location: String,
    pub remediation: Option<String>,
}

/// Severity levels
#[repr(u8)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Scan context provided to plugins
#[derive(Serialize, Deserialize)]
pub struct ScanContext {
    pub server_name: String,
    pub tools: Vec<Tool>,
    pub resources: Vec<Resource>,
    pub prompts: Vec<Prompt>,
}

/// Macro to simplify plugin creation
#[macro_export]
macro_rules! mcplint_plugin {
    ($info:expr, $check:expr) => {
        #[no_mangle]
        pub extern "C" fn plugin_info() -> *const PluginInfo {
            &$info as *const PluginInfo
        }

        #[no_mangle]
        pub extern "C" fn plugin_check(
            context_ptr: *const u8,
            context_len: u32,
        ) -> *const u8 {
            // Implementation
        }
    };
}
```

### 3.5 Example Plugin

```rust
// example-plugin/src/lib.rs

use mcplint_plugin_sdk::*;

static PLUGIN_INFO: PluginInfo = PluginInfo {
    name: "custom-company-rules",
    version: "1.0.0",
    author: "Security Team",
    description: "Custom security rules for our company policies",
};

fn check_tools(context: &ScanContext) -> Vec<PluginFinding> {
    let mut findings = Vec::new();

    for tool in &context.tools {
        // Custom check: tool names must start with company prefix
        if !tool.name.starts_with("acme_") {
            findings.push(PluginFinding {
                rule_id: "ACME-001".to_string(),
                severity: Severity::Low,
                title: "Tool missing company prefix".to_string(),
                description: format!(
                    "Tool '{}' should start with 'acme_' prefix per company policy",
                    tool.name
                ),
                location: format!("tool:{}", tool.name),
                remediation: Some("Rename tool to start with 'acme_'".to_string()),
            });
        }
    }

    findings
}

mcplint_plugin!(PLUGIN_INFO, check_tools);
```

### 3.6 CLI Integration

```bash
# List available plugins
mcplint plugins list

# Install plugin from file
mcplint plugins install ./custom-rules.wasm

# Install from URL
mcplint plugins install https://company.com/rules.wasm

# Enable/disable plugins
mcplint plugins enable custom-rules
mcplint plugins disable custom-rules

# Run scan with specific plugins
mcplint scan server.js --plugins custom-rules,other-rules

# Run scan without plugins
mcplint scan server.js --no-plugins

# Show plugin info
mcplint plugins info custom-rules
```

### 3.7 Config Integration

```toml
# .mcplint.toml

[plugins]
enabled = true
paths = [
    "./plugins",
    "~/.mcplint/plugins",
]

[plugins.limits]
max_memory = "16MB"
timeout = "5s"
max_findings = 100

[plugins.custom-rules]
enabled = true
config = { severity_threshold = "medium" }
```

### 3.8 Dependencies

```toml
[dependencies]
wasmtime = "15.0"

[features]
default = []
plugins = ["wasmtime"]
```

### 3.9 Success Criteria

- [ ] Load WASM plugins from disk
- [ ] Sandbox enforces memory limits
- [ ] Sandbox enforces execution timeout
- [ ] Plugins cannot access filesystem
- [ ] Plugins cannot access network
- [ ] Plugin findings merge with native findings
- [ ] Plugin SDK compiles to WASM
- [ ] Example plugin demonstrates full workflow

---

## Phase 4: Parallel Scanning (Week 5-6)

### 4.1 Overview

Enable parallel execution of security scans across multiple servers for performance at scale.

### 4.2 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Parallel Scanning System                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Parallel Scan Orchestrator               │  │
│  │                                                       │  │
│  │  • Semaphore-based concurrency control               │  │
│  │  • Per-server timeout management                     │  │
│  │  • Result aggregation                                │  │
│  │  • Error handling (continue-on-error option)         │  │
│  └──────────────────────────────────────────────────────┘  │
│                         │                                   │
│         ┌───────────────┼───────────────┐                  │
│         ▼               ▼               ▼                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ Worker 1 │    │ Worker 2 │    │ Worker 3 │              │
│  │          │    │          │    │          │              │
│  │ Server A │    │ Server B │    │ Server C │              │
│  └──────────┘    └──────────┘    └──────────┘              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.3 File Structure

```
src/scanner/
├── parallel.rs            # NEW: Parallel scanning orchestration
├── mod.rs                 # MODIFY: Add parallel module
└── engine.rs              # MODIFY: Make ScanEngine Clone-able

src/multi/
└── mod.rs                 # MODIFY: Use parallel scanner
```

### 4.4 Implementation

```rust
// src/scanner/parallel.rs

use tokio::sync::Semaphore;
use std::sync::Arc;

pub struct ParallelScanConfig {
    /// Maximum concurrent scans
    pub max_concurrent: usize,
    /// Timeout per server
    pub timeout_per_server: Duration,
    /// Continue scanning if one server fails
    pub continue_on_error: bool,
}

impl Default for ParallelScanConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            timeout_per_server: Duration::from_secs(120),
            continue_on_error: true,
        }
    }
}

pub struct ParallelScanner {
    config: ParallelScanConfig,
}

impl ParallelScanner {
    pub async fn scan_multiple(
        &self,
        servers: Vec<ServerSpec>,
        scan_config: ScanConfig,
    ) -> Result<HashMap<String, Result<ScanResults>>> {
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent));

        let handles: Vec<_> = servers
            .into_iter()
            .map(|server| {
                let sem = semaphore.clone();
                let config = scan_config.clone();
                let timeout = self.config.timeout_per_server;

                tokio::spawn(async move {
                    let _permit = sem.acquire().await?;

                    let result = tokio::time::timeout(
                        timeout,
                        scan_server(&server, &config),
                    ).await;

                    (server.name, result)
                })
            })
            .collect();

        // Collect results
        let mut results = HashMap::new();
        for handle in handles {
            match handle.await {
                Ok((name, Ok(Ok(result)))) => {
                    results.insert(name, Ok(result));
                }
                Ok((name, Ok(Err(e)))) => {
                    results.insert(name, Err(e));
                }
                Ok((name, Err(_))) => {
                    results.insert(name, Err(anyhow!("Timeout")));
                }
                Err(e) => {
                    // JoinError - task panicked
                }
            }
        }

        Ok(results)
    }
}
```

### 4.5 CLI Integration

```bash
# Parallel scan with default concurrency
mcplint multi-scan --config servers.toml --parallel

# Specify concurrency level
mcplint multi-scan --config servers.toml --parallel --concurrency 8

# Stop on first error
mcplint multi-scan --config servers.toml --parallel --fail-fast
```

### 4.6 Success Criteria

- [ ] Parallel execution respects concurrency limits
- [ ] Per-server timeouts work correctly
- [ ] Results properly aggregated
- [ ] Continue-on-error behavior works
- [ ] Performance improvement measurable (2x workers ≈ 2x throughput)

---

## Phase 5: Interactive AI Mode (Week 6-7)

### 5.1 Overview

Enable interactive conversations with the AI about security findings.

### 5.2 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│               Interactive AI Session                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Session Manager                          │  │
│  │                                                       │  │
│  │  • Conversation history (multi-turn)                 │  │
│  │  • Context management (finding + explanations)       │  │
│  │  • Suggested follow-up questions                     │  │
│  │  • Session persistence (optional)                    │  │
│  └──────────────────────────────────────────────────────┘  │
│                         │                                   │
│                         ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              AI Provider Interface                    │  │
│  │                                                       │  │
│  │  • chat() for multi-turn conversations               │  │
│  │  • Stream responses for real-time feedback           │  │
│  │  • Context-aware prompts                             │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 5.3 File Structure

```
src/ai/
├── interactive.rs         # NEW: Interactive session management
├── mod.rs                 # MODIFY: Add interactive module
├── provider/
│   └── mod.rs             # MODIFY: Add chat() method to Provider trait
└── engine.rs              # MODIFY: Add chat support to ExplainEngine

src/cli/commands/
└── explain.rs             # MODIFY: Add --interactive flag
```

### 5.4 Implementation

```rust
// src/ai/interactive.rs

pub struct InteractiveSession {
    engine: ExplainEngine,
    finding: Finding,
    history: Vec<ConversationTurn>,
    suggested_questions: Vec<String>,
}

pub struct ConversationTurn {
    pub role: Role,
    pub content: String,
    pub timestamp: DateTime<Utc>,
}

pub enum Role {
    User,
    Assistant,
    System,
}

impl InteractiveSession {
    pub async fn start(
        engine: ExplainEngine,
        finding: &Finding,
    ) -> Result<Self> {
        // Generate initial explanation
        let initial = engine.explain(finding).await?;

        let history = vec![
            ConversationTurn {
                role: Role::System,
                content: build_system_prompt(finding),
                timestamp: Utc::now(),
            },
            ConversationTurn {
                role: Role::Assistant,
                content: initial.explanation.summary.clone(),
                timestamp: Utc::now(),
            },
        ];

        let suggested = Self::generate_suggestions(finding);

        Ok(Self {
            engine,
            finding: finding.clone(),
            history,
            suggested_questions: suggested,
        })
    }

    pub async fn ask(&mut self, question: &str) -> Result<String> {
        // Add user message
        self.history.push(ConversationTurn {
            role: Role::User,
            content: question.to_string(),
            timestamp: Utc::now(),
        });

        // Generate response with full conversation context
        let response = self.engine.chat(&self.history).await?;

        // Add assistant response
        self.history.push(ConversationTurn {
            role: Role::Assistant,
            content: response.clone(),
            timestamp: Utc::now(),
        });

        // Update suggested questions based on conversation
        self.update_suggestions();

        Ok(response)
    }

    pub fn suggestions(&self) -> &[String] {
        &self.suggested_questions
    }

    fn generate_suggestions(finding: &Finding) -> Vec<String> {
        let mut suggestions = vec![
            "How can I fix this vulnerability?".to_string(),
            "What's the impact if this is exploited?".to_string(),
            "Can you show me an example attack?".to_string(),
        ];

        // Add rule-specific suggestions
        match finding.rule_id.as_str() {
            "MCP-INJ-001" | "MCP-INJ-002" => {
                suggestions.push("How do I sanitize inputs safely?".to_string());
            }
            "MCP-AUTH-001" | "MCP-AUTH-002" => {
                suggestions.push("What authentication methods work with MCP?".to_string());
            }
            "MCP-SEC-041" => {
                suggestions.push("How do I prevent tool shadowing?".to_string());
            }
            _ => {}
        }

        suggestions
    }
}
```

### 5.5 CLI Integration

```bash
# Start interactive session for a finding
mcplint explain server.js --interactive

# Interactive with specific finding
mcplint explain server.js --interactive --finding MCP-INJ-001

# Interactive mode example session:
# > What is command injection?
# AI: Command injection is...
#
# Suggested questions:
# 1. How can I fix this vulnerability?
# 2. What's the impact if this is exploited?
# 3. Can you show me an example attack?
#
# > 1
# AI: To fix this vulnerability...
```

### 5.6 Success Criteria

- [ ] Multi-turn conversations work correctly
- [ ] Context preserved across turns
- [ ] Suggested questions are contextually relevant
- [ ] Streaming responses for real-time feedback
- [ ] Session can be exited cleanly

---

## Phase 6: Auto-Fix Suggestions (Week 7-8)

### 6.1 Overview

Generate AI-powered fix suggestions for detected vulnerabilities.

### 6.2 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│               Auto-Fix Suggestion System                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Fix Generation Engine                    │  │
│  │                                                       │  │
│  │  • Analyze finding + evidence                        │  │
│  │  • Generate fix prompt                               │  │
│  │  • Parse structured response                         │  │
│  │  • Validate suggested changes                        │  │
│  └──────────────────────────────────────────────────────┘  │
│                         │                                   │
│                         ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Fix Suggestion Output                    │  │
│  │                                                       │  │
│  │  • Fix type (code_patch, config, architectural)      │  │
│  │  • Confidence score (0.0 - 1.0)                      │  │
│  │  • Code changes (file, line, original, replacement)  │  │
│  │  • Verification steps                                │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.3 File Structure

```
src/ai/
├── autofix.rs             # NEW: Auto-fix suggestion engine
├── mod.rs                 # MODIFY: Add autofix module
└── prompt.rs              # MODIFY: Add fix prompt templates

src/cli/commands/
├── fix.rs                 # NEW: Fix suggestion command
└── scan.rs                # MODIFY: Add --suggest-fixes flag
```

### 6.4 Implementation

```rust
// src/ai/autofix.rs

pub struct AutoFixEngine {
    ai_engine: ExplainEngine,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AutoFixSuggestion {
    pub finding_id: String,
    pub confidence: f64,
    pub fix_type: FixType,
    pub description: String,
    pub code_changes: Vec<CodeChange>,
    pub verification_steps: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum FixType {
    /// Direct code replacement
    CodePatch,
    /// Configuration change
    ConfigChange,
    /// Requires architectural changes
    ArchitecturalChange,
    /// Cannot auto-fix, manual intervention needed
    ManualRequired,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeChange {
    pub file_path: String,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
    pub original: Option<String>,
    pub replacement: String,
    pub explanation: String,
}

impl AutoFixEngine {
    pub async fn suggest_fix(
        &self,
        finding: &Finding,
    ) -> Result<AutoFixSuggestion> {
        let prompt = self.build_fix_prompt(finding);
        let response = self.ai_engine.generate_raw(&prompt).await?;
        self.parse_fix_response(&response, finding)
    }

    pub async fn suggest_fixes_batch(
        &self,
        findings: &[Finding],
    ) -> Result<Vec<AutoFixSuggestion>> {
        let mut suggestions = Vec::new();

        for finding in findings {
            match self.suggest_fix(finding).await {
                Ok(suggestion) => suggestions.push(suggestion),
                Err(e) => {
                    warn!("Failed to generate fix for {}: {}", finding.rule_id, e);
                }
            }
        }

        Ok(suggestions)
    }

    fn build_fix_prompt(&self, finding: &Finding) -> String {
        format!(r#"
You are a security expert providing auto-fix suggestions for MCP server vulnerabilities.

Finding:
- Rule: {} ({})
- Severity: {:?}
- Location: {}
- Description: {}

Evidence:
{}

Provide a JSON response with:
{{
    "fix_type": "code_patch" | "config_change" | "architectural_change" | "manual_required",
    "confidence": 0.0-1.0,
    "description": "Human-readable explanation of the fix",
    "code_changes": [
        {{
            "file_path": "path/to/file",
            "line_start": 10,
            "line_end": 15,
            "original": "original code if known",
            "replacement": "fixed code",
            "explanation": "why this change fixes the issue"
        }}
    ],
    "verification_steps": [
        "Step 1: ...",
        "Step 2: ..."
    ],
    "warnings": ["Any caveats about this fix"]
}}

Focus on security-first fixes that don't break functionality.
"#,
            finding.rule_id,
            finding.title,
            finding.severity,
            finding.location.identifier,
            finding.description,
            finding.evidence.iter()
                .map(|e| format!("- {}", e.description))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}
```

### 6.5 CLI Integration

```bash
# Suggest fixes for all findings
mcplint scan server.js --suggest-fixes

# Get fix for specific finding
mcplint fix server.js --finding MCP-INJ-001

# Output fixes as JSON for tooling integration
mcplint scan server.js --suggest-fixes --format json

# Show detailed fix with code changes
mcplint fix server.js --finding MCP-INJ-001 --verbose
```

### 6.6 Success Criteria

- [ ] Generate fix suggestions for common vulnerability types
- [ ] Confidence scores reflect fix reliability
- [ ] Code changes are properly formatted
- [ ] Verification steps are actionable
- [ ] Warnings highlight potential issues
- [ ] Works with all AI providers

---

## Phase 7: Distributed Fuzzing (Week 8-10)

### 7.1 Overview

Enable distributed fuzzing across multiple machines for large-scale security testing.

### 7.2 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              Distributed Fuzzing Architecture                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                   Coordinator                         │  │
│  │                                                       │  │
│  │  • Worker registration and health monitoring         │  │
│  │  • Corpus distribution and synchronization           │  │
│  │  • Finding aggregation                               │  │
│  │  • Statistics and progress tracking                  │  │
│  └──────────────────────────────────────────────────────┘  │
│                         │                                   │
│         ┌───────────────┼───────────────┐                  │
│         ▼               ▼               ▼                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ Worker 1 │    │ Worker 2 │    │ Worker 3 │              │
│  │          │    │          │    │          │              │
│  │ • Fuzz   │    │ • Fuzz   │    │ • Fuzz   │              │
│  │ • Report │    │ • Report │    │ • Report │              │
│  │ • Sync   │    │ • Sync   │    │ • Sync   │              │
│  └──────────┘    └──────────┘    └──────────┘              │
│                                                             │
│  Communication Protocol:                                    │
│  • TCP for control messages                                 │
│  • Protobuf or MessagePack for serialization               │
│  • Heartbeat for worker health                             │
│  • Corpus sync: periodic + on-discovery                    │
└─────────────────────────────────────────────────────────────┘
```

### 7.3 File Structure

```
src/fuzzer/
├── distributed/           # NEW directory
│   ├── mod.rs             # Distributed fuzzing entry point
│   ├── coordinator.rs     # Coordinator implementation
│   ├── worker.rs          # Worker implementation
│   ├── protocol.rs        # Communication protocol
│   └── sync.rs            # Corpus synchronization
├── mod.rs                 # MODIFY: Add distributed module
└── session.rs             # MODIFY: Support distributed mode

src/cli/commands/
├── fuzz_distributed.rs    # NEW: Distributed fuzzing command
└── mod.rs                 # MODIFY: Add fuzz-distributed command
```

### 7.4 Protocol Messages

```rust
// src/fuzzer/distributed/protocol.rs

#[derive(Serialize, Deserialize)]
pub enum Message {
    // Worker → Coordinator
    Register {
        worker_id: String,
        capabilities: WorkerCapabilities,
    },
    Heartbeat {
        worker_id: String,
        stats: WorkerStats,
    },
    NewInput {
        worker_id: String,
        input: FuzzInput,
        reason: InterestingReason,
    },
    Finding {
        worker_id: String,
        crash: FuzzCrash,
    },

    // Coordinator → Worker
    Welcome {
        worker_id: String,
        config: FuzzConfig,
        initial_corpus: Vec<FuzzInput>,
    },
    SyncCorpus {
        inputs: Vec<FuzzInput>,
    },
    Shutdown,

    // Bidirectional
    StatsUpdate {
        aggregate_stats: AggregateStats,
    },
}

#[derive(Serialize, Deserialize)]
pub struct WorkerCapabilities {
    pub max_memory: u64,
    pub cores: usize,
}

#[derive(Serialize, Deserialize)]
pub struct WorkerStats {
    pub executions: u64,
    pub coverage_paths: usize,
    pub crashes_found: usize,
    pub interesting_found: usize,
}
```

### 7.5 Coordinator Implementation

```rust
// src/fuzzer/distributed/coordinator.rs

pub struct FuzzCoordinator {
    config: CoordinatorConfig,
    workers: HashMap<String, WorkerState>,
    corpus: SharedCorpus,
    findings: Vec<FuzzCrash>,
    listener: TcpListener,
}

pub struct CoordinatorConfig {
    pub bind_addr: SocketAddr,
    pub sync_interval: Duration,
    pub heartbeat_timeout: Duration,
    pub target_config: FuzzConfig,
}

impl FuzzCoordinator {
    pub async fn new(config: CoordinatorConfig) -> Result<Self>;

    pub async fn run(&mut self) -> Result<FuzzResults> {
        loop {
            tokio::select! {
                // Accept new worker connections
                Ok((stream, addr)) = self.listener.accept() => {
                    self.handle_new_worker(stream, addr).await?;
                }

                // Handle incoming messages from workers
                Some((worker_id, msg)) = self.recv_message() => {
                    self.handle_message(worker_id, msg).await?;
                }

                // Periodic corpus sync
                _ = tokio::time::sleep(self.config.sync_interval) => {
                    self.sync_corpus_to_workers().await?;
                }

                // Check for timed-out workers
                _ = tokio::time::sleep(self.config.heartbeat_timeout / 2) => {
                    self.check_worker_health().await?;
                }
            }
        }
    }

    async fn handle_new_input(&mut self, worker_id: &str, input: FuzzInput) {
        // Add to corpus if interesting
        if self.corpus.is_interesting(&input) {
            self.corpus.add(input.clone());
            // Broadcast to all workers
            self.broadcast(Message::SyncCorpus {
                inputs: vec![input],
            }).await;
        }
    }
}
```

### 7.6 CLI Integration

```bash
# Start coordinator
mcplint fuzz-distributed \
    --coordinator \
    --bind 0.0.0.0:9999 \
    node server.js

# Start worker (on different machine)
mcplint fuzz-distributed \
    --worker \
    --coordinator 192.168.1.100:9999 \
    node server.js

# Local multi-worker mode (for testing)
mcplint fuzz-distributed \
    --workers 4 \
    node server.js

# With resource limits
mcplint fuzz-distributed \
    --coordinator \
    --bind 0.0.0.0:9999 \
    --max-time 1h \
    --max-memory 4G \
    node server.js
```

### 7.7 Dependencies

```toml
[dependencies]
# Serialization for network protocol
bincode = "1.3"

[features]
distributed = []
```

### 7.8 Success Criteria

- [ ] Coordinator accepts worker connections
- [ ] Workers register and receive initial corpus
- [ ] Interesting inputs shared across workers
- [ ] Findings reported to coordinator
- [ ] Statistics aggregated correctly
- [ ] Graceful shutdown of workers
- [ ] Linear scaling (2x workers ≈ 2x throughput)

---

## Dependencies Summary

### New Cargo.toml Additions

```toml
[dependencies]
# Resource monitoring (Phase 1)
sysinfo = "0.30"
humantime = "2.1"

# WASM plugin runtime (Phase 3)
wasmtime = { version = "15.0", optional = true }

# Network serialization (Phase 7)
bincode = { version = "1.3", optional = true }

[features]
default = []
plugins = ["wasmtime"]
distributed = ["bincode"]
all = ["plugins", "distributed"]
```

---

## Implementation Order Rationale

1. **Resource Limits (Phase 1)** - Foundation for safe fuzzing, low complexity
2. **Multi-Server Analysis (Phase 2)** - Builds on existing scanner, medium complexity
3. **WASM Plugins (Phase 3)** - Critical for extensibility, high complexity
4. **Parallel Scanning (Phase 4)** - Performance improvement, uses multi-server foundation
5. **Interactive AI (Phase 5)** - Builds on existing AI infrastructure
6. **Auto-Fix (Phase 6)** - Builds on AI foundation + scan results
7. **Distributed Fuzzing (Phase 7)** - Complex, benefits from resource limits foundation

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| WASM sandbox escape | Use wasmtime security features, extensive testing |
| Performance regression | Benchmark before/after each phase |
| Incorrect auto-fix suggestions | Always require human review, confidence scores |
| Distributed network failures | Graceful degradation, local fallback |
| Memory leaks in long sessions | Resource limits, periodic cleanup |

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Resource limit enforcement | >99% accuracy |
| Multi-server overhead | <20% vs sequential |
| Plugin sandbox security | 0 escapes |
| Auto-fix confidence correlation | >80% |
| Distributed scaling | Linear (2x = 2x) |

---

*Plan Version: 1.0*
*Generated: December 8, 2025*
