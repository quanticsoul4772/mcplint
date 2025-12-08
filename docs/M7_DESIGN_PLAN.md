# M7: Enterprise Features & Extensibility

**Status:** Design Phase
**Target Duration:** 8-10 weeks
**Dependencies:** M0-M6 complete

---

## Executive Summary

M7 transforms mcplint from a standalone tool into an **enterprise-grade security platform** with:

1. **HTML Report Generator** - Rich, interactive security reports for stakeholders
2. **Plugin Architecture** - WASM-based extensibility for custom security rules
3. **Resource Controls** - Fuzzer safety limits and resource monitoring
4. **Multi-Server Analysis** - Compare and validate multiple MCP servers simultaneously
5. **Enhanced AI Features** - Interactive remediation and auto-fix suggestions
6. **Performance & Scale** - Parallel scanning and distributed fuzzing

---

## Feature Overview

| Feature | Priority | Complexity | Business Value |
|---------|----------|------------|----------------|
| HTML Report Generator | 🔴 Critical | Medium | Stakeholder communication |
| Plugin Architecture (WASM) | 🔴 Critical | High | Custom rule extensibility |
| Resource Limits | 🟡 High | Low | Fuzzer safety/production use |
| Multi-Server Analysis | 🟡 High | Medium | Multi-service environments |
| Interactive AI Mode | 🟡 High | Medium | Developer experience |
| Auto-Fix Suggestions | 🟢 Medium | High | Remediation automation |
| Parallel Scanning | 🟢 Medium | Medium | Performance at scale |
| Distributed Fuzzing | 🟢 Medium | High | Large-scale security testing |

---

## Phase 1: HTML Report Generator (Weeks 1-2)

### 1.1 Problem Statement

Current output formats (text, JSON, SARIF, JUnit, GitLab) are designed for machines or developers. Stakeholders (managers, security teams, auditors) need rich, visual reports that communicate security posture effectively.

### 1.2 Solution Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  HTML Report Generator                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │    Scan      │    │   Template   │    │   Rendered   │  │
│  │   Results    │───▶│    Engine    │───▶│    HTML      │  │
│  │  + AI Expl.  │    │   (askama)   │    │   Report     │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                             │
│  Features:                                                  │
│  • Executive summary with severity breakdown                │
│  • Interactive findings table with filtering                │
│  • Trend charts (if baseline available)                     │
│  • AI explanations embedded inline                          │
│  • Dark mode support                                        │
│  • PDF export ready (print stylesheet)                      │
└─────────────────────────────────────────────────────────────┘
```

### 1.3 Report Sections

```rust
// src/reporter/html/sections.rs

pub struct HtmlReport {
    /// Executive summary with key metrics
    pub summary: ExecutiveSummary,
    /// Severity distribution chart data
    pub severity_chart: ChartData,
    /// Findings grouped by category
    pub findings_by_category: HashMap<String, Vec<FindingView>>,
    /// Trend analysis (if baseline provided)
    pub trend: Option<TrendAnalysis>,
    /// AI explanations (if available)
    pub explanations: HashMap<String, ExplanationView>,
    /// Scan metadata
    pub metadata: ReportMetadata,
}

pub struct ExecutiveSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub risk_score: f64,  // 0-100 composite score
    pub scan_duration: Duration,
    pub server_name: String,
    pub profile_used: String,
}
```

### 1.4 Template Structure

```
src/reporter/html/
├── mod.rs              # Generator entry point
├── templates/
│   ├── report.html     # Main template
│   ├── _header.html    # Partial: header/nav
│   ├── _summary.html   # Partial: executive summary
│   ├── _findings.html  # Partial: findings table
│   ├── _charts.html    # Partial: severity charts
│   ├── _trend.html     # Partial: trend analysis
│   └── _footer.html    # Partial: footer
├── assets/
│   ├── style.css       # Embedded styles
│   ├── charts.js       # Chart.js integration
│   └── interactive.js  # Filtering/search
└── views.rs            # View model structs
```

### 1.5 CLI Integration

```bash
# Generate HTML report
mcplint scan server.js --format html --output report.html

# HTML with AI explanations
mcplint scan server.js --format html --explain --output report.html

# HTML with baseline comparison (trend charts)
mcplint scan server.js --format html --baseline baseline.json --output report.html
```

### 1.6 Implementation

```rust
// src/reporter/html/mod.rs

use askama::Template;

#[derive(Template)]
#[template(path = "report.html")]
struct ReportTemplate {
    summary: ExecutiveSummary,
    findings: Vec<FindingView>,
    explanations: HashMap<String, ExplanationView>,
    trend: Option<TrendAnalysis>,
    generated_at: String,
    version: String,
}

pub fn generate_html(
    results: &ScanResults,
    explanations: Option<&[ExplanationResponse]>,
    diff: Option<&DiffResult>,
) -> Result<String> {
    let template = ReportTemplate {
        summary: build_summary(results),
        findings: results.findings.iter()
            .map(|f| FindingView::from(f))
            .collect(),
        explanations: build_explanation_map(explanations),
        trend: diff.map(|d| TrendAnalysis::from(d)),
        generated_at: chrono::Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    template.render().map_err(|e| anyhow::anyhow!("Template error: {}", e))
}

fn build_summary(results: &ScanResults) -> ExecutiveSummary {
    let severity_counts = results.severity_counts();

    ExecutiveSummary {
        total_findings: results.findings.len(),
        critical_count: severity_counts.critical,
        high_count: severity_counts.high,
        medium_count: severity_counts.medium,
        low_count: severity_counts.low,
        risk_score: calculate_risk_score(results),
        scan_duration: Duration::from_millis(results.duration_ms),
        server_name: results.server.clone(),
        profile_used: results.profile.clone(),
    }
}

/// Calculate composite risk score (0-100)
fn calculate_risk_score(results: &ScanResults) -> f64 {
    let weights = [
        (Severity::Critical, 25.0),
        (Severity::High, 15.0),
        (Severity::Medium, 5.0),
        (Severity::Low, 1.0),
    ];

    let score: f64 = results.findings.iter()
        .map(|f| weights.iter()
            .find(|(s, _)| *s == f.severity)
            .map(|(_, w)| *w)
            .unwrap_or(0.0))
        .sum();

    (score / 100.0 * 100.0).min(100.0)
}
```

---

## Phase 2: Plugin Architecture (Weeks 2-4)

### 2.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   Plugin System                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Plugin     │    │    WASM      │    │   Security   │  │
│  │   Registry   │───▶│   Runtime    │───▶│    Rules     │  │
│  │              │    │  (wasmtime)  │    │              │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                   │                   │          │
│         │                   │                   │          │
│         ▼                   ▼                   ▼          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                 Sandbox + Capabilities                │  │
│  │  • Memory limits (16MB default)                      │  │
│  │  • Execution timeout (5s default)                    │  │
│  │  • No filesystem access                              │  │
│  │  • No network access                                 │  │
│  │  • Read-only scan context                            │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Plugin Interface (Guest Side)

```rust
// mcplint-plugin-sdk/src/lib.rs

/// Plugin metadata returned by `plugin_info()`
#[repr(C)]
pub struct PluginInfo {
    pub name: *const u8,
    pub name_len: u32,
    pub version: *const u8,
    pub version_len: u32,
    pub author: *const u8,
    pub author_len: u32,
}

/// Finding returned by `check()` function
#[repr(C)]
pub struct PluginFinding {
    pub rule_id: *const u8,
    pub rule_id_len: u32,
    pub severity: u8,  // 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
    pub title: *const u8,
    pub title_len: u32,
    pub description: *const u8,
    pub description_len: u32,
    pub location: *const u8,
    pub location_len: u32,
}

/// Required exports from plugin WASM module
extern "C" {
    /// Return plugin metadata
    fn plugin_info() -> *const PluginInfo;

    /// Initialize plugin with config JSON
    fn plugin_init(config_ptr: *const u8, config_len: u32) -> i32;

    /// Run security check, returns findings count
    fn plugin_check(
        context_ptr: *const u8,
        context_len: u32,
        findings_ptr: *mut *const PluginFinding,
    ) -> u32;

    /// Clean up resources
    fn plugin_cleanup();
}
```

### 2.3 Plugin Host (mcplint Side)

```rust
// src/plugin/host.rs

use wasmtime::{Engine, Module, Store, Instance, Linker, Config as WasmConfig};

pub struct PluginHost {
    engine: Engine,
    plugins: Vec<LoadedPlugin>,
    config: PluginHostConfig,
}

pub struct LoadedPlugin {
    instance: Instance,
    store: Store<PluginState>,
    metadata: PluginMetadata,
}

pub struct PluginHostConfig {
    /// Maximum memory per plugin (bytes)
    pub max_memory: u64,
    /// Maximum execution time per check
    pub timeout: Duration,
    /// Plugin search paths
    pub plugin_paths: Vec<PathBuf>,
}

impl PluginHost {
    pub fn new(config: PluginHostConfig) -> Result<Self> {
        let mut wasm_config = WasmConfig::new();
        wasm_config.consume_fuel(true);  // Enable fuel for timeout
        wasm_config.epoch_interruption(true);

        let engine = Engine::new(&wasm_config)?;

        Ok(Self {
            engine,
            plugins: Vec::new(),
            config,
        })
    }

    /// Load a plugin from WASM file
    pub fn load_plugin(&mut self, path: &Path) -> Result<()> {
        let wasm_bytes = std::fs::read(path)?;
        let module = Module::new(&self.engine, &wasm_bytes)?;

        let mut store = Store::new(&self.engine, PluginState::default());

        // Set resource limits
        store.limiter(|state| &mut state.limiter);
        store.set_fuel(self.config.timeout.as_secs() * 1_000_000)?;

        let mut linker = Linker::new(&self.engine);
        self.define_host_functions(&mut linker)?;

        let instance = linker.instantiate(&mut store, &module)?;

        // Get plugin info
        let info_fn = instance.get_typed_func::<(), u32>(&mut store, "plugin_info")?;
        let info_ptr = info_fn.call(&mut store, ())?;
        let metadata = self.read_plugin_info(&store, info_ptr)?;

        info!("Loaded plugin: {} v{}", metadata.name, metadata.version);

        self.plugins.push(LoadedPlugin {
            instance,
            store,
            metadata,
        });

        Ok(())
    }

    /// Run all plugins against scan context
    pub fn run_checks(&mut self, context: &ScanContext) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();
        let context_json = serde_json::to_vec(context)?;

        for plugin in &mut self.plugins {
            match self.run_plugin_check(plugin, &context_json) {
                Ok(findings) => all_findings.extend(findings),
                Err(e) => {
                    warn!("Plugin {} failed: {}", plugin.metadata.name, e);
                }
            }
        }

        Ok(all_findings)
    }

    fn run_plugin_check(
        &self,
        plugin: &mut LoadedPlugin,
        context_json: &[u8],
    ) -> Result<Vec<Finding>> {
        // Reset fuel for this execution
        plugin.store.set_fuel(self.config.timeout.as_secs() * 1_000_000)?;

        // Write context to WASM memory
        let context_ptr = self.write_to_memory(&mut plugin.store, &plugin.instance, context_json)?;

        // Call plugin check function
        let check_fn = plugin.instance.get_typed_func::<(u32, u32, u32), u32>(
            &mut plugin.store,
            "plugin_check",
        )?;

        let findings_ptr_ptr = self.allocate_in_wasm(&mut plugin.store, &plugin.instance, 4)?;
        let count = check_fn.call(
            &mut plugin.store,
            (context_ptr, context_json.len() as u32, findings_ptr_ptr),
        )?;

        // Read findings from WASM memory
        let findings = self.read_findings(&plugin.store, &plugin.instance, findings_ptr_ptr, count)?;

        Ok(findings)
    }
}
```

### 2.4 Plugin Configuration

```toml
# .mcplint.toml

[plugins]
# Enable plugin loading
enabled = true

# Plugin search directories
paths = [
    "./plugins",
    "~/.mcplint/plugins",
]

# Resource limits per plugin
[plugins.limits]
max_memory = "16MB"
timeout = "5s"
max_findings = 100

# Individual plugin configuration
[plugins.my-custom-rules]
enabled = true
config = { severity_threshold = "medium", custom_patterns = ["pattern1", "pattern2"] }
```

### 2.5 CLI Integration

```bash
# List loaded plugins
mcplint plugins list

# Install plugin from URL
mcplint plugins install https://example.com/my-plugin.wasm

# Run scan with specific plugins
mcplint scan server.js --plugins my-custom-rules,company-rules

# Disable all plugins
mcplint scan server.js --no-plugins
```

---

## Phase 3: Resource Limits (Week 4-5)

### 3.1 Fuzzer Resource Controls

```rust
// src/fuzzer/limits.rs

use std::time::{Duration, Instant};
use sysinfo::{System, Pid, ProcessExt};

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum execution time
    pub max_time: Option<Duration>,
    /// Maximum memory usage (bytes)
    pub max_memory: Option<u64>,
    /// Maximum number of executions
    pub max_executions: Option<u64>,
    /// Maximum corpus size (entries)
    pub max_corpus_size: Option<usize>,
    /// CPU limit (percentage, 1-100)
    pub cpu_limit: Option<u8>,
    /// Maximum server restarts
    pub max_restarts: Option<u32>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_time: Some(Duration::from_secs(300)),      // 5 minutes
            max_memory: Some(512 * 1024 * 1024),           // 512MB
            max_executions: None,                          // Unlimited
            max_corpus_size: Some(10_000),                 // 10K entries
            cpu_limit: None,                               // No limit
            max_restarts: Some(10),                        // 10 restarts
        }
    }
}

impl ResourceLimits {
    pub fn from_cli(args: &FuzzArgs) -> Result<Self> {
        let mut limits = Self::default();

        if let Some(time) = &args.max_time {
            limits.max_time = Some(parse_duration(time)?);
        }
        if let Some(mem) = &args.max_memory {
            limits.max_memory = Some(parse_bytes(mem)?);
        }
        if let Some(execs) = args.max_execs {
            limits.max_executions = Some(execs);
        }
        if let Some(cpu) = args.cpu_limit {
            limits.cpu_limit = Some(cpu.clamp(1, 100));
        }

        Ok(limits)
    }
}

pub struct ResourceMonitor {
    limits: ResourceLimits,
    start_time: Instant,
    system: System,
    target_pid: Option<Pid>,
}

impl ResourceMonitor {
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            start_time: Instant::now(),
            system: System::new_all(),
            target_pid: None,
        }
    }

    pub fn set_target_pid(&mut self, pid: u32) {
        self.target_pid = Some(Pid::from(pid as usize));
    }

    pub fn check(&mut self, stats: &FuzzStats) -> Option<LimitExceeded> {
        // Time limit
        if let Some(max_time) = self.limits.max_time {
            if self.start_time.elapsed() >= max_time {
                return Some(LimitExceeded::Time(max_time));
            }
        }

        // Execution limit
        if let Some(max_execs) = self.limits.max_executions {
            if stats.executions >= max_execs {
                return Some(LimitExceeded::Executions(max_execs));
            }
        }

        // Memory limit
        if let Some(max_mem) = self.limits.max_memory {
            self.system.refresh_processes();
            if let Some(pid) = self.target_pid {
                if let Some(process) = self.system.process(pid) {
                    let memory = process.memory();
                    if memory >= max_mem {
                        return Some(LimitExceeded::Memory(max_mem));
                    }
                }
            }
        }

        // Corpus size limit
        if let Some(max_corpus) = self.limits.max_corpus_size {
            if stats.corpus_size >= max_corpus {
                return Some(LimitExceeded::CorpusSize(max_corpus));
            }
        }

        None
    }
}

#[derive(Debug, Clone)]
pub enum LimitExceeded {
    Time(Duration),
    Memory(u64),
    Executions(u64),
    CorpusSize(usize),
    Restarts(u32),
}

impl std::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Time(d) => write!(f, "Time limit exceeded: {:?}", d),
            Self::Memory(b) => write!(f, "Memory limit exceeded: {} bytes", b),
            Self::Executions(n) => write!(f, "Execution limit exceeded: {}", n),
            Self::CorpusSize(n) => write!(f, "Corpus size limit exceeded: {} entries", n),
            Self::Restarts(n) => write!(f, "Restart limit exceeded: {} restarts", n),
        }
    }
}
```

### 3.2 CLI Integration

```bash
# Time limit (supports s, m, h suffixes)
mcplint fuzz server.js --max-time 10m

# Memory limit (supports K, M, G suffixes)
mcplint fuzz server.js --max-memory 1G

# Execution limit
mcplint fuzz server.js --max-execs 50000

# CPU limit (percentage)
mcplint fuzz server.js --cpu-limit 50

# Combined limits
mcplint fuzz server.js \
    --max-time 30m \
    --max-memory 2G \
    --max-execs 100000 \
    --cpu-limit 75
```

---

## Phase 4: Multi-Server Analysis (Week 5-6)

### 4.1 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                Multi-Server Analysis                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │Server A │  │Server B │  │Server C │  │Server D │        │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘        │
│       │            │            │            │              │
│       └────────────┴────────────┴────────────┘              │
│                         │                                   │
│                         ▼                                   │
│              ┌──────────────────┐                          │
│              │  Cross-Server    │                          │
│              │   Analyzer       │                          │
│              │                  │                          │
│              │  • Tool conflicts│                          │
│              │  • Shadowing     │                          │
│              │  • Duplicates    │                          │
│              │  • Inconsistent  │                          │
│              │    permissions   │                          │
│              └──────────────────┘                          │
│                         │                                   │
│                         ▼                                   │
│              ┌──────────────────┐                          │
│              │ Combined Report  │                          │
│              │  • Per-server    │                          │
│              │  • Aggregate     │                          │
│              │  • Cross-cutting │                          │
│              └──────────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Data Structures

```rust
// src/multi/mod.rs

pub struct MultiServerConfig {
    pub servers: Vec<ServerSpec>,
    pub parallel: bool,
    pub cross_server_checks: bool,
    pub aggregate_report: bool,
}

pub struct ServerSpec {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
    pub env: HashMap<String, String>,
}

pub struct MultiServerResults {
    /// Results per server
    pub server_results: HashMap<String, ScanResults>,
    /// Cross-server findings
    pub cross_server_findings: Vec<CrossServerFinding>,
    /// Aggregate statistics
    pub aggregate: AggregateStats,
}

pub struct CrossServerFinding {
    pub finding_type: CrossServerFindingType,
    pub servers_involved: Vec<String>,
    pub details: String,
    pub severity: Severity,
}

pub enum CrossServerFindingType {
    /// Same tool name, different implementations
    ToolShadowing,
    /// Same tool with conflicting descriptions
    DescriptionConflict,
    /// Duplicate tool definitions
    DuplicateTool,
    /// Inconsistent permission models
    PermissionInconsistency,
    /// One server is more permissive
    SecurityGap,
}
```

### 4.3 CLI Integration

```bash
# Scan multiple servers
mcplint multi-scan \
    --server "api-server:node api/server.js" \
    --server "db-server:python db/server.py" \
    --server "auth-server:./auth-server"

# From config file
mcplint multi-scan --config servers.toml

# With cross-server analysis
mcplint multi-scan --config servers.toml --cross-server

# Parallel scanning
mcplint multi-scan --config servers.toml --parallel
```

### 4.4 Configuration File

```toml
# servers.toml

[options]
parallel = true
cross_server_checks = true
output_format = "html"

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
command = "./bin/auth-server"
env = { AUTH_MODE = "production" }
```

---

## Phase 5: Enhanced AI Features (Week 6-7)

### 5.1 Interactive AI Mode

```rust
// src/ai/interactive.rs

pub struct InteractiveSession {
    engine: ExplainEngine,
    context: SessionContext,
    history: Vec<ConversationTurn>,
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
    pub async fn start(engine: ExplainEngine, finding: &Finding) -> Result<Self> {
        let context = SessionContext {
            finding: finding.clone(),
            explanations_generated: Vec::new(),
            follow_ups_asked: 0,
        };

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

        Ok(Self { engine, context, history })
    }

    pub async fn ask(&mut self, question: &str) -> Result<String> {
        // Add user message to history
        self.history.push(ConversationTurn {
            role: Role::User,
            content: question.to_string(),
            timestamp: Utc::now(),
        });

        // Generate response with conversation context
        let response = self.engine.chat(&self.history).await?;

        // Add response to history
        self.history.push(ConversationTurn {
            role: Role::Assistant,
            content: response.clone(),
            timestamp: Utc::now(),
        });

        self.context.follow_ups_asked += 1;

        Ok(response)
    }

    pub fn suggested_questions(&self) -> Vec<String> {
        // Generate contextual follow-up suggestions
        let mut suggestions = vec![
            "How can I fix this vulnerability?".to_string(),
            "What's the impact if this is exploited?".to_string(),
            "Can you show me an example attack?".to_string(),
        ];

        // Add context-specific suggestions
        match self.context.finding.rule_id.as_str() {
            "MCP-INJ-001" => {
                suggestions.push("How do I sanitize command inputs?".to_string());
            }
            "MCP-AUTH-001" => {
                suggestions.push("What authentication methods work with MCP?".to_string());
            }
            _ => {}
        }

        suggestions
    }
}
```

### 5.2 Auto-Fix Suggestions

```rust
// src/ai/autofix.rs

pub struct AutoFixEngine {
    engine: ExplainEngine,
}

pub struct AutoFixSuggestion {
    pub finding_id: String,
    pub confidence: f64,
    pub fix_type: FixType,
    pub description: String,
    pub code_changes: Vec<CodeChange>,
    pub verification_steps: Vec<String>,
}

pub enum FixType {
    /// Direct code replacement
    CodePatch,
    /// Configuration change
    ConfigChange,
    /// Architecture recommendation
    ArchitecturalChange,
    /// Cannot auto-fix, manual intervention needed
    ManualRequired,
}

pub struct CodeChange {
    pub file_path: String,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
    pub original: Option<String>,
    pub replacement: String,
    pub explanation: String,
}

impl AutoFixEngine {
    pub async fn suggest_fix(&self, finding: &Finding) -> Result<AutoFixSuggestion> {
        let prompt = self.build_fix_prompt(finding);
        let response = self.engine.generate(&prompt).await?;

        self.parse_fix_response(&response, finding)
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
1. "fix_type": one of "code_patch", "config_change", "architectural_change", "manual_required"
2. "confidence": 0.0-1.0 (how confident you are in this fix)
3. "description": human-readable explanation of the fix
4. "code_changes": array of {{file_path, line_start, line_end, original, replacement, explanation}}
5. "verification_steps": array of steps to verify the fix works

Focus on security-first fixes that don't break functionality.
"#,
            finding.rule_id,
            finding.title,
            finding.severity,
            finding.location.identifier,
            finding.description,
            finding.evidence.iter()
                .map(|e| format!("- {}: {}", e.kind.as_str(), e.description))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}
```

### 5.3 CLI Integration

```bash
# Interactive mode with a finding
mcplint explain server.js --interactive

# Auto-fix suggestions
mcplint scan server.js --suggest-fixes

# Apply suggested fixes (with confirmation)
mcplint fix server.js --finding MCP-INJ-001 --apply
```

---

## Phase 6: Performance & Scale (Week 7-8)

### 6.1 Parallel Scanning

```rust
// src/scanner/parallel.rs

use rayon::prelude::*;
use tokio::sync::Semaphore;

pub struct ParallelScanConfig {
    /// Maximum concurrent scans
    pub max_concurrent: usize,
    /// Scan timeout per server
    pub timeout_per_server: Duration,
    /// Whether to continue on individual failures
    pub continue_on_error: bool,
}

pub struct ParallelScanner {
    config: ParallelScanConfig,
    engine: ScanEngine,
}

impl ParallelScanner {
    pub async fn scan_multiple(
        &self,
        servers: Vec<ServerSpec>,
    ) -> Result<HashMap<String, ScanResults>> {
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent));

        let handles: Vec<_> = servers.into_iter()
            .map(|server| {
                let sem = semaphore.clone();
                let engine = self.engine.clone();
                let timeout = self.config.timeout_per_server;

                tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();

                    tokio::time::timeout(timeout, async {
                        engine.scan(&server.command, &server.args, None).await
                    }).await
                })
            })
            .collect();

        let mut results = HashMap::new();

        for (i, handle) in handles.into_iter().enumerate() {
            match handle.await {
                Ok(Ok(Ok(result))) => {
                    results.insert(format!("server_{}", i), result);
                }
                Ok(Ok(Err(e))) => {
                    if !self.config.continue_on_error {
                        return Err(e);
                    }
                    warn!("Server {} scan failed: {}", i, e);
                }
                Ok(Err(_)) => {
                    warn!("Server {} scan timed out", i);
                }
                Err(e) => {
                    warn!("Server {} task panicked: {}", i, e);
                }
            }
        }

        Ok(results)
    }
}
```

### 6.2 Distributed Fuzzing

```rust
// src/fuzzer/distributed.rs

use tokio::net::{TcpListener, TcpStream};

pub struct DistributedFuzzer {
    role: FuzzerRole,
    coordinator_addr: Option<SocketAddr>,
    workers: Vec<WorkerHandle>,
}

pub enum FuzzerRole {
    /// Coordinates workers, aggregates results
    Coordinator {
        listen_addr: SocketAddr,
    },
    /// Executes fuzzing, reports to coordinator
    Worker {
        coordinator: SocketAddr,
    },
}

pub struct CoordinatorMessage {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

pub enum MessageType {
    /// Worker registration
    Register,
    /// Corpus sharing
    CorpusSync,
    /// New interesting input found
    NewInput,
    /// Crash/finding report
    Finding,
    /// Stats update
    Stats,
    /// Shutdown signal
    Shutdown,
}

impl DistributedFuzzer {
    /// Start as coordinator
    pub async fn start_coordinator(addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        info!("Coordinator listening on {}", addr);

        Ok(Self {
            role: FuzzerRole::Coordinator { listen_addr: addr },
            coordinator_addr: None,
            workers: Vec::new(),
        })
    }

    /// Start as worker
    pub async fn start_worker(coordinator: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(coordinator).await?;
        info!("Connected to coordinator at {}", coordinator);

        Ok(Self {
            role: FuzzerRole::Worker { coordinator },
            coordinator_addr: Some(coordinator),
            workers: Vec::new(),
        })
    }

    /// Run distributed fuzzing session
    pub async fn run(&mut self, config: &FuzzConfig) -> Result<FuzzResults> {
        match &self.role {
            FuzzerRole::Coordinator { .. } => self.run_coordinator(config).await,
            FuzzerRole::Worker { .. } => self.run_worker(config).await,
        }
    }
}
```

### 6.3 CLI Integration

```bash
# Start coordinator
mcplint fuzz-distributed --coordinator --bind 0.0.0.0:9999 server.js

# Start workers (on different machines)
mcplint fuzz-distributed --worker --coordinator 192.168.1.100:9999 server.js

# Local multi-worker (for testing)
mcplint fuzz-distributed --workers 4 server.js
```

---

## Dependencies

### New Crates

```toml
[dependencies]
# HTML templating
askama = "0.12"

# WASM plugin runtime
wasmtime = "15.0"

# System monitoring
sysinfo = "0.30"

# Duration/byte parsing
humantime = "2.1"
humanize-rs = "0.4"

# Network (for distributed fuzzing)
tokio = { version = "1", features = ["net"] }
```

### Feature Flags

```toml
[features]
default = ["html-reports"]
html-reports = ["askama"]
plugins = ["wasmtime"]
distributed = []
all = ["html-reports", "plugins", "distributed"]
```

---

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_html_report_generation() {
        let results = create_test_results();
        let html = generate_html(&results, None, None).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains(&results.server));
        assert!(html.contains("mcplint"));
    }

    #[test]
    fn test_plugin_sandbox_memory_limit() {
        let config = PluginHostConfig {
            max_memory: 1024 * 1024,  // 1MB
            ..Default::default()
        };

        let mut host = PluginHost::new(config).unwrap();
        host.load_plugin(Path::new("test_plugins/memory_hog.wasm")).unwrap();

        let result = host.run_checks(&ScanContext::default());
        assert!(matches!(result, Err(_)));  // Should fail
    }

    #[test]
    fn test_resource_limits_enforcement() {
        let limits = ResourceLimits {
            max_executions: Some(100),
            ..Default::default()
        };

        let mut monitor = ResourceMonitor::new(limits);
        let stats = FuzzStats { executions: 101, ..Default::default() };

        assert!(matches!(monitor.check(&stats), Some(LimitExceeded::Executions(_))));
    }
}
```

### Integration Tests

```rust
// tests/multi_server.rs

#[tokio::test]
async fn test_multi_server_scan() {
    let servers = vec![
        start_test_server("server_a").await,
        start_test_server("server_b").await,
    ];

    let results = multi_scan(&servers, MultiServerConfig::default()).await.unwrap();

    assert_eq!(results.server_results.len(), 2);
}

#[tokio::test]
async fn test_tool_shadowing_detection() {
    // Both servers register a tool called "execute"
    let server_a = start_server_with_tool("execute", "Run a command safely").await;
    let server_b = start_server_with_tool("execute", "Execute arbitrary code").await;

    let results = multi_scan(
        &[server_a, server_b],
        MultiServerConfig { cross_server_checks: true, ..Default::default() },
    ).await.unwrap();

    assert!(results.cross_server_findings.iter()
        .any(|f| f.finding_type == CrossServerFindingType::ToolShadowing));
}
```

---

## Timeline Summary

| Week | Phase | Deliverables |
|------|-------|--------------|
| 1-2 | HTML Reports | Template engine, styling, charts, CLI integration |
| 2-4 | Plugin Architecture | WASM runtime, sandbox, SDK, plugin loading |
| 4-5 | Resource Limits | Fuzzer controls, monitoring, CLI options |
| 5-6 | Multi-Server | Cross-server analysis, parallel scanning |
| 6-7 | AI Features | Interactive mode, auto-fix, conversation history |
| 7-8 | Performance | Parallel scanning, distributed fuzzing |

---

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| HTML report generation | <2s | Time for standard report |
| Plugin sandbox security | 100% | No sandbox escapes in testing |
| Resource limit accuracy | >95% | Limit enforcement precision |
| Multi-server overhead | <20% | Compared to sequential scanning |
| Auto-fix accuracy | >80% | Correct fixes for tested patterns |
| Distributed scaling | Linear | 2x workers = ~2x throughput |

---

## Risk Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| WASM sandbox escape | Low | Critical | Use wasmtime security features, fuzz plugins |
| Performance regression | Medium | Medium | Benchmark before/after each phase |
| AI fix suggestions incorrect | High | Medium | Always require human review |
| Distributed network issues | Medium | Low | Graceful degradation, local fallback |

---

*Document Version: 1.0*
*Last Updated: December 7, 2025*
*Author: Claude Code Design Agent*
