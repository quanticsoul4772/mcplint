# M1: Protocol Validator Implementation Plan

## Overview

M1 implements the **Protocol Validator** - a comprehensive MCP protocol compliance checker that validates servers against the MCP specification (2024-11-05 and 2025-03-26).

## Current State

**Existing Code:**
- `src/protocol/` - JSON-RPC and MCP types fully implemented (M0)
- `src/client/mod.rs` - McpClient with connect, initialize, list_tools, call_tool
- `src/transport/` - stdio, streamable_http, sse transports
- `src/validator/mod.rs` - Placeholder with `ValidationResults`, `ValidationCheck`, `CheckStatus`
- `src/rules/mod.rs` - Rule registry (security-focused, needs protocol rules)

**Gaps:**
- No actual validation logic (placeholder only)
- No protocol-specific validation rules (PROTO-001 to PROTO-010)
- No schema validation for tool inputSchema
- No sequence validation (message ordering)
- No capability validation
- No connection to McpClient for live testing

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Protocol Validator                        │
│       validate command → results → text/json/sarif           │
├─────────────────────────────────────────────────────────────┤
│                     Validation Engine                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Static    │  │   Runtime   │  │     Schema          │  │
│  │  Validators │  │  Validators │  │    Validators       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    Validation Rules                          │
│  PROTO-001..010 | SCHEMA-001..005 | SEQ-001..003            │
├─────────────────────────────────────────────────────────────┤
│                      MCP Client                              │
│        (connect → initialize → query → close)                │
└─────────────────────────────────────────────────────────────┘
```

---

## Validation Rules

### Protocol Rules (PROTO-001 to PROTO-010)

| Rule ID | Name | Category | Severity | Description |
|---------|------|----------|----------|-------------|
| PROTO-001 | Missing Required Field | initialize | Error | Required field missing in initialize response |
| PROTO-002 | Invalid JSON-RPC Version | jsonrpc | Error | jsonrpc field must be "2.0" |
| PROTO-003 | Tool Missing Name | tools | Error | Tool definition missing required 'name' field |
| PROTO-004 | Invalid Tool Schema | tools | Error | Tool inputSchema is not valid JSON Schema |
| PROTO-005 | Pre-Initialize Message | sequence | Error | Message sent before initialize completed |
| PROTO-006 | Unknown Notification | protocol | Warning | Unknown notification type received |
| PROTO-007 | Response ID Mismatch | jsonrpc | Error | Response ID doesn't match any pending request |
| PROTO-008 | Protocol Version Mismatch | initialize | Error | Unsupported protocol version |
| PROTO-009 | Capability Mismatch | capabilities | Warning | Server advertises capability it doesn't support |
| PROTO-010 | Session Violation | http | Error | Streamable HTTP session management violation |

### Schema Rules (SCHEMA-001 to SCHEMA-005)

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| SCHEMA-001 | Missing Type | Error | Schema missing 'type' field at root |
| SCHEMA-002 | Invalid Type | Error | Schema 'type' is not a valid JSON Schema type |
| SCHEMA-003 | Missing Properties | Warning | Object schema missing 'properties' |
| SCHEMA-004 | Required Not Array | Error | 'required' field is not an array |
| SCHEMA-005 | Unknown Required | Warning | 'required' lists property not in 'properties' |

### Sequence Rules (SEQ-001 to SEQ-003)

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| SEQ-001 | No Initialize | Error | Server doesn't respond to initialize |
| SEQ-002 | No Initialized Notification | Warning | Client didn't send initialized notification |
| SEQ-003 | Operations Before Ready | Error | Operations attempted before ready state |

---

## Implementation Tasks

### 1. Validation Rule Types (`src/validator/rules.rs`)

```rust
/// Protocol validation rule
pub trait ValidationRule: Send + Sync {
    /// Rule identifier (e.g., "PROTO-001")
    fn id(&self) -> &str;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Category for grouping
    fn category(&self) -> &str;

    /// Severity level
    fn severity(&self) -> ValidatorSeverity;

    /// Run validation against context
    fn validate(&self, context: &ValidationContext) -> Vec<Violation>;
}

/// Validation severity (distinct from security Severity)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorSeverity {
    Error,   // Fails validation
    Warning, // Issues reported but passes
    Info,    // Informational only
}

/// Validation violation
#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    pub rule_id: String,
    pub severity: ValidatorSeverity,
    pub message: String,
    pub location: Option<String>,
    pub details: Option<String>,
}

/// Context passed to validators
pub struct ValidationContext {
    pub server_info: Option<Implementation>,
    pub protocol_version: Option<String>,
    pub capabilities: Option<ServerCapabilities>,
    pub tools: Vec<Tool>,
    pub resources: Vec<Resource>,
    pub prompts: Vec<Prompt>,
    pub raw_responses: Vec<(String, Value)>, // (method, response)
}
```

### 2. Rule Implementations (`src/validator/rules/`)

**Directory Structure:**
```
src/validator/
├── mod.rs              # Main validator, results types
├── rules.rs            # Rule trait, types
├── context.rs          # ValidationContext builder
├── engine.rs           # Validation engine
└── rules/
    ├── mod.rs          # Rule registry
    ├── protocol.rs     # PROTO-001 to PROTO-010
    ├── schema.rs       # SCHEMA-001 to SCHEMA-005
    └── sequence.rs     # SEQ-001 to SEQ-003
```

**Protocol Rules (`protocol.rs`):**

```rust
pub struct Proto001MissingRequiredField;

impl ValidationRule for Proto001MissingRequiredField {
    fn id(&self) -> &str { "PROTO-001" }
    fn name(&self) -> &str { "Missing Required Field" }
    fn category(&self) -> &str { "initialize" }
    fn severity(&self) -> ValidatorSeverity { ValidatorSeverity::Error }

    fn validate(&self, ctx: &ValidationContext) -> Vec<Violation> {
        let mut violations = vec![];

        // Check initialize result has required fields
        if ctx.server_info.is_none() {
            violations.push(Violation {
                rule_id: self.id().to_string(),
                severity: self.severity(),
                message: "Initialize response missing serverInfo".to_string(),
                location: Some("initializeResult.serverInfo".to_string()),
                details: None,
            });
        }

        if ctx.protocol_version.is_none() {
            violations.push(Violation {
                rule_id: self.id().to_string(),
                severity: self.severity(),
                message: "Initialize response missing protocolVersion".to_string(),
                location: Some("initializeResult.protocolVersion".to_string()),
                details: None,
            });
        }

        violations
    }
}

pub struct Proto004InvalidToolSchema;

impl ValidationRule for Proto004InvalidToolSchema {
    fn id(&self) -> &str { "PROTO-004" }
    fn name(&self) -> &str { "Invalid Tool Schema" }
    fn category(&self) -> &str { "tools" }
    fn severity(&self) -> ValidatorSeverity { ValidatorSeverity::Error }

    fn validate(&self, ctx: &ValidationContext) -> Vec<Violation> {
        let mut violations = vec![];

        for (idx, tool) in ctx.tools.iter().enumerate() {
            // Check schema has 'type' field
            if !tool.input_schema.get("type").is_some() {
                violations.push(Violation {
                    rule_id: self.id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Tool '{}' has invalid inputSchema: missing 'type' field",
                        tool.name
                    ),
                    location: Some(format!("tools[{}].inputSchema", idx)),
                    details: None,
                });
            }
        }

        violations
    }
}
```

**Schema Validation (`schema.rs`):**

```rust
/// Validate JSON Schema structure
pub fn validate_json_schema(schema: &Value, path: &str) -> Vec<Violation> {
    let mut violations = vec![];

    // SCHEMA-001: Check for type field
    if !schema.get("type").is_some() && !schema.get("$ref").is_some() {
        violations.push(Violation {
            rule_id: "SCHEMA-001".to_string(),
            severity: ValidatorSeverity::Error,
            message: "Schema missing 'type' field".to_string(),
            location: Some(path.to_string()),
            details: None,
        });
    }

    // SCHEMA-002: Validate type value
    if let Some(type_val) = schema.get("type") {
        if let Some(type_str) = type_val.as_str() {
            let valid_types = ["string", "number", "integer", "boolean",
                             "array", "object", "null"];
            if !valid_types.contains(&type_str) {
                violations.push(Violation {
                    rule_id: "SCHEMA-002".to_string(),
                    severity: ValidatorSeverity::Error,
                    message: format!("Invalid type '{}' (expected one of: {})",
                                    type_str, valid_types.join(", ")),
                    location: Some(format!("{}.type", path)),
                    details: None,
                });
            }
        }
    }

    // SCHEMA-003: Object should have properties
    if schema.get("type") == Some(&Value::String("object".to_string())) {
        if !schema.get("properties").is_some()
           && !schema.get("additionalProperties").is_some() {
            violations.push(Violation {
                rule_id: "SCHEMA-003".to_string(),
                severity: ValidatorSeverity::Warning,
                message: "Object schema missing 'properties'".to_string(),
                location: Some(path.to_string()),
                details: Some("Consider defining expected properties".to_string()),
            });
        }
    }

    // SCHEMA-004: Required must be array
    if let Some(required) = schema.get("required") {
        if !required.is_array() {
            violations.push(Violation {
                rule_id: "SCHEMA-004".to_string(),
                severity: ValidatorSeverity::Error,
                message: "'required' field must be an array".to_string(),
                location: Some(format!("{}.required", path)),
                details: None,
            });
        }
    }

    // SCHEMA-005: Required references valid properties
    if let (Some(required), Some(properties)) =
        (schema.get("required"), schema.get("properties")) {
        if let (Some(req_arr), Some(props_obj)) =
            (required.as_array(), properties.as_object()) {
            for req in req_arr {
                if let Some(req_name) = req.as_str() {
                    if !props_obj.contains_key(req_name) {
                        violations.push(Violation {
                            rule_id: "SCHEMA-005".to_string(),
                            severity: ValidatorSeverity::Warning,
                            message: format!(
                                "Required property '{}' not defined in properties",
                                req_name
                            ),
                            location: Some(format!("{}.required", path)),
                            details: None,
                        });
                    }
                }
            }
        }
    }

    violations
}
```

### 3. Validation Engine (`src/validator/engine.rs`)

```rust
use crate::client::McpClient;
use crate::protocol::mcp::Tool;
use crate::transport::TransportConfig;

pub struct ValidationEngine {
    rules: Vec<Box<dyn ValidationRule>>,
    config: ValidationConfig,
}

#[derive(Debug, Clone)]
pub struct ValidationConfig {
    pub strict: bool,           // Treat warnings as errors
    pub check_schemas: bool,    // Validate tool inputSchemas
    pub check_sequences: bool,  // Validate message ordering
    pub timeout_secs: u64,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            strict: false,
            check_schemas: true,
            check_sequences: true,
            timeout_secs: 30,
        }
    }
}

impl ValidationEngine {
    pub fn new(config: ValidationConfig) -> Self {
        Self {
            rules: Self::default_rules(),
            config,
        }
    }

    fn default_rules() -> Vec<Box<dyn ValidationRule>> {
        vec![
            // Protocol rules
            Box::new(Proto001MissingRequiredField),
            Box::new(Proto002InvalidJsonRpcVersion),
            Box::new(Proto003ToolMissingName),
            Box::new(Proto004InvalidToolSchema),
            Box::new(Proto008ProtocolVersionMismatch),
            Box::new(Proto009CapabilityMismatch),
            // Sequence rules
            Box::new(Seq001NoInitialize),
        ]
    }

    pub async fn validate(&self, target: &str, args: &[String]) -> Result<ValidationResults> {
        let start = std::time::Instant::now();
        let mut checks = vec![];
        let mut context = ValidationContext::default();

        // Connect and gather data
        let transport_config = TransportConfig {
            timeout_secs: self.config.timeout_secs,
            ..Default::default()
        };

        // Check: Connection
        let connect_start = std::time::Instant::now();
        let mut client = match McpClient::connect_with_config(
            target, args, "mcplint", env!("CARGO_PKG_VERSION"), transport_config
        ).await {
            Ok(c) => {
                checks.push(ValidationCheck {
                    name: "Transport Connection".to_string(),
                    category: "connection".to_string(),
                    status: CheckStatus::Passed,
                    message: None,
                    duration_ms: connect_start.elapsed().as_millis() as u64,
                });
                c
            }
            Err(e) => {
                checks.push(ValidationCheck {
                    name: "Transport Connection".to_string(),
                    category: "connection".to_string(),
                    status: CheckStatus::Failed,
                    message: Some(e.to_string()),
                    duration_ms: connect_start.elapsed().as_millis() as u64,
                });
                return Ok(self.build_results(target, checks));
            }
        };

        // Check: Initialize
        let init_start = std::time::Instant::now();
        match client.initialize().await {
            Ok(result) => {
                context.server_info = Some(result.server_info.clone());
                context.protocol_version = Some(result.protocol_version.clone());
                context.capabilities = Some(result.capabilities.clone());

                checks.push(ValidationCheck {
                    name: "Initialize Handshake".to_string(),
                    category: "lifecycle".to_string(),
                    status: CheckStatus::Passed,
                    message: Some(format!(
                        "Protocol: {}, Server: {} v{}",
                        result.protocol_version,
                        result.server_info.name,
                        result.server_info.version
                    )),
                    duration_ms: init_start.elapsed().as_millis() as u64,
                });
            }
            Err(e) => {
                checks.push(ValidationCheck {
                    name: "Initialize Handshake".to_string(),
                    category: "lifecycle".to_string(),
                    status: CheckStatus::Failed,
                    message: Some(e.to_string()),
                    duration_ms: init_start.elapsed().as_millis() as u64,
                });
                let _ = client.close().await;
                return Ok(self.build_results(target, checks));
            }
        }

        // Check: List Tools (if capability advertised)
        if client.server_capabilities()
            .map(|c| c.has_tools())
            .unwrap_or(false)
        {
            let tools_start = std::time::Instant::now();
            match client.list_tools().await {
                Ok(tools) => {
                    context.tools = tools.clone();
                    checks.push(ValidationCheck {
                        name: "Tools List".to_string(),
                        category: "tools".to_string(),
                        status: CheckStatus::Passed,
                        message: Some(format!("{} tools available", tools.len())),
                        duration_ms: tools_start.elapsed().as_millis() as u64,
                    });
                }
                Err(e) => {
                    checks.push(ValidationCheck {
                        name: "Tools List".to_string(),
                        category: "tools".to_string(),
                        status: CheckStatus::Failed,
                        message: Some(e.to_string()),
                        duration_ms: tools_start.elapsed().as_millis() as u64,
                    });
                }
            }
        }

        // Check: List Resources (if capability advertised)
        if client.server_capabilities()
            .map(|c| c.has_resources())
            .unwrap_or(false)
        {
            let resources_start = std::time::Instant::now();
            match client.list_resources().await {
                Ok(resources) => {
                    context.resources = resources.clone();
                    checks.push(ValidationCheck {
                        name: "Resources List".to_string(),
                        category: "resources".to_string(),
                        status: CheckStatus::Passed,
                        message: Some(format!("{} resources available", resources.len())),
                        duration_ms: resources_start.elapsed().as_millis() as u64,
                    });
                }
                Err(e) => {
                    checks.push(ValidationCheck {
                        name: "Resources List".to_string(),
                        category: "resources".to_string(),
                        status: CheckStatus::Failed,
                        message: Some(e.to_string()),
                        duration_ms: resources_start.elapsed().as_millis() as u64,
                    });
                }
            }
        }

        // Check: List Prompts (if capability advertised)
        if client.server_capabilities()
            .map(|c| c.has_prompts())
            .unwrap_or(false)
        {
            let prompts_start = std::time::Instant::now();
            match client.list_prompts().await {
                Ok(prompts) => {
                    context.prompts = prompts.clone();
                    checks.push(ValidationCheck {
                        name: "Prompts List".to_string(),
                        category: "prompts".to_string(),
                        status: CheckStatus::Passed,
                        message: Some(format!("{} prompts available", prompts.len())),
                        duration_ms: prompts_start.elapsed().as_millis() as u64,
                    });
                }
                Err(e) => {
                    checks.push(ValidationCheck {
                        name: "Prompts List".to_string(),
                        category: "prompts".to_string(),
                        status: CheckStatus::Failed,
                        message: Some(e.to_string()),
                        duration_ms: prompts_start.elapsed().as_millis() as u64,
                    });
                }
            }
        }

        // Run validation rules
        let rules_start = std::time::Instant::now();
        let mut all_violations = vec![];

        for rule in &self.rules {
            let violations = rule.validate(&context);

            if !violations.is_empty() {
                for v in &violations {
                    checks.push(ValidationCheck {
                        name: format!("{}: {}", rule.id(), rule.name()),
                        category: rule.category().to_string(),
                        status: match v.severity {
                            ValidatorSeverity::Error => CheckStatus::Failed,
                            ValidatorSeverity::Warning => CheckStatus::Warning,
                            ValidatorSeverity::Info => CheckStatus::Passed,
                        },
                        message: Some(v.message.clone()),
                        duration_ms: 0,
                    });
                }
                all_violations.extend(violations);
            }
        }

        // Schema validation
        if self.config.check_schemas {
            for (idx, tool) in context.tools.iter().enumerate() {
                let schema_violations = validate_json_schema(
                    &tool.input_schema,
                    &format!("tools[{}].inputSchema", idx)
                );

                for v in &schema_violations {
                    checks.push(ValidationCheck {
                        name: format!("Schema: {}", tool.name),
                        category: "schema".to_string(),
                        status: match v.severity {
                            ValidatorSeverity::Error => CheckStatus::Failed,
                            ValidatorSeverity::Warning => CheckStatus::Warning,
                            ValidatorSeverity::Info => CheckStatus::Passed,
                        },
                        message: Some(v.message.clone()),
                        duration_ms: 0,
                    });
                }
                all_violations.extend(schema_violations);
            }
        }

        // Close connection
        let _ = client.close().await;

        Ok(self.build_results(target, checks))
    }

    fn build_results(&self, server: &str, checks: Vec<ValidationCheck>) -> ValidationResults {
        let passed = checks.iter()
            .filter(|c| matches!(c.status, CheckStatus::Passed))
            .count();
        let failed = checks.iter()
            .filter(|c| matches!(c.status, CheckStatus::Failed))
            .count();
        let warnings = checks.iter()
            .filter(|c| matches!(c.status, CheckStatus::Warning))
            .count();

        ValidationResults {
            server: server.to_string(),
            passed,
            failed,
            warnings,
            checks,
        }
    }
}
```

### 4. Update Validator Module (`src/validator/mod.rs`)

```rust
//! Protocol Validator - MCP protocol compliance checking

mod context;
mod engine;
mod rules;
mod schema;

pub use context::ValidationContext;
pub use engine::{ValidationConfig, ValidationEngine};
pub use rules::{ValidationRule, ValidatorSeverity, Violation};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Protocol validation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResults {
    pub server: String,
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub checks: Vec<ValidationCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationCheck {
    pub name: String,
    pub category: String,
    pub status: CheckStatus,
    pub message: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckStatus {
    Passed,
    Failed,
    Warning,
    Skipped,
}

impl ValidationResults {
    pub fn is_valid(&self) -> bool {
        self.failed == 0
    }

    pub fn print_text(&self) {
        use colored::Colorize;

        println!("{}", "Protocol Validation Results".cyan().bold());
        println!("{}", "=".repeat(50));
        println!();

        for check in &self.checks {
            let status = match check.status {
                CheckStatus::Passed => "✓ PASS".green(),
                CheckStatus::Failed => "✗ FAIL".red(),
                CheckStatus::Warning => "⚠ WARN".yellow(),
                CheckStatus::Skipped => "- SKIP".dimmed(),
            };
            println!("  {} {} ({})", status, check.name, check.category.dimmed());
            if let Some(ref msg) = check.message {
                println!("    {}", msg.dimmed());
            }
        }

        println!();
        println!(
            "Summary: {} passed, {} failed, {} warnings",
            self.passed.to_string().green(),
            self.failed.to_string().red(),
            self.warnings.to_string().yellow()
        );

        if self.is_valid() {
            println!("\n{}", "✓ Validation PASSED".green().bold());
        } else {
            println!("\n{}", "✗ Validation FAILED".red().bold());
        }
    }

    pub fn print_json(&self) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(self)?);
        Ok(())
    }

    pub fn print_sarif(&self) -> Result<()> {
        // SARIF output implementation
        let sarif = self.to_sarif()?;
        println!("{}", serde_json::to_string_pretty(&sarif)?);
        Ok(())
    }

    fn to_sarif(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "mcplint",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/quanticsoul4772/mcplint"
                    }
                },
                "results": self.checks.iter()
                    .filter(|c| !matches!(c.status, CheckStatus::Passed))
                    .map(|c| serde_json::json!({
                        "ruleId": c.name.clone(),
                        "level": match c.status {
                            CheckStatus::Failed => "error",
                            CheckStatus::Warning => "warning",
                            _ => "note"
                        },
                        "message": {
                            "text": c.message.clone().unwrap_or_default()
                        }
                    }))
                    .collect::<Vec<_>>()
            }]
        }))
    }
}

/// Legacy interface for backwards compatibility
pub struct ProtocolValidator {
    engine: ValidationEngine,
    server: String,
    args: Vec<String>,
}

impl ProtocolValidator {
    pub fn new(server: &str, args: &[String], timeout: u64) -> Self {
        let config = ValidationConfig {
            timeout_secs: timeout,
            ..Default::default()
        };

        Self {
            engine: ValidationEngine::new(config),
            server: server.to_string(),
            args: args.to_vec(),
        }
    }

    pub fn with_config(server: &str, args: &[String], config: ValidationConfig) -> Self {
        Self {
            engine: ValidationEngine::new(config),
            server: server.to_string(),
            args: args.to_vec(),
        }
    }

    pub async fn validate(&self) -> Result<ValidationResults> {
        self.engine.validate(&self.server, &self.args).await
    }
}
```

### 5. Update CLI Validate Command (`src/cli/commands/validate.rs`)

```rust
use crate::validator::{ProtocolValidator, ValidationConfig, ValidationResults};
use crate::OutputFormat;
use anyhow::Result;

pub async fn run(
    server: &str,
    args: &[String],
    format: OutputFormat,
    strict: bool,
    timeout: u64,
) -> Result<i32> {
    let config = ValidationConfig {
        strict,
        check_schemas: true,
        check_sequences: true,
        timeout_secs: timeout,
    };

    let validator = ProtocolValidator::with_config(server, args, config);
    let results = validator.validate().await?;

    match format {
        OutputFormat::Text => results.print_text(),
        OutputFormat::Json => results.print_json()?,
        OutputFormat::Sarif => results.print_sarif()?,
    }

    // Exit code: 0 = valid, 1 = invalid
    if results.is_valid() {
        Ok(0)
    } else {
        Ok(1)
    }
}
```

---

## File Structure

```
src/validator/
├── mod.rs              # Public API, ValidationResults
├── rules.rs            # ValidationRule trait, Violation type
├── context.rs          # ValidationContext
├── engine.rs           # ValidationEngine
├── schema.rs           # JSON Schema validation helpers
└── rules/
    ├── mod.rs          # Rule registry
    ├── protocol.rs     # PROTO-001 to PROTO-010
    ├── schema.rs       # SCHEMA-001 to SCHEMA-005 (specific impls)
    └── sequence.rs     # SEQ-001 to SEQ-003
```

---

## Validation Criteria

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto001_detects_missing_server_info() {
        let rule = Proto001MissingRequiredField;
        let ctx = ValidationContext::default(); // No server_info
        let violations = rule.validate(&ctx);
        assert!(violations.iter().any(|v| v.rule_id == "PROTO-001"));
    }

    #[test]
    fn schema_validates_type_field() {
        let schema = serde_json::json!({
            "properties": {"name": {"type": "string"}}
        });
        let violations = validate_json_schema(&schema, "test");
        assert!(violations.iter().any(|v| v.rule_id == "SCHEMA-001"));
    }

    #[test]
    fn schema_passes_valid_schema() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"]
        });
        let violations = validate_json_schema(&schema, "test");
        assert!(violations.is_empty());
    }

    #[test]
    fn schema_detects_unknown_required() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name", "unknown_field"]
        });
        let violations = validate_json_schema(&schema, "test");
        assert!(violations.iter().any(|v| v.rule_id == "SCHEMA-005"));
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn validate_demo_server() {
    // Test against reference server
    let validator = ProtocolValidator::new(
        "npx",
        &["-y".to_string(), "@anthropic-ai/mcp-server-demo".to_string()],
        30
    );
    let results = validator.validate().await.unwrap();

    assert!(results.is_valid());
    assert!(results.passed > 0);
}

#[tokio::test]
async fn validate_detects_invalid_schema() {
    // Test server with known schema issues
    // Would need a test fixture server
}
```

### Manual Testing

```bash
# Validate reference server
mcplint validate npx -y @anthropic-ai/mcp-server-demo

# Validate with JSON output
mcplint validate ./my-server --format=json

# Validate with strict mode
mcplint validate ./my-server --strict

# Validate HTTP server
mcplint validate https://example.com/mcp
```

---

## Output Example

### Text Output

```
Protocol Validation Results
==================================================

  ✓ PASS Transport Connection (connection)
  ✓ PASS Initialize Handshake (lifecycle)
    Protocol: 2025-03-26, Server: demo-server v1.0.0
  ✓ PASS Tools List (tools)
    3 tools available
  ⚠ WARN Schema: read_file (schema)
    Object schema missing 'properties'
  ✓ PASS Resources List (resources)
    2 resources available

Summary: 4 passed, 0 failed, 1 warnings

✓ Validation PASSED
```

### JSON Output

```json
{
  "server": "npx -y @anthropic-ai/mcp-server-demo",
  "passed": 4,
  "failed": 0,
  "warnings": 1,
  "checks": [
    {
      "name": "Transport Connection",
      "category": "connection",
      "status": "Passed",
      "message": null,
      "duration_ms": 1250
    },
    {
      "name": "Initialize Handshake",
      "category": "lifecycle",
      "status": "Passed",
      "message": "Protocol: 2025-03-26, Server: demo-server v1.0.0",
      "duration_ms": 89
    }
  ]
}
```

---

## Definition of Done

- [ ] `ValidationEngine` connects to servers via `McpClient`
- [ ] `ValidationEngine` runs all registered rules against context
- [ ] Protocol rules (PROTO-001 to PROTO-010) implemented
- [ ] Schema rules (SCHEMA-001 to SCHEMA-005) implemented
- [ ] Sequence rules (SEQ-001 to SEQ-003) implemented
- [ ] Text, JSON, SARIF output formats working
- [ ] Unit tests for all rules
- [ ] Integration tests against reference server
- [ ] `mcplint validate <server>` command works
- [ ] Exit codes: 0 = valid, 1 = invalid, 2 = error
- [ ] Documentation updated

---

## Dependencies

No new dependencies required. Uses existing:
- `serde` / `serde_json` for serialization
- `anyhow` for error handling
- `colored` for terminal output
- `tokio` for async runtime
